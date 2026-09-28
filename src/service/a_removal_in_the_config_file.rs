//! A device removed from `[authorized_fingerprints]` in config.toml, by an
//! older build (0.12 and before read that table as their allowlist and remove
//! a device by deleting its line) or by hand, is removed here too, and a line
//! added there grants nothing.
//!
//! Before, the table was a cache the daemon wrote and never read once the
//! trust store existed, so such a removal was undone: the device was trusted
//! again at the next start.
//!
//! The whole daemon runs in this process, started more than once on one
//! scratch directory as a machine is restarted; what is observed is its trust
//! store and what an app connected over its IPC socket is told.

use super::Service;
use crate::test_harness::run_local;
use crate::transport::Trust;
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

/// What must happen is waited for this long at most.
const DEADLINE: Duration = Duration::from_secs(120);

const DESK: &str = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:\
11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";
const LAPTOP: &str = "aa:bb:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:\
11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";

/// The scratch directory, removed with it.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str) -> Scratch {
    // Short, for a socket path in it (`sun_path`); by its real path, as the
    // config watcher reports it (on macOS /tmp is a link).
    let dir = PathBuf::from(format!("/tmp/h-cf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    Scratch(dir.canonicalize().expect("its real path"))
}

/// The config, with `trusted` as the `[authorized_fingerprints]` table.
fn config_listing(trusted: &[(&str, &str)]) -> String {
    let mut text = String::from(
        "port = 0\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\n\
         discovery = false\n\n[authorized_fingerprints]\n",
    );
    for (fp, label) in trusted {
        text.push_str(&format!("\"{fp}\" = \"{label}\"\n"));
    }
    text
}

/// Save `text` as the config the way an editor or an older build does: a
/// new file renamed over the old one.
fn save_config(dir: &Path, text: &str) {
    let saving = dir.join("config.toml.saving");
    std::fs::write(&saving, text).expect("the new config");
    std::fs::rename(&saving, dir.join("config.toml")).expect("renamed into place");
}

/// A daemon started on `dir`, its `n`th start, with an app's endpoint.
async fn start(dir: &Path, n: u32) -> (Service, DaemonEndpoint) {
    let endpoint = DaemonEndpoint::Unix(dir.join(format!("s{n}.sock")));
    let frontends = AsyncFrontendListener::at_with_token_file(&endpoint, &dir.join("ipc-token"))
        .await
        .expect("the scratch endpoint");
    let config = crate::config::Config::in_scratch(&dir.join("config.toml"), &dir.join("hops.pem"))
        .expect("the scratch config");
    let service = Service::with_backends(
        config,
        frontends,
        Some(input_capture::Backend::Dummy),
        Some(input_emulation::Backend::Dummy),
    )
    .await
    .expect("a daemon in the scratch directory");
    (service, endpoint)
}

/// Stop a daemon as a restart does.
async fn stop(mut service: Service) {
    service.capture.terminate().await;
    service.emulation.terminate().await;
    service.resolver.terminate().await;
}

/// (desk trusted, laptop trusted) in `trust`.
fn known(trust: &Trust) -> (bool, bool) {
    let trust = trust.read().expect("lock");
    (trust.is_known(DESK), trust.is_known(LAPTOP))
}

/// Connect an app to `endpoint` and wait for a notice that mentions
/// config.toml, while `service` runs. `then` runs once the app is connected.
async fn notice_while_running(
    service: &mut Service,
    dir: &Path,
    endpoint: &DaemonEndpoint,
    then: impl FnOnce(),
) -> String {
    let DaemonEndpoint::Unix(path) = endpoint else {
        unreachable!("a unix socket")
    };
    let token = std::fs::read_to_string(dir.join("ipc-token")).expect("the token");
    let told = async {
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .expect("the daemon's socket");
        let (read, mut write) = tokio::io::split(stream);
        let mut read = BufReader::new(read);
        hops_ipc::prove_to_daemon(&mut read, &mut write, token.trim())
            .await
            .expect("the two-way proof is made");
        // Known to the daemon once it answers a barrier, as an app that has
        // been open a while is; a notice sent before that reaches no one.
        let mut line = serde_json::to_string(&hops_ipc::FrontendRequest::Barrier(1)).expect("json");
        line.push('\n');
        tokio::io::AsyncWriteExt::write_all(&mut write, line.as_bytes())
            .await
            .expect("the barrier is sent");
        let mut then = Some(then);
        let mut lines = read.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let event: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
            if let Some(said) = event.get("Error").and_then(|e| e.as_str()) {
                if said.contains("config.toml") {
                    return said.to_string();
                }
            }
            if event.get("Barrier") == Some(&serde_json::json!(1)) {
                if let Some(then) = then.take() {
                    then();
                }
            }
        }
        panic!("the daemon hung up on the app");
    };
    tokio::select! {
        ended = service.run() => panic!("the daemon ended: {ended:?}"),
        told = told => told,
        _ = tokio::time::sleep(DEADLINE) => String::new(),
    }
}

// LEDGER T2264 | class B | 6 trust store state across three starts + 2 event over the real IPC socket
/// The upgrade and downgrade case: the store trusts both machines, an older
/// build removes the laptop from config.toml, and this build starts again.
#[test]
fn a_device_removed_from_the_file_while_stopped_is_forgotten_at_start() {
    run_local(async {
        let s = scratch("start");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        std::fs::write(s.0.join("config.toml"), config_listing(&both)).expect("a config");
        let (first, _) = start(&s.0, 1).await;
        let before = known(&first.trust);
        stop(first).await;

        // As an older build saves after removing the laptop.
        save_config(&s.0, &config_listing(&both[..1]));
        let (mut second, endpoint) = start(&s.0, 2).await;
        let after = known(&second.trust);
        let told = notice_while_running(&mut second, &s.0, &endpoint, || {}).await;
        stop(second).await;

        // A line put back grants nothing: only a pairing does.
        save_config(&s.0, &config_listing(&both));
        let (third, _) = start(&s.0, 3).await;
        let put_back = known(&third.trust);
        stop(third).await;

        assert_eq!(
            (before, after, put_back),
            ((true, true), (true, false), (true, false)),
            "((desk, laptop) trusted) at the first start, after config.toml dropped \
             the laptop, and after a line naming it was put back"
        );
        assert!(
            told.contains("\"laptop\""),
            "the app must be told the laptop was forgotten, and why: {told:?}"
        );
    });
}

// LEDGER T2265 | class B | 6 trust store state across two starts
/// A device the file never listed was not removed from it: a pairing made
/// by a build that did not write the cache, or whose write failed, stays.
#[test]
fn a_device_the_file_never_listed_is_kept() {
    run_local(async {
        let s = scratch("never");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        std::fs::write(s.0.join("config.toml"), config_listing(&both)).expect("a config");
        let (first, _) = start(&s.0, 1).await;
        stop(first).await;
        // As a build before this one left it: no record of what was listed,
        // and a cache that lags the store.
        std::fs::remove_file(s.0.join(crate::cache_listed::FILE_NAME)).expect("the record");
        save_config(&s.0, &config_listing(&both[..1]));
        let (second, _) = start(&s.0, 2).await;
        let after = known(&second.trust);
        stop(second).await;
        assert_eq!(
            after,
            (true, true),
            "(desk, laptop) trusted: the laptop was never listed as far as this \
             build knows, so its absence is not a removal"
        );
    });
}

// LEDGER T2266 | class B | 6 trust store state + 2 event over the real IPC socket, through the config watcher
/// A person removes the laptop's line while the daemon runs.
#[test]
fn a_device_removed_from_the_file_while_running_is_forgotten() {
    run_local(async {
        let s = scratch("live");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        std::fs::write(s.0.join("config.toml"), config_listing(&both)).expect("a config");
        let (mut service, endpoint) = start(&s.0, 1).await;
        let before = known(&service.trust);
        let dir = s.0.clone();
        let told = notice_while_running(&mut service, &s.0, &endpoint, move || {
            save_config(&dir, &config_listing(&both[..1]));
        })
        .await;
        let after = known(&service.trust);
        stop(service).await;
        assert_eq!(
            (before, after),
            ((true, true), (true, false)),
            "((desk, laptop) trusted) before and after the laptop's line was removed"
        );
        assert!(
            told.contains("\"laptop\""),
            "the app must be told the laptop was forgotten: {told:?}"
        );
    });
}

/// Have an app connected to `endpoint` send `request`, and return once the
/// daemon has handled it, while `service` runs.
async fn app_asks(
    service: &mut Service,
    dir: &Path,
    endpoint: &DaemonEndpoint,
    request: hops_ipc::FrontendRequest,
) {
    use tokio::io::AsyncWriteExt;
    let DaemonEndpoint::Unix(path) = endpoint else {
        unreachable!("a unix socket")
    };
    let token = std::fs::read_to_string(dir.join("ipc-token")).expect("the token");
    let handled = async {
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .expect("the daemon's socket");
        let (read, mut write) = tokio::io::split(stream);
        let mut read = BufReader::new(read);
        hops_ipc::prove_to_daemon(&mut read, &mut write, token.trim())
            .await
            .expect("the two-way proof is made");
        for request in [request, hops_ipc::FrontendRequest::Barrier(7)] {
            let mut line = serde_json::to_string(&request).expect("json");
            line.push('\n');
            write.write_all(line.as_bytes()).await.expect("sent");
        }
        let mut lines = read.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let event: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
            if event.get("Barrier") == Some(&serde_json::json!(7)) {
                return;
            }
        }
        panic!("the daemon hung up on the app");
    };
    tokio::select! {
        ended = service.run() => panic!("the daemon ended: {ended:?}"),
        () = handled => {}
        _ = tokio::time::sleep(DEADLINE) => panic!("the daemon did not handle the request"),
    }
}

// LEDGER T2267 | class B | 5 file content on disk after a request over the real IPC socket
/// The other direction: an older build reads the table as its allowlist, so
/// a device removed here must leave it at once, or running the older build
/// (a downgrade) trusts it again.
#[test]
fn a_device_removed_in_the_app_leaves_the_file_at_once() {
    run_local(async {
        let s = scratch("app");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        std::fs::write(s.0.join("config.toml"), config_listing(&both)).expect("a config");
        let (mut service, endpoint) = start(&s.0, 1).await;
        app_asks(
            &mut service,
            &s.0,
            &endpoint,
            hops_ipc::FrontendRequest::RemoveAuthorizedKey(LAPTOP.to_string()),
        )
        .await;
        let on_disk = std::fs::read_to_string(s.0.join("config.toml")).unwrap_or_default();
        stop(service).await;
        assert!(
            on_disk.contains(DESK) && !on_disk.contains(LAPTOP),
            "the laptop was removed in the app and config.toml still lists it, or \
             lost the desk:\n{on_disk}"
        );
    });
}

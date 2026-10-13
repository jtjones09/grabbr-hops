//! A device removed from `[authorized_fingerprints]` in config.toml, by an
//! older build (0.12 and before read that table as their allowlist and remove
//! a device by deleting its line) or by hand, is removed here too, and a line
//! added there grants nothing.
//!
//! Before, the table was a cache the daemon wrote and never read once the
//! trust store existed, so such a removal was undone: the device was trusted
//! again at the next start.
//!
//! A machine the table names that a build before the trust store paired, and
//! that the store holds only to be paired again (#231), is removed the same
//! way while the file still lists it. The table grants nothing either way: a
//! test here that needs a device trusted pairs it in the trust store before
//! the first start ([`paired_with`]), since a first start lists what the
//! table names to be paired again.
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

/// The config with no `[authorized_fingerprints]` table at all, as a
/// template, an old backup or a file written by hand has none; told apart
/// from the others by its release keys, two where they have the four the
/// daemon uses by default.
fn config_without_the_table() -> String {
    "port = 0\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\n\
     discovery = false\nrelease_bind = [\"KeyLeftCtrl\", \"KeyLeftAlt\"]\n"
        .to_string()
}

/// Pair the daemon in `dir` with each of `devices` before its first start,
/// each allowed to drive this machine and confirmed on both machines, as the
/// pairing card leaves it. Listing them in config.toml does not pair them: a
/// first start lists those to be paired again and grants them nothing
/// (#231).
fn paired_with(dir: &Path, devices: &[(&str, &str)]) {
    let pairings: Vec<(&str, &str, crate::trust::Caps)> = devices
        .iter()
        .map(|(fp, label)| (*fp, *label, crate::trust::Caps::DRIVE_ME))
        .collect();
    crate::test_harness::seed_pairings(dir, &dir.join("hops.pem"), &pairings);
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
    start_with(dir, n, || {}).await
}

/// [`start`], running `read` once the daemon has read its config.
async fn start_with(dir: &Path, n: u32, read: impl FnOnce()) -> (Service, DaemonEndpoint) {
    let endpoint = DaemonEndpoint::Unix(dir.join(format!("s{n}.sock")));
    let frontends = AsyncFrontendListener::at_with_token_file(&endpoint, &dir.join("ipc-token"))
        .await
        .expect("the scratch endpoint");
    let config = crate::config::Config::in_scratch(&dir.join("config.toml"), &dir.join("hops.pem"))
        .expect("the scratch config");
    read();
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
/// The downgrade case: the store trusts both machines, an older build
/// removes the laptop from config.toml, and this build starts again. The
/// store holds both from a pairing, not from the table (#231); the upgrade
/// case, where it holds them only to be paired again, is
/// [`a_machine_to_pair_again_removed_from_the_file_is_forgotten`].
#[test]
fn a_device_removed_from_the_file_while_stopped_is_forgotten_at_start() {
    run_local(async {
        let s = scratch("start");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        std::fs::write(s.0.join("config.toml"), config_listing(&both)).expect("a config");
        paired_with(&s.0, &both);
        let (first, _) = start(&s.0, 1).await;
        let before = known(&first.trust);
        stop(first).await;

        // As an older build saves after removing the laptop.
        save_config(&s.0, &config_listing(&both[..1]));
        let (mut second, endpoint) = start(&s.0, 2).await;
        let after = known(&second.trust);
        // The front door asks which build answers before every app it opens.
        let probed = front_door_probe(&mut second, &s.0, &endpoint).await;
        let told = told_on_attach(&mut second, &s.0, &endpoint).await;
        let again = told_on_attach(&mut second, &s.0, &endpoint).await;
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
             the laptop, and after a line naming it was put back. \
             Each device was paired in the trust store, as the table grants nothing (#231)."
        );
        assert!(probed.is_some(), "the front door's probe was not answered");
        assert!(
            told.iter().any(|said| said.contains("\"laptop\"")),
            "the app opened after the front door's build probe was not told: {told:?}"
        );
        assert!(
            again.iter().any(|said| said.contains("\"laptop\"")),
            "the next app opened was not told: {again:?}"
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
        paired_with(&s.0, &both);
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
             build knows, so its absence is not a removal. \
             Each device was paired in the trust store, as the table grants nothing (#231)."
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
        paired_with(&s.0, &both);
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
            "((desk, laptop) trusted) before and after the laptop's line was removed. \
             Each device was paired in the trust store, as the table grants nothing (#231)."
        );
        assert!(
            told.contains("\"laptop\""),
            "the app must be told the laptop was forgotten: {told:?}"
        );
    });
}

/// Have an app connected to `endpoint` send `request`, and return once the
/// daemon has handled it, while `service` runs, with every error notice the
/// app was sent until then.
async fn app_asks(
    service: &mut Service,
    dir: &Path,
    endpoint: &DaemonEndpoint,
    request: hops_ipc::FrontendRequest,
) -> Vec<String> {
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
        let mut errors = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            let event: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
            if let Some(said) = event.get("Error").and_then(|e| e.as_str()) {
                errors.push(said.to_string());
            }
            if event.get("Barrier") == Some(&serde_json::json!(7)) {
                return errors;
            }
        }
        panic!("the daemon hung up on the app");
    };
    tokio::select! {
        ended = service.run() => panic!("the daemon ended: {ended:?}"),
        errors = handled => errors,
        _ = tokio::time::sleep(DEADLINE) => panic!("the daemon did not handle the request"),
    }
}

/// Ask the daemon on `endpoint` which build it is, with the token, as the
/// front door does before it opens an app, while `service` runs.
async fn front_door_probe(
    service: &mut Service,
    dir: &Path,
    endpoint: &DaemonEndpoint,
) -> Option<hops_ipc::StatedBuild> {
    let token = std::fs::read_to_string(dir.join("ipc-token")).expect("the token");
    let endpoint = endpoint.clone();
    // A blocking ask, off the thread the daemon runs on.
    let asked = tokio::task::spawn_blocking(move || {
        endpoint.build(Some(token.trim()), Duration::from_secs(20))
    });
    tokio::select! {
        ended = service.run() => panic!("the daemon ended: {ended:?}"),
        answer = asked => answer.expect("the probe ran"),
    }
}

/// Connect an app to `endpoint` while `service` runs, and return every error
/// notice in the state it is sent on attaching, which ends with this
/// machine's fingerprint.
async fn told_on_attach(
    service: &mut Service,
    dir: &Path,
    endpoint: &DaemonEndpoint,
) -> Vec<String> {
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
        let mut lines = read.lines();
        let mut errors = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            let event: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
            if let Some(said) = event.get("Error").and_then(|e| e.as_str()) {
                errors.push(said.to_string());
            }
            if event.get("PublicKeyFingerprint").is_some() {
                return errors;
            }
        }
        panic!("the daemon hung up on the app");
    };
    tokio::select! {
        ended = service.run() => panic!("the daemon ended: {ended:?}"),
        errors = told => errors,
        _ = tokio::time::sleep(DEADLINE) => panic!("the app was not sent its state"),
    }
}

/// Run `service`, once `then` has run, until `signal` is raised with `done`
/// true of it.
async fn run_until(
    service: &mut Service,
    signal: Signal,
    then: impl FnOnce(),
    done: impl Fn(&Service) -> bool,
) {
    let signals = service.config_signals.clone();
    let notify = match signal {
        Signal::Reloaded => &signals.reloaded,
        Signal::Checked => &signals.checked,
    };
    // A signal left over from before `then` is not the one waited for.
    let _ = futures::FutureExt::now_or_never(notify.notified());
    then();
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        tokio::select! {
            ended = service.run() => panic!("the daemon ended: {ended:?}"),
            () = notify.notified() => {}
            _ = tokio::time::sleep_until(deadline) => panic!("the daemon never raised {signal:?}"),
        }
        if done(service) {
            return;
        }
    }
}

/// What [`run_until`] waits for.
#[derive(Debug, Clone, Copy)]
enum Signal {
    /// A change to config.toml was read.
    Reloaded,
    /// The check for removals a read scheduled has run.
    Checked,
}

/// Trust `fp` to drive this machine, as a pairing confirmed on both machines
/// does, and save the store and the config as the daemon does after one.
fn pair_while_running(service: &mut Service, fp: &str, label: &str) {
    service
        .trust
        .write()
        .expect("lock")
        .issue_confirmed(fp, label, crate::trust::Caps::DRIVE_ME)
        .expect("the grant");
    service.persist_trust(format!("trusting {label}"));
    service.save_config();
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
        paired_with(&s.0, &both);
        let (mut service, endpoint) = start(&s.0, 1).await;
        let _ = app_asks(
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
             lost the desk. Each device was paired in the trust store, as the table \
             grants nothing (#231):\n{on_disk}"
        );
    });
}

// LEDGER T2272 | class B | 6 trust store state across two starts
/// A device paired while the daemon runs is recorded as listed when the
/// config is saved with it, so removing its line later removes it, like any
/// other.
#[test]
fn a_device_paired_while_running_is_forgotten_once_removed_from_the_file() {
    run_local(async {
        let s = scratch("paired");
        let desk = [(DESK, "desk mac")];
        std::fs::write(s.0.join("config.toml"), config_listing(&desk)).expect("a config");
        paired_with(&s.0, &desk);
        let (mut first, _) = start(&s.0, 1).await;
        pair_while_running(&mut first, LAPTOP, "laptop");
        let saved = std::fs::read_to_string(s.0.join("config.toml")).unwrap_or_default();
        stop(first).await;
        assert!(
            saved.contains(LAPTOP),
            "the pairing was not saved:\n{saved}"
        );

        save_config(&s.0, &config_listing(&desk));
        let (second, _) = start(&s.0, 2).await;
        let after = known(&second.trust);
        stop(second).await;
        assert_eq!(
            after,
            (true, false),
            "(desk, laptop) trusted after the laptop, paired while the daemon ran, \
             was removed from config.toml. \
             Each device was paired in the trust store, as the table grants nothing (#231)."
        );
    });
}

// LEDGER T2273 | class B | 6 trust store state across two starts
/// A device paired while config.toml does not parse, so the save that would
/// list it fails, was never listed there: the file's lack of it once it
/// parses again is not a removal.
#[test]
fn a_device_paired_while_the_file_could_not_be_saved_is_kept() {
    run_local(async {
        let s = scratch("unsaved");
        let desk = [(DESK, "desk mac")];
        std::fs::write(s.0.join("config.toml"), config_listing(&desk)).expect("a config");
        paired_with(&s.0, &desk);
        let (mut first, _) = start(&s.0, 1).await;
        // A hand edit half done: the daemon leaves such a file as it is.
        std::fs::write(s.0.join("config.toml"), "port = [\n").expect("a broken config");
        pair_while_running(&mut first, LAPTOP, "laptop");
        stop(first).await;

        // The edit finished, from the copy the person had open.
        save_config(&s.0, &config_listing(&desk));
        let (second, _) = start(&s.0, 2).await;
        let after = known(&second.trust);
        stop(second).await;
        assert_eq!(
            after,
            (true, true),
            "(desk, laptop) trusted: the laptop was paired while config.toml could \
             not be saved, so it never listed it, and its absence is not a removal. \
             Each device was paired in the trust store, as the table grants nothing (#231)."
        );
    });
}

// LEDGER T2274 | class B | 6 trust store state at a start and while running, through the config watcher
/// A config.toml with no `[authorized_fingerprints]` table at all, as when it
/// is replaced by a template, an old backup or a file written by hand, is
/// not a removal of every device. Nor does a start that reads one forget
/// which devices the file listed, so removing the laptop's line once the
/// table is back is still a removal.
#[test]
fn a_file_with_no_table_removes_nothing() {
    run_local(async {
        let s = scratch("notable");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        std::fs::write(s.0.join("config.toml"), config_listing(&both)).expect("a config");
        paired_with(&s.0, &both);
        let (mut first, _) = start(&s.0, 1).await;
        let dir = s.0.clone();
        run_until(
            &mut first,
            Signal::Checked,
            move || save_config(&dir, &config_without_the_table()),
            |service| service.config.release_bind().len() == 2,
        )
        .await;
        let running = known(&first.trust);
        stop(first).await;

        // As the file is at this start, whatever was recorded before.
        save_config(&s.0, &config_without_the_table());
        let (second, _) = start(&s.0, 2).await;
        let at_start = known(&second.trust);
        stop(second).await;

        // The table back, without the laptop: a real removal.
        save_config(&s.0, &config_listing(&both[..1]));
        let (third, _) = start(&s.0, 3).await;
        let removed = known(&third.trust);
        stop(third).await;
        assert_eq!(
            (running, at_start, removed),
            ((true, true), (true, true), (true, false)),
            "((desk, laptop) trusted) after the table went while running, at the \
             next start, and once the table was back without the laptop. \
             Each device was paired in the trust store, as the table grants nothing (#231)."
        );
    });
}

// LEDGER T2275 | class B | 6 trust store state, through the config watcher
/// A save that writes the file in place can be read before it has written
/// every line. A removal is acted on only once the file has settled.
#[test]
fn a_file_read_while_it_was_still_being_written_removes_nothing() {
    run_local(async {
        let s = scratch("partial");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        let path = s.0.join("config.toml");
        std::fs::write(&path, config_listing(&both)).expect("a config");
        paired_with(&s.0, &both);
        let (mut service, _) = start(&s.0, 1).await;
        // The first part of a save written in place, read by the daemon ...
        let partial = path.clone();
        let listed = |service: &Service| service.config.listed_as_trusted().map(|t| t.len());
        run_until(
            &mut service,
            Signal::Reloaded,
            move || std::fs::write(&partial, config_listing(&both[..1])).expect("the first part"),
            |service| listed(service) == Some(1),
        )
        .await;
        let read_partly = listed(&service);
        // ... and the rest.
        run_until(
            &mut service,
            Signal::Checked,
            move || std::fs::write(&path, config_listing(&both)).expect("the rest"),
            |service| listed(service) == Some(2),
        )
        .await;
        let after = known(&service.trust);
        stop(service).await;
        assert_eq!(
            (read_partly, after),
            (Some(1), (true, true)),
            "(devices the daemon read while the save was part done, (desk, laptop) \
             trusted once it finished). \
             Each device was paired in the trust store, as the table grants nothing (#231)."
        );
    });
}

// LEDGER T2276 | class B | 6 trust store state
/// The check reads the file again, and forgets only what both reads agree
/// was removed: one read the file lacked a line, the file on disk has it.
#[test]
fn a_removal_the_file_on_disk_does_not_show_is_not_made() {
    run_local(async {
        let s = scratch("reread");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        let path = s.0.join("config.toml");
        std::fs::write(&path, config_listing(&both)).expect("a config");
        paired_with(&s.0, &both);
        let (mut service, _) = start(&s.0, 1).await;
        std::fs::write(&path, config_listing(&both[..1])).expect("the laptop's line gone");
        service.config.read_from_disk().expect("read");
        service.handle_config_change();
        std::fs::write(&path, config_listing(&both)).expect("and back");
        service.check_removals();
        let back = known(&service.trust);
        std::fs::write(&path, config_listing(&both[..1])).expect("the laptop's line gone");
        service.config.read_from_disk().expect("read");
        service.handle_config_change();
        service.check_removals();
        let gone = known(&service.trust);
        stop(service).await;
        assert_eq!(
            (back, gone),
            ((true, true), (true, false)),
            "((desk, laptop) trusted) when the file on disk lists the laptop again, \
             and when it agrees it is gone. \
             Each device was paired in the trust store, as the table grants nothing (#231)."
        );
    });
}

// LEDGER T2277 | class B | 6 trust store state across three starts
/// A device forgotten at a start whose trust store could not be saved is
/// still on disk: it must read as removed again at the next start, however
/// often the config is saved in between.
#[test]
fn a_removal_whose_store_save_failed_is_made_again_at_the_next_start() {
    run_local(async {
        let s = scratch("nosave");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        std::fs::write(s.0.join("config.toml"), config_listing(&both)).expect("a config");
        paired_with(&s.0, &both);
        let (first, _) = start(&s.0, 1).await;
        stop(first).await;

        save_config(&s.0, &config_listing(&both[..1]));
        // Every save of the trust store fails, as on a full disk.
        let staging =
            s.0.join(crate::trust_file::TRUST_FILE_NAME)
                .with_extension("toml.tmp");
        std::fs::create_dir_all(staging.join("in-the-way")).expect("block the store");
        let (mut second, _) = start(&s.0, 2).await;
        let forgotten = known(&second.trust);
        second.save_config();
        stop(second).await;

        std::fs::remove_dir_all(&staging).expect("unblock the store");
        let (third, _) = start(&s.0, 3).await;
        let again = known(&third.trust);
        stop(third).await;
        assert_eq!(
            (forgotten, again),
            ((true, false), (true, false)),
            "((desk, laptop) trusted) at the start that could not save the removal, \
             and at the next. \
             Each device was paired in the trust store, as the table grants nothing (#231)."
        );
    });
}

// LEDGER T2278 | class B | 6 trust store state across three starts
/// At a start too, a removal is made only when a second read of the file,
/// once it has settled, agrees: the daemon read it while a save was part
/// done, and the save has finished since. What that start records keeps
/// the laptop, so removing its line later is still a removal.
#[test]
fn a_file_read_part_written_at_a_start_removes_nothing() {
    run_local(async {
        let s = scratch("startpart");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        let path = s.0.join("config.toml");
        std::fs::write(&path, config_listing(&both)).expect("a config");
        paired_with(&s.0, &both);
        let (first, _) = start(&s.0, 1).await;
        stop(first).await;

        std::fs::write(&path, config_listing(&both[..1])).expect("the first part");
        let rest = path.clone();
        let (second, _) = start_with(&s.0, 2, move || {
            std::fs::write(&rest, config_listing(&both)).expect("the rest");
        })
        .await;
        let after = known(&second.trust);
        stop(second).await;

        // A real removal after that start is still honoured.
        save_config(&s.0, &config_listing(&both[..1]));
        let (third, _) = start(&s.0, 3).await;
        let removed = known(&third.trust);
        stop(third).await;
        assert_eq!(
            (after, removed),
            ((true, true), (true, false)),
            "((desk, laptop) trusted) after a start that read a save still being \
             written, and after the laptop's line was then removed. \
             Each device was paired in the trust store, as the table grants nothing (#231)."
        );
    });
}

const STRANGER: &str = "cc:bb:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:\
11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";
const PASSER: &str = "dd:bb:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:\
11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";

/// Of `fps`, each the store in `trust` grants anything to, in either
/// direction.
fn granted(trust: &Trust, fps: &[&str]) -> Vec<String> {
    let trust = trust.read().expect("lock");
    fps.iter()
        .filter(|fp| trust.capabilities(fp) != crate::trust::Caps::NONE)
        .map(|fp| fp.to_string())
        .collect()
}

/// Of `fps`, each the store in `trust` lists to be paired again (#231).
fn listed_again(trust: &Trust, fps: &[&str]) -> Vec<String> {
    let trust = trust.read().expect("lock");
    fps.iter()
        .filter(|fp| trust.to_pair_again(fp).is_some())
        .map(|fp| fp.to_string())
        .collect()
}

/// Whether a device of `service` is pinned to `fp`.
fn pinned(service: &Service, fp: &str) -> bool {
    !service.client_manager.every_pinned_to(fp).is_empty()
}

/// The config listing `trusted`, with a device on the left pinned to the
/// laptop, as a device folded into the laptop's listing is saved (#231).
fn with_a_device_for_the_laptop(trusted: &[(&str, &str)]) -> String {
    format!(
        "{}\n[[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = 9\n\
         fingerprint = \"{LAPTOP}\"\n",
        config_listing(trusted)
    )
}

/// What a notice of `laptop`'s removal must say when the laptop held only a
/// listing to be paired again: it had no pairing to remove (#231).
fn told_as_a_listing(told: &str) -> bool {
    told.contains("\"laptop\" was removed from the list an older version of hops wrote")
        && told.contains("no longer shown here as one to pair again")
        && !told.contains("pairing is removed")
}

// LEDGER R231-20 | class B | 6 trust store state across three starts and a reload through the config watcher
/// `[authorized_fingerprints]` in config.toml grants nothing, whether or not
/// the trust file is there (#231). With no trust file, as at the upgrade
/// from 0.12 or once the file is lost, each machine the table names is
/// listed to be paired again. With the trust file there, a line added while
/// the daemon is stopped, or while it runs, grants nothing and lists
/// nothing. A device pinned to a listed machine, as a device an older build
/// dialled is, makes no difference: it grants neither direction.
#[test]
fn the_list_in_the_config_file_grants_nothing_with_or_without_the_trust_file() {
    run_local(async {
        let s = scratch("grant");
        let all = [
            (DESK, "desk mac"),
            (LAPTOP, "laptop"),
            (STRANGER, "stranger"),
            (PASSER, "passer"),
        ];
        let fps: Vec<&str> = all.iter().map(|(fp, _)| *fp).collect();
        let seen = |trust: &Trust| (granted(trust, &fps), listed_again(trust, &fps));

        // No trust file: the first start after the upgrade from 0.12.
        std::fs::write(
            s.0.join("config.toml"),
            with_a_device_for_the_laptop(&all[..2]),
        )
        .expect("a config");
        let (first, _) = start(&s.0, 1).await;
        let upgraded = seen(&first.trust);
        let pinned_at_upgrade = pinned(&first, LAPTOP);
        stop(first).await;

        // The trust file there: a line added while the daemon is stopped ...
        save_config(&s.0, &with_a_device_for_the_laptop(&all[..3]));
        let (mut second, _) = start(&s.0, 2).await;
        let added_while_stopped = seen(&second.trust);
        // ... and one added while it runs.
        let dir = s.0.clone();
        run_until(
            &mut second,
            Signal::Checked,
            move || save_config(&dir, &with_a_device_for_the_laptop(&all)),
            |service| service.config.listed_as_trusted().map(|t| t.len()) == Some(4),
        )
        .await;
        let added_while_running = seen(&second.trust);
        stop(second).await;

        // The trust file lost, with every line still in config.toml.
        std::fs::remove_file(s.0.join(crate::trust_file::TRUST_FILE_NAME)).expect("the trust file");
        let (third, _) = start(&s.0, 3).await;
        let rebuilt = seen(&third.trust);
        let pinned_when_rebuilt = pinned(&third, LAPTOP);
        stop(third).await;

        assert!(
            pinned_at_upgrade && pinned_when_rebuilt,
            "precondition: a device is pinned to the laptop at both starts with no trust \
             file (at the upgrade {pinned_at_upgrade}, once rebuilt {pinned_when_rebuilt})"
        );
        let none = Vec::<String>::new;
        let names = |fps: &[&str]| fps.iter().map(|fp| fp.to_string()).collect::<Vec<_>>();
        assert_eq!(
            (upgraded, added_while_stopped, added_while_running, rebuilt),
            (
                (none(), names(&[DESK, LAPTOP])),
                (none(), names(&[DESK, LAPTOP])),
                (none(), names(&[DESK, LAPTOP])),
                (none(), names(&fps)),
            ),
            "(granted anything, listed to pair again) with no trust file, after a line \
             was added while stopped, after one was added while running, and once the \
             trust file was lost: a list in config.toml granted a machine something, or \
             a line added beside the trust file listed one. The list never grants, with \
             or without the trust file (#231)."
        );
    });
}

// LEDGER R231-21 | class B | 6 trust store state and client pins across two starts + 2 event over the real IPC socket
/// The upgrade case of a removal in the file: the store holds what the 0.12
/// list named only to be paired again (#231). An older build removes the
/// laptop's line, and at the next start its listing goes, and so does the
/// pin of the device folded into it; the app is told by the laptop's name.
#[test]
fn a_machine_to_pair_again_removed_from_the_file_is_forgotten() {
    run_local(async {
        let s = scratch("again");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        std::fs::write(s.0.join("config.toml"), with_a_device_for_the_laptop(&both))
            .expect("a config");
        let (first, _) = start(&s.0, 1).await;
        let upgraded = (
            listed_again(&first.trust, &[DESK, LAPTOP]),
            pinned(&first, LAPTOP),
        );
        stop(first).await;

        // As an older build saves after removing the laptop.
        save_config(&s.0, &with_a_device_for_the_laptop(&both[..1]));
        let (mut second, endpoint) = start(&s.0, 2).await;
        let after = (
            listed_again(&second.trust, &[DESK, LAPTOP]),
            pinned(&second, LAPTOP),
        );
        let told = told_on_attach(&mut second, &s.0, &endpoint).await;
        stop(second).await;
        assert_eq!(
            (upgraded, after),
            (
                (vec![DESK.to_string(), LAPTOP.to_string()], true),
                (vec![DESK.to_string()], false),
            ),
            "((listed to pair again), a device pinned to the laptop) at the upgrade \
             and once an older build removed the laptop from config.toml: its \
             listing, or the pin of the device folded into it, was kept (#231)"
        );
        assert!(
            told.iter().any(|said| told_as_a_listing(said)),
            "the app was not told, by the laptop's name, that its listing to pair again \
             was removed, or was told a pairing was removed that it never held (#231): \
             {told:?}"
        );
    });
}

// LEDGER R231-22 | class B | 6 trust store state and client pins + 2 event over the real IPC socket, through the config watcher
/// A person removes, while the daemon runs, the line of a machine the store
/// lists to be paired again (#231): its listing goes, and so does the pin of
/// the device folded into it, and the app is told by its name.
#[test]
fn a_machine_to_pair_again_removed_from_the_file_while_running_is_forgotten() {
    run_local(async {
        let s = scratch("againlive");
        let both = [(DESK, "desk mac"), (LAPTOP, "laptop")];
        std::fs::write(s.0.join("config.toml"), with_a_device_for_the_laptop(&both))
            .expect("a config");
        let (mut service, endpoint) = start(&s.0, 1).await;
        let before = (
            listed_again(&service.trust, &[DESK, LAPTOP]),
            pinned(&service, LAPTOP),
        );
        let dir = s.0.clone();
        let told = notice_while_running(&mut service, &s.0, &endpoint, move || {
            save_config(&dir, &with_a_device_for_the_laptop(&both[..1]));
        })
        .await;
        let after = (
            listed_again(&service.trust, &[DESK, LAPTOP]),
            pinned(&service, LAPTOP),
        );
        stop(service).await;
        assert_eq!(
            (before, after),
            (
                (vec![DESK.to_string(), LAPTOP.to_string()], true),
                (vec![DESK.to_string()], false),
            ),
            "((listed to pair again), a device pinned to the laptop) before and after \
             the laptop's line was removed while the daemon ran (#231)"
        );
        assert!(
            told_as_a_listing(&told),
            "the app was not told, by the laptop's name, that its listing to pair again \
             was removed, or was told a pairing was removed that it never held (#231): \
             {told:?}"
        );
    });
}

// LEDGER R231-23 | class B | 6 trust store state across two starts + 5 file content on disk
/// The daemon's own save drops the 0.12 list from config.toml, since a
/// machine to pair again is not in the cache (#231). That is not a removal:
/// the listings stay at the next start, even when the save came while a
/// trust change could not reach disk, which keeps what is recorded.
#[test]
fn the_daemon_dropping_the_old_list_is_not_a_removal() {
    run_local(async {
        let s = scratch("dropped");
        std::fs::write(
            s.0.join("config.toml"),
            config_listing(&[(DESK, "desk mac")]),
        )
        .expect("a config");
        let (mut first, _) = start(&s.0, 1).await;
        // Every save of the trust store fails, as on a full disk, so the
        // pairing below waits to reach it as the config is saved.
        let staging =
            s.0.join(crate::trust_file::TRUST_FILE_NAME)
                .with_extension("toml.tmp");
        std::fs::create_dir_all(staging.join("in-the-way")).expect("block the store");
        pair_while_running(&mut first, LAPTOP, "laptop");
        let saved = std::fs::read_to_string(s.0.join("config.toml")).unwrap_or_default();
        stop(first).await;
        std::fs::remove_dir_all(&staging).expect("unblock the store");

        let (second, _) = start(&s.0, 2).await;
        let after = listed_again(&second.trust, &[DESK]);
        stop(second).await;
        assert!(
            !saved.contains(DESK),
            "precondition: the daemon's save kept the 0.12 list's line:\n{saved}"
        );
        assert_eq!(
            after,
            vec![DESK.to_string()],
            "the desk, listed to pair again, was forgotten because the daemon's own \
             save dropped its line from config.toml (#231)"
        );
    });
}

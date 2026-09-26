//! A trust change the daemon cannot write to disk is shown to the user, and
//! named (#215).
//!
//! Runs the built binary with dummy capture and emulation, and makes the
//! directory that holds the trust store read-only while a device is removed.
//! The change stays in effect in memory, so without a notice nothing looks
//! wrong until a restart rebuilds trust from the last file on disk. The retry
//! and the notice that the change is saved are tested on real files in
//! `trust_save`: here, a second trust change once the directory is writable
//! again would write the config too, and that write can hang the daemon on
//! macOS while the config watcher's queue is full, which is a separate defect.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{AsyncFrontendEventReader, FrontendEvent, FrontendRequest};

/// A device that is removed while the disk refuses writes.
const DESK: &str = "1e:19:1b:c4:a8:40:f5:26:37:39:9d:c7:c7:75:fe:17:\
4f:03:d5:a9:76:49:cd:b1:12:d1:2f:6c:1f:d2:22:c5";

/// The scratch home: removed at the end, writable again first.
struct Scratch {
    dir: PathBuf,
    config_dir: PathBuf,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        set_mode(&self.config_dir, 0o755);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Daemon {
    child: Child,
    log: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

fn set_mode(path: &Path, mode: u32) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

fn scratch() -> Scratch {
    // Short, for `sun_path` (about 104 bytes on macOS).
    let dir = PathBuf::from(format!("/tmp/h-tsave-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment. The frontend connector finds the
    // daemon's socket and token through them.
    unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
    }
    Scratch { dir, config_dir }
}

fn start(s: &Scratch) -> Daemon {
    let config = s.config_dir.join("config.toml");
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free port")
        .port();
    std::fs::write(
        &config,
        format!(
            "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n"
        ),
    )
    .expect("a config");
    let log = s.dir.join("daemon.log");
    let child = Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--config")
        .arg(&config)
        .arg("--cert-path")
        .arg(s.config_dir.join("lan-mouse.pem"))
        .arg("daemon")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &s.dir)
        .env("XDG_RUNTIME_DIR", &s.dir)
        .env("XDG_CONFIG_HOME", s.dir.join(".config"))
        .env("XDG_STATE_HOME", &s.dir)
        .env("HOPS_LOG_FILE", &log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts");
    let daemon = Daemon { child, log };
    let deadline = Instant::now() + Duration::from_secs(60);
    while !daemon.log().contains("service running; stops on") {
        assert!(
            Instant::now() < deadline,
            "the daemon never reported its service loop running; log:\n{}",
            daemon.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    daemon
}

/// The next `Error` notice within `within`, skipping every other event.
async fn next_error(events: &mut AsyncFrontendEventReader, within: Duration) -> Option<String> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, events.next()).await {
            Ok(Some(Ok(FrontendEvent::Error(e)))) => return Some(e),
            Ok(Some(_)) => continue,
            _ => return None,
        }
    }
}

/// Read up to the end of the state a frontend is sent when it attaches.
async fn attached(events: &mut AsyncFrontendEventReader) {
    loop {
        match tokio::time::timeout(PATIENCE, events.next()).await {
            Ok(Some(Ok(FrontendEvent::RevokedUpdated(_)))) => return,
            Ok(Some(_)) => continue,
            other => panic!("the daemon never sent its state: {other:?}"),
        }
    }
}

const PATIENCE: Duration = Duration::from_secs(10);

#[test]
fn a_trust_change_that_cannot_be_saved_is_shown_to_every_frontend() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let s = scratch();
        let daemon = start(&s);
        let (mut events, mut requests) = hops_ipc::connect_async(Some(PATIENCE))
            .await
            .expect("a frontend connects");
        attached(&mut events).await;

        set_mode(&s.config_dir, 0o555);
        assert!(
            std::fs::write(s.config_dir.join("probe"), b"").is_err(),
            "the trust directory still takes writes, so nothing here can fail to \
             save (a test run as root ignores the mode)"
        );
        requests
            .request(FrontendRequest::RemoveAuthorizedKey(DESK.into()))
            .await
            .expect("remove");
        let told = next_error(&mut events, PATIENCE).await.unwrap_or_else(|| {
            panic!(
                "a removal that could not be saved was not shown to the user; a \
                 restart would trust the device again. log:\n{}",
                daemon.log()
            )
        });
        assert!(
            told.contains("Could not save")
                && told.contains(&DESK[..11])
                && told.contains("every minute"),
            "the notice must say what was not saved, and that it is retried: {told:?}"
        );

        // A frontend that attaches while the change is unsaved is told too.
        let (mut late, _late_requests) = hops_ipc::connect_async(Some(PATIENCE))
            .await
            .expect("a second frontend connects");
        let told = next_error(&mut late, PATIENCE).await;
        assert!(
            told.as_deref()
                .is_some_and(|t| t.contains("Could not save") && t.contains(&DESK[..11])),
            "a frontend attaching while the removal is unsaved was not told: {told:?}; \
             log:\n{}",
            daemon.log()
        );
    });
}

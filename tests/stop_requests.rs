//! A daemon asked to stop by SIGTERM, which launchd, systemd and
//! `hops-ctl stop-daemon` send, leaves through its shutdown, where held keys
//! and buttons are released, instead of dying with them held (#197).
//!
//! Runs the built binary with dummy capture and emulation, discovery off, a
//! free port, and every path it could touch in a scratch directory.
#![cfg(unix)]

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn wait_for(log: &PathBuf, needle: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if std::fs::read_to_string(log).is_ok_and(|s| s.contains(needle)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// LEDGER T1 | class B | 5 process exit status + log lines
#[test]
fn sigterm_runs_the_shutdown_that_releases_held_input() {
    // Short, for `sun_path`.
    let dir = PathBuf::from(format!("/tmp/h-stop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");

    // A port nothing holds right now, so this never meets a running daemon.
    let port = UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free port")
        .port();
    let config = config_dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n"
        ),
    )
    .expect("a config");
    let log = dir.join("daemon.log");

    let mut daemon = Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--config")
        .arg(&config)
        .arg("--cert-path")
        .arg(config_dir.join("lan-mouse.pem"))
        .arg("daemon")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &dir)
        .env("XDG_RUNTIME_DIR", &dir)
        .env("XDG_CONFIG_HOME", dir.join(".config"))
        .env("XDG_STATE_HOME", &dir)
        .env("HOPS_LOG_FILE", &log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts");

    let ready = wait_for(&log, "service running; stops on", Duration::from_secs(60));
    if !ready {
        let _ = daemon.kill();
        let _ = daemon.wait();
        panic!(
            "the daemon never reported its service loop running; log:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
    }

    let sent = Command::new("kill")
        .arg("-TERM")
        .arg(daemon.id().to_string())
        .status()
        .expect("kill runs");
    assert!(sent.success(), "SIGTERM could not be sent");

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = daemon.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = daemon.kill();
            let _ = daemon.wait();
            panic!("the daemon was still running 30 s after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        status.success(),
        "SIGTERM ended the daemon with {status} instead of a clean shutdown; log:\n{text}"
    );
    assert!(
        text.contains("SIGTERM received") && text.contains("terminating service"),
        "the daemon exited without going through its shutdown; log:\n{text}"
    );
}

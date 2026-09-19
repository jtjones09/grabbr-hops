//! A second `hops daemon`, started while another holds the IPC endpoint, stops
//! before it reads or writes the config, the token or the identity key (#159,
//! decided 2026-09-16: at most one daemon).
//!
//! Runs the built binary. Everything it could touch is pointed at a scratch
//! directory, and the config there does not parse, so if the process ever got
//! past the claim it would exit on the config instead of running as a daemon.
//!
//! Unix only: the endpoint there is a socket under `HOME` or
//! `XDG_RUNTIME_DIR`, which the test can hold in a scratch directory. On
//! Windows it is a fixed loopback port, and this test never binds that.
#![cfg(unix)]

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// LEDGER T23 | class B | 5 process exit code and log line + 4 files on disk
#[test]
fn a_second_daemon_exits_as_already_running_before_reading_the_config() {
    // Short, for `sun_path`.
    let dir = PathBuf::from(format!("/tmp/h-2nd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    let socket = if cfg!(target_os = "macos") {
        dir.join("Library/Caches/lan-mouse-socket.sock")
    } else {
        dir.join("lan-mouse-socket.sock")
    };
    // The running daemon, as far as the second one can tell.
    let running = UnixListener::bind(&socket).expect("the first daemon's socket");

    let config = config_dir.join("config.toml");
    let unparseable = "port = \"not a port\"\n";
    std::fs::write(&config, unparseable).expect("a config");
    let cert = config_dir.join("lan-mouse.pem");
    let log = dir.join("daemon.log");

    let mut second = Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--config")
        .arg(&config)
        .arg("--cert-path")
        .arg(&cert)
        .arg("daemon")
        .env_clear()
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
    let deadline = Instant::now() + Duration::from_secs(30);
    let exit = loop {
        if let Some(status) = second.try_wait().expect("the process's status") {
            break Some(status.code());
        }
        if Instant::now() > deadline {
            let _ = second.kill();
            let _ = second.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    let config_after = std::fs::read_to_string(&config).unwrap_or_default();
    let token = config_dir.join("ipc-token").exists();
    let identity = cert.exists();
    drop(running);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        exit,
        Some(Some(0)),
        "a second daemon beside a running one did not exit 0 as already running. \
         Exiting 1 on the config means it read the config before its claim, and \
         launchd restarts a daemon that exits 1. Its log:\n{logged}"
    );
    assert!(
        logged.contains("already running"),
        "the second daemon exited 0 without saying a daemon is already running. \
         Its log:\n{logged}"
    );
    assert_eq!(
        (config_after.as_str(), token, identity),
        (unparseable, false, false),
        "(config, created a token, created an identity). A second daemon touched \
         what the running daemon holds before it found the endpoint taken."
    );
}

//! On Windows, hops 0.12 and older listened on 127.0.0.1:5252 and this build
//! listens on a named pipe, so a daemon of this build did not see one of 0.12
//! and ran beside it, with the same identity and config (#222: at most one
//! daemon). A `hops daemon` started while a 0.12 daemon answers there exits
//! before it mints its token, reads the config or makes its key, and says how
//! to stop the old one and its sign-in task.
//!
//! Runs the built binary against a stand-in for the 0.12 daemon on that port,
//! which, as 0.12 does, sends its state to whatever connects. Everything the
//! binary could touch is pointed at a scratch directory, and the config there
//! does not parse, so a daemon that got past the check exits on the config
//! instead of running, having made its token.
//!
//! And the other way round: a daemon of this build, once running, holds
//! that port, so a 0.12 daemon started after it finds it taken and exits.
//!
//! Windows only: nowhere else did an older build listen where this build's
//! endpoint does not reach.
#![cfg(windows)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Held by each test while it uses 127.0.0.1:5252, which they share.
static OLD_PORT: Mutex<()> = Mutex::new(());

/// `hops daemon` with everything it could touch in `dir`, logging to `log`.
fn daemon_in(dir: &Path, config: &Path, log: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--config")
        .arg(config)
        .arg("--cert-path")
        .arg(config.with_file_name("lan-mouse.pem"))
        .arg("daemon")
        .env("LOCALAPPDATA", dir)
        .env("APPDATA", dir)
        .env("HOPS_LOG_FILE", log)
        .env("HOPS_LOG_LEVEL", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts")
}

/// A hops 0.12 daemon on its endpoint: its first words to any connection
/// are its state.
fn hops_0_12() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:5252")
        .expect("127.0.0.1:5252 is free on the test machine, for a stand-in hops 0.12 daemon");
    let serving = listener.try_clone().expect("the listener");
    std::thread::spawn(move || {
        for stream in serving.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let _ = stream.write_all(b"{\"Enumerate\":[]}\n{\"PortChanged\":[4242,null]}\n");
                let mut sink = [0u8; 256];
                while matches!(stream.read(&mut sink), Ok(1..)) {}
            });
        }
    });
    listener
}

// LEDGER T2269 | class B | 5 process exit code and log line + 4 files on disk
#[test]
fn a_daemon_exits_beside_a_0_12_daemon_before_it_touches_anything() {
    let _port = OLD_PORT.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("h-old-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join("lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    let config = config_dir.join("config.toml");
    std::fs::write(&config, "port = \"not a port\"\n").expect("a config");
    let cert = config_dir.join("lan-mouse.pem");
    let log = dir.join("daemon.log");
    let old = hops_0_12();

    let mut daemon = daemon_in(&dir, &config, &log);
    let deadline = Instant::now() + Duration::from_secs(60);
    let exit = loop {
        if let Some(status) = daemon.try_wait().expect("the process's status") {
            break Some(status.code());
        }
        if Instant::now() > deadline {
            let _ = daemon.kill();
            let _ = daemon.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    let token = config_dir.join("ipc-token").exists();
    let identity = cert.exists();
    drop(old);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        (exit, token, identity),
        (Some(Some(1)), false, false),
        "(exit code, token made, key made) of a daemon started beside a hops 0.12 \
         daemon; it must exit 1 before touching anything:\n{logged}"
    );
    for needed in [
        "older hops daemon",
        "Unregister-ScheduledTask -TaskName hops-daemon",
        "-Name hops-daemon,hops-gui",
        "-LocalPort 5252",
    ] {
        assert!(
            logged.contains(needed),
            "the log must say why the daemon did not start and how to stop the old \
             one; missing {needed:?} in:\n{logged}"
        );
    }
}

/// A daemon of this build, killed and its directory removed when the test
/// ends, however it ends.
struct Running(Child, PathBuf);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

// LEDGER T2281 | class B | 5 log line + a bind on the real port, against the built binary
#[test]
fn a_running_daemon_holds_the_0_12_port() {
    let _port = OLD_PORT.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("h-hold-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join("lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    let config = config_dir.join("config.toml");
    std::fs::write(
        &config,
        "port = 0\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\n\
         discovery = false\n",
    )
    .expect("a config");
    let log = dir.join("daemon.log");
    let mut daemon = Running(daemon_in(&dir, &config, &log), dir.clone());

    // The service loop is logged as running only after the port is taken.
    let read = || std::fs::read_to_string(&log).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !read().contains("service running; stops on") {
        let ended = daemon.0.try_wait().expect("the process's status");
        assert!(
            ended.is_none() && Instant::now() < deadline,
            "the daemon never reported its service loop running ({ended:?}):\n{}",
            read()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let taken = TcpListener::bind("127.0.0.1:5252").map(drop);
    let logged = read();
    drop(daemon);
    assert_eq!(
        taken.map_err(|e| e.kind()),
        Err(std::io::ErrorKind::AddrInUse),
        "a hops 0.12 daemon started now could take 127.0.0.1:5252 and run beside \
         this one:\n{logged}"
    );
}

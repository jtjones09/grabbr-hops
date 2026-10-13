//! A daemon the front door starts that exits on its config is reported as
//! exited, with the file that says why, not as running (#159).
//!
//! Runs the built binary as the started daemon. Everything it could touch is
//! pointed at a scratch directory, and the config there does not parse, so it
//! claims its endpoint, mints a token and exits: the start that used to be
//! logged as "the daemon is running".
//!
//! Unix only: the endpoint there is a socket under `HOME` or
//! `XDG_RUNTIME_DIR`, which the test can put in a scratch directory. On
//! Windows it is a fixed loopback port, and this test never binds that.
#![cfg(unix)]

use std::cell::Cell;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hops::daemon_start::{DaemonStart, ThisMachine, Watch, ensure_running_reported_with};

// LEDGER T40 | class B | 5 process exit and log file + 1 return value (T64: the report's text)
#[test]
fn a_started_daemon_that_exits_on_its_config_is_reported_as_exited() {
    // Short, for `sun_path`.
    let dir = PathBuf::from(format!("/tmp/h-fail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    let config = config_dir.join("config.toml");
    std::fs::write(&config, "port = \"not a port\"\n").expect("a config");
    let log = dir.join("daemon.log");
    let env = [
        ("HOME", dir.clone()),
        ("XDG_RUNTIME_DIR", dir.clone()),
        ("XDG_CONFIG_HOME", dir.join(".config")),
        ("XDG_STATE_HOME", dir.clone()),
        ("HOPS_LOG_FILE", log.clone()),
    ];
    // The front door's own view: the endpoint, token and log file it works
    // out, all in the scratch directory.
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment.
    unsafe {
        for (name, value) in &env {
            std::env::set_var(name, value);
        }
    }

    let started = Cell::new(None);
    let start = || {
        let mut daemon = Command::new(env!("CARGO_BIN_EXE_hops"))
            .arg("--config")
            .arg(&config)
            .arg("--cert-path")
            .arg(config_dir.join("lan-mouse.pem"))
            .arg("daemon")
            .env_clear()
            .envs(env.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = daemon.id();
        started.set(Some(pid));
        // As the front door does: reaped when it exits, and not before.
        std::thread::spawn(move || daemon.wait());
        Ok(pid)
    };
    let within = Duration::from_secs(20);
    let began = Instant::now();
    let report = ensure_running_reported_with(start, &mut ThisMachine, within);
    let got = report.outcome;
    let took = began.elapsed();
    let named = ThisMachine.log_file();
    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    let pid = started.get().expect("the front door started a daemon");
    assert_eq!(
        got,
        DaemonStart::Exited(pid),
        "the daemon exited on its config, and the front door reported {got:?}. \
         It used to log \"the daemon is running as process {pid}\". Its log:\n{logged}"
    );
    assert!(
        took < within / 2,
        "the daemon had exited, and the front door waited {took:?} of {within:?}"
    );
    assert_eq!(
        named.as_deref(),
        Some(log.as_path()),
        "the front door names a different file from the one the daemon logs to"
    );
    assert!(
        logged.contains("could not be parsed"),
        "the file the front door names does not say why the daemon exited:\n{logged}"
    );
    // What the app shows instead of "connecting" (#189).
    let shown = report.problem().unwrap_or_default();
    assert!(
        shown.contains("stopped again before it answered")
            && shown.contains(&log.display().to_string()),
        "the app is not told the service stopped, or where it says why: {shown:?}"
    );
}

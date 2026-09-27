//! The front door against a real daemon on Linux (#222): a daemon of another
//! build that the service runs is stopped and replaced, and one of this build
//! is left running.
//!
//! Runs the built binary as the daemon, detached into a session of its own as
//! the front door starts it, with dummy capture and emulation, discovery off,
//! a free port, and every path it could touch in a scratch directory. What the
//! front door asks is real: the daemon's build over IPC, the process behind
//! the socket from the kernel, and `/proc`. Only "this build" is made up, so
//! the daemon counts as another build.
//!
//! Runs in its own test binary, so pointing `HOME` and the XDG directories at
//! the scratch directory cannot disturb anything else.
#![cfg(target_os = "linux")]

mod common;

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hops::daemon_start::{
    DaemonStart, Launch, ThisMachine, start_or_restart_reported, stop_outdated_daemon,
};
use hops_ipc::{Build, DaemonEndpoint};

const WITHIN: Duration = Duration::from_secs(30);

/// The scratch directory and the config every daemon here runs with.
struct Scratch {
    dir: PathBuf,
    config: PathBuf,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn scratch() -> Scratch {
    // Short, for `sun_path`.
    let dir = PathBuf::from(format!("/tmp/h-rst-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    let config = config_dir.join("config.toml");
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment. The front door finds the daemon's
    // socket and token through them.
    unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
        std::env::set_var("XDG_STATE_HOME", &dir);
    }
    Scratch { dir, config }
}

/// Start `hops daemon` the way the front door does: in a session of its own,
/// so it has no controlling terminal, on a port of its own. Waits until its
/// loop runs.
fn daemon(scratch: &Scratch, log: &Path) -> Child {
    let (child, _) = common::launch(
        &scratch.config,
        |port| {
            format!(
                "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n"
            )
        },
        log,
        || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_hops"));
            command
                .arg("--config")
                .arg(&scratch.config)
                .arg("daemon")
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("HOME", &scratch.dir)
                .env("XDG_RUNTIME_DIR", &scratch.dir)
                .env("XDG_CONFIG_HOME", scratch.dir.join(".config"))
                .env("XDG_STATE_HOME", &scratch.dir)
                .env("HOPS_LOG_FILE", log)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // SAFETY: setsid is async-signal-safe and touches only the child.
            unsafe {
                command.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
            command.spawn().expect("the hops binary starts")
        },
    );
    child
}

/// The build the binary names for itself: `hops <version> (<commit>)`.
fn build_of_the_binary() -> Build {
    let out = Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--version")
        .output()
        .expect("hops --version runs");
    let text = String::from_utf8_lossy(&out.stdout);
    let words: Vec<&str> = text.split_whitespace().collect();
    let [.., version, commit] = words.as_slice() else {
        panic!("`hops --version` printed {text:?}");
    };
    Build {
        version: version.to_string(),
        commit: commit.trim_matches(|c| c == '(' || c == ')').to_string(),
    }
}

/// Wait until `child` has exited, and say whether it did by `within`.
fn exits(child: &mut Child, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// LEDGER T2229 | class B | 5 processes started and stopped + 1 return value, over the real IPC socket and /proc
#[test]
fn an_outdated_daemon_is_replaced_and_one_of_this_build_is_left_running() {
    let scratch = scratch();
    let endpoint = DaemonEndpoint::of_this_platform().expect("the scratch endpoint");
    let mut old = daemon(&scratch, &scratch.dir.join("old.log"));
    let ours = build_of_the_binary();

    // The daemon is this build: nothing is launched, and it keeps running.
    let mut launched = Vec::new();
    let same = start_or_restart_reported(
        Ok(endpoint.clone()),
        &ours,
        |launch| {
            launched.push(launch);
            Err(std::io::Error::other("not to be asked"))
        },
        &mut ThisMachine,
        WITHIN,
    );
    let old_still_runs = matches!(old.try_wait(), Ok(None));

    // The app is another build: the daemon is stopped, and the one the
    // restart starts serves in its place.
    let mut new = None;
    let other = Build {
        version: "0.0.0".into(),
        commit: "notthis".into(),
    };
    let replaced = start_or_restart_reported(
        Ok(endpoint.clone()),
        &other,
        |launch| {
            let Launch::Restart(pid) = launch else {
                return Err(std::io::Error::other(format!("asked to {launch:?}")));
            };
            stop_outdated_daemon(pid, &endpoint, WITHIN)?;
            let started = daemon(&scratch, &scratch.dir.join("new.log"));
            let id = started.id();
            new = Some((pid, started));
            Ok(id)
        },
        &mut ThisMachine,
        WITHIN,
    );
    let old_pid = old.id();
    let old_exited = exits(&mut old, WITHIN);
    let (asked_to_stop, mut new) = new.expect("a restart was asked for");
    let new_pid = new.id();
    let _ = new.kill();
    let _ = new.wait();
    if !old_exited {
        let _ = old.kill();
        let _ = old.wait();
    }

    assert_eq!(
        (same.outcome, launched, old_still_runs),
        (DaemonStart::AlreadyRunning, vec![], true),
        "a daemon of this build was answering, and the front door did something \
         about it: {same:?}"
    );
    assert_eq!(
        (replaced.outcome, asked_to_stop, old_exited),
        (DaemonStart::Started(new_pid), old_pid, true),
        "the daemon runs {ours}, the app {other}, and the service started it; it \
         had to be stopped and replaced: {replaced:?}\nold log:\n{}",
        std::fs::read_to_string(scratch.dir.join("old.log")).unwrap_or_default()
    );
    let note = replaced.note().unwrap_or_default();
    assert!(
        note.contains(&format!("hops {ours}")),
        "the app must say it restarted the service, and which build it ran: {note:?}"
    );
}

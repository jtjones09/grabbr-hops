//! The enter hook is run as a program with arguments, never through a shell
//! (#108).
//!
//! Runs the built binary with dummy capture and emulation. The dummy capture
//! backend crosses at the left edge, so a device placed there is entered and
//! its hook runs. The hook's arguments hold a `;`: a shell would split the
//! command there, and a program run directly receives it as part of an
//! argument.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
    dir: PathBuf,
    log: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Daemon {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// Start a daemon with one device on the left whose enter hook is `hook`,
/// with `{out}` replaced by a directory the test reads afterwards.
fn start(hook: &str) -> (Daemon, PathBuf) {
    let dir = PathBuf::from(format!("/tmp/h-hook-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    let out = dir.join("out");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    std::fs::create_dir_all(&out).expect("a directory for the hook to write in");
    let free_port = || {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .expect("a free port")
            .port()
    };
    let (port, device_port) = (free_port(), free_port());
    let hook = hook.replace("{out}", &out.display().to_string());
    let config = config_dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "port = {port}\n\
             capture_backend = \"dummy\"\n\
             emulation_backend = \"dummy\"\n\
             discovery = false\n\
             \n\
             [[clients]]\n\
             position = \"left\"\n\
             hostname = \"127.0.0.1\"\n\
             ips = [\"127.0.0.1\"]\n\
             port = {device_port}\n\
             activate_on_startup = true\n\
             enter_hook = {}\n",
            toml_string(&hook)
        ),
    )
    .expect("a config");
    let log = dir.join("daemon.log");
    let child = Command::new(env!("CARGO_BIN_EXE_hops"))
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
        // A hook that mangles a path must not leave files in the checkout.
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts");
    (Daemon { child, dir, log }, out)
}

/// `s` as a TOML basic string.
fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

// LEDGER T64 | class B | 4 file on disk
#[test]
fn the_enter_hook_runs_as_a_program_and_never_through_a_shell() {
    let (daemon, out) = start(r#"touch "{out}/quoted name" {out}/semi;touch {out}/after"#);

    // `after` is the last file the hook creates, with or without a shell.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !out.join("after").exists() {
        assert!(
            Instant::now() < deadline,
            "the enter hook did not create `after` within 60 s; it created {:?}; \
             log:\n{}",
            names_in(&out),
            daemon.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    assert_eq!(
        names_in(&out),
        vec![
            "after".to_string(),
            "quoted name".to_string(),
            "semi;touch".to_string()
        ],
        "the enter hook ran through a shell, or its quoting was lost. A shell \
         splits the hook at `;` into two commands and creates `semi`; a program \
         run directly is handed `semi;touch` as one argument. Quotes must still \
         group `quoted name` into one argument; log:\n{}",
        daemon.log()
    );
    // The arguments may hold secrets: only the program is logged by default.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !daemon.log().contains("exited successfully") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        daemon.log().contains("the enter hook `touch`") && !daemon.log().contains("quoted name"),
        "the daemon's log names the enter hook's arguments, or not its program; \
         log:\n{}",
        daemon.log()
    );
}

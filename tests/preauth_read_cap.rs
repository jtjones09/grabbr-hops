//! A local process that has not presented the IPC token cannot grow the
//! daemon's memory (#175).
//!
//! Runs the built binary, streams one very long line with no newline at its
//! frontend socket, and measures the daemon's resident memory with `ps`.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
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

    /// Resident memory in KiB, as `ps` reports it on macOS and Linux.
    fn rss_kib(&self) -> u64 {
        let out = Command::new("ps")
            .args(["-o", "rss=", "-p", &self.child.id().to_string()])
            .output()
            .expect("ps runs");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("ps gave no RSS for the daemon: {out:?}"))
    }
}

fn start() -> (Daemon, PathBuf) {
    // Short, for `sun_path` (about 104 bytes on macOS).
    let dir = PathBuf::from(format!("/tmp/h-cap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment. They name the daemon's socket.
    unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
    }
    let hops_ipc::DaemonEndpoint::Unix(socket) =
        hops_ipc::DaemonEndpoint::of_this_platform().expect("a socket path")
    else {
        unreachable!("the endpoint is a Unix socket on Unix")
    };
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
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
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts");
    let daemon = Daemon { child, dir, log };
    let deadline = Instant::now() + Duration::from_secs(60);
    while !daemon.log().contains("service running; stops on") {
        assert!(
            Instant::now() < deadline,
            "the daemon never reported its service loop running; log:\n{}",
            daemon.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    (daemon, socket)
}

// LEDGER T62 | class B | 5 process
#[test]
fn a_client_without_the_token_cannot_grow_the_daemon() {
    const TOTAL: usize = 128 * 1024 * 1024;
    let (daemon, socket) = start();
    let before = daemon.rss_kib();

    let mut client = UnixStream::connect(&socket).expect("the daemon's socket accepts");
    client
        .set_write_timeout(Some(Duration::from_secs(20)))
        .expect("a write timeout");
    let chunk = vec![b'x'; 1024 * 1024];
    let mut sent = 0;
    let mut refused = None;
    while sent < TOTAL {
        match client.write(&chunk) {
            Ok(0) => {
                refused = Some("a write of zero bytes".to_string());
                break;
            }
            Ok(n) => sent += n,
            Err(e) => {
                refused = Some(e.to_string());
                break;
            }
        }
    }
    // Let the daemon read what is still in flight.
    std::thread::sleep(Duration::from_millis(500));
    let grew_mib = daemon.rss_kib().saturating_sub(before) / 1024;

    assert!(
        grew_mib < 32,
        "the daemon's resident memory grew by {grew_mib} MiB while a client that \
         never presented the IPC token sent {} MiB of one unterminated line. Any \
         local process that can reach the socket can grow it until it is killed; \
         log:\n{}",
        sent / (1024 * 1024),
        daemon.log()
    );
    assert!(
        refused.is_some() && sent < 4 * 1024 * 1024,
        "the daemon kept reading {sent} bytes of one unterminated line from a \
         client that never presented the IPC token, and did not hang up \
         (refused: {refused:?}); log:\n{}",
        daemon.log()
    );
}

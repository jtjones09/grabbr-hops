//! A local process that has not presented the IPC token cannot grow the
//! daemon's memory (#175): not with one long line, and not with many idle
//! connections.
//!
//! Runs the built binary against its frontend socket, and measures the
//! daemon's resident memory with `ps`.
#![cfg(unix)]

use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
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

/// The one socket under `dir`: the daemon's frontend endpoint.
fn find_socket(dir: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let kind = entry.file_type().ok()?;
        if kind.is_socket() {
            return Some(entry.path());
        }
        if kind.is_dir() {
            if let Some(found) = find_socket(&entry.path()) {
                return Some(found);
            }
        }
    }
    None
}

fn start(tag: &str) -> (Daemon, PathBuf) {
    // Short, for `sun_path` (about 104 bytes on macOS).
    let dir = PathBuf::from(format!("/tmp/h-cap-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
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
    let socket = find_socket(&daemon.dir).expect("the daemon's frontend socket");
    (daemon, socket)
}

/// Whether the daemon closed `client`, waiting up to `wait` for it to.
fn hung_up(client: &mut UnixStream, wait: Duration) -> bool {
    // macOS refuses socket options, with EINVAL, on a socket its peer has
    // already closed.
    if client.set_read_timeout(Some(wait)).is_err() {
        return true;
    }
    let mut buf = [0u8; 64];
    match client.read(&mut buf) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
    }
}

// LEDGER T62 | class B | 5 process
#[test]
fn a_client_without_the_token_cannot_grow_the_daemon() {
    const TOTAL: usize = 128 * 1024 * 1024;
    let (daemon, socket) = start("line");
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
        refused.is_some() && sent < 4 * 1024 * 1024 && hung_up(&mut client, Duration::from_secs(5)),
        "the daemon took {sent} bytes of one unterminated line from a \
         client that never presented the IPC token, and did not hang up \
         (refused: {refused:?}); log:\n{}",
        daemon.log()
    );
}

// LEDGER T72 | class B | 5 process
#[test]
fn idle_clients_without_the_token_are_capped_then_closed() {
    const CLIENTS: usize = 3 * hops_ipc::PREAUTH_CONNECTIONS_MAX;
    let (daemon, socket) = start("idle");
    let mut clients: Vec<UnixStream> = (0..CLIENTS)
        .map(|_| {
            let mut c = UnixStream::connect(&socket).expect("the daemon's socket accepts");
            let _ = c.write_all(&[b'x'; 100]);
            c
        })
        .collect();

    std::thread::sleep(Duration::from_secs(1));
    let at_once = clients
        .iter_mut()
        .filter_map(|c| hung_up(c, Duration::from_millis(10)).then_some(()))
        .count();
    let kept = CLIENTS - at_once;
    assert!(
        kept <= hops_ipc::PREAUTH_CONNECTIONS_MAX,
        "the daemon holds {kept} idle connections that never presented the IPC \
         token; at most {} may wait. Without a cap any local process can open \
         thousands, each with its read buffer; log:\n{}",
        hops_ipc::PREAUTH_CONNECTIONS_MAX,
        daemon.log()
    );

    let give_up = Instant::now() + hops_ipc::PREAUTH_DEADLINE + Duration::from_secs(10);
    let open = clients
        .iter_mut()
        .filter_map(|c| {
            let wait = give_up.saturating_duration_since(Instant::now());
            (!hung_up(c, wait.max(Duration::from_millis(1)))).then_some(())
        })
        .count();
    assert!(
        open == 0,
        "{} connections that never presented the IPC token were still open {:?} \
         after they connected; log:\n{}",
        open,
        hops_ipc::PREAUTH_DEADLINE + Duration::from_secs(11),
        daemon.log()
    );
}

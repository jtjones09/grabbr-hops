//! A device added while add device is open is dialled at once and then every
//! second, without waiting for the pointer to cross to it, and only then
//! (#195).
//!
//! Runs the built binary with dummy capture and emulation. The dummy capture
//! backend only ever crosses at the left edge, so the device goes on the right:
//! any dial the receiver sees came from adding it. The receiver is a QUIC
//! server that counts connection attempts.
#![cfg(unix)]

use std::cell::Cell;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{AsyncFrontendEventReader, FrontendEvent, FrontendRequest, Position};

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

fn start() -> (Daemon, u16) {
    // Short, for `sun_path` (about 104 bytes on macOS).
    let dir = PathBuf::from(format!("/tmp/h-add-{}", std::process::id()));
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
    (daemon, port)
}

/// A receiver that counts every connection attempt made to it.
fn counting_receiver() -> (u16, Rc<Cell<u32>>) {
    let key = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec!["grabbr".to_owned()])
        .expect("params")
        .self_signed(&key)
        .expect("self signed");
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).expect("key der"),
        )
        .expect("server cert");
    crypto.alpn_protocols = vec![b"grabbr-hop/1".to_vec()];
    let cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic server"),
    ));
    let ep = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().expect("addr")).expect("server");
    let port = ep.local_addr().expect("local addr").port();
    let attempts = Rc::new(Cell::new(0));
    let counted = attempts.clone();
    tokio::task::spawn_local(async move {
        while let Some(incoming) = ep.accept().await {
            counted.set(counted.get() + 1);
            tokio::task::spawn_local(async move {
                let _ = incoming.await;
            });
        }
    });
    (port, attempts)
}

/// Ask the daemon for a new device pointed at the receiver; return its handle.
async fn add_device(
    events: &mut AsyncFrontendEventReader,
    requests: &mut hops_ipc::AsyncFrontendRequestWriter,
    port: u16,
) -> u64 {
    requests
        .request(FrontendRequest::Create)
        .await
        .expect("create");
    let handle = loop {
        match tokio::time::timeout(Duration::from_secs(10), events.next()).await {
            Ok(Some(Ok(FrontendEvent::Created(handle, _, _)))) => break handle,
            Ok(Some(_)) => continue,
            other => panic!("no Created event: {other:?}"),
        }
    };
    for r in [
        FrontendRequest::UpdateHostname(handle, Some("127.0.0.1".into())),
        // Pinned, so the address is known the moment the device is switched on
        // and the first dial really reaches the receiver, as it does for a
        // device picked from the network list.
        FrontendRequest::UpdateFixIps(handle, vec!["127.0.0.1".parse().expect("ip")]),
        FrontendRequest::UpdatePort(handle, port),
        // The dummy capture backend crosses at the left edge only, a thousand
        // times a second. On the right, nothing ever crosses to this device.
        FrontendRequest::UpdatePosition(handle, Position::Right),
    ] {
        requests.request(r).await.expect("configure");
    }
    handle
}

async fn settle(for_: Duration) {
    tokio::time::sleep(for_).await;
}

#[test]
fn a_device_added_while_pairing_is_open_is_dialled_until_switched_off() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let (daemon, _) = start();
        let (mut events, mut requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
            .await
            .expect("a frontend connects");
        let (port, attempts) = counting_receiver();
        let handle = add_device(&mut events, &mut requests, port).await;

        // Switched on with add device closed: nothing dials it.
        requests
            .request(FrontendRequest::Activate(handle, true))
            .await
            .expect("activate");
        settle(Duration::from_secs(3)).await;
        assert_eq!(
            attempts.get(),
            0,
            "a device switched on with add device closed was dialled; log:\n{}",
            daemon.log()
        );

        // Switched on again with add device open: dialled, and again.
        requests
            .request(FrontendRequest::Activate(handle, false))
            .await
            .expect("deactivate");
        requests
            .request(FrontendRequest::OpenPairing)
            .await
            .expect("open");
        requests
            .request(FrontendRequest::Activate(handle, true))
            .await
            .expect("activate");
        settle(Duration::from_secs(4)).await;
        let dialled = attempts.get();
        assert!(
            dialled >= 3,
            "a device added with add device open was dialled {dialled} time(s) in 4 s, \
             with no crossing; expected about one a second; log:\n{}",
            daemon.log()
        );

        // Switched off: the dialling stops.
        requests
            .request(FrontendRequest::Activate(handle, false))
            .await
            .expect("deactivate");
        settle(Duration::from_secs(2)).await;
        let at_off = attempts.get();
        settle(Duration::from_secs(3)).await;
        assert_eq!(
            attempts.get(),
            at_off,
            "the device was still being dialled after it was switched off; log:\n{}",
            daemon.log()
        );
    });
}

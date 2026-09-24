//! A stranger's knock raises a pairing prompt only while add device is open on
//! the machine it knocks on (#195).
//!
//! Runs the built binary with dummy capture and emulation, discovery off, a
//! free port, and every path it could touch in a scratch directory. The
//! stranger is a QUIC client with a certificate the daemon has never seen,
//! which is exactly what an unknown machine on the network is. The frontend is
//! the real IPC connector.
//!
//! Runs in its own test binary, so pointing `HOME` and the XDG directories at
//! the scratch directory cannot disturb anything else.
#![cfg(unix)]

use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{AsyncFrontendEventReader, AttemptOrigin, FrontendEvent, FrontendRequest};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

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
    let dir = PathBuf::from(format!("/tmp/h-pair-{}", std::process::id()));
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

/// Accepts any server certificate: the stranger does not care who answers.
#[derive(Debug)]
struct AnyServer;

impl ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A machine the daemon has never seen dials it, with a fresh certificate.
/// The daemon refuses the handshake; what matters is whether it prompts.
async fn knock(port: u16) {
    let key = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec!["grabbr".to_owned()])
        .expect("params")
        .self_signed(&key)
        .expect("self signed");
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer))
        .with_client_auth_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::try_from(key.serialize_der()).expect("key der"),
        )
        .expect("client auth");
    crypto.alpn_protocols = vec![b"grabbr-hop/1".to_vec()];
    let cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic client"),
    ));
    let ep = quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
    let at: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    if let Ok(connecting) = ep.connect_with(cfg, at, "grabbr") {
        // Refused, whether the daemon says so during the handshake or just after.
        if let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(5), connecting).await {
            let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
        }
    }
}

/// Every pairing prompt the frontend receives within `within`.
async fn prompts(events: &mut AsyncFrontendEventReader, within: Duration) -> Vec<AttemptOrigin> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.next()).await {
        if let Ok(FrontendEvent::ConnectionAttempt { origin, .. }) = event {
            seen.push(origin);
        }
    }
    seen
}

#[tokio::test(flavor = "current_thread")]
async fn a_stranger_prompts_only_while_add_device_is_open() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (daemon, port) = start();
    let (mut events, mut requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
        .await
        .expect("a frontend connects");

    knock(port).await;
    let before = prompts(&mut events, Duration::from_secs(3)).await;
    assert!(
        before.is_empty(),
        "a stranger raised {} pairing prompt(s) with add device closed; log:\n{}",
        before.len(),
        daemon.log()
    );
    assert!(
        daemon.log().contains("refused a pairing request"),
        "the refused knock was not logged; log:\n{}",
        daemon.log()
    );

    requests
        .request(FrontendRequest::OpenPairing)
        .await
        .expect("request sent");
    knock(port).await;
    let after = prompts(&mut events, Duration::from_secs(5)).await;
    assert_eq!(
        after,
        vec![AttemptOrigin::Inbound],
        "with add device open, a stranger's knock must raise exactly one prompt; log:\n{}",
        daemon.log()
    );
}

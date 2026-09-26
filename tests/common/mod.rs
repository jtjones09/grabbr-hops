//! The built daemon, a frontend attached to it, and a peer that speaks the
//! wire protocol, for tests that watch what the frontend is told.
//!
//! The daemon runs with dummy capture and emulation, discovery off, a free
//! port, and every path it could touch in a scratch directory.
// Each test binary that includes this uses part of it.
#![allow(dead_code)]

use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{AsyncFrontendEventReader, FrontendEvent};
use hops_proto::{MAX_EVENT_SIZE, ProtoEvent};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

pub struct Daemon {
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
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// Start the built daemon in a scratch directory named for `tag`, with
/// `tables` appended to its config, and return it with the port it listens
/// on.
///
/// Points `HOME` and the XDG directories of this process at the scratch
/// directory, which is how the frontend connector finds the daemon's socket
/// and token. So call it once per test binary, before anything that reads
/// the environment.
pub fn start(tag: &str, tables: &str) -> (Daemon, u16) {
    // Short, for `sun_path` (about 104 bytes on macOS).
    let dir = PathBuf::from(format!("/tmp/{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    // SAFETY: each test binary including this has one test, which calls this
    // before it starts anything that reads the environment.
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
            "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n\n{tables}"
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
    // Starting writes the token, keys and trust files next to the config, and
    // the config watcher reports each. A config write while those are still
    // queued can stop the daemon on macOS (a defect of the watcher, not of
    // what these tests are about), so let it drain them first.
    std::thread::sleep(Duration::from_secs(1));
    (daemon, port)
}

/// Wait at most `within` for a frontend event `pick` accepts, and return
/// what it made of it. `None` if none came.
pub async fn next_matching<T>(
    events: &mut AsyncFrontendEventReader,
    within: Duration,
    mut pick: impl FnMut(FrontendEvent) -> Option<T>,
) -> Option<T> {
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.next()).await {
        if let Some(found) = event.ok().and_then(&mut pick) {
            return Some(found);
        }
    }
    None
}

/// A certificate and its key: one machine's identity.
pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl Identity {
    pub fn new() -> Identity {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let cert = rcgen::CertificateParams::new(vec!["grabbr".to_owned()])
            .expect("params")
            .self_signed(&key)
            .expect("self signed");
        Identity {
            cert: cert.der().clone(),
            key: PrivateKeyDer::try_from(key.serialize_der()).expect("key der"),
        }
    }

    /// The fingerprint the daemon knows this machine by.
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        sha2::Sha256::digest(self.cert.as_ref())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Dial as this machine, accepting whatever certificate answers.
    pub fn client_config(&self) -> quinn::ClientConfig {
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyServer))
            .with_client_auth_cert(vec![self.cert.clone()], self.key.clone_key())
            .expect("client auth");
        crypto.alpn_protocols = vec![b"grabbr-hop/1".to_vec()];
        quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic client"),
        ))
    }

    /// Answer dials as this machine, asking the dialler for no certificate.
    pub fn server_config(&self) -> quinn::ServerConfig {
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
            .expect("server cert");
        crypto.alpn_protocols = vec![b"grabbr-hop/1".to_vec()];
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic server"),
        ))
    }

    /// Dial the daemon's listener from a fresh socket. `None` if it refused.
    /// The endpoint comes back with the connection, to be kept as long as it.
    pub async fn dial(&self, port: u16) -> Option<(quinn::Endpoint, quinn::Connection)> {
        let ep = quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
        let at: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let connecting = ep.connect_with(self.client_config(), at, "grabbr").ok()?;
        let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .ok()?
            .ok()?;
        // A refused client certificate closes the connection just after the
        // handshake completes, so an admitted one is one that stays up.
        match tokio::time::timeout(Duration::from_millis(500), conn.closed()).await {
            Ok(_) => None,
            Err(_) => Some((ep, conn)),
        }
    }
}

/// Accepts any server certificate.
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

/// Write one event as the daemon frames it: a length byte, then the event.
pub async fn write(send: &mut quinn::SendStream, event: ProtoEvent) {
    let (buf, len): ([u8; MAX_EVENT_SIZE], usize) = event.into();
    let mut frame = vec![len as u8];
    frame.extend_from_slice(&buf[..len]);
    send.write_all(&frame).await.expect("write a frame");
}

/// Read one framed event; `None` once the stream or connection ends.
pub async fn read(recv: &mut quinn::RecvStream) -> Option<ProtoEvent> {
    let mut len = [0u8; 1];
    recv.read_exact(&mut len).await.ok()?;
    let mut buf = [0u8; MAX_EVENT_SIZE];
    recv.read_exact(&mut buf[..len[0] as usize]).await.ok()?;
    ProtoEvent::try_from(buf).ok()
}

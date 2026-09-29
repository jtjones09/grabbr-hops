//! The built daemon, a frontend attached to it, and a peer that speaks the
//! wire protocol, for tests that watch what the frontend is told.
//!
//! The daemon runs with dummy capture and emulation, discovery off, a free
//! port, and every path it could touch in a scratch directory.
// Each test binary that includes this uses part of it.
#![allow(dead_code)]

/// Ports for a daemon, where no dial is given one (shared with the crate's
/// own tests).
#[path = "../../src/test_ports.rs"]
pub mod ports;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
    config: PathBuf,
    starts: u32,
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

    /// Whether the daemon has not exited.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Stop the daemon and start it again on the same files, logging to a
    /// new file, and return once it reports its service loop running.
    pub fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.starts += 1;
        self.log = self.dir.join(format!("daemon.{}.log", self.starts));
        self.child = spawn(&self.dir, &self.config, &self.log);
        if wait_until_running(&mut self.child, &self.log).is_err() {
            panic!(
                "the daemon's port was taken while it restarted; log:\n{}",
                self.log()
            );
        }
        self.drain_the_watcher();
    }

    fn drain_the_watcher(&self) {
        // Starting writes the token, keys and trust files next to the config, and
        // the config watcher reports each. A config write while those are still
        // queued can stop the daemon on macOS (a defect of the watcher, not of
        // what these tests are about), so let it drain them first.
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn spawn(dir: &std::path::Path, config: &std::path::Path, log: &std::path::Path) -> Child {
    let config_dir = config.parent().expect("the config's directory");
    Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--config")
        .arg(config)
        .arg("--cert-path")
        .arg(config_dir.join("lan-mouse.pem"))
        .arg("daemon")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("XDG_CONFIG_HOME", dir.join(".config"))
        .env("XDG_STATE_HOME", dir)
        .env("HOPS_LOG_FILE", log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts")
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
    start_on(ports::pick, tag, tables)
}

/// A pairing a daemon starts with: the other machine's fingerprint, the
/// name it was paired under, and what it grants.
pub type Pairing<'a> = (&'a str, &'a str, hops::trust::Caps);

/// Each machine may drive the other, and the clipboard goes both ways.
pub const BOTH_WAYS: hops::trust::Caps = hops::trust::Caps::KNOWN;

/// That machine may drive this one and send it its clipboard, and nothing
/// goes the other way.
pub const DRIVES_US: hops::trust::Caps =
    hops::trust::Caps::DRIVE_ME.union(hops::trust::Caps::CLIPBOARD_FROM);

/// [`start`], already paired with each machine in `pairings`: the daemon's
/// identity and a trust store signed by its authority are written before it
/// first starts, each pairing confirmed on both machines, as the pairing
/// card leaves it.
///
/// `[authorized_fingerprints]` in `tables` is not a way to pair: a daemon's
/// first start lists those machines to be paired again and grants them
/// nothing.
pub fn start_paired(tag: &str, tables: &str, pairings: &[Pairing]) -> (Daemon, u16) {
    let dir = PathBuf::from(format!("/tmp/{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    seed_pairings(&config_dir, pairings);
    start_in(dir, ports::pick, tables)
}

/// Write an identity for the daemon whose configuration directory is
/// `config_dir`, where it reads it from, and a trust store holding
/// `pairings`, signed by that directory's authority.
pub fn seed_pairings(config_dir: &Path, pairings: &[Pairing]) {
    use hops::trust_file::{TrustFile, records_of};
    let key = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec!["grabbr".to_owned()])
        .expect("params")
        .self_signed(&key)
        .expect("self signed");
    std::fs::write(
        config_dir.join("lan-mouse.pem"),
        format!("{}{}", key.serialize_pem(), cert.pem()),
    )
    .expect("the identity");
    let ours = {
        use sha2::Digest;
        sha2::Sha256::digest(cert.der().as_ref())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let authority: Arc<dyn hops::authority::Authority> = Arc::new(
        hops::authority::SoftwareAuthority::load_or_generate(
            &config_dir.join(hops::authority::AUTHORITY_KEY_FILE_NAME),
        )
        .expect("the authority"),
    );
    let (mut file, _) = TrustFile::open(config_dir, authority).expect("the trust file");
    let mut store = hops::trust::TrustStore::new(&ours, file.now()).expect("our fingerprint");
    for (fp, label, caps) in pairings {
        store.issue(fp, label, *caps).expect("a pairing");
        store.confirm(fp).expect("confirmed");
    }
    file.save(&records_of(&store))
        .expect("the trust file saved");
}

/// [`start`] on the ports `port` gives, one per start (see [`launch_on`]).
pub fn start_on(port: impl FnMut() -> u16, tag: &str, tables: &str) -> (Daemon, u16) {
    // Short, for `sun_path` (about 104 bytes on macOS).
    let dir = PathBuf::from(format!("/tmp/{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    start_in(dir, port, tables)
}

/// [`start_on`] in the scratch directory `dir`, which may already hold the
/// daemon's identity and trust store.
fn start_in(dir: PathBuf, port: impl FnMut() -> u16, tables: &str) -> (Daemon, u16) {
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
    let config = config_dir.join("config.toml");
    let log = dir.join("daemon.log");
    let (child, port) = launch_on(
        port,
        &config,
        |port| {
            format!(
                "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n\n{tables}"
            )
        },
        &log,
        || spawn(&dir, &config, &log),
    );
    let daemon = Daemon {
        child,
        dir,
        log,
        config,
        starts: 0,
    };
    daemon.drain_the_watcher();
    (daemon, port)
}

/// How many ports a daemon is started on before its test gives up.
const PORT_ATTEMPTS: usize = 10;

/// The daemon's port was bound by something else before the daemon bound it;
/// what it logged.
#[derive(Debug)]
pub struct PortTaken(pub String);

/// Whether a daemon's log says it stopped because its port was in use.
pub fn port_taken(log: &str) -> bool {
    log.contains("Address already in use") || log.contains("os error 10048")
}

/// Wait until the daemon `child`, logging to `log`, reports its service loop
/// running, or `Err(PortTaken)` once it has exited saying an address was in
/// use. Its exiting for any other reason fails the test at once, and so
/// does its not running within a minute, each with its log.
pub fn wait_until_running(child: &mut Child, log: &Path) -> Result<(), PortTaken> {
    let read = || std::fs::read_to_string(log).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if read().contains("service running; stops on") {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            let text = read();
            if text.contains("service running; stops on") {
                return Ok(());
            }
            if port_taken(&text) {
                return Err(PortTaken(text));
            }
            panic!("the daemon exited ({status}) before its service loop ran; log:\n{text}");
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never reported its service loop running; log:\n{}",
            read()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Start a daemon on a port from [`ports::pick`], and return it, running,
/// with that port: `config_for(port)` is written to `config`, and `spawn`
/// starts the daemon logging to `log`.
///
/// Another process can bind the port between its being picked and the
/// daemon binding it. The daemon then exits, and is started again on
/// another port.
pub fn launch(
    config: &Path,
    config_for: impl Fn(u16) -> String,
    log: &Path,
    spawn: impl FnMut() -> Child,
) -> (Child, u16) {
    launch_on(ports::pick, config, config_for, log, spawn)
}

/// [`launch`] on the ports `port` gives, one per start.
pub fn launch_on(
    mut port: impl FnMut() -> u16,
    config: &Path,
    config_for: impl Fn(u16) -> String,
    log: &Path,
    mut spawn: impl FnMut() -> Child,
) -> (Child, u16) {
    let mut last = String::new();
    for _ in 0..PORT_ATTEMPTS {
        let port = port();
        std::fs::write(config, config_for(port)).expect("a config");
        // Each start's log on its own, so an earlier start's exit is not
        // read as this one's.
        let _ = std::fs::remove_file(log);
        let mut child = Reaped(Some(spawn()));
        match wait_until_running(child.0.as_mut().expect("the child"), log) {
            Ok(()) => return (child.0.take().expect("the child"), port),
            Err(PortTaken(text)) => last = text,
        }
    }
    // An address in use can also be something other than the port, so the
    // last start's log goes with it.
    panic!("every port picked for the daemon was taken before it bound it; last log:\n{last}");
}

/// A daemon killed and waited for when a start fails the test.
struct Reaped(Option<Child>);

impl Drop for Reaped {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
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

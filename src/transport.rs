//! Shared QUIC + rustls plumbing for the sender ([`crate::connect`]) and
//! receiver ([`crate::listen`]).
//!
//! Trust is established by **mutual fingerprint authentication** over
//! self-signed certificates — there is no CA. Both sides check the peer's
//! leaf-cert SHA-256 fingerprint against the shared `authorized_fingerprints`
//! allowlist, and both danger-trait verifiers **still delegate handshake-
//! signature verification** to rustls: the certificate is public, so only the
//! signature proves the peer holds the matching private key. Skipping that
//! delegation would reopen the MITM hole this migration closes.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Once, RwLock};

use lan_mouse_proto::{MAX_EVENT_SIZE, ProtoEvent, ProtocolError};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use thiserror::Error;

use crate::crypto::generate_fingerprint;

/// Authorized-fingerprint allowlist shared by both directions.
pub type Authorized = Arc<RwLock<HashMap<String, String>>>;

/// Private ALPN so we never complete a handshake with a stray QUIC peer.
pub const ALPN: &[u8] = b"grabbr-hop/1";

static INSTALL: Once = Once::new();

/// Install the rustls ring [`CryptoProvider`] exactly once. MUST run before any
/// rustls `ClientConfig`/`ServerConfig` builder, or they panic. Idempotent, so
/// it is safe (and required) to call from every config-building entry point.
pub fn install_crypto_provider() {
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Fingerprint string (`aa:bb:..` lowercase) of a DER cert — identical to
/// [`crate::crypto::generate_fingerprint`], i.e. the persisted identity format.
pub fn fingerprint_of(der: &CertificateDer<'_>) -> String {
    generate_fingerprint(der.as_ref())
}

// ---------------------------------------------------------------------------
// client side — verify the server (receiver) we are sending input to
// ---------------------------------------------------------------------------

/// rustls [`ServerCertVerifier`] that accepts a receiver iff its leaf-cert
/// fingerprint is in the shared allowlist. The presented fingerprint is always
/// recorded in `observed` (whether accepted or rejected) so the caller can log
/// it — making it trivial for the user to authorize the receiver.
#[derive(Debug)]
pub struct FpServerVerifier {
    provider: Arc<CryptoProvider>,
    authorized: Authorized,
    observed: Arc<Mutex<Option<String>>>,
}

impl FpServerVerifier {
    pub fn new(authorized: Authorized, observed: Arc<Mutex<Option<String>>>) -> Self {
        Self {
            provider: provider(),
            authorized,
            observed,
        }
    }
}

impl ServerCertVerifier for FpServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let fingerprint = fingerprint_of(end_entity);
        let authorized = self.authorized.read().expect("lock").contains_key(&fingerprint);
        *self.observed.lock().expect("lock") = Some(fingerprint);
        if authorized {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General("receiver fingerprint not authorized".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// server side — verify the client (sender) against the authorized allowlist
// ---------------------------------------------------------------------------

/// rustls [`ClientCertVerifier`] that accepts a sender iff its leaf-cert
/// fingerprint is in the allowlist; otherwise records the attempt (so the
/// frontend can prompt to authorize it) and rejects.
#[derive(Debug)]
pub struct FpClientVerifier {
    provider: Arc<CryptoProvider>,
    authorized: Authorized,
    attempts: Arc<Mutex<VecDeque<String>>>,
}

impl FpClientVerifier {
    pub fn new(authorized: Authorized, attempts: Arc<Mutex<VecDeque<String>>>) -> Self {
        Self {
            provider: provider(),
            authorized,
            attempts,
        }
    }
}

impl ClientCertVerifier for FpClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let fingerprint = fingerprint_of(end_entity);
        if self.authorized.read().expect("lock").contains_key(&fingerprint) {
            Ok(ClientCertVerified::assertion())
        } else {
            self.attempts.lock().expect("lock").push_back(fingerprint);
            Err(TlsError::General("sender fingerprint not authorized".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// framing — reliable QUIC streams are byte streams with no message boundary,
// so each event is prefixed with a single length byte. (Datagrams in stage 2
// preserve 1-message-per-recv and won't need this.)
// ---------------------------------------------------------------------------

const _: () = assert!(MAX_EVENT_SIZE <= u8::MAX as usize);

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("quic write error: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("quic read error: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("frame length {0} exceeds maximum")]
    BadLength(usize),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// Write one length-prefixed [`ProtoEvent`] to a reliable stream.
pub async fn write_frame(send: &mut quinn::SendStream, event: ProtoEvent) -> Result<(), FrameError> {
    let (buf, len): ([u8; MAX_EVENT_SIZE], usize) = event.into();
    let mut frame = [0u8; 1 + MAX_EVENT_SIZE];
    frame[0] = len as u8;
    frame[1..1 + len].copy_from_slice(&buf[..len]);
    send.write_all(&frame[..1 + len]).await?;
    Ok(())
}

/// Read one length-prefixed [`ProtoEvent`] from a reliable stream.
///
/// Returns `Ok(None)` when the stream ends cleanly. The length byte is
/// bound-checked before any copy so a hostile/buggy peer can't trigger an
/// out-of-bounds panic.
pub async fn read_frame(recv: &mut quinn::RecvStream) -> Result<Option<ProtoEvent>, FrameError> {
    let mut len_buf = [0u8; 1];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        // stream finished (or was reset) — treat as a clean end of input
        Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = len_buf[0] as usize;
    if len > MAX_EVENT_SIZE {
        return Err(FrameError::BadLength(len));
    }
    let mut buf = [0u8; MAX_EVENT_SIZE];
    recv.read_exact(&mut buf[..len]).await?;
    Ok(Some(ProtoEvent::try_from(buf)?))
}

// ---------------------------------------------------------------------------
// clipboard — variable-length content that does not fit the fixed event frame.
// Each transfer rides its OWN ephemeral uni stream (opened on copy, finished
// immediately): a large paste never head-of-line-blocks the realtime input
// stream, and the stream's clean finish delimits the message (no length
// prefix). The input/reply "primary" stream is always opened first at
// connection setup, so on the receiving side it is accepted before any
// clipboard stream and the two never get confused.
// ---------------------------------------------------------------------------

/// Hard cap on a single clipboard transfer so a hostile/buggy peer cannot make
/// us buffer unbounded data. 1 MiB is generous for text (images, when added,
/// get their own typed path).
pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

/// Abandon a single clipboard transfer (send or receive) that stalls longer
/// than this. Dropping the future resets/stops the stream and frees its
/// uni-stream slot, so a stuck or half-open stream (sender crash, congestion,
/// hostile peer) cannot pin a task or a slot for the life of the connection.
/// QUIC keep-alive defeats the connection idle timeout, so this is the only
/// thing that reaps such streams. 10s is far above any real LAN transfer.
pub const CLIPBOARD_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("open stream: {0}")]
    Open(#[from] quinn::ConnectionError),
    #[error("write: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("finish: {0}")]
    Finish(#[from] quinn::ClosedStream),
    #[error("read: {0}")]
    Read(#[from] quinn::ReadToEndError),
    #[error("clipboard payload was not valid utf-8")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Send one clipboard text payload to a peer on a fresh uni stream. The stream
/// is finished immediately; quinn delivers the buffered data + FIN even after
/// the handle is dropped, so this is fire-and-forget.
pub async fn send_clipboard(conn: &quinn::Connection, text: &str) -> Result<(), ClipboardError> {
    let mut send = conn.open_uni().await?;
    send.write_all(text.as_bytes()).await?;
    send.finish()?;
    Ok(())
}

/// Read one clipboard text payload from an accepted uni stream, bounded by
/// [`MAX_CLIPBOARD_BYTES`]. The stream's clean finish delimits the payload.
pub async fn recv_clipboard(mut recv: quinn::RecvStream) -> Result<String, ClipboardError> {
    let bytes = recv.read_to_end(MAX_CLIPBOARD_BYTES).await?;
    Ok(String::from_utf8(bytes)?)
}

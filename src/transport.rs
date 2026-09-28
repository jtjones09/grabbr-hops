//! Shared QUIC + rustls plumbing for the sender ([`crate::connect`]) and
//! receiver ([`crate::listen`]).
//!
//! Trust is established by **mutual fingerprint authentication** over
//! self-signed certificates — there is no CA. Both sides check the peer's
//! leaf-cert SHA-256 fingerprint against the shared lease store, and they ask
//! it DIFFERENT questions: the receiver asks whether this peer may drive us,
//! the sender asks whether we may drive that peer. One flat allowlist answered
//! both with the same bit, which is how confirming a machine we dialled also
//! handed it control of this one. Both danger-trait verifiers **still delegate
//! handshake-
//! signature verification** to rustls: the certificate is public, so only the
//! signature proves the peer holds the matching private key. Skipping that
//! delegation would reopen the MITM hole this migration closes.

use std::cell::Cell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex, Once, RwLock};

use hops_ipc::ClientHandle;
use hops_proto::{MAX_EVENT_SIZE, ProtoEvent, ProtocolError};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
};
use thiserror::Error;

use crate::crypto::generate_fingerprint;

/// The lease store, shared by both directions and by the clipboard doors.
///
/// Shared, but not symmetric: each verifier below asks it the question for its
/// own direction. That is the whole of the fix — the store can express "this
/// peer may drive me" and "I may drive this peer" separately, where a
/// `HashMap<fingerprint, label>` could only express "known".
pub type Trust = Arc<RwLock<crate::trust::TrustStore>>;

/// Private ALPN so we never complete a handshake with a stray QUIC peer.
///
/// This is a wire-protocol identifier, NOT a display name — it is deliberately
/// frozen at `grabbr-hop/1` and must match byte-for-byte on both peers, so do not
/// "rebrand" it to `hops/1` to match the app name. Changing it is a breaking
/// protocol bump: bump the version suffix and rebuild both ends together.
pub const ALPN: &[u8] = b"grabbr-hop/1";

/// The ALPN a machine dials with to be DRIVEN by the machine it dials (#15).
///
/// [`ALPN`] says the dialler will drive the machine it reached; this one says
/// the reverse, so each side knows its role when the handshake ends, before a
/// byte of input moves. A machine behind a client that drops unsolicited
/// inbound connections reaches the machine that controls it this way. It is
/// offered on its own, never beside [`ALPN`], and a peer that does not serve
/// it (v0.12 and earlier) refuses it as `no_application_protocol`.
pub const ALPN_DRIVEN: &[u8] = b"grabbr-hop/1-driven";

/// What the machine that dialled a link does over it: which of the two
/// ALPNs it offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dialler {
    /// It sends input to the machine it dialled ([`ALPN`]).
    Drives,
    /// It receives input from the machine it dialled ([`ALPN_DRIVEN`]).
    IsDriven,
}

impl Dialler {
    /// The ALPN a dialler in this role offers.
    pub fn alpn(self) -> &'static [u8] {
        match self {
            Dialler::Drives => ALPN,
            Dialler::IsDriven => ALPN_DRIVEN,
        }
    }

    /// The role an ALPN names, if it is one of ours.
    pub fn of_alpn(alpn: &[u8]) -> Option<Dialler> {
        SERVED.into_iter().find(|d| d.alpn() == alpn)
    }
}

/// The roles a listener serves, in the order it prefers them. rustls picks
/// the first of the server's list that the client offers, and
/// [`chosen_role`] must pick the same one.
pub const SERVED: [Dialler; 2] = [Dialler::Drives, Dialler::IsDriven];

/// The ALPN list a listener serves.
pub fn served_alpns() -> Vec<Vec<u8>> {
    SERVED.iter().map(|d| d.alpn().to_vec()).collect()
}

/// The role a listener will negotiate with a client that offered `offered`:
/// the first of [`SERVED`] among them, as rustls chooses.
pub fn chosen_role(offered: &[&[u8]]) -> Option<Dialler> {
    SERVED
        .into_iter()
        .find(|d| offered.iter().any(|o| *o == d.alpn()))
}

/// The role the dialler of `conn` took, from the ALPN its handshake settled
/// on. `None` for a connection with none of ours, which is refused.
pub fn negotiated_role(conn: &quinn::Connection) -> Option<Dialler> {
    let data = conn.handshake_data()?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    Dialler::of_alpn(data.protocol.as_deref()?)
}

/// Where a listener's certificate resolver writes the role a connecting
/// client asked for, for that connection's [`FpClientVerifier`] to read.
pub type Offered = Arc<Mutex<Option<Dialler>>>;

/// Hands every connection this machine's certificate, and notes which role
/// the client asked for on the way.
///
/// rustls gives a client-certificate verifier the certificate and nothing
/// else, so a verifier cannot see the ALPN. The resolver runs on the
/// ClientHello, before the client sends its certificate, and each connection
/// is accepted with a config of its own, so the slot it writes belongs to one
/// connection, and the verifier asks the question for that role.
#[derive(Debug)]
pub struct RoleResolver {
    key: Arc<rustls::sign::CertifiedKey>,
    offered: Offered,
}

impl RoleResolver {
    pub fn new(key: Arc<rustls::sign::CertifiedKey>, offered: Offered) -> Self {
        Self { key, offered }
    }
}

impl rustls::server::ResolvesServerCert for RoleResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let role = client_hello.alpn().and_then(|offered| {
            let offered: Vec<&[u8]> = offered.collect();
            chosen_role(&offered)
        });
        *self.offered.lock().expect("lock") = role;
        Some(self.key.clone())
    }
}

/// This machine's certificate and key, for a [`RoleResolver`].
pub fn certified_key(
    identity: &crate::crypto::Identity,
) -> Result<Arc<rustls::sign::CertifiedKey>, TlsError> {
    rustls::sign::CertifiedKey::from_der(
        vec![identity.cert.clone()],
        identity.key.clone_key(),
        &provider(),
    )
    .map(Arc::new)
}

/// The QUIC transport error for the TLS alert `no_application_protocol`
/// (120): a peer that serves none of the ALPNs offered. A v0.12 peer answers
/// [`ALPN_DRIVEN`] this way.
pub(crate) const NO_APPLICATION_PROTOCOL: u64 = 0x100 + 120;

/// Whether the peer refused the ALPN this machine offered.
pub(crate) fn refused_protocol(e: &quinn::ConnectionError) -> bool {
    matches!(e, quinn::ConnectionError::ConnectionClosed(close)
        if u64::from(close.error_code) == NO_APPLICATION_PROTOCOL)
}

/// The reason a link closes with when this machine holds no pairing with the
/// machine at the other end, because it was removed here (#184).
///
/// It can only take trust away: the machine that receives it forgets the one
/// that sent it, and nothing else, and only when it held a pairing with it.
/// A link carries it only while its TLS identity is proven, so no machine can
/// send it for another.
pub(crate) const REMOVED: &[u8] = b"removed";

/// The QUIC transport error for the TLS alert `access_denied` (49): QUIC
/// carries a TLS alert as `0x100` plus the alert (RFC 9001, section 4.8).
///
/// A receiver refuses a dialler it holds no pairing with this way (#184), and
/// every other refusal as `handshake_failure`, so a dialler that holds a
/// pairing with the receiver can tell that the receiver removed it.
pub(crate) const ACCESS_DENIED: u64 = 0x100 + 49;

/// Whether the machine at the other end closed this link because it removed
/// this machine ([`REMOVED`]).
pub(crate) fn closed_as_removed(e: &quinn::ConnectionError) -> bool {
    matches!(e, quinn::ConnectionError::ApplicationClosed(close) if close.reason.as_ref() == REMOVED)
}

/// Whether the receiver refused this machine's certificate as one it holds
/// no pairing with ([`ACCESS_DENIED`]).
pub(crate) fn refused_as_unknown(e: &quinn::ConnectionError) -> bool {
    matches!(e, quinn::ConnectionError::ConnectionClosed(close)
        if u64::from(close.error_code) == ACCESS_DENIED)
}

/// The reason to close a link to `fingerprint` with: [`REMOVED`] when this
/// machine holds no pairing with it any more, `otherwise` when it does.
///
/// Decided from the store, at the moment of closing, rather than by the
/// caller: removal forgets first and closes after, and whichever of the
/// closers reaches a link first sends the one reason QUIC keeps.
pub(crate) fn close_reason(
    trust: &Trust,
    fingerprint: &str,
    otherwise: &'static [u8],
) -> &'static [u8] {
    if trust.read().expect("lock").is_known(fingerprint) {
        otherwise
    } else {
        REMOVED
    }
}

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

/// rustls [`ServerCertVerifier`] that accepts a receiver iff we hold a live
/// lease permitting us to drive it. The presented fingerprint is always
/// recorded in `observed` (whether accepted or rejected) so the caller can log
/// it — making it trivial for the user to authorize the receiver.
///
/// This is the OUTBOUND question, and it is deliberately not the inbound one.
#[derive(Debug)]
pub struct FpServerVerifier {
    provider: Arc<CryptoProvider>,
    trust: Trust,
    observed: Arc<Mutex<Option<String>>>,
    role: Dialler,
}

impl FpServerVerifier {
    /// For a dial that will drive the machine it reaches.
    #[cfg(test)]
    pub fn new(trust: Trust, observed: Arc<Mutex<Option<String>>>) -> Self {
        Self::for_role(trust, observed, Dialler::Drives)
    }

    /// For a dial in `role`: one that will drive the machine it reaches
    /// asks whether this machine may drive it, and one that will be driven
    /// asks whether it may drive this machine (#15).
    pub fn for_role(trust: Trust, observed: Arc<Mutex<Option<String>>>, role: Dialler) -> Self {
        Self {
            provider: provider(),
            trust,
            observed,
            role,
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
        // Or a receiver this machine approved pairing with and has not yet
        // compared a number with: far enough to compare it, and no further
        // (#167). In either direction: which way control goes is what the
        // person approving chose (#220), not which machine dials, and until
        // both confirm nothing moves on the connection either way.
        //
        // A dial to be driven asks the inbound question of the machine it
        // reached, and nothing else: it is admitted only by a machine this
        // one lets drive it, and a pairing is never made over it.
        let permitted = {
            let trust = self.trust.read().expect("lock");
            match self.role {
                Dialler::Drives => {
                    trust.we_may_drive(&fingerprint) || trust.is_pairing(&fingerprint)
                }
                Dialler::IsDriven => trust.may_drive_us(&fingerprint),
            }
        };
        *self.observed.lock().expect("lock") = Some(fingerprint);
        if permitted {
            Ok(ServerCertVerified::assertion())
        } else if self.role == Dialler::IsDriven {
            Err(TlsError::General(
                "we hold no live lease letting that machine drive this one".into(),
            ))
        } else {
            Err(TlsError::General(
                "we hold no live lease permitting us to drive that receiver".into(),
            ))
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
/// fingerprint is in the allowlist; otherwise records the refused fingerprint
/// (so the frontend can prompt to authorize it) and rejects.
///
/// One per connection. rustls hands a verifier the certificate and nothing
/// else, so the only way to know which connection a rejection belongs to is
/// for the verifier itself to belong to one: the listener accepts every
/// connection with its own config, and reads this connection's slot when its
/// handshake fails. A single verifier shared by every connection fed one queue
/// that failed handshakes popped from in whatever order they finished, so a
/// prompt could carry another machine's fingerprint (#83).
#[derive(Debug)]
pub struct FpClientVerifier {
    provider: Arc<CryptoProvider>,
    trust: Trust,
    refused: Arc<Mutex<Option<String>>>,
    /// Which role the client asked for, written by this connection's
    /// [`RoleResolver`]. `None`: a verifier for [`ALPN`] alone.
    offered: Option<Offered>,
}

impl FpClientVerifier {
    /// `refused` receives the fingerprint of a certificate this verifier
    /// turned away. Give each connection its own. Asks only the question for
    /// a dialler that drives this machine.
    pub fn new(trust: Trust, refused: Arc<Mutex<Option<String>>>) -> Self {
        Self {
            provider: provider(),
            trust,
            refused,
            offered: None,
        }
    }

    /// [`Self::new`], for a listener serving both roles: the question asked
    /// is the one for the role `offered` holds when the certificate arrives.
    pub fn for_roles(trust: Trust, refused: Arc<Mutex<Option<String>>>, offered: Offered) -> Self {
        Self {
            offered: Some(offered),
            ..Self::new(trust, refused)
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
        let role = match &self.offered {
            None => Some(Dialler::Drives),
            Some(offered) => *offered.lock().expect("lock"),
        };
        match role {
            Some(Dialler::Drives) => {}
            // A machine dialling to be driven by this one (#15): admitted only
            // if this machine may drive it. Never a pairing, and never a
            // prompt: a refusal here is not a request to pair.
            Some(Dialler::IsDriven) => {
                let (permitted, known) = {
                    let trust = self.trust.read().expect("lock");
                    (
                        trust.we_may_drive(&fingerprint),
                        trust.is_known(&fingerprint),
                    )
                };
                return if permitted {
                    Ok(ClientCertVerified::assertion())
                } else if known {
                    Err(TlsError::General(
                        "no live lease lets this machine drive that dialler".into(),
                    ))
                } else {
                    Err(TlsError::InvalidCertificate(
                        CertificateError::ApplicationVerificationFailure,
                    ))
                };
            }
            // No role of ours was asked for: rustls refuses the ALPN too.
            None => {
                return Err(TlsError::General("no role of ours was offered".into()));
            }
        }
        // The INBOUND question, and deliberately not the outbound one. A peer
        // we hold an outbound lease on — a receiver we confirmed our own dial
        // reached — gets nothing here. Nobody was asked whether it may drive
        // this machine.
        //
        // Or a sender this machine approved, whose number is not yet compared:
        // admitted far enough to compare it (#167), whichever way the person
        // approving chose control to go (#220). Nothing it sends is read
        // until both machines confirm.
        let (permitted, known) = {
            let trust = self.trust.read().expect("lock");
            (
                trust.may_drive_us(&fingerprint) || trust.is_pairing(&fingerprint),
                trust.is_known(&fingerprint),
            )
        };
        if permitted {
            return Ok(ClientCertVerified::assertion());
        }
        // This connection's own slot, so the rejection reaches the accept
        // loop tied to the connection that presented it. One value per
        // connection: nothing a stranger does grows it.
        *self.refused.lock().expect("lock") = Some(fingerprint);
        if known {
            // Paired, in the other direction only: said as
            // `handshake_failure`. A machine waiting for its number, in either
            // direction, was admitted above and never reaches here.
            Err(TlsError::General(
                "no live lease permits that sender to drive this machine".into(),
            ))
        } else {
            // No pairing at all, as for a machine removed here: said as
            // `access_denied`, which is how a dialler that still holds a
            // pairing with this machine learns it was removed (#184).
            Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
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
pub async fn write_frame(
    send: &mut quinn::SendStream,
    event: ProtoEvent,
) -> Result<(), FrameError> {
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
    let event = ProtoEvent::try_from(buf)?;
    // A truncated (or over-long) frame would otherwise decode from the
    // zero-padded buffer into a bogus event. The frame length must equal the
    // event's true encoded width — re-encode (ProtoEvent is Copy) and reject a
    // mismatch rather than accept garbage from a malformed/hostile peer.
    let (_, encoded_len): ([u8; MAX_EVENT_SIZE], usize) = event.into();
    if encoded_len != len {
        return Err(FrameError::BadLength(len));
    }
    Ok(Some(event))
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
/// Abandon a single INPUT frame that stalls longer than this, and drop the peer.
///
/// The sender's capture task awaits this write inline — it is one arm of the
/// `do_capture_session` select, and the sole consumer of `capture.next()`. With
/// no bound, an authorized peer that stops reading its input stream freezes that
/// task: the user's own input stops being drained, and on macOS the event tap
/// blocks behind a 32-slot channel until the kernel disables it with
/// `kCGEventTapDisabledByTimeout`. The re-enable path lives inside the blocked
/// callback, so capture is then silently and permanently gone, with no log line
/// explaining it (#64).
///
/// At the fork base this send was a UDP datagram and physically could not block,
/// which is why the inherited loop awaits it inline. The wire became a reliable
/// QUIC stream in `4daa6125` and the loop was left alone.
///
/// 250 ms is ~200 events of backlog at 800 Hz. A peer that cannot accept 21
/// bytes in that time on a LAN is not recovering, and every millisecond spent
/// waiting is a millisecond of the user's own input frozen.
pub const INPUT_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

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

/// Clipboard text a peer sent, with the fingerprint its connection presented.
///
/// The fingerprint travels with the text so the service can ask the store
/// again before it applies it: a peer removed between the transfer and the
/// apply must not have its text land.
pub(crate) struct PeerClipboard {
    pub(crate) from: String,
    /// The device this machine dialled the link for; `None` over a link the
    /// peer opened.
    pub(crate) dialled_for: Option<ClientHandle>,
    pub(crate) text: String,
    /// Its share of the link's queue, given back when this is dropped: once
    /// the text is applied or refused. `None` for text that came off no link.
    pub(crate) _place: Option<Place>,
}

/// At most this many transfers from one link wait here to be applied (per
/// link: a peer linked more than once holds this on each), ...
pub(crate) const QUEUED_PER_LINK: usize = 4;
/// ... holding at most this many bytes between them. A transfer past either
/// is dropped: only the latest copy matters, and a peer that sends faster
/// than they are applied must not grow this machine's memory without end.
pub(crate) const QUEUED_BYTES_PER_LINK: usize = 2 * MAX_CLIPBOARD_BYTES;

/// What one link has waiting to be applied.
#[derive(Default)]
struct Waiting {
    transfers: Cell<usize>,
    bytes: Cell<usize>,
}

impl Waiting {
    /// No room even for an empty transfer.
    fn full(&self) -> bool {
        self.transfers.get() >= QUEUED_PER_LINK || self.bytes.get() >= QUEUED_BYTES_PER_LINK
    }

    /// A place for a transfer of `bytes`, if the link has room for it.
    fn take(self: &Rc<Self>, bytes: usize) -> Option<Place> {
        let (transfers, held) = (self.transfers.get() + 1, self.bytes.get() + bytes);
        if transfers > QUEUED_PER_LINK || held > QUEUED_BYTES_PER_LINK {
            return None;
        }
        self.transfers.set(transfers);
        self.bytes.set(held);
        Some(Place {
            waiting: self.clone(),
            bytes,
        })
    }
}

/// One transfer's share of its link's queue.
pub(crate) struct Place {
    waiting: Rc<Waiting>,
    bytes: usize,
}

impl Drop for Place {
    fn drop(&mut self) {
        let waiting = &self.waiting;
        waiting.transfers.set(waiting.transfers.get() - 1);
        waiting.bytes.set(waiting.bytes.get() - self.bytes);
    }
}

/// Where one connection's clipboard transfers go, and whose connection it is.
pub(crate) struct ClipboardInlet {
    /// The fingerprint the peer presented at the handshake.
    pub(crate) from: String,
    /// The device this machine dialled the link for; `None` for a link the
    /// peer opened.
    pub(crate) dialled_for: Option<ClientHandle>,
    pub(crate) trust: Trust,
    pub(crate) tx: local_channel::mpsc::Sender<PeerClipboard>,
}

impl ClipboardInlet {
    /// Whether the pairing takes clipboard from this peer, right now.
    fn permits(&self) -> bool {
        self.trust.read().expect("lock").clipboard_from(&self.from)
    }
}

/// The stop code a peer sees when this machine refuses its clipboard.
pub(crate) const CLIPBOARD_REFUSED: u32 = 1;
/// The stop code a peer sees when the link already has as much clipboard
/// waiting here as it may.
pub(crate) const CLIPBOARD_BUSY: u32 = 2;

const CLIP_BUSY_LOG_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(60);
thread_local! {
    static PREV_CLIP_BUSY_LOG: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
}

fn clipboard_busy(addr: SocketAddr) {
    crate::debounce!(
        PREV_CLIP_BUSY_LOG,
        CLIP_BUSY_LOG_DEBOUNCE,
        log::warn!(
            "{addr}: clipboard text dropped: {QUEUED_PER_LINK} transfers or \
             {QUEUED_BYTES_PER_LINK} bytes from this peer are already waiting to be applied"
        )
    );
}

const CLIP_REFUSED_LOG_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(60);
thread_local! {
    static PREV_CLIP_REFUSED_LOG: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
}

fn clipboard_refused(addr: SocketAddr) {
    // Info and debounced: after an upgrade a machine being driven by an older
    // build keeps sending in the direction nobody granted, on every copy.
    crate::debounce!(
        PREV_CLIP_REFUSED_LOG,
        CLIP_REFUSED_LOG_DEBOUNCE,
        log::info!(
            "{addr}: clipboard not taken; the pairing does not share the clipboard \
             in that direction"
        )
    );
}

/// Accepts the peer's clipboard uni streams (every stream after the primary
/// one) and hands each payload on, with the peer's fingerprint, if the
/// pairing takes clipboard from that peer.
///
/// One loop for both ends of a link: the listener's and the dialler's.
///
/// Asked twice. When a stream arrives, so a peer the pairing takes nothing
/// from is stopped before it sends the rest; and when the transfer completes,
/// because one begun while the peer was trusted can finish after it was
/// removed.
pub(crate) async fn clipboard_accept_loop(
    conn: quinn::Connection,
    addr: SocketAddr,
    inlet: ClipboardInlet,
) {
    let inlet = Rc::new(inlet);
    let waiting = Rc::new(Waiting::default());
    // `while let` rather than `loop`+`match`: the error arm is only ever
    // "connection closed", handled by the input loop, so there is nothing to
    // distinguish.
    while let Ok(mut recv) = conn.accept_uni().await {
        if !inlet.permits() {
            let _ = recv.stop(CLIPBOARD_REFUSED.into());
            clipboard_refused(addr);
            continue;
        }
        // Stopped before it is read: the peer stops sending what would only
        // be dropped.
        if waiting.full() {
            let _ = recv.stop(CLIPBOARD_BUSY.into());
            clipboard_busy(addr);
            continue;
        }
        let (inlet, waiting) = (inlet.clone(), waiting.clone());
        tokio::task::spawn_local(async move {
            match tokio::time::timeout(CLIPBOARD_IO_TIMEOUT, recv_clipboard(recv)).await {
                // Asked again at the end: transfers read side by side can
                // each have found room when they started.
                Ok(Ok(text)) if inlet.permits() => match waiting.take(text.len()) {
                    Some(place) => {
                        let _ = inlet.tx.send(PeerClipboard {
                            from: inlet.from.clone(),
                            dialled_for: inlet.dialled_for,
                            text,
                            _place: Some(place),
                        });
                    }
                    None => clipboard_busy(addr),
                },
                Ok(Ok(_)) => clipboard_refused(addr),
                Ok(Err(e)) => log::debug!("{addr}: bad clipboard transfer: {e}"),
                // dropping the recv future on timeout stops the stream
                // and frees the uni-stream slot (never reaped otherwise)
                Err(_) => log::debug!("{addr}: clipboard transfer timed out"),
            }
        });
    }
}

#[cfg(test)]
mod a_link_holds_a_bounded_share_of_the_clipboard_queue {
    use std::rc::Rc;

    use super::{MAX_CLIPBOARD_BYTES, QUEUED_BYTES_PER_LINK, QUEUED_PER_LINK, Waiting};

    // LEDGER T22422 | class B | 1 return value: Waiting::take, Waiting::full; 6 struct state after Place is dropped
    #[test]
    fn a_transfer_past_the_count_or_the_bytes_finds_no_room_until_one_is_applied() {
        let waiting = Rc::new(Waiting::default());
        let mut held: Vec<_> = (0..QUEUED_PER_LINK)
            .map(|_| waiting.take(1).expect("room"))
            .collect();
        assert!(waiting.full());
        assert!(
            waiting.take(1).is_none(),
            "a transfer past {QUEUED_PER_LINK} waiting found room"
        );
        held.pop();
        assert!(!waiting.full(), "an applied transfer gave back no room");
        assert!(waiting.take(1).is_some());

        let waiting = Rc::new(Waiting::default());
        let big = waiting.take(MAX_CLIPBOARD_BYTES).expect("room");
        assert!(
            waiting
                .take(QUEUED_BYTES_PER_LINK - MAX_CLIPBOARD_BYTES + 1)
                .is_none(),
            "transfers holding more than {QUEUED_BYTES_PER_LINK} bytes found room"
        );
        let _rest = waiting
            .take(QUEUED_BYTES_PER_LINK - MAX_CLIPBOARD_BYTES)
            .expect("room");
        assert!(waiting.full());
        drop(big);
        assert!(waiting.take(MAX_CLIPBOARD_BYTES).is_some());
    }
}

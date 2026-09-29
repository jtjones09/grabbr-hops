//! A controlled machine dialling the machine that controls it (#15).
//!
//! A machine behind a client that drops unsolicited inbound connections
//! cannot be dialled, but everything it opens itself gets through. So it
//! dials the machine that controls it, offering [`transport::ALPN_DRIVEN`],
//! and the link then runs with the roles reversed: the machine that answered
//! drives, and the machine that dialled injects.
//!
//! # Who dials whom
//!
//! Decided by the lease, never by the address. This machine holds a standing
//! link to a device, dialled to be driven by it, when the device is switched
//! on, has an address, is pinned to its machine, and the lease with that
//! machine lets it drive this one ([`crate::trust::Caps::DRIVE_ME`]). That
//! holds whether or not the lease also lets this machine drive that one, and
//! whether or not this machine listens (#232): a machine that cannot be
//! dialled, behind a VPN or security client that drops incoming connections,
//! is still reached through the link it opens, with no setting to find.
//! `listen = false` means only that no port is opened.
//!
//! When both machines dial for one direction, one link carries it. A link
//! the controlling machine dialled in is up, so this machine waits rather
//! than dialling; the controlling machine takes a link dialled to it only
//! while its own is not up, and closes its own dial if one dialled to it
//! came up first (`connect::Adopter::adopt`). The first link up is kept, and
//! the other attempt stops without either being closed in turn.
//!
//! # Admission, both ends
//!
//! The dialler asks the machine that answers whether it may drive this one;
//! the machine that answers asks whether it may drive the dialler. Each is
//! the inbound question on one side and the outbound one on the other, asked
//! inside the TLS verifiers, so neither side reads a byte from a machine the
//! lease does not name in that direction. The link is then admitted into the
//! listener exactly as a dialled-in link is, so every event it carries is
//! checked again as it arrives (#211, #212).
//!
//! # Retrying
//!
//! The link is held: dialled again when it drops or cannot be made, after
//! [`FIRST_RETRY`], doubling to [`LAST_RETRY`]. A link that stayed up that
//! long starts the wait over. A dial that reached nothing looks the
//! device's hostname up again before the next one, so a machine whose
//! address changed, or whose name did not resolve when this one started, is
//! found again without anyone switching the device off and on.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use hops_ipc::ClientHandle;
use hops_proto::ProtoEvent;
use local_channel::mpsc::Sender;
use quinn::{Connection, Endpoint, RecvStream};
use tokio::task::{JoinHandle, JoinSet, spawn_local};

use crate::client::ClientManager;
use crate::connect::{DialRefusal, client_config_for};
use crate::crypto::Identity;
use crate::listen::Admitter;
use crate::transport::{self, Dialler, Trust};

/// How long after a failed or dropped dial the next one starts, at first.
pub(crate) const FIRST_RETRY: Duration = Duration::from_secs(1);
/// The longest wait between two dials.
pub(crate) const LAST_RETRY: Duration = Duration::from_secs(30);
/// How long a dial waits for an answer.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the machine that answered has to send its first frame.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
/// How long looking the device's hostname up again may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a dial to be driven made no link.
#[derive(Debug)]
pub(crate) enum DialBackError {
    /// The device has no address resolved to dial.
    NoAddress,
    /// Nothing answered at any address.
    NotAnswered,
    /// The machine at `addr` does not serve [`transport::ALPN_DRIVEN`]: an
    /// older hops.
    OlderVersion(SocketAddr),
    /// The machine at `addr` refused this one as a machine it holds no
    /// pairing with (#184).
    Forgotten(SocketAddr),
    /// The machine at `addr` refused this one: nothing it holds lets it
    /// drive this machine.
    Refused(SocketAddr),
    /// `addr` answered as another machine than the one the device is pinned
    /// to.
    NotThePinnedMachine(SocketAddr, String),
    /// The machine that answered took the link and closed it for a reason
    /// of its own, such as its device for this machine being switched off.
    NotTaken,
}

/// A link made, with the first frame the machine that answered sent on it.
pub(crate) struct DialledOut {
    pub(crate) conn: Connection,
    /// The machine the handshake proved is at the other end: the one the
    /// device is pinned to, or no link is made.
    pub(crate) fingerprint: String,
    /// Kept for as long as the link: the connection's own socket.
    pub(crate) endpoint: Endpoint,
    pub(crate) first: (RecvStream, ProtoEvent),
}

fn unspecified(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    }
}

/// What a connection the dialled machine ended says about why.
fn refusal_of(e: &quinn::ConnectionError, addr: SocketAddr) -> DialBackError {
    use quinn::ConnectionError as E;
    if transport::refused_protocol(e) {
        DialBackError::OlderVersion(addr)
    } else if transport::refused_as_unknown(e) {
        DialBackError::Forgotten(addr)
    } else {
        match e {
            E::ConnectionClosed(close)
                if (0x100..=0x1ff).contains(&u64::from(close.error_code)) =>
            {
                DialBackError::Refused(addr)
            }
            E::ApplicationClosed(close)
                if close.reason.as_ref() == b"unauthorized"
                    || close.reason.as_ref() == b"not permitted" =>
            {
                DialBackError::Refused(addr)
            }
            E::ApplicationClosed(close) if close.reason.as_ref() == transport::REMOVED => {
                DialBackError::Forgotten(addr)
            }
            E::ApplicationClosed(_) => DialBackError::NotTaken,
            _ => DialBackError::NotAnswered,
        }
    }
}

/// What a handshake that failed says about the machine at `addr`: nothing
/// that machine said, bar that it is an older hops.
///
/// The machine this one is pinned to refuses this machine's certificate
/// only once it has it, after this side's half of the handshake, and by
/// then the connection is made here: its refusal lands on that connection,
/// after the pin check ([`attempt`]). What ends the handshake itself can
/// come from anything at the address or on the path, a machine that holds
/// no key at all or a forged close, and believed it would tell the person
/// that the machine this one is paired with removed or refused it. An
/// older hops refuses the protocol before any certificate, so that alone
/// is told apart, and saying so asks nothing destructive.
fn refusal_in_handshake(e: &quinn::ConnectionError, addr: SocketAddr) -> DialBackError {
    if transport::refused_protocol(e) {
        DialBackError::OlderVersion(addr)
    } else {
        DialBackError::NotAnswered
    }
}

/// One address: the handshake, the pin, and the first frame.
async fn attempt(
    identity: Arc<Identity>,
    trust: Trust,
    addr: SocketAddr,
    expected: String,
) -> Result<DialledOut, DialBackError> {
    let endpoint = Endpoint::client(unspecified(addr)).map_err(|_| DialBackError::NotAnswered)?;
    let cfg = client_config_for(
        &identity,
        trust.clone(),
        Arc::new(StdMutex::new(None)),
        Dialler::IsDriven,
    );
    let connecting = endpoint
        .connect_with(cfg, addr, "grabbr")
        .map_err(|_| DialBackError::NotAnswered)?;
    let conn = match tokio::time::timeout(DIAL_TIMEOUT, connecting).await {
        Err(_) => return Err(DialBackError::NotAnswered),
        Ok(Err(e)) => return Err(refusal_in_handshake(&e, addr)),
        Ok(Ok(conn)) => conn,
    };
    // Fail closed: the machine this device is pinned to, and no other.
    let actual = conn
        .peer_identity()
        .and_then(|i| {
            i.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .and_then(|certs| certs.first().map(transport::fingerprint_of));
    let fingerprint = match actual {
        Some(actual) if actual == expected => actual,
        actual => {
            conn.close(0u32.into(), b"fingerprint mismatch");
            return Err(DialBackError::NotThePinnedMachine(
                addr,
                actual.unwrap_or_default(),
            ));
        }
    };
    // Whether that machine may drive this one was asked in the handshake,
    // and is asked again as the link is admitted ([`Admitter::admit`]).
    // The machine that answered checks this one's certificate after this
    // side's half of the handshake, so its refusal can land on a connection
    // that looked open. It opens its input stream only for a machine it
    // admitted, and greets on it first.
    let first = async {
        let mut recv = conn.accept_uni().await?;
        loop {
            match transport::read_frame(&mut recv).await {
                Ok(Some(event)) => return Ok(Some((recv, event))),
                Ok(None) => return Ok(None),
                Err(transport::FrameError::Protocol(_)) => continue,
                Err(_) => return Ok(None),
            }
        }
    };
    let first: Result<Option<(RecvStream, ProtoEvent)>, quinn::ConnectionError> =
        match tokio::time::timeout(FIRST_FRAME_TIMEOUT, first).await {
            Ok(r) => r,
            Err(_) => Ok(None),
        };
    match first {
        Ok(Some(first)) => Ok(DialledOut {
            conn,
            fingerprint,
            endpoint,
            first,
        }),
        Ok(None) => {
            let why = conn
                .close_reason()
                .map_or(DialBackError::NotTaken, |e| refusal_of(&e, addr));
            conn.close(0u32.into(), b"bye");
            Err(why)
        }
        Err(e) => Err(refusal_of(&e, addr)),
    }
}

/// Dial `addrs` at once, to be driven by the machine pinned as `expected`,
/// and keep the first link made. What went wrong is the most telling of the
/// failures: a refusal says more than silence.
pub(crate) async fn dial_to_be_driven(
    identity: &Arc<Identity>,
    trust: &Trust,
    addrs: &[SocketAddr],
    expected: &str,
) -> Result<DialledOut, DialBackError> {
    if addrs.is_empty() {
        return Err(DialBackError::NoAddress);
    }
    let mut attempts = JoinSet::new();
    for &addr in addrs {
        attempts.spawn_local(attempt(
            identity.clone(),
            trust.clone(),
            addr,
            expected.to_string(),
        ));
    }
    let mut worst = DialBackError::NotAnswered;
    while let Some(done) = attempts.join_next().await {
        match done {
            Ok(Ok(up)) => return Ok(up),
            Ok(Err(e)) => {
                if rank(&e) > rank(&worst) {
                    worst = e;
                }
            }
            Err(_) => {}
        }
    }
    Err(worst)
}

fn rank(e: &DialBackError) -> u8 {
    match e {
        DialBackError::NoAddress | DialBackError::NotAnswered => 0,
        DialBackError::NotTaken => 1,
        DialBackError::OlderVersion(_) => 2,
        DialBackError::Refused(_) => 3,
        DialBackError::Forgotten(_) => 4,
        DialBackError::NotThePinnedMachine(..) => 5,
    }
}

/// What answered at an older hops' port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyAnswer {
    /// Something there does not serve [`transport::ALPN_DRIVEN`]: hops v0.12
    /// or earlier.
    OlderVersion(SocketAddr),
    /// A hops that does serve it: this version, told to listen on the old
    /// port by its config.
    OldPort(SocketAddr),
}

/// The server-certificate check of a port probe: it notes the certificate
/// it is shown and refuses it, whoever it names.
///
/// Refusing it is what makes the probe a probe. Under TLS 1.3 a client
/// checks the server's certificate before it sends its own, so the machine
/// probed never sees one, never finishes the handshake, and has no link to
/// hand over or pairing to prompt for. A certificate shown at all says
/// that a hops serving [`transport::ALPN_DRIVEN`] answered.
#[derive(Debug)]
struct ProbeVerifier {
    shown: Arc<StdMutex<Option<String>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for ProbeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.shown.lock().expect("lock") = Some(transport::fingerprint_of(end_entity));
        Err(rustls::Error::General("a port probe takes no link".into()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("a port probe takes no link".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("a port probe takes no link".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A probe's config: [`transport::ALPN_DRIVEN`] alone, no certificate of
/// this machine's, and a [`ProbeVerifier`] writing to `shown`.
fn probe_config(shown: Arc<StdMutex<Option<String>>>) -> Option<quinn::ClientConfig> {
    transport::install_crypto_provider();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ProbeVerifier { shown, provider }))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![transport::ALPN_DRIVEN.to_vec()];
    crypto.resumption = rustls::client::Resumption::disabled();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).ok()?;
    Some(quinn::ClientConfig::new(Arc::new(crypto)))
}

/// Ask `ips` at `port`, where hops listened before v0.13 (#16), whether a
/// hops answers there, and which. Nothing is sent but the start of a
/// handshake offering [`transport::ALPN_DRIVEN`], and no handshake is
/// finished: an older hops refuses that ALPN before it shows a
/// certificate, and a newer one shows its certificate, which the probe
/// refuses before sending one of its own ([`ProbeVerifier`]). Neither
/// machine's lease is asked, so the controlling machine and the controlled
/// one hear the same answer.
pub(crate) async fn older_version_at(ips: &[IpAddr], port: u16) -> Option<LegacyAnswer> {
    let mut probes = JoinSet::new();
    for &ip in ips {
        let addr = SocketAddr::new(ip, port);
        probes.spawn_local(async move {
            let shown: Arc<StdMutex<Option<String>>> = Default::default();
            let cfg = probe_config(shown.clone())?;
            let endpoint = Endpoint::client(unspecified(addr)).ok()?;
            let connecting = endpoint.connect_with(cfg, addr, "grabbr").ok()?;
            let ended = match tokio::time::timeout(DIAL_TIMEOUT, connecting).await {
                Err(_) => return None,
                Ok(Ok(conn)) => {
                    // Not reached: the verifier refuses every certificate.
                    conn.close(0u32.into(), b"probe");
                    None
                }
                Ok(Err(e)) => Some(e),
            };
            if shown.lock().expect("lock").is_some() {
                Some(LegacyAnswer::OldPort(addr))
            } else if ended.as_ref().is_some_and(transport::refused_protocol) {
                Some(LegacyAnswer::OlderVersion(addr))
            } else {
                None
            }
        });
    }
    while let Some(done) = probes.join_next().await {
        if let Ok(Some(answer)) = done {
            return Some(answer);
        }
    }
    None
}

/// The refusal the service is told for `e`, if it says anything.
fn told(handle: ClientHandle, fingerprint: &str, e: &DialBackError) -> Option<DialRefusal> {
    match e {
        DialBackError::OlderVersion(addr) => Some(DialRefusal::OlderVersion {
            handle,
            addr: *addr,
        }),
        DialBackError::Forgotten(addr) => Some(DialRefusal::Forgotten {
            handle,
            fingerprint: fingerprint.to_string(),
            addr: *addr,
        }),
        DialBackError::Refused(addr) => Some(DialRefusal::WontDrive {
            handle,
            fingerprint: fingerprint.to_string(),
            addr: *addr,
        }),
        DialBackError::NotThePinnedMachine(addr, seen) => Some(DialRefusal::NotThePinnedMachine {
            handle,
            seen: vec![(*addr, seen.clone())],
        }),
        DialBackError::NoAddress | DialBackError::NotAnswered | DialBackError::NotTaken => None,
    }
}

/// Everything a held link needs, shared by every one.
#[derive(Clone)]
struct Context {
    identity: Arc<Identity>,
    trust: Trust,
    clients: ClientManager,
    admitter: Admitter,
    refusals: Sender<DialRefusal>,
    state_tx: Sender<ClientHandle>,
}

/// One device this machine dials to be driven by.
struct Held {
    fingerprint: String,
    task: JoinHandle<()>,
    link: Rc<RefCell<Option<Connection>>>,
}

/// The links this machine holds to the machines that control it.
pub(crate) struct DialBack {
    context: Context,
    held: HashMap<ClientHandle, Held>,
}

impl DialBack {
    pub(crate) fn new(
        identity: Arc<Identity>,
        trust: Trust,
        clients: ClientManager,
        admitter: Admitter,
        refusals: Sender<DialRefusal>,
        state_tx: Sender<ClientHandle>,
    ) -> Self {
        Self {
            context: Context {
                identity,
                trust,
                clients,
                admitter,
                refusals,
                state_tx,
            },
            held: HashMap::new(),
        }
    }

    /// The devices this machine should dial to be driven by, and the
    /// machine each is pinned to. See the module docs for the rule.
    pub(crate) fn wanted(&self) -> HashMap<ClientHandle, String> {
        let trust = self.context.trust.read().expect("lock");
        self.context
            .clients
            .get_client_states()
            .into_iter()
            .filter_map(|(handle, config, state)| {
                let fp = state.peer_fingerprint?;
                let has_address = config.hostname.is_some() || !config.fix_ips.is_empty();
                let wanted = state.active && has_address && trust.may_drive_us(&fp);
                wanted.then_some((handle, fp))
            })
            .collect()
    }

    /// Start a held link for each device wanted and not yet held, and stop
    /// each one held that is no longer wanted, closing its link.
    pub(crate) fn reconcile(&mut self) {
        let wanted = self.wanted();
        let stale: Vec<ClientHandle> = self
            .held
            .iter()
            .filter(|(h, held)| wanted.get(h) != Some(&held.fingerprint) || held.task.is_finished())
            .map(|(h, _)| *h)
            .collect();
        for handle in stale {
            self.stop(handle);
        }
        for (handle, fingerprint) in wanted {
            if self.held.contains_key(&handle) {
                continue;
            }
            log::info!("client {handle}: dialling {fingerprint} to be driven by it");
            let link: Rc<RefCell<Option<Connection>>> = Default::default();
            let task = spawn_local(hold(
                self.context.clone(),
                handle,
                fingerprint.clone(),
                link.clone(),
            ));
            self.held.insert(
                handle,
                Held {
                    fingerprint,
                    task,
                    link,
                },
            );
        }
    }

    /// Stop dialling `handle`, and close the link it holds.
    fn stop(&mut self, handle: ClientHandle) {
        if let Some(held) = self.held.remove(&handle) {
            log::info!(
                "client {handle}: no longer dialling {} to be driven",
                held.fingerprint
            );
            held.task.abort();
            if let Some(conn) = held.link.borrow_mut().take() {
                let reason =
                    transport::close_reason(&self.context.trust, &held.fingerprint, b"bye");
                conn.close(0u32.into(), reason);
            }
        }
    }

    /// The listener's door for the links this machine dials, for a test to
    /// count the links in it holds.
    #[cfg(all(test, unix))]
    pub(crate) fn admitter(&self) -> Admitter {
        self.context.admitter.clone()
    }

    /// Stop every held link.
    pub(crate) fn stop_all(&mut self) {
        let handles: Vec<ClientHandle> = self.held.keys().copied().collect();
        for handle in handles {
            self.stop(handle);
        }
    }
}

/// Where `handle` is dialled now: each of its addresses at its port.
fn addresses(clients: &ClientManager, handle: ClientHandle) -> (Vec<SocketAddr>, u16) {
    let port = clients.get_port(handle).unwrap_or(hops_ipc::DEFAULT_PORT);
    let addrs = clients
        .get_ips(handle)
        .unwrap_or_default()
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    (addrs, port)
}

/// Look `handle`'s hostname up again, if it has one, for the next dial.
///
/// Addresses found replace those found before; a lookup that fails keeps
/// them, since a name that does not resolve for a moment says nothing about
/// whether they still reach the machine. With none at all to dial, the
/// person is told the name was not found, and it is looked up again after
/// the next dial.
async fn look_up_again(context: &Context, handle: ClientHandle) {
    let Some(hostname) = context.clients.get_hostname(handle) else {
        return;
    };
    let found = tokio::time::timeout(LOOKUP_TIMEOUT, crate::dns::resolve_hostname(&hostname))
        .await
        .ok()
        .and_then(Result::ok)
        .filter(|ips| !ips.is_empty());
    match found {
        Some(ips) => {
            let known = context
                .clients
                .get_state(handle)
                .map(|(_, s)| s.dns_ips)
                .unwrap_or_default();
            let changed = ips.len() != known.len() || ips.iter().any(|ip| !known.contains(ip));
            if changed {
                log::info!("client {handle}: {hostname} is now at {ips:?}");
                context.clients.set_dns_ips(handle, ips);
                let _ = context.state_tx.send(handle);
            }
        }
        None => {
            log::debug!("client {handle}: {hostname} did not resolve");
            if addresses(&context.clients, handle).0.is_empty() {
                let _ = context
                    .refusals
                    .send(DialRefusal::NotResolved { handle, hostname });
            }
        }
    }
}

/// Hold a link to `handle`'s machine, dialled to be driven by it, until
/// stopped.
async fn hold(
    context: Context,
    handle: ClientHandle,
    fingerprint: String,
    link: Rc<RefCell<Option<Connection>>>,
) {
    let mut wait = FIRST_RETRY;
    loop {
        // The machine that drives this one dialled it, and that link is up:
        // it carries this direction, so nothing is dialled until it drops
        // (#232). Asked before every dial, so a link dialled here and one
        // dialled in are never both kept, and neither is closed for the
        // other.
        if context.admitter.links_from(&fingerprint).await > 0 {
            wait = FIRST_RETRY;
            tokio::time::sleep(FIRST_RETRY).await;
            continue;
        }
        let (addrs, port) = addresses(&context.clients, handle);
        match dial_to_be_driven(&context.identity, &context.trust, &addrs, &fingerprint).await {
            Ok(up) => {
                let started = Instant::now();
                let DialledOut {
                    conn,
                    fingerprint: proven,
                    endpoint,
                    first,
                } = up;
                *link.borrow_mut() = Some(conn.clone());
                // Admitted as the machine the handshake proved, which the
                // pin above made the one this device is pinned to.
                if context
                    .admitter
                    .admit(conn.clone(), proven, Some(first))
                    .await
                {
                    log::info!(
                        "client {handle}: linked to {fingerprint}, which drives this machine"
                    );
                    if context.clients.set_removed_by_peer(handle, false) {
                        let _ = context.state_tx.send(handle);
                    }
                    let ended = conn.closed().await;
                    log::info!("client {handle}: the link to {fingerprint} closed: {ended}");
                }
                link.borrow_mut().take();
                drop(endpoint);
                if started.elapsed() >= LAST_RETRY {
                    wait = FIRST_RETRY;
                }
            }
            Err(e) => {
                log::debug!("client {handle}: dialling {fingerprint} to be driven: {e:?}");
                let mut refusal = told(handle, &fingerprint, &e);
                if matches!(e, DialBackError::NotAnswered) && port == hops_ipc::DEFAULT_PORT {
                    let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
                    let legacy = older_version_at(&ips, hops_ipc::PORT_BEFORE_V013).await;
                    refusal = legacy.map(|answer| match answer {
                        LegacyAnswer::OlderVersion(addr) => {
                            DialRefusal::OlderVersion { handle, addr }
                        }
                        LegacyAnswer::OldPort(addr) => DialRefusal::OldPort { handle, addr },
                    });
                }
                if let Some(refusal) = refusal {
                    let _ = context.refusals.send(refusal);
                }
                // Only the pinned machine, proven, answering at an address
                // says the addresses are right. Anything else at them, even
                // another hops, may hold an address the machine moved from.
                let reached = matches!(
                    e,
                    DialBackError::Forgotten(_)
                        | DialBackError::Refused(_)
                        | DialBackError::NotTaken
                );
                if !reached {
                    look_up_again(&context, handle).await;
                }
            }
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(LAST_RETRY);
    }
}

#[cfg(test)]
mod tests {
    //! The reversed link end to end on loopback, each end the production
    //! code: the controlled machine dials ([`dial_to_be_driven`]) and admits
    //! the link into a listener that binds no port; the controlling machine's
    //! own listener hands it over, its connection adopts it as a device's
    //! link, and it sends through its ordinary send path. Injection lands in
    //! a recording emulation backend.
    use super::*;
    use crate::connect::Adopter;
    use crate::emulation::Emulation;
    use crate::listen::{DialledIn, LanMouseListener};
    use crate::test_harness::{
        ARRIVES_WITHIN, Dialer, Machine, NEVER_WITHIN, dialer, heard_within, machine, next_within,
        run_local, trust, wait_until,
    };
    use crate::trust::Caps;
    use hops_proto::Position;
    use input_emulation::recording::{Recorded, Recording};
    use input_event::{Event, KeyboardEvent};
    use local_channel::mpsc::{Receiver, channel};

    fn key(key: u32) -> Event {
        Event::Keyboard(KeyboardEvent::Key {
            time: 0,
            key,
            state: 1,
        })
    }

    fn consumed(recording: &Recording, event: Event) -> bool {
        recording
            .calls()
            .iter()
            .any(|c| matches!(c, Recorded::Consume(e, _) if *e == event))
    }

    /// The controlling machine: its listener on loopback, and a device for
    /// the controlled machine pinned to it, whose link is whatever that
    /// machine dials in.
    struct Controller {
        port: u16,
        dialer: Dialer,
        /// Links its listener handed over, and whether each was adopted.
        adopted: Rc<RefCell<Vec<bool>>>,
        _listener: LanMouseListener,
    }

    async fn controller(me: &Machine, trust: Trust, controlled: &str) -> Controller {
        let at = SocketAddr::from(([127, 0, 0, 1], 0));
        controller_at(me, trust, controlled, at)
            .await
            .expect("listener")
    }

    /// A controlling machine as [`controller`] makes, listening at `at`.
    async fn controller_at(
        me: &Machine,
        trust: Trust,
        controlled: &str,
        at: SocketAddr,
    ) -> Option<Controller> {
        let (clipboard_tx, _) = channel();
        let (mut listener, port) =
            LanMouseListener::bind_at(at, me.identity.clone(), trust.clone(), clipboard_tx)
                .await
                .ok()?;
        let mut dialled_in: Receiver<DialledIn> = listener.take_dialled_in().expect("once");
        // Never dialled by this machine: nothing listens at port 9.
        let dialer = dialer(me, trust, 9, hops_ipc::Position::Right);
        dialer
            .clients
            .set_peer_fingerprint(dialer.handle, Some(controlled.to_string()));
        let adopter: Adopter = dialer.conn.adopter();
        let handle = dialer.handle;
        let adopted: Rc<RefCell<Vec<bool>>> = Default::default();
        let seen = adopted.clone();
        spawn_local(async move {
            while let Some(link) = dialled_in.recv().await {
                let taken = adopter.adopt(handle, link).await;
                seen.borrow_mut().push(taken);
            }
        });
        Some(Controller {
            port,
            dialer,
            adopted,
            _listener: listener,
        })
    }

    impl Controller {
        /// Send `event` over the device's link, through the send path a
        /// crossing uses.
        async fn send(&self, event: ProtoEvent) {
            self.dialer
                .conn
                .send(event, self.dialer.handle)
                .await
                .unwrap_or_else(|e| panic!("sending {event}: {e}"));
        }
    }

    /// The controlled machine: a listener on no port, injecting into
    /// `recording`, with the link it dialled to the controller admitted.
    struct Controlled {
        heard: Receiver<crate::transport::PeerClipboard>,
        sends: crate::listen::ClipboardSenderListen,
        _emulation: Emulation,
        _link: (Connection, Endpoint),
    }

    async fn controlled(
        me: &Machine,
        trust: Trust,
        controller: &str,
        port: u16,
        recording: &Recording,
    ) -> Result<Controlled, DialBackError> {
        let (clipboard_tx, heard) = channel();
        let listener =
            LanMouseListener::dial_only(me.identity.clone(), trust.clone(), clipboard_tx)
                .await
                .expect("a listener on no port");
        let admitter = listener.admitter();
        let sends = listener.clipboard_sender(ClientManager::default());
        let at = SocketAddr::from(([127, 0, 0, 1], port));
        let DialledOut {
            conn,
            fingerprint,
            endpoint,
            first,
        } = dial_to_be_driven(&me.identity, &trust, &[at], controller).await?;
        let emulation = Emulation::new(Some(recording.backend()), listener, trust.clone());
        assert!(
            admitter.admit(conn.clone(), fingerprint, Some(first)).await,
            "the controlled machine refused the link it dialled"
        );
        Ok(Controlled {
            heard,
            sends,
            _emulation: emulation,
            _link: (conn, endpoint),
        })
    }

    /// `us`'s store, holding a lease on `peer` with `caps`, or none.
    fn store(us: &Machine, peer: &Machine, caps: Caps) -> Trust {
        if caps.is_empty() {
            trust(us, &[], caps)
        } else {
            trust(us, &[peer], caps)
        }
    }

    /// A controlling machine `k` and a controlled one `c`, paired with the
    /// drive bits given, and whether `c`'s dial made a link.
    async fn reversed(
        k_caps: Caps,
        c_caps: Caps,
        recording: &Recording,
    ) -> (Controller, Result<Controlled, DialBackError>) {
        let (k, c) = (machine(), machine());
        let k_side = controller(&k, store(&k, &c, k_caps), &c.fingerprint).await;
        let c_side = controlled(
            &c,
            store(&c, &k, c_caps),
            &k.fingerprint,
            k_side.port,
            recording,
        )
        .await;
        (k_side, c_side)
    }

    // LEDGER T7 | class B | 1 return value: dial_to_be_driven through listen::server_config's verifier, and Adopter::adopt
    /// Who may dial whom, both ends. The machine that dials to be driven is
    /// let in only by a machine whose lease lets it drive the dialler, and
    /// takes the link only from a machine whose lease lets that machine
    /// drive it. Every other combination makes no link.
    #[test]
    fn a_link_to_be_driven_is_made_only_where_both_leases_say_so() {
        run_local(async {
            let drives = [Caps::NONE, Caps::OUTBOUND, Caps::INBOUND, Caps::DRIVE];
            for k_caps in drives {
                for c_caps in drives {
                    let recording = Recording::new();
                    let (k, c) = reversed(k_caps, c_caps, &recording).await;
                    let expected =
                        k_caps.contains(Caps::I_MAY_DRIVE) && c_caps.contains(Caps::DRIVE_ME);
                    assert_eq!(
                        c.is_ok(),
                        expected,
                        "controller {k_caps:?}, controlled {c_caps:?}: {:?}",
                        c.as_ref().err()
                    );
                    if expected {
                        assert_eq!(*k.adopted.borrow(), vec![true]);
                    } else {
                        assert!(
                            k.adopted.borrow().is_empty(),
                            "controller {k_caps:?}, controlled {c_caps:?}: a link was handed \
                             over although the leases do not make one"
                        );
                    }
                }
            }
        });
    }

    // LEDGER T7b | class B | 1 return value: dial_to_be_driven's error for each refusal
    /// A refusal says who refused and why: a controller that holds no
    /// pairing with the dialler says so as a removal (#184), one paired only
    /// the other way as a refusal.
    #[test]
    fn a_refused_dial_says_why() {
        run_local(async {
            let recording = Recording::new();
            let (_k, unknown) = reversed(Caps::NONE, Caps::INBOUND, &recording).await;
            assert!(
                matches!(unknown, Err(DialBackError::Forgotten(_))),
                "{:?}",
                unknown.err()
            );
            let (_k, other_way) = reversed(Caps::INBOUND, Caps::INBOUND, &recording).await;
            assert!(
                matches!(other_way, Err(DialBackError::Refused(_))),
                "{:?}",
                other_way.err()
            );
        });
    }

    /// How long a held link may take to come up in the tests below: a
    /// dial that reaches nothing, a lookup, and the waits between them.
    const HELD_WITHIN: Duration = Duration::from_secs(30);

    /// The controlled machine `c`, holding a device for the controlling
    /// machine `k` at `hostname` and the port `k` listens on, pinned to it,
    /// with the addresses `resolved` as the name's last lookup found, and
    /// letting `k` and each of `also` drive it. Its held links, and what it
    /// tells the service.
    async fn holding(
        c: &Machine,
        k: &Machine,
        also: &[&Machine],
        port: u16,
        hostname: &str,
        resolved: Vec<IpAddr>,
    ) -> (DialBack, Receiver<DialRefusal>, LanMouseListener) {
        let drivers: Vec<&Machine> = std::iter::once(k).chain(also.iter().copied()).collect();
        let c_trust = trust(c, &drivers, Caps::INBOUND);
        let clients = ClientManager::default();
        let handle = clients.add_client();
        clients.set_hostname(handle, Some(hostname.to_string()));
        clients.set_dns_ips(handle, resolved);
        clients.set_port(handle, port);
        clients.set_peer_fingerprint(handle, Some(k.fingerprint.clone()));
        clients.activate_client(handle);
        let (clipboard_tx, _) = channel();
        let listener =
            LanMouseListener::dial_only(c.identity.clone(), c_trust.clone(), clipboard_tx)
                .await
                .expect("a listener on no port");
        let (refusals_tx, refusals) = channel();
        let (state_tx, _) = channel();
        let dial_back = DialBack::new(
            c.identity.clone(),
            c_trust,
            clients,
            listener.admitter(),
            refusals_tx,
            state_tx,
        );
        (dial_back, refusals, listener)
    }

    // LEDGER T33 | class B | 6 struct state: the controlling machine's Adopter::adopt results for links DialBack::reconcile's held dial makes
    /// The controlled machine could not look the controlling one's name up
    /// when it started, so it holds no address for it, and later the name
    /// resolves; or the name's address changed since it was looked up. Either
    /// way the held link looks the name up again and comes up, with no one
    /// switching the device off and on.
    #[test]
    fn a_held_link_looks_its_hostname_up_again_until_it_reaches_the_machine() {
        run_local(async {
            let not_yet: Vec<IpAddr> = Vec::new();
            let moved = vec![IpAddr::from([127, 0, 0, 2])];
            for (case, resolved) in [
                ("a link to the machine whose name never resolved", not_yet),
                ("a link to the machine whose address moved", moved),
            ] {
                let (k_m, c_m) = (machine(), machine());
                let k =
                    controller(&k_m, trust(&k_m, &[&c_m], Caps::OUTBOUND), &c_m.fingerprint).await;
                let (mut dial_back, _refusals, _listener) =
                    holding(&c_m, &k_m, &[], k.port, "localhost", resolved).await;
                dial_back.reconcile();
                wait_until(case, HELD_WITHIN, || k.adopted.borrow().contains(&true)).await;
                dial_back.stop_all();
            }

            // The address it moved from now answers as another machine this
            // one lets drive it. That proves only that the pinned machine is
            // not there, so the name is looked up again all the same.
            let (k_m, other_m, c_m) = (machine(), machine(), machine());
            let k = controller(&k_m, trust(&k_m, &[&c_m], Caps::OUTBOUND), &c_m.fingerprint).await;
            let (_other, stale) = elsewhere_on_loopback(&other_m, &c_m, k.port).await;
            let (mut dial_back, mut refusals, _listener) =
                holding(&c_m, &k_m, &[&other_m], k.port, "127.0.0.1", vec![stale]).await;
            dial_back.reconcile();
            let told = next_within(&mut refusals, HELD_WITHIN).await;
            assert!(
                matches!(&told, Some(DialRefusal::NotThePinnedMachine { seen, .. })
                    if seen.iter().all(|(_, fp)| *fp == other_m.fingerprint)),
                "precondition: the old address did not answer as the other machine: {told:?}"
            );
            wait_until(
                "a link to the machine whose old address another machine took",
                HELD_WITHIN,
                || k.adopted.borrow().contains(&true),
            )
            .await;
            dial_back.stop_all();
        });
    }

    /// Another controlling machine, `me`, listening at `port` on a loopback
    /// address other than 127.0.0.1, and that address: `::1`, or
    /// 127.0.0.2 on a host with no IPv6 loopback.
    async fn elsewhere_on_loopback(
        me: &Machine,
        controlled: &Machine,
        port: u16,
    ) -> (Controller, IpAddr) {
        for ip in [
            IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
            IpAddr::from([127, 0, 0, 2]),
        ] {
            let store = trust(me, &[controlled], Caps::OUTBOUND);
            let at = SocketAddr::new(ip, port);
            if let Some(it) = controller_at(me, store, &controlled.fingerprint, at).await {
                return (it, ip);
            }
        }
        panic!("precondition: no loopback address but 127.0.0.1 to listen on");
    }

    // LEDGER T35 | class B | 6 struct state: the DialRefusal DialBack's held dial sends the service
    /// A name that does not resolve for a while says nothing while the
    /// addresses found before are still there to dial: only a device with
    /// none at all cannot be dialled.
    #[test]
    fn a_name_that_does_not_resolve_says_nothing_while_there_is_an_address_to_dial() {
        run_local(async {
            // The address answers as another machine, so each dial fails and
            // is told, and the name is looked up again after each.
            let (k, other_m, c) = (machine(), machine(), machine());
            let (_other, port) = {
                let store = trust(&other_m, &[&c], Caps::OUTBOUND);
                let other = controller(&other_m, store, &c.fingerprint).await;
                let port = other.port;
                (other, port)
            };
            let at = vec![IpAddr::from([127, 0, 0, 1])];
            let (mut dial_back, mut refusals, _listener) =
                holding(&c, &k, &[&other_m], port, "no-such-machine.invalid", at).await;
            dial_back.reconcile();
            // Two dials, and the lookup after the first between them.
            for dial in ["first", "second"] {
                let told = next_within(&mut refusals, HELD_WITHIN).await;
                assert!(
                    matches!(&told, Some(DialRefusal::NotThePinnedMachine { .. })),
                    "after the {dial} dial, with an address still to dial, the person was told: \
                     {told:?}"
                );
            }
            dial_back.stop_all();
        });
    }

    // LEDGER T34 | class B | 6 struct state: the DialRefusal DialBack's held dial sends the service
    /// A name that resolves to nothing, with no other address to dial: the
    /// person is told the name was not found, rather than the device
    /// waiting, silent, for an address it will never have.
    #[test]
    fn a_held_link_whose_hostname_resolves_to_nothing_says_so() {
        run_local(async {
            let (k, c) = (machine(), machine());
            let (mut dial_back, mut refusals, _listener) =
                holding(&c, &k, &[], 9, "no-such-machine.invalid", Vec::new()).await;
            dial_back.reconcile();
            let told = next_within(&mut refusals, HELD_WITHIN).await;
            assert!(
                matches!(&told, Some(DialRefusal::NotResolved { hostname, .. })
                    if hostname == "no-such-machine.invalid"),
                "the person was not told the name resolves to nothing: {told:?}"
            );
            dial_back.stop_all();
        });
    }

    // LEDGER T31 | class B | 1 return value: dial_to_be_driven's error and told()'s notice for a keyless endpoint
    /// A machine that holds no key, or a close forged on the path, ends the
    /// handshake with the same alert the pinned machine refuses a removed
    /// machine with. Nothing proved it is the pinned machine, so the dial
    /// says nothing answered, and the person is told nothing about it.
    #[test]
    fn a_refusal_from_a_machine_that_showed_no_certificate_is_not_believed() {
        run_local(async {
            let (k, c) = (machine(), machine());
            let (_keyless, port, answered) = crate::test_harness::keyless_listener();
            let c_trust = trust(&c, &[&k], Caps::INBOUND);
            let at = SocketAddr::from(([127, 0, 0, 1], port));
            let got = dial_to_be_driven(&c.identity, &c_trust, &[at], &k.fingerprint).await;
            assert!(
                !answered.borrow().is_empty(),
                "precondition: the keyless endpoint never answered"
            );
            let e = got.err().expect("no link to a machine with no key");
            assert!(
                matches!(e, DialBackError::NotAnswered),
                "a refusal nothing proved came from the pinned machine was believed: {e:?}"
            );
            assert!(told(7, &k.fingerprint, &e).is_none());
        });
    }

    /// How a dial made with `cfg` to the listener at `port` ended: the
    /// handshake's error, or what closed the connection it made.
    async fn how_it_ended(cfg: quinn::ClientConfig, port: u16) -> quinn::ConnectionError {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("ep");
        let at = SocketAddr::from(([127, 0, 0, 1], port));
        let conn = tokio::time::timeout(
            ARRIVES_WITHIN,
            endpoint.connect_with(cfg, at, "grabbr").expect("dial"),
        )
        .await
        .expect("an answer");
        // The listener checks the dialler's certificate after the dialler's
        // half of the handshake: its refusal lands on the connection.
        match conn {
            Ok(conn) => tokio::time::timeout(ARRIVES_WITHIN, conn.closed())
                .await
                .expect("the listener ends the connection"),
            Err(e) => e,
        }
    }

    /// Whether `e` is the listener refusing in the handshake itself: a TLS
    /// alert, not a close after it.
    fn at_the_door(e: &quinn::ConnectionError) -> bool {
        matches!(e, quinn::ConnectionError::ConnectionClosed(close)
            if (0x100..=0x1ff).contains(&u64::from(close.error_code)))
    }

    // LEDGER T7c | class B | 1 return value: the connection error of a handshake against listen::server_config
    /// A machine that may not drive the dialler refuses it at the TLS door,
    /// known to it or not: nothing the dialler sends is read, and the check
    /// after the handshake is a second one, not the only one.
    #[test]
    fn a_listener_that_may_not_drive_the_dialler_refuses_it_in_the_handshake() {
        run_local(async {
            for k_caps in [Caps::NONE, Caps::INBOUND] {
                let (k_m, c_m) = (machine(), machine());
                let k = controller(&k_m, store(&k_m, &c_m, k_caps), &c_m.fingerprint).await;
                let cfg = client_config_for(
                    &c_m.identity,
                    trust(&c_m, &[&k_m], Caps::INBOUND),
                    Arc::new(StdMutex::new(None)),
                    Dialler::IsDriven,
                );
                let ended = how_it_ended(cfg, k.port).await;
                assert!(
                    at_the_door(&ended),
                    "controller {k_caps:?}: refused otherwise than at the TLS door: {ended:?}"
                );
                assert!(k.adopted.borrow().is_empty(), "controller {k_caps:?}");
            }
        });
    }

    // LEDGER T13 | class B | 1 return value: dial_to_be_driven's error when another machine answers
    /// The dialler takes the link only from the machine its device is pinned
    /// to. Another machine at that address, even one this machine also lets
    /// drive it, is refused before any of its input is read.
    #[test]
    fn a_dial_to_be_driven_is_taken_only_from_the_pinned_machine() {
        run_local(async {
            let (pinned, other, c) = (machine(), machine(), machine());
            let recording = Recording::new();
            let answers =
                controller(&other, trust(&other, &[&c], Caps::OUTBOUND), &c.fingerprint).await;
            let c_trust = trust(&c, &[&pinned, &other], Caps::INBOUND);
            let got = controlled(&c, c_trust, &pinned.fingerprint, answers.port, &recording).await;
            assert!(
                matches!(&got, Err(DialBackError::NotThePinnedMachine(_, seen))
                    if *seen == other.fingerprint),
                "another machine answering at the address was taken as the pinned one: {:?}",
                got.as_ref().map(|_| "linked")
            );
        });
    }

    // LEDGER T14 | class B | 1 return value: Admitter::admit after the lease was withdrawn
    /// A lease withdrawn between the dial and its admission admits nothing:
    /// the link is closed, not read.
    #[test]
    fn a_lease_withdrawn_before_admission_admits_nothing() {
        run_local(async {
            let (k_m, c_m) = (machine(), machine());
            let k = controller(&k_m, trust(&k_m, &[&c_m], Caps::OUTBOUND), &c_m.fingerprint).await;
            let c_trust = trust(&c_m, &[&k_m], Caps::INBOUND);
            let (clipboard_tx, _heard) = channel();
            let listener =
                LanMouseListener::dial_only(c_m.identity.clone(), c_trust.clone(), clipboard_tx)
                    .await
                    .expect("a listener on no port");
            let admitter = listener.admitter();
            let at = SocketAddr::from(([127, 0, 0, 1], k.port));
            let out = dial_to_be_driven(&c_m.identity, &c_trust, &[at], &k_m.fingerprint)
                .await
                .expect("dialled");
            c_trust
                .write()
                .expect("lock")
                .drop_capabilities(&k_m.fingerprint, Caps::DRIVE_ME);
            let conn = out.conn.clone();
            assert!(
                !admitter
                    .admit(out.conn, out.fingerprint, Some(out.first))
                    .await,
                "a link was admitted after the lease letting its machine drive this one was \
                 withdrawn"
            );
            tokio::time::timeout(ARRIVES_WITHIN, conn.closed())
                .await
                .expect("the link not admitted is closed");
            drop(listener);
        });
    }

    // LEDGER T15 | class B | 6 struct state: the controlling machine's ClientManager behind Adopter::adopt
    /// A device switched off takes no link its machine dials (#218), and its
    /// card says nothing new about who dials. Switched on, it takes the next
    /// one, and its card says its machine dials in.
    #[test]
    fn a_device_switched_off_takes_no_link_its_machine_dials() {
        run_local(async {
            let (k_m, c_m) = (machine(), machine());
            let recording = Recording::new();
            let k = controller(&k_m, trust(&k_m, &[&c_m], Caps::OUTBOUND), &c_m.fingerprint).await;
            let c_trust = trust(&c_m, &[&k_m], Caps::INBOUND);
            let dials_us = |k: &Controller| {
                k.dialer
                    .clients
                    .get_state(k.dialer.handle)
                    .is_some_and(|(_, s)| s.dials_us)
            };
            k.dialer.clients.deactivate_client(k.dialer.handle);
            let got = controlled(&c_m, c_trust.clone(), &k_m.fingerprint, k.port, &recording).await;
            wait_until("the dial to be handed over", ARRIVES_WITHIN, || {
                !k.adopted.borrow().is_empty()
            })
            .await;
            assert!(
                got.is_err() && *k.adopted.borrow() == vec![false],
                "a device switched off took the link its machine dialled: {:?}",
                k.adopted.borrow()
            );
            assert!(
                !dials_us(&k),
                "a dial turned away marked the card as dialled into"
            );

            k.dialer.clients.activate_client(k.dialer.handle);
            let _c = controlled(&c_m, c_trust, &k_m.fingerprint, k.port, &recording)
                .await
                .expect("linked once switched on");
            wait_until("the dial to be taken", ARRIVES_WITHIN, || {
                k.adopted.borrow().contains(&true)
            })
            .await;
            assert!(dials_us(&k), "the card does not say its machine dials in");
        });
    }

    // LEDGER T5 | class B | 6 struct state: Recording::calls() behind Admitter::admit and the emulation gates
    /// #212 on the reversed link: input from the controlling machine is
    /// injected only once it crossed onto this machine.
    #[test]
    fn a_controller_that_has_not_crossed_injects_nothing_over_the_link_dialled_to_it() {
        run_local(async {
            let recording = Recording::new();
            let (k, c) = reversed(Caps::OUTBOUND, Caps::INBOUND, &recording).await;
            let _c = c.expect("linked");
            k.dialer.until_alive().await;

            k.send(ProtoEvent::Input(key(1))).await;
            k.send(ProtoEvent::Enter(Position::Left)).await;
            k.send(ProtoEvent::Input(key(2))).await;
            wait_until("input after the crossing to land", ARRIVES_WITHIN, || {
                consumed(&recording, key(2))
            })
            .await;
            assert!(
                !consumed(&recording, key(1)),
                "input sent before the controller crossed was injected: {:?}",
                recording.calls()
            );
        });
    }

    // LEDGER T6 | class B | 6 struct state: Recording::calls() behind Admitter::admit and the emulation gates
    /// #211 on the reversed link: every event is asked whether the
    /// controller may still drive this machine, not only the handshake.
    #[test]
    fn input_after_the_lease_is_withdrawn_is_dropped_on_the_link_dialled_out() {
        run_local(async {
            let (k_m, c_m) = (machine(), machine());
            let recording = Recording::new();
            let c_trust = trust(&c_m, &[&k_m], Caps::INBOUND);
            let k = controller(&k_m, trust(&k_m, &[&c_m], Caps::OUTBOUND), &c_m.fingerprint).await;
            let _c = controlled(&c_m, c_trust.clone(), &k_m.fingerprint, k.port, &recording)
                .await
                .expect("linked");
            k.dialer.until_alive().await;
            k.send(ProtoEvent::Enter(Position::Left)).await;
            k.send(ProtoEvent::Input(key(2))).await;
            wait_until("input after the crossing to land", ARRIVES_WITHIN, || {
                consumed(&recording, key(2))
            })
            .await;

            c_trust
                .write()
                .expect("lock")
                .drop_capabilities(&k_m.fingerprint, Caps::DRIVE_ME);
            k.send(ProtoEvent::Input(key(3))).await;
            // Refused, what the controller held is let go: the sign that the
            // event was read, before the lease comes back.
            wait_until(
                "the refused controller to be let go",
                ARRIVES_WITHIN,
                || {
                    recording
                        .calls()
                        .iter()
                        .any(|c| matches!(c, Recorded::Destroy(_)))
                },
            )
            .await;
            c_trust
                .write()
                .expect("lock")
                .issue_confirmed(&k_m.fingerprint, "controller", Caps::INBOUND)
                .expect("issue");
            k.send(ProtoEvent::Enter(Position::Left)).await;
            k.send(ProtoEvent::Input(key(4))).await;
            wait_until(
                "input after the lease came back to land",
                ARRIVES_WITHIN,
                || consumed(&recording, key(4)),
            )
            .await;
            assert!(
                !consumed(&recording, key(3)),
                "input sent while the controller's lease was withdrawn was injected: {:?}",
                recording.calls()
            );
        });
    }

    // LEDGER T10 | class B | 6 queue state: the transports' clipboard queues on both ends of a reversed link
    /// The clipboard over a reversed link follows each machine's lease, as
    /// over any link: the controller's text reaches the controlled machine,
    /// which takes it; the controlled machine's reaches a controller whose
    /// lease takes it, and not one whose lease does not.
    #[test]
    fn the_clipboard_over_a_reversed_link_follows_the_lease() {
        run_local(async {
            let recording = Recording::new();
            let (mut k, c) = reversed(
                Caps::OUTBOUND | Caps::CLIPBOARD_FROM,
                Caps::INBOUND | Caps::CLIPBOARD_TO,
                &recording,
            )
            .await;
            let c = c.expect("linked");
            k.dialer.until_alive().await;
            c.sends.broadcast("taken by the controller".into()).await;
            assert_eq!(
                heard_within(&mut k.dialer.notices.clipboard, ARRIVES_WITHIN)
                    .await
                    .map(|(text, _)| text),
                Some("taken by the controller".to_string()),
                "the controlled machine's clipboard did not reach a controller whose lease \
                 takes it"
            );

            let (mut k, c) = reversed(
                Caps::OUTBOUND | Caps::CLIPBOARD_TO,
                Caps::INBOUND | Caps::CLIPBOARD_FROM | Caps::CLIPBOARD_TO,
                &recording,
            )
            .await;
            let mut c = c.expect("linked");
            k.dialer.until_alive().await;

            k.dialer
                .conn
                .clipboard_sender()
                .broadcast("from the controller".into())
                .await;
            assert_eq!(
                heard_within(&mut c.heard, ARRIVES_WITHIN)
                    .await
                    .map(|(text, _)| text),
                Some("from the controller".to_string()),
                "the controller's clipboard did not reach the machine it controls"
            );

            c.sends.broadcast("from the controlled".into()).await;
            assert_eq!(
                heard_within(&mut k.dialer.notices.clipboard, NEVER_WITHIN).await,
                None,
                "the controlled machine's clipboard reached a controller whose lease does \
                 not take it"
            );
        });
    }

    // LEDGER T9 | class B | 1 return value: a handshake against listen::server_config
    /// A dialler that offers both ALPNs is judged by the one the listener
    /// settles on, the forward one, and asked that question at the TLS
    /// door: a machine the listener may drive, and that may not drive it,
    /// is refused by the handshake itself.
    #[test]
    fn a_dialler_offering_both_roles_is_asked_the_question_of_the_one_negotiated() {
        run_local(async {
            let (k, c) = (machine(), machine());
            let recording = Recording::new();
            let k_side = controller(&k, trust(&k, &[&c], Caps::OUTBOUND), &c.fingerprint).await;
            let c_trust = trust(&c, &[&k], Caps::DRIVE);
            let verifier = Arc::new(transport::FpServerVerifier::for_role(
                c_trust,
                Arc::new(StdMutex::new(None)),
                Dialler::IsDriven,
            ));
            let mut crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_auth_cert(vec![c.identity.cert.clone()], c.identity.key.clone_key())
                .expect("client auth");
            crypto.alpn_protocols = vec![transport::ALPN_DRIVEN.to_vec(), transport::ALPN.to_vec()];
            let cfg = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic"),
            ));
            let endpoint = Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("ep");
            let at = SocketAddr::from(([127, 0, 0, 1], k_side.port));
            let conn = tokio::time::timeout(
                ARRIVES_WITHIN,
                endpoint.connect_with(cfg, at, "grabbr").expect("dial"),
            )
            .await
            .expect("an answer");
            // The listener checks this certificate after this side's half of
            // the handshake: its refusal lands on the connection.
            let closed = match conn {
                Ok(conn) => tokio::time::timeout(ARRIVES_WITHIN, conn.closed())
                    .await
                    .expect("the listener ends the connection"),
                Err(e) => e,
            };
            assert!(
                matches!(&closed, quinn::ConnectionError::ConnectionClosed(close)
                    if (0x100..=0x1ff).contains(&u64::from(close.error_code))),
                "refused otherwise than at the TLS door: {closed:?}"
            );
            assert!(
                k_side.adopted.borrow().is_empty(),
                "the link was handed over to be driven"
            );
            drop(recording);
        });
    }

    /// A listener as a hops before v0.13 had one: only [`transport::ALPN`].
    fn older_listener(me: &Machine, trust: Trust) -> (Endpoint, u16) {
        let mut crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(transport::FpClientVerifier::new(
                trust,
                Arc::new(StdMutex::new(None)),
            )))
            .with_single_cert(vec![me.identity.cert.clone()], me.identity.key.clone_key())
            .expect("cert");
        crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
        let cfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic"),
        ));
        let endpoint = Endpoint::server(cfg, "127.0.0.1:0".parse().expect("addr")).expect("ep");
        let port = endpoint.local_addr().expect("addr").port();
        let serving = endpoint.clone();
        spawn_local(async move {
            while let Some(incoming) = serving.accept().await {
                let _ = incoming.await;
            }
        });
        (endpoint, port)
    }

    // LEDGER T11 | class B | 1 return value: dial_to_be_driven and older_version_at against an older listener
    /// A machine running hops v0.12 or earlier is named as that, not as
    /// unreachable: it refuses the ALPN a controlled machine dials with, and
    /// answers at the port those versions listened on (#16).
    #[test]
    fn an_older_hops_is_told_apart_from_one_that_is_not_there() {
        run_local(async {
            let (k, c) = (machine(), machine());
            let (_older, port) = older_listener(&k, trust(&k, &[&c], Caps::DRIVE));
            let c_trust = trust(&c, &[&k], Caps::INBOUND);
            let at = SocketAddr::from(([127, 0, 0, 1], port));
            let dialled = dial_to_be_driven(&c.identity, &c_trust, &[at], &k.fingerprint).await;
            assert!(
                matches!(dialled, Err(DialBackError::OlderVersion(a)) if a == at),
                "{:?}",
                dialled.err()
            );
            let loopback = [IpAddr::from([127, 0, 0, 1])];
            assert_eq!(
                older_version_at(&loopback, port).await,
                Some(LegacyAnswer::OlderVersion(at))
            );

            // This version, told by its config to listen on the old port.
            let newer = controller(&k, trust(&k, &[&c], Caps::OUTBOUND), &c.fingerprint).await;
            assert_eq!(
                older_version_at(&loopback, newer.port).await,
                Some(LegacyAnswer::OldPort(SocketAddr::from((
                    [127, 0, 0, 1],
                    newer.port
                )))),
            );
            // A probe is not a dial: it hands the machine it reached nothing
            // to adopt. A real dial after it is taken, and is the only one.
            let recording = Recording::new();
            let _c = controlled(&c, c_trust.clone(), &k.fingerprint, newer.port, &recording)
                .await
                .expect("linked");
            wait_until("the dial to be taken", ARRIVES_WITHIN, || {
                newer.adopted.borrow().contains(&true)
            })
            .await;
            assert_eq!(
                *newer.adopted.borrow(),
                vec![true],
                "the port probe was handed over as a dial to be driven"
            );

            // The controlling machine probes too, when its own dial finds
            // nothing. Its lease does not let the machine it reached drive
            // it, and it still hears that a newer hops is there.
            let (clipboard_tx, _) = channel();
            let (_on_old_port, old_port) = LanMouseListener::bind_loopback(
                c.identity.clone(),
                trust(&c, &[&k], Caps::INBOUND),
                clipboard_tx,
            )
            .await
            .expect("listener");
            assert_eq!(
                older_version_at(&loopback, old_port).await,
                Some(LegacyAnswer::OldPort(SocketAddr::from((
                    [127, 0, 0, 1],
                    old_port
                )))),
                "the controlling machine's probe did not hear the newer hops on the old port"
            );

            // Nothing there at all.
            let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a silent port");
            let silent_port = silent.local_addr().expect("addr").port();
            assert_eq!(older_version_at(&loopback, silent_port).await, None);
        });
    }
}

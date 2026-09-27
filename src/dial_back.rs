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
//! machine lets it drive this one ([`crate::trust::Caps::DRIVE_ME`]) and
//! either does not let this machine drive it, or this machine does not
//! listen. A lease that goes both ways, on a machine that listens, is dialled
//! as before: each machine dials the other to drive it.
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
//! long starts the wait over.

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
    /// This machine no longer lets that machine drive it.
    NotPermitted,
}

/// A link made, with the first frame the machine that answered sent on it.
pub(crate) struct DialledOut {
    pub(crate) conn: Connection,
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
        Ok(Err(e)) => return Err(refusal_of(&e, addr)),
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
    if actual.as_deref() != Some(expected.as_str()) {
        conn.close(0u32.into(), b"fingerprint mismatch");
        return Err(DialBackError::NotThePinnedMachine(
            addr,
            actual.unwrap_or_default(),
        ));
    }
    if !trust.read().expect("lock").may_drive_us(&expected) {
        conn.close(0u32.into(), b"not permitted");
        return Err(DialBackError::NotPermitted);
    }
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
        DialBackError::NotPermitted => 6,
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

/// Ask `ips` at `port`, where hops listened before v0.13 (#16), whether a
/// hops answers there, and which. Nothing is sent but a handshake offering
/// [`transport::ALPN_DRIVEN`]: an older hops refuses that ALPN before it
/// reads a certificate, and a newer one is closed at once if it lets the
/// handshake finish.
pub(crate) async fn older_version_at(
    identity: &Arc<Identity>,
    trust: &Trust,
    ips: &[IpAddr],
    port: u16,
) -> Option<LegacyAnswer> {
    let mut probes = JoinSet::new();
    for &ip in ips {
        let addr = SocketAddr::new(ip, port);
        let (identity, trust) = (identity.clone(), trust.clone());
        probes.spawn_local(async move {
            let endpoint = Endpoint::client(unspecified(addr)).ok()?;
            let cfg = client_config_for(
                &identity,
                trust,
                Arc::new(StdMutex::new(None)),
                Dialler::IsDriven,
            );
            let connecting = endpoint.connect_with(cfg, addr, "grabbr").ok()?;
            match tokio::time::timeout(DIAL_TIMEOUT, connecting).await {
                Err(_) => None,
                Ok(Err(e)) if transport::refused_protocol(&e) => {
                    Some(LegacyAnswer::OlderVersion(addr))
                }
                Ok(Err(quinn::ConnectionError::ConnectionClosed(_))) => {
                    Some(LegacyAnswer::OldPort(addr))
                }
                Ok(Err(_)) => None,
                Ok(Ok(conn)) => {
                    conn.close(0u32.into(), b"probe");
                    Some(LegacyAnswer::OldPort(addr))
                }
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
        DialBackError::NoAddress
        | DialBackError::NotAnswered
        | DialBackError::NotTaken
        | DialBackError::NotPermitted => None,
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
    pub(crate) fn wanted(&self, listening: bool) -> HashMap<ClientHandle, String> {
        let trust = self.context.trust.read().expect("lock");
        self.context
            .clients
            .get_client_states()
            .into_iter()
            .filter_map(|(handle, config, state)| {
                let fp = state.peer_fingerprint?;
                let has_address = config.hostname.is_some() || !config.fix_ips.is_empty();
                let wanted = state.active
                    && has_address
                    && trust.may_drive_us(&fp)
                    && (!trust.we_may_drive(&fp) || !listening);
                wanted.then_some((handle, fp))
            })
            .collect()
    }

    /// Start a held link for each device wanted and not yet held, and stop
    /// each one held that is no longer wanted, closing its link.
    pub(crate) fn reconcile(&mut self, listening: bool) {
        let wanted = self.wanted(listening);
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
        let (addrs, port) = addresses(&context.clients, handle);
        match dial_to_be_driven(&context.identity, &context.trust, &addrs, &fingerprint).await {
            Ok(up) => {
                let started = Instant::now();
                let DialledOut {
                    conn,
                    endpoint,
                    first,
                } = up;
                *link.borrow_mut() = Some(conn.clone());
                if context
                    .admitter
                    .admit(conn.clone(), fingerprint.clone(), Some(first))
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
                    let legacy = older_version_at(
                        &context.identity,
                        &context.trust,
                        &ips,
                        hops_ipc::PORT_BEFORE_V013,
                    )
                    .await;
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
        ARRIVES_WITHIN, Dialer, Machine, NEVER_WITHIN, dialer, heard_within, machine, run_local,
        trust, wait_until,
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
        let (clipboard_tx, _) = channel();
        let (mut listener, port) =
            LanMouseListener::bind_loopback(me.identity.clone(), trust.clone(), clipboard_tx)
                .await
                .expect("listener");
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
        Controller {
            port,
            dialer,
            adopted,
            _listener: listener,
        }
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
            endpoint,
            first,
        } = dial_to_be_driven(&me.identity, &trust, &[at], controller).await?;
        let emulation = Emulation::new(Some(recording.backend()), listener, trust.clone());
        assert!(
            admitter
                .admit(conn.clone(), controller.to_string(), Some(first))
                .await,
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
    /// which takes it, and the controlled machine's does not reach a
    /// controller whose lease does not take it.
    #[test]
    fn the_clipboard_over_a_reversed_link_follows_the_lease() {
        run_local(async {
            let recording = Recording::new();
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
                older_version_at(&c.identity, &c_trust, &loopback, port).await,
                Some(LegacyAnswer::OlderVersion(at))
            );

            // This version, told by its config to listen on the old port.
            let newer = controller(&k, trust(&k, &[&c], Caps::OUTBOUND), &c.fingerprint).await;
            assert_eq!(
                older_version_at(&c.identity, &c_trust, &loopback, newer.port).await,
                Some(LegacyAnswer::OldPort(SocketAddr::from((
                    [127, 0, 0, 1],
                    newer.port
                )))),
            );

            // Nothing there at all.
            let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a silent port");
            let silent_port = silent.local_addr().expect("addr").port();
            assert_eq!(
                older_version_at(&c.identity, &c_trust, &loopback, silent_port).await,
                None
            );
        });
    }
}

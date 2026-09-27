//! Pick-the-number pairing (#11, #167): what happens on the connection that
//! two approvals let two machines make, until both machines confirm.
//!
//! An approval issues a lease that grants nothing (`TrustStore::confirm`).
//! It admits the other machine at TLS in the approved direction only, far
//! enough to run [`crate::pair_ceremony`] and no further. The machine that
//! added the other shows the number; the machine being added offers three and
//! asks which one it sees. A wrong pick ends the attempt, and the adding
//! machine still confirms on its side.
//!
//! # Nothing moves before both machines confirm
//!
//! A connection held here is in no connection list: no input stream is read
//! or opened, no reply stream, no clipboard, no broadcast. Each machine says
//! it confirmed by sending its first frame, a `Hello`, only after the person
//! there answered:
//!
//! - the adding machine (the dialler) opens its input stream and sends its
//!   `Hello` once its person confirms;
//! - the machine being added reads that `Hello` only once its person picked
//!   the right number, confirms its lease, and answers with its own;
//! - the adding machine confirms its lease when that answer arrives, and only
//!   then joins its connection list, so its first input follows both.
//!
//! So an answer lost on the wire can leave only the machine being added
//! paired. The adding machine then says to remove the pairing there.
//!
//! # The number dies with its connection
//!
//! A close, a cancel, a wrong pick, a device removed or switched off, or
//! [`Pairings::DEADLINE`] without both answers ends the attempt, and the
//! service forgets the lease. A reconnect never summons the comparison again:
//! a lease still waiting at a restart is dropped when the store loads.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use hops_ipc::ClientHandle;
use hops_proto::ProtoEvent;
use local_channel::mpsc::{Receiver, Sender, channel};
use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::Notify;

use crate::client::ClientManager;
use crate::pair_ceremony::{self, CeremonyError};
use crate::transport;

/// Which half of the comparison this machine does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// This machine added the other: show the number, and confirm.
    Show,
    /// This machine is being added: pick the number the other one shows.
    Pick,
}

/// Why an attempt ended without pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Why {
    /// The other machine offered no number to compare: a build from before
    /// the comparison, or one that already trusts this machine.
    NoComparison,
    /// The connection closed before both machines confirmed.
    Closed,
    /// Nobody finished it in time.
    TimedOut,
    /// The device being added was removed or switched off here.
    DeviceGone,
    /// The other machine sent something other than its confirmation.
    Unexpected,
    /// The comparison itself failed.
    Failed(String),
}

/// What a held attempt tells the service.
#[derive(Debug)]
pub(crate) enum PairingEvent {
    /// Both machines arrived at `number`. For the dialler, `handle` is the
    /// device being added: its add dial can stop.
    Number {
        fingerprint: String,
        addr: SocketAddr,
        role: Role,
        number: String,
        handle: Option<ClientHandle>,
    },
    /// The person here answered, and the other machine's confirmation then
    /// arrived on the connection. The service confirms the lease and calls
    /// [`Pairings::settled`].
    PeerConfirmed { fingerprint: String },
    /// Ended without pairing. The service forgets the lease.
    Ended {
        fingerprint: String,
        why: Why,
        handle: Option<ClientHandle>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Showing the number, waiting for the person here.
    Comparing,
    /// The person here answered; waiting for the other machine.
    Answered,
    /// Confirmed in the store: the connection may carry input.
    Settled,
    /// Ended here, by the service or a removal. The holder closes quietly:
    /// whoever ended it already said so.
    Over,
}

struct Held {
    conn: Connection,
    stage: Stage,
    wake: Rc<Notify>,
}

struct Board {
    held: HashMap<String, Held>,
    deadline: Duration,
}

/// The attempts one transport holds, shared with the service, which answers
/// them. One per fingerprint.
#[derive(Clone)]
pub(crate) struct Pairings {
    board: Rc<RefCell<Board>>,
    events: Sender<PairingEvent>,
}

impl Pairings {
    /// How long an attempt waits for both machines to confirm, from the
    /// moment the number is shown.
    pub(crate) const DEADLINE: Duration = Duration::from_secs(120);

    pub(crate) fn new() -> (Pairings, Receiver<PairingEvent>) {
        let (events, rx) = channel();
        (
            Pairings {
                board: Rc::new(RefCell::new(Board {
                    held: HashMap::new(),
                    deadline: Self::DEADLINE,
                })),
                events,
            },
            rx,
        )
    }

    /// A shorter deadline, so a test can watch one pass.
    #[cfg(test)]
    pub(crate) fn set_deadline(&self, deadline: Duration) {
        self.board.borrow_mut().deadline = deadline;
    }

    /// The person here answered rightly: the adding machine's confirm, or the
    /// right pick. The held connection goes on to exchange confirmations.
    pub(crate) fn answered(&self, fingerprint: &str) -> bool {
        self.advance(fingerprint, Stage::Comparing, Stage::Answered)
    }

    /// Both machines confirmed and the store says so: the held connection may
    /// carry input now.
    pub(crate) fn settled(&self, fingerprint: &str) -> bool {
        self.advance(fingerprint, Stage::Answered, Stage::Settled)
    }

    /// End the attempt with `fingerprint`, closing its connection. `true`
    /// when one was held. Whoever calls this says why; the holder does not.
    pub(crate) fn end(&self, fingerprint: &str) -> bool {
        let mut board = self.board.borrow_mut();
        let Some(held) = board.held.get_mut(fingerprint) else {
            return false;
        };
        held.stage = Stage::Over;
        held.conn.close(0u32.into(), b"pairing ended");
        held.wake.notify_one();
        true
    }

    fn advance(&self, fingerprint: &str, from: Stage, to: Stage) -> bool {
        let mut board = self.board.borrow_mut();
        match board.held.get_mut(fingerprint) {
            Some(held) if held.stage == from => {
                held.stage = to;
                held.wake.notify_one();
                true
            }
            _ => false,
        }
    }

    fn tell(&self, event: PairingEvent) {
        let _ = self.events.send(event);
    }

    /// Hold `conn` for `fingerprint`, unless another attempt with it is held.
    fn hold(&self, fingerprint: &str, conn: &Connection) -> Option<Ticket> {
        let mut board = self.board.borrow_mut();
        if board.held.contains_key(fingerprint) {
            return None;
        }
        let wake = Rc::new(Notify::new());
        board.held.insert(
            fingerprint.to_string(),
            Held {
                conn: conn.clone(),
                stage: Stage::Comparing,
                wake: wake.clone(),
            },
        );
        Some(Ticket {
            pairings: self.clone(),
            fingerprint: fingerprint.to_string(),
            id: conn.stable_id(),
            wake,
            deadline: tokio::time::Instant::now() + board.deadline,
        })
    }
}

/// One held attempt. Dropping it releases the slot.
struct Ticket {
    pairings: Pairings,
    fingerprint: String,
    id: usize,
    wake: Rc<Notify>,
    deadline: tokio::time::Instant,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut board = self.pairings.board.borrow_mut();
        if board
            .held
            .get(&self.fingerprint)
            .is_some_and(|h| h.conn.stable_id() == self.id)
        {
            board.held.remove(&self.fingerprint);
        }
    }
}

impl Ticket {
    fn stage(&self) -> Stage {
        self.pairings
            .board
            .borrow()
            .held
            .get(&self.fingerprint)
            .map_or(Stage::Over, |h| h.stage)
    }

    /// Wait until the stage reaches `want`, or say why it never will.
    /// `still` is asked every quarter second; false ends the attempt.
    async fn until(
        &self,
        conn: &Connection,
        want: Stage,
        mut still: impl FnMut() -> bool,
    ) -> Result<(), Option<Why>> {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            match self.stage() {
                s if s == want => return Ok(()),
                // Ended here: whoever ended it says so.
                Stage::Over => return Err(None),
                _ => {}
            }
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = conn.closed() => return Err(Some(Why::Closed)),
                _ = tokio::time::sleep_until(self.deadline) => return Err(Some(Why::TimedOut)),
                _ = tick.tick() => {
                    if !still() {
                        return Err(Some(Why::DeviceGone));
                    }
                }
            }
        }
    }

    /// A future bounded by this attempt's end: it closing, it being ended
    /// here, or the deadline.
    async fn bounded<T>(
        &self,
        conn: &Connection,
        f: impl std::future::Future<Output = Option<T>>,
    ) -> Result<T, Option<Why>> {
        tokio::select! {
            r = f => match r {
                Some(v) => Ok(v),
                None if conn.close_reason().is_some() => Err(Some(Why::Closed)),
                None => Err(Some(Why::Unexpected)),
            },
            _ = conn.closed() => Err(Some(Why::Closed)),
            _ = tokio::time::sleep_until(self.deadline) => Err(Some(Why::TimedOut)),
            _ = async {
                loop {
                    if self.stage() == Stage::Over {
                        return;
                    }
                    self.wake.notified().await;
                }
            } => Err(None),
        }
    }
}

/// What a comparison that did not produce a number means for the attempt.
///
/// A connection that closed before a number was shown is dropped quietly: a
/// dial raced to another address of the same machine and lost, or the link
/// blipped, and the add dial tries again. One still open that offered no
/// number is a peer that will never offer one.
fn before_number(conn: &Connection, e: CeremonyError) -> Option<Why> {
    if conn.close_reason().is_some() {
        return None;
    }
    Some(match e {
        CeremonyError::NotSupported => Why::NoComparison,
        e => Why::Failed(e.to_string()),
    })
}

/// The first frame on the peer's first input stream: its confirmation.
async fn first_frame(conn: &Connection) -> Option<(RecvStream, ProtoEvent)> {
    let mut recv = conn.accept_uni().await.ok()?;
    let frame = transport::read_frame(&mut recv).await.ok()??;
    Some((recv, frame))
}

/// The machine being added: the listener's half.
///
/// Runs the comparison on a connection from `theirs`, shows the three numbers
/// through the service, and waits for the pick, then for the adding machine's
/// confirmation. Returns that machine's input stream and its first frame,
/// its `Hello`, once both machines confirmed; `None` when the attempt ended,
/// with the connection closed and the service told.
pub(crate) async fn as_added(
    pairings: &Pairings,
    conn: &Connection,
    ours: &str,
    theirs: &str,
    addr: SocketAddr,
) -> Option<(RecvStream, ProtoEvent)> {
    let ended = |why: Option<Why>| {
        if let Some(why) = why {
            log::info!("pairing with {theirs} at {addr} ended: {why:?}");
            pairings.tell(PairingEvent::Ended {
                fingerprint: theirs.to_string(),
                why,
                handle: None,
            });
        }
        conn.close(0u32.into(), b"pairing ended");
        None
    };
    let number = match pair_ceremony::as_responder(conn, ours, theirs).await {
        Ok(number) => number,
        Err(e) => {
            log::info!("{addr}: no number compared with {theirs}: {e}");
            return ended(before_number(conn, e));
        }
    };
    let Some(ticket) = pairings.hold(theirs, conn) else {
        log::info!("{addr}: a pairing with {theirs} is already open; closing this one");
        conn.close(0u32.into(), b"pairing busy");
        return None;
    };
    pairings.tell(PairingEvent::Number {
        fingerprint: theirs.to_string(),
        addr,
        role: Role::Pick,
        number,
        handle: None,
    });
    if let Err(why) = ticket.until(conn, Stage::Answered, || true).await {
        return ended(why);
    }
    // Read only now, after the right pick: the adding machine's first frame
    // on its input stream, which it sends once its person confirmed.
    let (recv, hello) = match ticket.bounded(conn, first_frame(conn)).await {
        Ok(first) => first,
        Err(why) => return ended(why),
    };
    if !matches!(hello, ProtoEvent::Hello { .. }) {
        log::warn!("{addr}: {theirs} sent {hello} before confirming the pairing");
        return ended(Some(Why::Unexpected));
    }
    pairings.tell(PairingEvent::PeerConfirmed {
        fingerprint: theirs.to_string(),
    });
    if let Err(why) = ticket.until(conn, Stage::Settled, || true).await {
        return ended(why);
    }
    Some((recv, hello))
}

/// What the adding machine has once both machines confirmed: its input
/// stream, with its `Hello` and capabilities already sent, the stream the
/// other machine answers on, and the build that answer named.
pub(crate) struct Confirmed {
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
    pub(crate) commit: [u8; 8],
}

/// The adding machine: the dialler's half.
///
/// Runs the comparison on the connection a dial for device `handle` made,
/// shows the number through the service, and waits for the person here to
/// confirm and for the other machine's answer. Ends if the device is removed
/// or switched off meanwhile.
pub(crate) async fn as_adding(
    pairings: &Pairings,
    conn: &Connection,
    ours: &str,
    theirs: &str,
    addr: SocketAddr,
    handle: ClientHandle,
    clients: &ClientManager,
) -> Option<Confirmed> {
    let ended = |why: Option<Why>| {
        if let Some(why) = why {
            log::info!("pairing with {theirs} at {addr} ended: {why:?}");
            pairings.tell(PairingEvent::Ended {
                fingerprint: theirs.to_string(),
                why,
                handle: Some(handle),
            });
        }
        conn.close(0u32.into(), b"pairing ended");
        None
    };
    let number = match pair_ceremony::as_initiator(conn, ours, theirs).await {
        Ok(number) => number,
        Err(e) => {
            log::info!("{addr}: no number compared with {theirs}: {e}");
            return ended(before_number(conn, e));
        }
    };
    let Some(ticket) = pairings.hold(theirs, conn) else {
        log::info!("{addr}: a pairing with {theirs} is already open; closing this one");
        conn.close(0u32.into(), b"pairing busy");
        return None;
    };
    pairings.tell(PairingEvent::Number {
        fingerprint: theirs.to_string(),
        addr,
        role: Role::Show,
        number,
        handle: Some(handle),
    });
    let still = || clients.targets(handle, addr) && clients.is_on(handle);
    if let Err(why) = ticket.until(conn, Stage::Answered, still).await {
        return ended(why);
    }
    // The person here confirmed. Saying so is this machine's first frame.
    let send = async {
        let mut send = conn.open_uni().await.ok()?;
        transport::write_frame(
            &mut send,
            ProtoEvent::Hello {
                commit: crate::config::local_commit(),
            },
        )
        .await
        .ok()?;
        transport::write_frame(
            &mut send,
            ProtoEvent::Capability {
                flags: crate::config::local_caps(),
            },
        )
        .await
        .ok()?;
        Some(send)
    };
    let send = match ticket.bounded(conn, send).await {
        Ok(send) => send,
        Err(why) => return ended(why),
    };
    // The other machine's answer: sent once its person picked the right
    // number and it read the frame above.
    let (recv, answer) = match ticket.bounded(conn, first_frame(conn)).await {
        Ok(first) => first,
        Err(why) => return ended(why),
    };
    let ProtoEvent::Hello { commit } = answer else {
        log::warn!("{addr}: {theirs} sent {answer} before confirming the pairing");
        return ended(Some(Why::Unexpected));
    };
    pairings.tell(PairingEvent::PeerConfirmed {
        fingerprint: theirs.to_string(),
    });
    if let Err(why) = ticket.until(conn, Stage::Settled, still).await {
        return ended(why);
    }
    Some(Confirmed { send, recv, commit })
}

/// The three numbers the machine being added offers: the real one at a
/// random place among two others, all different. `None` if this machine
/// could not draw randomness, which ends the attempt rather than offering a
/// guessable choice.
pub(crate) fn choices(real: &str) -> Option<Vec<String>> {
    let mut failed = false;
    let draw = || {
        let mut b = [0u8; 4];
        if !pair_ceremony::fill_random(&mut b) {
            failed = true;
        }
        u32::from_le_bytes(b)
    };
    let out = choices_from(real, draw);
    (!failed).then_some(out)
}

/// [`choices`] from a source of numbers. The real one's place is the first
/// draw, so it moves; each other is drawn until it differs from all before it.
fn choices_from(real: &str, mut draw: impl FnMut() -> u32) -> Vec<String> {
    let at = (draw() % 3) as usize;
    let mut out: Vec<String> = vec![real.to_string()];
    // Bounded: a source that keeps repeating gives up with counted numbers,
    // which are still different from each other and from the real one.
    let mut tries = 0u32;
    while out.len() < 3 {
        let candidate = if tries < 64 {
            format!("{:06}", draw() % 1_000_000)
        } else {
            format!("{:06}", (tries as u64 * 7919) % 1_000_000)
        };
        tries += 1;
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out.swap(0, at);
    out
}

#[cfg(test)]
mod the_three_numbers {
    use super::*;

    /// Three different numbers, the real one among them, and the real one's
    /// place changes: a card that always put it first would be answered by
    /// position, not by looking at the other screen (#11).
    // LEDGER G-10 | class B | 1 return value: choices
    #[test]
    fn the_three_numbers_are_distinct_and_the_real_one_moves() {
        let mut seen_at = [0usize; 3];
        for _ in 0..300 {
            let offered = choices("042917").expect("randomness");
            assert_eq!(offered.len(), 3, "offered {offered:?}");
            let mut distinct = offered.clone();
            distinct.sort();
            distinct.dedup();
            assert_eq!(distinct.len(), 3, "not all different: {offered:?}");
            assert!(
                offered.iter().all(|n| n.len() == 6),
                "not six digits: {offered:?}"
            );
            let at = offered
                .iter()
                .position(|n| n == "042917")
                .unwrap_or_else(|| panic!("the real number is not offered: {offered:?}"));
            seen_at[at] += 1;
        }
        assert!(
            seen_at.iter().all(|&n| n > 0),
            "the real number never moved to some place in 300 draws: {seen_at:?}"
        );
    }

    /// A source that keeps giving the real number, or the same one, still
    /// yields three different numbers.
    // LEDGER G-10b | class B | 1 return value: choices_from
    #[test]
    fn a_source_that_repeats_still_offers_three_different_numbers() {
        let offered = choices_from("000007", || 7);
        let mut distinct = offered.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 3, "{offered:?}");
        assert!(offered.contains(&"000007".to_string()));
    }
}

#[cfg(test)]
mod on_the_wire {
    //! Two machines over loopback: a production listener or dialler on one
    //! side, and on the other the production one too, or a peer that speaks
    //! the wire itself so a test can do what the production code never does.
    //! These tests stand in for the service, which answers the attempts: the
    //! person's answer is [`Pairings::answered`], and the store's
    //! confirmation `TrustStore::confirm` then [`Pairings::settled`].

    use std::sync::{Arc, RwLock};

    use hops_ipc::Position;
    use hops_proto::ProtoEvent;
    use input_emulation::recording::{Recorded, Recording};
    use input_event::{Event, KeyboardEvent};

    use super::*;
    use crate::emulation::{Emulation, EmulationEvent};
    use crate::listen::LanMouseListener;
    use crate::test_harness::{Machine, NEVER_WITHIN, dialer, machine, next_within, run_local};
    use crate::transport::{PeerClipboard, Trust};
    use crate::trust::{Caps, TrustStore};

    /// How long a test waits for what must happen.
    const WITHIN: Duration = Duration::from_secs(30);

    /// `us`'s store, holding for `peer` the lease an approval here issued for
    /// `caps`, not yet confirmed on both machines.
    fn approved(us: &Machine, peer: &Machine, caps: Caps) -> Trust {
        let mut s = TrustStore::new(&us.fingerprint, 0).expect("ours");
        s.issue(&peer.fingerprint, "peer", caps).expect("approve");
        assert!(s.is_pairing(&peer.fingerprint), "precondition: mid-pairing");
        Arc::new(RwLock::new(s))
    }

    /// `us`'s store, paired with `peer` for `caps`.
    fn paired(us: &Machine, peer: &Machine, caps: Caps) -> Trust {
        let mut s = TrustStore::new(&us.fingerprint, 0).expect("ours");
        s.issue_confirmed(&peer.fingerprint, "peer", caps)
            .expect("pair");
        Arc::new(RwLock::new(s))
    }

    /// The machine being added: a production listener into a recording
    /// backend, and the attempts it holds.
    struct Added {
        me: Machine,
        trust: Trust,
        port: u16,
        pairings: Pairings,
        events: Receiver<PairingEvent>,
        emulation: Emulation,
        recording: Recording,
        clipboard: Receiver<PeerClipboard>,
    }

    async fn added(me: Machine, trust: Trust) -> Added {
        let (clip_tx, clipboard) = channel();
        let (mut listener, port) =
            LanMouseListener::bind_loopback(me.identity.clone(), trust.clone(), clip_tx)
                .await
                .expect("listener");
        let pairings = listener.pairings();
        let events = listener.take_pairing_events().expect("pairing events");
        let recording = Recording::new();
        let emulation = Emulation::new(Some(recording.backend()), listener, trust.clone());
        Added {
            me,
            trust,
            port,
            pairings,
            events,
            emulation,
            recording,
            clipboard,
        }
    }

    impl Added {
        /// Every input event that reached the backend.
        fn injected(&self) -> Vec<Event> {
            self.recording
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    Recorded::Consume(e, _) => Some(e),
                    _ => None,
                })
                .collect()
        }

        /// Anything the emulation said about a peer within `limit`: that it
        /// connected, entered, or sent a Hello or its capabilities.
        async fn heard_of_a_peer(&mut self, limit: Duration) -> Option<&'static str> {
            let deadline = tokio::time::Instant::now() + limit;
            loop {
                let event = match tokio::time::timeout_at(deadline, self.emulation.event()).await {
                    Ok(event) => event,
                    Err(_) => return None,
                };
                match event {
                    EmulationEvent::Connected { .. } => return Some("Connected"),
                    EmulationEvent::Entered { .. } => return Some("Entered"),
                    EmulationEvent::PeerHello { .. } => return Some("PeerHello"),
                    EmulationEvent::PeerCaps { .. } => return Some("PeerCaps"),
                    EmulationEvent::ReleaseNotify => return Some("ReleaseNotify"),
                    _ => {}
                }
            }
        }
    }

    /// A dialler that speaks the wire itself. Its own TLS check accepts the
    /// machine it dials.
    struct RawDialer {
        me: Machine,
        endpoint: quinn::Endpoint,
    }

    fn raw_dialer(me: Machine, dials: &Machine) -> RawDialer {
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")).expect("endpoint");
        endpoint.set_default_client_config(crate::test_harness::raw_client_config(
            &me,
            paired(&me, dials, Caps::OUTBOUND),
            1 << 20,
        ));
        RawDialer { me, endpoint }
    }

    impl RawDialer {
        async fn connect(&self, port: u16) -> Result<quinn::Connection, String> {
            let at = SocketAddr::new("127.0.0.1".parse().expect("loopback"), port);
            let connecting = self
                .endpoint
                .connect(at, "grabbr")
                .map_err(|e| e.to_string())?;
            match tokio::time::timeout(WITHIN, connecting).await {
                Ok(r) => r.map_err(|e| e.to_string()),
                Err(_) => Err("timed out".to_string()),
            }
        }

        /// Whether the listener's TLS check refused this dialler: the
        /// handshake fails, or the connection it thought complete is closed
        /// by a TLS alert rather than by the listener's code after it.
        async fn refused_at_tls(&self, port: u16) -> bool {
            let conn = match self.connect(port).await {
                Ok(conn) => conn,
                Err(_) => return true,
            };
            match tokio::time::timeout(WITHIN, conn.closed()).await {
                Ok(quinn::ConnectionError::ConnectionClosed(_)) => true,
                Ok(_) | Err(_) => false,
            }
        }
    }

    /// A receiver that speaks the wire itself. Its own TLS check lets the
    /// machine that dials it in.
    struct RawReceiver {
        me: Machine,
        endpoint: quinn::Endpoint,
        port: u16,
    }

    fn raw_receiver(me: Machine, dialled_by: &Machine) -> RawReceiver {
        crate::transport::install_crypto_provider();
        let cfg = crate::listen::server_config(
            &me.identity,
            paired(&me, dialled_by, Caps::INBOUND),
            Default::default(),
        )
        .expect("server config");
        let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().expect("loopback"))
            .expect("endpoint");
        let port = endpoint.local_addr().expect("bound").port();
        RawReceiver { me, endpoint, port }
    }

    impl RawReceiver {
        /// The next connection whose handshake completes, within `limit`.
        async fn next(&self, limit: Duration) -> Option<quinn::Connection> {
            let deadline = tokio::time::Instant::now() + limit;
            loop {
                let incoming = tokio::time::timeout_at(deadline, self.endpoint.accept())
                    .await
                    .ok()??;
                if let Ok(Ok(conn)) = tokio::time::timeout_at(deadline, incoming).await {
                    return Some(conn);
                }
            }
        }
    }

    /// The next number an attempt showed on `events`.
    async fn number(events: &mut Receiver<PairingEvent>, what: &str) -> (Role, String) {
        match next_within(events, WITHIN).await {
            Some(PairingEvent::Number { role, number, .. }) => (role, number),
            other => panic!("{what} reached no number: {other:?}"),
        }
    }

    fn key(key: u32, state: u8) -> Event {
        Event::Keyboard(KeyboardEvent::Key {
            time: 0,
            key,
            state,
        })
    }

    const KEY_A: u32 = 30;

    // LEDGER G-2 | class B | 1 return value + 6 struct state: pair_ceremony::as_initiator against LanMouseListener's PairingEvent::Number
    /// A machine that approved being added, and has not yet confirmed a
    /// number, lets the adding machine in far enough to compare one, and
    /// offers the same number the adding machine computes.
    #[test]
    fn an_approved_receiver_reaches_the_number() {
        run_local(async {
            let (b, a) = (machine(), machine());
            let trust = approved(&b, &a, Caps::INBOUND);
            let mut b = added(b, trust).await;
            let a = raw_dialer(a, &b.me);
            let conn = a
                .connect(b.port)
                .await
                .expect("an approved sender completes the handshake");
            let theirs =
                crate::pair_ceremony::as_initiator(&conn, &a.me.fingerprint, &b.me.fingerprint)
                    .await
                    .expect("the receiver takes part in the comparison");
            let (role, number) = number(&mut b.events, "the receiver").await;
            assert_eq!(role, Role::Pick, "the machine being added picks");
            assert_eq!(number, theirs, "the two machines reached different numbers");
        });
    }

    // LEDGER G-1 | class B | 6 struct state: PairingEvent::Number from LanMouseConnection and LanMouseListener
    /// An approved sender, the production dialler, reaches the number with
    /// the production listener: the same number on both, shown on the adding
    /// machine and offered on the one being added.
    #[test]
    fn an_approved_sender_reaches_the_number() {
        run_local(async {
            let (a, b) = (machine(), machine());
            let b_trust = approved(&b, &a, Caps::INBOUND);
            let mut b = added(b, b_trust).await;
            let mut d = dialer(
                &a,
                approved(&a, &b.me, Caps::OUTBOUND),
                b.port,
                Position::Left,
            );
            let mut a_events = d.conn.take_pairing_events().expect("pairing events");
            d.conn.dial(d.handle).await;
            let (role, shown) = number(&mut a_events, "the sender").await;
            assert_eq!(role, Role::Show, "the adding machine shows the number");
            let (_, offered) = number(&mut b.events, "the receiver").await;
            assert_eq!(shown, offered, "the two machines reached different numbers");
            assert!(
                d.clients.active_addr(d.handle).is_none(),
                "a link was taken up before either machine confirmed"
            );
        });
    }

    // LEDGER G-1b | class B | 6 struct state: Recording after LanMouseConnection + LanMouseListener pair
    /// The whole of it, both ends production code: two approvals, the
    /// number, both answers, and the first input the adding machine sends
    /// then arrives on the machine it added.
    #[test]
    fn two_approvals_and_both_answers_pair_and_carry_input() {
        run_local(async {
            let (a, b) = (machine(), machine());
            let b_trust = approved(&b, &a, Caps::INBOUND);
            let mut b = added(b, b_trust).await;
            let a_trust = approved(&a, &b.me, Caps::OUTBOUND);
            let mut d = dialer(&a, a_trust.clone(), b.port, Position::Left);
            let a_pairings = d.conn.pairings();
            let mut a_events = d.conn.take_pairing_events().expect("pairing events");
            d.conn.dial(d.handle).await;
            let (_, shown) = number(&mut a_events, "the sender").await;
            let (_, _) = number(&mut b.events, "the receiver").await;
            // The right pick on the machine being added, and the confirm on
            // the one adding.
            assert!(b.pairings.answered(&a.fingerprint));
            assert!(a_pairings.answered(&b.me.fingerprint));
            let (mut a_done, mut b_done) = (false, false);
            let deadline = tokio::time::Instant::now() + WITHIN;
            while !(a_done && b_done) {
                tokio::select! {
                    e = a_events.recv() => match e {
                        Some(PairingEvent::PeerConfirmed { fingerprint }) => {
                            a_trust.write().expect("lock").confirm(&fingerprint).expect("confirm");
                            a_pairings.settled(&fingerprint);
                            a_done = true;
                        }
                        other => panic!("the sender said {other:?}"),
                    },
                    e = b.events.recv() => match e {
                        Some(PairingEvent::PeerConfirmed { fingerprint }) => {
                            b.trust.write().expect("lock").confirm(&fingerprint).expect("confirm");
                            b.pairings.settled(&fingerprint);
                            b_done = true;
                        }
                        other => panic!("the receiver said {other:?}"),
                    },
                    _ = tokio::time::sleep_until(deadline) => {
                        panic!("both machines did not confirm (sender {a_done}, receiver {b_done})")
                    }
                }
            }
            assert!(!shown.is_empty());
            d.until_alive().await;
            d.send(ProtoEvent::Enter(hops_proto::Position::Right)).await;
            d.send(ProtoEvent::Input(key(KEY_A, 1))).await;
            crate::test_harness::wait_until("the key to arrive", WITHIN, || {
                b.injected().contains(&key(KEY_A, 1))
            })
            .await;
        });
    }

    // LEDGER G-3 | class B | 6 struct state: Recording after LanMouseListener admits the pairing's connection
    /// Once the person picked the right number and the adding machine
    /// confirmed, its input arrives on the connection the number was
    /// compared on. No second handshake: this dialler has one connection.
    #[test]
    fn the_pick_admits_input_on_the_same_connection() {
        run_local(async {
            let (b, a) = (machine(), machine());
            let trust = approved(&b, &a, Caps::INBOUND);
            let mut b = added(b, trust).await;
            let a = raw_dialer(a, &b.me);
            let conn = a.connect(b.port).await.expect("handshake");
            crate::pair_ceremony::as_initiator(&conn, &a.me.fingerprint, &b.me.fingerprint)
                .await
                .expect("a number");
            number(&mut b.events, "the receiver").await;
            assert!(b.pairings.answered(&a.me.fingerprint), "the right pick");
            // The adding machine confirms: its input stream, its Hello first.
            let mut input = conn.open_uni().await.expect("input stream");
            crate::transport::write_frame(&mut input, ProtoEvent::Hello { commit: [0; 8] })
                .await
                .expect("hello");
            match next_within(&mut b.events, WITHIN).await {
                Some(PairingEvent::PeerConfirmed { fingerprint }) => {
                    b.trust
                        .write()
                        .expect("lock")
                        .confirm(&fingerprint)
                        .expect("confirm");
                    assert!(b.pairings.settled(&fingerprint));
                }
                other => panic!("the receiver did not read the confirmation: {other:?}"),
            }
            // It answers on the same connection.
            let mut replies = tokio::time::timeout(WITHIN, conn.accept_uni())
                .await
                .expect("an answer in time")
                .expect("the receiver's answer stream");
            let answer = crate::transport::read_frame(&mut replies)
                .await
                .expect("a frame")
                .expect("not the end");
            assert!(
                matches!(answer, ProtoEvent::Hello { .. }),
                "the answer was {answer}, not a Hello"
            );
            for event in [
                ProtoEvent::Enter(hops_proto::Position::Right),
                ProtoEvent::Input(key(KEY_A, 1)),
            ] {
                crate::transport::write_frame(&mut input, event)
                    .await
                    .expect("send");
            }
            crate::test_harness::wait_until("the key to arrive", WITHIN, || {
                b.injected().contains(&key(KEY_A, 1))
            })
            .await;
        });
    }

    // LEDGER G-12 | class B | 2 bytes at the dialler + 6 struct state: Recording, EmulationEvent, clipboard queue
    /// Until both machines confirm, a machine mid-pairing gets nothing back
    /// and nothing it sends is read: not its Hello, not a ping, not a
    /// crossing, not a key, not its clipboard.
    #[test]
    fn nothing_moves_while_pending() {
        run_local(async {
            let (b, a) = (machine(), machine());
            let trust = approved(&b, &a, Caps::INBOUND);
            let mut b = added(b, trust).await;
            let a = raw_dialer(a, &b.me);
            let conn = a.connect(b.port).await.expect("handshake");
            crate::pair_ceremony::as_initiator(&conn, &a.me.fingerprint, &b.me.fingerprint)
                .await
                .expect("a number");
            number(&mut b.events, "the receiver").await;

            let mut input = conn.open_uni().await.expect("input stream");
            for event in [
                ProtoEvent::Hello { commit: [0; 8] },
                ProtoEvent::Capability { flags: 0 },
                ProtoEvent::Ping,
                ProtoEvent::Enter(hops_proto::Position::Right),
                ProtoEvent::Input(key(KEY_A, 1)),
                ProtoEvent::Input(key(KEY_A, 0)),
            ] {
                crate::transport::write_frame(&mut input, event)
                    .await
                    .expect("send");
            }
            let clip = conn.clone();
            tokio::task::spawn_local(async move {
                let _ = crate::transport::send_clipboard(&clip, "not for you").await;
            });

            let answered = tokio::time::timeout(NEVER_WITHIN, conn.accept_uni()).await;
            assert!(
                answered.is_err(),
                "the machine being added opened a stream to a machine nobody \
                 confirmed"
            );
            if let Some(what) = b.heard_of_a_peer(NEVER_WITHIN).await {
                panic!("the emulation heard {what} from a machine mid-pairing");
            }
            assert!(
                b.injected().is_empty(),
                "input from a machine mid-pairing was injected: {:?}",
                b.injected()
            );
            assert!(
                next_within(&mut b.clipboard, NEVER_WITHIN).await.is_none(),
                "clipboard from a machine mid-pairing was queued"
            );
            assert!(
                next_within(&mut b.events, NEVER_WITHIN).await.is_none(),
                "the receiver read a confirmation nobody here gave"
            );
        });
    }

    // LEDGER G-13 | class B | 2 bytes at the receiver + 6 struct state: ClientManager, clipboard queue
    /// The dialler's half: until both confirm, the adding machine opens no
    /// stream and sends no Hello, and nothing the other machine sends is
    /// read, its clipboard included.
    #[test]
    fn nothing_moves_while_pending_on_the_dialer() {
        run_local(async {
            let (a, b) = (machine(), machine());
            let b = raw_receiver(b, &a);
            let mut d = dialer(
                &a,
                approved(&a, &b.me, Caps::OUTBOUND),
                b.port,
                Position::Left,
            );
            let mut a_events = d.conn.take_pairing_events().expect("pairing events");
            d.conn.dial(d.handle).await;
            let conn = b.next(WITHIN).await.expect("the dial reaches the receiver");
            crate::pair_ceremony::as_responder(&conn, &b.me.fingerprint, &a.fingerprint)
                .await
                .expect("a number");
            number(&mut a_events, "the sender").await;

            let mut replies = conn.open_uni().await.expect("reply stream");
            for event in [
                ProtoEvent::Hello { commit: [0; 8] },
                ProtoEvent::Capability { flags: 0 },
                ProtoEvent::Pong(true),
                ProtoEvent::Leave(0),
            ] {
                crate::transport::write_frame(&mut replies, event)
                    .await
                    .expect("send");
            }
            let clip = conn.clone();
            tokio::task::spawn_local(async move {
                let _ = crate::transport::send_clipboard(&clip, "not for you").await;
            });

            let opened = tokio::time::timeout(NEVER_WITHIN, conn.accept_uni()).await;
            assert!(
                opened.is_err(),
                "the adding machine opened its input stream before anyone confirmed"
            );
            assert!(
                !d.clients.alive(d.handle) && d.clients.active_addr(d.handle).is_none(),
                "the adding machine took up a link nobody confirmed"
            );
            assert!(
                next_within(&mut d.notices.clipboard, NEVER_WITHIN)
                    .await
                    .is_none(),
                "clipboard from a machine mid-pairing was queued"
            );
            assert!(
                next_within(&mut a_events, NEVER_WITHIN).await.is_none(),
                "the adding machine read a confirmation nobody here gave"
            );
        });
    }

    // LEDGER G-11 | class B | 2 connections counted at the receiver
    /// Crossing towards the machine being added, while the number is on
    /// screen, opens no second connection: the dial is still under way.
    #[test]
    fn a_crossing_while_pending_opens_no_second_connection() {
        run_local(async {
            let (a, b) = (machine(), machine());
            let b = raw_receiver(b, &a);
            let mut d = dialer(
                &a,
                approved(&a, &b.me, Caps::OUTBOUND),
                b.port,
                Position::Left,
            );
            let mut a_events = d.conn.take_pairing_events().expect("pairing events");
            d.conn.dial(d.handle).await;
            let conn = b.next(WITHIN).await.expect("the dial reaches the receiver");
            crate::pair_ceremony::as_responder(&conn, &b.me.fingerprint, &a.fingerprint)
                .await
                .expect("a number");
            number(&mut a_events, "the sender").await;
            for _ in 0..5 {
                let _ = d
                    .conn
                    .send(ProtoEvent::Enter(hops_proto::Position::Right), d.handle)
                    .await;
                d.conn.dial(d.handle).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(
                b.next(NEVER_WITHIN).await.is_none(),
                "a crossing during the comparison opened a second connection"
            );
            drop(conn);
        });
    }

    // LEDGER G-7 | class B | 2 handshake outcome at each end + 6 struct state: no PairingEvent
    /// The machine being added holds its approval in the other direction:
    /// "may drive me". Crossing into the machine adding it, it dials the
    /// wrong way, and each end's TLS check refuses on its own, so no
    /// comparison starts.
    #[test]
    fn the_added_machine_crossing_into_its_pending_peer_starts_no_ceremony() {
        run_local(async {
            // The adding machine listening: its approval is "I may drive it".
            let (adding, being_added) = (machine(), machine());
            let trust = approved(&adding, &being_added, Caps::OUTBOUND);
            let mut listening = added(adding, trust).await;
            let crossing = raw_dialer(being_added, &listening.me);
            assert!(
                crossing.refused_at_tls(listening.port).await,
                "the adding machine's TLS check let the machine it is adding dial it"
            );
            assert!(
                next_within(&mut listening.events, NEVER_WITHIN)
                    .await
                    .is_none(),
                "a comparison started the wrong way"
            );

            // The machine being added dialling: its approval is "it may drive me".
            let (adding, being_added) = (machine(), machine());
            let receiving = raw_receiver(adding, &being_added);
            let mut d = dialer(
                &being_added,
                approved(&being_added, &receiving.me, Caps::INBOUND),
                receiving.port,
                Position::Left,
            );
            let mut events = d.conn.take_pairing_events().expect("pairing events");
            d.conn.dial(d.handle).await;
            assert!(
                receiving.next(NEVER_WITHIN * 3).await.is_none(),
                "the machine being added completed a dial to the machine adding it"
            );
            assert!(
                next_within(&mut events, NEVER_WITHIN).await.is_none(),
                "a comparison started the wrong way"
            );
        });
    }

    // LEDGER G-14 | class B | 6 struct state: the peer's connection closed, PairingEvent::Ended
    /// An attempt ends, and its connection closes, when it is ended here
    /// (the device removed), when the device being added is switched off,
    /// and when nobody answers in time.
    #[test]
    fn a_pending_pairing_closes_on_removal_and_after_120_s() {
        assert_eq!(
            Pairings::DEADLINE,
            Duration::from_secs(120),
            "the time both machines have to answer is not the two minutes the notices name"
        );
        run_local(async {
            // Removed on the machine being added.
            let (b, a) = (machine(), machine());
            let trust = approved(&b, &a, Caps::INBOUND);
            let mut b = added(b, trust).await;
            let a = raw_dialer(a, &b.me);
            let conn = a.connect(b.port).await.expect("handshake");
            crate::pair_ceremony::as_initiator(&conn, &a.me.fingerprint, &b.me.fingerprint)
                .await
                .expect("a number");
            number(&mut b.events, "the receiver").await;
            assert!(b.pairings.end(&a.me.fingerprint), "an attempt was held");
            assert!(
                tokio::time::timeout(WITHIN, conn.closed()).await.is_ok(),
                "a pairing ended here kept its connection open"
            );

            // Nobody answers in time.
            let (b, a) = (machine(), machine());
            let trust = approved(&b, &a, Caps::INBOUND);
            let mut b = added(b, trust).await;
            b.pairings.set_deadline(Duration::from_millis(300));
            let a = raw_dialer(a, &b.me);
            let conn = a.connect(b.port).await.expect("handshake");
            crate::pair_ceremony::as_initiator(&conn, &a.me.fingerprint, &b.me.fingerprint)
                .await
                .expect("a number");
            number(&mut b.events, "the receiver").await;
            assert!(
                tokio::time::timeout(WITHIN, conn.closed()).await.is_ok(),
                "a pairing nobody answered kept its connection open past its deadline"
            );
            match next_within(&mut b.events, WITHIN).await {
                Some(PairingEvent::Ended { why, .. }) => assert_eq!(why, Why::TimedOut),
                other => panic!("the service was not told the attempt ended: {other:?}"),
            }

            // The device being added is switched off on the adding machine.
            let (a, b) = (machine(), machine());
            let b = raw_receiver(b, &a);
            let mut d = dialer(
                &a,
                approved(&a, &b.me, Caps::OUTBOUND),
                b.port,
                Position::Left,
            );
            let mut a_events = d.conn.take_pairing_events().expect("pairing events");
            d.conn.dial(d.handle).await;
            let conn = b.next(WITHIN).await.expect("the dial reaches the receiver");
            crate::pair_ceremony::as_responder(&conn, &b.me.fingerprint, &a.fingerprint)
                .await
                .expect("a number");
            number(&mut a_events, "the sender").await;
            d.clients.deactivate_client(d.handle);
            assert!(
                tokio::time::timeout(WITHIN, conn.closed()).await.is_ok(),
                "switching the device off kept the pairing's connection open"
            );
            match next_within(&mut a_events, WITHIN).await {
                Some(PairingEvent::Ended { why, handle, .. }) => {
                    assert_eq!(why, Why::DeviceGone);
                    assert_eq!(handle, Some(d.handle));
                }
                other => panic!("the service was not told the attempt ended: {other:?}"),
            }
        });
    }

    // LEDGER G-15 | class B | 6 struct state: PairingEvent::Ended from LanMouseConnection
    /// A receiver that offers no number within the step, as a build from
    /// before the comparison does, ends the attempt with that reason, so the
    /// adding machine can say what to do.
    #[test]
    fn a_peer_that_offers_no_number_is_named() {
        run_local(async {
            let (a, b) = (machine(), machine());
            let b = raw_receiver(b, &a);
            let mut d = dialer(
                &a,
                approved(&a, &b.me, Caps::OUTBOUND),
                b.port,
                Position::Left,
            );
            let mut a_events = d.conn.take_pairing_events().expect("pairing events");
            d.conn.dial(d.handle).await;
            let _conn = b.next(WITHIN).await.expect("the dial reaches the receiver");
            match next_within(&mut a_events, WITHIN).await {
                Some(PairingEvent::Ended { why, handle, .. }) => {
                    assert_eq!(why, Why::NoComparison);
                    assert_eq!(handle, Some(d.handle));
                }
                other => panic!("an older receiver was not named: {other:?}"),
            }
        });
    }
}

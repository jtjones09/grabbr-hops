//! Pick-the-number pairing (#11, #167): what happens on the connection that
//! two approvals let two machines make, until both machines confirm.
//!
//! An approval issues a lease that grants nothing (`TrustStore::confirm`).
//! It admits the other machine at TLS, whichever machine dials, far enough
//! to run [`crate::pair_ceremony`] and no further: which way control goes is
//! what each person answered on the card (#220), not who dialled. The machine
//! that dialled shows the number; the machine it reached offers three and
//! asks which one it sees. A wrong pick ends the attempt, and the dialling
//! machine still confirms on its side.
//!
//! # One comparison per pair of machines
//!
//! Two machines adding each other dial each other, and both dials reach a
//! machine mid-pairing. Each machine holds one attempt per machine, for both
//! of its transports, and both keep the same one: the connection the machine
//! whose fingerprint sorts first dialled ([`preferred`]). The other is closed
//! as superseded while nobody here has answered it yet, and the machine at
//! its other end lets it go without ending the pairing.
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
    /// The other machine closed this connection because another connection
    /// between the two carries the comparison. Ends nothing: the approval
    /// stays, and the number card goes until that connection shows one.
    Withdrawn,
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
        /// The connection it was compared on.
        conn: usize,
    },
    /// The person here answered, and the other machine's confirmation then
    /// arrived on the connection. The service confirms the lease and calls
    /// [`Pairings::settled`].
    PeerConfirmed { fingerprint: String },
    /// Ended without pairing. The service forgets the lease, unless the
    /// attempt was [`Why::Withdrawn`].
    Ended {
        fingerprint: String,
        why: Why,
        handle: Option<ClientHandle>,
        /// The connection it ended on.
        conn: usize,
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
    /// Dialled by the machine whose fingerprint sorts first.
    preferred: bool,
}

/// Whether the connection `dialler` made to `listener` is the one two
/// machines pairing compare their number on, when there are two: the dial
/// of the machine whose fingerprint sorts first. Both machines work it out
/// alike from the same two fingerprints, so both keep the same connection.
pub(crate) fn preferred(dialler: &str, listener: &str) -> bool {
    dialler < listener
}

/// What closing a connection for another between the same two machines
/// says, so the machine at its other end ends nothing.
const SUPERSEDED: &[u8] = b"pairing superseded";
/// What closing a second connection while one is held says.
const BUSY: &[u8] = b"pairing busy";

/// Whether the other machine closed `conn` because another connection
/// between the two carries the comparison.
fn withdrawn_by_peer(conn: &Connection) -> bool {
    matches!(
        conn.close_reason(),
        Some(quinn::ConnectionError::ApplicationClosed(c))
            if &c.reason[..] == SUPERSEDED || &c.reason[..] == BUSY
    )
}

/// Why an attempt whose connection closed ended.
fn closed(conn: &Connection) -> Why {
    if withdrawn_by_peer(conn) {
        Why::Withdrawn
    } else {
        Why::Closed
    }
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

    /// The connection held for `fingerprint`, if any.
    #[cfg(test)]
    fn held_conn(&self, fingerprint: &str) -> Option<usize> {
        self.board
            .borrow()
            .held
            .get(fingerprint)
            .map(|h| h.conn.stable_id())
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

    /// Whether an attempt with `fingerprint` on a connection that is
    /// `preferred` or not may start: nothing is held for it, or what is held
    /// gives way to this one.
    fn may_start(&self, fingerprint: &str, preferred: bool) -> bool {
        self.board
            .borrow()
            .held
            .get(fingerprint)
            .is_none_or(|held| gives_way(held, preferred))
    }

    /// Hold `conn` for `fingerprint`, unless another attempt with it is held
    /// that this one does not supersede (see [`preferred`]).
    fn hold(&self, fingerprint: &str, conn: &Connection, preferred: bool) -> Option<Ticket> {
        let mut board = self.board.borrow_mut();
        if let Some(held) = board.held.get_mut(fingerprint) {
            if !gives_way(held, preferred) {
                return None;
            }
            // Its holder ends quietly: the attempt goes on, here.
            log::info!("{fingerprint}: the other connection between the two carries the pairing");
            held.stage = Stage::Over;
            held.conn.close(0u32.into(), SUPERSEDED);
            held.wake.notify_one();
        }
        let wake = Rc::new(Notify::new());
        board.held.insert(
            fingerprint.to_string(),
            Held {
                conn: conn.clone(),
                stage: Stage::Comparing,
                wake: wake.clone(),
                preferred,
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

/// Whether `held` gives way to an attempt on a connection that is
/// `preferred` or not: only the one both machines keep supersedes, and only
/// before anyone here answered, so an answer given is never thrown away
/// here.
fn gives_way(held: &Held, preferred: bool) -> bool {
    preferred && !held.preferred && held.stage == Stage::Comparing
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
    /// This attempt's stage: over once another took its place.
    fn stage(&self) -> Stage {
        self.pairings
            .board
            .borrow()
            .held
            .get(&self.fingerprint)
            .filter(|h| h.conn.stable_id() == self.id)
            .map_or(Stage::Over, |h| h.stage)
    }

    /// Why this attempt ended with its connection closed: nothing to say
    /// when it was ended here, another taking its place included.
    fn why_closed(&self, conn: &Connection) -> Option<Why> {
        (self.stage() != Stage::Over).then(|| closed(conn))
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
                _ = conn.closed() => return Err(self.why_closed(conn)),
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
                None if conn.close_reason().is_some() => Err(self.why_closed(conn)),
                None => Err(Some(Why::Unexpected)),
            },
            _ = conn.closed() => Err(self.why_closed(conn)),
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
                conn: conn.stable_id(),
            });
        }
        if conn.close_reason().is_none() {
            conn.close(0u32.into(), b"pairing ended");
        }
        None
    };
    let preferred = preferred(theirs, ours);
    if !pairings.may_start(theirs, preferred) {
        log::info!("{addr}: a pairing with {theirs} is already open; closing this one");
        conn.close(0u32.into(), BUSY);
        return None;
    }
    let number = match pair_ceremony::as_responder(conn, ours, theirs).await {
        Ok(number) => number,
        Err(e) => {
            log::info!("{addr}: no number compared with {theirs}: {e}");
            return ended(before_number(conn, e));
        }
    };
    let Some(ticket) = pairings.hold(theirs, conn, preferred) else {
        log::info!("{addr}: a pairing with {theirs} is already open; closing this one");
        conn.close(0u32.into(), BUSY);
        return None;
    };
    pairings.tell(PairingEvent::Number {
        fingerprint: theirs.to_string(),
        addr,
        role: Role::Pick,
        number,
        handle: None,
        conn: conn.stable_id(),
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
                conn: conn.stable_id(),
            });
        }
        // A connection the other machine already closed keeps its reason, so
        // the dial can tell a refusal of this machine from any other end
        // (#171): closing it here would overwrite that with our own.
        if conn.close_reason().is_none() {
            conn.close(0u32.into(), b"pairing ended");
        }
        None
    };
    let preferred = preferred(ours, theirs);
    if !pairings.may_start(theirs, preferred) {
        log::info!("{addr}: a pairing with {theirs} is already open; closing this one");
        conn.close(0u32.into(), BUSY);
        return None;
    }
    let number = match pair_ceremony::as_initiator(conn, ours, theirs).await {
        Ok(number) => number,
        Err(e) => {
            log::info!("{addr}: no number compared with {theirs}: {e}");
            return ended(before_number(conn, e));
        }
    };
    let Some(ticket) = pairings.hold(theirs, conn, preferred) else {
        log::info!("{addr}: a pairing with {theirs} is already open; closing this one");
        conn.close(0u32.into(), BUSY);
        return None;
    };
    pairings.tell(PairingEvent::Number {
        fingerprint: theirs.to_string(),
        addr,
        role: Role::Show,
        number,
        handle: Some(handle),
        conn: conn.stable_id(),
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

    // LEDGER G-7 | class B | 2 handshake outcome at each end + 1 PairingEvent: Number, each way
    /// Which machine dials says nothing about which way control goes (#220):
    /// a machine approved here, whichever way the person approving chose,
    /// reaches the number whether it dials this machine or this machine dials
    /// it. So two machines adding each other can pair.
    #[test]
    fn either_machine_dialling_reaches_the_number_whichever_way_control_goes() {
        run_local(async {
            // Approved here as the machine this one controls, and dialling here.
            let (here, there) = (machine(), machine());
            let trust = approved(&here, &there, Caps::OUTBOUND);
            let mut listening = added(here, trust).await;
            let dialling = raw_dialer(there, &listening.me);
            let conn = dialling
                .connect(listening.port)
                .await
                .expect("the machine approved here is admitted, to compare a number");
            crate::pair_ceremony::as_initiator(
                &conn,
                &dialling.me.fingerprint,
                &listening.me.fingerprint,
            )
            .await
            .expect("the two machines compare a number");
            let (role, _) = number(
                &mut listening.events,
                "a dial from the machine this one controls",
            )
            .await;
            assert_eq!(role, Role::Pick, "the machine dialled picks");

            // Approved here as the machine that controls this one, and dialled
            // from here.
            let (here, there) = (machine(), machine());
            let receiving = raw_receiver(there, &here);
            let mut d = dialer(
                &here,
                approved(&here, &receiving.me, Caps::INBOUND),
                receiving.port,
                Position::Left,
            );
            let mut events = d.conn.take_pairing_events().expect("pairing events");
            d.conn.dial(d.handle).await;
            let conn = receiving
                .next(WITHIN)
                .await
                .expect("this machine dials the machine it approved to control it");
            crate::pair_ceremony::as_responder(&conn, &receiving.me.fingerprint, &here.fingerprint)
                .await
                .expect("the two machines compare a number");
            let (role, _) =
                number(&mut events, "a dial to the machine that controls this one").await;
            assert_eq!(role, Role::Show, "the machine dialling shows the number");
        });
    }

    // LEDGER G-21 | class B | 6 struct state + 2 connection closed: the connection each machine's board holds, the close reason at the other end
    /// Two machines adding each other have two connections between them,
    /// and each machine can meet them in either order. Whatever the order,
    /// both machines keep the same one: the dial of the machine whose
    /// fingerprint sorts first (#220).
    #[test]
    fn two_machines_meeting_both_connections_keep_the_same_one() {
        run_local(async {
            for (l_first, h_first) in [(true, true), (true, false), (false, true), (false, false)] {
                let (one, two) = (machine(), machine());
                let (low, high) = if one.fingerprint < two.fingerprint {
                    (one, two)
                } else {
                    (two, one)
                };
                let (lf, hf) = (low.fingerprint.clone(), high.fingerprint.clone());
                // The connection the machine sorting last dialled, and the
                // other: each seen from both ends.
                let on_low = raw_receiver(low.clone(), &high);
                let from_high = raw_dialer(high.clone(), &low);
                let (x_high, x_low) =
                    tokio::join!(from_high.connect(on_low.port), on_low.next(WITHIN));
                let (x_high, x_low) = (x_high.expect("a dial"), x_low.expect("its other end"));
                let on_high = raw_receiver(high.clone(), &low);
                let from_low = raw_dialer(low.clone(), &high);
                let (z_low, z_high) =
                    tokio::join!(from_low.connect(on_high.port), on_high.next(WITHIN));
                let (z_low, z_high) = (z_low.expect("a dial"), z_high.expect("its other end"));

                let (at_low, _low_events) = Pairings::new();
                let (at_high, _high_events) = Pairings::new();
                let mut held = Vec::new();
                // As `as_added` and `as_adding` do: a connection not held
                // is closed as busy.
                let mut meet =
                    |board: &Pairings, peer: &str, conns: [(&quinn::Connection, bool); 2]| {
                        for (conn, preferred) in conns {
                            match board.hold(peer, conn, preferred) {
                                Some(ticket) => held.push(ticket),
                                None => conn.close(0u32.into(), BUSY),
                            }
                        }
                    };
                let x_pref = preferred(&hf, &lf);
                let z_pref = preferred(&lf, &hf);
                let low_order = if l_first {
                    [(&x_low, x_pref), (&z_low, z_pref)]
                } else {
                    [(&z_low, z_pref), (&x_low, x_pref)]
                };
                let high_order = if h_first {
                    [(&x_high, x_pref), (&z_high, z_pref)]
                } else {
                    [(&z_high, z_pref), (&x_high, x_pref)]
                };
                meet(&at_low, &hf, low_order);
                meet(&at_high, &lf, high_order);
                let order = format!(
                    "the machine sorting first met {}, the other {}",
                    if l_first {
                        "the other's dial first"
                    } else {
                        "its own dial first"
                    },
                    if h_first {
                        "its own dial first"
                    } else {
                        "the other's dial first"
                    }
                );
                assert_eq!(
                    (at_low.held_conn(&hf), at_high.held_conn(&lf)),
                    (Some(z_low.stable_id()), Some(z_high.stable_id())),
                    "{order}: the two machines did not both keep the dial of the machine \
                     sorting first, so each can wait on a number the other never shows"
                );
                drop(held);
            }
        });
    }

    // LEDGER G-22 | class B | 1 return value: Ticket::until on a connection the other end closed
    /// An attempt whose connection the other machine closed because another
    /// connection between the two carries the comparison is withdrawn, which
    /// ends nothing here; closed for any other reason, it ended (#220).
    #[test]
    fn a_connection_given_up_for_the_other_one_ends_nothing() {
        run_local(async {
            for (reason, want) in [
                (SUPERSEDED, Why::Withdrawn),
                (BUSY, Why::Withdrawn),
                (&b"pairing ended"[..], Why::Closed),
            ] {
                let (here, there) = (machine(), machine());
                let receiving = raw_receiver(here.clone(), &there);
                let dialling = raw_dialer(there.clone(), &here);
                let (theirs, ours) =
                    tokio::join!(dialling.connect(receiving.port), receiving.next(WITHIN));
                let (theirs, ours) = (theirs.expect("a dial"), ours.expect("its other end"));
                let (board, _events) = Pairings::new();
                let ticket = board
                    .hold(&there.fingerprint, &ours, false)
                    .expect("nothing else is held");
                theirs.close(0u32.into(), reason);
                let ended = ticket.until(&ours, Stage::Answered, || true).await;
                assert_eq!(
                    ended,
                    Err(Some(want.clone())),
                    "closed by the other machine as {:?}",
                    String::from_utf8_lossy(reason)
                );
            }
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

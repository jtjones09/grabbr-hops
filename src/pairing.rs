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
//! # One number per approval
//!
//! Two machines adding each other dial each other, and both dials reach a
//! machine mid-pairing. Of all the comparisons with one machine, for both
//! of this machine's transports, only one ever sends this machine's half
//! (the dialler's nonce, or the reveal): until then nobody can know its
//! number, and once it is sent that comparison is the only one. A
//! connection that arrives after it is closed as busy before any
//! comparison, and one under way gives up before its own half.
//!
//! Two comparisons under way at once end on the same connection at both
//! machines: the one the machine whose fingerprint sorts first dialled
//! ([`preferred`]). The other holds its half back while that one is under
//! way. It gives up, having sent nothing, once that one sends its half here,
//! and goes on only if that one ends before sending anything. So the other
//! machine learns one number from one approval, however it orders, stalls
//! or closes the two connections.
//!
//! What the other machine says when it closes a connection counts for
//! nothing: a comparison whose half went out ends the attempt however it
//! closes, and the service forgets the approval, so no machine can draw a
//! second number from one approval.
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

/// Which way the person at one machine said control goes, on the card for
/// a pairing (#220), as that machine tells the other during the comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Answer(u8);

impl Answer {
    /// The machine that sent it controls the other.
    const CONTROLS: u8 = 1;
    /// The other machine controls the one that sent it.
    const CONTROLLED: u8 = 2;

    /// The answer the approval here gave for `fingerprint`, while it waits
    /// for its number: the drive bits it will grant.
    pub(crate) fn here(trust: &crate::trust::TrustStore, fingerprint: &str) -> Option<Answer> {
        use crate::trust::Caps;
        let bits = if trust.awaits(fingerprint, Caps::I_MAY_DRIVE) {
            Self::CONTROLS
        } else {
            0
        } | if trust.awaits(fingerprint, Caps::DRIVE_ME) {
            Self::CONTROLLED
        } else {
            0
        };
        Self::from_wire(bits)
    }

    /// One read off the wire: only the two bits, and at least one of them.
    fn from_wire(bits: u8) -> Option<Answer> {
        (bits != 0 && bits & !(Self::CONTROLS | Self::CONTROLLED) == 0).then_some(Answer(bits))
    }

    pub(crate) fn controls(self) -> bool {
        self.0 & Self::CONTROLS != 0
    }

    pub(crate) fn controlled(self) -> bool {
        self.0 & Self::CONTROLLED != 0
    }

    /// Whether control can go some way both answers allow: this machine's
    /// answer, and `theirs`, the one the other machine sent.
    pub(crate) fn agrees_with(self, theirs: Answer) -> bool {
        (self.controls() && theirs.controlled()) || (self.controlled() && theirs.controls())
    }
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
        /// The attempt it was compared in: one per connection, never reused.
        attempt: u64,
        /// What the person at the other machine answered on its card, if it
        /// said.
        theirs: Option<Answer>,
    },
    /// The person here answered, and the other machine's confirmation then
    /// arrived on the connection. The service confirms the lease and calls
    /// [`Pairings::settled`].
    PeerConfirmed { fingerprint: String },
    /// Ended without pairing. The service forgets the lease when this is
    /// the attempt whose number is on screen.
    Ended {
        fingerprint: String,
        why: Why,
        handle: Option<ClientHandle>,
        /// The attempt that ended.
        attempt: u64,
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
    attempt: u64,
    stage: Stage,
    wake: Rc<Notify>,
}

/// The comparisons under way with one machine, before their numbers: how
/// many on connections the machine sorting first dialled and on others,
/// and whether one of them sent this machine's half.
#[derive(Default)]
struct Arriving {
    preferred: usize,
    other: usize,
    /// One of them sent this machine's half: no other may, for as long as
    /// any comparison with that machine is under way. It stays set once
    /// that one holds, ends or is cancelled, so the rule does not rest on
    /// the order the tasks happen to run in.
    sent: bool,
    /// One of them ended with the service told, which forgets the approval:
    /// no other may send its half.
    told: bool,
    /// Woken whenever any of the above changes.
    wake: Rc<Notify>,
    /// How many hold this machine's half back right now, for a test to wait on.
    #[cfg(test)]
    holding_back: usize,
}

impl Arriving {
    fn count(&mut self, preferred: bool) -> &mut usize {
        if preferred {
            &mut self.preferred
        } else {
            &mut self.other
        }
    }
}

/// Whether the connection `dialler` made to `listener` is the one two
/// machines pairing compare their number on, when there are two: the dial
/// of the machine whose fingerprint sorts first. Both machines work it out
/// alike from the same two fingerprints, so both keep the same connection.
pub(crate) fn preferred(dialler: &str, listener: &str) -> bool {
    dialler < listener
}

/// Whether this machine's end of a connection is the one [`preferred`]
/// keeps, given which half of the comparison it does there: the machine
/// that dialled shows the number. Both call sites decide through this one.
fn keeps(role: Role, ours: &str, theirs: &str) -> bool {
    match role {
        Role::Show => preferred(ours, theirs),
        Role::Pick => preferred(theirs, ours),
    }
}

/// What closing a connection whose number was never shown, for another
/// between the same two machines, says. Informational: the other machine
/// reads no close reason.
const SUPERSEDED: &[u8] = b"pairing superseded";
/// What closing a second connection while one is held says.
const BUSY: &[u8] = b"pairing busy";

struct Board {
    held: HashMap<String, Held>,
    arriving: HashMap<String, Arriving>,
    /// The last attempt number given out.
    attempts: u64,
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
                    arriving: HashMap::new(),
                    attempts: 0,
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

    /// Start an attempt with `theirs` on a connection where this machine
    /// does `role`, unless one already sent this machine's half, or ended
    /// with the service told: then this one could never be shown. Several
    /// may be under way: a dial that raced to more than one address of this
    /// machine arrives on each, and only one of them sends this machine's
    /// half (see [`Arrival::may_send`]).
    fn begin(&self, role: Role, ours: &str, theirs: &str) -> Option<Arrival> {
        let preferred = keeps(role, ours, theirs);
        let mut board = self.board.borrow_mut();
        if board.held.contains_key(theirs)
            || board.arriving.get(theirs).is_some_and(|a| a.sent || a.told)
        {
            return None;
        }
        *board
            .arriving
            .entry(theirs.to_string())
            .or_default()
            .count(preferred) += 1;
        board.attempts += 1;
        Some(Arrival {
            pairings: self.clone(),
            fingerprint: theirs.to_string(),
            preferred,
            attempt: board.attempts,
        })
    }
}

/// A comparison under way, before its number. Dropping it counts it out,
/// and lets one held back for it go on.
struct Arrival {
    pairings: Pairings,
    fingerprint: String,
    preferred: bool,
    attempt: u64,
}

impl Drop for Arrival {
    fn drop(&mut self) {
        let mut board = self.pairings.board.borrow_mut();
        if let Some(arriving) = board.arriving.get_mut(&self.fingerprint) {
            let count = arriving.count(self.preferred);
            *count = count.saturating_sub(1);
            arriving.wake.notify_waiters();
            if arriving.preferred == 0 && arriving.other == 0 {
                board.arriving.remove(&self.fingerprint);
            }
        }
    }
}

impl Arrival {
    /// Whether this comparison may send this machine's half, asked just
    /// before it would. Only one comparison with a machine ever does, so
    /// the other machine can know one number at most:
    ///
    /// - not once another sent its half, is held, or ended with the service
    ///   told, which forgets the approval;
    /// - on a connection the machine sorting first did not dial, not while
    ///   one it dialled is under way: this one waits for that one to send
    ///   its half, and then gives up, or to end having sent nothing, and
    ///   then goes on.
    ///
    /// `false` when it gives up, with nothing sent, or its connection closes
    /// meanwhile. `true` marks the half as sent.
    async fn may_send(&self, conn: &Connection) -> bool {
        loop {
            let wake = {
                let mut board = self.pairings.board.borrow_mut();
                let held = board.held.contains_key(&self.fingerprint);
                let Some(arriving) = board.arriving.get_mut(&self.fingerprint) else {
                    return false;
                };
                if held || arriving.sent || arriving.told {
                    return false;
                }
                if self.preferred || arriving.preferred == 0 {
                    arriving.sent = true;
                    arriving.wake.notify_waiters();
                    return true;
                }
                arriving.wake.clone()
            };
            // Registered before anything else can run on this thread, so no
            // change is missed between the look above and the wait.
            let changed = wake.notified();
            #[cfg(test)]
            self.holding_back(1);
            let closed = tokio::select! {
                _ = changed => false,
                _ = conn.closed() => true,
            };
            #[cfg(test)]
            self.holding_back(-1);
            if closed {
                return false;
            }
        }
    }

    #[cfg(test)]
    fn holding_back(&self, by: isize) {
        if let Some(a) = self
            .pairings
            .board
            .borrow_mut()
            .arriving
            .get_mut(&self.fingerprint)
        {
            a.holding_back = a.holding_back.saturating_add_signed(by);
        }
    }

    /// This comparison ended with the service told, which forgets the
    /// approval: no other comparison with that machine may send its half.
    fn told(&self) {
        let mut board = self.pairings.board.borrow_mut();
        if let Some(arriving) = board.arriving.get_mut(&self.fingerprint) {
            arriving.told = true;
            arriving.wake.notify_waiters();
        }
    }

    /// Hold `conn`, whose comparison finished: the one comparison with that
    /// machine that sent this machine's half.
    fn hold(self, conn: &Connection, theirs: Option<Answer>) -> Option<Ticket> {
        let mut board = self.pairings.board.borrow_mut();
        if board.held.contains_key(&self.fingerprint) {
            return None;
        }
        let wake = Rc::new(Notify::new());
        board.held.insert(
            self.fingerprint.clone(),
            Held {
                conn: conn.clone(),
                attempt: self.attempt,
                stage: Stage::Comparing,
                wake: wake.clone(),
            },
        );
        Some(Ticket {
            pairings: self.pairings.clone(),
            fingerprint: self.fingerprint.clone(),
            attempt: self.attempt,
            wake,
            deadline: tokio::time::Instant::now() + board.deadline,
            theirs,
        })
    }
}

/// One held attempt. Dropping it releases the slot.
struct Ticket {
    pairings: Pairings,
    fingerprint: String,
    attempt: u64,
    wake: Rc<Notify>,
    deadline: tokio::time::Instant,
    /// What the other machine's person answered on its card, if it said.
    theirs: Option<Answer>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut board = self.pairings.board.borrow_mut();
        if board
            .held
            .get(&self.fingerprint)
            .is_some_and(|h| h.attempt == self.attempt)
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
            .filter(|h| h.attempt == self.attempt)
            .map_or(Stage::Over, |h| h.stage)
    }

    /// Why this attempt ended with its connection closed: nothing to say
    /// when it was ended here. The other machine's close reason is not
    /// read: it cannot turn an end into anything else.
    fn why_closed(&self, _conn: &Connection) -> Option<Why> {
        (self.stage() != Stage::Over).then_some(Why::Closed)
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
/// A connection that closed before this machine's half of the comparison
/// went out is dropped quietly: nobody can know a number from it. A dial
/// raced to another address of the same machine and lost, or the link
/// blipped, and the add dial tries again. One that closed after its half
/// went out ends the approval, since the other machine may know the number
/// and could draw again: it was the one comparison allowed to send it. One
/// still open that offered no number is a peer that will never offer one.
fn before_number(conn: &Connection, e: CeremonyError) -> Option<Why> {
    if conn.close_reason().is_some() {
        return e.late().then_some(Why::Closed);
    }
    Some(match e {
        CeremonyError::NotSupported => Why::NoComparison,
        // Which half had gone out decided how this ends; the person is told
        // what failed.
        CeremonyError::Late(e) => Why::Failed(e.to_string()),
        e => Why::Failed(e.to_string()),
    })
}

/// The first frame on the peer's first input stream: its confirmation.
async fn first_frame(conn: &Connection) -> Option<(RecvStream, ProtoEvent)> {
    let mut recv = conn.accept_uni().await.ok()?;
    let frame = transport::read_frame(&mut recv).await.ok()??;
    Some((recv, frame))
}

/// How an attempt that reached no number here ended: its attempt, and why,
/// when there is something to say.
type NoNumber = (u64, Option<Why>);

/// The start both halves share: take this machine's place for a connection
/// with `theirs`, compare the number on `conn`, hold it, and wait until it
/// may be shown. `role` is the half this machine does, which also says
/// which machine dialled.
async fn reach_number(
    pairings: &Pairings,
    conn: &Connection,
    role: Role,
    ours: &str,
    theirs: &str,
    addr: SocketAddr,
    answer: Option<Answer>,
) -> Result<(Ticket, String), NoNumber> {
    let Some(arrival) = pairings.begin(role, ours, theirs) else {
        log::info!("{addr}: a pairing with {theirs} is already open; closing this one");
        conn.close(0u32.into(), BUSY);
        return Err((0, None));
    };
    let attempt = arrival.attempt;
    let go = arrival.may_send(conn);
    let answer = answer.map(|a| a.0);
    let compared = match role {
        Role::Show => pair_ceremony::as_initiator_when(conn, ours, theirs, answer, go).await,
        Role::Pick => pair_ceremony::as_responder_when(conn, ours, theirs, answer, go).await,
    };
    let (number, answered) = match compared {
        Ok(compared) => compared,
        Err(CeremonyError::HeldBack) => {
            log::info!("{addr}: the pairing with {theirs} goes on over another connection");
            if conn.close_reason().is_none() {
                conn.close(0u32.into(), SUPERSEDED);
            }
            return Err((attempt, None));
        }
        Err(e) => {
            log::info!("{addr}: no number compared with {theirs}: {e}");
            let why = before_number(conn, e);
            if why.is_some() {
                arrival.told();
            }
            drop(arrival);
            return Err((attempt, why));
        }
    };
    let Some(ticket) = arrival.hold(conn, answered.and_then(Answer::from_wire)) else {
        log::info!("{addr}: a pairing with {theirs} is already open; closing this one");
        conn.close(0u32.into(), BUSY);
        return Err((attempt, None));
    };
    Ok((ticket, number))
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
    answer: Option<Answer>,
) -> Option<(RecvStream, ProtoEvent)> {
    let ended = |attempt: u64, why: Option<Why>| {
        if let Some(why) = why {
            log::info!("pairing with {theirs} at {addr} ended: {why:?}");
            pairings.tell(PairingEvent::Ended {
                fingerprint: theirs.to_string(),
                why,
                handle: None,
                attempt,
            });
        }
        if conn.close_reason().is_none() {
            conn.close(0u32.into(), b"pairing ended");
        }
        None
    };
    let (ticket, number) =
        match reach_number(pairings, conn, Role::Pick, ours, theirs, addr, answer).await {
            Ok(reached) => reached,
            Err((attempt, why)) => return ended(attempt, why),
        };
    let attempt = ticket.attempt;
    let ended = |why: Option<Why>| ended(attempt, why);
    pairings.tell(PairingEvent::Number {
        fingerprint: theirs.to_string(),
        addr,
        role: Role::Pick,
        number,
        handle: None,
        attempt,
        theirs: ticket.theirs,
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn as_adding(
    pairings: &Pairings,
    conn: &Connection,
    ours: &str,
    theirs: &str,
    addr: SocketAddr,
    handle: ClientHandle,
    clients: &ClientManager,
    answer: Option<Answer>,
) -> Option<Confirmed> {
    let ended = |attempt: u64, why: Option<Why>| {
        if let Some(why) = why {
            log::info!("pairing with {theirs} at {addr} ended: {why:?}");
            pairings.tell(PairingEvent::Ended {
                fingerprint: theirs.to_string(),
                why,
                handle: Some(handle),
                attempt,
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
    let (ticket, number) =
        match reach_number(pairings, conn, Role::Show, ours, theirs, addr, answer).await {
            Ok(reached) => reached,
            Err((attempt, why)) => return ended(attempt, why),
        };
    let attempt = ticket.attempt;
    let ended = |why: Option<Why>| ended(attempt, why);
    pairings.tell(PairingEvent::Number {
        fingerprint: theirs.to_string(),
        addr,
        role: Role::Show,
        number,
        handle: Some(handle),
        attempt,
        theirs: ticket.theirs,
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
mod the_two_answers {
    use super::Answer;

    // LEDGER G-35 | class B | 1 return value + 1 notice text: Answer::agrees_with over every pair of card answers, and the notice the service builds from one that does not
    /// Two answers agree when control can go some way both allow: one
    /// machine says it controls the other and the other says it is
    /// controlled, or the reverse. Two machines that each say they are in
    /// control, or each that the other is, agree on nothing, and the notice
    /// says what each answered, from this machine's side.
    #[test]
    fn two_answers_agree_only_when_control_can_go_some_way_both_allow() {
        let controls = Answer(Answer::CONTROLS);
        let controlled = Answer(Answer::CONTROLLED);
        let both = Answer(Answer::CONTROLS | Answer::CONTROLLED);
        for (ours, theirs, agree) in [
            (controls, controlled, true),
            (controlled, controls, true),
            (both, both, true),
            (both, controls, true),
            (both, controlled, true),
            (controls, both, true),
            (controlled, both, true),
            (controls, controls, false),
            (controlled, controlled, false),
        ] {
            assert_eq!(
                ours.agrees_with(theirs),
                agree,
                "{ours:?} here and {theirs:?} there"
            );
        }
        let notice = crate::service::disagreement_notice("\"B\"", controls, controls);
        assert!(
            notice.contains("the answer here was that this machine controls \"B\"")
                && notice.contains("the answer on \"B\" was that \"B\" controls this machine"),
            "{notice}"
        );
        assert_eq!(Answer::from_wire(0), None, "an answer of no direction");
        assert_eq!(Answer::from_wire(4), None, "a bit this build does not know");
    }
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

    // LEDGER G-21 | class B | 1 return value + 6 struct state + 2 connection closed: reach_number, the start as_added and as_adding share, at both ends of two real connections; the connection each board holds; what each one given up says
    /// Two machines adding each other have two connections between them,
    /// and meet them in any order. Whatever the order, both machines end on
    /// the same one: the first connection on which a machine sent its half
    /// keeps it, and only when both comparisons run at once does the dial of
    /// the machine sorting first win, before either machine sent its half on
    /// the other. The one given up ends quietly: the approval stays with the
    /// one kept (#220).
    #[test]
    fn two_machines_meeting_both_connections_keep_the_same_one() {
        #[derive(Debug, Clone, Copy, PartialEq)]
        enum Order {
            /// One machine's dial showed its number on both before the other
            /// dial arrived: a crossed add at the speed of people.
            TheirsShownFirst,
            OursShownFirst,
            /// Both comparisons under way at once on both machines.
            AtOnce,
            /// The machine sorting first began its own dial's comparison
            /// before its half on the other's went out; the other machine
            /// met that dial only once its own half on its dial had gone out.
            MetLateThere,
        }
        run_local(async {
            for order in [
                Order::TheirsShownFirst,
                Order::OursShownFirst,
                Order::AtOnce,
                Order::MetLateThere,
            ] {
                let (one, two) = (machine(), machine());
                let (low, high) = if one.fingerprint < two.fingerprint {
                    (one, two)
                } else {
                    (two, one)
                };
                let (lf, hf) = (low.fingerprint.clone(), high.fingerprint.clone());
                // x: the dial of the machine sorting last. z: the other.
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
                let at = SocketAddr::from(([127, 0, 0, 1], 4242));
                // Each end as the production halves start it: the machine
                // that dialled shows, the one dialled picks.
                let x_at_low = || reach_number(&at_low, &x_low, Role::Pick, &lf, &hf, at, None);
                let x_at_high = || reach_number(&at_high, &x_high, Role::Show, &hf, &lf, at, None);
                let z_at_low = || reach_number(&at_low, &z_low, Role::Show, &lf, &hf, at, None);
                let z_at_high = || reach_number(&at_high, &z_high, Role::Pick, &hf, &lf, at, None);
                let ((xl, xh), (zl, zh)) = match order {
                    Order::TheirsShownFirst => {
                        let x = tokio::join!(x_at_low(), x_at_high());
                        (x, tokio::join!(z_at_low(), z_at_high()))
                    }
                    Order::OursShownFirst => {
                        let z = tokio::join!(z_at_low(), z_at_high());
                        (tokio::join!(x_at_low(), x_at_high()), z)
                    }
                    Order::AtOnce => {
                        let (xl, xh, zl, zh) =
                            tokio::join!(x_at_low(), x_at_high(), z_at_low(), z_at_high());
                        ((xl, xh), (zl, zh))
                    }
                    Order::MetLateThere => {
                        let (zl, (xl, (xh, zh))) = tokio::join!(z_at_low(), async {
                            tokio::join!(x_at_low(), async {
                                tokio::join!(x_at_high(), async {
                                    sent_here(&at_high, &lf).await;
                                    z_at_high().await
                                })
                            })
                        });
                        ((xl, xh), (zl, zh))
                    }
                };
                let kept_z = order == Order::OursShownFirst || order == Order::AtOnce;
                let told = [&xl, &xh, &zl, &zh]
                    .into_iter()
                    .filter_map(|r| r.as_ref().err().and_then(|(_, why)| why.clone()))
                    .collect::<Vec<_>>();
                assert!(
                    told.is_empty(),
                    "{order:?}: a connection given up for the one kept ended the approval: \
                     {told:?}"
                );
                let reached = |r: &Result<(Ticket, String), NoNumber>| r.is_ok();
                assert_eq!(
                    (reached(&xl), reached(&xh), reached(&zl), reached(&zh)),
                    (!kept_z, !kept_z, kept_z, kept_z),
                    "{order:?}: the numbers shown were not those of one connection, the same \
                     at both machines (x at the machine sorting first, x at the other, then \
                     z likewise)"
                );
                let (kept_low, kept_high) = if kept_z {
                    (z_low.stable_id(), z_high.stable_id())
                } else {
                    (x_low.stable_id(), x_high.stable_id())
                };
                assert_eq!(
                    (at_low.held_conn(&hf), at_high.held_conn(&lf)),
                    (Some(kept_low), Some(kept_high)),
                    "{order:?}: the two machines do not hold the same connection, so each can \
                     wait on a number the other never shows"
                );
                let numbers = [&xl, &xh, &zl, &zh]
                    .into_iter()
                    .filter_map(|r| r.as_ref().ok().map(|(_, n)| n.clone()))
                    .collect::<Vec<_>>();
                assert!(
                    numbers.len() == 2 && numbers[0] == numbers[1],
                    "{order:?}: the two machines were shown different numbers: {numbers:?}"
                );
                drop((xl, xh, zl, zh));
            }
        });
    }

    // LEDGER G-31 | class B | 1 return value: Arrival::may_send on real connections, for a comparison on the dial the machine sorting first did not make, while one on its dial is under way
    /// A comparison on the dial the machine sorting first did not make holds
    /// this machine's half back while one on that machine's dial is under
    /// way. It gives up, having sent nothing, once that one sends its half,
    /// and goes on once that one ends having sent nothing: either way only
    /// one of the two ever tells the other machine a number (#220).
    #[test]
    fn a_half_held_back_waits_for_the_comparison_kept() {
        run_local(async {
            let (one, two) = (machine(), machine());
            let (low, high) = if one.fingerprint < two.fingerprint {
                (one, two)
            } else {
                (two, one)
            };
            let (lf, hf) = (low.fingerprint.clone(), high.fingerprint.clone());
            let on_low = raw_receiver(low.clone(), &high);
            let from_high = raw_dialer(high.clone(), &low);
            let (dialled, arrived) =
                tokio::join!(from_high.connect(on_low.port), on_low.next(WITHIN));
            let (_dialled, conn) = (dialled.expect("a dial"), arrived.expect("its other end"));
            let (pairings, _events) = Pairings::new();
            for kept_sends in [true, false] {
                // At the machine sorting first: the other's dial, which it
                // picks on, then its own, which it shows on.
                let held_back = pairings
                    .begin(Role::Pick, &lf, &hf)
                    .expect("the other's dial");
                let kept = pairings.begin(Role::Show, &lf, &hf).expect("its own dial");
                let asked = held_back.may_send(&conn);
                let mut asked = std::pin::pin!(asked);
                assert!(
                    futures::poll!(asked.as_mut()).is_pending(),
                    "a half on the dial not kept went out while the kept one was compared"
                );
                if kept_sends {
                    assert!(kept.may_send(&conn).await, "the kept comparison may send");
                    assert!(
                        !asked.await,
                        "a half held back went out after the kept comparison sent its own: \
                         the other machine could know two numbers"
                    );
                } else {
                    drop(kept);
                    assert!(
                        asked.await,
                        "a half held back for a comparison that ended having sent nothing \
                         never went out, and the pairing stalled"
                    );
                }
            }
        });
    }

    // LEDGER G-32 | class B | 1 PairingEvent + 1 notice text: Ended from the production dialler whose comparison failed after its nonce went out, on a connection still open; the notice the service builds from it
    /// A comparison that failed after this machine's half went out, on a
    /// connection still open, is told in the words of what failed. Which
    /// half had gone out decides how the attempt ends; it is not something
    /// the person can act on.
    #[test]
    fn a_comparison_failed_late_is_told_in_plain_words() {
        run_local(async {
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
            let conn = receiving.next(WITHIN).await.expect("a dial");
            // The other machine's half, with a reveal that opens nothing.
            let (mut send, mut recv) = conn.open_bi().await.expect("the comparison stream");
            send.write_all(&[0u8; crate::match_code::COMMIT_LEN])
                .await
                .expect("commitment");
            let mut theirs = [0u8; crate::match_code::NONCE_LEN];
            recv.read_exact(&mut theirs)
                .await
                .expect("the dialler's nonce");
            send.write_all(&[0u8; crate::match_code::NONCE_LEN])
                .await
                .expect("the reveal");
            let _ = send.finish();
            let why = match next_within(&mut events, WITHIN).await {
                Some(PairingEvent::Ended { why, .. }) => why,
                other => panic!("a comparison that failed did not end the attempt: {other:?}"),
            };
            let notice = crate::service::ended_notice("\"B\"", &why, false);
            let failed = crate::pair_ceremony::CeremonyError::CommitmentBroken.to_string();
            assert!(
                notice.starts_with(&format!("Pairing with \"B\" failed ({failed}), ")),
                "the notice for a comparison that failed late: {notice:?}"
            );
            drop(conn);
        });
    }

    // LEDGER G-22 | class B | 1 PairingEvent: Ended from the production listener after the other end closed a connection whose number was shown
    /// A number shown here ends the attempt, whatever reason the other
    /// machine gives for closing its connection: a machine that says it gave
    /// the connection up for another cannot keep the approval standing and
    /// draw a second number from it (#220).
    #[test]
    fn a_number_shown_ends_whatever_the_other_machine_says() {
        run_local(async {
            // Each machine stays up until the end, as its tasks expect.
            let mut up = Vec::new();
            for reason in [SUPERSEDED, BUSY, &b"pairing ended"[..]] {
                let (b, a) = (machine(), machine());
                let trust = approved(&b, &a, Caps::INBOUND);
                let mut b = added(b, trust).await;
                let a = raw_dialer(a, &b.me);
                let conn = a.connect(b.port).await.expect("handshake");
                crate::pair_ceremony::as_initiator(&conn, &a.me.fingerprint, &b.me.fingerprint)
                    .await
                    .expect("a number");
                number(&mut b.events, "the receiver").await;
                conn.close(0u32.into(), reason);
                match next_within(&mut b.events, WITHIN).await {
                    Some(PairingEvent::Ended { why, .. }) => assert_eq!(
                        why,
                        Why::Closed,
                        "closed by the other machine as {:?}",
                        String::from_utf8_lossy(reason)
                    ),
                    other => panic!(
                        "a number shown here, its connection closed by the other machine as \
                         {:?}, did not end the attempt: {other:?}",
                        String::from_utf8_lossy(reason)
                    ),
                }
                up.push((b, conn));
            }
        });
    }

    /// Wait until `pairings` counts a comparison with `fingerprint` under way
    /// on a connection the machine sorting first dialled.
    async fn arriving_preferred(pairings: &Pairings, fingerprint: &str) {
        while !pairings
            .board
            .borrow()
            .arriving
            .get(fingerprint)
            .is_some_and(|a| a.preferred > 0)
        {
            tokio::task::yield_now().await;
        }
    }

    /// Wait until this machine sent its half to `fingerprint` on some
    /// comparison, or holds one.
    async fn sent_here(pairings: &Pairings, fingerprint: &str) {
        let deadline = tokio::time::Instant::now() + WITHIN;
        loop {
            {
                let board = pairings.board.borrow();
                if board.held.contains_key(fingerprint)
                    || board.arriving.get(fingerprint).is_some_and(|a| a.sent)
                {
                    return;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "this machine never sent its half on any comparison"
            );
            tokio::task::yield_now().await;
        }
    }

    /// Wait until a comparison with `fingerprint` holds this machine's half
    /// back.
    async fn held_back_here(pairings: &Pairings, fingerprint: &str) {
        let deadline = tokio::time::Instant::now() + WITHIN;
        while !pairings
            .board
            .borrow()
            .arriving
            .get(fingerprint)
            .is_some_and(|a| a.holding_back > 0)
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "no comparison here held its half back while the kept one was under way"
            );
            tokio::task::yield_now().await;
        }
    }

    /// Two machines, and the two connections two machines adding each other
    /// make: `x`, dialled by the machine sorting last, and `z`, dialled by
    /// the one sorting first, with each end as `(at low, at high)`.
    struct Crossed {
        lf: String,
        hf: String,
        x: (quinn::Connection, quinn::Connection),
        z: (quinn::Connection, quinn::Connection),
        _ends: (RawReceiver, RawDialer, RawReceiver, RawDialer),
    }

    async fn crossed() -> Crossed {
        let (one, two) = (machine(), machine());
        let (low, high) = if one.fingerprint < two.fingerprint {
            (one, two)
        } else {
            (two, one)
        };
        let (lf, hf) = (low.fingerprint.clone(), high.fingerprint.clone());
        let on_low = raw_receiver(low.clone(), &high);
        let from_high = raw_dialer(high.clone(), &low);
        let (x_high, x_low) = tokio::join!(from_high.connect(on_low.port), on_low.next(WITHIN));
        let on_high = raw_receiver(high.clone(), &low);
        let from_low = raw_dialer(low, &high);
        let (z_low, z_high) = tokio::join!(from_low.connect(on_high.port), on_high.next(WITHIN));
        Crossed {
            lf,
            hf,
            x: (x_low.expect("its other end"), x_high.expect("a dial")),
            z: (z_low.expect("a dial"), z_high.expect("its other end")),
            _ends: (on_low, from_high, on_high, from_low),
        }
    }

    /// Read the reveal the machine being dialled sends on `recv`, as far as
    /// it arrives.
    async fn read_reveal(
        mut recv: quinn::RecvStream,
    ) -> Result<[u8; crate::match_code::NONCE_LEN], String> {
        let mut reveal = [0u8; crate::match_code::NONCE_LEN];
        recv.read_exact(&mut reveal)
            .await
            .map(|()| reveal)
            .map_err(|e| e.to_string())
    }

    /// The dialler's steps as far as its nonce, on `conn`: the reveal is left
    /// to read.
    async fn send_nonce(conn: &quinn::Connection) -> (quinn::SendStream, quinn::RecvStream) {
        let (mut send, mut recv) = conn.accept_bi().await.expect("the comparison stream");
        let mut commitment = [0u8; crate::match_code::COMMIT_LEN];
        recv.read_exact(&mut commitment).await.expect("commitment");
        send.write_all(&[7u8; crate::match_code::NONCE_LEN])
            .await
            .expect("the dialler's nonce");
        let _ = send.finish();
        (send, recv)
    }

    /// The other machine's half of the comparison as far as the nonce of the
    /// machine that dialled it: from there it can work out the number, and it
    /// closes the connection before revealing its own half. What it commits
    /// to does not matter; nothing checks it before the reveal.
    async fn learn_the_number_and_close(conn: &quinn::Connection) {
        let (mut send, mut recv) = conn.open_bi().await.expect("the comparison stream");
        send.write_all(&[0u8; crate::match_code::COMMIT_LEN])
            .await
            .expect("commitment");
        let mut theirs = [0u8; crate::match_code::NONCE_LEN];
        recv.read_exact(&mut theirs)
            .await
            .expect("the dialler's nonce");
        conn.close(0u32.into(), b"pairing ended");
    }

    // LEDGER G-24 | class B | 2 wire bytes + 1 return value: what the other machine reads on the connection whose comparison is held back, and reach_number at both of this machine's ends
    /// The other machine, adding this one while this one adds it, learns no
    /// number from the comparison held back here: this machine never sends
    /// its half there. It learns the number compared on the dial both
    /// machines keep, and nothing else, so a machine in the middle has one
    /// try at a matching number, not two (#220).
    #[test]
    fn the_other_machine_learns_no_number_from_a_comparison_held_back() {
        run_local(async {
            let c = crossed().await;
            let (here, _events) = Pairings::new();
            let at = SocketAddr::from(([127, 0, 0, 1], 4242));
            let (p, l, h, z) = (here.clone(), c.lf.clone(), c.hf.clone(), c.z.0.clone());
            let kept = tokio::task::spawn_local(async move {
                reach_number(&p, &z, Role::Show, &l, &h, at, None)
                    .await
                    .map(|(_, n)| n)
            });
            arriving_preferred(&here, &c.hf).await;
            let (p, l, h, x) = (here.clone(), c.lf.clone(), c.hf.clone(), c.x.0.clone());
            let held_back = tokio::task::spawn_local(async move {
                reach_number(&p, &x, Role::Pick, &l, &h, at, None)
                    .await
                    .map(|(_, n)| n)
            });

            // The other machine sends its nonce on its own dial and waits for
            // this machine's reveal there, while it lets this machine's dial
            // be compared to the end.
            let (_send, recv) = send_nonce(&c.x.1).await;
            let reveal = tokio::task::spawn_local(read_reveal(recv));
            let theirs = crate::pair_ceremony::as_responder(&c.z.1, &c.hf, &c.lf)
                .await
                .expect("the number on the dial both keep");
            let ours = kept
                .await
                .expect("task")
                .expect("this machine reaches the number on its own dial");
            assert_eq!(ours, theirs, "the two machines hold different numbers");
            let learned = reveal.await.expect("task");
            assert!(
                learned.is_err(),
                "the other machine read this machine's reveal on the comparison held \
                 back, so it knew a second number to choose from: {learned:?}"
            );
            assert!(
                matches!(held_back.await.expect("task"), Err((_, None))),
                "the comparison held back ended the approval the kept one carries"
            );
        });
    }

    /// Wait until `pairings` counts a comparison with `fingerprint` under way
    /// on a connection the machine sorting first did not dial.
    async fn arriving_other(pairings: &Pairings, fingerprint: &str) {
        let deadline = tokio::time::Instant::now() + WITHIN;
        while !pairings
            .board
            .borrow()
            .arriving
            .get(fingerprint)
            .is_some_and(|a| a.other > 0)
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "no comparison here began on the connection not kept"
            );
            tokio::task::yield_now().await;
        }
    }

    // LEDGER G-36 | class B | 2 wire bytes + 1 return value: what the other machine reads on this machine's own dial, held back while the kept comparison is under way or reaching its point of sending only after the kept one reached its number and was let go, and reach_number at both of this machine's ends
    /// The same as [`the_other_machine_learns_no_number_from_a_comparison_held_back`]
    /// for the machine sorting last, whose half on its own dial, which
    /// neither keeps, is its nonce. Whether that comparison reaches the
    /// point of sending while the kept one is under way, or only once the
    /// kept one reached its number and let it go at once, the kept one's
    /// half went out, so this one sends nothing (#220).
    #[test]
    fn the_machine_sorting_last_sends_no_nonce_on_its_own_dial_held_back() {
        #[derive(Debug, Clone, Copy, PartialEq)]
        enum Commitment {
            /// Arrives on this machine's dial while the kept one is under way.
            First,
            /// Arrives only once the kept comparison is over here.
            Last,
        }
        /// The other machine's commitment on this machine's dial, and what
        /// it reads there after.
        async fn commit_and_read(
            conn: quinn::Connection,
        ) -> (
            quinn::SendStream,
            Result<[u8; crate::match_code::NONCE_LEN], String>,
        ) {
            let (mut send, mut recv) = conn.open_bi().await.expect("the stream");
            send.write_all(&[0u8; crate::match_code::COMMIT_LEN])
                .await
                .expect("commitment");
            let mut nonce = [0u8; crate::match_code::NONCE_LEN];
            let learned = recv
                .read_exact(&mut nonce)
                .await
                .map(|()| nonce)
                .map_err(|e| e.to_string());
            (send, learned)
        }
        run_local(async {
            for commitment in [Commitment::First, Commitment::Last] {
                let c = crossed().await;
                let (here, _events) = Pairings::new();
                let at = SocketAddr::from(([127, 0, 0, 1], 4242));
                let (p, h, l, z) = (here.clone(), c.hf.clone(), c.lf.clone(), c.z.1.clone());
                let kept = tokio::task::spawn_local(async move {
                    // The ticket is let go the moment the number is reached.
                    reach_number(&p, &z, Role::Pick, &h, &l, at, None)
                        .await
                        .map(|(_, n)| n)
                });
                arriving_preferred(&here, &c.lf).await;
                let (p, h, l, x) = (here.clone(), c.hf.clone(), c.lf.clone(), c.x.1.clone());
                let held_back = tokio::task::spawn_local(async move {
                    reach_number(&p, &x, Role::Show, &h, &l, at, None)
                        .await
                        .map(|(_, n)| n)
                });
                arriving_other(&here, &c.lf).await;

                // The other machine's commitment on this machine's dial, and
                // what it reads there after.
                let early = if commitment == Commitment::First {
                    let read = tokio::task::spawn_local(commit_and_read(c.x.0.clone()));
                    held_back_here(&here, &c.lf).await;
                    Some(read)
                } else {
                    None
                };

                let theirs = crate::pair_ceremony::as_initiator(&c.z.0, &c.lf, &c.hf)
                    .await
                    .expect("the number on the dial both keep");
                let ours = kept
                    .await
                    .expect("task")
                    .expect("this machine reaches the number on the dial both keep");
                assert_eq!(
                    ours, theirs,
                    "{commitment:?}: the two machines hold different numbers"
                );

                let (_send, learned) = match early {
                    Some(read) => read.await.expect("task"),
                    None => commit_and_read(c.x.0.clone()).await,
                };
                assert!(
                    learned.is_err(),
                    "{commitment:?}: the other machine read this machine's nonce on its own \
                     dial held back, and the kept comparison's half went out too: {learned:?}"
                );
                assert!(
                    matches!(held_back.await.expect("task"), Err((_, None))),
                    "{commitment:?}: the comparison held back ended the approval the kept \
                     one carries"
                );
            }
        });
    }

    // LEDGER G-37 | class B | 2 wire bytes: what the other machine reads on this machine's own dial after the comparison kept was cancelled here once its half went out
    /// A comparison cancelled here once this machine's half went out on it,
    /// as when its task is stopped, may have let the other machine know its
    /// number. The comparison held back still sends nothing after it (#220).
    #[test]
    fn a_comparison_cancelled_after_its_half_keeps_the_one_held_back_silent() {
        run_local(async {
            let c = crossed().await;
            let (here, _events) = Pairings::new();
            let at = SocketAddr::from(([127, 0, 0, 1], 4242));
            let (p, h, l, z) = (here.clone(), c.hf.clone(), c.lf.clone(), c.z.1.clone());
            let kept = tokio::task::spawn_local(async move {
                reach_number(&p, &z, Role::Pick, &h, &l, at, None)
                    .await
                    .map(|(_, n)| n)
            });
            arriving_preferred(&here, &c.lf).await;
            let (p, h, l, x) = (here.clone(), c.hf.clone(), c.lf.clone(), c.x.1.clone());
            let held_back = tokio::task::spawn_local(async move {
                reach_number(&p, &x, Role::Show, &h, &l, at, None)
                    .await
                    .map(|(_, n)| n)
            });
            arriving_other(&here, &c.lf).await;

            // The other machine reads this machine's reveal on the dial both
            // keep, and sends nothing after its nonce: the comparison waits
            // for its answer, and is cancelled there.
            let (mut send, mut recv) = c.z.0.accept_bi().await.expect("the comparison stream");
            let mut commitment = [0u8; crate::match_code::COMMIT_LEN];
            recv.read_exact(&mut commitment).await.expect("commitment");
            send.write_all(&[7u8; crate::match_code::NONCE_LEN])
                .await
                .expect("nonce");
            read_reveal(recv).await.expect("this machine's reveal");
            kept.abort();
            assert!(
                kept.await.is_err_and(|e| e.is_cancelled()),
                "the kept comparison was not cancelled"
            );

            let (mut send, mut recv) = c.x.0.open_bi().await.expect("the comparison stream");
            send.write_all(&[0u8; crate::match_code::COMMIT_LEN])
                .await
                .expect("commitment");
            let mut nonce = [0u8; crate::match_code::NONCE_LEN];
            let learned = recv
                .read_exact(&mut nonce)
                .await
                .map(|()| nonce)
                .map_err(|e| e.to_string());
            assert!(
                learned.is_err(),
                "the other machine read this machine's nonce on its own dial after \
                 the kept comparison, whose half went out, was cancelled: {learned:?}"
            );
            assert!(
                matches!(held_back.await.expect("task"), Err((_, None))),
                "the comparison held back ended the approval itself"
            );
        });
    }

    // LEDGER G-25 | class B | 1 PairingEvent: Ended from LanMouseConnection after the other end closed the comparison once it held the dialler's nonce
    /// The machine being dialled can work out the number as soon as the
    /// dialler's nonce arrives, before the dialler can. Closing then ends
    /// the approval: otherwise the add dial comes back with a fresh number
    /// each time, and the other machine lets through the one it likes.
    #[test]
    fn a_comparison_abandoned_after_the_dialler_s_nonce_ends_the_approval() {
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
            learn_the_number_and_close(&conn).await;
            match next_within(&mut a_events, WITHIN).await {
                Some(PairingEvent::Ended { why, .. }) => assert_eq!(why, Why::Closed),
                other => panic!(
                    "the machine dialled closed the comparison once it could know the \
                     number, and the approval stood: {other:?}"
                ),
            }
        });
    }

    // LEDGER G-26 | class B | 1 connection closed + 1 return value: the close of a crossing dial at the production listener, and reach_number on this machine's own dial after its half went out
    /// Once this machine sent its half on its own dial, that comparison is
    /// the only one with the other machine: the other machine's dial,
    /// arriving after it, is closed as busy before any comparison, although
    /// it is the one both keep when the two are under way at once. That
    /// comparison closed by the other machine then ends the approval (#220).
    #[test]
    fn a_dial_arriving_after_this_machine_s_half_is_busy() {
        run_local(async {
            let here = machine();
            let mut there = machine();
            while there.fingerprint >= here.fingerprint {
                there = machine();
            }
            let trust = approved(&here, &there, Caps::INBOUND);
            let their_end = raw_receiver(there.clone(), &here);
            let ours_out = raw_dialer(here.clone(), &there);
            let here = added(here, trust).await;
            let (hf, tf) = (here.me.fingerprint.clone(), there.fingerprint.clone());

            // This machine's dial, which does not sort first, as far as its
            // nonce.
            let (ours, theirs_end) =
                tokio::join!(ours_out.connect(their_end.port), their_end.next(WITHIN));
            let (ours, theirs_end) = (ours.expect("dial"), theirs_end.expect("accepted"));
            let pairings = here.pairings.clone();
            let (h, t) = (hf.clone(), tf.clone());
            let at = SocketAddr::from(([127, 0, 0, 1], 4242));
            let ours_task = tokio::task::spawn_local(async move {
                reach_number(&pairings, &ours, Role::Show, &h, &t, at, None)
                    .await
                    .map(|_| ())
            });
            let (mut send, mut recv) = theirs_end.open_bi().await.expect("stream");
            send.write_all(&[0u8; crate::match_code::COMMIT_LEN])
                .await
                .expect("commitment");
            let mut nonce = [0u8; crate::match_code::NONCE_LEN];
            recv.read_exact(&mut nonce).await.expect("nonce");

            // The other machine's dial, which sorts first, arrives after.
            let dials = raw_dialer(there.clone(), &here.me);
            let crossing = dials.connect(here.port).await.expect("handshake");
            let compared = crate::pair_ceremony::as_initiator(&crossing, &tf, &hf).await;
            assert!(
                compared.is_err(),
                "a dial arriving after this machine sent its half on its own reached a \
                 second number: {compared:?}"
            );
            let busy = tokio::time::timeout(WITHIN, crossing.closed()).await;
            assert!(
                matches!(&busy, Ok(quinn::ConnectionError::ApplicationClosed(c)) if &c.reason[..] == BUSY),
                "the dial arriving after was not closed as busy: {busy:?}"
            );

            theirs_end.close(0u32.into(), b"pairing ended");
            match ours_task.await.expect("task") {
                Err((_, Some(Why::Closed))) => {}
                other => panic!(
                    "the one comparison whose half went out, closed by the other machine, \
                     left the approval standing: {other:?}"
                ),
            }
        });
    }

    // LEDGER G-27 | class B | 1 PairingEvent: Number, not Ended, from the production listener after an earlier connection closed before the dialler's nonce
    /// A connection closed before the dialler's nonce went out carries no
    /// number anyone could know: a dial raced to another address and lost,
    /// or the link blipped. It ends quietly, and the next reaches a number.
    #[test]
    fn a_comparison_closed_before_any_nonce_ends_quietly() {
        run_local(async {
            let (b, a) = (machine(), machine());
            let trust = approved(&b, &a, Caps::INBOUND);
            let mut b = added(b, trust).await;
            let a = raw_dialer(a, &b.me);
            let lost = a.connect(b.port).await.expect("handshake");
            let (_send, mut recv) = lost.accept_bi().await.expect("the comparison stream");
            let mut commitment = [0u8; crate::match_code::COMMIT_LEN];
            recv.read_exact(&mut commitment).await.expect("commitment");
            lost.close(0u32.into(), b"lost the race");
            let conn = a.connect(b.port).await.expect("handshake");
            crate::pair_ceremony::as_initiator(&conn, &a.me.fingerprint, &b.me.fingerprint)
                .await
                .expect("a number");
            match next_within(&mut b.events, WITHIN).await {
                Some(PairingEvent::Number { .. }) => {}
                other => panic!(
                    "a connection closed before any nonce went out ended the attempt: {other:?}"
                ),
            }
        });
    }

    // LEDGER G-28 | class B | 2 wire bytes + 1 PairingEvent + 1 return value: what the other machine reads on its dial held back at the production listener, what that listener says, and reach_number on the dial kept, as the kept one ends before or after this machine's half
    /// A comparison held back is settled only once the one kept here holds
    /// or ends. The kept one ended quietly, having sent nothing: the one
    /// held back goes on, and its number is shown. The kept one ended after
    /// this machine's half went out, or ended the approval without it: the
    /// one held back gives up having sent nothing, so the other machine
    /// still knows one number at most (#220).
    #[test]
    fn a_half_held_back_goes_out_only_if_the_kept_comparison_sent_nothing() {
        #[derive(Debug, Clone, Copy, PartialEq)]
        enum Kept {
            /// Closed before anything was sent on it.
            Quiet,
            /// Closed once this machine's half on it went out.
            AfterItsHalf,
            /// A commitment cut short on a connection still open: no
            /// number, and the approval is forgotten.
            ForgettingTheApproval,
        }
        run_local(async {
            let mut up = Vec::new();
            for kept_ended in [Kept::Quiet, Kept::AfterItsHalf, Kept::ForgettingTheApproval] {
                let here = machine();
                let mut there = machine();
                while here.fingerprint >= there.fingerprint {
                    there = machine();
                }
                let trust = approved(&here, &there, Caps::INBOUND);
                let stall_end = raw_receiver(there.clone(), &here);
                let ours_out = raw_dialer(here.clone(), &there);
                let mut here = added(here, trust).await;
                let (hf, tf) = (here.me.fingerprint.clone(), there.fingerprint.clone());

                // This machine's own dial, which sorts first, held up by the
                // other machine.
                let (kept, stall) =
                    tokio::join!(ours_out.connect(stall_end.port), stall_end.next(WITHIN));
                let (kept, stall) = (kept.expect("dial"), stall.expect("accepted"));
                let pairings = here.pairings.clone();
                let (h, t) = (hf.clone(), tf.clone());
                let at = SocketAddr::from(([127, 0, 0, 1], 4242));
                let kept_task = tokio::task::spawn_local(async move {
                    reach_number(&pairings, &kept, Role::Show, &h, &t, at, None)
                        .await
                        .map(|_| ())
                });
                arriving_preferred(&here.pairings, &tf).await;

                // The other machine's dial, held back here once its nonce is in.
                let theirs = raw_dialer(there.clone(), &here.me);
                let held = theirs.connect(here.port).await.expect("handshake");
                let (_send, recv) = send_nonce(&held).await;
                held_back_here(&here.pairings, &tf).await;
                let reveal = tokio::task::spawn_local(read_reveal(recv));

                if kept_ended != Kept::Quiet {
                    let (mut send, mut recv) = stall.open_bi().await.expect("stream");
                    let told = if kept_ended == Kept::AfterItsHalf {
                        // It learns this machine's half on the kept dial,
                        // then closes it.
                        send.write_all(&[0u8; crate::match_code::COMMIT_LEN])
                            .await
                            .expect("commitment");
                        let mut nonce = [0u8; crate::match_code::NONCE_LEN];
                        recv.read_exact(&mut nonce).await.expect("nonce");
                        stall.close(0u32.into(), b"pairing ended");
                        Why::Closed
                    } else {
                        send.write_all(&[0u8; 3])
                            .await
                            .expect("part of a commitment");
                        let _ = send.finish();
                        Why::NoComparison
                    };
                    let ended = kept_task.await.expect("task");
                    assert!(
                        matches!(&ended, Err((_, Some(why))) if *why == told),
                        "{kept_ended:?}: the kept comparison did not end the approval as \
                         {told:?}: {ended:?}"
                    );
                    let learned = reveal.await.expect("task");
                    assert!(
                        learned.is_err(),
                        "{kept_ended:?}: the half held back went out after the kept \
                         comparison ended the approval: the other machine knew a number \
                         from an approval already given up: {learned:?}"
                    );
                } else {
                    stall.close(0u32.into(), b"pairing ended");
                    assert!(
                        matches!(kept_task.await.expect("task"), Err((_, None))),
                        "the kept comparison, closed before anything was sent, ended the \
                         approval"
                    );
                    let learned = reveal.await.expect("task");
                    assert!(
                        learned.is_ok(),
                        "the half held back never went out once the kept comparison ended \
                         having sent nothing: {learned:?}"
                    );
                    let (role, _) = number(&mut here.events, "the comparison held back").await;
                    assert_eq!(role, Role::Pick);
                }
                up.push((here, held, theirs, stall_end, ours_out));
            }
        });
    }

    // LEDGER G-33 | class B | 1 return value: reach_number at both of this machine's ends when the other machine's close of its own dial arrives before anything on this machine's dial
    /// Two machines adding each other: the other machine, sorting last,
    /// keeps this machine's dial and gives its own up. Its close of its own
    /// dial and its half on this machine's dial travel on two connections,
    /// so either may arrive first. The close arriving first, while this
    /// machine holds its half back on that dial, ends that comparison
    /// quietly, and this machine's dial still reaches the number: a packet
    /// late or out of order does not cost the approval (#220).
    #[test]
    fn the_close_of_the_dial_given_up_arriving_first_keeps_the_approval() {
        run_local(async {
            let c = crossed().await;
            let (here, _events) = Pairings::new();
            let at = SocketAddr::from(([127, 0, 0, 1], 4242));
            let (p, l, h, z) = (here.clone(), c.lf.clone(), c.hf.clone(), c.z.0.clone());
            let kept = tokio::task::spawn_local(async move {
                reach_number(&p, &z, Role::Show, &l, &h, at, None)
                    .await
                    .map(|(_, n)| n)
            });
            arriving_preferred(&here, &c.hf).await;
            let (p, l, h, x) = (here.clone(), c.lf.clone(), c.hf.clone(), c.x.0.clone());
            let given_up = tokio::task::spawn_local(async move {
                reach_number(&p, &x, Role::Pick, &l, &h, at, None)
                    .await
                    .map(|(_, n)| n)
            });
            // The other machine's nonce on its own dial, then its close of it,
            // both before anything of its half on this machine's dial.
            let (_send, _recv) = send_nonce(&c.x.1).await;
            held_back_here(&here, &c.hf).await;
            c.x.1.close(0u32.into(), SUPERSEDED);
            let given_up = given_up.await.expect("task");
            assert!(
                matches!(given_up, Err((_, None))),
                "the close of the dial given up, arriving before anything on the dial \
                 kept, ended the approval: {:?}",
                given_up.map(|_| ())
            );
            let theirs = crate::pair_ceremony::as_responder(&c.z.1, &c.hf, &c.lf)
                .await
                .expect("the number on the dial both keep");
            let ours = kept
                .await
                .expect("task")
                .expect("this machine's dial reached no number after the close");
            assert_eq!(ours, theirs, "the two machines hold different numbers");
        });
    }

    /// A receiver like [`raw_receiver`] that lets the dialler send at most
    /// `window` bytes on a stream before reading them.
    fn raw_receiver_windowed(me: Machine, dialled_by: &Machine, window: u32) -> RawReceiver {
        crate::transport::install_crypto_provider();
        let mut cfg = crate::listen::server_config(
            &me.identity,
            paired(&me, dialled_by, Caps::INBOUND),
            Default::default(),
        )
        .expect("server config");
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(8u8.into());
        transport.stream_receive_window(window.into());
        cfg.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().expect("loopback"))
            .expect("endpoint");
        let port = endpoint.local_addr().expect("bound").port();
        RawReceiver { me, endpoint, port }
    }

    /// Wait until `conn` has received `frames` stream frames.
    async fn stream_frames(conn: &quinn::Connection, frames: u64) {
        while conn.stats().frame_rx.stream < frames {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    const PART: usize = 8;

    // LEDGER G-29 | class B | 1 PairingEvent: Ended from LanMouseConnection after the other end closed the comparison holding part of the dialler's nonce
    /// Part of the dialler's nonce is part of the number: a machine that
    /// lets only some of it through before closing already narrows the
    /// number down, so that ends the approval too.
    #[test]
    fn a_comparison_closed_on_part_of_the_dialler_s_nonce_ends_the_approval() {
        run_local(async {
            let (a, b) = (machine(), machine());
            let b = raw_receiver_windowed(b, &a, PART as u32);
            let mut d = dialer(
                &a,
                approved(&a, &b.me, Caps::OUTBOUND),
                b.port,
                Position::Left,
            );
            let mut a_events = d.conn.take_pairing_events().expect("pairing events");
            d.conn.dial(d.handle).await;
            let conn = b.next(WITHIN).await.expect("the dial reaches the receiver");
            let (mut send, mut recv) = conn.open_bi().await.expect("the comparison stream");
            send.write_all(&[0u8; crate::match_code::COMMIT_LEN])
                .await
                .expect("commitment");
            // The first stream frame this end receives is the nonce, cut off
            // at the window: read it whole, and close in the same step.
            stream_frames(&conn, 1).await;
            let mut part = [0u8; PART];
            recv.read_exact(&mut part).await.expect("part of the nonce");
            conn.close(0u32.into(), b"pairing ended");
            match next_within(&mut a_events, WITHIN).await {
                Some(PairingEvent::Ended { why, .. }) => assert_eq!(why, Why::Closed),
                other => panic!(
                    "the machine dialled closed the comparison on part of the dialler's \
                     nonce, and the approval stood: {other:?}"
                ),
            }
        });
    }

    // LEDGER G-30 | class B | 1 PairingEvent: Ended from the production listener after the other end closed the comparison holding part of the reveal
    /// The machine being added reveals its half last. A dialler that lets
    /// only part of the reveal through before closing can narrow the number
    /// down against the commitment, so that ends the approval too.
    #[test]
    fn a_comparison_closed_on_part_of_the_reveal_ends_the_approval() {
        run_local(async {
            let (b, a) = (machine(), machine());
            let trust = approved(&b, &a, Caps::INBOUND);
            let mut b = added(b, trust).await;
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback"))
                .expect("endpoint");
            endpoint.set_default_client_config(crate::test_harness::raw_client_config(
                &a,
                paired(&a, &b.me, Caps::OUTBOUND),
                (crate::match_code::COMMIT_LEN + PART) as u32,
            ));
            let at = SocketAddr::new("127.0.0.1".parse().expect("loopback"), b.port);
            let conn = endpoint
                .connect(at, "grabbr")
                .expect("connect")
                .await
                .expect("handshake");
            let (mut send, mut recv) = conn.accept_bi().await.expect("the comparison stream");
            // The commitment is left unread, so the window stays shut behind
            // part of the reveal.
            send.write_all(&[0u8; crate::match_code::NONCE_LEN])
                .await
                .expect("nonce");
            stream_frames(&conn, 2).await;
            let mut got = [0u8; crate::match_code::COMMIT_LEN + PART];
            recv.read_exact(&mut got)
                .await
                .expect("the commitment and part of the reveal");
            conn.close(0u32.into(), b"pairing ended");
            match next_within(&mut b.events, WITHIN).await {
                Some(PairingEvent::Ended { why, .. }) => assert_eq!(why, Why::Closed),
                other => panic!(
                    "the dialler closed the comparison on part of the reveal, and the \
                     approval stood: {other:?}"
                ),
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

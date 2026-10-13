//! The queue between a capture backend's event thread and the async consumer.
//!
//! A capture thread produces events at the rate the hardware does (a gaming
//! mouse moves ~1000 times a second) while the consumer can stall for tens of
//! milliseconds on a network send. A plain bounded channel then has to either
//! block the producer, which is not allowed inside an OS input hook, or drop
//! whatever arrives while it is full. Dropping a button-up or a key-up leaves
//! the peer holding it, and nothing downstream can tell (#81).
//!
//! This queue never blocks the producer, never fails and never panics, and
//! decides what may be lost by what an event means:
//!
//! - Relative motion is a sample. A motion arriving behind motion the
//!   consumer has not taken yet is summed into the waiting motion for its
//!   position, so the total displacement
//!   is kept exactly and ordering against buttons and keys is unchanged.
//!   Motion is never dropped: there is at most one motion entry per position
//!   between two other entries.
//! - Presses, releases, scrolls and `Begin` are kept, in order, up to
//!   `capacity` of them.
//! - A release of something this queue delivered a press for is always kept,
//!   even past `capacity`: there are at most as many as there are held keys
//!   and buttons.
//! - When a press or a scroll arrives and `capacity` is reached, the consumer
//!   is not taking events. The queue then appends a release for every key and
//!   button it delivered a press for and not yet a release, and refuses
//!   presses and scrolls until the consumer has taken everything. A refused
//!   press can leave the peer missing a key, never holding one.
//! - `Begin` is never refused: without it the consumer would not know the
//!   capture is active while the hook swallows local input. One is produced
//!   per crossing, and a crossing needs the consumer to release first.
//!
//! Once the receiver is gone every push is discarded, so a backend thread that
//! outlives its consumer during teardown cannot fail or panic (#80).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use input_event::{Event, KeyboardEvent, PointerEvent};

use crate::{CaptureEvent, Position};

/// How many kept events may wait for the consumer before the queue releases
/// what it holds. Motion does not count, it merges.
pub(crate) const CAPACITY: usize = 256;

type Item = (Position, CaptureEvent);

/// Creates a queue that keeps up to `capacity` events other than motion.
pub(crate) fn channel(capacity: usize) -> (QueueSender, QueueReceiver) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            events: VecDeque::new(),
            kept: 0,
            capacity: capacity.max(1),
            held: Vec::new(),
            refusing: None,
            sender_gone: false,
            receiver_gone: false,
            waker: None,
        }),
    });
    (
        QueueSender {
            shared: Arc::clone(&shared),
        },
        QueueReceiver { shared },
    )
}

struct Shared {
    state: Mutex<State>,
}

impl Shared {
    /// A poisoned lock still holds a consistent queue: every critical section
    /// below is panic-free. Taking it anyway keeps the producer panic-free.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    Button(u32),
    Key(u32),
}

impl Held {
    fn release(self) -> CaptureEvent {
        match self {
            Held::Button(button) => CaptureEvent::Input(Event::Pointer(PointerEvent::Button {
                time: 0,
                button,
                state: 0,
            })),
            Held::Key(key) => CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key {
                time: 0,
                key,
                state: 0,
            })),
        }
    }
}

enum Kind {
    Motion(f64, f64),
    Press(Held),
    Release(Held),
    Begin,
    /// Scrolls and anything else that is neither a sample nor held state.
    Other,
}

fn kind(event: &CaptureEvent) -> Kind {
    match event {
        CaptureEvent::Begin => Kind::Begin,
        CaptureEvent::Input(Event::Pointer(PointerEvent::Motion { dx, dy, .. })) => {
            Kind::Motion(*dx, *dy)
        }
        CaptureEvent::Input(Event::Pointer(PointerEvent::Button { button, state, .. })) => {
            if *state == 0 {
                Kind::Release(Held::Button(*button))
            } else {
                Kind::Press(Held::Button(*button))
            }
        }
        CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key { key, state, .. })) => {
            if *state == 0 {
                Kind::Release(Held::Key(*key))
            } else {
                Kind::Press(Held::Key(*key))
            }
        }
        CaptureEvent::Input(_) => Kind::Other,
    }
}

/// What was refused while the queue could not deliver, for one log line.
#[derive(Default, Clone, Copy)]
struct Refused {
    presses: usize,
    others: usize,
}

struct State {
    events: VecDeque<Item>,
    /// Entries in `events` that are not motion.
    kept: usize,
    capacity: usize,
    /// Keys and buttons this queue accepted a press for and no release since,
    /// in press order.
    held: Vec<(Position, Held)>,
    /// Set from the moment the queue released what it held until the consumer
    /// has taken every event.
    refusing: Option<Refused>,
    sender_gone: bool,
    receiver_gone: bool,
    waker: Option<Waker>,
}

/// Something worth one log line, written after the lock is released.
enum Note {
    Overflowed { released: usize, capacity: usize },
    Drained(Refused),
}

impl State {
    fn push(&mut self, pos: Position, event: CaptureEvent) -> Option<Note> {
        if self.receiver_gone {
            return None;
        }
        match kind(&event) {
            Kind::Motion(dx, dy) => {
                // Merge into this position's motion in the run of motion at
                // the tail, so there is at most one motion entry per position
                // between two kept entries.
                for (last_pos, last) in self.events.iter_mut().rev() {
                    let CaptureEvent::Input(Event::Pointer(PointerEvent::Motion {
                        dx: last_dx,
                        dy: last_dy,
                        ..
                    })) = last
                    else {
                        break;
                    };
                    if *last_pos == pos {
                        *last_dx += dx;
                        *last_dy += dy;
                        return None;
                    }
                }
                self.events.push_back((pos, event));
                None
            }
            Kind::Begin => {
                self.keep(pos, event);
                None
            }
            Kind::Release(held) => {
                if let Some(i) = self.held.iter().position(|&h| h == (pos, held)) {
                    self.held.remove(i);
                    self.keep(pos, event);
                } else if self.refusing.is_none() && self.kept < self.capacity {
                    // Not one of ours to release, so it cannot leave anything
                    // held; forwarded as before while there is room.
                    self.keep(pos, event);
                }
                None
            }
            Kind::Press(_) | Kind::Other if self.refusing.is_some() => {
                self.count_refused(&event);
                None
            }
            Kind::Press(_) | Kind::Other if self.kept >= self.capacity => {
                let released = self.held.len();
                for (held_pos, held) in std::mem::take(&mut self.held) {
                    self.keep(held_pos, held.release());
                }
                self.refusing = Some(Refused::default());
                self.count_refused(&event);
                Some(Note::Overflowed {
                    released,
                    capacity: self.capacity,
                })
            }
            Kind::Press(held) => {
                if !self.held.contains(&(pos, held)) {
                    self.held.push((pos, held));
                }
                self.keep(pos, event);
                None
            }
            Kind::Other => {
                self.keep(pos, event);
                None
            }
        }
    }

    fn keep(&mut self, pos: Position, event: CaptureEvent) {
        self.events.push_back((pos, event));
        self.kept += 1;
    }

    fn count_refused(&mut self, event: &CaptureEvent) {
        if let Some(refused) = self.refusing.as_mut() {
            match kind(event) {
                Kind::Press(_) => refused.presses += 1,
                _ => refused.others += 1,
            }
        }
    }

    fn pop(&mut self) -> Option<(Item, Option<Note>)> {
        let item = self.events.pop_front()?;
        if !matches!(kind(&item.1), Kind::Motion(..)) {
            self.kept = self.kept.saturating_sub(1);
        }
        let note = if self.events.is_empty() {
            self.refusing.take().map(Note::Drained)
        } else {
            None
        };
        Some((item, note))
    }
}

fn log_note(note: Note) {
    // Counts only: which key was involved belongs to the keylog, never to
    // the general log (#117).
    match note {
        Note::Overflowed { released, capacity } => log::warn!(
            "input capture: {capacity} events are waiting to be sent; released {released} \
             held keys and buttons and refusing presses until they are sent"
        ),
        Note::Drained(refused) => log::info!(
            "input capture: the queue drained; {} presses and {} scrolls were refused \
             while it was full",
            refused.presses,
            refused.others
        ),
    }
}

/// The producer's end. Used from inside OS input hooks: nothing here blocks
/// for longer than the consumer's pop, and nothing here can panic.
pub(crate) struct QueueSender {
    shared: Arc<Shared>,
}

impl QueueSender {
    pub(crate) fn push(&self, pos: Position, event: CaptureEvent) {
        let (note, waker) = {
            let mut state = self.shared.lock();
            let note = state.push(pos, event);
            (note, state.waker.take())
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        if let Some(note) = note {
            log_note(note);
        }
    }
}

impl Drop for QueueSender {
    fn drop(&mut self) {
        let waker = {
            let mut state = self.shared.lock();
            state.sender_gone = true;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The consumer's end.
pub(crate) struct QueueReceiver {
    shared: Arc<Shared>,
}

impl QueueReceiver {
    /// The next event; `None` once the sender is gone and everything it sent
    /// has been taken.
    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Item>> {
        let popped = {
            let mut state = self.shared.lock();
            match state.pop() {
                Some(popped) => Some(popped),
                None if state.sender_gone => return Poll::Ready(None),
                None => {
                    state.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        };
        let Some((item, note)) = popped else {
            return Poll::Pending;
        };
        if let Some(note) = note {
            log_note(note);
        }
        Poll::Ready(Some(item))
    }
}

impl Drop for QueueReceiver {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.receiver_gone = true;
        state.events.clear();
        state.kept = 0;
        state.held.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use input_event::{BTN_LEFT, BTN_RIGHT};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Wake;

    const POS: Position = Position::Right;

    fn motion(dx: f64, dy: f64) -> CaptureEvent {
        CaptureEvent::Input(Event::Pointer(PointerEvent::Motion { time: 0, dx, dy }))
    }
    fn button(button: u32, state: u32) -> CaptureEvent {
        CaptureEvent::Input(Event::Pointer(PointerEvent::Button {
            time: 0,
            button,
            state,
        }))
    }
    fn key(key: u32, state: u8) -> CaptureEvent {
        CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key {
            time: 0,
            key,
            state,
        }))
    }
    fn scroll(value: i32) -> CaptureEvent {
        CaptureEvent::Input(Event::Pointer(PointerEvent::AxisDiscrete120 {
            axis: 0,
            value,
        }))
    }

    struct Flag(AtomicBool);
    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn try_recv(rx: &mut QueueReceiver) -> Poll<Option<Item>> {
        let waker = Waker::from(Arc::new(Flag(AtomicBool::new(false))));
        rx.poll_recv(&mut Context::from_waker(&waker))
    }

    /// Everything the receiver has right now.
    fn drain(rx: &mut QueueReceiver) -> Vec<Item> {
        let mut out = vec![];
        while let Poll::Ready(Some(item)) = try_recv(rx) {
            out.push(item);
        }
        out
    }

    fn total_motion(items: &[Item]) -> (f64, f64) {
        items.iter().fold((0.0, 0.0), |(x, y), (_, e)| match e {
            CaptureEvent::Input(Event::Pointer(PointerEvent::Motion { dx, dy, .. })) => {
                (x + dx, y + dy)
            }
            _ => (x, y),
        })
    }

    fn without_motion(items: &[Item]) -> Vec<Item> {
        items
            .iter()
            .filter(|(_, e)| !matches!(kind(e), Kind::Motion(..)))
            .copied()
            .collect()
    }

    /// Keys and buttons a stream leaves held, in the order first pressed.
    fn held_after(items: &[Item]) -> Vec<(Position, Held)> {
        let mut held = vec![];
        for (pos, e) in items {
            match kind(e) {
                Kind::Press(h) if !held.contains(&(*pos, h)) => held.push((*pos, h)),
                Kind::Release(h) => held.retain(|x| *x != (*pos, h)),
                _ => {}
            }
        }
        held
    }

    #[test]
    fn a_button_up_behind_a_flood_of_motion_is_delivered() {
        let (tx, mut rx) = channel(CAPACITY);
        tx.push(POS, button(BTN_LEFT, 1));
        for _ in 0..5000 {
            tx.push(POS, motion(1.0, -2.0));
        }
        tx.push(POS, button(BTN_LEFT, 0));

        let got = drain(&mut rx);
        assert_eq!(
            without_motion(&got),
            vec![(POS, button(BTN_LEFT, 1)), (POS, button(BTN_LEFT, 0))],
            "a button transition was lost behind motion"
        );
        assert_eq!(total_motion(&got), (5000.0, -10000.0), "motion lost");
    }

    #[test]
    fn a_burst_of_keys_the_consumer_has_not_taken_yet_is_delivered_in_order() {
        let (tx, mut rx) = channel(CAPACITY);
        let mut sent = vec![];
        for k in 30..60 {
            for state in [1, 0] {
                tx.push(POS, key(k, state));
                sent.push((POS, key(k, state)));
            }
        }
        assert_eq!(drain(&mut rx), sent, "a key transition was lost");
    }

    #[test]
    fn motion_merges_only_with_motion_not_across_a_button_or_key() {
        let (tx, mut rx) = channel(CAPACITY);
        tx.push(POS, motion(1.0, 1.0));
        tx.push(POS, button(BTN_LEFT, 1));
        tx.push(POS, motion(2.0, 0.0));
        tx.push(POS, motion(3.0, 0.0));
        tx.push(Position::Left, motion(7.0, 0.0));
        tx.push(POS, button(BTN_LEFT, 0));
        assert_eq!(
            drain(&mut rx),
            vec![
                (POS, motion(1.0, 1.0)),
                (POS, button(BTN_LEFT, 1)),
                (POS, motion(5.0, 0.0)),
                (Position::Left, motion(7.0, 0.0)),
                (POS, button(BTN_LEFT, 0)),
            ]
        );
    }

    #[test]
    fn a_queue_that_cannot_deliver_releases_what_it_holds_and_refuses_presses() {
        let (tx, mut rx) = channel(4);
        tx.push(POS, key(42, 1));
        tx.push(POS, button(BTN_RIGHT, 1));
        tx.push(POS, scroll(120));
        tx.push(POS, scroll(120));
        // Full: the consumer has taken nothing.
        tx.push(POS, key(30, 1));
        tx.push(POS, scroll(120));
        tx.push(POS, key(42, 0));
        tx.push(POS, motion(4.0, 4.0));
        tx.push(POS, CaptureEvent::Begin);

        let got = drain(&mut rx);
        assert!(
            held_after(&got).is_empty(),
            "the peer is left holding {:?}",
            held_after(&got)
        );
        assert_eq!(
            without_motion(&got),
            vec![
                (POS, key(42, 1)),
                (POS, button(BTN_RIGHT, 1)),
                (POS, scroll(120)),
                (POS, scroll(120)),
                (POS, key(42, 0)),
                (POS, button(BTN_RIGHT, 0)),
                (POS, CaptureEvent::Begin),
            ]
        );
        assert_eq!(total_motion(&got), (4.0, 4.0));

        // Everything was taken: presses are accepted again.
        tx.push(POS, key(31, 1));
        assert_eq!(drain(&mut rx), vec![(POS, key(31, 1))]);
    }

    #[test]
    fn presses_stay_refused_until_the_consumer_has_taken_everything() {
        let (tx, mut rx) = channel(2);
        tx.push(POS, key(30, 1));
        tx.push(POS, key(31, 1));
        // Full: the queue releases both keys and starts refusing.
        tx.push(POS, scroll(120));
        let mut taken = vec![];
        for _ in 0..3 {
            let Poll::Ready(Some(item)) = try_recv(&mut rx) else {
                panic!("the backlog ended early: {taken:?}");
            };
            taken.push(item);
        }
        assert_eq!(
            taken,
            vec![(POS, key(30, 1)), (POS, key(31, 1)), (POS, key(30, 0))]
        );

        // Room again, but one event still waits: still refusing.
        tx.push(POS, key(32, 1));
        tx.push(POS, scroll(120));
        assert_eq!(drain(&mut rx), vec![(POS, key(31, 0))]);

        // Everything was taken: accepted again.
        tx.push(POS, key(33, 1));
        assert_eq!(drain(&mut rx), vec![(POS, key(33, 1))]);
    }

    #[test]
    fn a_release_of_something_held_is_kept_even_when_full() {
        let (tx, mut rx) = channel(2);
        tx.push(POS, button(BTN_LEFT, 1));
        tx.push(POS, key(29, 1));
        tx.push(POS, key(29, 0));
        tx.push(POS, button(BTN_LEFT, 0));
        let got = drain(&mut rx);
        assert_eq!(without_motion(&got).len(), 4, "{got:?}");
        assert!(held_after(&got).is_empty());
    }

    #[test]
    fn a_push_after_the_receiver_is_gone_is_discarded_not_a_panic() {
        let (tx, rx) = channel(CAPACITY);
        drop(rx);
        tx.push(POS, CaptureEvent::Begin);
        tx.push(POS, key(30, 1));
        tx.push(POS, motion(1.0, 1.0));
        assert!(tx.shared.lock().events.is_empty());
    }

    #[test]
    fn the_receiver_ends_after_the_sender_is_gone_and_everything_was_taken() {
        let (tx, mut rx) = channel(CAPACITY);
        tx.push(POS, key(30, 1));
        drop(tx);
        assert_eq!(try_recv(&mut rx), Poll::Ready(Some((POS, key(30, 1)))));
        assert_eq!(try_recv(&mut rx), Poll::Ready(None));
    }

    #[test]
    fn a_waiting_receiver_is_woken_by_a_push_and_by_the_sender_going() {
        let (tx, mut rx) = channel(CAPACITY);
        for last in [false, true] {
            let flag = Arc::new(Flag(AtomicBool::new(false)));
            let waker = Waker::from(Arc::clone(&flag));
            assert_eq!(
                rx.poll_recv(&mut Context::from_waker(&waker)),
                Poll::Pending
            );
            if last {
                drop(tx);
                assert!(flag.0.load(Ordering::SeqCst), "not woken on close");
                assert_eq!(try_recv(&mut rx), Poll::Ready(None));
                return;
            }
            tx.push(POS, motion(1.0, 0.0));
            assert!(flag.0.load(Ordering::SeqCst), "not woken on push");
            assert!(matches!(try_recv(&mut rx), Poll::Ready(Some(_))));
        }
    }

    /// xorshift64*, so the property test needs no new dependency and a
    /// failing seed can be replayed.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Random pushes against a consumer that takes a random number of events
    /// at random times, with small capacities so the queue overflows often.
    /// Checked for every run:
    /// - after the consumer takes everything, it holds no key or button the
    ///   producer released (nothing sticks);
    /// - the total motion taken toward each position equals the total pushed
    ///   toward it (integer deltas, as a hook produces, so the f64 sums are
    ///   exact);
    /// - a run that never overflowed delivers every non-motion event, in
    ///   order;
    /// - the queue stays bounded.
    #[test]
    fn no_transition_is_lost_and_motion_keeps_its_total() {
        let codes = [
            Held::Key(29),
            Held::Key(30),
            Held::Key(42),
            Held::Button(BTN_LEFT),
            Held::Button(BTN_RIGHT),
        ];
        let positions = [Position::Left, Position::Right];
        let mut overflowed_runs = 0;
        for seed in 1..=400u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let capacity = 1 + rng.below(8) as usize;
            let (tx, mut rx) = channel(capacity);
            let mut pushed: Vec<Item> = vec![];
            let mut got: Vec<Item> = vec![];
            let mut begins = 0;
            let mut overflowed = false;
            for _ in 0..600 {
                let pos = positions[rng.below(2) as usize];
                let event = match rng.below(10) {
                    0..=3 => motion(rng.below(21) as f64 - 10.0, rng.below(21) as f64 - 10.0),
                    4..=7 => {
                        let state = rng.below(2) as u32;
                        match codes[rng.below(codes.len() as u64) as usize] {
                            Held::Key(k) => key(k, state as u8),
                            Held::Button(b) => button(b, state),
                        }
                    }
                    8 if rng.below(20) == 0 => {
                        begins += 1;
                        CaptureEvent::Begin
                    }
                    _ => scroll(120),
                };
                tx.push(pos, event);
                pushed.push((pos, event));
                {
                    let state = tx.shared.lock();
                    let bound = capacity + codes.len() * positions.len() + begins;
                    assert!(state.kept <= bound, "seed {seed}: {} kept", state.kept);
                    let motions = (state.kept + 1) * positions.len();
                    assert!(state.events.len() <= state.kept + motions, "seed {seed}");
                    overflowed |= state.refusing.is_some();
                }
                if rng.below(4) == 0 {
                    for _ in 0..rng.below(capacity as u64 + 2) {
                        match try_recv(&mut rx) {
                            Poll::Ready(Some(item)) => got.push(item),
                            _ => break,
                        }
                    }
                }
            }
            got.extend(drain(&mut rx));

            let still_held = held_after(&pushed);
            for h in held_after(&got) {
                assert!(
                    still_held.contains(&h),
                    "seed {seed}: {h:?} is held on the peer after the producer released it"
                );
            }
            for pos in positions {
                let at = |items: &[Item]| -> Vec<Item> {
                    items.iter().filter(|(p, _)| *p == pos).copied().collect()
                };
                assert_eq!(
                    total_motion(&at(&got)),
                    total_motion(&at(&pushed)),
                    "seed {seed}: motion toward {pos:?}"
                );
            }
            if !overflowed {
                assert_eq!(without_motion(&got), without_motion(&pushed), "seed {seed}");
                continue;
            }
            overflowed_runs += 1;
            // An overflow adds releases and leaves presses and scrolls out;
            // what it delivers of those is still in the order pushed, and
            // every Begin arrives.
            let sent: Vec<Item> = without_motion(&pushed)
                .into_iter()
                .filter(|(_, e)| !matches!(kind(e), Kind::Release(_)))
                .collect();
            let mut sent = sent.into_iter();
            for item in without_motion(&got) {
                if matches!(kind(&item.1), Kind::Release(_)) {
                    continue;
                }
                loop {
                    let Some(next) = sent.next() else {
                        panic!("seed {seed}: {item:?} delivered out of order or never pushed");
                    };
                    if next == item {
                        break;
                    }
                    assert!(
                        !matches!(kind(&next.1), Kind::Begin),
                        "seed {seed}: a Begin was refused"
                    );
                }
            }
            assert!(
                sent.all(|(_, e)| !matches!(kind(&e), Kind::Begin)),
                "seed {seed}: a Begin was refused"
            );
        }
        assert!(
            overflowed_runs > 50,
            "only {overflowed_runs} runs overflowed"
        );
    }
}

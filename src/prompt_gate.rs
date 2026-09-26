//! When a pairing prompt may appear (#195).
//!
//! A prompt appears only while this machine's pairing window is open: someone
//! opened the add-device flow here within the last two minutes. Adding a device
//! happens inside that flow, so the prompt our own dial raises for the device
//! being added falls inside the window too. Every other unknown machine is
//! refused and logged.
//!
//! Without this, any machine that reached this one could put a prompt on screen
//! whenever it liked, and a removed machine, which is forgotten (#184), could
//! ask again straight away. Picking the matching number does not close that
//! gap: with three to choose from, a careless tap approves one time in three.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// What to do with one unknown machine's attempt to pair.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    /// Show the prompt.
    Prompt,
    /// Refused: the pairing window is not open on this machine.
    Closed,
    /// Already prompted for this machine moments ago.
    Repeat,
}

pub(crate) struct PromptGate {
    opened: Option<Instant>,
    recent: RecentPrompts,
    refusals: RefusalLog,
    admitted: AdmittedLog,
}

impl PromptGate {
    /// How long the window stays open after the add-device flow is opened.
    pub(crate) const WINDOW: Duration = Duration::from_secs(120);

    pub(crate) fn new() -> Self {
        Self {
            opened: None,
            recent: RecentPrompts::new(),
            refusals: RefusalLog::new(),
            admitted: AdmittedLog::new(),
        }
    }

    /// Someone opened the add-device flow on this machine.
    pub(crate) fn open(&mut self, now: Instant) {
        self.opened = Some(now);
    }

    /// How long the window has left, or `None` when it is closed.
    pub(crate) fn remaining(&self, now: Instant) -> Option<Duration> {
        let opened = self.opened?;
        Self::WINDOW
            .checked_sub(now.saturating_duration_since(opened))
            .filter(|left| !left.is_zero())
    }

    /// Whether `fingerprint`'s attempt may raise a prompt.
    ///
    /// Only an admitted attempt is remembered for the repeat check. A knock
    /// refused while the window was closed must not suppress the one that
    /// arrives just after it opens, or the person who opened it waits for a
    /// prompt that never comes.
    pub(crate) fn admit(&mut self, fingerprint: &str, now: Instant) -> Admit {
        if self.remaining(now).is_none() {
            return Admit::Closed;
        }
        if self.recent.seen_recently(fingerprint, now) {
            return Admit::Repeat;
        }
        Admit::Prompt
    }

    /// Record a refusal, and return a line to log when one is due.
    ///
    /// A stranger generating a fresh key per dial offers a new fingerprint every
    /// time, measured at 120 a second from one host. One log line per refusal
    /// would let anyone on the network fill the log, so refusals are counted and
    /// summarised at most once per `RefusalLog::EVERY`.
    pub(crate) fn note_refusal(&mut self, fingerprint: &str, now: Instant) -> Option<String> {
        self.refusals.note(fingerprint, now)
    }

    /// Record an admitted request from another machine. `Some(n)` when it
    /// should be logged, `n` being how many before it were not.
    pub(crate) fn note_admitted(&mut self, now: Instant) -> Option<u32> {
        self.admitted.note(now)
    }

    /// Whether a prompt admitted at `admitted` may be shown again now, to a
    /// frontend that was not attached when it was raised (#114).
    ///
    /// Only while the window is open, as for any prompt, and only for a request
    /// admitted since it opened: opening add device for one machine must not
    /// bring back a request some other machine made in an earlier window.
    /// Opening add device again while the window is open starts a new window,
    /// so what was admitted before that is not shown again. A machine still
    /// asking knocks again, and its next knock is admitted in the new window.
    pub(crate) fn replayable(&self, admitted: Instant, now: Instant) -> bool {
        self.remaining(now).is_some() && self.opened.is_some_and(|opened| admitted >= opened)
    }
}

/// Machines prompted for moments ago, so one machine retrying in a loop raises
/// one prompt and not one per retry.
///
/// Anyone on the network can add to this: dial with a certificate we do not
/// know and, while the window is open, an entry is recorded. A peer generating
/// a fresh key per dial produces a fresh entry per dial, so entries older than
/// the suppression window are dropped and the map is bounded.
struct RecentPrompts {
    seen: HashMap<String, Instant>,
}

impl RecentPrompts {
    /// How long a machine stays suppressed after it raises a prompt.
    const WINDOW: Duration = Duration::from_secs(2);

    /// Prune once the map is larger than a real fleet could explain. Chosen so
    /// pruning is rare in normal use and cheap when an attacker forces it.
    const PRUNE_AT: usize = 256;

    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// True if `fingerprint` raised a prompt within the suppression window.
    /// Records it either way.
    fn seen_recently(&mut self, fingerprint: &str, now: Instant) -> bool {
        if self.seen.len() >= Self::PRUNE_AT {
            self.seen
                .retain(|_, at| now.saturating_duration_since(*at) < Self::WINDOW);
            // Everything still here is inside the window, which means a flood of
            // distinct fingerprints rather than a fleet. Drop it: the cost is a
            // repeated prompt for a machine that dialled seconds ago, and the
            // alternative is unbounded growth driven by a stranger.
            if self.seen.len() >= Self::PRUNE_AT {
                self.seen.clear();
            }
        }
        match self.seen.insert(fingerprint.to_owned(), now) {
            None => false,
            Some(at) => now.saturating_duration_since(at) < Self::WINDOW,
        }
    }
}

/// Bounds the log lines written for admitted requests.
///
/// Each one is logged with its fingerprint, so a machine without a frontend
/// attached can still be approved from the command line (#114). Admission is
/// per fingerprint, though, so a stranger generating a fresh key per dial is
/// admitted on every dial while the window is open. A handful of lines per
/// period covers any real pairing; past that, requests are counted and the
/// count goes on the next line written.
struct AdmittedLog {
    period: Option<Instant>,
    lines: u32,
    unlogged: u32,
}

impl AdmittedLog {
    const EVERY: Duration = Duration::from_secs(10);
    const LINES: u32 = 8;

    fn new() -> Self {
        Self {
            period: None,
            lines: 0,
            unlogged: 0,
        }
    }

    fn note(&mut self, now: Instant) -> Option<u32> {
        if self
            .period
            .is_none_or(|start| now.saturating_duration_since(start) >= Self::EVERY)
        {
            self.period = Some(now);
            self.lines = 0;
        }
        if self.lines < Self::LINES {
            self.lines += 1;
            Some(std::mem::take(&mut self.unlogged))
        } else {
            self.unlogged = self.unlogged.saturating_add(1);
            None
        }
    }
}

/// Counts refusals between log lines.
struct RefusalLog {
    last: Option<Instant>,
    since: u32,
}

impl RefusalLog {
    const EVERY: Duration = Duration::from_secs(10);

    fn new() -> Self {
        Self {
            last: None,
            since: 0,
        }
    }

    fn note(&mut self, fingerprint: &str, now: Instant) -> Option<String> {
        self.since = self.since.saturating_add(1);
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < Self::EVERY)
        {
            return None;
        }
        let count = std::mem::take(&mut self.since);
        self.last = Some(now);
        Some(if count == 1 {
            format!(
                "refused a pairing request from {fingerprint}: add device is not open \
                 on this machine"
            )
        } else {
            format!(
                "refused {count} pairing requests, the latest from {fingerprint}: add \
                 device is not open on this machine"
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn a_knock_while_add_device_is_closed_raises_no_prompt() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        assert_eq!(gate.admit("stranger", now), Admit::Closed);
    }

    #[test]
    fn a_knock_while_the_window_is_open_prompts_once() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        assert_eq!(gate.admit("peer", now + S), Admit::Prompt);
        assert_eq!(
            gate.admit("peer", now + S),
            Admit::Repeat,
            "a machine retrying in a loop must raise one prompt, not one per retry"
        );
    }

    /// The window lasts two minutes and then closes by itself.
    #[test]
    fn the_window_closes_two_minutes_after_it_opens() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        assert_eq!(
            gate.admit("early", now + PromptGate::WINDOW - S),
            Admit::Prompt
        );
        assert_eq!(
            gate.admit("late", now + PromptGate::WINDOW),
            Admit::Closed,
            "a knock after the two minutes was still allowed to prompt"
        );
        assert_eq!(gate.remaining(now + PromptGate::WINDOW), None);
    }

    /// A machine that knocked before the window opened, and knocks again once it
    /// is open, gets its prompt. Remembering the refused knock would suppress it.
    #[test]
    fn a_knock_refused_before_pairing_opens_prompts_once_it_opens() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        assert_eq!(gate.admit("peer", now), Admit::Closed);
        gate.open(now + S / 2);
        assert_eq!(
            gate.admit("peer", now + S),
            Admit::Prompt,
            "the knock refused half a second before the window opened suppressed \
             the one after it"
        );
    }

    #[test]
    fn opening_again_restarts_the_two_minutes() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        gate.open(now + 100 * S);
        assert_eq!(gate.admit("peer", now + 200 * S), Admit::Prompt);
    }

    /// Remote unauthenticated memory growth. A peer generating a fresh
    /// self-signed certificate per dial offers a new fingerprint every time;
    /// without the pruning each would stay resident for the life of the daemon.
    #[test]
    fn a_flood_of_unknown_fingerprints_cannot_grow_memory_without_bound() {
        let mut recent = RecentPrompts::new();
        let now = Instant::now();
        for i in 0..50_000u32 {
            recent.seen_recently(&format!("fp-{i:08x}"), now);
        }
        assert!(
            recent.seen.len() < RecentPrompts::PRUNE_AT * 2,
            "50,000 distinct dials left {} entries resident: an unauthenticated \
             peer can still drive unbounded growth in the daemon holding the \
             private key",
            recent.seen.len()
        );
    }

    /// The bound must not cost the thing the map exists to do.
    #[test]
    fn a_peer_retrying_in_a_loop_still_raises_only_one_prompt() {
        let mut recent = RecentPrompts::new();
        let now = Instant::now();
        assert!(!recent.seen_recently("aa:bb:cc", now));
        for _ in 0..10_000 {
            assert!(
                recent.seen_recently("aa:bb:cc", now),
                "a peer retrying inside the window must not raise a second prompt"
            );
        }
    }

    /// A frontend that attaches while add device is open is shown what was
    /// admitted since the window opened, and nothing else (#114, #195).
    // LEDGER T7 | class B | 1 return value: PromptGate::replayable
    #[test]
    fn a_prompt_is_shown_again_only_inside_the_window_it_was_raised_in() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        assert!(
            gate.replayable(now + S, now + 30 * S),
            "a request admitted half a minute ago, with the window open, was not \
             shown to a frontend that attached since"
        );
        assert!(
            !gate.replayable(now + 100 * S, now + PromptGate::WINDOW + 5 * S),
            "a request 25 seconds old was shown again after the window closed"
        );
        gate.open(now + 200 * S);
        assert!(
            !gate.replayable(now + S, now + 201 * S),
            "opening add device again brought back a request from an earlier window"
        );
        assert!(gate.replayable(now + 200 * S, now + 201 * S));
    }

    /// A request from an earlier window is not replayed into a later one, even
    /// when it is under two minutes old. Someone who opens add device to pair
    /// one machine must not be shown another machine's request from before.
    // LEDGER T15 | class B | 1 return value: PromptGate::replayable
    #[test]
    fn a_request_from_an_earlier_window_is_not_replayed_in_a_new_one() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        let from_x = now + 100 * S;
        gate.open(now + 130 * S);
        assert!(
            !gate.replayable(from_x, now + 135 * S),
            "X's request from the earlier window was replayed in the new one"
        );
        assert!(gate.replayable(now + 131 * S, now + 135 * S));
    }

    /// Opening add device again while the window is still open starts a new
    /// window: what was admitted before the reopen is not replayed after it.
    // LEDGER T16 | class B | 1 return value: PromptGate::replayable
    #[test]
    fn reopening_add_device_inside_the_window_starts_a_new_one_for_replay() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        let from_x = now + 10 * S;
        assert!(gate.replayable(from_x, now + 20 * S));
        gate.open(now + 30 * S);
        assert!(
            !gate.replayable(from_x, now + 40 * S),
            "a request admitted before add device was reopened was replayed after it"
        );
        assert!(
            gate.replayable(now + 30 * S, now + 40 * S),
            "a request admitted the instant the window reopened was not replayed"
        );
    }

    /// Each admitted request is logged with its fingerprint, but a stranger
    /// offering a fresh key per dial cannot turn that into a line per dial.
    // LEDGER T8 | class B | 1 return value: PromptGate::note_admitted
    #[test]
    fn admitted_requests_are_each_logged_until_they_become_a_flood() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        assert_eq!(
            gate.note_admitted(now),
            Some(0),
            "the first request is logged"
        );
        assert_eq!(
            gate.note_admitted(now + S),
            Some(0),
            "a second machine a second later is logged too"
        );
        let logged = (0..1200u64)
            .filter(|i| {
                gate.note_admitted(now + 2 * S + Duration::from_millis(i * 5))
                    .is_some()
            })
            .count();
        assert!(
            logged <= AdmittedLog::LINES as usize,
            "1,200 admitted requests in six seconds wrote {logged} lines"
        );
        let next = gate
            .note_admitted(now + 11 * S)
            .expect("a new period logs again");
        assert_eq!(
            next as usize,
            1200 - logged,
            "the requests that were not logged were not counted"
        );
    }

    /// A flood of refusals becomes a handful of log lines, and none is lost
    /// from the count.
    #[test]
    fn refusals_are_summarised_not_logged_one_by_one() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        let lines: Vec<String> = (0..1200u32)
            .filter_map(|i| {
                gate.note_refusal(
                    &format!("fp-{i}"),
                    now + Duration::from_millis(i as u64 * 8),
                )
            })
            .collect();
        assert!(
            lines.len() <= 2,
            "1,200 refusals over under ten seconds wrote {} log lines",
            lines.len()
        );
        assert!(
            lines[0].contains("fp-0"),
            "the first refusal is logged at once"
        );
        let later = gate
            .note_refusal("fp-last", now + 11 * S)
            .expect("a line is due after ten seconds");
        assert!(
            later.contains("refused 1200 pairing requests"),
            "the summary lost count: {later}"
        );
    }
}

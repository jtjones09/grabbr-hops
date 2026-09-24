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
}

impl PromptGate {
    /// How long the window stays open after the add-device flow is opened.
    pub(crate) const WINDOW: Duration = Duration::from_secs(120);

    pub(crate) fn new() -> Self {
        Self {
            opened: None,
            recent: RecentPrompts::new(),
            refusals: RefusalLog::new(),
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

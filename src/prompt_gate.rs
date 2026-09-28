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
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
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
    /// Another machine at the same address prompted moments ago.
    Throttled,
}

pub(crate) struct PromptGate {
    opened: Option<Instant>,
    /// When the window last opened while it was closed. Opening it again
    /// while it is open moves `opened` and not this: the window never closed.
    open_since: Option<Instant>,
    recent: RecentPrompts,
    sources: RecentSources,
    refusals: Tally,
    throttled: Tally,
    admitted: AdmittedLog,
}

impl PromptGate {
    /// How long the window stays open after the add-device flow is opened.
    pub(crate) const WINDOW: Duration = Duration::from_secs(120);

    pub(crate) fn new() -> Self {
        Self {
            opened: None,
            open_since: None,
            recent: RecentPrompts::new(),
            sources: RecentSources::new(),
            refusals: Tally::new(),
            throttled: Tally::new(),
            admitted: AdmittedLog::new(),
        }
    }

    /// Someone opened the add-device flow on this machine.
    pub(crate) fn open(&mut self, now: Instant) {
        if self.remaining(now).is_none() {
            self.open_since = Some(now);
        }
        self.opened = Some(now);
    }

    /// How long the window has left, or `None` when it is closed.
    pub(crate) fn remaining(&self, now: Instant) -> Option<Duration> {
        let opened = self.opened?;
        Self::WINDOW
            .checked_sub(now.saturating_duration_since(opened))
            .filter(|left| !left.is_zero())
    }

    /// Whether `fingerprint`'s attempt may raise a prompt. `from` is the
    /// address an unsolicited knock came from; `None` for this machine's own
    /// dial, which nobody else can time.
    ///
    /// Only an admitted attempt is remembered for the repeat check. A knock
    /// refused while the window was closed must not suppress the one that
    /// arrives just after it opens, or the person who opened it waits for a
    /// prompt that never comes.
    ///
    /// A knock is also refused while another machine at its address prompted
    /// less than [`RecentSources::WINDOW`] ago. The fingerprint is the
    /// knocker's own choice, so a stranger minting a key per dial passed the
    /// repeat check every time and raised a prompt per dial, measured at 120
    /// a second from one host (#101). An address costs it something.
    pub(crate) fn admit(&mut self, fingerprint: &str, from: Option<IpAddr>, now: Instant) -> Admit {
        if self.remaining(now).is_none() {
            return Admit::Closed;
        }
        let from = from.map(source_of);
        if from.is_some_and(|ip| self.sources.taken_by_another(ip, fingerprint, now)) {
            return Admit::Throttled;
        }
        if self.recent.seen_recently(fingerprint, now) {
            return Admit::Repeat;
        }
        if let Some(ip) = from {
            self.sources.record(ip, fingerprint, now);
        }
        Admit::Prompt
    }

    /// Record a refusal, and return a summary when one is due.
    ///
    /// A stranger generating a fresh key per dial offers a new fingerprint every
    /// time, measured at 120 a second from one host. One log line, or one line
    /// in the app, per refusal would let anyone on the network fill both, so
    /// refusals are counted and summarised at most once per [`Tally::EVERY`].
    pub(crate) fn note_refusal(
        &mut self,
        fingerprint: &str,
        from: Option<SocketAddr>,
        now: Instant,
    ) -> Option<Refused> {
        self.refusals.note(now).map(|count| Refused {
            count,
            fingerprint: fingerprint.to_owned(),
            from,
            paired: None,
        })
    }

    /// Record a knock held back by [`Admit::Throttled`], and return a line to
    /// log when one is due.
    pub(crate) fn note_throttled(
        &mut self,
        from: Option<SocketAddr>,
        now: Instant,
    ) -> Option<String> {
        let count = self.throttled.note(now)?;
        let from = from.map_or_else(|| "an unknown address".to_owned(), |a| a.ip().to_string());
        Some(format!(
            "held back {count} pairing request(s), the latest from {from}: another machine \
             at that address was shown a prompt less than {} s ago",
            RecentSources::WINDOW.as_secs()
        ))
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

    /// Whether the window has stayed open from `admitted` until `now`, so a
    /// prompt admitted then may still be approved (#107).
    ///
    /// A prompt lapses when the window closes, and opening add device again
    /// afterwards does not bring it back. Opening it again while the window
    /// is still open closes nothing, so a prompt already on screen can still
    /// be answered, though a reopen ends its being shown again to a frontend
    /// that attaches later ([`Self::replayable`]).
    pub(crate) fn open_throughout(&self, admitted: Instant, now: Instant) -> bool {
        self.remaining(now).is_some() && self.open_since.is_some_and(|since| admitted >= since)
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
    /// Records it only when it raises one: a refresh on every knock kept a
    /// machine that knocks every second suppressed for good, so its card went
    /// stale on screen while it was still asking, and a machine added again
    /// soon after an attempt ended was never asked about at all.
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
        match self.seen.get(fingerprint) {
            Some(at) if now.saturating_duration_since(*at) < Self::WINDOW => true,
            _ => {
                self.seen.insert(fingerprint.to_owned(), now);
                false
            }
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

/// What refusing knocks came to since the last summary.
pub(crate) struct Refused {
    /// Knocks refused since the last summary, the latest included.
    pub(crate) count: u32,
    /// The latest knock's certificate.
    pub(crate) fingerprint: String,
    /// Where the latest knock came from.
    pub(crate) from: Option<SocketAddr>,
    /// What this machine holds for the latest knock's machine, when it holds
    /// a pairing with it: set by the caller, which holds the trust store and
    /// the devices.
    pub(crate) paired: Option<PairedHere>,
}

/// A refused machine this machine is paired with, in the terms the app's
/// line uses.
pub(crate) struct PairedHere {
    /// The name it was paired under.
    pub(crate) name: String,
    /// This machine may control it.
    pub(crate) controlled_from_here: bool,
    /// Every device here for it is switched off.
    pub(crate) switched_off: bool,
}

impl Refused {
    /// The daemon log's line, which names the certificate.
    pub(crate) fn log_line(&self) -> String {
        let at = self.from.map(|a| format!(" at {a}")).unwrap_or_default();
        if self.count == 1 {
            format!(
                "refused a pairing request from {}{at}: add device is not open on this machine",
                self.fingerprint
            )
        } else {
            format!(
                "refused {} pairing requests, the latest from {}{at}: add device is not open \
                 on this machine",
                self.count, self.fingerprint
            )
        }
    }

    /// The app's line: activity, not an error. Nobody at this machine asked
    /// for it, and a stranger can cause it whenever it likes (#150).
    ///
    /// Worded to hold for every machine refused here: a stranger and one
    /// this machine has removed. A machine paired with this one is named,
    /// and not told to open add device, which does nothing for it; its
    /// device here being switched off is said, since that is what the person
    /// here chose.
    pub(crate) fn notice(&self) -> String {
        if let Some(paired) = &self.paired {
            return paired.notice(self.count);
        }
        let from = self
            .from
            .map_or_else(|| "a machine".to_owned(), |a| a.ip().to_string());
        if self.count == 1 {
            format!(
                "Refused a connection from {from}: it is not paired to control this machine, \
                 and add device is not open here."
            )
        } else {
            format!(
                "Refused {} connections from machines not paired to control this one, the \
                 latest from {from}: add device is not open here.",
                self.count
            )
        }
    }
}

impl PairedHere {
    fn notice(&self, count: u32) -> String {
        let name = &self.name;
        let refused = if count == 1 {
            format!("Refused a connection from {name}")
        } else {
            format!("Refused {count} connections, the latest from {name}")
        };
        let why = if self.controlled_from_here {
            "this machine controls it, and it may not control this one"
        } else {
            "its pairing does not let it control this machine"
        };
        let off = if self.switched_off {
            format!(" Its device here is switched off; switch {name} on to use it.")
        } else {
            String::new()
        };
        format!("{refused}: {why}.{off}")
    }
}

/// Counts events between summaries, one summary per [`Self::EVERY`] at most.
struct Tally {
    last: Option<Instant>,
    since: u32,
}

impl Tally {
    const EVERY: Duration = Duration::from_secs(10);

    fn new() -> Self {
        Self {
            last: None,
            since: 0,
        }
    }

    /// Count one. When a summary is due, how many it covers, this one
    /// included.
    fn note(&mut self, now: Instant) -> Option<u32> {
        self.since = self.since.saturating_add(1);
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < Self::EVERY)
        {
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.since))
    }
}

/// The address a knock is counted against. IPv6 by its /64: one host on a
/// network is handed a whole /64 and can knock from any address in it.
fn source_of(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// Which machine each address last raised a prompt for, and when.
///
/// Anyone on the network can add to this, one entry per address, so entries
/// older than the window are dropped and the map is bounded.
struct RecentSources {
    seen: HashMap<IpAddr, (String, Instant)>,
}

impl RecentSources {
    /// How long an address that raised a prompt holds back other machines'
    /// knocks from it.
    const WINDOW: Duration = Duration::from_secs(10);

    /// Prune once the map is larger than a real network explains.
    const PRUNE_AT: usize = 256;

    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// Whether a machine other than `fingerprint` raised a prompt from `ip`
    /// within the window.
    fn taken_by_another(&self, ip: IpAddr, fingerprint: &str, now: Instant) -> bool {
        self.seen.get(&ip).is_some_and(|(by, at)| {
            by != fingerprint && now.saturating_duration_since(*at) < Self::WINDOW
        })
    }

    fn record(&mut self, ip: IpAddr, fingerprint: &str, now: Instant) {
        if self.seen.len() >= Self::PRUNE_AT {
            self.seen
                .retain(|_, (_, at)| now.saturating_duration_since(*at) < Self::WINDOW);
            // Every address still here prompted within the window: hundreds of
            // addresses at once is a flood, not a network. Bounded memory comes
            // first; each of those addresses can prompt again.
            if self.seen.len() >= Self::PRUNE_AT {
                self.seen.clear();
            }
        }
        self.seen.insert(ip, (fingerprint.to_owned(), now));
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
        assert_eq!(gate.admit("stranger", None, now), Admit::Closed);
    }

    #[test]
    fn a_knock_while_the_window_is_open_prompts_once() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        assert_eq!(gate.admit("peer", None, now + S), Admit::Prompt);
        assert_eq!(
            gate.admit("peer", None, now + S),
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
            gate.admit("early", None, now + PromptGate::WINDOW - S),
            Admit::Prompt
        );
        assert_eq!(
            gate.admit("late", None, now + PromptGate::WINDOW),
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
        assert_eq!(gate.admit("peer", None, now), Admit::Closed);
        gate.open(now + S / 2);
        assert_eq!(
            gate.admit("peer", None, now + S),
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
        assert_eq!(gate.admit("peer", None, now + 200 * S), Admit::Prompt);
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

    // LEDGER G-17 | class B | 1 return value: RecentPrompts::seen_recently
    /// A machine that keeps knocking once a second, as the add dial does, is
    /// prompted for again once the window since its last prompt has passed:
    /// its card stays live while it asks, and adding it again soon after an
    /// attempt ended still asks the person here (#167).
    #[test]
    fn a_peer_still_knocking_is_prompted_again_after_the_window() {
        let mut recent = RecentPrompts::new();
        let t0 = Instant::now();
        assert!(!recent.seen_recently("aa:bb:cc", t0));
        let mut prompted = 0;
        for s in 1..=6 {
            if !recent.seen_recently("aa:bb:cc", t0 + Duration::from_secs(s)) {
                prompted += 1;
            }
        }
        assert!(
            prompted >= 2,
            "a machine knocking every second for six seconds was prompted for {prompted} \
             more time(s): the suppression never lets it through again"
        );
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
                    None,
                    now + Duration::from_millis(i as u64 * 8),
                )
            })
            .map(|r| r.log_line())
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
            .note_refusal("fp-last", None, now + 11 * S)
            .expect("a line is due after ten seconds")
            .log_line();
        assert!(
            later.contains("refused 1200 pairing requests"),
            "the summary lost count: {later}"
        );
    }

    fn at(ip: &str) -> Option<IpAddr> {
        Some(ip.parse().expect("an address"))
    }

    /// A stranger minting a key per knock passes the repeat check every time.
    /// Counted by its address, it raises one prompt per window (#101).
    // LEDGER T2371 | class B | 1 return value: PromptGate::admit
    #[test]
    fn a_stranger_minting_a_key_per_knock_prompts_once_per_address_window() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        let prompts = (0..1000u64)
            .filter(|i| {
                gate.admit(
                    &format!("fp-{i}"),
                    at("192.0.2.7"),
                    now + Duration::from_millis(i * 5),
                ) == Admit::Prompt
            })
            .count();
        assert_eq!(
            prompts, 1,
            "1,000 knocks with fresh keys from one address in five seconds raised \
             {prompts} prompts"
        );
        assert_eq!(
            gate.admit("fp-later", at("192.0.2.7"), now + RecentSources::WINDOW + S),
            Admit::Prompt,
            "the address may prompt again once the window has passed"
        );
    }

    /// The limit delays a second machine behind the same address; it must not
    /// shut it out. A machine being added knocks every second, and a throttled
    /// knock must not count as a prompt shown, or every later knock would be
    /// a repeat of a prompt nobody saw.
    #[test]
    fn a_second_machine_at_the_same_address_prompts_once_the_window_passes() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        assert_eq!(gate.admit("desk", at("192.0.2.7"), now), Admit::Prompt);
        let mut second = None;
        for i in 1..=15u32 {
            let when = now + S * i;
            if gate.admit("laptop", at("192.0.2.7"), when) == Admit::Prompt {
                second = Some(when);
                break;
            }
        }
        let second = second.expect("the second machine never raised a prompt");
        assert!(
            second.duration_since(now) >= RecentSources::WINDOW,
            "the second machine prompted {:?} after the first",
            second.duration_since(now)
        );
    }

    /// One machine retrying is still a repeat, and our own dial is never
    /// counted against an address.
    #[test]
    fn the_limit_leaves_repeats_and_our_own_dials_alone() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        assert_eq!(gate.admit("desk", at("192.0.2.7"), now), Admit::Prompt);
        assert_eq!(gate.admit("desk", at("192.0.2.7"), now + S), Admit::Repeat);
        assert_eq!(gate.admit("receiver", None, now + S), Admit::Prompt);
        assert_eq!(gate.admit("other", None, now + S), Admit::Prompt);
    }

    /// An IPv6 host holds a whole /64; it is one source. An IPv4 address
    /// written as IPv6 is the IPv4 address.
    #[test]
    fn a_source_is_an_ipv4_address_or_an_ipv6_64() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        assert_eq!(gate.admit("a", at("2001:db8:1:2::10"), now), Admit::Prompt);
        assert_eq!(
            gate.admit("b", at("2001:db8:1:2::99"), now),
            Admit::Throttled,
            "another address in the same /64 is the same source"
        );
        assert_eq!(gate.admit("c", at("2001:db8:1:3::10"), now), Admit::Prompt);
        assert_eq!(gate.admit("d", at("192.0.2.9"), now), Admit::Prompt);
        assert_eq!(
            gate.admit("e", at("::ffff:192.0.2.9"), now),
            Admit::Throttled,
            "an IPv4-mapped address is the IPv4 address"
        );
    }

    /// Each address costs an entry, and addresses are cheap on a network a
    /// stranger shares.
    #[test]
    fn a_flood_of_addresses_cannot_grow_memory_without_bound() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        gate.open(now);
        for i in 0..50_000u32 {
            // Each in its own /64 of the documentation prefix.
            let ip = IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                (i >> 16) as u16,
                i as u16,
                0,
                0,
                0,
                1,
            ));
            gate.admit(&format!("fp-{i}"), Some(ip), now);
        }
        assert!(
            gate.sources.seen.len() < RecentSources::PRUNE_AT * 2,
            "50,000 addresses left {} entries resident",
            gate.sources.seen.len()
        );
    }

    /// The app's line for refused knocks names where they came from and says
    /// why, without the certificate a stranger chose.
    #[test]
    fn a_refusal_summary_says_where_and_why() {
        let mut gate = PromptGate::new();
        let now = Instant::now();
        let from: SocketAddr = "192.0.2.7:50123".parse().expect("addr");
        let first = gate
            .note_refusal("aa:bb", Some(from), now)
            .expect("the first refusal is summarised at once");
        assert_eq!(
            first.notice(),
            "Refused a connection from 192.0.2.7: it is not paired to control this \
             machine, and add device is not open here."
        );
        assert!(first.log_line().contains("aa:bb") && first.log_line().contains("192.0.2.7"));
        for i in 0..5u32 {
            assert!(gate.note_refusal("x", Some(from), now + S * i).is_none() || i == 0);
        }
        let later = gate
            .note_refusal("cc:dd", Some(from), now + 11 * S)
            .expect("a summary is due");
        assert!(
            later.notice().starts_with("Refused 6 connections"),
            "{}",
            later.notice()
        );
    }
}

//! Picking up a macOS permission granted while the daemon runs (#221).
//!
//! macOS checks Accessibility and Input Monitoring when capture or emulation
//! is created, and a daemon whose check failed then waits for the user to ask
//! again. A grant made in System Settings may not reach a process that is
//! already running, and the app does not restart a daemon of its own build.
//! So while capture or emulation is not running, the daemon asks the same
//! silent checks the backends use, every few seconds and off its loop. When a
//! side that was missing a permission has everything it needs, a daemon that
//! launchd starts again after a failure exits unsuccessfully, and its launchd
//! job starts a fresh process, which sees the grant. Any other daemon says
//! that the permission is granted and takes effect once hops restarts.
//!
//! Each side is settled on its own. A Mac that is only ever controlled never
//! grants Input Monitoring, which only capture needs, and emulation must still
//! start once Accessibility is granted. The side still missing a permission
//! reads as missing on the fresh process's first check, so the exit does not
//! repeat.
//!
//! While emulation runs, the same check asks whether Accessibility is still
//! granted (#240). Posting events without it fails silently, so a Mac that is
//! only ever controlled would otherwise read as working with the grant gone.
//! Capture is not watched here while it runs: its backend asks the same
//! question on its own and takes its event taps down before it says so.
//!
//! Accessibility is asked through the process's tap gate
//! ([`input_event::accessibility::Gate`]). Until the user clicks enable
//! input or open settings, a daemon that `AXIsProcessTrusted` says lacks it
//! creates no tap and so never sees a grant made while it runs (#243, #169).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use input_event::accessibility::{Gate, REFUSALS_BEFORE_REVOKED};
use tokio::task::JoinHandle;
use tokio::time::{Interval, MissedTickBehavior};

/// A macOS permission capture or emulation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// Privacy & Security → Accessibility (`AXIsProcessTrusted`).
    Accessibility,
    /// Privacy & Security → Input Monitoring, to read input
    /// (`CGPreflightListenEventAccess`).
    InputMonitoring,
    /// Posting input events, granted with Accessibility
    /// (`CGPreflightPostEventAccess`).
    PostEvents,
}

impl Permission {
    /// The System Settings list that grants it, as this Mac names it.
    fn pane(self) -> &'static str {
        match self {
            Self::Accessibility | Self::PostEvents => input_event::settings_pane::accessibility(),
            Self::InputMonitoring => "Input Monitoring",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accessibility | Self::InputMonitoring => f.write_str(self.pane()),
            Self::PostEvents => write!(f, "{} (to post input)", self.pane()),
        }
    }
}

/// The half of the daemon that could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    Capture,
    Emulation,
}

impl Side {
    /// The permissions this side's macOS backend checks before it starts.
    fn needs(self) -> &'static [Permission] {
        match self {
            Self::Capture => &[Permission::Accessibility, Permission::InputMonitoring],
            Self::Emulation => &[Permission::Accessibility, Permission::PostEvents],
        }
    }

    /// The permissions checked while this side runs, whose loss stops it.
    /// Accessibility only, by the probe tap: the preflight checks can keep
    /// their first answer in a running process, and posting events is
    /// granted with Accessibility. Capture checks its own (see the module).
    fn watched_while_running(self) -> &'static [Permission] {
        match self {
            Self::Capture => &[],
            Self::Emulation => &[Permission::Accessibility],
        }
    }
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Capture => "input capture",
            Self::Emulation => "input emulation",
        })
    }
}

/// Asks whether a permission is granted, without raising a prompt.
pub type Probe = Arc<dyn Fn(Permission) -> bool + Send + Sync>;

/// Whether launchd starts this process again after an unsuccessful exit.
pub type Restarts = Arc<dyn Fn() -> bool + Send + Sync>;

/// What the daemon does once a side has the permissions it was missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfterGrant {
    /// Exit unsuccessfully: launchd starts a fresh process, which has them.
    Exit(Vec<Permission>),
    /// Keep running, and say that they take effect once hops restarts:
    /// nothing would start this process again.
    Tell(Vec<Permission>),
}

impl AfterGrant {
    /// What was granted, as the System Settings lists that grant it, each
    /// named once: "Accessibility and Input Monitoring".
    pub fn granted(&self) -> String {
        let (Self::Exit(granted) | Self::Tell(granted)) = self;
        named(granted)
    }
}

/// `permissions` as the System Settings lists that grant them, each named
/// once: "Accessibility and Input Monitoring".
pub fn named(permissions: &[Permission]) -> String {
    let mut panes: Vec<&str> = Vec::new();
    for pane in permissions.iter().map(|p| p.pane()) {
        if !panes.contains(&pane) {
            panes.push(pane);
        }
    }
    match panes.as_slice() {
        [] => "the permission".to_string(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// What a check found that the daemon must act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A side that was missing a permission has every one it needs.
    Granted(AfterGrant),
    /// macOS took `missing` from `side` while it ran: it must stop, and say
    /// what to grant. The side is watched for the grant from here on.
    Revoked {
        side: Side,
        missing: Vec<Permission>,
    },
}

/// What one check found: each permission asked, and whether it is granted;
/// and whether launchd would restart this process, asked only when a side
/// that was missing something has it all.
type Checked = (BTreeMap<Permission, bool>, bool);

/// Watches the permissions of each side that is not running, and of each
/// that runs for what it would lose (see the module).
pub struct PermissionWatch {
    probe: Probe,
    restarts: Restarts,
    every: Duration,
    /// Sides that are not running, each with what the checks found it
    /// missing: `None` until a check has run since it stopped. A side found
    /// missing nothing stopped for another reason, and is not watched.
    waiting: BTreeMap<Side, Option<BTreeSet<Permission>>>,
    /// Sides that run through a backend that needs a permission, each
    /// watched for [`Side::watched_while_running`], with how many checks
    /// in a row have found one gone.
    running: BTreeMap<Side, u32>,
    /// What a check found and the daemon has not yet been handed.
    found: VecDeque<Change>,
    ticks: Option<Interval>,
    /// A check running off the loop, kept across a `select!` that drops
    /// [`Self::changed`] before it resolves.
    pending: Option<JoinHandle<Checked>>,
    /// Whether this system has such permissions at all.
    enabled: bool,
}

/// How often a missing permission is checked again.
const CHECK_EVERY: Duration = Duration::from_secs(2);

impl PermissionWatch {
    /// A watch that asks `probe`, and `restarts` once a side has what it was
    /// missing, every `every`. Nothing is watched until a side stops.
    pub fn new(probe: Probe, restarts: Restarts, every: Duration) -> Self {
        Self {
            probe,
            restarts,
            every,
            waiting: BTreeMap::new(),
            running: BTreeMap::new(),
            found: VecDeque::new(),
            ticks: None,
            pending: None,
            enabled: true,
        }
    }

    /// The watch a daemon starts with: neither side runs yet, so both are
    /// watched until each says it runs. A backend that cannot be created
    /// never says it stopped, so a daemon started without a permission is
    /// watched only because of this.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn at_daemon_start(probe: Probe, restarts: Restarts, every: Duration) -> Self {
        let mut watch = Self::new(probe, restarts, every);
        watch.stopped(Side::Capture);
        watch.stopped(Side::Emulation);
        watch
    }

    /// This machine's: the macOS checks through `gate` and launchd, as a
    /// daemon starts. Elsewhere there are no such permissions, and nothing
    /// is ever watched.
    pub fn of_this_machine(gate: &'static Gate) -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::at_daemon_start(
                Arc::new(move |p| tcc::granted(gate, p)),
                Arc::new(crate::daemon_start::launchd_restarts_this_process),
                CHECK_EVERY,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = gate;
            Self {
                enabled: false,
                ..Self::new(Arc::new(|_| true), Arc::new(|| false), CHECK_EVERY)
            }
        }
    }

    /// `side` is not running: watch what it needs.
    pub fn stopped(&mut self, side: Side) {
        self.running.remove(&side);
        if self.enabled {
            self.waiting.entry(side).or_insert(None);
        }
    }

    /// `side` is running. Through a backend that `needs_permissions`, it
    /// is watched for what it would lose; one that needs none, such as
    /// `dummy` chosen on purpose, has nothing to lose and is not watched.
    pub fn started(&mut self, side: Side, needs_permissions: bool) {
        self.waiting.remove(&side);
        self.running.remove(&side);
        if self.enabled && needs_permissions {
            self.running.insert(side, 0);
        }
        if !self.watching() {
            self.pending = None;
        }
    }

    /// Whether any check has a side to ask about.
    fn watching(&self) -> bool {
        !self.waiting.is_empty()
            || self
                .running
                .keys()
                .any(|side| !side.watched_while_running().is_empty())
    }

    /// Resolves once a side that was missing a permission has every one it
    /// needs, or once a side that runs has lost one, with what to do about
    /// it. Never resolves while no side is watched, or while nothing
    /// changes.
    ///
    /// The checks run on a blocking thread, so a slow answer from the
    /// system never holds the daemon's loop. Safe to drop at any await.
    pub async fn changed(&mut self) -> Change {
        loop {
            if let Some(change) = self.found.pop_front() {
                return change;
            }
            if !self.watching() {
                return std::future::pending().await;
            }
            if self.pending.is_none() {
                let every = self.every;
                let ticks = self.ticks.get_or_insert_with(|| {
                    let mut ticks = tokio::time::interval(every);
                    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
                    ticks
                });
                ticks.tick().await;
                let (probe, restarts) = (self.probe.clone(), self.restarts.clone());
                let needed: BTreeSet<Permission> = self
                    .waiting
                    .keys()
                    .flat_map(|side| side.needs().iter().copied())
                    .chain(
                        self.running
                            .keys()
                            .flat_map(|side| side.watched_while_running().iter().copied()),
                    )
                    .collect();
                // The sides a grant can complete: those seen missing something.
                let armed: Vec<&'static [Permission]> = self
                    .waiting
                    .iter()
                    .filter(|(_, missing)| missing.is_some())
                    .map(|(side, _)| side.needs())
                    .collect();
                self.pending = Some(tokio::task::spawn_blocking(move || {
                    let answers: BTreeMap<Permission, bool> =
                        needed.into_iter().map(|p| (p, probe(p))).collect();
                    let complete = armed
                        .iter()
                        .any(|needs| needs.iter().all(|p| answers.get(p) == Some(&true)));
                    // Asked only when about to act: it runs `launchctl`.
                    (answers, complete && restarts())
                }));
            }
            let Some(check) = self.pending.as_mut() else {
                continue;
            };
            let checked = check.await;
            self.pending = None;
            // A check that panicked is tried again at the next tick.
            if let Ok((answers, restarts)) = checked {
                self.revoke(&answers);
                if let Some(after) = self.settle(&answers, restarts) {
                    self.found.push_back(Change::Granted(after));
                }
            }
        }
    }

    /// Each running side that [`REFUSALS_BEFORE_REVOKED`] checks in a row
    /// found has lost a permission stops being watched as running, and
    /// waits for the grant instead. A check that finds it all there starts
    /// the count again.
    fn revoke(&mut self, answers: &BTreeMap<Permission, bool>) {
        let running: Vec<Side> = self.running.keys().copied().collect();
        for side in running {
            let missing: Vec<Permission> = side
                .watched_while_running()
                .iter()
                .copied()
                .filter(|p| answers.get(p) == Some(&false))
                .collect();
            let Some(refused) = self.running.get_mut(&side) else {
                continue;
            };
            if missing.is_empty() {
                *refused = 0;
                continue;
            }
            *refused += 1;
            if *refused < REFUSALS_BEFORE_REVOKED {
                log::debug!(
                    "permission watch: {side} found without {}; acted on if the next \
                     check finds the same",
                    named(&missing)
                );
                continue;
            }
            self.running.remove(&side);
            self.waiting
                .insert(side, Some(missing.iter().copied().collect()));
            self.found.push_back(Change::Revoked { side, missing });
        }
    }

    /// Fold one check into each waiting side; `Some` once a side that was
    /// missing something has all it needs.
    fn settle(
        &mut self,
        answers: &BTreeMap<Permission, bool>,
        restarts: bool,
    ) -> Option<AfterGrant> {
        let mut granted = BTreeSet::new();
        let sides: Vec<Side> = self.waiting.keys().copied().collect();
        for side in sides {
            // A side that stopped after the check began was not asked about.
            let Some(missing) = side
                .needs()
                .iter()
                .map(|p| answers.get(p).map(|&ok| (!ok).then_some(*p)))
                .collect::<Option<Vec<Option<Permission>>>>()
            else {
                continue;
            };
            let missing: BTreeSet<Permission> = missing.into_iter().flatten().collect();
            match (
                self.waiting.get(&side).cloned().flatten(),
                missing.is_empty(),
            ) {
                // It stopped with everything it needs: for another reason,
                // which no grant mends.
                (None, true) => {
                    self.waiting.remove(&side);
                }
                (None, false) => {
                    log::info!(
                        "missing macOS permission(s) for {side}: {}; checking again every \
                         {} s until granted",
                        missing
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", "),
                        self.every.as_secs_f64()
                    );
                    self.waiting.insert(side, Some(missing));
                }
                (Some(was), true) => {
                    granted.extend(was);
                    self.waiting.remove(&side);
                }
                (Some(_), false) => {
                    self.waiting.insert(side, Some(missing));
                }
            }
        }
        if granted.is_empty() {
            return None;
        }
        let granted = granted.into_iter().collect();
        Some(if restarts {
            AfterGrant::Exit(granted)
        } else {
            AfterGrant::Tell(granted)
        })
    }
}

/// Whether `permission` is granted, from macOS's preflight checks and the
/// probe tap, which asks for no events (`tap` creates an active tap for the
/// events in a mask and says whether macOS allowed it).
///
/// `AXIsProcessTrusted` and the `CGPreflight*` checks can keep their first
/// answer for the life of a running process on macOS 27, so a grant made in
/// System Settings went unseen until a manual restart (#240). Whether
/// macOS lets the process create an active event tap is asked afresh each
/// time, and it does only with Accessibility. So it answers Accessibility
/// once `gate` is open, and posting events, which Accessibility grants, is
/// granted when either says so. While `gate` is closed no tap is created
/// and the preflight check answers Accessibility (#243). Input Monitoring
/// has no such probe: a listen-only tap is let through by Accessibility too.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn answer(
    permission: Permission,
    gate: &Gate,
    preflight: impl Fn(Permission) -> bool,
    tap: impl Fn(u64) -> bool,
) -> bool {
    let probe = || {
        gate.accessibility(
            "permission watch",
            || preflight(Permission::Accessibility),
            &tap,
        )
    };
    match permission {
        Permission::Accessibility => probe(),
        Permission::PostEvents => preflight(Permission::PostEvents) || probe(),
        Permission::InputMonitoring => preflight(Permission::InputMonitoring),
    }
}

/// The silent checks the capture and emulation backends make.
#[cfg(target_os = "macos")]
mod tcc {
    use super::Permission;
    use input_event::accessibility::{self, Gate, LastAnswer};

    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        // Apple declares this `Boolean` (u8), not C `_Bool`.
        fn AXIsProcessTrusted() -> u8;
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGPreflightListenEventAccess() -> bool;
        fn CGPreflightPostEventAccess() -> bool;
    }

    /// What the preflight checks say. None raises a prompt.
    fn preflight(permission: Permission) -> bool {
        // SAFETY: each takes no arguments and only reads this process's
        // permission.
        unsafe {
            match permission {
                Permission::Accessibility => AXIsProcessTrusted() != 0,
                Permission::InputMonitoring => CGPreflightListenEventAccess(),
                Permission::PostEvents => CGPreflightPostEventAccess(),
            }
        }
    }

    /// Logged when its answer changes, not on every check: emulation
    /// that runs is checked every few seconds for as long as it runs.
    pub(super) fn granted(gate: &Gate, permission: Permission) -> bool {
        static ACCESSIBILITY: LastAnswer = LastAnswer::new();
        static INPUT_MONITORING: LastAnswer = LastAnswer::new();
        static POST_EVENTS: LastAnswer = LastAnswer::new();
        let last = match permission {
            Permission::Accessibility => &ACCESSIBILITY,
            Permission::InputMonitoring => &INPUT_MONITORING,
            Permission::PostEvents => &POST_EVENTS,
        };
        let granted = super::answer(
            permission,
            gate,
            preflight,
            accessibility::create_active_tap,
        );
        if last.changed(granted) {
            log::debug!(
                "permission watch: {permission:?} {}; preflight says {}",
                if granted { "granted" } else { "missing" },
                preflight(permission)
            );
        }
        granted
    }
}

#[cfg(test)]
mod a_grant_made_while_the_daemon_runs {
    //! The probe and launchd are stand-ins. What must happen is waited for
    //! with a generous deadline; what must not is watched for a window that
    //! holds many checks.

    use super::{AfterGrant, Change, Permission, PermissionWatch, Side, answer};
    use input_event::accessibility::Gate;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A gate the user has opened, so the probe tap may be created.
    fn consented() -> &'static Gate {
        let gate: &'static Gate = Box::leak(Box::new(Gate::new()));
        gate.consent();
        gate
    }

    /// A system where `denied` are missing until `grant` is set.
    struct System {
        denied: Mutex<Vec<Permission>>,
        asked: AtomicUsize,
    }

    impl System {
        fn new(denied: &[Permission]) -> Arc<Self> {
            Arc::new(Self {
                denied: Mutex::new(denied.to_vec()),
                asked: AtomicUsize::new(0),
            })
        }
        fn grant(&self) {
            self.denied.lock().expect("lock").clear();
        }
        fn grant_only(&self, permission: Permission) {
            self.denied
                .lock()
                .expect("lock")
                .retain(|&p| p != permission);
        }
    }

    fn watch(system: &Arc<System>, restarts: bool) -> PermissionWatch {
        let probe = system.clone();
        PermissionWatch::new(
            Arc::new(move |p| {
                probe.asked.fetch_add(1, Ordering::SeqCst);
                !probe.denied.lock().expect("lock").contains(&p)
            }),
            Arc::new(move || restarts),
            EVERY,
        )
    }

    const EVERY: Duration = Duration::from_millis(20);
    const DEADLINE: Duration = Duration::from_secs(30);
    /// Long enough for ten checks or more.
    const NOTHING_FOR: Duration = Duration::from_millis(300);

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    // LEDGER T2232 | class B | 1 return value of PermissionWatch::granted
    #[test]
    fn a_missing_permission_granted_later_exits_only_when_launchd_restarts_the_daemon() {
        for (restarts, expected) in [
            (true, AfterGrant::Exit(vec![Permission::Accessibility])),
            (false, AfterGrant::Tell(vec![Permission::Accessibility])),
        ] {
            let system = System::new(&[Permission::Accessibility]);
            let mut watch = watch(&system, restarts);
            watch.stopped(Side::Emulation);
            let got = runtime().block_on(async {
                let granter = system.clone();
                // Granted once the watch has seen it missing a few times.
                tokio::spawn(async move {
                    while granter.asked.load(Ordering::SeqCst) < 6 {
                        tokio::time::sleep(EVERY).await;
                    }
                    granter.grant();
                });
                tokio::time::timeout(DEADLINE, watch.changed()).await
            });
            assert_eq!(
                got,
                Ok(Change::Granted(expected.clone())),
                "Accessibility was granted after emulation failed for want of it \
                 (launchd restarts the daemon: {restarts}). The daemon must exit \
                 for launchd to start it with the grant, and must not exit when \
                 nothing would start it again."
            );
        }
    }

    /// Each side is settled on its own: a Mac that is only ever controlled
    /// never grants Input Monitoring, which only capture needs, and emulation
    /// must start once Accessibility is granted.
    // LEDGER T2240 | class B | 1 return value of PermissionWatch::granted
    #[test]
    fn a_side_that_has_all_it_needs_restarts_the_daemon_while_the_other_still_lacks_one() {
        let system = System::new(&[Permission::Accessibility, Permission::InputMonitoring]);
        let mut both = watch(&system, true);
        both.stopped(Side::Capture);
        both.stopped(Side::Emulation);
        let got = runtime().block_on(async {
            let granter = system.clone();
            tokio::spawn(async move {
                while granter.asked.load(Ordering::SeqCst) < 12 {
                    tokio::time::sleep(EVERY).await;
                }
                granter.grant_only(Permission::Accessibility);
            });
            tokio::time::timeout(DEADLINE, both.changed()).await
        });
        assert_eq!(
            got,
            Ok(Change::Granted(AfterGrant::Exit(vec![
                Permission::Accessibility
            ]))),
            "Accessibility, all emulation needs, was granted while Input Monitoring, \
             which only capture needs, stayed off. Emulation must start with it; \
             waiting for both leaves a controlled-only Mac without input until \
             someone clicks enable input or logs in again."
        );

        // The fresh process: capture still lacks Input Monitoring, and that
        // alone never ends the daemon again.
        let fresh = System::new(&[Permission::InputMonitoring]);
        let mut again = watch(&fresh, true);
        again.stopped(Side::Capture);
        let after =
            runtime().block_on(async { tokio::time::timeout(NOTHING_FOR, again.changed()).await });
        assert!(
            fresh.asked.load(Ordering::SeqCst) > 0 && after.is_err(),
            "a side that still lacks a permission after the restart ended the \
             daemon again: {after:?}"
        );
    }

    /// The watch the daemon is built with. On a Mac it watches both sides
    /// from the start: a backend macOS refuses is never created, so neither
    /// side would ever say it stopped. Elsewhere it watches nothing, ever.
    // LEDGER T2255 | class B | 6 state of PermissionWatch::of_this_machine()
    #[test]
    fn this_machines_watch_waits_on_both_sides_from_the_start_only_on_a_mac() {
        let mut watch = PermissionWatch::of_this_machine(Box::leak(Box::new(Gate::new())));
        let at_start: Vec<Side> = watch.waiting.keys().copied().collect();
        watch.stopped(Side::Capture);
        let after_a_stop: Vec<Side> = watch.waiting.keys().copied().collect();
        let expected = if cfg!(target_os = "macos") {
            vec![Side::Capture, Side::Emulation]
        } else {
            vec![]
        };
        assert_eq!(
            (at_start, after_a_stop),
            (expected.clone(), expected),
            "(watched as the daemon starts, watched after capture stops). On a Mac \
             a daemon started without a permission has no backend to say a side \
             stopped, so both must be watched from the start; elsewhere there is \
             no such permission to wait for."
        );
    }

    /// The words name each System Settings list once.
    // LEDGER T2241 | class B | 1 return value of AfterGrant::granted
    #[test]
    fn what_was_granted_is_named_as_the_settings_that_grant_it() {
        use Permission::{Accessibility, InputMonitoring, PostEvents};
        let pane = input_event::settings_pane::accessibility();
        for (granted, said) in [
            (vec![Accessibility], pane.to_string()),
            (vec![Accessibility, PostEvents], pane.to_string()),
            (
                vec![Accessibility, InputMonitoring, PostEvents],
                format!("{pane} and Input Monitoring"),
            ),
        ] {
            assert_eq!(
                AfterGrant::Exit(granted.clone()).granted(),
                said,
                "{granted:?}"
            );
        }
    }

    // LEDGER T2234 | class B | 1 return value of PermissionWatch::granted
    #[test]
    fn nothing_happens_without_a_missing_permission_or_once_the_side_started() {
        // Every permission present when the side stopped: it stopped for
        // another reason, and exiting would restart the daemon for nothing,
        // and again after every restart.
        let present = System::new(&[]);
        let mut unneeded = watch(&present, true);
        unneeded.stopped(Side::Capture);
        // Missing, but the side started anyway once asked again.
        let missing = System::new(&[Permission::InputMonitoring]);
        let mut recovered = watch(&missing, true);
        recovered.stopped(Side::Capture);
        let got = runtime().block_on(async {
            let unneeded = tokio::time::timeout(NOTHING_FOR, unneeded.changed()).await;
            let first = tokio::time::timeout(NOTHING_FOR, recovered.changed()).await;
            recovered.started(Side::Capture, false);
            missing.grant();
            let after = tokio::time::timeout(NOTHING_FOR, recovered.changed()).await;
            (unneeded.is_err(), first.is_err(), after.is_err())
        });
        assert!(
            present.asked.load(Ordering::SeqCst) > 0 && missing.asked.load(Ordering::SeqCst) > 0,
            "no check ran, so this compared nothing"
        );
        assert_eq!(
            got,
            (true, true, true),
            "(nothing was missing, still missing, granted after the side started): \
             each must keep the daemon running"
        );
    }

    /// The checks run off the daemon's loop: while one is stuck, other work on
    /// the same single thread goes on.
    // LEDGER T2233 | class B | 6 state of another task on the same LocalSet
    #[test]
    fn a_check_that_blocks_does_not_hold_the_loop() {
        let entered = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let rx = Mutex::new(rx);
        let (inside, seen) = (entered.clone(), released.clone());
        let mut watch = PermissionWatch::new(
            Arc::new(move |_| {
                // Stuck until the loop's other task answers, or gives up.
                inside.store(true, Ordering::SeqCst);
                let heard = rx
                    .lock()
                    .expect("lock")
                    .recv_timeout(Duration::from_secs(5))
                    .is_ok();
                seen.store(heard, Ordering::SeqCst);
                false
            }),
            Arc::new(|| true),
            Duration::from_secs(60),
        );
        watch.stopped(Side::Capture);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            // The loop's other work: it answers once the check is under way,
            // which it can only do if the check is not on its thread.
            tokio::task::spawn_local(async move {
                while !entered.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let _ = tx.send(());
                let _ = tx.send(());
            });
            let heard = async {
                while !released.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            tokio::select! {
                _ = watch.changed() => {}
                _ = heard => {}
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        });
        assert!(
            released.load(Ordering::SeqCst),
            "a permission check held the daemon's loop: no other task ran while \
             it waited"
        );
    }
    // LEDGER T2412 | class B | 1 return value of PermissionWatch::granted over answer()
    /// macOS 27 left every preflight check at its first answer in a running
    /// daemon: Accessibility granted in System Settings was never seen (#240).
    /// The tap probe sees it.
    #[test]
    fn a_grant_the_preflight_checks_never_see_is_seen_by_the_tap_probe() {
        let tap = Arc::new(AtomicBool::new(false));
        let asked = Arc::new(AtomicUsize::new(0));
        let open = consented();
        let probe = {
            let (tap, asked) = (tap.clone(), asked.clone());
            Arc::new(move |p| {
                asked.fetch_add(1, Ordering::SeqCst);
                // Stale: every preflight check still says no.
                answer(p, open, |_| false, |_| tap.load(Ordering::SeqCst))
            })
        };
        let mut watch = PermissionWatch::new(probe, Arc::new(|| true), EVERY);
        watch.stopped(Side::Emulation);
        let got = runtime().block_on(async {
            let (granter, asked) = (tap.clone(), asked.clone());
            tokio::spawn(async move {
                while asked.load(Ordering::SeqCst) < 6 {
                    tokio::time::sleep(EVERY).await;
                }
                granter.store(true, Ordering::SeqCst);
            });
            tokio::time::timeout(DEADLINE, watch.changed()).await
        });
        assert_eq!(
            got,
            Ok(Change::Granted(AfterGrant::Exit(vec![
                Permission::Accessibility,
                Permission::PostEvents
            ]))),
            "Accessibility was granted while the daemon ran and the preflight checks \
             never said so. The tap probe must answer, so launchd restarts the daemon \
             with the grant (Err(Elapsed): never noticed)"
        );
    }

    // LEDGER T2453 | class B | 1 return value of PermissionWatch::changed over answer() + 6 stand-in taps created
    /// The daemon a fresh launch starts: the silent checks say Accessibility
    /// is missing and stay stale after it is granted, as they do in a
    /// running process (#240). Before the user asks, no tap is created over
    /// many checks, so the grant goes unseen; once the user asks, the probe
    /// runs and the grant is found (#243).
    #[test]
    fn the_watch_creates_no_tap_until_the_user_asks() {
        let gate: &'static Gate = Box::leak(Box::new(Gate::new()));
        let taps = Arc::new(AtomicUsize::new(0));
        let silent = Arc::new(AtomicUsize::new(0));
        let probe = {
            let (taps, silent) = (taps.clone(), silent.clone());
            Arc::new(move |p| {
                answer(
                    p,
                    gate,
                    |_| {
                        silent.fetch_add(1, Ordering::SeqCst);
                        false
                    },
                    // Granted in System Settings: the probe is permitted.
                    |_| {
                        taps.fetch_add(1, Ordering::SeqCst);
                        true
                    },
                )
            })
        };
        let mut watch = PermissionWatch::at_daemon_start(probe, Arc::new(|| true), EVERY);
        let (unasked, asked) = runtime().block_on(async {
            let unasked = tokio::time::timeout(NOTHING_FOR, watch.changed()).await;
            let before = (unasked.is_err(), taps.load(Ordering::SeqCst));
            gate.consent();
            (
                before,
                tokio::time::timeout(DEADLINE, watch.changed()).await,
            )
        });
        assert!(
            silent.load(Ordering::SeqCst) > 10,
            "the watch made {} silent checks: too few to show anything",
            silent.load(Ordering::SeqCst)
        );
        assert_eq!(
            (unasked, asked),
            (
                (true, 0),
                Ok(Change::Granted(AfterGrant::Exit(vec![
                    Permission::Accessibility,
                    Permission::PostEvents
                ])))
            ),
            "((nothing found, taps created) before the user asked; what the watch \
             found after). A tap before the ask can raise macOS's dialog at launch; \
             no probe after it leaves the grant unseen (Err(Elapsed))"
        );
    }

    // LEDGER T2434 | class B | 1 return value of PermissionWatch::changed
    /// Emulation runs and Accessibility is switched off. Posting events then
    /// fails without a word, so the watch must say so (#240); once it is
    /// granted again, the daemon exits for launchd as after any grant.
    #[test]
    fn accessibility_taken_from_running_emulation_is_found_and_so_is_its_grant() {
        let system = System::new(&[]);
        let mut watch = watch(&system, true);
        watch.started(Side::Emulation, true);
        let got = runtime().block_on(async {
            let unchanged = tokio::time::timeout(NOTHING_FOR, watch.changed()).await;
            let checked = system.asked.load(Ordering::SeqCst);
            system
                .denied
                .lock()
                .expect("lock")
                .push(Permission::Accessibility);
            let revoked = tokio::time::timeout(DEADLINE, watch.changed()).await;
            system.grant();
            let granted = tokio::time::timeout(DEADLINE, watch.changed()).await;
            (unchanged.is_err() && checked > 0, revoked, granted)
        });
        assert_eq!(
            got,
            (
                true,
                Ok(Change::Revoked {
                    side: Side::Emulation,
                    missing: vec![Permission::Accessibility]
                }),
                Ok(Change::Granted(AfterGrant::Exit(vec![
                    Permission::Accessibility
                ])))
            ),
            "(checked while granted and nothing changed, after the switch-off, after \
             the grant). Err(Elapsed): never noticed. Running emulation whose grant \
             is gone must be reported, or the app shows it on while nothing it posts \
             arrives."
        );
    }

    // LEDGER T2435 | class B | 6 tap masks requested through answer() by PermissionWatch::changed
    /// Every probe tap the watch makes, for a side that waits and for one
    /// that runs, asks for no events.
    #[test]
    fn every_probe_the_watch_makes_asks_for_no_events() {
        let masks = Arc::new(Mutex::new(Vec::new()));
        let open = consented();
        let probe = {
            let masks = masks.clone();
            Arc::new(move |p| {
                answer(
                    p,
                    open,
                    |_| false,
                    |mask| {
                        masks.lock().expect("masks").push(mask);
                        true
                    },
                )
            })
        };
        let mut watch = PermissionWatch::new(probe, Arc::new(|| false), EVERY);
        watch.stopped(Side::Capture);
        watch.started(Side::Emulation, true);
        let _ =
            runtime().block_on(async { tokio::time::timeout(NOTHING_FOR, watch.changed()).await });
        let masks = masks.lock().expect("masks").clone();
        assert!(
            masks.len() > 2 && masks.iter().all(|&m| m == 0),
            "every probe tap must ask for no events (mask 0); masks asked: {masks:?}"
        );
    }

    // LEDGER T2440 | class B | 1 return value of PermissionWatch::changed
    /// One refused probe while emulation runs stops nothing: it may be
    /// spurious, and acting on it would stop emulation and, once the next
    /// check answers, restart the daemon for nothing.
    #[test]
    fn a_single_refusal_while_emulation_runs_stops_nothing() {
        let asked = Arc::new(AtomicUsize::new(0));
        let probe = {
            let asked = asked.clone();
            // Refused once, on the third check.
            Arc::new(move |_| asked.fetch_add(1, Ordering::SeqCst) != 2)
        };
        let mut watch = PermissionWatch::new(probe, Arc::new(|| true), EVERY);
        watch.started(Side::Emulation, true);
        let got =
            runtime().block_on(async { tokio::time::timeout(NOTHING_FOR, watch.changed()).await });
        assert!(
            asked.load(Ordering::SeqCst) > 4 && got.is_err(),
            "one refusal, then granted on every check after it ({} checks): \
             nothing may change, it gave {got:?}",
            asked.load(Ordering::SeqCst)
        );
    }

    // LEDGER T2441 | class B | 1 return value of PermissionWatch::changed + 6 probe calls
    /// Emulation through a backend that needs no permission, such as
    /// `dummy` chosen on purpose, is not watched: a refused probe must not
    /// stop it.
    #[test]
    fn emulation_through_a_backend_that_needs_nothing_is_not_watched() {
        let system = System::new(&[Permission::Accessibility, Permission::PostEvents]);
        let mut watch = watch(&system, true);
        watch.started(Side::Emulation, false);
        let got =
            runtime().block_on(async { tokio::time::timeout(NOTHING_FOR, watch.changed()).await });
        assert_eq!(
            (got.is_err(), system.asked.load(Ordering::SeqCst)),
            (true, 0),
            "(nothing changed, checks made) for emulation that needs no permission; \
             it gave {got:?}"
        );
    }
}

#[cfg(test)]
mod a_permission_is_named_as_this_macos_names_it {
    use super::{AfterGrant, Permission};
    use input_event::settings_pane::assume_major;

    // LEDGER T12 | class B | 1 return value: AfterGrant::granted, <Permission as Display>::fmt
    #[test]
    fn what_was_granted_is_named_as_macos_26_and_27_name_it() {
        let said = |major| {
            assume_major(Some(major));
            let s = (
                AfterGrant::Exit(vec![
                    Permission::Accessibility,
                    Permission::InputMonitoring,
                    Permission::PostEvents,
                ])
                .granted(),
                Permission::PostEvents.to_string(),
            );
            assume_major(None);
            s
        };
        assert_eq!(
            [said(26), said(27)],
            [
                (
                    "Accessibility and Input Monitoring".to_string(),
                    "Accessibility (to post input)".to_string()
                ),
                (
                    "Device Control and Data Access and Input Monitoring".to_string(),
                    "Device Control and Data Access (to post input)".to_string()
                ),
            ]
        );
    }
}

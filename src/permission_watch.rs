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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

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
    /// The System Settings list that grants it.
    fn pane(self) -> &'static str {
        match self {
            Self::Accessibility | Self::PostEvents => "Accessibility",
            Self::InputMonitoring => "Input Monitoring",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Accessibility => "Accessibility",
            Self::InputMonitoring => "Input Monitoring",
            Self::PostEvents => "Accessibility (to post input)",
        })
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
        let mut panes: Vec<&str> = Vec::new();
        for pane in granted.iter().map(|p| p.pane()) {
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
}

/// What one check found: each permission asked, and whether it is granted;
/// and whether launchd would restart this process, asked only when a side
/// that was missing something has it all.
type Checked = (BTreeMap<Permission, bool>, bool);

/// Watches the permissions of each side that is not running (see the module).
pub struct PermissionWatch {
    probe: Probe,
    restarts: Restarts,
    every: Duration,
    /// Sides that are not running, each with what the checks found it
    /// missing: `None` until a check has run since it stopped. A side found
    /// missing nothing stopped for another reason, and is not watched.
    waiting: BTreeMap<Side, Option<BTreeSet<Permission>>>,
    ticks: Option<Interval>,
    /// A check running off the loop, kept across a `select!` that drops
    /// [`Self::granted`] before it resolves.
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

    /// This machine's: the macOS checks and launchd, as a daemon starts.
    /// Elsewhere there are no such permissions, and nothing is ever watched.
    pub fn of_this_machine() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::at_daemon_start(
                Arc::new(tcc::granted),
                Arc::new(crate::daemon_start::launchd_restarts_this_process),
                CHECK_EVERY,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self {
                enabled: false,
                ..Self::new(Arc::new(|_| true), Arc::new(|| false), CHECK_EVERY)
            }
        }
    }

    /// `side` is not running: watch what it needs.
    pub fn stopped(&mut self, side: Side) {
        if self.enabled {
            self.waiting.entry(side).or_insert(None);
        }
    }

    /// `side` is running: stop watching for it.
    pub fn started(&mut self, side: Side) {
        self.waiting.remove(&side);
        if self.waiting.is_empty() {
            self.pending = None;
        }
    }

    /// Resolves once a side that was missing a permission has every one it
    /// needs, with what to do about it. Never resolves while no side is
    /// waiting, or while each waiting side lacks something.
    ///
    /// The checks run on a blocking thread, so a slow answer from the
    /// system never holds the daemon's loop. Safe to drop at any await.
    pub async fn granted(&mut self) -> AfterGrant {
        loop {
            if self.waiting.is_empty() {
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
                if let Some(after) = self.settle(&answers, restarts) {
                    return after;
                }
            }
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

/// The silent checks the capture and emulation backends make.
#[cfg(target_os = "macos")]
mod tcc {
    use super::Permission;

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

    pub(super) fn granted(permission: Permission) -> bool {
        // SAFETY: each takes no arguments and only reads this process's
        // permission; none raises a prompt.
        unsafe {
            match permission {
                Permission::Accessibility => AXIsProcessTrusted() != 0,
                Permission::InputMonitoring => CGPreflightListenEventAccess(),
                Permission::PostEvents => CGPreflightPostEventAccess(),
            }
        }
    }
}

#[cfg(test)]
mod a_grant_made_while_the_daemon_runs {
    //! The probe and launchd are stand-ins. What must happen is waited for
    //! with a generous deadline; what must not is watched for a window that
    //! holds many checks.

    use super::{AfterGrant, Permission, PermissionWatch, Side};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
                tokio::time::timeout(DEADLINE, watch.granted()).await
            });
            assert_eq!(
                got,
                Ok(expected.clone()),
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
            tokio::time::timeout(DEADLINE, both.granted()).await
        });
        assert_eq!(
            got,
            Ok(AfterGrant::Exit(vec![Permission::Accessibility])),
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
            runtime().block_on(async { tokio::time::timeout(NOTHING_FOR, again.granted()).await });
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
        let mut watch = PermissionWatch::of_this_machine();
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
        for (granted, said) in [
            (vec![Accessibility], "Accessibility"),
            (vec![Accessibility, PostEvents], "Accessibility"),
            (
                vec![Accessibility, InputMonitoring, PostEvents],
                "Accessibility and Input Monitoring",
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
            let unneeded = tokio::time::timeout(NOTHING_FOR, unneeded.granted()).await;
            let first = tokio::time::timeout(NOTHING_FOR, recovered.granted()).await;
            recovered.started(Side::Capture);
            missing.grant();
            let after = tokio::time::timeout(NOTHING_FOR, recovered.granted()).await;
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
                _ = watch.granted() => {}
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
}

//! Picking up a macOS permission granted while the daemon runs (#221).
//!
//! macOS checks Accessibility and Input Monitoring when capture or emulation
//! is created, and a daemon whose check failed then waits for the user to ask
//! again. A grant made in System Settings may not reach a process that is
//! already running, and the app does not restart a daemon of its own build.
//! So while capture or emulation is not running, the daemon asks the same
//! silent checks the backends use, every few seconds and off its loop. When a
//! permission that was missing is granted, a daemon that launchd starts again
//! after a failure exits unsuccessfully, and its launchd job starts a fresh
//! process, which sees the grant. Any other daemon says that the permission is
//! granted and takes effect once hops restarts.

use std::collections::BTreeSet;
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

/// Asks whether a permission is granted, without raising a prompt.
pub type Probe = Arc<dyn Fn(Permission) -> bool + Send + Sync>;

/// Whether launchd starts this process again after an unsuccessful exit.
pub type Restarts = Arc<dyn Fn() -> bool + Send + Sync>;

/// What the daemon does once the permissions it was missing are granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfterGrant {
    /// Exit unsuccessfully: launchd starts a fresh process, which has them.
    Exit(Vec<Permission>),
    /// Keep running, and say that they take effect once hops restarts:
    /// nothing would start this process again.
    Tell(Vec<Permission>),
}

impl AfterGrant {
    /// The permissions granted, in words: "Accessibility and Input Monitoring".
    pub fn granted(&self) -> String {
        let (Self::Exit(granted) | Self::Tell(granted)) = self;
        let names: Vec<String> = granted.iter().map(ToString::to_string).collect();
        match names.as_slice() {
            [] => "the permission".to_string(),
            [one] => one.clone(),
            [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
        }
    }
}

/// What one check found, and whether launchd would restart this process.
type Checked = (BTreeSet<Permission>, bool);

/// Watches the permissions of a side that is not running (see the module).
pub struct PermissionWatch {
    probe: Probe,
    restarts: Restarts,
    every: Duration,
    /// Sides that are not running, whose permissions are checked.
    waiting: BTreeSet<Side>,
    /// What the checks found missing, once one has run since a side stopped.
    /// `None` until then; a check that finds nothing missing ends the watch.
    missing: Option<BTreeSet<Permission>>,
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
    /// A watch that asks `probe`, and `restarts` once everything is granted,
    /// every `every`. Nothing is watched until a side stops.
    pub fn new(probe: Probe, restarts: Restarts, every: Duration) -> Self {
        Self {
            probe,
            restarts,
            every,
            waiting: BTreeSet::new(),
            missing: None,
            ticks: None,
            pending: None,
            enabled: true,
        }
    }

    /// This machine's: the macOS checks and launchd, with both sides waiting
    /// to start. Elsewhere there are no such permissions, and nothing is ever
    /// watched.
    pub fn of_this_machine() -> Self {
        #[cfg(target_os = "macos")]
        {
            let mut watch = Self::new(
                Arc::new(tcc::granted),
                Arc::new(crate::daemon_start::launchd_restarts_this_process),
                CHECK_EVERY,
            );
            watch.stopped(Side::Capture);
            watch.stopped(Side::Emulation);
            watch
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
            self.waiting.insert(side);
        }
    }

    /// `side` is running: stop watching for it.
    pub fn started(&mut self, side: Side) {
        self.waiting.remove(&side);
        if self.waiting.is_empty() {
            self.missing = None;
            self.pending = None;
        }
    }

    /// Resolves once every permission that was missing is granted, with what
    /// to do about it. Never resolves while no side is waiting, or while
    /// nothing was found missing.
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
                    .iter()
                    .flat_map(|side| side.needs().iter().copied())
                    .collect();
                let watching = self.missing.is_some();
                self.pending = Some(tokio::task::spawn_blocking(move || {
                    let missing: BTreeSet<Permission> =
                        needed.into_iter().filter(|&p| !probe(p)).collect();
                    // Asked only when about to act: it runs `launchctl`.
                    let restarts = watching && missing.is_empty() && restarts();
                    (missing, restarts)
                }));
            }
            let Some(check) = self.pending.as_mut() else {
                continue;
            };
            let checked = check.await;
            self.pending = None;
            // A check that panicked is tried again at the next tick.
            if let Ok((missing, restarts)) = checked {
                if let Some(after) = self.settle(missing, restarts) {
                    return after;
                }
            }
        }
    }

    /// Fold one check into the watch; `Some` once what was missing is granted.
    fn settle(&mut self, missing: BTreeSet<Permission>, restarts: bool) -> Option<AfterGrant> {
        let Some(was) = self.missing.take() else {
            if missing.is_empty() {
                // Nothing was missing when the side stopped, so no grant
                // will start it: stop watching until another side stops.
                self.waiting.clear();
            } else {
                log::info!(
                    "missing macOS permission(s): {}; checking again every {} s until granted",
                    missing
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                    self.every.as_secs_f64()
                );
                self.missing = Some(missing);
            }
            return None;
        };
        if !missing.is_empty() {
            self.missing = Some(missing);
            return None;
        }
        self.waiting.clear();
        let granted = was.into_iter().collect();
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

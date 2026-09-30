//! Keeping a Mac awake while another machine may control it.
//!
//! A Mac that idle-sleeps suspends hops, and the machine controlling it can
//! no longer reach it until someone wakes it by hand. So a Mac holds a power
//! assertion, `PreventUserIdleSystemSleep` named "hops KVM receiver active",
//! but only while at least one paired device may control it ([`wanted`]).
//! With nothing paired, or with every such pairing removed or no longer
//! granting control, the Mac sleeps as it would without hops. Remote input
//! also wakes the display, which the emulation backend does per event and
//! is not decided here.
//!
//! Switching a device off does not let the Mac sleep: it stops this Mac's
//! pointer crossing to that device, but the device may still cross onto
//! this Mac over a link it opens (#218), and an asleep Mac is unreachable.
//!
//! `GRABBR_KEEP_AWAKE=display` holds `PreventUserIdleDisplaySleep` instead,
//! so the screen never blanks; `=off` never holds one, for a Mac woken over
//! the network some other way.
//!
//! The decision is made here, on every platform, and reaches the system
//! through [`PowerAssertion`]; only macOS has one to take.

use crate::transport::Trust;

/// Whether this machine should be kept awake now: some device it holds a
/// pairing with may control it. That is
/// [`crate::trust::TrustStore::may_drive_us`], the test every inbound event
/// passes and nothing else: a device switched off here may still drive this
/// machine over a link it opened.
pub(crate) fn wanted(trust: &Trust) -> bool {
    let store = trust.read().expect("lock");
    let any = store.entries().any(|(fp, _)| store.may_drive_us(fp));
    any
}

/// What `GRABBR_KEEP_AWAKE` asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Hold no assertion at all.
    Off,
    /// Keep the system awake; the display may blank. The default.
    System,
    /// Keep the display on too.
    Display,
}

/// Which assertion to hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `PreventUserIdleSystemSleep`.
    System,
    /// `PreventUserIdleDisplaySleep`.
    Display,
}

impl Mode {
    /// The mode a value of `GRABBR_KEEP_AWAKE` asks for. Anything but `off`
    /// and `display`, and no value, is the default.
    pub(crate) fn from_value(value: Option<&str>) -> Mode {
        match value {
            Some("off") => Mode::Off,
            Some("display") => Mode::Display,
            _ => Mode::System,
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn from_env() -> Mode {
        Mode::from_value(std::env::var("GRABBR_KEEP_AWAKE").ok().as_deref())
    }

    /// The assertion this mode holds while wanted; none for `off`.
    pub(crate) fn kind(self) -> Option<Kind> {
        match self {
            Mode::Off => None,
            Mode::System => Some(Kind::System),
            Mode::Display => Some(Kind::Display),
        }
    }
}

/// The system's power assertion: the one seam between [`KeepAwake`] and the
/// OS, so the decision is tested on every platform. Only macOS has one
/// outside tests.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) trait PowerAssertion {
    /// Take the assertion. `false` when the system refused it.
    fn take(&mut self) -> bool;
    /// Let it go. Called only after a `take` that returned `true`.
    fn release(&mut self);
}

/// Holds the assertion while it is wanted, and only then.
pub(crate) struct KeepAwake {
    power: Option<Box<dyn PowerAssertion>>,
    wanted: bool,
    held: bool,
}

impl KeepAwake {
    /// This machine's: on macOS the real assertion of the kind
    /// `GRABBR_KEEP_AWAKE` asks for, elsewhere none.
    ///
    /// A daemon a test runs in-process takes none, and the tests that run
    /// the hops binary start it with `GRABBR_KEEP_AWAKE=off`, so a test run
    /// leaves the machine's sleep alone; a test that wants the real one
    /// builds it.
    pub(crate) fn for_this_machine() -> Self {
        if cfg!(test) {
            return Self::without_power();
        }
        #[cfg(target_os = "macos")]
        {
            Self::for_mode(Mode::from_env(), |kind| {
                Box::new(macos::Assertion::new(kind))
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::without_power()
        }
    }

    /// Holding the assertion `mode` asks for, made by `make`; none for
    /// `off`.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn for_mode(mode: Mode, make: impl FnOnce(Kind) -> Box<dyn PowerAssertion>) -> Self {
        match mode.kind() {
            Some(kind) => Self::with(make(kind)),
            None => {
                log::info!(
                    "GRABBR_KEEP_AWAKE=off: holding no power assertion; this machine \
                     may sleep while another machine controls it"
                );
                Self::without_power()
            }
        }
    }

    /// Holding through `power`, which nothing has taken yet.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn with(power: Box<dyn PowerAssertion>) -> Self {
        Self {
            power: Some(power),
            wanted: false,
            held: false,
        }
    }

    fn without_power() -> Self {
        Self {
            power: None,
            wanted: false,
            held: false,
        }
    }

    /// Take the assertion when it becomes wanted, release it when it stops
    /// being wanted. Nothing happens while `wanted` is unchanged, so this is
    /// cheap to call after every event; an assertion the system refused is
    /// tried again by [`KeepAwake::retry_refused`].
    pub(crate) fn set(&mut self, wanted: bool) {
        if wanted == self.wanted {
            return;
        }
        self.wanted = wanted;
        if wanted {
            self.take();
        } else if self.release() {
            log::info!("released the power assertion: no paired device may control this machine");
        }
    }

    /// Try again to take an assertion that is wanted but was refused. Not
    /// on every event: a refusal is a system call that failed, and the
    /// caller paces this.
    pub(crate) fn retry_refused(&mut self) {
        if self.wanted && !self.held {
            self.take();
        }
    }

    /// Let the assertion go because the daemon is stopping.
    pub(crate) fn release_for_exit(&mut self) {
        self.wanted = false;
        if self.release() {
            log::info!("released the power assertion: the daemon is stopping");
        }
    }

    fn take(&mut self) {
        if let Some(power) = self.power.as_mut() {
            self.held = power.take();
        }
    }

    /// Whether there was one to release.
    fn release(&mut self) -> bool {
        match self.power.as_mut() {
            Some(power) if std::mem::take(&mut self.held) => {
                power.release();
                true
            }
            _ => false,
        }
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        self.release_for_exit();
    }
}

#[cfg(target_os = "macos")]
pub(crate) mod macos {
    //! The real assertion, through `input_emulation::macos_keep_awake`.

    use super::{Kind, PowerAssertion};
    use input_emulation::macos_keep_awake::{self as iopm, AssertionKind};

    pub(crate) struct Assertion {
        kind: AssertionKind,
        held: Option<iopm::PowerAssertion>,
    }

    impl Assertion {
        pub(crate) fn new(kind: Kind) -> Self {
            let kind = match kind {
                Kind::System => AssertionKind::System,
                Kind::Display => AssertionKind::Display,
            };
            Self { kind, held: None }
        }
    }

    impl PowerAssertion for Assertion {
        fn take(&mut self) -> bool {
            let kind = self.kind.type_name();
            match iopm::PowerAssertion::take(self.kind) {
                Ok(held) => {
                    log::info!(
                        "holding a power assertion ({kind}): a paired device may control \
                         this Mac, and an asleep Mac is unreachable"
                    );
                    self.held = Some(held);
                    true
                }
                Err(code) => {
                    log::warn!(
                        "could not hold a power assertion ({kind}, {code:#x}); this Mac \
                         may sleep and become unreachable while another machine controls \
                         it; trying again at the next lease sweep"
                    );
                    false
                }
            }
        }

        fn release(&mut self) {
            self.held = None;
        }
    }
}

#[cfg(test)]
pub(crate) mod recording {
    //! A [`PowerAssertion`] that records what it was asked to do.

    use super::PowerAssertion;
    use std::cell::Cell;
    use std::rc::Rc;

    /// What the recording seam saw, shared with the test.
    #[derive(Default)]
    pub(crate) struct Seen {
        pub(crate) held: Cell<bool>,
        pub(crate) takes: Cell<u32>,
        pub(crate) releases: Cell<u32>,
        /// How many more takes the system refuses.
        pub(crate) refusals: Cell<u32>,
    }

    impl Seen {
        /// `(held, takes, releases)`.
        pub(crate) fn get(&self) -> (bool, u32, u32) {
            (self.held.get(), self.takes.get(), self.releases.get())
        }
    }

    pub(crate) struct Recording(pub(crate) Rc<Seen>);

    impl PowerAssertion for Recording {
        fn take(&mut self) -> bool {
            assert!(
                !self.0.held.get(),
                "an assertion already held was taken again"
            );
            if self.0.refusals.get() > 0 {
                self.0.refusals.set(self.0.refusals.get() - 1);
                return false;
            }
            self.0.held.set(true);
            self.0.takes.set(self.0.takes.get() + 1);
            true
        }

        fn release(&mut self) {
            assert!(self.0.held.get(), "an assertion not held was released");
            self.0.held.set(false);
            self.0.releases.set(self.0.releases.get() + 1);
        }
    }
}

#[cfg(test)]
mod held_only_while_a_controller_may_drive {
    //! The decision, over real trust stores: pairing, the direction a lease
    //! grants, and removal.

    use super::recording::{Recording, Seen};
    use super::*;
    use crate::test_harness::{Machine, machine};
    use crate::trust::{Caps, TrustStore};
    use std::rc::Rc;
    use std::sync::{Arc, RwLock};

    fn store(us: &Machine) -> Trust {
        Arc::new(RwLock::new(
            TrustStore::new(&us.fingerprint, 0).expect("our fingerprint"),
        ))
    }

    // LEDGER KA-1 | class B | 1 return value: keep_awake::wanted over a real TrustStore
    #[test]
    fn only_a_paired_device_that_may_control_this_machine_keeps_it_awake() {
        let (mac, pc, laptop) = (machine(), machine(), machine());
        let trust = store(&mac);
        assert!(!wanted(&trust), "kept awake with nothing paired");

        // This machine controls the laptop only: the laptop may not drive it.
        trust
            .write()
            .expect("lock")
            .issue_confirmed(&laptop.fingerprint, "laptop", Caps::OUTBOUND)
            .expect("issue");
        assert!(
            !wanted(&trust),
            "kept awake for a pairing that only lets this machine control the other"
        );

        // A pairing still waiting for its number grants nothing yet.
        trust
            .write()
            .expect("lock")
            .issue(&pc.fingerprint, "desk pc", Caps::INBOUND)
            .expect("issue");
        assert!(
            !wanted(&trust),
            "kept awake for a pairing not yet confirmed"
        );

        trust
            .write()
            .expect("lock")
            .issue_confirmed(&pc.fingerprint, "desk pc", Caps::DRIVE)
            .expect("issue");
        assert!(
            wanted(&trust),
            "not kept awake for a paired machine that may control this one"
        );

        trust
            .write()
            .expect("lock")
            .drop_capabilities(&pc.fingerprint, Caps::DRIVE_ME);
        assert!(
            !wanted(&trust),
            "kept awake for a machine that may no longer control this one"
        );

        trust
            .write()
            .expect("lock")
            .issue_confirmed(&pc.fingerprint, "desk pc", Caps::DRIVE)
            .expect("issue");
        assert!(wanted(&trust), "paired again, not kept awake");
        trust.write().expect("lock").forget(&pc.fingerprint);
        assert!(!wanted(&trust), "kept awake for a machine that was removed");
    }

    // LEDGER KA-2 | class B | 1 calls made through the PowerAssertion seam by KeepAwake::set
    #[test]
    fn the_assertion_is_taken_once_when_wanted_and_released_once_when_not() {
        let seen = Rc::new(Seen::default());
        let mut awake = KeepAwake::with(Box::new(Recording(seen.clone())));
        awake.set(false);
        assert_eq!(
            seen.get(),
            (false, 0, 0),
            "(held, takes, releases) unwanted"
        );
        awake.set(true);
        awake.set(true);
        assert_eq!(
            seen.get(),
            (true, 1, 0),
            "(held, takes, releases) wanted twice"
        );
        awake.set(false);
        awake.set(false);
        assert_eq!(seen.get(), (false, 1, 1), "(held, takes, releases) let go");
        awake.set(true);
        drop(awake);
        assert_eq!(
            seen.get(),
            (false, 2, 2),
            "(held, takes, releases): dropping it while held must release it"
        );
    }

    // LEDGER KA-2b | class B | 1 calls made through the PowerAssertion seam by KeepAwake::set and retry_refused
    #[test]
    fn a_refused_assertion_is_tried_again_only_when_retried() {
        let seen = Rc::new(Seen::default());
        seen.refusals.set(1);
        let mut awake = KeepAwake::with(Box::new(Recording(seen.clone())));
        awake.set(true);
        awake.set(true);
        assert_eq!(
            seen.get(),
            (false, 0, 0),
            "(held, takes, releases) once the system refused it"
        );
        awake.retry_refused();
        awake.retry_refused();
        assert_eq!(
            seen.get(),
            (true, 1, 0),
            "(held, takes, releases) once retried"
        );
        awake.set(false);
        awake.retry_refused();
        assert_eq!(
            seen.get(),
            (false, 1, 1),
            "(held, takes, releases): retried while unwanted"
        );
    }

    // LEDGER KA-3 | class B | 1 return value: Mode::from_value
    #[test]
    fn the_switch_keeps_its_meaning() {
        assert_eq!(
            [None, Some("off"), Some("display"), Some("on"), Some("")].map(Mode::from_value),
            [
                Mode::System,
                Mode::Off,
                Mode::Display,
                Mode::System,
                Mode::System
            ],
            "GRABBR_KEEP_AWAKE unset, off, display, on and empty"
        );
    }

    // LEDGER KA-3b | class B | 1 the kind KeepAwake::for_mode asks its maker for, and the calls made through what it made
    #[test]
    fn each_mode_holds_its_own_assertion_and_off_holds_none() {
        for (mode, kind) in [
            (Mode::System, Some(Kind::System)),
            (Mode::Display, Some(Kind::Display)),
            (Mode::Off, None),
        ] {
            let seen = Rc::new(Seen::default());
            let mut asked = None;
            let mut awake = KeepAwake::for_mode(mode, |k| {
                asked = Some(k);
                Box::new(Recording(seen.clone()))
            });
            awake.set(true);
            assert_eq!(
                (asked, seen.get().0),
                (kind, kind.is_some()),
                "(kind made, held while wanted) for {mode:?}"
            );
        }
    }

    // LEDGER KA-4 | class B | 2 IOPMCopyAssertionsByProcess for this process, what `pmset -g assertions` lists
    /// The real assertion of each kind, taken and released through the seam:
    /// this process holds it only between the two, as `pmset -g assertions`
    /// shows. No daemon a test runs takes one, so any found is this test's.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_real_assertion_is_held_only_while_wanted() {
        use input_emulation::macos_keep_awake::{ASSERTION_NAME, held_by_this_process};
        let ours = || {
            held_by_this_process()
                .into_iter()
                .filter(|(_, name)| name == ASSERTION_NAME)
                .map(|(kind, _)| kind)
                .collect::<Vec<_>>()
        };
        assert_eq!(ours(), Vec::<String>::new(), "precondition: none held");
        for (kind, listed) in [
            (Kind::System, "PreventUserIdleSystemSleep"),
            (Kind::Display, "PreventUserIdleDisplaySleep"),
        ] {
            let mut awake = KeepAwake::with(Box::new(macos::Assertion::new(kind)));
            assert_eq!(ours(), Vec::<String>::new(), "held before it was wanted");
            awake.set(true);
            assert_eq!(ours(), [listed], "not held while wanted ({kind:?})");
            awake.set(false);
            assert_eq!(ours(), Vec::<String>::new(), "still held once unwanted");
            awake.set(true);
            drop(awake);
            assert_eq!(ours(), Vec::<String>::new(), "still held once dropped");
        }
    }
}

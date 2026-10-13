//! An emulation backend that injects nothing and records everything it is
//! asked to inject, so a test can assert on exactly what reached a backend.
//!
//! Compiled only with the `recording` feature, which the hops crate enables as a
//! dev-dependency and nothing else enables. A config file cannot name it, and
//! the fallback list never picks it: the only way to select it is
//! [`Recording::backend`], which needs a [`Recording`] in the same process.

use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use input_event::Event;

use crate::{Backend, ButtonScope, Emulation, EmulationHandle, error::EmulationError};

/// Which [`Recording`] a [`Backend::Recording`] writes to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecordingId(u64);

/// One call a backend received, in order.
#[derive(Clone, Debug, PartialEq)]
pub enum Recorded {
    Create(EmulationHandle),
    Consume(Event, EmulationHandle),
    Destroy(EmulationHandle),
    Terminate,
}

type FailWhen = Box<dyn Fn(&Event) -> bool + Send>;

struct Log {
    calls: Vec<Recorded>,
    fail_when: Option<FailWhen>,
    button_scope: ButtonScope,
    /// How long each injected event takes, so a test can make injection the
    /// slow step and see what happens to everything waiting behind it.
    consume_takes: Option<std::time::Duration>,
    /// Creating a backend fails as a system withholding its permission
    /// does.
    refused: bool,
    /// Needs Accessibility while it runs, as the macOS backend does.
    as_mac: bool,
    /// Can start again with nothing shown to the user, as the libei
    /// backend can with a restore token.
    unasked: bool,
    /// Whether the screen shield is up, as the libei backend reads it from
    /// logind and the screensaver: `None` when it cannot be read.
    shield: Option<bool>,
    /// Reading the shield does not answer until this is cleared, as a
    /// D-Bus service that hangs.
    shield_stalls: bool,
    /// How many times a test ended the session from the system's side.
    ends: u64,
    /// How many backends were created from this recording.
    started: usize,
    /// Every event injected is a deliberate push past this edge, as a
    /// backend's adaptive edge concludes while the pointer is held there.
    pushed_past: Option<crate::EdgeSide>,
}

type Shared = Arc<Mutex<Log>>;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);
static REGISTRY: Mutex<Option<HashMap<RecordingId, Shared>>> = Mutex::new(None);

/// A test's handle on what a recording backend received.
///
/// Every backend created from [`Self::backend`] appends to the same log, so a
/// backend that is torn down and created again keeps one history. Dropping this
/// unregisters it; creating a backend for it afterwards fails.
pub struct Recording {
    id: RecordingId,
    log: Shared,
}

impl Recording {
    /// A recording that answers like a backend whose handles share one
    /// device.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_button_scope(ButtonScope::Machine)
    }

    /// A recording that answers `scope` when asked how it counts buttons, so
    /// a test can drive the release rules of either kind of backend.
    pub fn with_button_scope(button_scope: ButtonScope) -> Self {
        let id = RecordingId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let log = Arc::new(Mutex::new(Log {
            calls: Vec::new(),
            fail_when: None,
            button_scope,
            consume_takes: None,
            refused: false,
            as_mac: false,
            unasked: false,
            shield: Some(false),
            shield_stalls: false,
            ends: 0,
            started: 0,
            pushed_past: None,
        }));
        REGISTRY
            .lock()
            .expect("recording registry")
            .get_or_insert_with(HashMap::new)
            .insert(id, log.clone());
        Self { id, log }
    }

    /// The backend to hand to `InputEmulation::new`.
    pub fn backend(&self) -> Backend {
        Backend::Recording(self.id)
    }

    /// Every call so far, oldest first.
    pub fn calls(&self) -> Vec<Recorded> {
        self.log.lock().expect("recording log").calls.clone()
    }

    /// Make every injected event take `how_long`, so injection is the slow
    /// step: what a real backend costs (a blocking syscall per event) without
    /// waiting on a real device.
    pub fn consume_takes(&self, how_long: std::time::Duration) {
        self.log.lock().expect("recording log").consume_takes = Some(how_long);
    }

    /// Make every backend created from this one need Accessibility while
    /// it runs, as the macOS backend does.
    pub fn needs_accessibility(&self) {
        self.log.lock().expect("recording log").as_mac = true;
    }

    /// Make every backend created from this one say it can start again
    /// with nothing shown to the user, as the libei backend does with a
    /// restore token.
    pub fn starts_without_asking(&self) {
        self.log.lock().expect("recording log").unasked = true;
    }

    /// Answer `up` when asked whether the screen shield is up: `None` as
    /// when it cannot be read.
    pub fn shield(&self, up: Option<bool>) {
        self.log.lock().expect("recording log").shield = up;
    }

    /// Make reading the shield hang while `stalls`, as a D-Bus service
    /// that never answers does.
    pub fn stall_shield(&self, stalls: bool) {
        self.log.lock().expect("recording log").shield_stalls = stalls;
    }

    /// End the running session from the system's side with no event
    /// injected, as the compositor closing the libei stream does.
    pub fn end_session(&self) {
        self.log.lock().expect("recording log").ends += 1;
    }

    /// How many backends were created from this recording.
    pub fn started(&self) -> usize {
        self.log.lock().expect("recording log").started
    }

    /// Report every event injected from here on as a deliberate push past
    /// `side`, as a backend's adaptive edge does while the pointer is held
    /// against it; `None` stops.
    pub fn pushes_past(&self, side: Option<crate::EdgeSide>) {
        self.log.lock().expect("recording log").pushed_past = side;
    }

    /// Make creating a backend fail as it does on a Mac that has not
    /// granted hops Accessibility.
    pub fn refuse_permission(&self) {
        self.log.lock().expect("recording log").refused = true;
    }

    /// Make `consume` return an error for every event matching `when`. The
    /// call is still recorded, since a real backend is handed the event before
    /// it fails.
    pub fn fail_when(&self, when: impl Fn(&Event) -> bool + Send + 'static) {
        self.log.lock().expect("recording log").fail_when = Some(Box::new(when));
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        if let Ok(mut registry) = REGISTRY.lock() {
            if let Some(registry) = registry.as_mut() {
                registry.remove(&self.id);
            }
        }
    }
}

/// What the recording `id` answers when asked whether the screen shield is
/// up, once it no longer stalls; `None` once the recording is dropped.
pub(crate) async fn shield_up(id: RecordingId) -> Option<bool> {
    let log = REGISTRY
        .lock()
        .expect("recording registry")
        .as_ref()
        .and_then(|registry| registry.get(&id).cloned())?;
    loop {
        let (stalls, up) = {
            let log = log.lock().expect("recording log");
            (log.shield_stalls, log.shield)
        };
        if !stalls {
            return up;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

pub(crate) struct RecordingEmulation {
    log: Shared,
    /// Session ends asked for before this backend was created, which are
    /// not its own.
    ends_before: u64,
}

impl RecordingEmulation {
    pub(crate) fn new(id: RecordingId) -> Result<Self, RecordingEmulationCreationError> {
        let log = REGISTRY
            .lock()
            .expect("recording registry")
            .as_ref()
            .and_then(|registry| registry.get(&id).cloned())
            .ok_or(RecordingEmulationCreationError::NotRegistered)?;
        let ends_before = {
            let mut log = log.lock().expect("recording log");
            if log.refused {
                return Err(RecordingEmulationCreationError::Refused);
            }
            log.started += 1;
            log.ends
        };
        Ok(Self { log, ends_before })
    }

    fn record(&self, call: Recorded) {
        self.log.lock().expect("recording log").calls.push(call);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordingEmulationCreationError {
    #[error("no recording is registered under this id; was it dropped?")]
    NotRegistered,
    #[error("the system does not grant the permission to post input")]
    Refused,
}

#[async_trait]
impl Emulation for RecordingEmulation {
    async fn consume(
        &mut self,
        event: Event,
        handle: EmulationHandle,
    ) -> Result<(), EmulationError> {
        let (fail, takes) = {
            let mut log = self.log.lock().expect("recording log");
            log.calls.push(Recorded::Consume(event, handle));
            (
                log.fail_when.as_ref().is_some_and(|fail| fail(&event)),
                log.consume_takes,
            )
        };
        if let Some(takes) = takes {
            tokio::time::sleep(takes).await;
        }
        if fail {
            return Err(io::Error::other("recording: failure requested by the test").into());
        }
        Ok(())
    }

    async fn create(&mut self, handle: EmulationHandle) {
        self.record(Recorded::Create(handle));
    }

    async fn destroy(&mut self, handle: EmulationHandle) {
        self.record(Recorded::Destroy(handle));
    }

    async fn terminate(&mut self) {
        self.record(Recorded::Terminate);
    }

    fn button_scope(&self) -> ButtonScope {
        self.log.lock().expect("recording log").button_scope
    }

    fn take_edge_push(&mut self) -> Option<crate::EdgeSide> {
        self.log.lock().expect("recording log").pushed_past
    }

    fn starts_unasked(&self) -> bool {
        self.log.lock().expect("recording log").unasked
    }

    async fn ended(&mut self) -> EmulationError {
        while self.log.lock().expect("recording log").ends == self.ends_before {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        EmulationError::EndOfStream
    }

    fn needs(&self) -> &'static [crate::error::Permission] {
        if self.log.lock().expect("recording log").as_mac {
            &[crate::error::Permission::Accessibility]
        } else {
            &[]
        }
    }
}

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

pub(crate) struct RecordingEmulation {
    log: Shared,
}

impl RecordingEmulation {
    pub(crate) fn new(id: RecordingId) -> Result<Self, RecordingEmulationCreationError> {
        let log = REGISTRY
            .lock()
            .expect("recording registry")
            .as_ref()
            .and_then(|registry| registry.get(&id).cloned())
            .ok_or(RecordingEmulationCreationError::NotRegistered)?;
        Ok(Self { log })
    }

    fn record(&self, call: Recorded) {
        self.log.lock().expect("recording log").calls.push(call);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordingEmulationCreationError {
    #[error("no recording is registered under this id; was it dropped?")]
    NotRegistered,
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
}

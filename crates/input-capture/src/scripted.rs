//! A capture backend that reads no device: it yields exactly the events a test
//! pushes into its [`Script`], so the real capture task can be driven through a
//! crossing, a drag or a release bind without a display or permissions.
//!
//! Compiled only with the `scripted` feature, which the hops crate enables as a
//! dev-dependency and nothing else enables. A config file cannot name it, and
//! the fallback list never picks it: the only way to select it is
//! [`Script::backend`], which needs a [`Script`] in the same process.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures_core::Stream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::{Backend, Capture, CaptureError, CaptureEvent, Position};

/// Which [`Script`] a [`Backend::Scripted`] reads from.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScriptId(u64);

/// What a script delivers: an event, or a backend failure.
enum Item {
    Event(Position, CaptureEvent),
    Fail,
}

type Events = UnboundedReceiver<Item>;
/// The receiving end, lent to one live backend at a time.
type Slot = Arc<Mutex<Option<Events>>>;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);
static REGISTRY: Mutex<Option<HashMap<ScriptId, Slot>>> = Mutex::new(None);

/// A test's handle for feeding a scripted capture backend.
///
/// Dropping it unregisters it and ends the backend's event stream.
pub struct Script {
    id: ScriptId,
    tx: UnboundedSender<Item>,
}

impl Script {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let id = ScriptId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = unbounded_channel();
        REGISTRY
            .lock()
            .expect("script registry")
            .get_or_insert_with(HashMap::new)
            .insert(id, Arc::new(Mutex::new(Some(rx))));
        Self { id, tx }
    }

    /// The backend to hand to `InputCapture::new`.
    pub fn backend(&self) -> Backend {
        Backend::Scripted(self.id)
    }

    /// Deliver one event, as if the device at `pos` produced it.
    pub fn push(&self, pos: Position, event: CaptureEvent) {
        let _ = self.tx.send(Item::Event(pos, event));
    }

    /// Fail the backend: its stream yields an error next, as a real backend
    /// does when its event tap or portal session dies.
    pub fn fail(&self) {
        let _ = self.tx.send(Item::Fail);
    }
}

impl Drop for Script {
    fn drop(&mut self) {
        if let Ok(mut registry) = REGISTRY.lock() {
            if let Some(registry) = registry.as_mut() {
                registry.remove(&self.id);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScriptedCaptureCreationError {
    #[error("no script is registered under this id, or a live backend already reads it")]
    Unavailable,
}

pub(crate) struct ScriptedCapture {
    slot: Slot,
    events: Option<Events>,
}

impl ScriptedCapture {
    pub(crate) fn new(id: ScriptId) -> Result<Self, ScriptedCaptureCreationError> {
        let slot = REGISTRY
            .lock()
            .expect("script registry")
            .as_ref()
            .and_then(|registry| registry.get(&id).cloned())
            .ok_or(ScriptedCaptureCreationError::Unavailable)?;
        let events = slot
            .lock()
            .expect("script slot")
            .take()
            .ok_or(ScriptedCaptureCreationError::Unavailable)?;
        Ok(Self {
            slot,
            events: Some(events),
        })
    }
}

impl Drop for ScriptedCapture {
    /// Hand the stream back, so a capture task that restarts its backend reads
    /// the same script.
    fn drop(&mut self) {
        if let (Some(events), Ok(mut slot)) = (self.events.take(), self.slot.lock()) {
            *slot = Some(events);
        }
    }
}

#[async_trait(?Send)]
impl Capture for ScriptedCapture {
    async fn create(&mut self, _pos: Position) -> Result<(), CaptureError> {
        Ok(())
    }

    async fn destroy(&mut self, _pos: Position) -> Result<(), CaptureError> {
        Ok(())
    }

    async fn release(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
}

impl Stream for ScriptedCapture {
    type Item = Result<(Position, CaptureEvent), CaptureError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.events.as_mut() {
            Some(events) => events.poll_recv(cx).map(|item| {
                item.map(|item| match item {
                    Item::Event(pos, event) => Ok((pos, event)),
                    Item::Fail => Err(CaptureError::Io(std::io::Error::other(
                        "scripted: failure requested by the test",
                    ))),
                })
            }),
            None => Poll::Ready(None),
        }
    }
}

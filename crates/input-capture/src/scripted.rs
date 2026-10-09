//! A capture backend that reads no device: it yields exactly the events a test
//! pushes into its [`Script`], so the real capture task can be driven through a
//! crossing, a drag or a release bind without a display or permissions.
//!
//! Compiled only with the `scripted` feature, which the hops crate enables as a
//! dev-dependency and nothing else enables. A config file cannot name it, and
//! the fallback list never picks it: the only way to select it is
//! [`Script::backend`], which needs a [`Script`] in the same process.
//!
//! It holds the pointer the way a real backend does: from the `Begin` it
//! yields until it is told to release, or ends. [`Script::held`] says whether
//! it holds it now, which is what a user at the edge feels.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures_core::Stream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::{Backend, Capture, CaptureError, CaptureEvent, Permission, Position};

/// Which [`Script`] a [`Backend::Scripted`] reads from.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScriptId(u64);

/// What a script delivers: an event, or a backend failure.
enum Item {
    Event(Position, CaptureEvent),
    Fail,
    Interrupt,
    Revoke(Vec<Permission>),
}

type Events = UnboundedReceiver<Item>;

/// What a script shares with the backend reading it.
#[derive(Clone, Default)]
struct Shared {
    /// The receiving end, lent to one live backend at a time.
    events: Arc<Mutex<Option<Events>>>,
    /// The pointer is held: a `Begin` went out and no release came since.
    held: Arc<AtomicBool>,
    /// How many times the backend was told to release.
    releases: Arc<AtomicUsize>,
    /// The permissions the backend is refused at creation, as macOS refuses one.
    withheld: Arc<Mutex<Vec<Permission>>>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(0);
static REGISTRY: Mutex<Option<HashMap<ScriptId, Shared>>> = Mutex::new(None);

/// A test's handle for feeding a scripted capture backend.
///
/// Dropping it unregisters it and ends the backend's event stream.
pub struct Script {
    id: ScriptId,
    tx: UnboundedSender<Item>,
    shared: Shared,
}

impl Script {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let id = ScriptId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = unbounded_channel();
        let shared = Shared {
            events: Arc::new(Mutex::new(Some(rx))),
            ..Default::default()
        };
        REGISTRY
            .lock()
            .expect("script registry")
            .get_or_insert_with(HashMap::new)
            .insert(id, shared.clone());
        Self { id, tx, shared }
    }

    /// Whether the backend holds the pointer: it yielded a `Begin` and was
    /// not told to release since, nor ended.
    pub fn held(&self) -> bool {
        self.shared.held.load(Ordering::SeqCst)
    }

    /// How many times the backend was told to release the pointer.
    pub fn releases(&self) -> usize {
        self.shared.releases.load(Ordering::SeqCst)
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

    /// Interrupt the backend: its stream yields the error a macOS backend
    /// yields when the system disabled its event tap for a reason that
    /// passes, after which capture starts again on its own.
    pub fn interrupt(&self) {
        let _ = self.tx.send(Item::Interrupt);
    }

    /// Refuse every backend created from now on for want of `missing`, as
    /// macOS refuses one while a permission is not granted. An empty list
    /// lets the next one start.
    pub fn withhold(&self, missing: &[Permission]) {
        *self.shared.withheld.lock().expect("withheld") = missing.to_vec();
    }

    /// Take `missing` away from the running backend: its stream yields the
    /// error the macOS backend yields once it finds a permission gone.
    pub fn revoke(&self, missing: &[Permission]) {
        let _ = self.tx.send(Item::Revoke(missing.to_vec()));
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
    #[error("{}", crate::error::Permission::sentence(.0))]
    MissingPermissions(Vec<Permission>),
}

pub(crate) struct ScriptedCapture {
    shared: Shared,
    events: Option<Events>,
}

impl ScriptedCapture {
    pub(crate) fn new(id: ScriptId) -> Result<Self, ScriptedCaptureCreationError> {
        let shared = REGISTRY
            .lock()
            .expect("script registry")
            .as_ref()
            .and_then(|registry| registry.get(&id).cloned())
            .ok_or(ScriptedCaptureCreationError::Unavailable)?;
        let missing = shared.withheld.lock().expect("withheld").clone();
        if !missing.is_empty() {
            return Err(ScriptedCaptureCreationError::MissingPermissions(missing));
        }
        let events = shared
            .events
            .lock()
            .expect("script slot")
            .take()
            .ok_or(ScriptedCaptureCreationError::Unavailable)?;
        Ok(Self {
            shared,
            events: Some(events),
        })
    }
}

impl Drop for ScriptedCapture {
    /// Hand the stream back, so a capture task that restarts its backend reads
    /// the same script. A backend that ends holds nothing.
    fn drop(&mut self) {
        self.shared.held.store(false, Ordering::SeqCst);
        if let (Some(events), Ok(mut slot)) = (self.events.take(), self.shared.events.lock()) {
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
        self.shared.held.store(false, Ordering::SeqCst);
        self.shared.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), CaptureError> {
        self.shared.held.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl Stream for ScriptedCapture {
    type Item = Result<(Position, CaptureEvent), CaptureError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self { shared, events } = self.get_mut();
        match events.as_mut() {
            Some(events) => events.poll_recv(cx).map(|item| {
                item.map(|item| match item {
                    Item::Event(pos, event) => {
                        if event == CaptureEvent::Begin {
                            shared.held.store(true, Ordering::SeqCst);
                        }
                        Ok((pos, event))
                    }
                    Item::Fail => Err(CaptureError::Io(std::io::Error::other(
                        "scripted: failure requested by the test",
                    ))),
                    Item::Interrupt => Err(CaptureError::Interrupted(
                        "scripted: interruption requested by the test".to_string(),
                    )),
                    Item::Revoke(missing) => Err(CaptureError::MissingPermissions(missing)),
                })
            }),
            None => Poll::Ready(None),
        }
    }
}

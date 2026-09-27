use async_trait::async_trait;
use core::task::{Context, Poll};
use event_thread::EventThread;
use futures::Stream;
use std::pin::Pin;

use std::task::ready;

use super::event_queue::{self, QueueReceiver};
use super::{Capture, CaptureError, CaptureEvent, Position};

mod display_util;
mod event_thread;

pub struct WindowsInputCapture {
    // Fields drop in declaration order, so the hook thread goes first: its
    // drop asks it to exit and joins it, and it removes both hooks before it
    // returns. Only then does the queue's receiver go, so no hook runs
    // against a queue nobody reads (#80). A push after the receiver is gone
    // is discarded rather than failing, should this order ever change.
    event_thread: EventThread,
    events: QueueReceiver,
}

#[async_trait(?Send)]
impl Capture for WindowsInputCapture {
    async fn create(&mut self, pos: Position) -> Result<(), CaptureError> {
        self.event_thread.create(pos);
        Ok(())
    }

    async fn destroy(&mut self, pos: Position) -> Result<(), CaptureError> {
        self.event_thread.destroy(pos);
        Ok(())
    }

    async fn release(&mut self) -> Result<(), CaptureError> {
        self.event_thread.release_capture();
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
}

impl WindowsInputCapture {
    pub(crate) fn new() -> Self {
        // Not a bounded channel: one drops a button-up or a key-up whenever
        // the consumer falls ten events behind (#81). See `event_queue`.
        let (event_tx, events) = event_queue::channel(event_queue::CAPACITY);
        let event_thread = EventThread::new(event_tx);
        Self {
            event_thread,
            events,
        }
    }
}

impl Stream for WindowsInputCapture {
    type Item = Result<(Position, CaptureEvent), CaptureError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.events.poll_recv(cx)) {
            None => Poll::Ready(None),
            Some(e) => Poll::Ready(Some(Ok(e))),
        }
    }
}

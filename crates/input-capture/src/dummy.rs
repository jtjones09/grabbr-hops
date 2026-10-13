use std::f64::consts::PI;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use async_trait::async_trait;
use futures_core::Stream;
use input_event::PointerEvent;
use tokio::time::{self, Instant, Interval};

use super::{Capture, CaptureError, CaptureEvent, Position};

/// A capture backend that reads no device: a pointer held at the left edge,
/// moving in a circle. It crosses as it starts, when a barrier is made, and
/// again [`RECROSS_AFTER`] after it is released, as a pointer still pushing
/// at a real edge does.
pub struct DummyInputCapture {
    /// When the current crossing began; `None` until the next one does.
    start: Option<Instant>,
    interval: Interval,
    offset: (i32, i32),
}

impl DummyInputCapture {
    pub fn new() -> Self {
        Self {
            start: None,
            interval: time::interval(Duration::from_millis(1)),
            offset: (0, 0),
        }
    }
}

/// How long after a release the pointer crosses again. A hand pushing at
/// an edge does not cross a thousand times a second, and a refused crossing
/// is released at once: without a pause this looped at the tick rate.
const RECROSS_AFTER: Duration = Duration::from_millis(250);

impl DummyInputCapture {
    /// Make the next event a crossing.
    fn cross_again(&mut self) {
        self.start = None;
        self.offset = (0, 0);
    }
}

impl Default for DummyInputCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl Capture for DummyInputCapture {
    async fn create(&mut self, _pos: Position) -> Result<(), CaptureError> {
        self.cross_again();
        Ok(())
    }

    async fn destroy(&mut self, _pos: Position) -> Result<(), CaptureError> {
        Ok(())
    }

    async fn release(&mut self) -> Result<(), CaptureError> {
        self.cross_again();
        self.interval.reset_after(RECROSS_AFTER);
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
}

const FREQUENCY_HZ: f64 = 1.0;
const RADIUS: f64 = 100.0;

impl Stream for DummyInputCapture {
    type Item = Result<(Position, CaptureEvent), CaptureError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let current = ready!(self.interval.poll_tick(cx));
        let event = match self.start {
            None => {
                self.start.replace(current);
                CaptureEvent::Begin
            }
            Some(start) => {
                let elapsed = start.elapsed();
                let elapsed_sec_f64 = elapsed.as_secs_f64();
                let second_fraction = elapsed_sec_f64 - elapsed_sec_f64 as u64 as f64;
                let radians = second_fraction * 2. * PI * FREQUENCY_HZ;
                let offset = (radians.cos() * RADIUS * 2., (radians * 2.).sin() * RADIUS);
                let offset = (offset.0 as i32, offset.1 as i32);
                let relative_motion = (offset.0 - self.offset.0, offset.1 - self.offset.1);
                self.offset = offset;
                let (dx, dy) = (relative_motion.0 as f64, relative_motion.1 as f64);
                CaptureEvent::Input(input_event::Event::Pointer(PointerEvent::Motion {
                    time: 0,
                    dx,
                    dy,
                }))
            }
        };
        Poll::Ready(Some(Ok((Position::Left, event))))
    }
}

#[cfg(test)]
mod crossing_again {
    use futures::StreamExt;

    use super::*;

    async fn next_begin(capture: &mut DummyInputCapture) {
        loop {
            let (_, event) = capture
                .next()
                .await
                .expect("the dummy never ends")
                .expect("the dummy never fails");
            if event == CaptureEvent::Begin {
                return;
            }
        }
    }

    // LEDGER TD-1 | class B | the backend's own event stream
    /// Released, it crosses again, but not before [`RECROSS_AFTER`]: a
    /// crossing refused and released at once otherwise loops at the tick
    /// rate. A lower bound, which a loaded run only makes longer.
    #[tokio::test]
    async fn a_released_pointer_crosses_again_after_a_pause() {
        let mut capture = DummyInputCapture::new();
        capture.create(Position::Left).await.expect("create");
        next_begin(&mut capture).await;

        capture.release().await.expect("release");
        let released = Instant::now();
        next_begin(&mut capture).await;
        assert!(
            released.elapsed() >= RECROSS_AFTER,
            "the pointer crossed again {:?} after it was released",
            released.elapsed()
        );
    }
}

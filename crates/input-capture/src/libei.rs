use ashpd::{
    desktop::{
        Session,
        input_capture::{
            Activated, ActivatedBarrier, Barrier, BarrierID, Capabilities, CreateSessionOptions,
            InputCapture, Region, ReleaseOptions, Zones,
        },
    },
    enumflags2::BitFlags,
};
use async_trait::async_trait;
use futures::{FutureExt, StreamExt};
use reis::{
    ei::{self, handshake::ContextType},
    event::{Connection, DeviceCapability, EiEvent},
    tokio::EiConvertEventStream,
};
use std::{
    cell::Cell,
    collections::HashMap,
    io,
    mem::ManuallyDrop,
    num::NonZeroU32,
    os::unix::net::UnixStream,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::{
    sync::{
        Notify,
        mpsc::{self, Receiver, Sender},
    },
    task::{JoinError, JoinHandle},
};
use tokio_util::sync::CancellationToken;

use futures_core::Stream;

use input_event::Event;

use crate::CaptureEvent;

use super::{
    Capture as LanMouseInputCapture, Position,
    error::{CaptureError, LibeiCaptureCreationError},
};

/* there is a bug in xdg-remote-desktop-portal-gnome / mutter that
 * prevents receiving further events after a session has been disabled once.
 * Therefore the session needs to be recreated when the barriers are updated */

/// events that necessitate restarting the capture session
#[derive(Clone, Copy, Debug)]
enum LibeiNotifyEvent {
    Create(Position),
    Destroy(Position),
}

pub struct LibeiInputCapture {
    capture_task: CaptureTask<InputCapture>,
    event_rx: Receiver<(Position, CaptureEvent)>,
    notify_capture: Sender<LibeiNotifyEvent>,
    notify_release: Arc<Notify>,
}

/// The capture task, and the value it reads through a raw pointer, which
/// must outlive it.
///
/// Dropping it without [`CaptureTask::terminate`] used to panic, which with
/// `panic = "abort"` ended the daemon, and during an unwind aborts any build
/// (#103). It now stops the task instead, and leaks `owner` while the task
/// may still exist, so the pointer never dangles.
struct CaptureTask<T> {
    owner: ManuallyDrop<Pin<Box<T>>>,
    task: JoinHandle<Result<(), CaptureError>>,
    cancel: CancellationToken,
    /// The task's result was taken, so the handle must not be polled again.
    done: bool,
}

impl<T> CaptureTask<T> {
    fn new(
        owner: Pin<Box<T>>,
        task: JoinHandle<Result<(), CaptureError>>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            owner: ManuallyDrop::new(owner),
            task,
            cancel,
            done: false,
        }
    }

    /// The task's result, once. Afterwards it reads as ended.
    fn poll_result(&mut self, cx: &mut Context) -> Poll<Result<(), CaptureError>> {
        if self.done {
            return Poll::Ready(Ok(()));
        }
        let r = ready!(self.task.poll_unpin(cx));
        self.done = true;
        Poll::Ready(joined(r))
    }

    /// Stops the task and waits for it. Calling it again is harmless.
    async fn terminate(&mut self) -> Result<(), CaptureError> {
        self.cancel.cancel();
        if self.done {
            return Ok(());
        }
        log::debug!("waiting for capture to terminate...");
        let r = (&mut self.task).await;
        self.done = true;
        log::debug!("done!");
        joined(r)
    }
}

/// A task that did not return, as the error it ends capture with.
fn joined(r: Result<Result<(), CaptureError>, JoinError>) -> Result<(), CaptureError> {
    r.unwrap_or_else(|e| Err(CaptureError::TaskFailed(e.to_string())))
}

impl<T> Drop for CaptureTask<T> {
    fn drop(&mut self) {
        if self.done || self.task.is_finished() {
            // SAFETY: the task's future is gone, so nothing reads `owner`
            // through a pointer any more; it is dropped once, here.
            unsafe { ManuallyDrop::drop(&mut self.owner) };
        } else {
            // The runtime drops an aborted task's future only when it next
            // runs it, and that future still points into `owner`: leave
            // `owner` allocated rather than let the pointer dangle.
            log::warn!("input capture was dropped without being terminated: stopping its task");
            self.cancel.cancel();
            self.task.abort();
        }
    }
}

/// returns (start pos, end pos), inclusive
fn pos_to_barrier(r: &Region, pos: Position) -> (i32, i32, i32, i32) {
    let (x, y) = (r.x_offset(), r.y_offset());
    let (w, h) = (r.width() as i32, r.height() as i32);
    match pos {
        Position::Left => (x, y, x, y + h - 1),
        Position::Right => (x + w, y, x + w, y + h - 1),
        Position::Top => (x, y, x + w - 1, y),
        Position::Bottom => (x, y + h, x + w - 1, y + h),
    }
}

/// Ashpd does not expose fields
#[derive(Clone, Copy, Debug)]
struct ICBarrier {
    barrier_id: BarrierID,
    position: (i32, i32, i32, i32),
}

impl ICBarrier {
    fn new(barrier_id: BarrierID, position: (i32, i32, i32, i32)) -> Self {
        Self {
            barrier_id,
            position,
        }
    }
}

impl From<ICBarrier> for Barrier {
    fn from(barrier: ICBarrier) -> Self {
        Barrier::new(barrier.barrier_id, barrier.position)
    }
}

fn select_barriers(
    zones: &Zones,
    clients: &[Position],
    next_barrier_id: &mut NonZeroU32,
) -> (Vec<ICBarrier>, HashMap<BarrierID, Position>) {
    let mut pos_for_barrier = HashMap::new();
    let mut barriers: Vec<ICBarrier> = vec![];

    for pos in clients {
        let mut client_barriers = zones
            .regions()
            .iter()
            .map(|r| {
                let id = take_barrier_id(next_barrier_id);
                let position = pos_to_barrier(r, *pos);
                pos_for_barrier.insert(id, *pos);
                ICBarrier::new(id, position)
            })
            .collect();
        barriers.append(&mut client_barriers);
    }
    (barriers, pos_for_barrier)
}

/// The next barrier id, starting over at 1 past `u32::MAX`: ids only need to
/// differ within one session, and a session sets far fewer.
fn take_barrier_id(next: &mut NonZeroU32) -> BarrierID {
    let id = *next;
    *next = next.checked_add(1).unwrap_or(NonZeroU32::MIN);
    id
}

async fn update_barriers(
    input_capture: &InputCapture,
    session: &Session<InputCapture>,
    active_clients: &[Position],
    next_barrier_id: &mut NonZeroU32,
) -> Result<(Vec<ICBarrier>, HashMap<BarrierID, Position>), ashpd::Error> {
    let zones = input_capture
        .zones(session, Default::default())
        .await?
        .response()?;
    log::debug!("zones: {zones:?}");

    let (barriers, id_map) = select_barriers(&zones, active_clients, next_barrier_id);
    log::debug!("barriers: {barriers:?}");
    log::debug!("client for barrier id: {id_map:?}");

    let ashpd_barriers: Vec<Barrier> = barriers.iter().copied().map(|b| b.into()).collect();
    let response = input_capture
        .set_pointer_barriers(
            session,
            &ashpd_barriers,
            zones.zone_set(),
            Default::default(),
        )
        .await?;
    let response = response.response()?;
    log::debug!("{response:?}");
    Ok((barriers, id_map))
}

async fn create_session(
    input_capture: &InputCapture,
) -> std::result::Result<(Session<InputCapture>, BitFlags<Capabilities>), ashpd::Error> {
    log::debug!("creating input capture session");
    let create_session_options = CreateSessionOptions::default().set_capabilities(
        Capabilities::Keyboard | Capabilities::Pointer | Capabilities::Touchscreen,
    );
    input_capture
        .create_session(None, create_session_options)
        .await
}

async fn connect_to_eis(
    input_capture: &InputCapture,
    session: &Session<InputCapture>,
) -> Result<(ei::Context, Connection, EiConvertEventStream), CaptureError> {
    log::debug!("connect_to_eis");
    let fd = input_capture
        .connect_to_eis(session, Default::default())
        .await?;

    ei_handshake(UnixStream::from(fd)).await
}

/// Opens the ei connection on `stream` and names hops to the EIS server, which
/// names the devices it creates for us after it.
async fn ei_handshake(
    stream: UnixStream,
) -> Result<(ei::Context, Connection, EiConvertEventStream), CaptureError> {
    stream.set_nonblocking(true)?;
    let context = ei::Context::new(stream)?;
    let (conn, event_stream) = context
        .handshake_tokio(input_event::APP_ID, ContextType::Receiver)
        .await?;
    Ok((context, conn, event_stream))
}

async fn libei_event_handler(
    mut ei_event_stream: EiConvertEventStream,
    context: ei::Context,
    event_tx: Sender<(Position, CaptureEvent)>,
    release_session: Arc<Notify>,
    current_pos: Rc<Cell<Option<Position>>>,
) -> Result<(), CaptureError> {
    loop {
        let ei_event = ei_event_stream
            .next()
            .await
            .ok_or(CaptureError::EndOfStream)??;
        // A keyboard event's Debug names the key. It is traced once it is a
        // CaptureEvent, which does not (#117).
        match &ei_event {
            EiEvent::KeyboardKey(_) | EiEvent::KeyboardModifiers(_) => {}
            other => log::trace!("from ei: {other:?}"),
        }
        let client = current_pos.get();
        handle_ei_event(ei_event, client, &context, &event_tx, &release_session).await?;
    }
}

impl LibeiInputCapture {
    pub async fn new() -> std::result::Result<Self, LibeiCaptureCreationError> {
        // Before any portal call, so the consent prompt can name hops.
        input_event::portal::register().await;
        let input_capture = Box::pin(InputCapture::new().await?);
        let input_capture_ptr = input_capture.as_ref().get_ref() as *const InputCapture;
        let first_session = Some(create_session(unsafe { &*input_capture_ptr }).await?);

        let (event_tx, event_rx) = mpsc::channel(1);
        let (notify_capture, notify_rx) = mpsc::channel(1);
        let notify_release = Arc::new(Notify::new());

        let cancellation_token = CancellationToken::new();

        let capture = do_capture(
            input_capture_ptr,
            notify_rx,
            notify_release.clone(),
            first_session,
            event_tx,
            cancellation_token.clone(),
        );
        let capture_task = tokio::task::spawn_local(capture);

        let producer = Self {
            capture_task: CaptureTask::new(input_capture, capture_task, cancellation_token),
            event_rx,
            notify_capture,
            notify_release,
        };

        Ok(producer)
    }
}

async fn do_capture(
    input_capture: *const InputCapture,
    mut capture_event: Receiver<LibeiNotifyEvent>,
    notify_release: Arc<Notify>,
    session: Option<(Session<InputCapture>, BitFlags<Capabilities>)>,
    event_tx: Sender<(Position, CaptureEvent)>,
    cancellation_token: CancellationToken,
) -> Result<(), CaptureError> {
    let mut session = session.map(|s| s.0);

    /* safety: libei_task does not outlive Self */
    let input_capture = unsafe { &*input_capture };
    let mut active_clients: Vec<Position> = vec![];
    let mut next_barrier_id = NonZeroU32::MIN;

    let mut zones_changed = input_capture.receive_zones_changed().await?;

    loop {
        // do capture session
        let cancel_session = CancellationToken::new();
        let cancel_update = CancellationToken::new();

        let mut capture_event_occured: Option<LibeiNotifyEvent> = None;
        let mut zones_have_changed = false;

        // kill session if clients need to be updated
        let handle_session_update_request = async {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    log::debug!("cancelled")
                }, /* exit requested */
                _ = cancel_update.cancelled() => {
                    log::debug!("update task cancelled");
                }, /* session exited */
                _ = zones_changed.next() => {
                    log::debug!("zones changed!");
                    zones_have_changed = true
                }, /* zones have changed */
                e = capture_event.recv() => if let Some(e) = e { /* clients changed */
                    log::debug!("capture event: {e:?}");
                    capture_event_occured.replace(e);
                },
            }
            // kill session (might already be dead!)
            log::debug!("=> cancelling session");
            cancel_session.cancel();
        };

        if !active_clients.is_empty() {
            // create session
            let mut session = match session.take() {
                Some(s) => s,
                None => create_session(input_capture).await?.0,
            };

            let capture_session = do_capture_session(
                input_capture,
                &mut session,
                &event_tx,
                &active_clients,
                &mut next_barrier_id,
                &notify_release,
                (cancel_session.clone(), cancel_update.clone()),
            );

            let (capture_result, ()) = tokio::join!(capture_session, handle_session_update_request);
            log::debug!("capture session + session_update task done!");

            // disable capture
            log::debug!("disabling input capture");
            if let Err(e) = input_capture.disable(&session, Default::default()).await {
                log::warn!("input_capture.disable(&session) {e}");
            }
            if let Err(e) = session.close().await {
                log::warn!("session.close(): {e}");
            }

            // propagate error from capture session
            capture_result?;
        } else {
            handle_session_update_request.await;
        }

        // update clients if requested
        if let Some(event) = capture_event_occured.take() {
            match event {
                LibeiNotifyEvent::Create(p) => active_clients.push(p),
                LibeiNotifyEvent::Destroy(p) => active_clients.retain(|&pos| pos != p),
            }
        }

        // break
        if cancellation_token.is_cancelled() {
            break Ok(());
        }
    }
}

async fn do_capture_session(
    input_capture: &InputCapture,
    session: &mut Session<InputCapture>,
    event_tx: &Sender<(Position, CaptureEvent)>,
    active_clients: &[Position],
    next_barrier_id: &mut NonZeroU32,
    notify_release: &Notify,
    cancel: (CancellationToken, CancellationToken),
) -> Result<(), CaptureError> {
    let (cancel_session, cancel_update) = cancel;
    // current client
    let current_pos = Rc::new(Cell::new(None));

    // connect to eis server
    let (context, _conn, ei_event_stream) = connect_to_eis(input_capture, session).await?;

    // set barriers
    let (barriers, pos_for_barrier_id) =
        update_barriers(input_capture, session, active_clients, next_barrier_id).await?;

    log::debug!("enabling session");
    input_capture.enable(session, Default::default()).await?;

    // cancellation token to release session
    let release_session = Arc::new(Notify::new());

    // async event task
    let cancel_ei_handler = CancellationToken::new();
    let event_chan = event_tx.clone();
    let pos = current_pos.clone();
    let cancel_session_clone = cancel_session.clone();
    let release_session_clone = release_session.clone();
    let cancel_ei_handler_clone = cancel_ei_handler.clone();
    let ei_task = async move {
        tokio::select! {
            r = libei_event_handler(
                ei_event_stream,
                context,
                event_chan,
                release_session_clone,
                pos,
            ) => {
                log::debug!("libei exited: {r:?} cancelling session task");
                cancel_session_clone.cancel();
            }
            _ = cancel_ei_handler_clone.cancelled() => {},
        }
        Ok::<(), CaptureError>(())
    };

    let capture_session_task = async {
        let r = async {
            // receiver for activation tokens
            let mut activated = input_capture.receive_activated().await?;
            let mut ei_devices_changed = false;
            loop {
                tokio::select! {
                    activated = activated.next() => {
                        let activated = activated.ok_or(CaptureError::ActivationClosed)?;
                        log::debug!("activated: {activated:?}");

                        let (barrier_id, pos) = match client_for_activation(
                            activated.barrier_id(),
                            activated.cursor_position(),
                            &barriers,
                            &pos_for_barrier_id,
                        ) {
                            Ok(found) => found,
                            Err(e) => {
                                // The compositor holds the pointer until told
                                // to let go: give it back before stopping.
                                log::warn!("{e}");
                                let released =
                                    release_capture(input_capture, session, &activated, None).await;
                                if let Err(r) = released {
                                    log::warn!("could not hand the pointer back: {r}");
                                }
                                return Err(e);
                            }
                        };
                        current_pos.replace(Some(pos));

                        // client entered => send event
                        event_tx
                            .send((pos, CaptureEvent::Begin))
                            .await
                            .map_err(|_| CaptureError::EndOfStream)?;

                        tokio::select! {
                            _ = notify_release.notified() => { /* capture release */
                                log::debug!("release session requested");
                            },
                            _ = release_session.notified() => { /* release session */
                                log::debug!("ei devices changed");
                                ei_devices_changed = true;
                            },
                            _ = cancel_session.cancelled() => { /* kill session notify */
                                log::debug!("session cancel requested");
                                break
                            },
                        }

                        let barrier = barriers.iter().find(|b| b.barrier_id == barrier_id);
                        let at = release_point(activated.cursor_position(), barrier, pos);
                        release_capture(input_capture, session, &activated, at).await?;

                    }
                    _ = notify_release.notified() => { /* capture release -> we are not capturing anyway, so ignore */
                        log::debug!("release session requested");
                    },
                    _ = release_session.notified() => { /* release session */
                        log::debug!("ei devices changed");
                        ei_devices_changed = true;
                    },
                    _ = cancel_session.cancelled() => { /* kill session notify */
                        log::debug!("session cancel requested");
                        break
                    },
                }
                if ei_devices_changed {
                    /* for whatever reason, GNOME seems to kill the session
                     * as soon as devices are added or removed, so we need
                     * to cancel */
                    break;
                }
            }
            Ok::<(), CaptureError>(())
        }
        .await;
        // However the session ended, the libei task must too, or the join
        // below waits on it for good.
        log::debug!("session exited: killing libei task");
        cancel_ei_handler.cancel();
        r
    };

    let (a, b) = tokio::join!(ei_task, capture_session_task);

    cancel_update.cancel();

    log::debug!("both session and ei task finished!");
    a?;
    b?;

    Ok(())
}

/// Hands the pointer back to the compositor, at `at` when given.
async fn release_capture(
    input_capture: &InputCapture,
    session: &Session<InputCapture>,
    activated: &Activated,
    at: Option<(f64, f64)>,
) -> Result<(), CaptureError> {
    if let Some(activation_id) = activated.activation_id() {
        log::debug!("releasing input capture {activation_id}");
    }
    let release_options = ReleaseOptions::default()
        .set_activation_id(activated.activation_id())
        .set_cursor_position(at);
    input_capture.release(session, release_options).await?;
    Ok(())
}

/// The barrier and client an activation is for: the barrier the compositor
/// names or, when it names none (KDE Plasma), the one nearest the cursor.
///
/// Both are optional in the portal protocol. This used to `.expect()` them,
/// which ended the daemon on a compositor that sent neither (#103).
fn client_for_activation(
    barrier: Option<ActivatedBarrier>,
    cursor: Option<(f32, f32)>,
    barriers: &[ICBarrier],
    pos_for_barrier_id: &HashMap<BarrierID, Position>,
) -> Result<(BarrierID, Position), CaptureError> {
    let barrier_id = match barrier {
        Some(ActivatedBarrier::Barrier(id)) => id,
        Some(ActivatedBarrier::UnknownBarrier) | None => {
            let Some(cursor) = cursor else {
                return Err(CaptureError::Unattributed(
                    "reported neither the barrier crossed nor the cursor position".into(),
                ));
            };
            find_corresponding_client(barriers, cursor).ok_or_else(|| {
                CaptureError::Unattributed("no barrier was set to match the cursor to".into())
            })?
        }
    };
    match pos_for_barrier_id.get(&barrier_id) {
        Some(&pos) => Ok((barrier_id, pos)),
        None => Err(CaptureError::Unattributed(format!(
            "named barrier {barrier_id}, which hops did not set"
        ))),
    }
}

/// Where to hand the pointer back: one pixel inside the edge crossed, so it
/// does not cross again at once. At the cursor when the compositor reported
/// it, which it need not; otherwise at the middle of the barrier crossed.
fn release_point(
    cursor: Option<(f32, f32)>,
    barrier: Option<&ICBarrier>,
    pos: Position,
) -> Option<(f64, f64)> {
    let (x, y) = match (cursor, barrier) {
        (Some((x, y)), _) => (f64::from(x), f64::from(y)),
        (None, Some(b)) => {
            let (x1, y1, x2, y2) = b.position;
            log::warn!(
                "the compositor did not report the cursor position: \
                 releasing at the middle of the {pos} barrier"
            );
            (
                (f64::from(x1) + f64::from(x2)) / 2.,
                (f64::from(y1) + f64::from(y2)) / 2.,
            )
        }
        (None, None) => {
            log::warn!(
                "the compositor did not report the cursor position: \
                 releasing where the compositor chooses"
            );
            return None;
        }
    };
    log::debug!("client entered @ ({x}, {y})");
    let (dx, dy) = match pos {
        Position::Left => (1., 0.),
        Position::Right => (-1., 0.),
        Position::Top => (0., 1.),
        Position::Bottom => (0., -1.),
    };
    Some((x + dx, y + dy))
}

/// The barrier nearest `pos`, if any was set.
fn find_corresponding_client(barriers: &[ICBarrier], pos: (f32, f32)) -> Option<BarrierID> {
    barriers
        .iter()
        .copied()
        .min_by_key(|b| {
            let (x1, y1, x2, y2) = b.position;
            let (x1, y1, x2, y2) = (x1 as f32, y1 as f32, x2 as f32, y2 as f32);
            distance_to_line(((x1, y1), (x2, y2)), pos) as i32
        })
        .map(|b| b.barrier_id)
}

fn distance_to_line(line: ((f32, f32), (f32, f32)), p: (f32, f32)) -> f32 {
    let ((x1, y1), (x2, y2)) = line;
    let (x0, y0) = p;
    /*
     * we use the fact that for the triangle spanned by the line and p,
     * the height of the triangle is the desired distance and can be calculated by
     * h = 2A / b with b being the line_length and
     */
    let double_triangle_area = ((y2 - y1) * x0 - (x2 - x1) * y0 + x2 * y1 - y2 * x1).abs();
    let line_length = ((y2 - y1).powf(2.0) + (x2 - x1).powf(2.0)).sqrt();
    let distance = double_triangle_area / line_length;
    log::debug!("distance to line({line:?}, {p:?}) = {distance}");
    distance
}

static ALL_CAPABILITIES: &[DeviceCapability] = &[
    DeviceCapability::Pointer,
    DeviceCapability::PointerAbsolute,
    DeviceCapability::Keyboard,
    DeviceCapability::Touch,
    DeviceCapability::Scroll,
    DeviceCapability::Button,
];

async fn handle_ei_event(
    ei_event: EiEvent,
    current_client: Option<Position>,
    context: &ei::Context,
    event_tx: &Sender<(Position, CaptureEvent)>,
    release_session: &Notify,
) -> Result<(), CaptureError> {
    match ei_event {
        EiEvent::SeatAdded(s) => {
            s.seat.bind_capabilities(ALL_CAPABILITIES);
            context.flush().map_err(|e| io::Error::new(e.kind(), e))?;
        }
        EiEvent::SeatRemoved(_) | /* EiEvent::DeviceAdded(_) | */ EiEvent::DeviceRemoved(_) => {
            log::debug!("releasing session: a seat or device was removed");
            release_session.notify_waiters();
        }
        EiEvent::DevicePaused(_) | EiEvent::DeviceResumed(_) => {}
        EiEvent::DeviceStartEmulating(_) => log::debug!("START EMULATING"),
        EiEvent::DeviceStopEmulating(_) => log::debug!("STOP EMULATING"),
        EiEvent::Disconnected(d) => {
            return Err(CaptureError::Disconnected(format!("{:?}", d.reason)))
        }
        _ => {
            if let Some(pos) = current_client {
                for event in Event::from_ei_event(ei_event) {
                    event_tx
                        .send((pos, CaptureEvent::Input(event)))
                        .await
                        .map_err(|_| CaptureError::EndOfStream)?;
                }
            }
        }
    }
    Ok(())
}

#[async_trait(?Send)]
impl LanMouseInputCapture for LibeiInputCapture {
    async fn create(&mut self, pos: Position) -> Result<(), CaptureError> {
        let _ = self
            .notify_capture
            .send(LibeiNotifyEvent::Create(pos))
            .await;
        Ok(())
    }

    async fn destroy(&mut self, pos: Position) -> Result<(), CaptureError> {
        let _ = self
            .notify_capture
            .send(LibeiNotifyEvent::Destroy(pos))
            .await;
        Ok(())
    }

    async fn release(&mut self) -> Result<(), CaptureError> {
        self.notify_release.notify_waiters();
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), CaptureError> {
        self.capture_task.terminate().await
    }
}

impl Stream for LibeiInputCapture {
    type Item = Result<(Position, CaptureEvent), CaptureError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.capture_task.poll_result(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(None),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => self.event_rx.poll_recv(cx).map(|e| e.map(Result::Ok)),
        }
    }
}

/// What a compositor may leave out of the portal's data, run through the
/// decisions the capture makes on it. The portal types are built by decoding
/// the D-Bus bytes a compositor would send, so a terse message is exactly
/// what ashpd hands the capture.
#[cfg(test)]
mod terse_compositor {
    use std::{cell::Cell, collections::HashMap, num::NonZeroU32, rc::Rc};

    use ashpd::{
        desktop::input_capture::{Activated, Zones},
        zvariant::{self, LE, OwnedObjectPath, Value, serialized::Context},
    };
    use tokio_util::sync::CancellationToken;

    use super::{
        CaptureError, CaptureTask, ICBarrier, Position, client_for_activation, release_point,
        select_barriers,
    };

    /// An `Activated` signal carrying only `fields`.
    fn activated(fields: &[(&'static str, Value<'static>)]) -> Activated {
        let path = OwnedObjectPath::try_from("/org/freedesktop/portal/desktop/session/1/t")
            .expect("a path");
        let dict: HashMap<&str, Value> = fields.iter().cloned().collect();
        let data = zvariant::to_bytes(Context::new_dbus(LE, 0), &(path, dict)).expect("encodes");
        data.deserialize::<Activated>().expect("decodes").0
    }

    /// A `Zones` response listing `regions` as (width, height, x, y).
    fn zones(regions: Vec<(u32, u32, i32, i32)>) -> Zones {
        let dict = HashMap::from([
            ("zones", Value::from(regions)),
            ("zone_set", Value::from(7u32)),
        ]);
        let data = zvariant::to_bytes(Context::new_dbus(LE, 0), &dict).expect("encodes");
        data.deserialize::<Zones>().expect("decodes").0
    }

    /// One 1920x1080 screen, and hops's barriers on its left and right edges.
    fn screen() -> (Vec<ICBarrier>, HashMap<NonZeroU32, Position>) {
        let zones = zones(vec![(1920, 1080, 0, 0)]);
        let mut next = NonZeroU32::MIN;
        select_barriers(&zones, &[Position::Left, Position::Right], &mut next)
    }

    fn cursor(x: f64, y: f64) -> (&'static str, Value<'static>) {
        ("cursor_position", Value::from((x, y)))
    }

    fn barrier(id: u32) -> (&'static str, Value<'static>) {
        ("barrier_id", Value::from(id))
    }

    fn attribute(a: &Activated) -> Result<(NonZeroU32, Position), CaptureError> {
        let (barriers, ids) = screen();
        client_for_activation(a.barrier_id(), a.cursor_position(), &barriers, &ids)
    }

    fn unattributed(r: Result<(NonZeroU32, Position), CaptureError>) -> String {
        match r {
            Err(e @ CaptureError::Unattributed(_)) => e.to_string(),
            other => panic!("expected capture to end naming what is missing, got {other:?}"),
        }
    }

    // LEDGER | behaviour | client_for_activation over a decoded Activated signal
    #[test]
    fn an_activation_naming_its_barrier_goes_to_that_edge() {
        let (_, right) =
            attribute(&activated(&[barrier(2), cursor(1919.0, 500.0)])).expect("found");
        assert_eq!(right, Position::Right);
        let (_, left) = attribute(&activated(&[barrier(1)])).expect("found");
        assert_eq!(left, Position::Left);
    }

    // LEDGER | behaviour | client_for_activation, KDE Plasma's shape
    #[test]
    fn an_activation_naming_no_barrier_goes_to_the_edge_nearest_the_cursor() {
        // Plasma sends barrier id 0, which ashpd reads as UnknownBarrier.
        let unknown = activated(&[barrier(0), cursor(1919.0, 20.0)]);
        assert_eq!(attribute(&unknown).expect("found").1, Position::Right);
        let absent = activated(&[cursor(0.0, 900.0)]);
        assert_eq!(attribute(&absent).expect("found").1, Position::Left);
    }

    // LEDGER | behaviour | client_for_activation with neither optional field
    #[test]
    fn an_activation_naming_neither_barrier_nor_cursor_ends_capture_not_the_daemon() {
        for terse in [activated(&[]), activated(&[barrier(0)])] {
            let e = unattributed(attribute(&terse));
            assert!(
                e.contains("neither the barrier crossed nor the cursor position"),
                "the error does not say what the compositor left out: {e}"
            );
        }
    }

    // LEDGER | behaviour | client_for_activation with a barrier id hops never set
    #[test]
    fn an_activation_naming_a_barrier_hops_did_not_set_ends_capture() {
        let e = unattributed(attribute(&activated(&[barrier(99), cursor(0.0, 0.0)])));
        assert!(e.contains("barrier 99"), "{e}");
    }

    // LEDGER | behaviour | client_for_activation with no barriers set
    #[test]
    fn a_cursor_with_no_barrier_to_match_ends_capture() {
        let a = activated(&[cursor(10.0, 10.0)]);
        let e = unattributed(client_for_activation(
            a.barrier_id(),
            a.cursor_position(),
            &[],
            &HashMap::new(),
        ));
        assert!(e.contains("no barrier"), "{e}");
    }

    // LEDGER | behaviour | release_point for each thing a compositor may send
    #[test]
    fn a_release_without_a_cursor_position_lands_inside_the_barrier_crossed() {
        let (barriers, _) = screen();
        let right = barriers
            .iter()
            .find(|b| b.barrier_id.get() == 2)
            .expect("right barrier");
        let a = activated(&[barrier(2)]);
        assert_eq!(a.cursor_position(), None);
        assert_eq!(
            release_point(a.cursor_position(), Some(right), Position::Right),
            Some((1919.0, 539.5)),
            "released anywhere but one pixel inside the middle of the right edge"
        );
        let a = activated(&[barrier(2), cursor(1920.0, 300.0)]);
        assert_eq!(
            release_point(a.cursor_position(), Some(right), Position::Right),
            Some((1919.0, 300.0))
        );
        assert_eq!(release_point(None, None, Position::Left), None);
    }

    // LEDGER | behaviour | select_barriers on decoded Zones at the top of the id range
    #[test]
    fn barrier_ids_start_over_instead_of_running_out() {
        let zones = zones(vec![(1920, 1080, 0, 0), (1280, 1024, 1920, 0)]);
        let mut next = NonZeroU32::MAX;
        let (barriers, ids) = select_barriers(&zones, &[Position::Right], &mut next);
        let got: Vec<u32> = barriers.iter().map(|b| b.barrier_id.get()).collect();
        assert_eq!(got, [u32::MAX, 1]);
        assert_eq!(ids.len(), 2);
        assert_eq!(next.get(), 2);
    }

    /// Something the capture task borrows, which says when it is freed.
    struct Owner(Rc<Cell<bool>>);

    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    fn owner() -> (std::pin::Pin<Box<Owner>>, Rc<Cell<bool>>) {
        let freed = Rc::new(Cell::new(false));
        (Box::pin(Owner(freed.clone())), freed)
    }

    // LEDGER | behaviour | CaptureTask dropped while its task runs
    #[tokio::test(flavor = "current_thread")]
    async fn dropping_the_capture_unterminated_stops_its_task_instead_of_panicking() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (owner, freed) = owner();
                let cancel = CancellationToken::new();
                let task = tokio::task::spawn_local(futures::future::pending());
                drop(CaptureTask::new(owner, task, cancel.clone()));
                assert!(cancel.is_cancelled(), "the task was not told to stop");
                assert!(
                    !freed.get(),
                    "what the running task points into was freed under it"
                );
            })
            .await;
    }

    // LEDGER | behaviour | CaptureTask::terminate on a task that panicked
    #[tokio::test(flavor = "current_thread")]
    async fn a_capture_task_that_panicked_ends_capture_with_an_error() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (owner, freed) = owner();
                let task = tokio::task::spawn_local(async {
                    panic!("the capture task fails");
                });
                let mut capture = CaptureTask::new(owner, task, CancellationToken::new());
                match capture.terminate().await {
                    Err(CaptureError::TaskFailed(_)) => {}
                    other => panic!("expected TaskFailed, got {other:?}"),
                }
                assert!(
                    capture.terminate().await.is_ok(),
                    "a second terminate failed"
                );
                let polled = std::future::poll_fn(|cx| capture.poll_result(cx)).await;
                assert!(polled.is_ok(), "the ended task was read twice");
                drop(capture);
                assert!(freed.get(), "a terminated capture leaked what it owned");
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::net::UnixStream,
        time::{Duration, Instant},
    };

    use reis::{PendingRequestResult, eis, handshake::EisHandshaker};

    /// Plays the compositor's side of the ei handshake on `socket`, and returns
    /// the name and context type the client gave, with the context kept open.
    fn compositor_side(
        socket: UnixStream,
    ) -> (Option<String>, eis::handshake::ContextType, eis::Context) {
        let context = eis::Context::new(socket).expect("an eis context");
        let mut handshaker = EisHandshaker::new(&context, 1);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            // The socket is non-blocking: 0 is "nothing yet", and a hang-up is
            // an UnexpectedEof error.
            match context.read() {
                Ok(0) => {
                    assert!(Instant::now() < deadline, "no handshake within 30s");
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Ok(_) => {}
                Err(e) => panic!("reading the handshake: {e}"),
            }
            while let Some(pending) = context.pending_request() {
                let PendingRequestResult::Request(request) = pending else {
                    panic!("the client sent something that is not a request");
                };
                if let Some(done) = handshaker
                    .handle_request(request)
                    .expect("a valid handshake")
                {
                    context.flush().expect("the handshake reply is sent");
                    return (done.name, done.context_type, context);
                }
            }
        }
    }

    // LEDGER T2 | class B | 2 frames received by a stand-in EIS server from libei::ei_handshake
    /// The compositor names the virtual devices after the handshake name, and
    /// shows them to the user under it.
    #[tokio::test]
    async fn the_capture_handshake_names_hops_to_the_compositor() {
        let (ours, theirs) = UnixStream::pair().expect("a socket pair");
        let compositor = std::thread::spawn(move || compositor_side(theirs));
        let ours = tokio::time::timeout(Duration::from_secs(30), super::ei_handshake(ours))
            .await
            .expect("the handshake finished within 30s");
        let (name, context_type, _context) = compositor.join().expect("the compositor side");
        if let Err(e) = ours {
            panic!("the handshake failed on our side: {e}");
        }
        assert_eq!(
            name.as_deref(),
            Some(input_event::APP_ID),
            "input capture names itself to the compositor as something other \
             than hops, so the devices it is given carry another name"
        );
        assert_eq!(context_type, eis::handshake::ContextType::Receiver);
    }
}

use futures::{StreamExt, future};
use std::{
    env,
    ffi::OsString,
    fs, io,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::PathBuf,
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinHandle;

use ashpd::desktop::{
    PersistMode, Session,
    remote_desktop::{DeviceType, RemoteDesktop, SelectDevicesOptions},
};
use async_trait::async_trait;

use reis::{
    ei::{
        self, Button, Keyboard, Pointer, Scroll, button::ButtonState, handshake::ContextType,
        keyboard::KeyState,
    },
    event::{self, Connection, DeviceCapability, DeviceEvent, EiEvent, SeatEvent},
    tokio::EiConvertEventStream,
};

use input_event::{Event, KeyboardEvent, PointerEvent};

use crate::error::EmulationError;

use super::{ButtonScope, Emulation, EmulationHandle, error::LibeiEmulationCreationError};

#[derive(Clone, Default)]
struct Devices {
    pointer: Arc<RwLock<Option<(ei::Device, ei::Pointer)>>>,
    scroll: Arc<RwLock<Option<(ei::Device, ei::Scroll)>>>,
    button: Arc<RwLock<Option<(ei::Device, ei::Button)>>>,
    keyboard: Arc<RwLock<Option<(ei::Device, ei::Keyboard)>>>,
}

pub(crate) struct LibeiEmulation {
    context: ei::Context,
    conn: event::Connection,
    devices: Devices,
    ei_task: JoinHandle<()>,
    error: Arc<Mutex<Option<EmulationError>>>,
    libei_error: Arc<AtomicBool>,
    _remote_desktop: RemoteDesktop,
    session: Session<RemoteDesktop>,
}

/// The RemoteDesktop token file, under `$XDG_CACHE_HOME` or else
/// `$HOME/.cache`; none when neither is set, which used to panic. A value
/// that is empty or relative counts as unset, as the XDG spec says.
fn token_file_path(cache_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
    let cache_dir = match (absolute(cache_home), absolute(home)) {
        (Some(cache), _) => cache,
        (None, Some(home)) => home.join(".cache"),
        (None, None) => return None,
    };
    // Keeps the upstream directory name on purpose, like ~/.config/lan-mouse;
    // the identity shown to users is input_event::APP_ID.
    Some(cache_dir.join("lan-mouse").join("remote-desktop.token"))
}

fn get_token_file_path() -> io::Result<PathBuf> {
    token_file_path(env::var_os("XDG_CACHE_HOME"), env::var_os("HOME")).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "neither XDG_CACHE_HOME nor HOME is set",
        )
    })
}

/// Read the RemoteDesktop token from file
fn read_token() -> Option<String> {
    let token_path = get_token_file_path().ok()?;
    match fs::read_to_string(&token_path) {
        Ok(token) => Some(token.trim().to_string()),
        Err(_) => None,
    }
}

/// Write the RemoteDesktop token to file
fn write_token(token: &str) -> io::Result<()> {
    let token_path = get_token_file_path()?;
    if let Some(parent) = token_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&token_path, token)?;
    Ok(())
}

/// Microseconds since the Unix epoch, or 0 on a clock set before it.
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64)
}

async fn get_ei_fd() -> Result<(RemoteDesktop, Session<RemoteDesktop>, OwnedFd), ashpd::Error> {
    // Before any portal call, so the consent prompt can name hops.
    input_event::portal::register().await;
    let remote_desktop = RemoteDesktop::new().await?;

    let restore_token = read_token();

    log::debug!("creating session ...");
    let session = remote_desktop.create_session(Default::default()).await?;

    log::debug!("selecting devices ...");
    let options = SelectDevicesOptions::default()
        .set_devices(DeviceType::Keyboard | DeviceType::Pointer)
        .set_persist_mode(PersistMode::ExplicitlyRevoked)
        .set_restore_token(restore_token.as_deref());
    remote_desktop.select_devices(&session, options).await?;

    log::info!("requesting permission for input emulation");
    let start_response = remote_desktop
        .start(&session, None, Default::default())
        .await?
        .response()?;

    // The restore token is only valid once, we need to re-save it each time
    if let Some(token_str) = start_response.restore_token() {
        if let Err(e) = write_token(token_str) {
            log::warn!("failed to save RemoteDesktop token: {}", e);
        }
    }

    let fd = remote_desktop
        .connect_to_eis(&session, Default::default())
        .await?;
    Ok((remote_desktop, session, fd))
}

/// Opens the ei connection on `stream` and names hops to the EIS server, which
/// names the virtual devices it creates for us after it.
async fn ei_handshake(
    stream: UnixStream,
) -> Result<(ei::Context, Connection, EiConvertEventStream), LibeiEmulationCreationError> {
    stream.set_nonblocking(true)?;
    let context = ei::Context::new(stream)?;
    let (conn, events) = context
        .handshake_tokio(input_event::APP_ID, ContextType::Sender)
        .await?;
    Ok((context, conn, events))
}

impl LibeiEmulation {
    pub(crate) async fn new() -> Result<Self, LibeiEmulationCreationError> {
        let (_remote_desktop, session, eifd) = get_ei_fd().await?;
        let (context, conn, events) = ei_handshake(UnixStream::from(eifd)).await?;
        let devices = Devices::default();
        let libei_error = Arc::new(AtomicBool::default());
        let error = Arc::new(Mutex::new(None));
        let ei_handler = ei_task(
            events,
            conn.clone(),
            context.clone(),
            devices.clone(),
            libei_error.clone(),
            error.clone(),
        );
        let ei_task = tokio::task::spawn_local(ei_handler);

        Ok(Self {
            context,
            conn,
            devices,
            ei_task,
            error,
            libei_error,
            _remote_desktop,
            session,
        })
    }
}

impl Drop for LibeiEmulation {
    fn drop(&mut self) {
        self.ei_task.abort();
    }
}

#[async_trait]
impl Emulation for LibeiEmulation {
    async fn consume(
        &mut self,
        event: Event,
        _handle: EmulationHandle,
    ) -> Result<(), EmulationError> {
        let now = now_micros();
        if self.libei_error.load(Ordering::SeqCst) {
            // don't break sending additional events but signal error
            if let Some(e) = self
                .error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                return Err(e);
            }
        }
        match event {
            Event::Pointer(p) => match p {
                PointerEvent::Motion { time: _, dx, dy } => {
                    let pointer_device = self
                        .devices
                        .pointer
                        .read()
                        .unwrap_or_else(PoisonError::into_inner);
                    if let Some((d, p)) = pointer_device.as_ref() {
                        p.motion_relative(dx as f32, dy as f32);
                        d.frame(self.conn.serial(), now);
                    }
                }
                PointerEvent::Button {
                    time: _,
                    button,
                    state,
                } => {
                    let button_device = self
                        .devices
                        .button
                        .read()
                        .unwrap_or_else(PoisonError::into_inner);
                    if let Some((d, b)) = button_device.as_ref() {
                        b.button(
                            button,
                            match state {
                                0 => ButtonState::Released,
                                _ => ButtonState::Press,
                            },
                        );
                        d.frame(self.conn.serial(), now);
                    }
                }
                PointerEvent::Axis {
                    time: _,
                    axis,
                    value,
                } => {
                    let scroll_device = self
                        .devices
                        .scroll
                        .read()
                        .unwrap_or_else(PoisonError::into_inner);
                    if let Some((d, s)) = scroll_device.as_ref() {
                        match axis {
                            0 => s.scroll(0., value as f32),
                            _ => s.scroll(value as f32, 0.),
                        }
                        d.frame(self.conn.serial(), now);
                    }
                }
                PointerEvent::AxisDiscrete120 { axis, value } => {
                    let scroll_device = self
                        .devices
                        .scroll
                        .read()
                        .unwrap_or_else(PoisonError::into_inner);
                    if let Some((d, s)) = scroll_device.as_ref() {
                        match axis {
                            0 => s.scroll_discrete(0, value),
                            _ => s.scroll_discrete(value, 0),
                        }
                        d.frame(self.conn.serial(), now);
                    }
                }
            },
            Event::Keyboard(k) => match k {
                KeyboardEvent::Key {
                    time: _,
                    key,
                    state,
                } => {
                    let keyboard_device = self
                        .devices
                        .keyboard
                        .read()
                        .unwrap_or_else(PoisonError::into_inner);
                    if let Some((d, k)) = keyboard_device.as_ref() {
                        k.key(
                            key,
                            match state {
                                0 => KeyState::Released,
                                _ => KeyState::Press,
                            },
                        );
                        d.frame(self.conn.serial(), now);
                    }
                }
                KeyboardEvent::Modifiers { .. } => {}
            },
        }
        self.context
            .flush()
            .map_err(|e| io::Error::new(e.kind(), e))?;
        Ok(())
    }

    async fn create(&mut self, _: EmulationHandle) {}
    async fn destroy(&mut self, _: EmulationHandle) {}

    async fn terminate(&mut self) {
        let _ = self.session.close().await;
        self.ei_task.abort();
    }

    /// Every handle injects through the one button device the EIS server
    /// gave this context (`Devices::button`). mutter ignores a repeated press
    /// or release on a device (`handle_button` in meta-eis-client.c), so the
    /// first up lets go of that device's press. How other EIS servers count
    /// is not checked.
    fn button_scope(&self) -> ButtonScope {
        ButtonScope::Machine
    }
}

async fn ei_task(
    mut events: EiConvertEventStream,
    _conn: Connection,
    context: ei::Context,
    devices: Devices,
    libei_error: Arc<AtomicBool>,
    error: Arc<Mutex<Option<EmulationError>>>,
) {
    loop {
        match ei_event_handler(&mut events, &context, &devices).await {
            Ok(()) => {}
            Err(e) => {
                libei_error.store(true, Ordering::SeqCst);
                error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .replace(e);
                // wait for termination -> otherwise we will loop forever
                future::pending::<()>().await;
            }
        }
    }
}

async fn ei_event_handler(
    events: &mut EiConvertEventStream,
    context: &ei::Context,
    devices: &Devices,
) -> Result<(), EmulationError> {
    loop {
        let event = events.next().await.ok_or(EmulationError::EndOfStream)??;
        const CAPABILITIES: &[DeviceCapability] = &[
            DeviceCapability::Pointer,
            DeviceCapability::PointerAbsolute,
            DeviceCapability::Keyboard,
            DeviceCapability::Touch,
            DeviceCapability::Scroll,
            DeviceCapability::Button,
        ];
        // The modifier masks beside each key give away case (#117).
        if !matches!(event, EiEvent::KeyboardModifiers(_)) {
            log::debug!("{event:?}");
        }
        match event {
            EiEvent::Disconnected(e) => {
                log::debug!("ei disconnected: {e:?}");
                return Err(EmulationError::EndOfStream);
            }
            EiEvent::SeatAdded(e) => {
                e.seat().bind_capabilities(CAPABILITIES);
            }
            EiEvent::SeatRemoved(e) => {
                log::debug!("seat removed: {:?}", e.seat());
            }
            EiEvent::DeviceAdded(e) => {
                let device_type = e.device().device_type();
                let name = e.device().name().unwrap_or("");
                log::debug!("device added: {device_type:?} {name:?}");
                e.device().device();
                let device = e.device();
                if let Some(pointer) = e.device().interface::<Pointer>() {
                    devices
                        .pointer
                        .write()
                        .unwrap_or_else(PoisonError::into_inner)
                        .replace((device.device().clone(), pointer));
                }
                if let Some(keyboard) = e.device().interface::<Keyboard>() {
                    devices
                        .keyboard
                        .write()
                        .unwrap_or_else(PoisonError::into_inner)
                        .replace((device.device().clone(), keyboard));
                }
                if let Some(scroll) = e.device().interface::<Scroll>() {
                    devices
                        .scroll
                        .write()
                        .unwrap_or_else(PoisonError::into_inner)
                        .replace((device.device().clone(), scroll));
                }
                if let Some(button) = e.device().interface::<Button>() {
                    devices
                        .button
                        .write()
                        .unwrap_or_else(PoisonError::into_inner)
                        .replace((device.device().clone(), button));
                }
            }
            EiEvent::DeviceRemoved(e) => {
                log::debug!("device removed: {:?}", e.device().device_type());
            }
            EiEvent::DevicePaused(e) => {
                log::debug!("device paused: {:?}", e.device().device_type());
            }
            EiEvent::DeviceResumed(e) => {
                log::debug!("device resumed: {:?}", e.device().device_type());
                e.device().device().start_emulating(0, 0);
            }
            EiEvent::KeyboardModifiers(_) => {
                log::debug!("keyboard modifiers changed");
            }
            // only for receiver context
            // EiEvent::Frame(_) => { },
            // EiEvent::DeviceStartEmulating(_) => { },
            // EiEvent::DeviceStopEmulating(_) => { },
            // EiEvent::PointerMotion(_) => { },
            // EiEvent::PointerMotionAbsolute(_) => { },
            // EiEvent::Button(_) => { },
            // EiEvent::ScrollDelta(_) => { },
            // EiEvent::ScrollStop(_) => { },
            // EiEvent::ScrollCancel(_) => { },
            // EiEvent::ScrollDiscrete(_) => { },
            // EiEvent::KeyboardKey(_) => { },
            // EiEvent::TouchDown(_) => { },
            // EiEvent::TouchUp(_) => { },
            // EiEvent::TouchMotion(_) => { },
            // A sender context is sent none of these; an EIS server that
            // does anyway is ignored, not a reason to end the daemon.
            _ => log::warn!("ignoring an ei event meant for a receiver context"),
        }
        context.flush().map_err(|e| io::Error::new(e.kind(), e))?;
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

    // LEDGER T3 | class B | 2 frames received by a stand-in EIS server from libei::ei_handshake
    /// The compositor names the virtual devices after the handshake name, and
    /// shows them to the user under it.
    #[tokio::test]
    async fn the_emulation_handshake_names_hops_to_the_compositor() {
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
            "input emulation names itself to the compositor as something other \
             than hops, so the devices it is given carry another name"
        );
        assert_eq!(context_type, eis::handshake::ContextType::Sender);
    }

    // LEDGER | behaviour | token_file_path for each environment a session may have
    /// A session started without HOME, as some service managers do, used to
    /// end the daemon when emulation asked the portal for a restore token.
    #[test]
    fn the_restore_token_needs_no_home_to_start_emulation() {
        use std::path::PathBuf;

        use super::token_file_path;

        assert_eq!(token_file_path(None, None), None);
        assert_eq!(
            token_file_path(None, Some("/home/t".into())),
            Some(PathBuf::from(
                "/home/t/.cache/lan-mouse/remote-desktop.token"
            ))
        );
        assert_eq!(
            token_file_path(Some("/c".into()), Some("/home/t".into())),
            Some(PathBuf::from("/c/lan-mouse/remote-desktop.token"))
        );
    }

    // LEDGER | behaviour | token_file_path with an empty or relative variable
    /// The XDG spec says to ignore a relative XDG_CACHE_HOME; taking it put
    /// the token under whatever directory the daemon was started in.
    #[test]
    fn a_relative_cache_dir_is_ignored() {
        use std::path::PathBuf;

        use super::token_file_path;

        let home = Some(PathBuf::from(
            "/home/t/.cache/lan-mouse/remote-desktop.token",
        ));
        assert_eq!(
            token_file_path(Some("".into()), Some("/home/t".into())),
            home
        );
        assert_eq!(
            token_file_path(Some("cache".into()), Some("/home/t".into())),
            home
        );
        assert_eq!(token_file_path(Some("".into()), None), None);
        assert_eq!(token_file_path(None, Some("".into())), None);
        assert_eq!(token_file_path(None, Some("t".into())), None);
    }
}

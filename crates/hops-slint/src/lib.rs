//! hops Slint GUI frontend (P2 — live status + device/trusted lists,
//! token-driven design system, core interactions wired).
//!
//! Mirrors the TUI's architecture: a background tokio thread owns the
//! auto-reconnecting [`hops_frontend_core::FrontendClient`], and the Slint
//! event loop (main thread) polls the observable model on a timer and pushes it
//! into the window — status fields plus the device + trusted lists as Slint
//! models. Slint components/models aren't `Send`, so the model snapshot crosses
//! threads (the client handle is `Send + Sync`) and the `VecModel`s are built on
//! the UI thread. UI callbacks send [`FrontendRequest`]s back through the client.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use hops_frontend_core::{
    ClientHandle, FrontendClient, FrontendRequest, Position, Status, TrustState, prefs, theme,
};
use hops_ipc::{DEFAULT_PORT, Geometry};
use slint::{ComponentHandle, ModelRc, VecModel};
use thiserror::Error;

slint::include_modules!();

#[cfg(target_os = "macos")]
mod macos_app;

/// A pairing prompt is "live" only this long after the last connection attempt
/// (the daemon emits no retraction); matches the TUI's `STALE_TTL`.
const STALE_TTL: Duration = Duration::from_secs(12);
/// After the user denies a pairing, snooze the prompt this long so a retrying
/// peer doesn't nag — but a later attempt re-asks; matches the TUI's `DISMISS_TTL`.
const DISMISS_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Error)]
pub enum SlintError {
    #[error("slint platform error: {0}")]
    Platform(#[from] slint::PlatformError),
    #[error("frontend client thread failed to start")]
    ClientInit,
}

/// Everything the poll loop pushes into the window, in a cheaply-comparable form.
/// Re-pushing an identical model every 250ms forces a repaint even when nothing
/// changed — which makes variable-refresh-rate (G-Sync/FreeSync) displays flicker
/// — so the poll only touches Slint when this differs from the previous tick.
/// Primitive fields because Slint's generated row structs aren't `PartialEq`.
#[derive(PartialEq)]
struct PolledUi {
    connected: bool,
    capture: String,
    emulation: String,
    port: String,
    fingerprint: String,
    pairing: String,
    /// Whether that pairing prompt came from OUR outbound dial rather than a
    /// peer connecting in (#61) — the card says which.
    pairing_from_our_dial: bool,
    /// The address that answered our dial, so the user can compare it with the
    /// one they typed (#93). Empty when unknown (every inbound attempt).
    pairing_addr: String,
    free_position: String,
    notice: String,
    notice_seq: i32,
    devices: Vec<(
        String,
        String,
        String,
        String,
        bool,
        bool,
        bool,
        String,
        String,
        bool,
        bool,
    )>,
}

fn status_text(s: Status) -> &'static str {
    match s {
        Status::Enabled => "enabled",
        Status::Disabled => "disabled",
    }
}

fn slint_color(c: theme::Rgb) -> slint::Color {
    slint::Color::from_rgb_u8(c.0, c.1, c.2)
}

/// Map a [`theme::Theme`] (Rust — the single source of truth for palette data,
/// built-in or user-authored) to the Slint-generated `ThemeColors` struct. `pub`
/// so other Slint-frontend code (e.g. the `render_png` self-review harness) can
/// populate `Theme.palettes` the same way without duplicating the field mapping.
pub fn theme_colors(t: &theme::Theme) -> ThemeColors {
    ThemeColors {
        background: slint_color(t.background),
        surface: slint_color(t.surface),
        surface_raised: slint_color(t.surface_raised),
        foreground: slint_color(t.foreground),
        muted: slint_color(t.muted),
        accent: slint_color(t.accent),
        on_accent: slint_color(t.on_accent),
        selection: slint_color(t.selection),
        border: slint_color(t.border),
        success: slint_color(t.success),
        warn: slint_color(t.warn),
        error: slint_color(t.error),
    }
}

/// First 16 hex chars of a fingerprint for a glanceable id.
fn short_fp(fp: &str) -> String {
    let head: String = fp.chars().take(16).collect();
    format!("{head}…")
}

/// A starting position for a device with no stored geometry yet, placed just
/// outside the "this Mac" anchor on its edge — matches layout_canvas.slint's
/// `CanvasSize` global (480x280 canvas, 96x64 boxes, Mac centered) so a
/// freshly opened canvas looks intentional rather than dumping everything at
/// the origin. Only ever a starting point — dragging overrides it immediately.
fn default_canvas_pos(pos: Position) -> (f32, f32) {
    match pos {
        Position::Left => (20.0, 108.0),
        Position::Right => (364.0, 108.0),
        Position::Top => (192.0, 16.0),
        Position::Bottom => (192.0, 200.0),
    }
}

/// Single-instance coordination result. A second `hops gui` launch signals the
/// first (any connection to the rendezvous = "show your window") and exits, so
/// re-launching focuses the resident menu-bar app instead of stacking duplicate
/// tray icons. The rendezvous is a Unix-domain socket on unix (per-user, scoped
/// by `~/.config` permissions) and a loopback `TcpListener` on Windows (no
/// per-user filesystem socket there; a `127.0.0.1` listener is the std-only
/// equivalent).
#[cfg(any(unix, windows))]
enum Instance {
    /// We're the first instance; the guard cleans up the rendezvous on exit.
    Primary(SingleInstanceGuard),
    /// Another instance is already running (we've signaled it).
    Secondary,
}

/// Cleans up the single-instance rendezvous on drop (normal GUI exit). Only Unix
/// leaves a filesystem artifact (the socket file); on Windows the `TcpListener`
/// closes itself, so `path` is left empty.
#[cfg(any(unix, windows))]
struct SingleInstanceGuard {
    // only Drop (unix-only) reads this; on Windows there's no socket file to
    // clean up, so the field is written-but-unread there.
    #[cfg_attr(not(unix), allow(dead_code))]
    path: std::path::PathBuf,
}

#[cfg(any(unix, windows))]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn gui_socket_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut p = std::path::PathBuf::from(home);
    p.push(".config/lan-mouse");
    let _ = std::fs::create_dir_all(&p);
    p.push("hops-gui.sock");
    Some(p)
}

/// Own the socket + spawn a thread that flips `show_requested` on every incoming
/// connection (each = a second launch asking us to surface the window).
#[cfg(unix)]
fn become_primary(
    listener: std::os::unix::net::UnixListener,
    path: std::path::PathBuf,
    show_requested: Arc<AtomicBool>,
) -> Instance {
    std::thread::spawn(move || {
        for _stream in listener.incoming() {
            show_requested.store(true, Ordering::SeqCst);
        }
    });
    Instance::Primary(SingleInstanceGuard { path })
}

/// Try to become the single running GUI instance; if one already runs, signal it.
#[cfg(unix)]
fn acquire_single_instance(show_requested: Arc<AtomicBool>) -> Instance {
    use std::os::unix::net::{UnixListener, UnixStream};
    // no socket path (no $HOME) → skip single-instance, just run
    let Some(path) = gui_socket_path() else {
        return Instance::Primary(SingleInstanceGuard {
            path: std::path::PathBuf::new(),
        });
    };
    match UnixListener::bind(&path) {
        Ok(listener) => become_primary(listener, path, show_requested),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // either a live primary, or a stale socket left by a crashed one
            if UnixStream::connect(&path).is_ok() {
                Instance::Secondary // signaled the live primary; we exit
            } else {
                let _ = std::fs::remove_file(&path); // stale — take it over
                match UnixListener::bind(&path) {
                    Ok(listener) => become_primary(listener, path, show_requested),
                    Err(_) => Instance::Primary(SingleInstanceGuard {
                        path: std::path::PathBuf::new(),
                    }),
                }
            }
        }
        // any other bind error → run anyway without single-instance
        Err(_) => Instance::Primary(SingleInstanceGuard {
            path: std::path::PathBuf::new(),
        }),
    }
}

/// Windows single-instance via a loopback `TcpListener`. Bound to `127.0.0.1`
/// only (never `0.0.0.0`), so it's a local rendezvous — not a reachable service —
/// and a loopback bind doesn't trip the Windows Firewall prompt. Any successful
/// connect from a second launch flips `show_requested`; the second launch then
/// exits. Degrades gracefully (runs without single-instance) on any bind error.
#[cfg(windows)]
fn acquire_single_instance(show_requested: Arc<AtomicBool>) -> Instance {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    // fixed high port below the ephemeral range (49152+) to avoid churn collisions
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 47842));
    match TcpListener::bind(addr) {
        Ok(listener) => {
            std::thread::spawn(move || {
                for _stream in listener.incoming() {
                    show_requested.store(true, Ordering::SeqCst);
                }
            });
            Instance::Primary(SingleInstanceGuard {
                path: std::path::PathBuf::new(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // a live primary already owns the port; poke it to surface, then exit
            if TcpStream::connect(addr).is_ok() {
                Instance::Secondary
            } else {
                Instance::Primary(SingleInstanceGuard {
                    path: std::path::PathBuf::new(),
                })
            }
        }
        // any other bind error → run anyway without single-instance
        Err(_) => Instance::Primary(SingleInstanceGuard {
            path: std::path::PathBuf::new(),
        }),
    }
}

/// Run the Slint GUI front-end. Blocks on the Slint event loop until the user
/// quits (macOS: via the menu bar "Quit"); the daemon keeps running regardless.
/// `hidden` starts with only the menu-bar/tray icon and no window (login
/// autostart); the window then opens on tray click or a second `hops gui` launch.
pub fn run(hidden: bool) -> Result<(), SlintError> {
    // A second launch surfaces the resident window rather than duplicating the
    // tray icon; the flag is flipped by the single-instance socket thread and
    // read by the poll timer (both below). Also the vehicle for "reopen".
    let show_requested = Arc::new(AtomicBool::new(false));
    #[cfg(any(unix, windows))]
    let _instance_guard = match acquire_single_instance(show_requested.clone()) {
        Instance::Secondary => return Ok(()),
        Instance::Primary(guard) => guard,
    };

    // background thread owns the tokio runtime + the IPC client
    let (tx, rx) = mpsc::channel::<FrontendClient>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let client = FrontendClient::spawn();
            let _ = tx.send(client);
            std::future::pending::<()>().await;
        });
    });
    let client = rx.recv().map_err(|_| SlintError::ClientInit)?;

    let ui = AppWindow::new()?;

    // Force the opening size to 560x690. preferred-width/height in app.slint
    // aren't enough alone: the ScrollView lets the window shrink to a tiny
    // content-min (~400x255 observed), so set the size explicitly. This is
    // SAFE only because the size is no longer locked with min==max — that
    // constant-folds the size property and set_size (or any winit resize)
    // panics "Constant property being changed" and aborts. A plain resizable
    // window's size property is mutable. Set at creation and on every show.
    ui.window().set_size(slint::LogicalSize::new(560.0, 690.0));

    // The notice banner has two sources — the daemon (FrontendEvent::Error) and
    // local input validation — so they share ONE increasing sequence. The poll
    // below only writes when the daemon's own seq changes, otherwise it would
    // overwrite a local validation message on the very next tick.
    let notice_seq: Rc<std::cell::Cell<i32>> = Rc::new(std::cell::Cell::new(0));
    let last_daemon_notice: Rc<std::cell::Cell<i32>> = Rc::new(std::cell::Cell::new(0));
    let notice_sink = {
        let weak = ui.as_weak();
        let seq = notice_seq.clone();
        move |msg: &str| {
            if let Some(ui) = weak.upgrade() {
                seq.set(seq.get().wrapping_add(1));
                ui.set_notice(msg.into());
                ui.set_notice_seq(seq.get());
            }
        }
    };
    // Set on every show; cleared by the rendering notifier below when a frame
    // actually reaches the screen. Lets the log distinguish "the window was
    // shown" from "the window was drawn" — which is the whole of #30.
    let awaiting_paint = Rc::new(std::cell::Cell::new(false));
    {
        let awaiting = awaiting_paint.clone();
        let notifier = ui.window().set_rendering_notifier(move |state, _| {
            if matches!(state, slint::RenderingState::AfterRendering) && awaiting.replace(false) {
                log::info!("window: painted a frame after show");
            }
        });
        if let Err(e) = notifier {
            log::debug!("this renderer has no rendering notifier: {e}");
        }
    }

    /// Show the window AND make sure something is actually drawn in it.
    ///
    /// `show()` alone is not enough. It goes to `set_visible(true)` ->
    /// `WindowVisibility::Shown`, and Slint's winit backend only pre-renders a
    /// frame for `ShownFirstTime`. A window created early and first shown much
    /// later — exactly what `--hidden` login autostart does, then opening from
    /// the tray hours afterwards — misses winit's one initial RedrawRequested
    /// and **maps blank**: correct size, correct layout, nothing painted, the
    /// desktop showing through. Dragging the corner "fixed" it only because a
    /// resize reaches the renderer by a different path.
    ///
    /// Slint hit this themselves and patched it for iOS, with a comment saying
    /// as much (winitwindowadapter.rs, `#[cfg(ios_and_friends)] request_redraw`).
    /// macOS is not in that cfg. This is the same one-line remedy.
    fn show_app_window(
        ui: &AppWindow,
        awaiting_paint: &std::cell::Cell<bool>,
    ) -> Result<(), slint::PlatformError> {
        ui.window().set_size(slint::LogicalSize::new(560.0, 690.0));
        ui.show()?;
        awaiting_paint.set(true);
        ui.window().request_redraw();
        Ok(())
    }

    // theme is a UI-local preference shared with the TUI. Rust owns the palette
    // DATA (built-ins + any user themes in ~/.config/lan-mouse/themes/*.toml) —
    // push the whole table into the GUI once, then just flip the index to switch.
    let themes = Rc::new(theme::all_themes());
    ui.global::<Theme>()
        .set_palettes(ModelRc::new(VecModel::from(
            themes.iter().map(theme_colors).collect::<Vec<_>>(),
        )));
    let theme_name = theme::load_name().unwrap_or_else(|| theme::default_theme().name.to_string());
    ui.global::<Theme>()
        .set_index(theme::index_of(&themes, &theme_name) as i32);

    // fingerprints the user has denied -> when (UI-local snooze; see DISMISS_TTL).
    // Shared between the deny callback and the poll loop, both on the UI thread.
    let dismissed: Rc<RefCell<HashMap<String, Instant>>> = Rc::new(RefCell::new(HashMap::new()));

    // --- wire UI actions -> FrontendRequests (each closure owns a client clone) ---
    {
        let c = client.clone();
        ui.on_enable_input(move || {
            c.request(FrontendRequest::EnableCapture);
            c.request(FrontendRequest::EnableEmulation);
        });
    }
    {
        let c = client.clone();
        ui.on_activate_device(move |handle, active| {
            if let Ok(h) = handle.as_str().parse::<u64>() {
                c.request(FrontendRequest::Activate(h, active));
            }
        });
    }
    {
        let c = client.clone();
        ui.on_reposition_device(move |handle, position| {
            if let Ok(h) = handle.as_str().parse::<u64>() {
                let pos = Position::try_from(position.as_str()).unwrap_or_default();
                c.request(FrontendRequest::UpdatePosition(h, pos));
            }
        });
    }
    {
        let c = client.clone();
        // `id` is the row's stable key: a ClientHandle for a device we dial,
        // otherwise the peer's fingerprint. A receive-only trusted peer has no
        // handle, so keying this on the handle alone meant the parse failed and
        // the rename silently did nothing — which is why the GUI could not name
        // an inbound peer at all while the TUI could.
        ui.on_rename_device(move |id, name| {
            let name = name.trim();
            if let Ok(h) = id.as_str().parse::<u64>() {
                let name = (!name.is_empty()).then(|| name.to_string());
                c.request(FrontendRequest::UpdateHostname(h, name));
                return;
            }
            // A rename is a rename. This used to re-send AuthorizeKey, so the
            // wire could not tell relabelling from granting trust; SetLabel
            // refuses a fingerprint that is not already authorized.
            let desc = if name.is_empty() {
                hops_frontend_core::fallback_label(id.as_str())
            } else {
                name.to_string()
            };
            c.request(FrontendRequest::SetLabel(id.to_string(), desc));
        });
    }
    {
        let c = client.clone();
        ui.on_delete_device(move |handle| {
            if let Ok(h) = handle.as_str().parse::<u64>() {
                c.request(FrontendRequest::Delete(h));
            }
        });
    }
    {
        let c = client.clone();
        ui.on_revoke(move |fp| {
            c.request(FrontendRequest::RemoveAuthorizedKey(fp.to_string()));
        });
    }
    {
        let c = client.clone();
        ui.on_approve_pairing(move |name, fp| {
            let desc = if name.trim().is_empty() {
                hops_frontend_core::fallback_label(fp.as_str())
            } else {
                name.trim().to_string()
            };
            c.request(FrontendRequest::AuthorizeKey(desc, fp.to_string()));
        });
    }
    {
        let dismissed = dismissed.clone();
        ui.on_deny_pairing(move |fp| {
            dismissed
                .borrow_mut()
                .insert(fp.to_string(), Instant::now());
        });
    }
    {
        // theme swatch picker: set the live palette + persist (shared with the TUI)
        let weak = ui.as_weak();
        let themes = themes.clone();
        ui.on_set_theme(move |i| {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Theme>().set_index(i);
            if let Some(t) = themes.get(i as usize) {
                theme::save_name(&t.name);
            }
        });
    }
    {
        ui.on_switch_interface(move || {
            let err = prefs::switch_to(prefs::Frontend::Tui);
            // only reached if the exec failed — a successful switch never returns
            log::warn!("could not switch to the terminal interface: {err}");
        });
    }

    // A device the user just asked to create, awaiting the handle the daemon
    // assigns (Create is fire-and-forget; the handle only appears once the
    // resulting `Created` event reaches the next snapshot). Applied by the poll
    // loop below as soon as a handle absent from `known_handles` shows up.
    let pending_new_device: Rc<RefCell<Option<(String, u16, Position)>>> =
        Rc::new(RefCell::new(None));
    let known_handles: Rc<RefCell<HashSet<ClientHandle>>> = Rc::new(RefCell::new(HashSet::new()));
    {
        let c = client.clone();
        let pending = pending_new_device.clone();
        let notice = notice_sink.clone();
        ui.on_create_device(move |name, port, position| {
            let name = name.trim().to_string();
            // An empty name produced a permanent "unnamed device / unresolved"
            // ghost card that could never connect — reachable by a stray
            // double-click, since the primary button was always live.
            if name.is_empty() {
                notice("Enter the other machine's hostname or IP address.");
                return;
            }
            // A port that does not parse was silently replaced with 4242, and the
            // panel closed as if obeyed. Port 0 was accepted and could never
            // connect. Say so instead of quietly substituting.
            let port_raw = port.trim();
            let port = if port_raw.is_empty() {
                DEFAULT_PORT
            } else {
                match port_raw.parse::<u16>() {
                    Ok(p) if p > 0 => p,
                    _ => {
                        notice(
                            "That port is not valid. Use a number from 1 to 65535, \
                             or leave it blank for the default.",
                        );
                        return;
                    }
                }
            };
            let position = Position::try_from(position.as_str()).unwrap_or_default();
            *pending.borrow_mut() = Some((name, port, position));
            c.request(FrontendRequest::Create);
        });
    }
    {
        // Snapshot device positions into canvas-boxes ONCE, here, rather than
        // feeding them from the regular poll loop — see layout_canvas.slint's
        // header note on why a live-updated model would fight an in-progress drag.
        let c = client.clone();
        let weak = ui.as_weak();
        ui.on_open_layout_canvas(move || {
            let Some(ui) = weak.upgrade() else { return };
            let m = c.snapshot();
            let boxes: Vec<CanvasBox> = m
                .clients
                .iter()
                .map(|(h, (cfg, _))| {
                    let (x, y) = cfg
                        .geometry
                        .map(|g| (g.x as f32, g.y as f32))
                        .unwrap_or_else(|| default_canvas_pos(cfg.pos));
                    CanvasBox {
                        handle: h.to_string().into(),
                        name: cfg
                            .hostname
                            .clone()
                            .unwrap_or_else(|| "unnamed".into())
                            .into(),
                        x,
                        y,
                    }
                })
                .collect();
            ui.set_canvas_boxes(ModelRc::new(VecModel::from(boxes)));
            ui.set_show_layout_canvas(true);
        });
    }
    {
        let c = client.clone();
        ui.on_update_device_geometry(move |handle, x, y| {
            if let Ok(h) = handle.as_str().parse::<u64>() {
                let geometry = Geometry {
                    x: x.round() as i32,
                    y: y.round() as i32,
                    width: 96,
                    height: 64,
                };
                c.request(FrontendRequest::UpdateGeometry(h, Some(geometry)));
            }
        });
    }

    // poll the model ~4x/sec and push it into the window — but only when it
    // actually changed since last tick (see PolledUi: a constant repaint flickers
    // VRR displays). `last_ui` holds the previous pushed state.
    let weak = ui.as_weak();
    let show_requested_poll = show_requested.clone();
    let awaiting_paint_poll = awaiting_paint.clone();
    let last_ui: RefCell<Option<PolledUi>> = RefCell::new(None);
    let timer = slint::Timer::default();
    let notice_seq_poll = notice_seq.clone();
    let last_daemon_notice = last_daemon_notice.clone();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(250),
        move || {
            let Some(ui) = weak.upgrade() else { return };

            // a second `hops gui` launch (or the tray on some paths) asked us to
            // surface the window — do it on the UI thread, here.
            if show_requested_poll.swap(false, Ordering::SeqCst) {
                // via the helper, NOT a bare show(): this was the one show path
                // of three that did not re-assert the size, so surfacing the
                // window from a second `hops gui` launch left it at whatever
                // size the layout happened to compute. See #30.
                let _ = show_app_window(&ui, &awaiting_paint_poll);
                #[cfg(target_os = "macos")]
                macos_app::activate_app();
            }

            let m = client.snapshot();

            // apply a pending create's name/port/position once its handle shows up
            {
                let current: HashSet<ClientHandle> = m.clients.keys().copied().collect();
                if let Some((name, port, position)) = pending_new_device.borrow_mut().take() {
                    match current.difference(&known_handles.borrow()).next() {
                        Some(&new_handle) => {
                            if !name.is_empty() {
                                client.request(FrontendRequest::UpdateHostname(
                                    new_handle,
                                    Some(name),
                                ));
                            }
                            client.request(FrontendRequest::UpdatePort(new_handle, port));
                            client.request(FrontendRequest::UpdatePosition(new_handle, position));
                            // ACTUALLY try the machine. Previously "add device"
                            // created an inert card: nothing was dialed, the other
                            // machine showed nothing, and two unnamed steps stood
                            // between "added" and "works" (find the unlabeled
                            // toggle, then shove the cursor off that edge). The
                            // form now opens on a free edge, so this cannot evict
                            // another device, and a name that will not resolve
                            // now reports itself.
                            client.request(FrontendRequest::Activate(new_handle, true));
                        }
                        // the Created event hasn't reached a snapshot yet — retry next tick
                        None => *pending_new_device.borrow_mut() = Some((name, port, position)),
                    }
                }
                *known_handles.borrow_mut() = current;
            }

            // --- Build the derived UI state, then push to Slint ONLY if it
            // changed since last tick. Re-pushing an identical model every 250ms
            // repaints the window constantly (flickering VRR displays); when
            // nothing changed we touch nothing and the window stays static.

            // a live pairing prompt: untrusted, still actively attempting (not a
            // stale prompt for a peer that left), and not currently snooze-dismissed
            let pairing = m
                .pending_pairing
                .as_ref()
                .filter(|fp| {
                    !m.authorized.contains_key(*fp)
                        && m.pending_pairing_since
                            .map(|t| t.elapsed() < STALE_TTL)
                            .unwrap_or(false)
                        && dismissed
                            .borrow()
                            .get(*fp)
                            .map(|t| t.elapsed() >= DISMISS_TTL)
                            .unwrap_or(true)
                })
                .cloned()
                .unwrap_or_default();
            let pairing_addr = if pairing.is_empty() {
                String::new()
            } else {
                m.pending_pairing_addr
                    .map(|a| a.to_string())
                    .unwrap_or_default()
            };
            let pairing_from_our_dial = !pairing.is_empty()
                && m.pending_pairing_origin
                    == Some(hops_frontend_core::AttemptOrigin::OutboundDial);

            // unified device view: one row per physical peer. AppModel::devices()
            // joins the outgoing clients with the trusted-fingerprint set by
            // identity (already sorted: send-facet devices by handle, then
            // receive-only by label). Filter out a bare inbound pairing request
            // (no send facet, not yet trusted) — it lives in the pairing banner
            // above, not the list.
            let devices: Vec<DeviceRow> = m
                .devices()
                .into_iter()
                .filter(|d| d.is_listable())
                .map(|d| {
                    let (handle, addr, pos, active, alive, has_send) = match &d.send {
                        Some(s) => {
                            let addr = s
                                .state
                                .active_addr
                                .map(|a| a.to_string())
                                .or_else(|| {
                                    s.config
                                        .fix_ips
                                        .first()
                                        .map(|ip| format!("{ip}:{}", s.config.port))
                                })
                                .or_else(|| {
                                    s.state
                                        .ips
                                        .iter()
                                        .next()
                                        .map(|ip| format!("{ip}:{}", s.config.port))
                                })
                                .unwrap_or_else(|| "unresolved".into());
                            (
                                s.handle.to_string(),
                                addr,
                                s.config.pos.to_string(),
                                s.state.active,
                                s.state.alive,
                                true,
                            )
                        }
                        None => (
                            String::new(),
                            String::new(),
                            String::new(),
                            false,
                            false,
                            false,
                        ),
                    };
                    DeviceRow {
                        handle: handle.into(),
                        name: d.label.clone().into(),
                        addr: addr.into(),
                        pos: pos.into(),
                        active,
                        alive,
                        has_send,
                        fingerprint: d
                            .fingerprint
                            .as_deref()
                            .map(short_fp)
                            .unwrap_or_default()
                            .into(),
                        fp_full: d.fingerprint.clone().unwrap_or_default().into(),
                        online: d.online,
                        trusted: d.receive,
                        revoked: d.trust == TrustState::Revoked,
                    }
                })
                .collect();

            let snap = PolledUi {
                connected: m.connected,
                capture: status_text(m.capture).to_string(),
                emulation: status_text(m.emulation).to_string(),
                port: m
                    .port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".to_string()),
                fingerprint: m.fingerprint.clone().unwrap_or_else(|| "—".to_string()),
                pairing,
                pairing_from_our_dial,
                pairing_addr,
                // the first edge nothing active is already using, so adding a
                // second device does not silently switch off the first
                free_position: ["left", "right", "top", "bottom"]
                    .into_iter()
                    .find(|p| {
                        !devices
                            .iter()
                            .any(|d| d.has_send && d.active && d.pos.as_str() == *p)
                    })
                    .unwrap_or("left")
                    .to_string(),
                notice: m.latest_message().unwrap_or_default().to_string(),
                // i32 is Slint's integer; the seq only needs to CHANGE, not be exact
                notice_seq: (m.message_seq % (i32::MAX as u64)) as i32,
                devices: devices
                    .iter()
                    .map(|d| {
                        (
                            d.handle.to_string(),
                            d.name.to_string(),
                            d.addr.to_string(),
                            d.pos.to_string(),
                            d.active,
                            d.alive,
                            d.has_send,
                            d.fingerprint.to_string(),
                            d.fp_full.to_string(),
                            d.online,
                            d.trusted,
                        )
                    })
                    .collect(),
            };

            // Unchanged since last tick → leave the window entirely alone (no
            // property writes, no model swap → Slint has nothing to repaint).
            if last_ui.borrow().as_ref() == Some(&snap) {
                return;
            }

            ui.set_connected(snap.connected);
            ui.set_capture(snap.capture.as_str().into());
            ui.set_emulation(snap.emulation.as_str().into());
            ui.set_port(snap.port.as_str().into());
            ui.set_fingerprint(snap.fingerprint.as_str().into());
            ui.set_pairing_fp(snap.pairing.as_str().into());
            ui.set_pairing_from_our_dial(snap.pairing_from_our_dial);
            ui.set_pairing_addr(snap.pairing_addr.as_str().into());
            // only when the DAEMON has something new — otherwise a local
            // validation notice would be overwritten on the next poll
            if snap.notice_seq != last_daemon_notice.get() {
                last_daemon_notice.set(snap.notice_seq);
                if !snap.notice.is_empty() {
                    notice_seq_poll.set(notice_seq_poll.get().wrapping_add(1));
                    ui.set_free_position(snap.free_position.as_str().into());
                    ui.set_notice(snap.notice.as_str().into());
                    ui.set_notice_seq(notice_seq_poll.get());
                }
            }
            ui.set_devices(ModelRc::new(VecModel::from(devices)));
            *last_ui.borrow_mut() = Some(snap);
        },
    );

    // The menu-bar / system-tray icon (native on every platform via Slint 1.17).
    // A visible tray keeps the event loop alive even with no window shown, so the
    // app can start `--hidden` (tray only) and reopen its window on demand — the
    // reason we run `run_event_loop_until_quit()` (quit only on the tray's "Quit")
    // instead of the generated `ui.run()`, which exits the moment the last window
    // hides. Keep the tray alive for the whole session (dropping it removes the
    // icon), so bind it to a name that lives until the function returns.
    let tray = HopsTray::new()?;
    {
        // "Open hops" (menu) and, on Windows/Linux, a left-click of the icon (the
        // builtin `clicked`, forwarded to `open-window` in tray.slint) both surface
        // the window.
        let weak = ui.as_weak();
        let awaiting_paint_tray = awaiting_paint.clone();
        tray.on_open_window(move || {
            if let Some(ui) = weak.upgrade() {
                let _ = show_app_window(&ui, &awaiting_paint_tray);
                #[cfg(target_os = "macos")]
                macos_app::activate_app();
            }
        });
        tray.on_quit(|| {
            // stops run_event_loop_until_quit(), letting run() return + the process exit
            let _ = slint::quit_event_loop();
        });
    }

    // Menu-bar-only app on macOS: no Dock icon / Cmd-Tab entry, so `--hidden`
    // login-autostart is truly just the tray. Must precede showing any window.
    #[cfg(target_os = "macos")]
    macos_app::set_accessory_policy();

    // `hidden` (login autostart) starts as tray only; the window opens on
    // tray-click / "Open hops" / a second launch. Manual launches show it now.
    if !hidden {
        show_app_window(&ui, &awaiting_paint)?;
    }
    tray.show()?;
    // This records INTENT, not outcome — it prints identically whether the icon
    // appears or not, so do not read it as "the tray is up".
    //
    // Slint reports a FAILED platform status item only through its own
    // debug_log and never retries; the process then lives on with no icon,
    // still holding the single-instance socket, so a later `hops gui` merely
    // signals an invisible primary (#43). Its handler is `#[doc(hidden)]` and
    // `SlintContext` is not re-exported, so we cannot observe the failure
    // without reaching into slint internals. What we CAN rely on: with no
    // `log` feature on i-slint-core, debug_log falls through to stderr, which
    // launchd sends to this same file. So the diagnostic pair is
    //   this line + "Failed to create system tray icon"  -> the icon failed
    //   this line + no icon + no such error              -> something else
    //   no line at all                                   -> died before asking
    log::info!("tray: requesting the platform status item");
    slint::run_event_loop_until_quit()?;

    ui.hide().ok();
    tray.hide().ok();
    drop(timer);
    Ok(())
}

/// Show the first-run "choose your interface" screen and block until the user
/// picks one (or closes the window, in which case `Ok(None)` — the caller should
/// treat that as "ask again next launch" rather than assuming a default, since
/// closing isn't the same as choosing).
pub fn run_onboarding() -> Result<Option<hops_frontend_core::prefs::Frontend>, SlintError> {
    use hops_frontend_core::prefs::Frontend;

    let ui = OnboardingWindow::new()?;

    let themes = theme::all_themes();
    ui.global::<Theme>()
        .set_palettes(ModelRc::new(VecModel::from(
            themes.iter().map(theme_colors).collect::<Vec<_>>(),
        )));
    let theme_name = theme::load_name().unwrap_or_else(|| theme::default_theme().name.to_string());
    ui.global::<Theme>()
        .set_index(theme::index_of(&themes, &theme_name) as i32);

    let choice: Rc<RefCell<Option<Frontend>>> = Rc::new(RefCell::new(None));
    {
        let choice = choice.clone();
        let weak = ui.as_weak();
        ui.on_choose_gui(move || {
            *choice.borrow_mut() = Some(Frontend::Gui);
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
        });
    }
    {
        let choice = choice.clone();
        let weak = ui.as_weak();
        ui.on_choose_tui(move || {
            *choice.borrow_mut() = Some(Frontend::Tui);
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
        });
    }

    // Force the opening size (preferred alone isn't reliable — see the main
    // window's note); safe because onboarding.slint no longer min==max-locks it.
    ui.window().set_size(slint::LogicalSize::new(580.0, 470.0));
    ui.run()?;
    let picked = *choice.borrow();
    Ok(picked)
}

#[cfg(test)]
mod tray_const_property {
    /// The tray must never let the Slint compiler const-fold `visible`.
    ///
    /// If it does, the generated `HopsTray::hide()` writes a constant property,
    /// i-slint-core panics "Constant property being changed", and `panic =
    /// "abort"` turns that into SIGABRT for the whole tray app — the two aborts
    /// in gui.log, and issue #4.
    ///
    /// This asserts on the GENERATED code rather than by calling `hide()`,
    /// deliberately: constructing a real `SystemTrayIcon` needs a live platform
    /// backend, so a behavioural test could not run on a headless CI box — and
    /// a guard that does not run in CI is how this shipped in the first place.
    /// `examples/tray_hide_repro.rs` is the behavioural check, for a machine
    /// with a desktop.
    #[test]
    fn tray_visible_is_not_const_folded() {
        let generated = std::fs::read_to_string(concat!(env!("OUT_DIR"), "/app.rs"))
            .expect("the slint build script must have generated app.rs");

        // narrow to the tray's own init, so an unrelated component's constant
        // `visible` cannot mask a regression here
        let start = generated
            .find("impl InnerHopsTray")
            .expect("generated code should contain InnerHopsTray");
        let body = &generated[start..];
        let end = body.find("impl ").map(|i| i + 5).unwrap_or(0);
        let init = &body[..body[end..]
            .find("\n    impl ")
            .map_or(body.len(), |i| end + i)];

        let offending: Vec<&str> = init
            .lines()
            .filter(|l| l.contains("r#visible") && l.contains("set_constant"))
            .collect();

        assert!(
            offending.is_empty(),
            "HopsTray::visible is const-folded again — hide() will abort the app (#4). \
             Re-bind it in ui/tray.slint (`in-out property <bool> shown: true; visible: root.shown;`). \
             Offending generated line(s): {offending:?}"
        );
    }
}

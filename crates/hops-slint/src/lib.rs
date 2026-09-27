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
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use hops_frontend_core::{
    AppModel, ApprovalRefused, CaptureState, ClientHandle, Clipboard, FrontendClient,
    FrontendRequest, Launch, PairingAttempt, PairingCard, PairingCheck, Position, Status, Tone,
    prefs, spaced_number, theme,
};
use hops_ipc::{DEFAULT_PORT, Geometry};
use slint::{ComponentHandle, ModelRc, VecModel};
use thiserror::Error;

slint::include_modules!();

#[cfg(target_os = "macos")]
mod macos_app;
mod privacy;

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
/// Slint's generated row structs derive `PartialEq`, so the rows are kept as
/// the window gets them rather than copied field by field.
#[derive(PartialEq)]
struct PolledUi {
    connected: bool,
    capture: String,
    /// Why capture, which should run, does not, from
    /// `AppModel::capture_problem`, or empty (#91).
    capture_problem: String,
    /// Whether the window offers the setting that mends it (#169).
    capture_settings: bool,
    emulation: String,
    port: String,
    fingerprint: String,
    pairing: String,
    /// Machines announcing themselves on the LAN that are not already added or
    /// trusted. Not devices and not identities (#136).
    discovered: Vec<DiscoveredRow>,
    /// Whether hops is looking at all — see `AppModel::discovery_active`.
    discovery_active: bool,
    /// What the network section says while it lists nobody.
    discovery_empty: String,
    /// Whether that pairing prompt came from OUR outbound dial rather than a
    /// peer connecting in (#61) — the card says which.
    pairing_from_our_dial: bool,
    /// The address that answered our dial, so the user can compare it with the
    /// one they typed (#93). Empty when unknown (every inbound attempt).
    pairing_addr: String,
    /// What the card for our own dial says: which device added here it
    /// dialled (#93). Empty for a knock.
    pairing_dialled: String,
    free_position: String,
    /// Seconds left in the pairing window, 0 when closed (#195).
    pairing_seconds: i32,
    /// The number card (#11, #167), empty fingerprint when there is none.
    check: CheckUi,
    notice: String,
    notice_seq: i32,
    /// What is wrong with the service, from `AppModel::service_problem`, or
    /// empty.
    service_problem: String,
    /// The rows exactly as the window gets them, so the gate compares every
    /// field a row shows and cannot drift from it (#172).
    devices: Vec<DeviceRow>,
}

/// The number card as the window gets it.
#[derive(Debug, Default, PartialEq)]
struct CheckUi {
    fp: String,
    from: String,
    /// This machine shows the number and confirms; otherwise it picks.
    show: bool,
    number: String,
    choices: Vec<String>,
    answered: bool,
}

/// The number card for the oldest open check in `m`, if any.
fn check_ui(m: &AppModel) -> CheckUi {
    let Some(card) = m.pairing_check() else {
        return CheckUi::default();
    };
    let (show, number, choices) = match &card.check {
        PairingCheck::Show(n) => (true, spaced_number(n), Vec::new()),
        PairingCheck::Pick(c) => (
            false,
            String::new(),
            c.iter().map(|n| spaced_number(n)).collect(),
        ),
    };
    CheckUi {
        fp: card.fingerprint.clone(),
        from: card.from(),
        show,
        number,
        choices,
        answered: card.answered,
    }
}

/// Put the number card in the window.
fn show_check(ui: &AppWindow, check: &CheckUi) {
    ui.set_check_fp(check.fp.as_str().into());
    ui.set_check_from(check.from.as_str().into());
    ui.set_check_show(check.show);
    ui.set_check_number(check.number.as_str().into());
    ui.set_check_choices(ModelRc::new(VecModel::from(
        check
            .choices
            .iter()
            .map(|n| slint::SharedString::from(n.as_str()))
            .collect::<Vec<_>>(),
    )));
    ui.set_check_answered(check.answered);
}

/// The request answering the number card on screen for `fingerprint` with
/// `number`, if that card is still the one the model holds.
fn check_answer(m: &AppModel, fingerprint: &str, number: &str) -> Option<FrontendRequest> {
    m.pairing_checks
        .iter()
        .find(|c| c.fingerprint == fingerprint && !c.answered)
        .map(|c| c.answer(number))
}

/// Whether an action armed on `handle` (as the UI holds it) with `pin` no
/// longer names the device it was armed on. Only a device handle can go stale
/// this way: an empty handle is nothing armed, and a receive-only row is keyed
/// by its fingerprint, which does not change under it.
fn armed_is_stale(m: &hops_frontend_core::AppModel, handle: &str, pin: &str) -> bool {
    let Ok(handle) = handle.parse::<ClientHandle>() else {
        return false;
    };
    !m.still_names(handle, (!pin.is_empty()).then_some(pin))
}

/// Unified device view: one row per physical peer. AppModel::devices()
/// joins the outgoing clients with the trusted-fingerprint set by
/// identity (already sorted: send-facet devices by handle, then
/// receive-only by label). Filter out a bare inbound pairing request
/// (no send facet, not yet trusted) — it lives in the pairing banner
/// above, not the list.
fn device_rows(m: &AppModel) -> Vec<DeviceRow> {
    m.devices()
        .into_iter()
        .filter(|d| d.is_listable())
        .map(|d| {
            let clipboard = d.fingerprint.as_deref().and_then(|fp| m.clipboard(fp));
            let (handle, addr, pos, active, has_send) = match &d.send {
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
                        true,
                    )
                }
                None => (String::new(), String::new(), String::new(), false, false),
            };
            DeviceRow {
                handle: handle.into(),
                name: d.label.clone().into(),
                addr: addr.into(),
                pos: pos.into(),
                active,
                tone: dot_tone(d.connection.tone()),
                status: d.connection.words().into(),
                has_send,
                fingerprint: d
                    .fingerprint
                    .as_deref()
                    .map(short_fp)
                    .unwrap_or_default()
                    .into(),
                fp_full: d.fingerprint.clone().unwrap_or_default().into(),
                pin: d
                    .send
                    .as_ref()
                    .and_then(|s| s.state.peer_fingerprint.clone())
                    .unwrap_or_default()
                    .into(),
                trusted: d.receive,
                clipboard: clipboard.map(clipboard_words).unwrap_or_default().into(),
                clipboard_on: clipboard.is_some_and(|c| c.is_on()),
            }
        })
        .collect()
}

/// The window's dot tone for a state's tone: the state is derived once, in
/// hops-frontend-core, for both frontends (#148).
pub fn dot_tone(tone: Tone) -> DotTone {
    match tone {
        Tone::Good => DotTone::Good,
        Tone::Warn => DotTone::Warn,
        Tone::Bad => DotTone::Bad,
        Tone::Quiet => DotTone::Quiet,
    }
}

/// What one poll tick puts in the window, from `m` and the request the
/// pairing card picked, `shown`.
fn polled_ui(m: &AppModel, shown: Option<&PairingAttempt>, now: Instant) -> PolledUi {
    let pairing = shown.map(|a| a.fingerprint.clone()).unwrap_or_default();
    let pairing_addr = shown
        .and_then(|a| a.addr)
        .map(|a| a.to_string())
        .unwrap_or_default();
    let pairing_from_our_dial =
        shown.is_some_and(|a| a.origin == hops_frontend_core::AttemptOrigin::OutboundDial);
    let pairing_dialled = shown
        .filter(|_| pairing_from_our_dial)
        .map(|a| hops_frontend_core::our_dial_words(&m.dialled(a)))
        .unwrap_or_default();
    let devices = device_rows(m);
    PolledUi {
        connected: m.connected,
        capture: capture_text(&m.capture).to_string(),
        capture_problem: m.capture_problem().unwrap_or_default(),
        capture_settings: cfg!(target_os = "macos") && privacy::for_capture(&m.capture).is_some(),
        emulation: status_text(m.emulation).to_string(),
        port: m
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string()),
        fingerprint: m.fingerprint.clone().unwrap_or_else(|| "—".to_string()),
        pairing,
        discovery_active: m.discovery_active,
        discovery_empty: discovery_empty(m.discovery_quiet).to_string(),
        discovered: m
            .discovered
            .iter()
            .map(|d| {
                let ips: Vec<String> = d.addrs.iter().map(|a| a.ip().to_string()).collect();
                DiscoveredRow {
                    label: d.label.as_str().into(),
                    fingerprint: d
                        .claimed_fingerprint
                        .as_deref()
                        .map(short_fp)
                        .unwrap_or_default()
                        .into(),
                    addr_summary: match ips.len() {
                        0 => String::new(),
                        1 => ips[0].clone(),
                        n => format!("{} +{} more", ips[0], n - 1),
                    }
                    .into(),
                    ips: ips.join(",").into(),
                    port: d
                        .addrs
                        .first()
                        .map(|a| a.port().to_string())
                        .unwrap_or_default()
                        .into(),
                }
            })
            .collect(),
        pairing_from_our_dial,
        pairing_addr,
        pairing_dialled,
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
        pairing_seconds: m
            .pairing_seconds_left(now)
            .map_or(0, |s| s.min(i32::MAX as u64) as i32),
        check: check_ui(m),
        // Errors only: the activity log also records a cursor entering, and
        // the banner is red (#150).
        notice: m.latest_error().unwrap_or_default().to_string(),
        // i32 is Slint's integer; the seq only needs to CHANGE, not be exact
        notice_seq: (m.error_seq % (i32::MAX as u64)) as i32,
        service_problem: m.service_problem().unwrap_or_default(),
        devices,
    }
}

/// What the poll last put in the window.
#[derive(Default)]
struct Repaint {
    /// The state last pushed. A tick that builds the same leaves the window
    /// alone.
    last: Option<PolledUi>,
    /// The daemon's notice sequence last shown. The banner has a second
    /// source, local validation, so only a new daemon notice may replace what
    /// it shows.
    daemon_notice: i32,
}

impl Repaint {
    /// Put `snap` in `ui`, unless it is what the last push put there. Returns
    /// whether anything was written. `notice_seq` is the banner's sequence,
    /// shared with local notices.
    fn push(&mut self, ui: &AppWindow, snap: PolledUi, notice_seq: &Cell<i32>) -> bool {
        // Unchanged since last tick → leave the window entirely alone (no
        // property writes, no model swap → Slint has nothing to repaint).
        if self.last.as_ref() == Some(&snap) {
            return false;
        }

        ui.set_connected(snap.connected);
        ui.set_service_problem(snap.service_problem.as_str().into());
        ui.set_capture(snap.capture.as_str().into());
        ui.set_capture_problem(snap.capture_problem.as_str().into());
        ui.set_capture_settings(snap.capture_settings);
        ui.set_emulation(snap.emulation.as_str().into());
        ui.set_port(snap.port.as_str().into());
        ui.set_fingerprint(snap.fingerprint.as_str().into());
        show_pairing_card(ui, &snap.pairing);
        ui.set_discovered(ModelRc::new(VecModel::from(snap.discovered.clone())));
        ui.set_discovery_active(snap.discovery_active);
        ui.set_discovery_empty(snap.discovery_empty.as_str().into());
        ui.set_pairing_from_our_dial(snap.pairing_from_our_dial);
        ui.set_pairing_addr(snap.pairing_addr.as_str().into());
        ui.set_pairing_dialled(snap.pairing_dialled.as_str().into());
        ui.set_pairing_seconds(snap.pairing_seconds);
        show_check(ui, &snap.check);
        // Every tick that changed, not only one with a new notice: the free
        // edge follows the devices, and a new device placed on an edge in use
        // switches the other one off (#32).
        ui.set_free_position(snap.free_position.as_str().into());
        // only when the DAEMON has something new — otherwise a local
        // validation notice would be overwritten on the next poll
        if snap.notice_seq != self.daemon_notice {
            self.daemon_notice = snap.notice_seq;
            if !snap.notice.is_empty() {
                notice_seq.set(notice_seq.get().wrapping_add(1));
                ui.set_notice(snap.notice.as_str().into());
                ui.set_notice_seq(notice_seq.get());
            }
        }
        ui.set_devices(ModelRc::new(VecModel::from(snap.devices.clone())));
        self.last = Some(snap);
        true
    }
}

/// What the network section says while it lists nobody. Once discovery has
/// heard no machine at all for a while, a Mac names the setting that keeps a
/// process from hearing its network with no error (#149); elsewhere nothing
/// is known to do that silently.
fn discovery_empty(quiet: bool) -> &'static str {
    if quiet && cfg!(target_os = "macos") {
        "No other machine has answered. If one on this network runs hops, check that \
         hops is on under System Settings → Privacy & Security → Local Network."
    } else {
        "looking — no other machines yet. They need hops running and to be on this network."
    }
}

/// Capture's state as the window reads it: failed is not off (#91).
fn capture_text(s: &CaptureState) -> &'static str {
    match s {
        CaptureState::Enabled => status_text(Status::Enabled),
        CaptureState::Disabled => status_text(Status::Disabled),
        CaptureState::Failed(_) => "failed",
    }
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

/// What the edit panel says under "clipboard", beside its switch (#182).
fn clipboard_words(c: Clipboard) -> &'static str {
    match c {
        Clipboard::BothWays => "shared both ways",
        Clipboard::FromIt => "arrives here from this device",
        Clipboard::ToIt => "goes from here to this device",
        Clipboard::Off => "off",
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
/// first ("show your window") and exits, so re-launching focuses the resident
/// menu-bar app instead of stacking duplicate tray icons. The rendezvous is a
/// Unix-domain socket on unix (per-user, scoped by `~/.config` permissions)
/// and, on Windows, a named event in the session's `Local\` namespace that
/// grants this user alone ([`hops_ipc::instance`]).
#[cfg(any(unix, windows))]
enum Instance {
    /// We're the first instance; the guard cleans up the rendezvous on exit.
    Primary(SingleInstanceGuard),
    /// Another instance is already running (we've signaled it).
    Secondary,
}

/// Cleans up the single-instance rendezvous on drop (normal GUI exit). Only Unix
/// leaves a filesystem artifact (the socket file). On Windows the event lasts
/// until the process exits: the thread that waits on it holds a handle of its
/// own, blocked for as long as the GUI runs.
#[cfg(any(unix, windows))]
struct SingleInstanceGuard {
    #[cfg(unix)]
    path: std::path::PathBuf,
    #[cfg(windows)]
    _event: hops_ipc::instance::First,
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

/// Windows single-instance through [`hops_ipc::instance::claim_gui`]: only a
/// running hops window of this user, found and asked to show, keeps this
/// launch closed. Anything else holding the name opens the window anyway,
/// so no other program can stop the GUI appearing (#176).
#[cfg(windows)]
fn acquire_single_instance(show_requested: Arc<AtomicBool>) -> Instance {
    match hops_ipc::instance::claim_gui(move || show_requested.store(true, Ordering::SeqCst)) {
        hops_ipc::instance::Found::First(first) => {
            Instance::Primary(SingleInstanceGuard { _event: first })
        }
        hops_ipc::instance::Found::Running => {
            log::info!("a hops window is already open for this user; it was asked to show");
            Instance::Secondary
        }
    }
}

/// The request "add" sends, from the add form's words or a machine picked off
/// the network list: the whole device in one request (#32), or what to tell
/// the person instead.
///
/// Both ways to add a machine go through here. Each used to carry its own copy
/// of a two-step sequence, a blank device and then its details once its handle
/// came back, and the discovered one only ever did the first step.
///
/// `port` is as typed: blank is the default port, and anything that is not a
/// port from 1 to 65535 is refused rather than quietly replaced. `fix_ips`
/// is empty for a typed device (its name is resolved) and holds the addresses
/// a discovered machine announced.
fn add_request(
    name: &str,
    port: &str,
    position: Position,
    fix_ips: Vec<std::net::IpAddr>,
) -> Result<FrontendRequest, &'static str> {
    let port = match port.trim() {
        "" => DEFAULT_PORT,
        typed => typed.parse::<u16>().map_err(|_| {
            "That port is not valid. Use a number from 1 to 65535, or leave it blank \
             for the default."
        })?,
    };
    hops_frontend_core::new_device(name, fix_ips, port, position)
}

/// Put `fingerprint`'s request on the pairing card.
///
/// A name typed, and answers given, while the card showed another machine
/// are cleared, so they can never be sent to approve this one (#168).
fn show_pairing_card(ui: &AppWindow, fingerprint: &str) {
    if ui.get_pairing_fp().as_str() != fingerprint {
        ui.set_pairing_name("".into());
        ui.set_pairing_controller(-1);
        ui.set_pairing_clipboard(false);
    }
    ui.set_pairing_fp(fingerprint.into());
}

/// What the card's answers are: which way control goes, as the index of the
/// row chosen (-1 for none), and the clipboard switch.
#[derive(Debug, Clone, Copy)]
struct CardAnswers {
    controller: i32,
    clipboard: bool,
}

impl CardAnswers {
    fn of(ui: &AppWindow) -> Self {
        CardAnswers {
            controller: ui.get_pairing_controller(),
            clipboard: ui.get_pairing_clipboard(),
        }
    }
}

/// The request a click on "trust & name" sends: `name` for `fingerprint`,
/// with the card's answers (#220, #182), if that is the machine the card has
/// been showing (#168) and someone chose which way control goes.
fn approval(
    card: &PairingCard,
    name: &str,
    fingerprint: &str,
    answers: CardAnswers,
    now: Instant,
) -> Result<FrontendRequest, ApprovalRefused> {
    card.approve(fingerprint, now)?;
    let controller = usize::try_from(answers.controller)
        .ok()
        .and_then(|i| hops_frontend_core::Controller::ALL.get(i).copied());
    hops_frontend_core::approval_request(fingerprint, name, controller, answers.clipboard)
}

/// What "save" on the rename field sends for the row keyed `id`: a handle for
/// a device this machine dials, else the fingerprint of a paired machine.
///
/// A device this machine dials is given a name of its own. Its hostname is
/// where it is dialled, and a rename used to replace it (#13).
fn rename_request(id: &str, name: &str) -> FrontendRequest {
    let name = name.trim();
    if let Ok(h) = id.parse::<u64>() {
        return FrontendRequest::UpdateLabel(h, (!name.is_empty()).then(|| name.to_string()));
    }
    // A rename is a rename. This used to re-send AuthorizeKey, so the
    // wire could not tell relabelling from granting trust; SetLabel
    // refuses a fingerprint that is not already authorized.
    let desc = if name.is_empty() {
        hops_frontend_core::fallback_label(id)
    } else {
        name.to_string()
    };
    FrontendRequest::SetLabel(id.to_string(), desc)
}

/// What "save" on the address field sends for the device `handle`: the
/// hostname or address to dial it at, carrying the pin the row showed. Its
/// pin stays, so only the same machine is reached there (#99). Nothing for a
/// blank field or a row that is not a device this machine dials.
fn readdress_request(handle: &str, pin: &str, address: &str) -> Option<FrontendRequest> {
    let address = address.trim();
    let handle = handle.parse::<u64>().ok()?;
    (!address.is_empty()).then(|| FrontendRequest::UpdateHostname {
        handle,
        hostname: Some(address.to_string()),
        fingerprint: (!pin.is_empty()).then(|| pin.to_string()),
    })
}

/// Run the Slint GUI front-end. Blocks on the Slint event loop until the user
/// quits (macOS: via the menu bar "Quit"); the daemon keeps running regardless.
/// `hidden` starts with only the menu-bar/tray icon and no window (login
/// autostart); the window then opens on tray click or a second `hops gui` launch.
/// `launch` is what the binary knows as it opens: its own build, and why a
/// service it tried to start did not come up.
/// Put what the app has to say as it opens, that it restarted its service
/// (#222), in the window's neutral info bar. It is news, not a failure, and
/// the red banner carries errors only (#150): pushed there as activity, the
/// window never showed it at all.
fn show_opening_info(ui: &AppWindow, restarted: Option<&str>) {
    if let Some(note) = restarted {
        ui.set_info(note.into());
    }
}

pub fn run(hidden: bool, launch: Launch) -> Result<(), SlintError> {
    let opening_info = launch.restarted.clone();
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
            let client = FrontendClient::spawn(launch);
            let _ = tx.send(client);
            std::future::pending::<()>().await;
        });
    });
    let client = rx.recv().map_err(|_| SlintError::ClientInit)?;

    let ui = AppWindow::new()?;
    show_opening_info(&ui, opening_info.as_deref());
    // The pairing card's answers, in the words every frontend uses (#220).
    ui.set_controller_choices(ModelRc::new(VecModel::from(
        hops_frontend_core::Controller::ALL
            .iter()
            .map(|c| slint::SharedString::from(c.describe()))
            .collect::<Vec<_>>(),
    )));

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
    // Which machine the pairing card shows, shared by the poll that fills it
    // and the approve callback that checks a click against it (#168).
    let card: Rc<RefCell<PairingCard>> = Rc::default();

    // --- wire UI actions -> FrontendRequests (each closure owns a client clone) ---
    {
        let c = client.clone();
        ui.on_enable_input(move || {
            // Turning capture on is when macOS is asked for what it lacks,
            // so its prompt shows then (#169).
            #[cfg(target_os = "macos")]
            if let Some(ask) = privacy::for_capture(&c.snapshot().capture) {
                privacy::act(ask, false);
            }
            c.request(FrontendRequest::EnableCapture);
            c.request(FrontendRequest::EnableEmulation);
        });
    }
    {
        #[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
        let c = client.clone();
        ui.on_open_capture_settings(move || {
            #[cfg(target_os = "macos")]
            if let Some(ask) = privacy::for_capture(&c.snapshot().capture) {
                privacy::act(ask, true);
            }
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
        ui.on_rename_device(move |id, _pin, name| {
            c.request(rename_request(id.as_str(), name.as_str()));
        });
    }
    {
        let c = client.clone();
        ui.on_readdress_device(move |handle, pin, address| {
            if let Some(request) =
                readdress_request(handle.as_str(), pin.as_str(), address.as_str())
            {
                c.request(request);
            }
        });
    }
    {
        let c = client.clone();
        ui.on_delete_device(move |handle, pin| {
            if let Ok(h) = handle.as_str().parse::<u64>() {
                c.request(FrontendRequest::Delete {
                    handle: h,
                    fingerprint: (!pin.is_empty()).then(|| pin.to_string()),
                });
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
        ui.on_disable_clipboard(move |fp| {
            c.request(FrontendRequest::DisableClipboard(fp.to_string()));
        });
    }
    {
        let c = client.clone();
        ui.on_enable_clipboard(move |fp| {
            c.request(FrontendRequest::EnableClipboard(fp.to_string()));
        });
    }
    {
        let c = client.clone();
        let card = card.clone();
        let weak = ui.as_weak();
        let notice = notice_sink.clone();
        ui.on_approve_pairing(move |name, fp| {
            let Some(answers) = weak.upgrade().map(|ui| CardAnswers::of(&ui)) else {
                return;
            };
            match approval(
                &card.borrow(),
                name.as_str(),
                fp.as_str(),
                answers,
                Instant::now(),
            ) {
                Ok(request) => {
                    c.request(request);
                    if let Some(ui) = weak.upgrade() {
                        ui.set_pairing_name("".into());
                    }
                }
                Err(refused) => notice(refused.notice()),
            }
        });
    }
    {
        // The number shown, or the one picked, for the card on screen. The
        // daemon compares it with the number it arrived at.
        let c = client.clone();
        ui.on_confirm_pairing(move |fp, number| {
            if let Some(request) = check_answer(&c.snapshot(), fp.as_str(), number.as_str()) {
                c.request(request);
            }
        });
    }
    {
        let c = client.clone();
        ui.on_cancel_pairing(move |fp| {
            c.request(FrontendRequest::CancelPairing(fp.to_string()));
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
    ui.set_can_switch_interface(prefs::CAN_SWITCH);
    {
        ui.on_switch_interface(move || {
            let err = prefs::switch_to(prefs::Frontend::Tui);
            // only reached if the exec failed — a successful switch never returns
            log::warn!("could not switch to the terminal interface: {err}");
        });
    }

    {
        // Add a machine picked off the network list. Same create sequence as a
        // hand-typed device -- it still dials, and it still goes through the
        // ordinary approval prompt. Discovery supplies the address; it does not
        // supply trust (#136).
        let notice = notice_sink.clone();
        let c = client.clone();
        ui.on_add_discovered(move |label, ips, port, position| {
            let addrs: Vec<std::net::IpAddr> = ips
                .split(',')
                .filter_map(|a| a.trim().parse().ok())
                .collect();
            if addrs.is_empty() {
                notice("That machine did not advertise an address hops can use.");
                return;
            }
            let position = Position::try_from(position.as_str()).unwrap_or_default();
            // Store the mDNS hostname, not the bare label. `desk-mac` does not
            // resolve; `desk-mac.local` does, through the OS name stack
            // (Bonjour on macOS, Avahi via nsswitch on Linux) -- see
            // resolve_hostname in src/dns.rs.
            //
            // This is what makes a discovered device SELF-HEALING. The pinned
            // addresses are a snapshot, so if the peer's DHCP lease changes they
            // go stale. hops dials the union of pinned addresses and freshly
            // resolved ones on every reconnect, so a resolvable `.local` name
            // keeps working after every address it was added with has changed.
            let hostname = hops_frontend_core::discovered_hostname(&label);
            match add_request(&hostname, &port, position, addrs) {
                Ok(add) => {
                    c.request(add);
                }
                Err(why) => notice(why),
            }
        });
    }
    {
        let c = client.clone();
        ui.on_open_pairing(move || {
            c.request(FrontendRequest::OpenPairing);
        });
    }
    {
        let c = client.clone();
        let notice = notice_sink.clone();
        ui.on_create_device(move |name, port, position| {
            let position = Position::try_from(position.as_str()).unwrap_or_default();
            // The whole device, or a notice saying what is missing: an empty
            // name once made a permanent "unnamed device" card, and a port
            // that did not parse was quietly replaced with 4242.
            match add_request(&name, &port, position, Vec::new()) {
                Ok(add) => {
                    c.request(add);
                }
                Err(why) => notice(why),
            }
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
    // VRR displays). `repaint` holds the previous pushed state.
    let weak = ui.as_weak();
    let show_requested_poll = show_requested.clone();
    let awaiting_paint_poll = awaiting_paint.clone();
    let repaint: RefCell<Repaint> = RefCell::default();
    let timer = slint::Timer::default();
    let notice_seq_poll = notice_seq.clone();
    let notice_sink_poll = notice_sink.clone();
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

            // An armed delete or an open rename names a device by handle and
            // the pin it had. Once that device is gone or pinned to another
            // machine, drop it rather than let the user confirm something the
            // row no longer shows (#94).
            if armed_is_stale(
                &m,
                &ui.get_confirm_delete_handle(),
                &ui.get_confirm_delete_pin(),
            ) {
                ui.set_confirm_delete_handle("".into());
                ui.set_confirm_delete_pin("".into());
                notice_sink_poll(
                    "That device changed, so it was not deleted. Check it and try again.",
                );
            }
            if armed_is_stale(&m, &ui.get_editing_device(), &ui.get_editing_pin()) {
                ui.set_editing_device("".into());
                ui.set_editing_pin("".into());
                notice_sink_poll(
                    "That device changed, so it was not renamed. Check it and try again.",
                );
            }

            // --- Build what the window would show, then push it ONLY if it
            // changed since last tick. Re-pushing an identical model every 250ms
            // repaints the window constantly (flickering VRR displays); when
            // nothing changed we touch nothing and the window stays static.

            // a live pairing prompt: untrusted, still actively attempting (not a
            // stale prompt for a peer that left), and not currently snooze-dismissed.
            // The card keeps the machine it shows while that request is live, so
            // another machine asking cannot take it over (#168).
            let shown = card
                .borrow_mut()
                .show(&m, Instant::now(), |fp| {
                    dismissed
                        .borrow()
                        .get(fp)
                        .is_some_and(|t| t.elapsed() < DISMISS_TTL)
                })
                .cloned();
            let snap = polled_ui(&m, shown.as_ref(), Instant::now());
            repaint.borrow_mut().push(&ui, snap, &notice_seq_poll);
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
mod armed_actions_follow_their_device {
    //! The GUI holds an armed delete and an open rename as a handle string and
    //! the row's pin. `armed_is_stale` is what the poll loop asks before
    //! clearing them (#94).

    use super::armed_is_stale;
    use hops_frontend_core::{AppModel, ClientConfig, ClientState, FrontendEvent};

    // LEDGER T16 | class B | 1 return value: armed_is_stale over AppModel::apply
    #[test]
    fn an_armed_action_goes_stale_exactly_when_its_device_changes() {
        let x = format!("{}aa", "aa:".repeat(31));
        let y = format!("{}bb", "bb:".repeat(31));
        let pinned = |fp: &str| ClientState {
            peer_fingerprint: Some(fp.to_string()),
            ..Default::default()
        };
        let mut m = AppModel::default();
        m.apply(FrontendEvent::Created(
            4,
            ClientConfig::default(),
            pinned(&x),
        ));
        m.apply(FrontendEvent::Created(
            5,
            ClientConfig::default(),
            ClientState::default(),
        ));

        let cases = [
            ("", "", false),         // nothing armed
            (x.as_str(), "", false), // a receive-only row, keyed by fingerprint
            ("4", x.as_str(), false),
            ("5", "", false), // armed on a device with no pin yet
            ("4", "", true),  // armed before it learned a pin
            ("4", y.as_str(), true),
            ("9", "", true), // gone, or replaced by a reload
        ];
        for (handle, pin, stale) in cases {
            assert_eq!(
                armed_is_stale(&m, handle, pin),
                stale,
                "armed on handle {handle:?} with pin {pin:?}"
            );
        }
    }
}

#[cfg(test)]
mod destructive_actions_say_so {
    //! The confirm text for delete and revoke must say what removal costs:
    //! using the device again means pairing the two machines again (#184).
    //!
    //! It used to say the other machine needed a NEW identity, which was the
    //! tombstone rule removal no longer follows: a removed machine keeps its
    //! identity and pairs again in full. A confirm that still said so would
    //! send someone to reinstall a machine for nothing.
    //!
    //! This is a source guard because Slint draws its own pixels — there is no
    //! runtime assertion that reaches this text.

    const APP_SLINT: &str = include_str!("../ui/app.slint");

    /// The window's text, comments dropped: the guard is about what a
    /// person reads, and a comment may name the old rule to explain it.
    fn shown() -> String {
        APP_SLINT
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    // LEDGER R184-7 | class S | source text: app.slint confirms, comments stripped
    #[test]
    fn both_confirms_say_the_device_returns_by_pairing_again() {
        let n = shown()
            .matches(r#""to use it again, pair it again""#)
            .count();
        assert_eq!(
            n, 2,
            "delete and revoke must BOTH say what removal costs; found {n} of 2"
        );
    }

    // LEDGER R184-8 | class S | source text: app.slint, comments stripped
    #[test]
    fn nothing_on_screen_teaches_the_tombstone() {
        for old in ["NEW identity", "new identity", "permanently"] {
            assert!(
                !shown().contains(old),
                "app.slint still shows `{old}`: removal forgets the device, and it \
                 pairs again with the identity it has (#184)"
            );
        }
    }
}

#[cfg(test)]
mod the_window_draws_the_state {
    //! The window's dot and status words are the device's one connection
    //! state, derived in hops-frontend-core for both frontends (#148). The
    //! row carries nothing else the dot could be computed from; the original
    //! #92 defect was a correct fact discarded at the render step.
    use super::*;
    use hops_frontend_core::{
        ClientConfig, ClientState, CrossingRefusal, FrontendEvent, PairingCheck, PeerTrust,
    };
    use slint::Model;

    const FP: &str = "1e:19:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8";

    fn pinned(active: bool, link: bool, alive: bool) -> ClientState {
        ClientState {
            active,
            alive,
            active_addr: link.then(|| "192.0.2.5:4242".parse().expect("addr")),
            peer_fingerprint: Some(FP.into()),
            ..Default::default()
        }
    }

    /// A model attached to a daemon, holding one device this machine dials.
    fn dialled(state: ClientState, paired: bool) -> AppModel {
        let mut m = AppModel::default();
        m.connected = true;
        m.apply(FrontendEvent::Enumerate(vec![(
            0,
            ClientConfig {
                hostname: Some("desk-mac".into()),
                ..Default::default()
            },
            state,
        )]));
        if paired {
            m.apply(FrontendEvent::TrustUpdated(
                [(
                    FP.to_string(),
                    PeerTrust {
                        clipboard_from: true,
                        clipboard_to: true,
                        pending: false,
                    },
                )]
                .into(),
            ));
        }
        m
    }

    /// One model per state, built from daemon events, with the words and
    /// dot the window must show. The same table as the terminal's, so the
    /// two frontends are held to one answer.
    fn scenarios() -> Vec<(AppModel, &'static str, DotTone)> {
        let connected = dialled(pinned(true, true, true), true);
        let mut refusing = dialled(pinned(true, true, false), true);
        refusing.apply(FrontendEvent::DeviceConnected {
            addr: "192.0.2.5:50001".parse().expect("addr"),
            fingerprint: FP.into(),
        });
        let mut unreachable = dialled(pinned(true, false, false), true);
        unreachable.apply(FrontendEvent::CrossingRefused {
            handle: 0,
            reason: CrossingRefusal::NotConnected,
        });
        let mut waiting = dialled(pinned(true, false, false), false);
        waiting.apply(FrontendEvent::TrustUpdated(
            [(
                FP.to_string(),
                PeerTrust {
                    pending: true,
                    ..Default::default()
                },
            )]
            .into(),
        ));
        let mut comparing = waiting.clone();
        comparing.apply(FrontendEvent::PairingCheck {
            fingerprint: FP.into(),
            addr: None,
            check: PairingCheck::Show("042917".into()),
            answered: false,
        });
        // Its machine refused this one's dial as one it holds no pairing
        // with: it removed this machine (#184).
        let removed_here = dialled(
            ClientState {
                removed_by_peer: true,
                ..pinned(true, false, false)
            },
            true,
        );
        let in_too = |mut m: AppModel| {
            m.apply(FrontendEvent::DeviceConnected {
                addr: "192.0.2.5:50001".parse().expect("addr"),
                fingerprint: FP.into(),
            });
            m
        };
        let off_in = in_too(dialled(pinned(false, false, false), true));
        let unreachable_in = in_too(unreachable.clone());
        let mut gone = connected.clone();
        gone.daemon_gone();
        vec![
            (connected, "connected", DotTone::Good),
            (off_in, "off", DotTone::Quiet),
            (unreachable_in, "unreachable", DotTone::Warn),
            (refusing, "not accepting input", DotTone::Bad),
            (
                dialled(pinned(false, false, false), true),
                "off",
                DotTone::Quiet,
            ),
            (
                dialled(pinned(true, false, false), true),
                "not connected",
                DotTone::Quiet,
            ),
            (unreachable, "unreachable", DotTone::Warn),
            (
                dialled(
                    ClientState {
                        active: true,
                        ..Default::default()
                    },
                    false,
                ),
                "not paired",
                DotTone::Warn,
            ),
            (waiting, "waiting for its approval", DotTone::Warn),
            (comparing, "compare the number", DotTone::Warn),
            (removed_here, "it removed this machine", DotTone::Bad),
            (gone, "service not answering", DotTone::Quiet),
        ]
    }

    // LEDGER T148-10 | class B | 3 widget tree: AppWindow devices after polled_ui + Repaint::push
    #[test]
    fn every_state_reaches_the_window_as_its_words_and_tone() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let mut repaint = Repaint::default();
        for (m, words, tone) in scenarios() {
            repaint.push(&ui, polled_ui(&m, None, Instant::now()), &Cell::new(0));
            let row = ui.get_devices().row_data(0).expect("one row");
            assert_eq!(
                (row.status.as_str(), row.tone),
                (words, tone),
                "the window shows another state"
            );
        }
    }

    /// Non-test source only, comments stripped, whitespace collapsed.
    fn slint_code() -> String {
        include_str!("../ui/app.slint")
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A headless window can be asked neither a colour nor, without the
    /// compiler's debug info, which text an element draws. So these are
    /// checked in the source: each tone gets its own theme colour, the
    /// device dot is coloured by the tone alone, and the row draws the
    /// status words in that colour.
    // LEDGER T148-11 | class S | source text: ui/app.slint tone-color, the device-row Dot and status Text
    #[test]
    fn each_tone_has_its_own_colour_and_the_row_uses_it() {
        let code = slint_code();
        for (tone, colour) in [("good", "success"), ("warn", "warn"), ("bad", "error")] {
            let rule = format!("if tone == DotTone.{tone} {{ return Theme.c.{colour}; }}");
            assert!(code.contains(&rule), "tone-color lost `{rule}`");
        }
        let rows = code
            .split("for d in root.devices:")
            .nth(1)
            .expect("the device list");
        let dot = rows.split("Dot {").nth(1).expect("the device dot");
        assert!(
            dot.trim_start()
                .starts_with("tint: root.tone-color(d.tone); }"),
            "the device dot is coloured from something other than its tone: {}",
            &dot[..dot.len().min(120)]
        );
        // the row's own markup: up to the next item of the list, if any
        let row = rows.split("for ").next().unwrap_or(rows);
        let status = "Text { text: d.status; color: root.tone-color(d.tone);";
        assert!(
            row.contains(status),
            "the device row no longer draws its status words in its tone: \
             `{status}` is gone"
        );
    }
}

#[cfg(test)]
mod discovery_states {
    //! Three states, three different sentences.
    //!
    //! An empty peer list cannot say whether discovery is **off**, **looking**,
    //! or **looking and there is genuinely nothing** — and #138 rendered the
    //! same absence for all three: the section simply did not appear. On a
    //! network where multicast is filtered, the feature was indistinguishable
    //! from a bug. The diagnostic probe had the same shape and the same fix:
    //! when a reader cannot tell what an empty result means, make the silence
    //! explain itself.

    const UI: &str = include_str!("../ui/app.slint");

    /// The section keys on "are we looking", not "did we find something".
    #[test]
    fn the_section_shows_while_looking_not_only_when_found() {
        assert!(
            UI.contains("if root.discovery-active: VerticalLayout"),
            "the network section must render whenever discovery is ACTIVE. Keying \
             it on a non-empty list means a user on a network where mDNS is \
             blocked sees nothing at all and cannot tell the feature from a bug."
        );
    }

    /// And says so when it has found nothing yet.
    #[test]
    fn an_empty_result_is_stated_not_left_blank() {
        assert!(
            UI.contains("if root.discovered.length == 0"),
            "an active search with no results must say so; an absent section is \
             not an answer"
        );
    }

    /// The empty-devices line may only point at the network list when that list
    /// is actually on screen — which needs BOTH conditions, since the section is
    /// hidden while discovery is off regardless of what the list holds.
    #[test]
    fn the_empty_state_never_points_at_a_hidden_section() {
        // The invariant, not the implementation that used to satisfy it. What
        // hops found now lives INSIDE the add panel, so there is no longer any
        // section for the empty state to point at: a direction like "below" or
        // "from your network" names something that is not on screen until add
        // is clicked. This used to be a ternary guarded on discovery being
        // active AND the list being non-empty; moving the list made the
        // pointer unconditionally wrong rather than conditionally right.
        let empty_state: Vec<&str> = UI
            .lines()
            .filter(|l| l.contains("no devices yet"))
            .collect();
        assert!(
            !empty_state.is_empty(),
            "the empty state itself went missing — an empty device list must \
             still say what to do"
        );
        for line in empty_state {
            for pointer in ["below", "from your network", "on your network"] {
                assert!(
                    !line.contains(pointer),
                    "the empty state says {pointer:?}, which names a section \
                     that is not rendered until the add panel is open. Line: \
                     {line}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// the tray's `visible` must stay bound, or hiding it aborts the app
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tray_const_property {
    //! A `SystemTrayIcon` that never assigns `visible` gets it const-folded by
    //! the Slint compiler: generated init sets it true, then calls
    //! `set_constant()`. The generated `hide()` still writes `false`, and
    //! writing a constant property panics "Constant property being changed" in
    //! i-slint-core. The release profile sets `panic = "abort"`, so that is
    //! SIGABRT for the whole app, not a caught error — issue #4.
    //!
    //! Binding it to a public `in-out` makes the compiler's `is_constant()`
    //! false, so `set_constant()` is never emitted and `hide()` is safe.
    //!
    //! **This is a source scan, deliberately, and it is the legitimate case for
    //! one:** the invariant is about text the Slint compiler reads, and a
    //! behavioural test would need a real tray on a real display, which CI does
    //! not have. It is scoped to the one file and mutation-tested.
    //!
    //! **It was deleted once**, during a merge-conflict resolution, with no
    //! mention in the commit message — while the issue it guards stayed open
    //! and the panic it prevents is still in the logs. Do not delete it again;
    //! if the tray stops needing it, say so in the diff.

    const TRAY: &str = include_str!("../ui/tray.slint");

    #[test]
    fn the_trays_visible_is_bound_to_a_property_and_not_a_literal() {
        let bound = TRAY
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .any(|l| l.trim_start().starts_with("visible:") && l.contains("root."));
        assert!(
            bound,
            "tray.slint no longer binds `visible` to a property. The Slint \
             compiler will const-fold it, `hide()` will write a constant, and \
             i-slint-core panics \"Constant property being changed\" — which \
             under `panic = \"abort\"` takes the whole app down rather than \
             failing an operation. See issue #4."
        );
    }

    #[test]
    fn the_property_it_binds_to_is_in_out_so_the_compiler_cannot_fold_it() {
        let declared = TRAY
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .any(|l| l.contains("in-out property <bool> shown"));
        assert!(
            declared,
            "the property `visible` binds to is no longer a public `in-out`. \
             The compiler's is_constant() then returns true, set_constant() is \
             emitted again, and hiding the tray aborts the app. The visibility \
             is what defeats the folding — an equivalent private property does \
             not."
        );
    }
}

#[cfg(test)]
mod adding_a_device {
    //! "add" sends the whole device in one request, typed or picked off the
    //! network list (#32), and the card for the dial it starts names it (#93).
    use super::*;
    use hops_frontend_core::{
        AppModel, AttemptOrigin, ClientConfig, ClientState, FrontendEvent, NewDevice,
    };

    // LEDGER T6 | class B | 1 return value: add_request, which both add callbacks send
    #[test]
    fn both_ways_to_add_send_the_whole_device_or_say_why() {
        let ip: std::net::IpAddr = "192.0.2.7".parse().expect("ip");
        assert_eq!(
            add_request("desk-mac.local", "", Position::Right, vec![]),
            Ok(FrontendRequest::Create(NewDevice {
                hostname: Some("desk-mac.local".into()),
                fix_ips: vec![],
                port: DEFAULT_PORT,
                pos: Position::Right,
            })),
            "a typed device"
        );
        assert_eq!(
            add_request("desk-mac.local", " 4300 ", Position::Top, vec![ip]),
            Ok(FrontendRequest::Create(NewDevice {
                hostname: Some("desk-mac.local".into()),
                fix_ips: vec![ip],
                port: 4300,
                pos: Position::Top,
            })),
            "a machine picked off the network list"
        );
        for (name, port) in [
            ("", ""),
            ("desk-mac.local", "0"),
            ("desk-mac.local", "70000"),
        ] {
            assert!(
                add_request(name, port, Position::Left, vec![]).is_err(),
                "{name:?} on port {port:?} would add a device that can never be dialled"
            );
        }
    }

    // LEDGER T7 | class B | 6 struct state: polled_ui, the pairing-dialled property it sets
    #[test]
    fn the_card_for_our_dial_names_the_device_and_a_knock_names_none() {
        const FP: &str = "1e:19:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8";
        let answered: std::net::SocketAddr = "192.0.2.7:4242".parse().expect("addr");
        let shown = |origin| {
            let mut m = AppModel::default();
            m.apply(FrontendEvent::Created(
                2,
                ClientConfig {
                    hostname: Some("desk-mac.local".into()),
                    ..Default::default()
                },
                ClientState {
                    active: true,
                    ips: [answered.ip()].into(),
                    ..Default::default()
                },
            ));
            m.apply(FrontendEvent::ConnectionAttempt {
                fingerprint: FP.into(),
                origin,
                addr: Some(answered),
            });
            let now = Instant::now();
            let attempt = hops_frontend_core::PairingCard::default()
                .show(&m, now, |_| false)
                .cloned();
            polled_ui(&m, attempt.as_ref(), now)
        };
        let ours = shown(AttemptOrigin::OutboundDial);
        assert!(
            ours.pairing_from_our_dial && ours.pairing_dialled.contains("desk-mac.local:4242"),
            "the card for this machine's own dial does not name the device: {:?}",
            ours.pairing_dialled
        );
        let knock = shown(AttemptOrigin::Inbound);
        assert!(
            !knock.pairing_from_our_dial && knock.pairing_dialled.is_empty(),
            "a knock was described as this machine's own dial: {:?}",
            knock.pairing_dialled
        );
    }
}

#[cfg(test)]
mod add_opens_pairing {
    //! Opening the add form must open the pairing window, or no pairing prompt
    //! can ever appear on this machine (#195). The link is in `app.slint`, which
    //! no test here can click, so this reads the button's handler.

    /// `app.slint` with `//` comments removed, so prose cannot satisfy it.
    fn code() -> String {
        include_str!("../ui/app.slint")
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The body of the first `clicked => { ... }` after `anchor`, braces matched.
    fn handler_after(code: &str, anchor: &str) -> String {
        let at = code.find(anchor).expect("the button is still there");
        let rest = &code[at..];
        let open = rest.find("clicked =>").expect("it has a click handler");
        let body = &rest[open..];
        let start = body.find('{').expect("a block");
        let mut depth = 0;
        for (i, ch) in body[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return body[start..start + i + 1].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced click handler");
    }

    #[test]
    fn opening_add_device_opens_the_pairing_window() {
        let handler = handler_after(&code(), "\"+ add\"");
        assert!(
            handler.contains("root.open-pairing()"),
            "the + add button no longer opens the pairing window, so no pairing \
             prompt can appear on this machine:\n{handler}"
        );
    }
}

#[cfg(test)]
mod second_direction {
    //! A machine that may already drive this one answers this machine's dial.
    //! The window's pairing card asks whether this machine may drive it: one
    //! approval grants one direction, so the reverse needs its own card (#166).
    use super::*;
    use hops_frontend_core::{AppModel, AttemptOrigin, FrontendEvent};

    const FP: &str = "1e:19:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8";

    // LEDGER T9 | class B | 1 return value: PairingCard::show, which the poll loop sets as pairing-fp
    #[test]
    fn the_card_for_the_second_direction_is_shown() {
        let mut m = AppModel::default();
        m.apply(FrontendEvent::AuthorizedUpdated(
            [(FP.to_owned(), "desk mac".to_owned())].into(),
        ));
        m.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: FP.into(),
            origin: AttemptOrigin::OutboundDial,
            addr: Some("10.0.0.5:4242".parse().expect("addr")),
        });
        let mut card = hops_frontend_core::PairingCard::default();
        assert_eq!(
            card.show(&m, Instant::now(), |_| false)
                .map(|a| a.fingerprint.as_str()),
            Some(FP),
            "no card asks whether this machine may drive a peer that may \
             already drive it"
        );
    }
}

#[cfg(test)]
mod pairing_card_binds_the_approval {
    //! What "trust & name" sends is decided by the card the window shows, and a
    //! name typed for one machine is never sent for another (#168).
    //!
    //! Drives a real `AppWindow` on Slint's headless testing backend, through
    //! the same functions the poll and the approve callback use.
    use super::*;
    use hops_frontend_core::{AppModel, AttemptOrigin, PairingAttempt};

    fn attempt(fp: &str, since: Instant) -> PairingAttempt {
        PairingAttempt {
            fingerprint: fp.into(),
            origin: AttemptOrigin::Inbound,
            addr: None,
            since,
        }
    }

    /// One poll tick: choose the card's machine and put it in the window.
    fn tick(ui: &AppWindow, card: &mut PairingCard, m: &AppModel, now: Instant) {
        let fp = card
            .show(m, now, |_| false)
            .map(|a| a.fingerprint.clone())
            .unwrap_or_default();
        show_pairing_card(ui, &fp);
    }

    /// A click on "trust & name": what the card's button passes.
    fn click(
        ui: &AppWindow,
        card: &PairingCard,
        now: Instant,
    ) -> Result<FrontendRequest, ApprovalRefused> {
        approval(
            card,
            ui.get_pairing_name().as_str(),
            ui.get_pairing_fp().as_str(),
            CardAnswers::of(ui),
            now,
        )
    }

    // LEDGER T11 | class B | 6 struct state + 1 return value: AppWindow pairing-fp/pairing-name via show_pairing_card, approval
    #[test]
    fn the_card_decides_what_trust_and_name_sends() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let mut card = PairingCard::default();
        let mut m = AppModel::default();
        let t0 = Instant::now();

        m.pairing_attempts = vec![attempt("bb:bb", t0)];
        tick(&ui, &mut card, &m, t0);
        ui.set_pairing_name("laptop".into()); // typed into the card's field
        assert_eq!(
            click(&ui, &card, t0 + Duration::from_secs(2)),
            Err(ApprovalRefused::NoController),
            "an approval went out before anyone chose which way control goes"
        );
        ui.set_pairing_controller(1); // "That machine controls this one"
        ui.set_pairing_clipboard(true);
        assert_eq!(
            click(&ui, &card, t0 + Duration::from_secs(2)),
            Ok(FrontendRequest::AuthorizeKey {
                label: "laptop".into(),
                fingerprint: "bb:bb".into(),
                controller: hops_frontend_core::Controller::ThatMachine,
                clipboard: true,
            }),
            "the approval did not carry the name typed, the answers given and the \
             machine on the card"
        );

        // B stops asking while the name is still in the field; C is live.
        let t1 = t0 + PairingCard::STALE_AFTER + Duration::from_secs(1);
        m.pairing_attempts.push(attempt("cc:cc", t1));
        tick(&ui, &mut card, &m, t1);
        assert_eq!(ui.get_pairing_fp().as_str(), "cc:cc");
        assert_eq!(
            ui.get_pairing_name().as_str(),
            "",
            "the name typed for bb:bb was left in the card once it showed cc:cc"
        );
        assert!(
            ui.get_pairing_controller() == -1 && !ui.get_pairing_clipboard(),
            "the answers given for bb:bb were left in the card once it showed cc:cc"
        );
        assert_eq!(
            click(&ui, &card, t1 + Duration::from_millis(300)),
            Err(ApprovalRefused::JustChanged),
            "a click 300 ms after the card switched to cc:cc approved it"
        );
    }
}

#[cfg(test)]
mod the_repaint_gate {
    //! The poll repaints only when what it built differs from what it last
    //! pushed, so the comparison has to see every field a row shows (#172).
    //!
    //! Drives a real `AppWindow` on Slint's headless testing backend through
    //! the functions the poll calls.
    use super::*;
    use hops_frontend_core::{ClientConfig, ClientState, Connection, FrontendEvent};
    use slint::Model;

    const FP: &str = "1e:19:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8";

    /// One poll tick.
    fn tick(ui: &AppWindow, repaint: &mut Repaint, m: &AppModel) {
        repaint.push(ui, polled_ui(m, None, Instant::now()), &Cell::new(0));
    }

    fn row(ui: &AppWindow) -> DeviceRow {
        ui.get_devices().row_data(0).expect("one row")
    }

    // LEDGER T514 | class B | 3 widget tree: AppWindow devices after polled_ui + Repaint::push
    #[test]
    fn a_row_change_no_other_field_shows_still_reaches_the_window() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let mut repaint = Repaint::default();
        let mut m = AppModel::default();
        m.connected = true;

        // Added by one fixed address, routed to, and dialled: no link yet.
        let config = ClientConfig {
            fix_ips: vec!["192.0.2.5".parse().expect("ip")],
            port: 4242,
            ..Default::default()
        };
        let dialling = ClientState {
            active: true,
            peer_fingerprint: Some(FP.into()),
            ..Default::default()
        };
        m.apply(FrontendEvent::Enumerate(vec![(
            0,
            config.clone(),
            dialling.clone(),
        )]));
        tick(&ui, &mut repaint, &m);
        let refused = Connection::NotAcceptingInput;
        assert!(
            row(&ui).status.as_str() != refused.words() && row(&ui).tone != DotTone::Bad,
            "precondition: nothing is refused before a link is up"
        );

        // The dial is answered on that same address by a machine whose input
        // emulation is off. The row's address reads the same before and after.
        m.apply(FrontendEvent::State(
            0,
            config.clone(),
            ClientState {
                active_addr: Some("192.0.2.5:4242".parse().expect("addr")),
                ..dialling.clone()
            },
        ));
        tick(&ui, &mut repaint, &m);
        assert!(
            row(&ui).status.as_str() == refused.words() && row(&ui).tone == DotTone::Bad,
            "the window never said \"not accepting input\" for a machine that \
             refuses everything sent to it"
        );

        // Then its machine refuses it as removed (#184): the row says so.
        m.apply(FrontendEvent::State(
            0,
            config,
            ClientState {
                removed_by_peer: true,
                ..dialling
            },
        ));
        tick(&ui, &mut repaint, &m);
        assert!(
            row(&ui).status.as_str() == Connection::NoLongerTrusts.words()
                && row(&ui).tone == DotTone::Bad,
            "the window never said the machine no longer trusts this one"
        );
    }

    // LEDGER T515 | class B | 1 return value: Repaint::push
    #[test]
    fn an_unchanged_tick_writes_nothing() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let mut repaint = Repaint::default();
        let mut m = AppModel::default();
        m.apply(FrontendEvent::AuthorizedUpdated(
            [(FP.to_owned(), "desk mac".to_owned())].into(),
        ));
        let now = Instant::now();
        assert!(
            repaint.push(&ui, polled_ui(&m, None, now), &Cell::new(0)),
            "the first tick fills the window"
        );
        assert!(
            !repaint.push(&ui, polled_ui(&m, None, now), &Cell::new(0)),
            "an identical tick repainted the window, which flickers \
             variable-refresh displays"
        );
    }
}

#[cfg(test)]
mod the_window_without_a_daemon {
    //! With the daemon gone the window says so, and nothing on it reads live:
    //! the devices are what was last known (#34).
    //!
    //! Drives a real `AppWindow` on Slint's headless testing backend through
    //! what the poll calls.
    use super::*;
    use hops_frontend_core::{
        ClientConfig, ClientState, Connection, DiscoveredDevice, FrontendEvent,
    };
    use slint::Model;

    const FP: &str = "1e:19:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8";
    const OTHER_FP: &str = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

    /// One poll tick, the pairing card included.
    fn tick(ui: &AppWindow, repaint: &mut Repaint, card: &mut PairingCard, m: &AppModel) {
        let now = Instant::now();
        let shown = card.show(m, now, |_| false).cloned();
        repaint.push(ui, polled_ui(m, shown.as_ref(), now), &Cell::new(0));
    }

    fn device(name: &str, ip: &str, pos: Position) -> ClientConfig {
        ClientConfig {
            hostname: Some(name.into()),
            fix_ips: vec![ip.parse().expect("ip")],
            port: 4242,
            pos,
            ..Default::default()
        }
    }

    fn rows(ui: &AppWindow) -> Vec<DeviceRow> {
        ui.get_devices().iter().collect()
    }

    // LEDGER T533 | class B | 3 widget tree: AppWindow connected, devices, discovered, pairing-fp after daemon_gone + polled_ui + Repaint::push
    #[test]
    fn a_lost_daemon_leaves_nothing_in_the_window_reading_live() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let mut repaint = Repaint::default();
        let mut card = PairingCard::default();
        let mut m = AppModel::default();
        m.connected = true;
        // One device up and connected, one dialled that refuses input, a
        // machine asking to pair, and one found on the network.
        m.apply(FrontendEvent::Enumerate(vec![
            (
                0,
                device("studio-pc", "192.0.2.5", Position::Left),
                ClientState {
                    active: true,
                    alive: true,
                    active_addr: Some("192.0.2.5:4242".parse().expect("addr")),
                    peer_fingerprint: Some(FP.into()),
                    ..Default::default()
                },
            ),
            (
                1,
                device("desk-pc", "192.0.2.6", Position::Right),
                ClientState {
                    active: true,
                    active_addr: Some("192.0.2.6:4242".parse().expect("addr")),
                    peer_fingerprint: Some(OTHER_FP.into()),
                    ..Default::default()
                },
            ),
        ]));
        m.apply(FrontendEvent::DeviceConnected {
            addr: "192.0.2.5:50001".parse().expect("addr"),
            fingerprint: FP.into(),
        });
        m.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: "cc:dd".into(),
            origin: hops_frontend_core::AttemptOrigin::Inbound,
            addr: Some("192.0.2.9:50002".parse().expect("addr")),
        });
        m.apply(FrontendEvent::Discovered {
            active: true,
            peers: vec![DiscoveredDevice {
                label: "desk-laptop".into(),
                claimed_fingerprint: None,
                addrs: vec!["192.0.2.7:4242".parse().expect("addr")],
            }],
            quiet: false,
        });
        tick(&ui, &mut repaint, &mut card, &m);
        let live = rows(&ui);
        assert!(
            ui.get_connected()
                && live[0].status.as_str() == Connection::Connected.words()
                && live[0].tone == DotTone::Good
                && live[1].status.as_str() == Connection::NotAcceptingInput.words()
                && live[1].tone == DotTone::Bad
                && ui.get_discovered().row_count() == 1
                && !ui.get_pairing_fp().is_empty(),
            "precondition: the window shows the daemon's live state"
        );

        m.daemon_gone();
        tick(&ui, &mut repaint, &mut card, &m);
        assert!(
            !ui.get_connected(),
            "with no daemon the window still said it was connected"
        );
        let last_known = rows(&ui);
        assert_eq!(
            last_known.len(),
            2,
            "the devices must stay listed, as last known"
        );
        for row in &last_known {
            assert!(
                row.status.as_str() == Connection::ServiceGone.words()
                    && row.tone == DotTone::Quiet,
                "with no daemon {} still reads \"{}\" in {:?}",
                row.name,
                row.status,
                row.tone
            );
        }
        assert_eq!(
            (
                ui.get_discovered().row_count(),
                ui.get_pairing_fp().as_str()
            ),
            (0, ""),
            "with no daemon the window still offers machines on the network or \
             a pairing request to approve"
        );
    }
}

#[cfg(test)]
mod the_banner_shows_errors {
    //! The red banner with a dismiss button shows what went wrong, not the
    //! activity log's latest line (#150).
    use super::*;
    use hops_frontend_core::{ClientConfig, ClientState, FrontendEvent};

    fn entered(m: &mut AppModel) {
        m.apply(FrontendEvent::DeviceEntered {
            addr: "192.0.2.5:52808".parse().expect("addr"),
            pos: Position::Right,
            fingerprint: "aa:bb".into(),
        });
    }

    // LEDGER T517 | class B | 3 widget tree: AppWindow notice after polled_ui + Repaint::push
    #[test]
    fn a_cursor_entering_is_not_an_error() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let mut repaint = Repaint::default();
        let seq = Cell::new(0);
        let mut m = AppModel::default();

        entered(&mut m);
        repaint.push(&ui, polled_ui(&m, None, Instant::now()), &seq);
        assert_eq!(
            ui.get_notice().as_str(),
            "",
            "a cursor crossing an edge was shown in the error banner"
        );

        m.apply(FrontendEvent::Error("could not resolve studio-pc".into()));
        repaint.push(&ui, polled_ui(&m, None, Instant::now()), &seq);
        assert_eq!(ui.get_notice().as_str(), "could not resolve studio-pc");
        let raised = ui.get_notice_seq();

        // The cursor enters again on a tick that also changes a row, so the
        // tick reaches the window: nothing new went wrong, so a banner the
        // user dismissed must stay dismissed.
        entered(&mut m);
        m.apply(FrontendEvent::Created(
            0,
            ClientConfig {
                hostname: Some("studio-pc".into()),
                ..Default::default()
            },
            ClientState::default(),
        ));
        assert!(
            repaint.push(&ui, polled_ui(&m, None, Instant::now()), &seq),
            "precondition: a tick that adds a row reaches the window"
        );
        assert_eq!(
            (ui.get_notice().as_str(), ui.get_notice_seq()),
            ("could not resolve studio-pc", raised),
            "a cursor entering replaced the error or raised a dismissed banner again"
        );

        // The same failure again is a new error, and raises the banner even
        // if the user dismissed the first one.
        m.apply(FrontendEvent::Error("could not resolve studio-pc".into()));
        repaint.push(&ui, polled_ui(&m, None, Instant::now()), &seq);
        assert!(
            ui.get_notice_seq() != raised,
            "a repeat of the same failure did not raise the banner again"
        );
    }

    /// The add form opens on the first edge no active device uses. That edge
    /// was written only alongside a new notice, which routine events no
    /// longer are.
    // LEDGER T518 | class B | 3 widget tree: AppWindow free-position after Repaint::push
    #[test]
    fn the_free_edge_follows_the_devices_without_a_notice() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let mut repaint = Repaint::default();
        let seq = Cell::new(0);
        let mut m = AppModel::default();
        repaint.push(&ui, polled_ui(&m, None, Instant::now()), &seq);
        assert_eq!(ui.get_free_position().as_str(), "left");

        let on_the_left = ClientConfig {
            hostname: Some("studio-pc".into()),
            pos: Position::Left,
            ..Default::default()
        };
        let active = ClientState {
            active: true,
            ..Default::default()
        };
        m.apply(FrontendEvent::Created(0, on_the_left, active));
        repaint.push(&ui, polled_ui(&m, None, Instant::now()), &seq);
        assert_eq!(
            ui.get_free_position().as_str(),
            "right",
            "the add form would open on the left edge an active device uses, \
             and adding there switches that device off"
        );
    }
}

#[cfg(test)]
mod the_restart_note_is_news_not_an_error {
    //! The app says it restarted its service (#222) in the neutral info bar.
    //! The red banner carries errors only (#150), and the note, recorded as
    //! activity, reached neither.
    use super::*;

    // LEDGER T519 | class B | 3 widget tree: AppWindow info/notice after show_opening_info
    #[test]
    fn a_restarted_service_is_told_in_the_info_bar_not_the_error_banner() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let note =
            "hops restarted its service because it was running hops 0.12.0, not this version.";
        show_opening_info(&ui, Some(note));
        assert_eq!(
            ui.get_info().as_str(),
            note,
            "the window never says it restarted the service"
        );
        assert_eq!(
            ui.get_notice().as_str(),
            "",
            "a restart that worked was shown as an error"
        );
    }
}

#[cfg(test)]
mod a_capture_that_cannot_run {
    //! A capture that failed reads as failed, not off, with what to change
    //! and, on a Mac, the way to the setting (#91, #169).
    use super::*;
    use hops_frontend_core::{CaptureFault, CaptureState, FrontendEvent, Permission};

    fn tick(ui: &AppWindow, repaint: &mut Repaint, m: &AppModel) {
        repaint.push(ui, polled_ui(m, None, Instant::now()), &Cell::new(0));
    }

    // LEDGER T9 | class B | 3 widget tree: AppWindow capture properties after polled_ui + Repaint::push
    #[test]
    fn the_window_says_capture_failed_and_what_to_change() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let mut repaint = Repaint::default();
        let mut m = AppModel::default();
        m.connected = true;
        m.apply(FrontendEvent::CaptureStatus(CaptureState::Failed(
            CaptureFault::Missing(vec![Permission::InputMonitoring]),
        )));
        tick(&ui, &mut repaint, &m);
        let failed = (
            ui.get_capture().to_string(),
            ui.get_capture_problem().to_string(),
            ui.get_capture_settings(),
        );
        m.apply(FrontendEvent::CaptureStatus(CaptureState::Disabled));
        tick(&ui, &mut repaint, &m);
        let off = (
            ui.get_capture().to_string(),
            ui.get_capture_problem().to_string(),
            ui.get_capture_settings(),
        );
        assert_eq!(
            [failed, off],
            [
                (
                    "failed".to_string(),
                    "Input capture cannot run: macOS does not grant hops Input Monitoring, \
                     which this Mac needs to control other machines. Turn hops on under \
                     System Settings → Privacy & Security → Input Monitoring."
                        .to_string(),
                    cfg!(target_os = "macos"),
                ),
                ("disabled".to_string(), String::new(), false),
            ],
            "(capture, problem, settings button) for a capture refused Input \
             Monitoring, then for one merely off"
        );
    }
}

#[cfg(test)]
mod a_network_that_answers_nothing {
    //! Discovery that has heard nobody says, on a Mac, which setting can keep
    //! it from hearing anything (#149).
    use super::*;
    use hops_frontend_core::FrontendEvent;

    // LEDGER T14 | class B | 3 widget tree: AppWindow discovery-empty after polled_ui + Repaint::push
    #[test]
    fn a_quiet_network_names_the_local_network_setting_on_a_mac() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        let mut repaint = Repaint::default();
        let mut m = AppModel::default();
        m.connected = true;
        let mut said = Vec::new();
        for quiet in [false, true, false] {
            m.apply(FrontendEvent::Discovered {
                active: true,
                peers: vec![],
                quiet,
            });
            repaint.push(&ui, polled_ui(&m, None, Instant::now()), &Cell::new(0));
            said.push(ui.get_discovery_empty().contains("Local Network"));
        }
        assert_eq!(
            said,
            [false, cfg!(target_os = "macos"), false],
            "(names Local Network) while looking, once nothing answered, and once \
             something did"
        );
    }
}

#[cfg(test)]
mod a_rename_names_and_changes_nothing_else {
    //! Renaming a device from its card names it. The name used to be the
    //! hostname it is dialled at, so a rename sent a new address: the device
    //! then dialled its new name, and until #99 lost its pin (#13).
    use super::*;

    const PIN: &str = "1e:19:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8";

    // LEDGER T9907 | class B | 1 return value: rename_request, the request the rename field's save sends
    #[test]
    fn renaming_a_device_this_machine_dials_sends_its_name_only() {
        assert_eq!(
            rename_request("4", "  den "),
            FrontendRequest::UpdateLabel(4, Some("den".into())),
            "renaming a device this machine dials has to send its name, and \
             not a hostname: that is where it dials"
        );
        assert_eq!(
            rename_request("4", ""),
            FrontendRequest::UpdateLabel(4, None),
            "clearing the name of a device never connected has to clear its \
             name, and not its address"
        );
        assert_eq!(
            rename_request(PIN, "laptop"),
            FrontendRequest::SetLabel(PIN.into(), "laptop".into()),
            "a paired machine this one does not dial is renamed by its \
             fingerprint, as before"
        );
    }

    // LEDGER T9908 | class B | 1 return value: readdress_request, the request the address field's save sends
    #[test]
    fn a_new_address_is_sent_as_the_hostname_with_the_pin_shown() {
        assert_eq!(
            readdress_request("4", PIN, " 192.0.2.20 "),
            Some(FrontendRequest::UpdateHostname {
                handle: 4,
                hostname: Some("192.0.2.20".into()),
                fingerprint: Some(PIN.into()),
            }),
            "a new address has to be sent as where the device is dialled, with \
             the pin the row showed"
        );
        assert_eq!(
            (
                readdress_request("4", PIN, "  "),
                readdress_request(PIN, PIN, "192.0.2.20")
            ),
            (None, None),
            "(a blank address, a row this machine does not dial): neither may \
             change where anything is dialled"
        );
    }
}

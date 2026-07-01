//! grabbr-hop Slint GUI frontend (P2 — live status + device/trusted lists,
//! token-driven design system, core interactions wired).
//!
//! Mirrors the TUI's architecture: a background tokio thread owns the
//! auto-reconnecting [`lan_mouse_frontend_core::FrontendClient`], and the Slint
//! event loop (main thread) polls the observable model on a timer and pushes it
//! into the window — status fields plus the device + trusted lists as Slint
//! models. Slint components/models aren't `Send`, so the model snapshot crosses
//! threads (the client handle is `Send + Sync`) and the `VecModel`s are built on
//! the UI thread. UI callbacks send [`FrontendRequest`]s back through the client.

use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    sync::mpsc,
    time::{Duration, Instant},
};

use lan_mouse_frontend_core::{theme, FrontendClient, FrontendRequest, Status};
use slint::{ComponentHandle, ModelRc, VecModel};
use thiserror::Error;

slint::include_modules!();

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

/// Run the Slint GUI front-end. Blocks on the Slint event loop until the window
/// closes; the daemon (separate launchd service) keeps running.
pub fn run() -> Result<(), SlintError> {
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

    // theme is a UI-local preference shared with the TUI. Rust owns the palette
    // DATA (built-ins + any user themes in ~/.config/lan-mouse/themes/*.toml) —
    // push the whole table into the GUI once, then just flip the index to switch.
    let themes = Rc::new(theme::all_themes());
    ui.global::<Theme>().set_palettes(ModelRc::new(VecModel::from(
        themes.iter().map(theme_colors).collect::<Vec<_>>(),
    )));
    let theme_name =
        theme::load_name().unwrap_or_else(|| theme::default_theme().name.to_string());
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
        ui.on_revoke(move |fp| {
            c.request(FrontendRequest::RemoveAuthorizedKey(fp.to_string()));
        });
    }
    {
        let c = client.clone();
        ui.on_approve_pairing(move |name, fp| {
            let desc = if name.trim().is_empty() {
                "device".to_string()
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

    // poll the model ~4x/sec and push it into the window
    let weak = ui.as_weak();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(250),
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let m = client.snapshot();

            ui.set_connected(m.connected);
            ui.set_capture(status_text(m.capture).into());
            ui.set_emulation(status_text(m.emulation).into());
            ui.set_port(
                m.port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".into())
                    .into(),
            );
            ui.set_fingerprint(m.fingerprint.as_deref().unwrap_or("—").into());

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
            ui.set_pairing_fp(pairing.into());

            // outgoing devices
            let devices: Vec<DeviceRow> = m
                .clients
                .iter()
                .map(|(h, (c, s))| {
                    let addr = s
                        .active_addr
                        .map(|a| a.to_string())
                        .or_else(|| c.fix_ips.first().map(|ip| format!("{ip}:{}", c.port)))
                        .or_else(|| s.ips.iter().next().map(|ip| format!("{ip}:{}", c.port)))
                        .unwrap_or_else(|| "unresolved".into());
                    DeviceRow {
                        handle: h.to_string().into(),
                        name: c.hostname.clone().unwrap_or_else(|| "unnamed".into()).into(),
                        addr: addr.into(),
                        pos: c.pos.to_string().into(),
                        active: s.active,
                        alive: s.alive,
                    }
                })
                .collect();
            ui.set_devices(ModelRc::new(VecModel::from(devices)));

            // trusted peers (sorted by description, then fingerprint)
            let mut tv: Vec<(String, String)> = m
                .authorized
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            tv.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
            let trusted: Vec<TrustedRow> = tv
                .iter()
                .map(|(fp, desc)| TrustedRow {
                    name: desc.clone().into(),
                    fp: short_fp(fp).into(),
                    fp_full: fp.clone().into(),
                    online: m.connected_peers.contains(fp),
                })
                .collect();
            ui.set_trusted(ModelRc::new(VecModel::from(trusted)));
        },
    );

    ui.run()?;
    drop(timer);
    Ok(())
}

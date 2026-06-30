//! grabbr-hop Slint GUI frontend (P1 — live status + device/trusted lists).
//!
//! Mirrors the TUI's architecture: a background tokio thread owns the
//! auto-reconnecting [`lan_mouse_frontend_core::FrontendClient`], and the Slint
//! event loop (main thread) polls the observable model on a timer and pushes it
//! into the window — status fields plus the device + trusted lists as Slint
//! models. Slint components/models aren't `Send`, so the model snapshot crosses
//! threads (the client handle is `Send + Sync`) and the `VecModel`s are built on
//! the UI thread. Read-only for now; interactivity is the next step.

use std::{sync::mpsc, time::Duration};

use lan_mouse_frontend_core::{theme, FrontendClient, Status};
use slint::{ModelRc, VecModel};
use thiserror::Error;

slint::include_modules!();

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

    // theme palette (UI-local preference, shared with the TUI)
    let t = theme::load_name()
        .map(|n| theme::by_name(&n))
        .unwrap_or_else(theme::default_theme);
    ui.set_palette(Palette {
        bg: slint_color(t.bg),
        fg: slint_color(t.fg),
        muted: slint_color(t.muted),
        accent: slint_color(t.accent),
        success: slint_color(t.success),
        warn: slint_color(t.warn),
        error: slint_color(t.error),
    });
    // dot colors precomputed (theme is fixed for the session)
    let c_success = slint_color(t.success);
    let c_warn = slint_color(t.warn);
    let c_muted = slint_color(t.muted);
    let c_error = slint_color(t.error);

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

            // outgoing devices
            let devices: Vec<DeviceRow> = m
                .clients
                .iter()
                .map(|(h, (c, s))| DeviceRow {
                    label: format!(
                        "[{}] {}:{}",
                        h,
                        c.hostname.clone().unwrap_or_else(|| "unnamed".into()),
                        c.port
                    )
                    .into(),
                    pos: format!("({})", c.pos).into(),
                    state: if s.active { "active".into() } else { "off".into() },
                    dot: if s.alive {
                        c_success
                    } else if s.active {
                        c_warn
                    } else {
                        c_muted
                    },
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
                .map(|(fp, desc)| {
                    let online = m.connected_peers.contains(fp);
                    TrustedRow {
                        name: desc.clone().into(),
                        fp: short_fp(fp).into(),
                        status: if online { "connected".into() } else { "offline".into() },
                        dot: if online { c_success } else { c_error },
                    }
                })
                .collect();
            ui.set_trusted(ModelRc::new(VecModel::from(trusted)));
        },
    );

    ui.run()?;
    drop(timer);
    Ok(())
}

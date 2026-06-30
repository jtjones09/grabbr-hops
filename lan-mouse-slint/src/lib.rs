//! grabbr-hop Slint GUI frontend (P0 scaffold).
//!
//! Mirrors the TUI's architecture: a background tokio thread owns the
//! auto-reconnecting [`lan_mouse_frontend_core::FrontendClient`], and the Slint
//! event loop (main thread) polls the observable model on a timer and pushes it
//! into the window. Slint components aren't `Send`, so the model snapshot crosses
//! threads (the client handle is `Send + Sync`) and only the UI thread touches
//! the window. Requests flow back through the client's request sink (later, when
//! the interactive widgets land).

use std::{sync::mpsc, time::Duration};

use lan_mouse_frontend_core::{theme, FrontendClient, Status};
use thiserror::Error;

slint::include_modules!();

#[derive(Debug, Error)]
pub enum SlintError {
    #[error("slint platform error: {0}")]
    Platform(#[from] slint::PlatformError),
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

/// Run the Slint GUI front-end. Blocks on the Slint event loop until the window
/// closes; the daemon (separate process) keeps running.
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
    let client = rx.recv().expect("frontend client handle");

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
            ui.set_summary(
                format!(
                    "{} trusted · {} device(s) · {} connected now",
                    m.authorized.len(),
                    m.clients.len(),
                    m.connected_peers.len()
                )
                .into(),
            );
            ui.set_fingerprint(m.fingerprint.clone().unwrap_or_else(|| "—".into()).into());
        },
    );

    ui.run()?;
    drop(timer);
    Ok(())
}

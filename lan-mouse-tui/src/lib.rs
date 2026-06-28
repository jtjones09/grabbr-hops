//! grabbr-hop terminal UI (Ratatui).
//!
//! A thin view over the shared [`lan_mouse_frontend_core`] client: it renders
//! the observable [`AppModel`] and (later) sends [`FrontendRequest`]s; it holds
//! no protocol logic. P0 scope: connect to the daemon, render the live device
//! list + capture/emulation status + this device's fingerprint, `q` to quit.

use std::{io, time::Duration};

use lan_mouse_frontend_core::{AppModel, FrontendClient, Status};
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal io error: {0}")]
    Io(#[from] io::Error),
}

/// Run the TUI front-end. Must be called within a tokio `LocalSet`.
pub async fn run() -> Result<(), TuiError> {
    let client = FrontendClient::spawn();

    // crossterm's event::read() blocks, so read keys on a dedicated OS thread
    // and forward them to the async loop over a channel.
    let (key_tx, mut key_rx) = mpsc::unbounded_channel::<KeyEvent>();
    std::thread::spawn(move || loop {
        match event::read() {
            Ok(Event::Key(k)) => {
                if key_tx.send(k).is_err() {
                    break; // UI gone
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    });

    // ratatui::init() enables raw mode + alt screen and installs a panic hook
    // that restores the terminal, so a panic won't wreck the user's shell.
    let mut terminal = ratatui::init();

    let result = loop {
        let model = client.snapshot();
        if let Err(e) = terminal.draw(|f| ui(f, &model)) {
            break Err(TuiError::from(e));
        }
        tokio::select! {
            _ = client.changed() => {}
            key = key_rx.recv() => match key {
                Some(k) if k.kind == KeyEventKind::Press => {
                    let ctrl_c = k.code == KeyCode::Char('c')
                        && k.modifiers.contains(KeyModifiers::CONTROL);
                    if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c {
                        break Ok(());
                    }
                }
                Some(_) => {}
                None => break Ok(()), // input thread ended
            },
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    };

    let _ = ratatui::restore();
    result
}

fn ui(f: &mut Frame, model: &AppModel) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

    // header: connection + capture/emulation status
    let conn = if model.connected {
        Span::styled("● connected", Style::default().fg(Color::Green))
    } else {
        Span::styled("○ connecting…", Style::default().fg(Color::Yellow))
    };
    let header = Line::from(vec![
        conn,
        Span::raw("   capture: "),
        status_span(model.capture),
        Span::raw("   emulation: "),
        status_span(model.emulation),
    ]);
    f.render_widget(
        Paragraph::new(header)
            .block(Block::default().borders(Borders::ALL).title(" grabbr-hop ")),
        chunks[0],
    );

    // body: device list
    let items: Vec<ListItem> = if model.clients.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no devices configured",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        model
            .clients
            .iter()
            .map(|(h, (c, s))| {
                let host = c.hostname.clone().unwrap_or_else(|| "unknown".into());
                let dot = if s.alive {
                    Span::styled("●", Style::default().fg(Color::Green))
                } else if s.active {
                    Span::styled("●", Style::default().fg(Color::Yellow))
                } else {
                    Span::styled("○", Style::default().fg(Color::DarkGray))
                };
                ListItem::new(Line::from(vec![
                    dot,
                    Span::raw(format!(" [{h}] {host}:{} ", c.port)),
                    Span::styled(format!("({})", c.pos), Style::default().fg(Color::Cyan)),
                    Span::raw(if s.active { "  active" } else { "" }),
                ]))
            })
            .collect()
    };
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(" devices ")),
        chunks[1],
    );

    // footer: this device's fingerprint + quit hint
    let fp = model
        .fingerprint
        .as_deref()
        .map(short_fp)
        .unwrap_or_else(|| "—".into());
    let footer = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit   ·   this device: "),
        Span::styled(fp, Style::default().fg(Color::Magenta)),
    ]);
    f.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );
}

fn status_span(s: Status) -> Span<'static> {
    match s {
        Status::Enabled => Span::styled("enabled", Style::default().fg(Color::Green)),
        Status::Disabled => Span::styled("disabled", Style::default().fg(Color::Red)),
    }
}

/// Show the first 16 hex chars of a fingerprint for a glanceable id.
fn short_fp(fp: &str) -> String {
    let head: String = fp.chars().take(16).collect();
    format!("{head}…")
}

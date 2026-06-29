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
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
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
            Constraint::Length(4),
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

    // body: configured devices (outgoing) on top, trusted devices (incoming) below
    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    // devices this machine is configured to cross *to* (outgoing clients)
    let devices: Vec<ListItem> = if model.clients.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "none — this device only receives (cross back with the release bind)",
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
        List::new(devices)
            .block(Block::default().borders(Borders::ALL).title(" devices (cross to) ")),
        body[0],
    );

    // trusted peers allowed to connect *in* — the saved relationships; persist offline
    let trusted: Vec<ListItem> = if model.authorized.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no trusted devices",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        let mut entries: Vec<(&String, &String)> = model.authorized.iter().collect();
        entries.sort_by(|a, b| a.1.cmp(b.1)); // stable order by description
        entries
            .into_iter()
            .map(|(fp, desc)| {
                let online = model.connected_peers.contains(fp);
                let (dot, dot_color, state) = if online {
                    (
                        "●",
                        Color::Green,
                        Span::styled("connected", Style::default().fg(Color::Green)),
                    )
                } else {
                    (
                        "○",
                        Color::Red,
                        Span::styled("offline", Style::default().fg(Color::Red)),
                    )
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{dot} "), Style::default().fg(dot_color)),
                    Span::raw(desc.clone()),
                    Span::styled(
                        format!("  {}  ", short_fp(fp)),
                        Style::default().fg(Color::DarkGray),
                    ),
                    state,
                ]))
            })
            .collect()
    };
    f.render_widget(
        List::new(trusted)
            .block(Block::default().borders(Borders::ALL).title(" trusted devices ")),
        body[1],
    );

    // footer: quit hint + this device's FULL fingerprint (the pairing id — must
    // be shown whole so it can be verified/added on the other device; wraps so a
    // narrow terminal still shows all of it)
    let fp = model.fingerprint.as_deref().unwrap_or("—");
    let footer = vec![
        Line::from(vec![
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" / "),
            Span::styled("esc", Style::default().fg(Color::Yellow)),
            Span::raw("   close   ·   engine keeps running"),
        ]),
        Line::from(vec![
            Span::raw("this device: "),
            Span::styled(fp.to_string(), Style::default().fg(Color::Magenta)),
        ]),
    ];
    f.render_widget(
        Paragraph::new(footer)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL)),
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

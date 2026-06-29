//! grabbr-hop terminal UI (Ratatui).
//!
//! A thin view + control surface over the shared [`lan_mouse_frontend_core`]
//! client: it renders the observable [`AppModel`] and sends [`FrontendRequest`]s.
//! It holds no protocol logic. Actions (P2, increment 1): add / delete / select a
//! device, re-enable capture+emulation, save config. Closing the UI leaves the
//! daemon (the core engine) running.

use std::{io, time::Duration};

use lan_mouse_frontend_core::{AppModel, FrontendClient, FrontendRequest, Status};
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
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

    // crossterm's event::read() blocks, so read keys on a dedicated OS thread.
    let (key_tx, mut key_rx) = mpsc::unbounded_channel::<KeyEvent>();
    std::thread::spawn(move || loop {
        match event::read() {
            Ok(Event::Key(k)) => {
                if key_tx.send(k).is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    });

    let mut terminal = ratatui::init();
    let mut selected: usize = 0; // highlighted row in the devices list

    let result = loop {
        let model = client.snapshot();
        let count = model.clients.len();
        // keep the selection valid as the list changes
        if count == 0 {
            selected = 0;
        } else if selected >= count {
            selected = count - 1;
        }
        let mut list_state = ListState::default();
        if count > 0 {
            list_state.select(Some(selected));
        }

        if let Err(e) = terminal.draw(|f| ui(f, &model, &mut list_state)) {
            break Err(TuiError::from(e));
        }

        tokio::select! {
            _ = client.changed() => {}
            key = key_rx.recv() => match key {
                Some(k) if k.kind == KeyEventKind::Press => {
                    let ctrl_c = k.code == KeyCode::Char('c')
                        && k.modifiers.contains(KeyModifiers::CONTROL);
                    match k.code {
                        KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                        _ if ctrl_c => break Ok(()),
                        KeyCode::Up | KeyCode::Char('k') => {
                            selected = selected.saturating_sub(1);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if count > 0 && selected + 1 < count {
                                selected += 1;
                            }
                        }
                        // add a (blank) device — name/position/activate come next increment
                        KeyCode::Char('a') => client.request(FrontendRequest::Create),
                        // delete the selected device
                        KeyCode::Char('d') | KeyCode::Delete => {
                            if let Some((&handle, _)) = model.clients.iter().nth(selected) {
                                client.request(FrontendRequest::Delete(handle));
                            }
                        }
                        // re-enable input capture + emulation (e.g. after a secure-input lockout)
                        KeyCode::Char('r') => {
                            client.request(FrontendRequest::EnableCapture);
                            client.request(FrontendRequest::EnableEmulation);
                        }
                        // persist current config to disk
                        KeyCode::Char('s') => client.request(FrontendRequest::SaveConfiguration),
                        _ => {}
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

fn ui(f: &mut Frame, model: &AppModel, devices_state: &mut ListState) {
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

    // body: configured devices (outgoing, selectable) on top, trusted (incoming) below
    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

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
    f.render_stateful_widget(
        List::new(devices)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" devices (cross to) "),
            )
            .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
            .highlight_symbol("▶ "),
        body[0],
        devices_state,
    );

    // trusted peers (incoming) — saved relationships; green=connected / red=offline
    let trusted: Vec<ListItem> = if model.authorized.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no trusted devices",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        let mut entries: Vec<(&String, &String)> = model.authorized.iter().collect();
        entries.sort_by(|a, b| a.1.cmp(b.1));
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
        List::new(trusted).block(Block::default().borders(Borders::ALL).title(" trusted devices ")),
        body[1],
    );

    // footer: actions + this device's FULL fingerprint (the pairing id), wrapped
    let fp = model.fingerprint.as_deref().unwrap_or("—");
    let key = Style::default().fg(Color::Yellow);
    let footer = vec![
        Line::from(vec![
            Span::styled("a", key),
            Span::raw(" add   "),
            Span::styled("d", key),
            Span::raw(" delete   "),
            Span::styled("r", key),
            Span::raw(" re-enable   "),
            Span::styled("s", key),
            Span::raw(" save   "),
            Span::styled("↑↓", key),
            Span::raw(" select   "),
            Span::styled("q", key),
            Span::raw(" close"),
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

/// Show the first 16 hex chars of a fingerprint for a glanceable list id.
fn short_fp(fp: &str) -> String {
    let head: String = fp.chars().take(16).collect();
    format!("{head}…")
}

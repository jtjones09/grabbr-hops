//! grabbr-hop terminal UI (Ratatui).
//!
//! A thin view + control surface over the shared [`lan_mouse_frontend_core`]
//! client: it renders the observable [`AppModel`] and sends [`FrontendRequest`]s;
//! it holds no protocol logic. Closing the UI leaves the daemon (the core engine)
//! running.
//!
//! Actions: a=add, d=delete, n=name (text input), p=cycle position,
//! space=activate/deactivate, r=re-enable capture+emulation, s=save, ↑↓=select,
//! q/esc=close.

use std::{io, time::Duration};

use lan_mouse_frontend_core::{
    AppModel, ClientHandle, FrontendClient, FrontendRequest, Position, Status,
};
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
    // Some(handle, buffer) while editing a device's hostname.
    let mut input: Option<(ClientHandle, String)> = None;

    let result = loop {
        let model = client.snapshot();
        let count = model.clients.len();
        if count == 0 {
            selected = 0;
        } else if selected >= count {
            selected = count - 1;
        }
        let mut list_state = ListState::default();
        if count > 0 {
            list_state.select(Some(selected));
        }

        if let Err(e) = terminal.draw(|f| ui(f, &model, &mut list_state, input.as_ref())) {
            break Err(TuiError::from(e));
        }

        tokio::select! {
            _ = client.changed() => {}
            key = key_rx.recv() => match key {
                Some(k) if k.kind == KeyEventKind::Press => {
                    if input.is_some() {
                        // ---- text-input mode (editing a hostname) ----
                        match k.code {
                            KeyCode::Enter => {
                                if let Some((handle, buf)) = input.take() {
                                    let val = (!buf.trim().is_empty()).then_some(buf);
                                    client.request(FrontendRequest::UpdateHostname(handle, val));
                                }
                            }
                            KeyCode::Esc => input = None,
                            KeyCode::Backspace => {
                                if let Some((_, buf)) = input.as_mut() {
                                    buf.pop();
                                }
                            }
                            KeyCode::Char(c) => {
                                if let Some((_, buf)) = input.as_mut() {
                                    buf.push(c);
                                }
                            }
                            _ => {}
                        }
                    } else {
                        // ---- normal mode ----
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
                            KeyCode::Char('a') => client.request(FrontendRequest::Create),
                            KeyCode::Char('d') | KeyCode::Delete => {
                                if let Some((&handle, _)) = model.clients.iter().nth(selected) {
                                    client.request(FrontendRequest::Delete(handle));
                                }
                            }
                            KeyCode::Char('n') => {
                                if let Some((&handle, (c, _))) = model.clients.iter().nth(selected) {
                                    input = Some((handle, c.hostname.clone().unwrap_or_default()));
                                }
                            }
                            KeyCode::Char('p') => {
                                if let Some((&handle, (c, _))) = model.clients.iter().nth(selected) {
                                    client.request(FrontendRequest::UpdatePosition(
                                        handle,
                                        next_pos(&c.pos),
                                    ));
                                }
                            }
                            KeyCode::Char(' ') => {
                                if let Some((&handle, (_, s))) = model.clients.iter().nth(selected) {
                                    client.request(FrontendRequest::Activate(handle, !s.active));
                                }
                            }
                            KeyCode::Char('r') => {
                                client.request(FrontendRequest::EnableCapture);
                                client.request(FrontendRequest::EnableEmulation);
                            }
                            KeyCode::Char('s') => {
                                client.request(FrontendRequest::SaveConfiguration)
                            }
                            _ => {}
                        }
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

/// Cycle a device's edge: left → right → top → bottom → left.
fn next_pos(p: &Position) -> Position {
    match p {
        Position::Left => Position::Right,
        Position::Right => Position::Top,
        Position::Top => Position::Bottom,
        Position::Bottom => Position::Left,
    }
}

fn ui(f: &mut Frame, model: &AppModel, devices_state: &mut ListState, input: Option<&(ClientHandle, String)>) {
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
                let host = c.hostname.clone().unwrap_or_else(|| "unnamed".into());
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
                    Span::raw(if s.active { "  active" } else { "  off" }),
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

    // footer: text-input prompt (when editing) OR the keymap, plus the full fingerprint
    let key = Style::default().fg(Color::Yellow);
    let line1 = if let Some((handle, buf)) = input {
        Line::from(vec![
            Span::styled(format!("name [{handle}]: "), key),
            Span::raw(buf.clone()),
            Span::styled("▌", key),
            Span::styled("   enter save · esc cancel", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled("a", key),
            Span::raw(" add  "),
            Span::styled("d", key),
            Span::raw(" del  "),
            Span::styled("n", key),
            Span::raw(" name  "),
            Span::styled("p", key),
            Span::raw(" pos  "),
            Span::styled("spc", key),
            Span::raw(" on/off  "),
            Span::styled("r", key),
            Span::raw(" re-en  "),
            Span::styled("s", key),
            Span::raw(" save  "),
            Span::styled("↑↓", key),
            Span::raw(" sel  "),
            Span::styled("q", key),
            Span::raw(" close"),
        ])
    };
    let fp = model.fingerprint.as_deref().unwrap_or("—");
    let footer = vec![
        line1,
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

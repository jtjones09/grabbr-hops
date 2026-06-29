//! grabbr-hop terminal UI (Ratatui).
//!
//! A thin view + control surface over the shared [`lan_mouse_frontend_core`]
//! client: it renders the observable [`AppModel`] and sends [`FrontendRequest`]s;
//! it holds no protocol logic. Closing the UI leaves the daemon (the core engine)
//! running.
//!
//! Tab switches focus between the *devices* panel (outgoing clients you cross to)
//! and the *trusted* panel (incoming peers allowed to control this machine).
//! Devices: a=add, d=delete, n=name, p=position, space=on/off. Trusted:
//! n=rename, d=revoke. Global: r=re-enable, s=save, t=theme, ↑↓=select, q=close.
//! An untrusted peer that connects raises an approve/deny pairing prompt.

use std::{collections::HashSet, io, time::Duration};

use lan_mouse_frontend_core::{
    theme::{self, Rgb, Theme},
    AppModel, ClientHandle, FrontendClient, FrontendRequest, Position, Status,
};
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal io error: {0}")]
    Io(#[from] io::Error),
}

/// Which panel has keyboard focus.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Devices,
    Trusted,
}

/// Active text-input edit, if any.
enum Input {
    /// Editing an outgoing client's hostname.
    Hostname { handle: ClientHandle, buf: String },
    /// Naming a trusted peer (new pairing approval, or rename existing).
    TrustedName { fp: String, buf: String },
}

impl Input {
    fn buf_mut(&mut self) -> &mut String {
        match self {
            Input::Hostname { buf, .. } => buf,
            Input::TrustedName { buf, .. } => buf,
        }
    }
}

/// A pending yes/no confirmation.
enum Confirm {
    /// Revoke trust for a peer (destructive — they'd need to re-pair).
    Revoke { fp: String, desc: String },
}

/// Map a theme [`Rgb`] to a true-color ratatui [`Color`].
fn col(c: Rgb) -> Color {
    Color::Rgb(c.0, c.1, c.2)
}

/// Trusted peers as a stable, displayable list (sorted by description, then fp)
/// so the rendered order matches the selection index.
fn sorted_trusted(model: &AppModel) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = model
        .authorized
        .iter()
        .map(|(fp, desc)| (fp.clone(), desc.clone()))
        .collect();
    v.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    v
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

    // theme: persisted name → built-in index, default to the first.
    let themes = theme::builtins();
    let mut theme_idx = theme::load_name()
        .and_then(|n| themes.iter().position(|t| t.name == n))
        .unwrap_or(0);

    let mut terminal = ratatui::init();
    let mut focus = Focus::Devices;
    let mut dev_sel: usize = 0;
    let mut trust_sel: usize = 0;
    let mut input: Option<Input> = None;
    let mut confirm: Option<Confirm> = None;
    // pairing requests the user has dismissed this session (denied "for now").
    let mut dismissed: HashSet<String> = HashSet::new();

    let result = loop {
        let model = client.snapshot();
        let trusted = sorted_trusted(&model);
        let dev_count = model.clients.len();
        let tr_count = trusted.len();
        dev_sel = clamp_sel(dev_sel, dev_count);
        trust_sel = clamp_sel(trust_sel, tr_count);

        // a pending pairing the user hasn't dismissed and isn't already trusted
        let pairing: Option<String> = model
            .pending_pairing
            .clone()
            .filter(|fp| !dismissed.contains(fp) && !model.authorized.contains_key(fp));

        let mut dev_state = ListState::default();
        if focus == Focus::Devices && dev_count > 0 {
            dev_state.select(Some(dev_sel));
        }
        let mut trust_state = ListState::default();
        if focus == Focus::Trusted && tr_count > 0 {
            trust_state.select(Some(trust_sel));
        }

        let theme = &themes[theme_idx];
        if let Err(e) = terminal.draw(|f| {
            ui(
                f,
                &model,
                focus,
                &mut dev_state,
                &mut trust_state,
                input.as_ref(),
                confirm.as_ref(),
                pairing.as_deref(),
                theme,
            )
        }) {
            break Err(TuiError::from(e));
        }

        tokio::select! {
            _ = client.changed() => {}
            key = key_rx.recv() => match key {
                Some(k) if k.kind == KeyEventKind::Press => {
                    let ctrl_c = k.code == KeyCode::Char('c')
                        && k.modifiers.contains(KeyModifiers::CONTROL);

                    if input.is_some() {
                        // ---- text-input mode ----
                        match k.code {
                            KeyCode::Enter => match input.take().expect("input set") {
                                Input::Hostname { handle, buf } => {
                                    let val = (!buf.trim().is_empty()).then_some(buf);
                                    client.request(FrontendRequest::UpdateHostname(handle, val));
                                }
                                Input::TrustedName { fp, buf } => {
                                    let desc = if buf.trim().is_empty() {
                                        short_fp(&fp)
                                    } else {
                                        buf.trim().to_string()
                                    };
                                    client.request(FrontendRequest::AuthorizeKey(desc, fp));
                                }
                            },
                            KeyCode::Esc => input = None,
                            KeyCode::Backspace => {
                                if let Some(i) = input.as_mut() {
                                    i.buf_mut().pop();
                                }
                            }
                            KeyCode::Char(c) => {
                                if let Some(i) = input.as_mut() {
                                    i.buf_mut().push(c);
                                }
                            }
                            _ => {}
                        }
                    } else if confirm.is_some() {
                        // ---- confirmation mode ----
                        match k.code {
                            KeyCode::Char('y') => {
                                if let Some(Confirm::Revoke { fp, .. }) = confirm.take() {
                                    client.request(FrontendRequest::RemoveAuthorizedKey(fp));
                                }
                            }
                            KeyCode::Char('n') | KeyCode::Esc => confirm = None,
                            _ => {}
                        }
                    } else if let Some(fp) = pairing.clone() {
                        // ---- pairing-approval prompt ----
                        match k.code {
                            KeyCode::Char('y') => {
                                input = Some(Input::TrustedName { fp, buf: String::new() });
                            }
                            KeyCode::Char('n') | KeyCode::Esc => {
                                dismissed.insert(fp);
                            }
                            _ if ctrl_c => break Ok(()),
                            _ => {}
                        }
                    } else {
                        // ---- normal mode ----
                        match k.code {
                            KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                            _ if ctrl_c => break Ok(()),
                            KeyCode::Tab | KeyCode::BackTab => {
                                focus = match focus {
                                    Focus::Devices => Focus::Trusted,
                                    Focus::Trusted => Focus::Devices,
                                };
                            }
                            KeyCode::Up | KeyCode::Char('k') => match focus {
                                Focus::Devices => dev_sel = dev_sel.saturating_sub(1),
                                Focus::Trusted => trust_sel = trust_sel.saturating_sub(1),
                            },
                            KeyCode::Down | KeyCode::Char('j') => match focus {
                                Focus::Devices => {
                                    if dev_count > 0 && dev_sel + 1 < dev_count {
                                        dev_sel += 1;
                                    }
                                }
                                Focus::Trusted => {
                                    if tr_count > 0 && trust_sel + 1 < tr_count {
                                        trust_sel += 1;
                                    }
                                }
                            },
                            KeyCode::Char('r') => {
                                client.request(FrontendRequest::EnableCapture);
                                client.request(FrontendRequest::EnableEmulation);
                            }
                            KeyCode::Char('s') => client.request(FrontendRequest::SaveConfiguration),
                            KeyCode::Char('t') => {
                                theme_idx = (theme_idx + 1) % themes.len();
                                theme::save_name(themes[theme_idx].name);
                            }
                            // panel-specific actions
                            _ => match focus {
                                Focus::Devices => match k.code {
                                    KeyCode::Char('a') => client.request(FrontendRequest::Create),
                                    KeyCode::Char('d') | KeyCode::Delete => {
                                        if let Some((&handle, _)) =
                                            model.clients.iter().nth(dev_sel)
                                        {
                                            client.request(FrontendRequest::Delete(handle));
                                        }
                                    }
                                    KeyCode::Char('n') => {
                                        if let Some((&handle, (c, _))) =
                                            model.clients.iter().nth(dev_sel)
                                        {
                                            input = Some(Input::Hostname {
                                                handle,
                                                buf: c.hostname.clone().unwrap_or_default(),
                                            });
                                        }
                                    }
                                    KeyCode::Char('p') => {
                                        if let Some((&handle, (c, _))) =
                                            model.clients.iter().nth(dev_sel)
                                        {
                                            client.request(FrontendRequest::UpdatePosition(
                                                handle,
                                                next_pos(&c.pos),
                                            ));
                                        }
                                    }
                                    KeyCode::Char(' ') => {
                                        if let Some((&handle, (_, s))) =
                                            model.clients.iter().nth(dev_sel)
                                        {
                                            client.request(FrontendRequest::Activate(
                                                handle, !s.active,
                                            ));
                                        }
                                    }
                                    _ => {}
                                },
                                Focus::Trusted => match k.code {
                                    KeyCode::Char('n') => {
                                        if let Some((fp, desc)) = trusted.get(trust_sel) {
                                            input = Some(Input::TrustedName {
                                                fp: fp.clone(),
                                                buf: desc.clone(),
                                            });
                                        }
                                    }
                                    KeyCode::Char('d') | KeyCode::Delete => {
                                        if let Some((fp, desc)) = trusted.get(trust_sel) {
                                            confirm = Some(Confirm::Revoke {
                                                fp: fp.clone(),
                                                desc: desc.clone(),
                                            });
                                        }
                                    }
                                    _ => {}
                                },
                            },
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

fn clamp_sel(sel: usize, count: usize) -> usize {
    if count == 0 {
        0
    } else {
        sel.min(count - 1)
    }
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

#[allow(clippy::too_many_arguments)]
fn ui(
    f: &mut Frame,
    model: &AppModel,
    focus: Focus,
    dev_state: &mut ListState,
    trust_state: &mut ListState,
    input: Option<&Input>,
    confirm: Option<&Confirm>,
    pairing: Option<&str>,
    theme: &Theme,
) {
    let base = Style::default().bg(col(theme.bg)).fg(col(theme.fg));
    let border = Style::default().fg(col(theme.muted)).bg(col(theme.bg));
    let accent = Style::default().fg(col(theme.accent)).bg(col(theme.bg));
    let muted = Style::default().fg(col(theme.muted)).bg(col(theme.bg));
    let highlight = Style::default()
        .fg(col(theme.highlight_fg))
        .bg(col(theme.highlight_bg));
    let panel = |title: Span<'static>, focused: bool| {
        let bs = if focused { accent } else { border };
        Block::default()
            .borders(Borders::ALL)
            .border_style(bs)
            .style(base)
            .title(title)
    };

    // paint the whole window in the theme background first
    f.render_widget(Block::default().style(base), f.area());

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
        Span::styled("● connected", Style::default().fg(col(theme.success)))
    } else {
        Span::styled("○ connecting…", Style::default().fg(col(theme.warn)))
    };
    let header = Line::from(vec![
        conn,
        Span::raw("   capture: "),
        status_span(model.capture, theme),
        Span::raw("   emulation: "),
        status_span(model.emulation, theme),
    ]);
    let title = format!(" grabbr-hop · {} ", theme.name);
    f.render_widget(
        Paragraph::new(header)
            .style(base)
            .block(panel(Span::styled(title, accent), false)),
        chunks[0],
    );

    // body: devices (outgoing) on top, trusted (incoming) below
    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let devices: Vec<ListItem> = if model.clients.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "none — this device only receives (cross back with the release bind)",
            muted,
        )))]
    } else {
        model
            .clients
            .iter()
            .map(|(h, (c, s))| {
                let host = c.hostname.clone().unwrap_or_else(|| "unnamed".into());
                let dot = if s.alive {
                    Span::styled("●", Style::default().fg(col(theme.success)))
                } else if s.active {
                    Span::styled("●", Style::default().fg(col(theme.warn)))
                } else {
                    Span::styled("○", Style::default().fg(col(theme.muted)))
                };
                ListItem::new(Line::from(vec![
                    dot,
                    Span::raw(format!(" [{h}] {host}:{} ", c.port)),
                    Span::styled(format!("({})", c.pos), Style::default().fg(col(theme.accent))),
                    Span::styled(
                        if s.active { "  active" } else { "  off" },
                        if s.active {
                            Style::default().fg(col(theme.fg))
                        } else {
                            muted
                        },
                    ),
                ]))
            })
            .collect()
    };
    f.render_stateful_widget(
        List::new(devices)
            .block(panel(
                Span::styled(" devices (cross to) ", accent),
                focus == Focus::Devices,
            ))
            .highlight_style(highlight)
            .highlight_symbol("▶ "),
        body[0],
        dev_state,
    );

    // trusted peers (incoming) — success=connected / error=offline
    let trusted_list = sorted_trusted(model);
    let trusted: Vec<ListItem> = if trusted_list.is_empty() {
        vec![ListItem::new(Line::from(Span::styled("no trusted devices", muted)))]
    } else {
        trusted_list
            .iter()
            .map(|(fp, desc)| {
                let online = model.connected_peers.contains(fp);
                let (dot, dot_color, state) = if online {
                    (
                        "●",
                        col(theme.success),
                        Span::styled("connected", Style::default().fg(col(theme.success))),
                    )
                } else {
                    (
                        "○",
                        col(theme.error),
                        Span::styled("offline", Style::default().fg(col(theme.error))),
                    )
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{dot} "), Style::default().fg(dot_color)),
                    Span::raw(desc.clone()),
                    Span::styled(format!("  {}  ", short_fp(fp)), muted),
                    state,
                ]))
            })
            .collect()
    };
    f.render_stateful_widget(
        List::new(trusted)
            .block(panel(
                Span::styled(" trusted devices ", accent),
                focus == Focus::Trusted,
            ))
            .highlight_style(highlight)
            .highlight_symbol("▶ "),
        body[1],
        trust_state,
    );

    // footer: input / confirm / keymap, plus the full fingerprint
    let line1 = footer_line(input, confirm, focus, theme);
    let fp = model.fingerprint.as_deref().unwrap_or("—");
    let footer = vec![
        line1,
        Line::from(vec![
            Span::styled("this device: ", muted),
            Span::styled(fp.to_string(), Style::default().fg(col(theme.accent))),
        ]),
    ];
    f.render_widget(
        Paragraph::new(footer)
            .style(base)
            .wrap(Wrap { trim: false })
            .block(panel(Span::styled("", accent), false)),
        chunks[2],
    );

    // pairing-approval popup (only when nothing else is capturing input)
    if let Some(fp) = pairing {
        if input.is_none() && confirm.is_none() {
            pairing_popup(f, fp, theme);
        }
    }
}

/// Build the footer's first line: an active text-input, a confirmation, or the
/// focus-aware keymap.
fn footer_line(
    input: Option<&Input>,
    confirm: Option<&Confirm>,
    focus: Focus,
    theme: &Theme,
) -> Line<'static> {
    let key = Style::default().fg(col(theme.accent)).bg(col(theme.bg));
    let muted = Style::default().fg(col(theme.muted)).bg(col(theme.bg));
    let warn = Style::default().fg(col(theme.warn)).bg(col(theme.bg));

    if let Some(inp) = input {
        let (label, buf) = match inp {
            Input::Hostname { handle, buf } => (format!("name [{handle}]: "), buf.clone()),
            Input::TrustedName { buf, .. } => ("trust as: ".to_string(), buf.clone()),
        };
        return Line::from(vec![
            Span::styled(label, key),
            Span::raw(buf),
            Span::styled("▌", key),
            Span::styled("   enter save · esc cancel", muted),
        ]);
    }
    if let Some(Confirm::Revoke { desc, .. }) = confirm {
        return Line::from(vec![
            Span::styled(format!("revoke trust for {desc}? "), warn),
            Span::styled("y", key),
            Span::raw(" yes  "),
            Span::styled("n", key),
            Span::raw(" no"),
        ]);
    }

    let mut spans = vec![Span::styled("tab", key), Span::raw(" panel  ")];
    match focus {
        Focus::Devices => {
            for (k, label) in [
                ("a", " add  "),
                ("d", " del  "),
                ("n", " name  "),
                ("p", " pos  "),
                ("spc", " on/off  "),
            ] {
                spans.push(Span::styled(k, key));
                spans.push(Span::raw(label));
            }
        }
        Focus::Trusted => {
            for (k, label) in [("n", " rename  "), ("d", " revoke  ")] {
                spans.push(Span::styled(k, key));
                spans.push(Span::raw(label));
            }
        }
    }
    for (k, label) in [("r", " re-en  "), ("s", " save  "), ("t", " theme  "), ("q", " close")] {
        spans.push(Span::styled(k, key));
        spans.push(Span::raw(label));
    }
    Line::from(spans)
}

/// Render a centered approve/deny popup for an untrusted incoming peer.
fn pairing_popup(f: &mut Frame, fp: &str, theme: &Theme) {
    let area = centered_rect(70, 9, f.area());
    let base = Style::default().bg(col(theme.bg)).fg(col(theme.fg));
    let warn = Style::default().fg(col(theme.warn)).bg(col(theme.bg));
    let key = Style::default().fg(col(theme.accent)).bg(col(theme.bg));
    let muted = Style::default().fg(col(theme.muted)).bg(col(theme.bg));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(warn)
        .style(base)
        .title(Span::styled(" pairing request ", warn));
    let body = vec![
        Line::from(Span::styled(
            "An untrusted device wants to control this machine:",
            base,
        )),
        Line::from(Span::styled(fp.to_string(), key)),
        Line::from(Span::raw("")),
        Line::from(vec![
            Span::styled("y", key),
            Span::styled(" trust & name      ", muted),
            Span::styled("n", key),
            Span::styled(" deny (for now)", muted),
        ]),
    ];
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .style(base)
            .block(block),
        area,
    );
}

/// A rectangle centered in `area`: `percent_x` wide, `height` rows tall.
fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let w = (area.width * percent_x / 100).max(1);
    let h = height.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    }
}

fn status_span(s: Status, theme: &Theme) -> Span<'static> {
    match s {
        Status::Enabled => Span::styled("enabled", Style::default().fg(col(theme.success))),
        Status::Disabled => Span::styled("disabled", Style::default().fg(col(theme.error))),
    }
}

/// Show the first 16 hex chars of a fingerprint for a glanceable list id.
fn short_fp(fp: &str) -> String {
    let head: String = fp.chars().take(16).collect();
    format!("{head}…")
}

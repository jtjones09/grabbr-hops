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
//! n=rename, d=revoke. Global: l=activity log, o=listen port, r=re-enable,
//! s=save, t=theme, g=switch to the graphical interface, ↑↓=select, q=close.
//! An untrusted peer that connects raises an approve/deny pairing prompt.

use std::{
    collections::{HashMap, VecDeque},
    io,
    time::{Duration, Instant},
};

use lan_mouse_frontend_core::{
    prefs::Frontend,
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

/// How long a denied pairing stays snoozed before a fresh attempt re-prompts.
const DISMISS_TTL: Duration = Duration::from_secs(120);
/// If no new ConnectionAttempt refreshes a pending pairing within this window,
/// treat it as stale (the peer gave up) and stop showing the prompt.
const STALE_TTL: Duration = Duration::from_secs(12);

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
    /// Editing the daemon's listen port.
    Port { buf: String },
}

impl Input {
    fn buf_mut(&mut self) -> &mut String {
        match self {
            Input::Hostname { buf, .. } => buf,
            Input::TrustedName { buf, .. } => buf,
            Input::Port { buf } => buf,
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

    // theme: built-ins + any user themes dropped in ~/.config/lan-mouse/themes/,
    // persisted name → index, default to the first.
    let themes = theme::all_themes();
    let mut theme_idx = theme::load_name()
        .map(|n| theme::index_of(&themes, &n))
        .unwrap_or(0);

    let mut terminal = ratatui::init();
    let mut focus = Focus::Devices;
    let mut dev_sel: usize = 0;
    let mut trust_sel: usize = 0;
    let mut input: Option<Input> = None;
    let mut confirm: Option<Confirm> = None;
    // fingerprint -> when the user last denied it; snoozes the prompt for
    // DISMISS_TTL so a retrying peer doesn't nag, but a later attempt re-asks.
    let mut dismissed: HashMap<String, Instant> = HashMap::new();
    let mut show_log = false;

    let result = loop {
        let model = client.snapshot();
        let trusted = sorted_trusted(&model);
        let dev_count = model.clients.len();
        let tr_count = trusted.len();
        dev_sel = clamp_sel(dev_sel, dev_count);
        trust_sel = clamp_sel(trust_sel, tr_count);

        // a live pending pairing: untrusted, still actively attempting (not a
        // stale prompt for a peer that left), and not currently snooze-dismissed
        let pairing: Option<String> = model.pending_pairing.clone().filter(|fp| {
            if model.authorized.contains_key(fp) {
                return false;
            }
            let fresh = model
                .pending_pairing_since
                .map(|t| t.elapsed() < STALE_TTL)
                .unwrap_or(false);
            let snoozed = dismissed
                .get(fp)
                .map(|t| t.elapsed() < DISMISS_TTL)
                .unwrap_or(false);
            fresh && !snoozed
        });

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
                show_log,
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
                    // Ctrl+C closes from any mode (raw mode swallows SIGINT), and
                    // must precede the text-input branch so it isn't typed as 'c'.
                    if ctrl_c {
                        break Ok(());
                    }

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
                                Input::Port { buf } => {
                                    if let Ok(port) = buf.trim().parse::<u16>() {
                                        client.request(FrontendRequest::ChangePort(port));
                                    }
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
                                    // the port field only accepts digits
                                    if !matches!(i, Input::Port { .. }) || c.is_ascii_digit() {
                                        i.buf_mut().push(c);
                                    }
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
                                dismissed.insert(fp, Instant::now());
                            }
                            _ => {}
                        }
                    } else if show_log {
                        // ---- activity-log overlay ----
                        match k.code {
                            KeyCode::Char('q') => break Ok(()),
                            KeyCode::Char('l') | KeyCode::Esc => show_log = false,
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
                                theme::save_name(&themes[theme_idx].name);
                            }
                            KeyCode::Char('l') => show_log = true,
                            KeyCode::Char('o') => {
                                input = Some(Input::Port {
                                    buf: model.port.map(|p| p.to_string()).unwrap_or_default(),
                                });
                            }
                            KeyCode::Char('g') => {
                                ratatui::restore();
                                let err = lan_mouse_frontend_core::prefs::switch_to(Frontend::Gui);
                                log::warn!("could not switch to the graphical interface: {err}");
                                // exec() failed (or this build has no GUI) — the
                                // process is still us, so put the terminal back.
                                terminal = ratatui::init();
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

/// Show the first-run "choose your interface" screen and block until the user
/// picks one. A terminal can't show a graphical preview, so unlike the GUI's
/// onboarding (which renders an illustrative mockup of each option) this is a
/// plain described choice — still the same underlying pick, just text instead of
/// pixels. Synchronous: runs before any daemon connection is needed. `Ok(None)`
/// on Esc/q — the caller should ask again next launch, not assume a default.
pub fn run_onboarding() -> Result<Option<Frontend>, TuiError> {
    let theme = theme::default_theme();
    let base = Style::default()
        .bg(col(theme.background))
        .fg(col(theme.foreground));
    let accent = Style::default().fg(col(theme.accent));
    let muted = Style::default().fg(col(theme.muted));
    let highlight = Style::default()
        .fg(col(theme.on_accent))
        .bg(col(theme.accent));

    let options: [(&str, &str); 2] = [
        ("graphical", "windowed, point-and-click — best on your desktop"),
        ("terminal (this)", "keyboard-driven — runs anywhere, great over SSH"),
    ];
    let mut sel: usize = 1; // we're already in a terminal; sensible default

    let mut terminal = ratatui::init();
    let result = loop {
        if let Err(e) = terminal.draw(|f| {
            f.render_widget(Block::default().style(base), f.area());
            let area = f.area();
            let v = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Min(0),
                    Constraint::Length(1),
                ])
                .split(area);

            f.render_widget(
                Paragraph::new("welcome to grabbr-hop").style(accent.add_modifier(
                    ratatui::style::Modifier::BOLD,
                )),
                v[0],
            );
            f.render_widget(
                Paragraph::new("choose how you'd like to control your devices — ↑↓ + enter, switch anytime from Settings")
                    .style(muted)
                    .wrap(Wrap { trim: true }),
                v[1],
            );

            let items: Vec<ListItem> = options
                .iter()
                .map(|(name, desc)| {
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{name:<18}"), Style::default()),
                        Span::styled(*desc, muted),
                    ]))
                })
                .collect();
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).style(base).border_style(muted))
                .highlight_style(highlight);
            let mut state = ListState::default();
            state.select(Some(sel));
            f.render_stateful_widget(list, v[3], &mut state);
        }) {
            break Err(TuiError::from(e));
        }

        if let Ok(true) = event::poll(Duration::from_millis(250)) {
            if let Ok(Event::Key(k)) = event::read() {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => sel = sel.saturating_sub(1),
                    KeyCode::Down | KeyCode::Char('j') => sel = (sel + 1).min(options.len() - 1),
                    KeyCode::Enter => {
                        break Ok(Some(if sel == 0 { Frontend::Gui } else { Frontend::Tui }));
                    }
                    KeyCode::Esc | KeyCode::Char('q') => break Ok(None),
                    _ => {}
                }
            }
        }
    };
    ratatui::restore();
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
    show_log: bool,
    theme: &Theme,
) {
    let base = Style::default().bg(col(theme.background)).fg(col(theme.foreground));
    let border = Style::default().fg(col(theme.muted)).bg(col(theme.background));
    let accent = Style::default().fg(col(theme.accent)).bg(col(theme.background));
    let muted = Style::default().fg(col(theme.muted)).bg(col(theme.background));
    let highlight = Style::default()
        .fg(col(theme.on_accent))
        .bg(col(theme.accent));
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
            Constraint::Length(6),
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
        Span::styled(
            format!(
                "   port: {}",
                model.port.map(|p| p.to_string()).unwrap_or_else(|| "—".into())
            ),
            muted,
        ),
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
                            Style::default().fg(col(theme.foreground))
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

    // overlays (only when nothing else is capturing input): pairing takes priority
    if let Some(fp) = pairing {
        if input.is_none() && confirm.is_none() {
            pairing_popup(f, fp, theme);
        }
    } else if show_log && input.is_none() && confirm.is_none() {
        log_overlay(f, &model.messages, theme);
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
    let key = Style::default().fg(col(theme.accent)).bg(col(theme.background));
    let muted = Style::default().fg(col(theme.muted)).bg(col(theme.background));
    let warn = Style::default().fg(col(theme.warn)).bg(col(theme.background));

    if let Some(inp) = input {
        let (label, buf) = match inp {
            Input::Hostname { handle, buf } => (format!("name [{handle}]: "), buf.clone()),
            Input::TrustedName { buf, .. } => ("trust as: ".to_string(), buf.clone()),
            Input::Port { buf } => ("listen port: ".to_string(), buf.clone()),
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
    for (k, label) in [
        ("l", " log  "),
        ("o", " port  "),
        ("r", " re-en  "),
        ("s", " save  "),
        ("t", " theme  "),
        ("g", " gui  "),
        ("q", " close"),
    ] {
        spans.push(Span::styled(k, key));
        spans.push(Span::raw(label));
    }
    Line::from(spans)
}

/// Render a centered approve/deny popup for an untrusted incoming peer.
fn pairing_popup(f: &mut Frame, fp: &str, theme: &Theme) {
    let area = centered_rect(70, 9, f.area());
    let base = Style::default().bg(col(theme.background)).fg(col(theme.foreground));
    let warn = Style::default().fg(col(theme.warn)).bg(col(theme.background));
    let key = Style::default().fg(col(theme.accent)).bg(col(theme.background));
    let muted = Style::default().fg(col(theme.muted)).bg(col(theme.background));
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

/// Render a centered overlay of the recent activity log (newest at the bottom).
fn log_overlay(f: &mut Frame, messages: &VecDeque<String>, theme: &Theme) {
    let h = f.area().height.saturating_sub(4).max(6);
    let area = centered_rect(80, h, f.area());
    let base = Style::default().bg(col(theme.background)).fg(col(theme.foreground));
    let accent = Style::default().fg(col(theme.accent)).bg(col(theme.background));
    let muted = Style::default().fg(col(theme.muted)).bg(col(theme.background));
    let cap = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = if messages.is_empty() {
        vec![Line::from(Span::styled("no activity yet", muted))]
    } else {
        messages
            .iter()
            .rev()
            .take(cap)
            .rev()
            .map(|m| Line::from(Span::styled(m.clone(), base)))
            .collect()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(accent)
        .style(base)
        .title(Span::styled(" activity log · l/esc close ", accent));
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(base)
            .block(block),
        area,
    );
}

/// A rectangle centered in `area`: `percent_x` wide, `height` rows tall.
fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let w = ((area.width as u32 * percent_x as u32 / 100) as u16).max(1);
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

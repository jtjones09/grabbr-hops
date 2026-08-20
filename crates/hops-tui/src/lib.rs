//! hops terminal UI (Ratatui).
//!
//! A thin view + control surface over the shared [`hops_frontend_core`]
//! client: it renders the observable [`AppModel`] and sends [`FrontendRequest`]s;
//! it holds no protocol logic. Closing the UI leaves the daemon (the core engine)
//! running.
//!
//! # One panel, one device
//!
//! This used to be two panels — *devices* (outgoing clients you cross to) and
//! *trusted* (incoming peers allowed to control this machine) — which meant one
//! physical machine appeared as two unrelated rows with two names, two states
//! and two different `d` keys. The list is now built from
//! [`AppModel::devices`], the same identity-joined projection the graphical
//! interface uses, so a machine you both cross to *and* trust is a single row.
//!
//! Keys: a=add, n=name, p=position, space=on/off, d=remove, l=activity log,
//! o=listen port, r=re-enable, s=save, t=theme, g=switch to the graphical
//! interface, ↑↓=select, q=close. Which of a/n/p/space apply depends on the
//! selected row — a receive-only peer has no edge to cross and nothing to
//! toggle. An untrusted peer that connects raises an approve/deny prompt.
//!
//! # Removal is permanent
//!
//! `d` expels a peer: its fingerprint is tombstoned and the daemon refuses to
//! re-authorize it, so the machine must present a *new* identity to come back.
//! There is deliberately no restore key and no reconnect affordance — a
//! "re-trust" path is exactly the thing an attacker who has already been thrown
//! out would try to provoke. Expelled rows stay visible (greyed, marked
//! `removed`) so a Linux/TUI-only user can see what they expelled; they are not
//! actionable.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    time::{Duration, Instant},
};

use hops_frontend_core::{
    AppModel, ClientHandle, Device, DeviceSend, FrontendClient, FrontendRequest, Position, Status,
    TrustState,
    prefs::Frontend,
    theme::{self, Rgb, Theme},
};
use hops_ipc::DEFAULT_PORT;
use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use thiserror::Error;
use tokio::sync::mpsc;

/// How long a denied pairing stays snoozed before a fresh attempt re-prompts.
const DISMISS_TTL: Duration = Duration::from_secs(120);
/// If no new ConnectionAttempt refreshes a pending pairing within this window,
/// treat it as stale (the peer gave up) and stop showing the prompt.
const STALE_TTL: Duration = Duration::from_secs(12);
/// How long a locally-generated notice (a rejected add, an inapplicable key)
/// stays in the footer before the keymap comes back.
const NOTICE_TTL: Duration = Duration::from_secs(6);

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal io error: {0}")]
    Io(#[from] io::Error),
}

/// Active text-input edit, if any.
enum Input {
    /// Adding a device: `host` or `host:port`.
    Add { buf: String },
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
            Input::Add { buf } => buf,
            Input::Hostname { buf, .. } => buf,
            Input::TrustedName { buf, .. } => buf,
            Input::Port { buf } => buf,
        }
    }
}

/// A pending yes/no confirmation.
enum Confirm {
    /// Remove a device. `handle` deletes the outgoing client (which the daemon
    /// also tombstones by fingerprint); `fp` alone revokes a receive-only peer.
    /// `destructive` distinguishes "burns an identity" from "drops a config
    /// entry for a machine we never actually met", so the prompt can tell the
    /// truth about which one is happening.
    Remove {
        label: String,
        handle: Option<ClientHandle>,
        fp: Option<String>,
        destructive: bool,
    },
}

/// Map a theme [`Rgb`] to a true-color ratatui [`Color`].
fn col(c: Rgb) -> Color {
    Color::Rgb(c.0, c.1, c.2)
}

/// The rows we actually render: one per physical peer, minus the bare inbound
/// pairing request (that lives in the popup, not the list) and minus ourselves
/// (already filtered by [`AppModel::devices`]).
fn listable(model: &AppModel) -> Vec<Device> {
    model
        .devices()
        .into_iter()
        .filter(|d| d.is_listable())
        .collect()
}

/// Pick an edge no configured device is already using, so adding a machine
/// cannot silently evict one that is already there. Falls back to Left once all
/// four are taken — at that point every choice collides and the user has to
/// resolve it, but the add still succeeds.
fn free_edge(model: &AppModel) -> Position {
    let taken: HashSet<Position> = model.clients.values().map(|(c, _)| c.pos).collect();
    [
        Position::Left,
        Position::Right,
        Position::Top,
        Position::Bottom,
    ]
    .into_iter()
    .find(|p| !taken.contains(p))
    .unwrap_or(Position::Left)
}

/// Split a typed `host` / `host:port` into its parts.
///
/// A bare IPv6 literal is all host and no port, so it is recognised *before*
/// any colon splitting — `fe80::1` otherwise splits at its last colon into the
/// host `fe80:` on port 1, which is a valid-looking result for a device that
/// can never connect. An IPv6 address with a port must be bracketed, as
/// everywhere else.
fn parse_target(raw: &str) -> Result<(String, u16), &'static str> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("Enter the other machine's hostname or IP address.");
    }
    if raw.parse::<std::net::IpAddr>().is_ok() {
        return Ok((raw.to_string(), DEFAULT_PORT));
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or("That address is missing its closing ].")?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err("That is not a valid IPv6 address.");
        }
        return match tail {
            "" => Ok((host.to_string(), DEFAULT_PORT)),
            _ => match tail.strip_prefix(':') {
                Some(p) => Ok((host.to_string(), parse_port(p)?)),
                None => Err("Write an IPv6 address as [address]:port."),
            },
        };
    }
    if let Some((host, port)) = raw.rsplit_once(':') {
        if host.contains(':') {
            // several colons but not a valid literal: an IPv6 typo, or a
            // bracketless address with a port. Both want the same advice.
            return Err("Write an IPv6 address as [address]:port.");
        }
        let host = host.trim();
        if host.is_empty() {
            return Err("Enter a hostname or IP address before the port.");
        }
        return Ok((host.to_string(), parse_port(port)?));
    }
    Ok((raw.to_string(), DEFAULT_PORT))
}

fn parse_port(s: &str) -> Result<u16, &'static str> {
    match s.trim().parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        Ok(_) => Err("Port 0 can never connect. Use a number from 1 to 65535."),
        Err(_) => Err("That port is not valid. Use a number from 1 to 65535."),
    }
}

/// Run the TUI front-end. Must be called within a tokio `LocalSet`.
pub async fn run() -> Result<(), TuiError> {
    let client = FrontendClient::spawn();

    // crossterm's event::read() blocks, so read keys on a dedicated OS thread.
    let (key_tx, mut key_rx) = mpsc::unbounded_channel::<KeyEvent>();
    std::thread::spawn(move || {
        loop {
            match event::read() {
                Ok(Event::Key(k)) => {
                    if key_tx.send(k).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // theme: built-ins + any user themes dropped in ~/.config/lan-mouse/themes/,
    // persisted name → index, default to the first.
    let themes = theme::all_themes();
    let mut theme_idx = theme::load_name()
        .map(|n| theme::index_of(&themes, &n))
        .unwrap_or(0);

    let mut terminal = ratatui::init();
    let mut sel: usize = 0;
    let mut input: Option<Input> = None;
    let mut confirm: Option<Confirm> = None;
    // fingerprint -> when the user last denied it; snoozes the prompt for
    // DISMISS_TTL so a retrying peer doesn't nag, but a later attempt re-asks.
    let mut dismissed: HashMap<String, Instant> = HashMap::new();
    let mut show_log = false;
    let mut notice: Option<(String, Instant)> = None;
    // A device the user just asked to create, awaiting the handle the daemon
    // assigns: `Create` is fire-and-forget, and the handle only exists once the
    // resulting `Created` event lands in a snapshot. Applied below as soon as a
    // handle we have not seen before shows up. Without this, TUI "add" made a
    // blank unnamed card with no address, no port and no edge — a device that
    // could never connect and that the TUI had no way to finish configuring.
    let mut pending_new: Option<(String, u16, Position)> = None;
    let mut known_handles: HashSet<ClientHandle> = HashSet::new();

    let result = loop {
        let model = client.snapshot();

        // finish an add as soon as the daemon hands back a handle
        let current: HashSet<ClientHandle> = model.clients.keys().copied().collect();
        if current != known_handles {
            if let Some((host, port, pos)) = pending_new.take() {
                match current.difference(&known_handles).copied().next() {
                    Some(h) => {
                        client.request(FrontendRequest::UpdateHostname(h, Some(host)));
                        client.request(FrontendRequest::UpdatePort(h, port));
                        client.request(FrontendRequest::UpdatePosition(h, pos));
                        // actually try the machine: an inert card that is never
                        // dialed looks identical to a broken one.
                        client.request(FrontendRequest::Activate(h, true));
                    }
                    // Created hasn't reached a snapshot yet — retry next tick
                    None => pending_new = Some((host, port, pos)),
                }
            }
            known_handles = current;
        }

        let devices = listable(&model);
        let count = devices.len();
        sel = clamp_sel(sel, count);
        let selected = devices.get(sel);

        if notice
            .as_ref()
            .is_some_and(|(_, t)| t.elapsed() > NOTICE_TTL)
        {
            notice = None;
        }

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

        let mut list_state = ListState::default();
        if count > 0 {
            list_state.select(Some(sel));
        }

        let theme = &themes[theme_idx];
        if let Err(e) = terminal.draw(|f| {
            ui(
                f,
                &model,
                &devices,
                &mut list_state,
                input.as_ref(),
                confirm.as_ref(),
                pairing.as_deref(),
                notice.as_ref().map(|(m, _)| m.as_str()),
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
                                Input::Add { buf } => match parse_target(&buf) {
                                    Ok((host, port)) => {
                                        pending_new = Some((host, port, free_edge(&model)));
                                        client.request(FrontendRequest::Create);
                                    }
                                    Err(msg) => {
                                        notice = Some((msg.to_string(), Instant::now()));
                                    }
                                },
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
                                if let Some(Confirm::Remove { handle, fp, .. }) = confirm.take() {
                                    // Deleting the outgoing client is the whole
                                    // removal: the daemon tombstones the pinned
                                    // fingerprint with it. Only a peer we have no
                                    // client for needs the allowlist request.
                                    if let Some(h) = handle {
                                        client.request(FrontendRequest::Delete(h));
                                    } else if let Some(fp) = fp {
                                        client.request(FrontendRequest::RemoveAuthorizedKey(fp));
                                    }
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
                            KeyCode::Up | KeyCode::Char('k') => sel = sel.saturating_sub(1),
                            KeyCode::Down | KeyCode::Char('j') => {
                                if count > 0 && sel + 1 < count {
                                    sel += 1;
                                }
                            }
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
                                let err = hops_frontend_core::prefs::switch_to(Frontend::Gui);
                                log::warn!("could not switch to the graphical interface: {err}");
                                // exec() failed (or this build has no GUI) — the
                                // process is still us, so put the terminal back.
                                terminal = ratatui::init();
                            }
                            KeyCode::Char('a') => {
                                input = Some(Input::Add { buf: String::new() });
                            }
                            // ---- actions on the selected device ----
                            KeyCode::Char('n') => match selected {
                                Some(d) if d.trust == TrustState::Revoked => {
                                    notice = Some((REVOKED_NOTE.to_string(), Instant::now()));
                                }
                                // an outgoing client is named by its hostname —
                                // that is also the address it dials
                                Some(d) if d.send.is_some() => {
                                    let s = d.send.as_ref().expect("send facet");
                                    input = Some(Input::Hostname {
                                        handle: s.handle,
                                        buf: s.config.hostname.clone().unwrap_or_default(),
                                    });
                                }
                                // receive-only: re-authorizing the same
                                // fingerprint with a new description IS the rename
                                Some(d) if d.receive => {
                                    if let Some(fp) = d.fingerprint.clone() {
                                        input = Some(Input::TrustedName {
                                            fp,
                                            buf: d.label.clone(),
                                        });
                                    }
                                }
                                _ => {}
                            },
                            KeyCode::Char('p') => match selected.and_then(|d| d.send.as_ref()) {
                                Some(s) => client.request(FrontendRequest::UpdatePosition(
                                    s.handle,
                                    next_pos(&s.config.pos),
                                )),
                                None => {
                                    notice = Some((NO_SEND_NOTE.to_string(), Instant::now()));
                                }
                            },
                            KeyCode::Char(' ') => match selected.and_then(|d| d.send.as_ref()) {
                                Some(s) => client
                                    .request(FrontendRequest::Activate(s.handle, !s.state.active)),
                                None => {
                                    notice = Some((NO_SEND_NOTE.to_string(), Instant::now()));
                                }
                            },
                            KeyCode::Char('d') | KeyCode::Delete => match selected {
                                // already expelled — there is nothing left to do
                                // to it, and offering one would imply a way back
                                Some(d) if d.trust == TrustState::Revoked => {
                                    notice = Some((REVOKED_NOTE.to_string(), Instant::now()));
                                }
                                Some(d) => {
                                    let handle = d.send.as_ref().map(|s| s.handle);
                                    let fp = d.fingerprint.clone();
                                    confirm = Some(Confirm::Remove {
                                        label: d.label.clone(),
                                        handle,
                                        fp: fp.clone(),
                                        // nothing is burned if we never learned
                                        // who this machine is
                                        destructive: fp.is_some(),
                                    });
                                }
                                None => {}
                            },
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

/// Shown when a key is pressed on a row it cannot apply to.
const REVOKED_NOTE: &str =
    "This device was removed. It must pair again with a new identity — there is no way back in.";
const NO_SEND_NOTE: &str =
    "This device only connects in to you. Add it as a device to cross to it.";

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
        (
            "graphical",
            "windowed, point-and-click — best on your desktop",
        ),
        (
            "terminal (this)",
            "keyboard-driven — runs anywhere, great over SSH",
        ),
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
                Paragraph::new("welcome to hops").style(accent.add_modifier(
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
                        break Ok(Some(if sel == 0 {
                            Frontend::Gui
                        } else {
                            Frontend::Tui
                        }));
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
    if count == 0 { 0 } else { sel.min(count - 1) }
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

/// The address a configured client will actually dial, preferring where traffic
/// was last seen over what DNS merely offers.
fn send_addr(s: &DeviceSend) -> String {
    s.state
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
        .unwrap_or_else(|| "unresolved".into())
}

/// One row of the unified device list.
///
/// The two facets a device can have — we cross *to* it, it may connect *in* to
/// us — are shown as one arrow badge rather than as membership of two different
/// lists, which is the whole point of the projection.
fn device_row(d: &Device, theme: &Theme) -> ListItem<'static> {
    let muted = Style::default().fg(col(theme.muted));
    let revoked = d.trust == TrustState::Revoked;

    let dot = if revoked {
        Span::styled("⊘", Style::default().fg(col(theme.error)))
    } else if d.online || d.send.as_ref().is_some_and(|s| s.state.alive) {
        Span::styled("●", Style::default().fg(col(theme.success)))
    } else if d.send.as_ref().is_some_and(|s| s.state.active) {
        Span::styled("●", Style::default().fg(col(theme.warn)))
    } else {
        Span::styled("○", muted)
    };

    let dir = match (d.send.is_some(), d.receive) {
        (true, true) => "⇄",
        (true, false) => "→",
        (false, true) => "←",
        (false, false) => " ",
    };

    let (trust_text, trust_style) = match d.trust {
        TrustState::Trusted => ("trusted", Style::default().fg(col(theme.success))),
        TrustState::Provisional => ("unverified", Style::default().fg(col(theme.warn))),
        TrustState::PendingApproval => ("pending", Style::default().fg(col(theme.warn))),
        TrustState::Revoked => ("removed", Style::default().fg(col(theme.error))),
    };

    let mut spans = vec![
        dot,
        Span::raw(" "),
        Span::styled(
            format!("{:<18}", trunc(&d.label, 18)),
            if revoked {
                muted
            } else {
                Style::default().fg(col(theme.foreground))
            },
        ),
        Span::styled(format!("{dir} "), Style::default().fg(col(theme.accent))),
        Span::styled(format!("{trust_text:<11}"), trust_style),
    ];

    if revoked {
        // no address, no edge, no toggle — say what the row means instead of
        // showing stale connection details for a machine that cannot return
        spans.push(Span::styled(
            "pair again with a new identity to come back",
            muted,
        ));
        return ListItem::new(Line::from(spans));
    }

    spans.push(Span::styled(
        match &d.fingerprint {
            Some(fp) => format!("{}  ", short_fp(fp)),
            None => "not yet identified  ".to_string(),
        },
        muted,
    ));

    if let Some(s) = &d.send {
        spans.push(Span::raw(format!("{} ", send_addr(s))));
        spans.push(Span::styled(
            format!("({}) ", s.config.pos),
            Style::default().fg(col(theme.accent)),
        ));
        spans.push(Span::styled(
            if s.state.active { " active" } else { " off" },
            if s.state.active {
                Style::default().fg(col(theme.foreground))
            } else {
                muted
            },
        ));
    } else {
        spans.push(Span::styled("connects in only", muted));
    }

    ListItem::new(Line::from(spans))
}

/// Clip a label to `n` display cells so a long hostname cannot shove the rest of
/// the row off the edge of the terminal.
fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let head: String = s.chars().take(n.saturating_sub(1)).collect();
    format!("{head}…")
}

#[allow(clippy::too_many_arguments)]
fn ui(
    f: &mut Frame,
    model: &AppModel,
    devices: &[Device],
    list_state: &mut ListState,
    input: Option<&Input>,
    confirm: Option<&Confirm>,
    pairing: Option<&str>,
    notice: Option<&str>,
    show_log: bool,
    theme: &Theme,
) {
    let base = Style::default()
        .bg(col(theme.background))
        .fg(col(theme.foreground));
    let border = Style::default()
        .fg(col(theme.muted))
        .bg(col(theme.background));
    let accent = Style::default()
        .fg(col(theme.accent))
        .bg(col(theme.background));
    let muted = Style::default()
        .fg(col(theme.muted))
        .bg(col(theme.background));
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
                model
                    .port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".into())
            ),
            muted,
        ),
    ]);
    let title = format!(" hops · {} ", theme.name);
    f.render_widget(
        Paragraph::new(header)
            .style(base)
            .block(panel(Span::styled(title, accent), false)),
        chunks[0],
    );

    // body: one row per physical peer, both directions on the same line
    let rows: Vec<ListItem> = if devices.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no devices yet — press a to add the machine you want to cross to",
            muted,
        )))]
    } else {
        devices.iter().map(|d| device_row(d, theme)).collect()
    };
    f.render_stateful_widget(
        List::new(rows)
            .block(panel(Span::styled(" devices ", accent), true))
            .highlight_style(highlight)
            .highlight_symbol("▶ "),
        chunks[1],
        list_state,
    );

    // footer: input / confirm / notice / keymap, plus our own fingerprint
    let line1 = footer_line(
        input,
        confirm,
        notice,
        devices.get(selected_index(list_state)),
        theme,
    );
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

fn selected_index(state: &ListState) -> usize {
    state.selected().unwrap_or(0)
}

/// Build the footer's first line: an active text-input, a confirmation, a
/// transient notice, or the keymap for the selected row.
fn footer_line(
    input: Option<&Input>,
    confirm: Option<&Confirm>,
    notice: Option<&str>,
    selected: Option<&Device>,
    theme: &Theme,
) -> Line<'static> {
    let key = Style::default()
        .fg(col(theme.accent))
        .bg(col(theme.background));
    let muted = Style::default()
        .fg(col(theme.muted))
        .bg(col(theme.background));
    let warn = Style::default()
        .fg(col(theme.warn))
        .bg(col(theme.background));

    if let Some(inp) = input {
        let (label, buf) = match inp {
            Input::Add { buf } => ("add device — host or host:port: ".to_string(), buf.clone()),
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
    if let Some(Confirm::Remove {
        label, destructive, ..
    }) = confirm
    {
        // Tell the truth about which removal this is. Expelling a peer we have
        // identified burns that identity permanently; dropping a card for a
        // machine we never reached costs nothing and is worth not overstating.
        let question = if *destructive {
            format!("remove {label} permanently? it must pair again with a NEW identity — ")
        } else {
            format!("remove {label}? ")
        };
        return Line::from(vec![
            Span::styled(question, warn),
            Span::styled("y", key),
            Span::raw(" yes  "),
            Span::styled("n", key),
            Span::raw(" no"),
        ]);
    }
    if let Some(msg) = notice {
        return Line::from(Span::styled(msg.to_string(), warn));
    }

    let mut spans = vec![Span::styled("a", key), Span::raw(" add  ")];
    match selected {
        // an expelled row is inert on purpose — no rename, no restore
        Some(d) if d.trust == TrustState::Revoked => {
            spans.push(Span::styled("(removed — no way back in)  ", muted));
        }
        Some(d) => {
            spans.push(Span::styled("n", key));
            spans.push(Span::raw(if d.send.is_some() {
                " name  "
            } else {
                " rename  "
            }));
            if d.send.is_some() {
                for (k, label) in [("p", " pos  "), ("spc", " on/off  ")] {
                    spans.push(Span::styled(k, key));
                    spans.push(Span::raw(label));
                }
            }
            spans.push(Span::styled("d", key));
            spans.push(Span::raw(" remove  "));
        }
        None => {}
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
    let base = Style::default()
        .bg(col(theme.background))
        .fg(col(theme.foreground));
    let warn = Style::default()
        .fg(col(theme.warn))
        .bg(col(theme.background));
    let key = Style::default()
        .fg(col(theme.accent))
        .bg(col(theme.background));
    let muted = Style::default()
        .fg(col(theme.muted))
        .bg(col(theme.background));
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
    let base = Style::default()
        .bg(col(theme.background))
        .fg(col(theme.foreground));
    let accent = Style::default()
        .fg(col(theme.accent))
        .bg(col(theme.background));
    let muted = Style::default()
        .fg(col(theme.muted))
        .bg(col(theme.background));
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

#[cfg(test)]
mod tests {
    use super::*;
    use hops_frontend_core::{ClientConfig, ClientState, RevokedEntry};
    use ratatui::{Terminal, backend::TestBackend};

    const FP: &str = "1e:19:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8";
    const OTHER_FP: &str = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

    /// Render `ui` into an off-screen terminal and return the visible text, one
    /// String per row. Rendering is the only way to catch a row that the
    /// projection produces but the view silently filters out — a logic-level
    /// assertion on `devices()` would have passed for every bug below.
    fn render(model: &AppModel, sel: usize) -> Vec<String> {
        let devices = listable(model);
        let mut state = ListState::default();
        if !devices.is_empty() {
            state.select(Some(sel));
        }
        let theme = theme::default_theme();
        let mut term = Terminal::new(TestBackend::new(120, 24)).expect("test terminal");
        term.draw(|f| {
            ui(
                f, model, &devices, &mut state, None, None, None, None, false, &theme,
            )
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn screen(model: &AppModel, sel: usize) -> String {
        render(model, sel).join("\n")
    }

    /// One machine we both cross to AND trust must be ONE row.
    ///
    /// This is the defect the device model exists to fix, and the TUI kept it
    /// long after the GUI was fixed: two panels fed from two tables rendered the
    /// same machine twice, with two names and two different `d` keys.
    #[test]
    fn a_machine_we_both_send_to_and_trust_is_one_row() {
        let mut model = AppModel::default();
        model.clients.insert(
            0,
            (
                ClientConfig {
                    hostname: Some("ScornW20".into()),
                    ..Default::default()
                },
                ClientState {
                    peer_fingerprint: Some(FP.into()),
                    active: true,
                    alive: true,
                    ..Default::default()
                },
            ),
        );
        model.authorized.insert(FP.into(), "ScornW20".into());

        let out = screen(&model, 0);
        assert_eq!(
            out.matches("ScornW20").count(),
            1,
            "one machine must occupy exactly one row, got:\n{out}"
        );
        // and it must show BOTH directions on that single row
        assert!(out.contains('⇄'), "both facets should be badged:\n{out}");
        assert!(out.contains("trusted"), "trust state missing:\n{out}");
    }

    /// A peer that only connects in still gets a row — that is the half the old
    /// device panel could not show at all.
    #[test]
    fn a_receive_only_peer_is_listed() {
        let mut model = AppModel::default();
        model.authorized.insert(FP.into(), "Carrier MBP".into());
        let out = screen(&model, 0);
        assert!(out.contains("Carrier MBP"), "missing peer:\n{out}");
        assert!(out.contains('←'), "should be badged inbound-only:\n{out}");
    }

    /// We must never list ourselves. The old trusted panel did.
    #[test]
    fn this_machine_is_not_listed_as_a_trusted_device() {
        let mut model = AppModel::default();
        model.fingerprint = Some(FP.into());
        model.authorized.insert(FP.into(), "me".into());
        let out = screen(&model, 0);
        assert!(
            out.contains("no devices yet"),
            "our own fingerprint must not become a row:\n{out}"
        );
    }

    /// Revoked devices must be VISIBLE. On a TUI-only Linux box an invisible
    /// revocation makes the feature unusable: there is no other surface.
    #[test]
    fn a_revoked_device_is_visible_and_says_it_cannot_return() {
        let mut model = AppModel::default();
        model.revoked.insert(
            FP.into(),
            RevokedEntry {
                label: "old-laptop".into(),
                revoked_at: 0,
            },
        );
        let out = screen(&model, 0);
        assert!(out.contains("old-laptop"), "expelled row missing:\n{out}");
        assert!(out.contains("removed"), "not marked as removed:\n{out}");
        assert!(
            out.contains("pair again"),
            "must say how it could come back:\n{out}"
        );
    }

    /// Removal is permanent by design. The footer must not advertise a restore,
    /// and there is no key bound to one — a "re-trust" affordance is exactly
    /// what an expelled attacker would try to provoke.
    #[test]
    fn a_revoked_row_offers_no_way_back_in() {
        let mut model = AppModel::default();
        model.revoked.insert(
            FP.into(),
            RevokedEntry {
                label: "old-laptop".into(),
                revoked_at: 0,
            },
        );
        let out = screen(&model, 0);
        assert!(
            out.contains("no way back in"),
            "footer should state the row is inert:\n{out}"
        );
        for forbidden in ["restore", "re-trust", "reconnect", "trust again"] {
            assert!(
                !out.to_lowercase().contains(forbidden),
                "footer must not offer {forbidden:?}:\n{out}"
            );
        }
    }

    /// Revoked outranks authorized: a hand-edited config naming a fingerprint in
    /// both tables must read as expelled, never as trusted.
    #[test]
    fn revoked_wins_over_a_stale_authorized_entry() {
        let mut model = AppModel::default();
        model.authorized.insert(FP.into(), "ghost".into());
        model.revoked.insert(
            FP.into(),
            RevokedEntry {
                label: "ghost".into(),
                revoked_at: 0,
            },
        );
        let out = screen(&model, 0);
        assert!(out.contains("removed"), "should read as expelled:\n{out}");
        assert!(
            !out.contains("trusted"),
            "must never render as trusted:\n{out}"
        );
    }

    /// The keymap is per-row: a peer with no send facet has no edge to cycle and
    /// nothing to toggle, so offering `p` / `spc` would be a lie.
    #[test]
    fn the_keymap_matches_what_the_selected_row_can_do() {
        let mut model = AppModel::default();
        model.authorized.insert(FP.into(), "inbound-only".into());
        let receive_only = screen(&model, 0);
        assert!(
            !receive_only.contains("on/off"),
            "receive-only row cannot be toggled:\n{receive_only}"
        );
        assert!(
            receive_only.contains("rename") && receive_only.contains("remove"),
            "receive-only row should still be nameable and removable:\n{receive_only}"
        );

        let mut model = AppModel::default();
        model.clients.insert(
            0,
            (
                ClientConfig {
                    hostname: Some("crossable".into()),
                    ..Default::default()
                },
                ClientState::default(),
            ),
        );
        let send = screen(&model, 0);
        assert!(
            send.contains("on/off") && send.contains("pos"),
            "a device we cross to must offer edge + toggle:\n{send}"
        );
    }

    /// A client that has never completed a handshake has no identity yet, and
    /// must not be dressed up as trusted.
    #[test]
    fn a_never_connected_client_reads_as_unverified() {
        let mut model = AppModel::default();
        model.clients.insert(
            0,
            (
                ClientConfig {
                    hostname: Some("new-box".into()),
                    ..Default::default()
                },
                ClientState::default(),
            ),
        );
        let out = screen(&model, 0);
        assert!(out.contains("new-box"), "missing row:\n{out}");
        assert!(out.contains("unverified"), "should be unverified:\n{out}");
        assert!(
            out.contains("not yet identified"),
            "should say the fingerprint is unknown:\n{out}"
        );
    }

    /// Two different machines stay two rows — the join must not over-merge.
    #[test]
    fn distinct_peers_stay_distinct() {
        let mut model = AppModel::default();
        model.authorized.insert(FP.into(), "alpha".into());
        model.authorized.insert(OTHER_FP.into(), "beta".into());
        let out = screen(&model, 0);
        assert!(out.contains("alpha") && out.contains("beta"), "\n{out}");
    }

    #[test]
    fn a_typed_target_is_parsed_or_explained() {
        assert_eq!(
            parse_target("10.0.0.5").expect("bare host"),
            ("10.0.0.5".to_string(), DEFAULT_PORT)
        );
        assert_eq!(
            parse_target(" desktop.local:4722 ").expect("host and port"),
            ("desktop.local".to_string(), 4722)
        );
        // an IPv6 literal must not be shredded at its last colon into the
        // plausible-looking, permanently-unreachable ("fe80:", 1)
        assert_eq!(
            parse_target("fe80::1").expect("ipv6"),
            ("fe80::1".to_string(), DEFAULT_PORT)
        );
        assert_eq!(
            parse_target("[fe80::1]:4722").expect("bracketed ipv6"),
            ("fe80::1".to_string(), 4722)
        );
        // bracketless means no port, per the usual rule — and `fe80::1:4722`
        // is itself a legal address, so guessing that the tail was a port
        // would silently dial the wrong machine
        assert_eq!(
            parse_target("fe80::1:4722").expect("legal ipv6"),
            ("fe80::1:4722".to_string(), DEFAULT_PORT)
        );
        // a malformed address with a trailing number is refused, not salvaged
        assert!(
            parse_target("fe80::zz::1:22").is_err(),
            "a malformed ipv6 must be refused, not split into host+port"
        );
        // and the rejections must say why rather than silently substituting
        assert!(parse_target("   ").is_err(), "empty is rejected");
        assert!(parse_target("host:0").is_err(), "port 0 can never connect");
        assert!(parse_target("host:notaport").is_err(), "garbage port");
    }

    /// Adding a device must not evict one that is already on that edge.
    #[test]
    fn a_new_device_lands_on_a_free_edge() {
        let mut model = AppModel::default();
        model.clients.insert(
            0,
            (
                ClientConfig {
                    pos: Position::Left,
                    ..Default::default()
                },
                ClientState::default(),
            ),
        );
        assert_ne!(free_edge(&model), Position::Left);
        model.clients.insert(
            1,
            (
                ClientConfig {
                    pos: free_edge(&model),
                    ..Default::default()
                },
                ClientState::default(),
            ),
        );
        let third = free_edge(&model);
        assert!(
            !model.clients.values().any(|(c, _)| c.pos == third),
            "third device must not collide"
        );
    }
}

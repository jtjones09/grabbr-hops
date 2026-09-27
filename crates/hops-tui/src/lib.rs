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
    AppModel, ApprovalRefused, AttemptOrigin, CaptureState, ClientHandle, Clipboard, Controller,
    Device, DeviceSend, FrontendClient, FrontendRequest, Launch, PairingAnswers, PairingAttempt,
    PairingCard, PairingCheck, PairingCheckCard, Position, Status, TrustState,
    prefs::Frontend,
    spaced_number,
    theme::{self, Rgb, Theme},
};
use hops_ipc::DEFAULT_PORT;
use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use thiserror::Error;
use tokio::sync::mpsc;

/// How long a denied pairing stays snoozed before a fresh attempt re-prompts.
const DISMISS_TTL: Duration = Duration::from_secs(120);
/// How long a locally-generated notice (a rejected add, an inapplicable key)
/// stays in the footer before the keymap comes back.
const NOTICE_TTL: Duration = Duration::from_secs(6);

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal io error: {0}")]
    Io(#[from] io::Error),
}

/// `y` on the pairing prompt: the name prompt for `fp`, bound to that machine
/// and to the answers given for it, if the prompt has shown it long enough
/// for the key to have been meant for it (#168) and someone said which way
/// control goes (#220).
fn approve_prompt(
    card: &PairingCard,
    answers: &PairingAnswers,
    fp: String,
    now: Instant,
) -> Result<Input, ApprovalRefused> {
    card.approve(&fp, now)?;
    // Checked now, so the name prompt never opens for an approval that
    // cannot be sent; the request itself is built when the name is.
    answers.approval(&fp, "")?;
    Ok(Input::TrustedName {
        fp,
        buf: String::new(),
        grant: answers.controller.map(|c| (c, answers.clipboard)),
    })
}

/// A key on the pairing prompt that answers one of its questions (#220,
/// #182): `1` this machine controls that one, `2` that one controls this
/// one, `3` each controls the other, and `c` the clipboard, yes or no.
/// `true` when the key was one of those.
fn answer_key(answers: &mut PairingAnswers, code: KeyCode) -> bool {
    match code {
        KeyCode::Char(d @ '1'..='3') => {
            answers.controller = Controller::ALL.get(d as usize - '1' as usize).copied();
            true
        }
        KeyCode::Char('c') => {
            answers.clipboard = !answers.clipboard;
            true
        }
        _ => false,
    }
}

/// A key on the number card, as the request it sends (#11, #167): `y`
/// confirms the number this machine shows, `1` to `3` pick one of the three
/// the machine being added offers, and `n` or Esc ends the pairing ("none of
/// these"). Once this machine answered only ending it is left. Any other key
/// does nothing.
fn check_key(card: &PairingCheckCard, code: KeyCode) -> Option<FrontendRequest> {
    if matches!(code, KeyCode::Char('n') | KeyCode::Esc) {
        return Some(card.cancel());
    }
    if card.answered {
        return None;
    }
    match (&card.check, code) {
        (PairingCheck::Show(number), KeyCode::Char('y')) => Some(card.answer(number)),
        (PairingCheck::Pick(choices), KeyCode::Char(d @ '1'..='3')) => choices
            .get(d as usize - '1' as usize)
            .map(|number| card.answer(number)),
        _ => None,
    }
}

/// Active text-input edit, if any.
enum Input {
    /// Adding a device: `host` or `host:port`.
    Add { buf: String },
    /// Naming a device this machine dials. Only its name: where it is
    /// dialled and its pin stay (#13).
    Name { handle: ClientHandle, buf: String },
    /// Editing where a device this machine dials is dialled: its hostname or
    /// address. `pin` is the client's pin when the edit opened, which the
    /// request carries (#94), and which the new address keeps (#99).
    Hostname {
        handle: ClientHandle,
        pin: Option<String>,
        buf: String,
    },
    /// Naming a peer. `grant` distinguishes the two things this used to
    /// conflate: approving a NEW device (a trust grant, with the answers its
    /// card was given) versus renaming one that is already trusted (`None`).
    /// They were the same wire request, so a rename could not be expressed
    /// without also expressing "trust this fingerprint".
    TrustedName {
        fp: String,
        buf: String,
        grant: Option<(Controller, bool)>,
    },
    /// Editing the daemon's listen port.
    Port { buf: String },
}

impl Input {
    fn buf_mut(&mut self) -> &mut String {
        match self {
            Input::Add { buf } => buf,
            Input::Name { buf, .. } => buf,
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
        /// The outgoing client's pin when this was armed, which the delete
        /// carries (#94).
        pin: Option<String>,
        destructive: bool,
    },
    /// Turn a paired device's clipboard off. Asked first; `c` again turns it
    /// back on (#182).
    ClipboardOff { label: String, fp: String },
}

/// What the TUI says when it drops an armed action.
const CHANGED_NOTE: &str = "That device changed, so nothing was done. Check it and try again.";

/// What saving the name typed for the device `handle` sends: that name, or
/// none for a blank one, so it goes by its hostname or pairing again (#13).
fn name_request(handle: ClientHandle, buf: &str) -> FrontendRequest {
    let name = buf.trim();
    FrontendRequest::UpdateLabel(handle, (!name.is_empty()).then(|| name.to_string()))
}

/// What `n` opens on the row `d`, which is not revoked.
fn name_input(d: &Device) -> Option<Input> {
    match (&d.send, &d.fingerprint) {
        // a device this machine dials has a name of its own, apart from the
        // address it dials (#13)
        (Some(s), _) => Some(Input::Name {
            handle: s.handle,
            buf: d.label.clone(),
        }),
        // receive-only: re-authorizing the same fingerprint with a new
        // description IS the rename
        (None, Some(fp)) if d.receive => Some(Input::TrustedName {
            fp: fp.clone(),
            buf: d.label.clone(),
            grant: None,
        }),
        _ => None,
    }
}

/// Drop an armed delete or an open rename whose device is gone or now pinned
/// to another machine. Returns whether anything was dropped.
///
/// Both hold a handle while the user decides. A reload can replace the device
/// behind it, and a dial can pin it to a different machine, and a delete
/// revokes the pin: confirming then would act on something the screen no
/// longer shows (#94).
fn drop_stale(model: &AppModel, confirm: &mut Option<Confirm>, input: &mut Option<Input>) -> bool {
    let mut dropped = false;
    if let Some(Confirm::Remove {
        handle: Some(h),
        pin,
        ..
    }) = confirm.as_ref()
    {
        if !model.still_names(*h, pin.as_deref()) {
            *confirm = None;
            dropped = true;
        }
    }
    if let Some(Confirm::ClipboardOff { fp, .. }) = confirm.as_ref() {
        if !model.clipboard(fp).is_some_and(Clipboard::is_on) {
            *confirm = None;
            dropped = true;
        }
    }
    if let Some(Input::Hostname { handle, pin, .. }) = input.as_ref() {
        if !model.still_names(*handle, pin.as_deref()) {
            *input = None;
            dropped = true;
        }
    }
    dropped
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

/// A device the user asked to add: its address, port and edge, waiting for
/// the handle the daemon assigns.
type NewDevice = (String, u16, Position);

/// Ask the daemon to create a device, and stage `device` for its handle.
///
/// `request` returns the connection that took the request, the model's
/// `link`, or `None` when no daemon did. Then nothing is staged: a staged add
/// with none in flight would claim whichever handle appears next, another
/// device's.
fn stage_add(
    request: impl FnOnce(FrontendRequest) -> Option<u64>,
    device: NewDevice,
) -> Option<(u64, NewDevice)> {
    request(FrontendRequest::Create).map(|link| (link, device))
}

/// The staged add and its handle, once `arrived` is a handle this frontend
/// had not seen; left staged until then.
///
/// `link` is the connection the model now describes. An add staged on
/// another one is dropped: that connection was lost, and the `Create` or any
/// word of its handle with it, so the next handle to appear is another
/// device's, and would be given this one's address, edge and a switch-on
/// (#34).
fn claim_add(
    staged: &mut Option<(u64, NewDevice)>,
    link: u64,
    arrived: Option<ClientHandle>,
) -> Option<(ClientHandle, NewDevice)> {
    match (staged.take()?, arrived) {
        ((on, _), _) if on != link => None,
        ((_, device), Some(handle)) => Some((handle, device)),
        (kept, None) => {
            *staged = Some(kept);
            None
        }
    }
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
/// `launch` is what the binary knows as it opens: its own build, and why a
/// service it tried to start did not come up.
pub async fn run(launch: Launch) -> Result<(), TuiError> {
    let opening = opening_notice(&launch, Instant::now());
    let client = FrontendClient::spawn(launch);

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
    // Which machine the pairing prompt shows. It keeps that machine while its
    // request is live, so another machine asking cannot take over the prompt
    // between reading it and pressing `y` (#168).
    let mut card = PairingCard::default();
    // What was answered on that prompt: which way control goes, and the
    // clipboard (#220, #182).
    let mut answers = PairingAnswers::default();
    let mut show_log = false;
    let mut notice: Option<(String, Instant)> = opening;
    // The model's error sequence last put in the footer.
    let mut errors_seen: u64 = 0;
    // A device the user just asked to create, awaiting the handle the daemon
    // assigns: `Create` is fire-and-forget, and the handle only exists once the
    // resulting `Created` event lands in a snapshot. Applied below as soon as a
    // handle we have not seen before shows up. Without this, TUI "add" made a
    // blank unnamed card with no address, no port and no edge — a device that
    // could never connect and that the TUI had no way to finish configuring.
    let mut pending_new: Option<(u64, NewDevice)> = None;
    let mut known_handles: HashSet<ClientHandle> = HashSet::new();

    let result = loop {
        let model = client.snapshot();

        // finish an add as soon as the daemon hands back a handle
        let current: HashSet<ClientHandle> = model.clients.keys().copied().collect();
        let arrived = current.difference(&known_handles).copied().next();
        if let Some((h, (host, port, pos))) = claim_add(&mut pending_new, model.link, arrived) {
            // Just created: never connected, so no pin.
            client.request(FrontendRequest::UpdateHostname {
                handle: h,
                hostname: Some(host),
                fingerprint: None,
            });
            client.request(FrontendRequest::UpdatePort(h, port));
            client.request(FrontendRequest::UpdatePosition(h, pos));
            // actually try the machine: an inert card that is never
            // dialed looks identical to a broken one.
            client.request(FrontendRequest::Activate(h, true));
        }
        known_handles = current;

        // A request refused with no daemon, or one the daemon never took, is
        // said here rather than only in the log (#34).
        if let Some(error) = new_error(&model, &mut errors_seen) {
            notice = Some((error, Instant::now()));
        }

        if drop_stale(&model, &mut confirm, &mut input) {
            notice = Some((CHANGED_NOTE.to_string(), Instant::now()));
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
        let pairing: Option<PairingAttempt> = card
            .show(&model, Instant::now(), |fp| {
                dismissed.get(fp).is_some_and(|t| t.elapsed() < DISMISS_TTL)
            })
            .cloned();
        // The answers belong to the machine on the prompt, and go when it
        // changes (#168).
        if let Some(p) = &pairing {
            answers.for_card(&p.fingerprint);
        }

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
                pairing.as_ref(),
                &answers,
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
                                        pending_new = stage_add(
                                            |r| client.request_on(r),
                                            (host, port, free_edge(&model)),
                                        );
                                    }
                                    Err(msg) => {
                                        notice = Some((msg.to_string(), Instant::now()));
                                    }
                                },
                                Input::Name { handle, buf } => {
                                    client.request(name_request(handle, &buf));
                                }
                                Input::Hostname { handle, pin, buf } => {
                                    let val = (!buf.trim().is_empty()).then_some(buf);
                                    client.request(FrontendRequest::UpdateHostname {
                                        handle,
                                        hostname: val,
                                        fingerprint: pin,
                                    });
                                }
                                Input::TrustedName { fp, buf, grant } => match grant {
                                    // the same request, and the same fallback
                                    // name, the GUI sends
                                    Some((controller, clipboard)) => {
                                        if let Ok(request) = hops_frontend_core::approval_request(
                                            &fp,
                                            &buf,
                                            Some(controller),
                                            clipboard,
                                        ) {
                                            client.request(request);
                                        }
                                    }
                                    None => {
                                        let desc = if buf.trim().is_empty() {
                                            hops_frontend_core::fallback_label(&fp)
                                        } else {
                                            buf.trim().to_string()
                                        };
                                        client.request(FrontendRequest::SetLabel(fp, desc));
                                    }
                                },
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
                                if let Some(request) = confirm.take().and_then(confirmed) {
                                    client.request(request);
                                }
                            }
                            KeyCode::Char('n') | KeyCode::Esc => confirm = None,
                            _ => {}
                        }
                    } else if let Some(check) = model.pairing_check() {
                        // ---- the number card: before any approval card ----
                        if let Some(request) = check_key(check, k.code) {
                            client.request(request);
                        }
                    } else if let Some(fp) = pairing.as_ref().map(|a| a.fingerprint.clone()) {
                        // ---- pairing-approval prompt ----
                        match k.code {
                            // The name prompt that follows is bound to this
                            // machine, and only if the prompt has shown it long
                            // enough for the key to have been meant for it.
                            KeyCode::Char('y') => {
                                match approve_prompt(&card, &answers, fp, Instant::now()) {
                                    Ok(naming) => input = Some(naming),
                                    Err(refused) => {
                                        notice =
                                            Some((refused.notice().to_string(), Instant::now()));
                                    }
                                }
                            }
                            code if answer_key(answers.for_card(&fp), code) => {}
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
                            KeyCode::Char('s') => {
                                client.request(FrontendRequest::SaveConfiguration);
                            }
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
                            KeyCode::Char('g') if hops_frontend_core::prefs::CAN_SWITCH => {
                                ratatui::restore();
                                let err = hops_frontend_core::prefs::switch_to(Frontend::Gui);
                                log::warn!("could not switch to the graphical interface: {err}");
                                // exec() failed (or this build has no GUI) — the
                                // process is still us, so put the terminal back.
                                terminal = ratatui::init();
                            }
                            KeyCode::Char('a') => {
                                // Opening add device is what lets a pairing
                                // prompt appear here, for two minutes (#195).
                                client.request(FrontendRequest::OpenPairing);
                                input = Some(Input::Add { buf: String::new() });
                            }
                            // ---- actions on the selected device ----
                            KeyCode::Char('n') => match selected {
                                Some(d) if d.trust == TrustState::Revoked => {
                                    notice = Some((REVOKED_NOTE.to_string(), Instant::now()));
                                }
                                Some(d) => {
                                    if let Some(open) = name_input(d) {
                                        input = Some(open);
                                    }
                                }
                                None => {}
                            },
                            // where a device this machine dials is dialled
                            KeyCode::Char('h') => match selected {
                                Some(d) if d.trust == TrustState::Revoked => {
                                    notice = Some((REVOKED_NOTE.to_string(), Instant::now()));
                                }
                                Some(Device { send: Some(s), .. }) => {
                                    input = Some(Input::Hostname {
                                        handle: s.handle,
                                        pin: s.state.peer_fingerprint.clone(),
                                        buf: s.config.hostname.clone().unwrap_or_default(),
                                    });
                                }
                                _ => {
                                    notice = Some((NO_SEND_NOTE.to_string(), Instant::now()));
                                }
                            },
                            KeyCode::Char('p') => match selected.and_then(|d| d.send.as_ref()) {
                                Some(s) => {
                                    client.request(FrontendRequest::UpdatePosition(
                                        s.handle,
                                        next_pos(&s.config.pos),
                                    ));
                                }
                                None => {
                                    notice = Some((NO_SEND_NOTE.to_string(), Instant::now()));
                                }
                            },
                            KeyCode::Char(' ') => match selected.and_then(|d| d.send.as_ref()) {
                                Some(s) => {
                                    client.request(FrontendRequest::Activate(
                                        s.handle,
                                        !s.state.active,
                                    ));
                                }
                                None => {
                                    notice = Some((NO_SEND_NOTE.to_string(), Instant::now()));
                                }
                            },
                            KeyCode::Char('c') => match clipboard_key(&model, selected) {
                                Ok(ClipboardKey::AskOff(ask)) => confirm = Some(ask),
                                Ok(ClipboardKey::TurnOn(request)) => {
                                    client.request(request);
                                }
                                Err(why) => notice = Some((why.to_string(), Instant::now())),
                            },
                            KeyCode::Char('d') | KeyCode::Delete => match selected {
                                // already expelled — there is nothing left to do
                                // to it, and offering one would imply a way back
                                Some(d) if d.trust == TrustState::Revoked => {
                                    notice = Some((REVOKED_NOTE.to_string(), Instant::now()));
                                }
                                Some(d) => {
                                    let handle = d.send.as_ref().map(|s| s.handle);
                                    let pin = d
                                        .send
                                        .as_ref()
                                        .and_then(|s| s.state.peer_fingerprint.clone());
                                    let fp = d.fingerprint.clone();
                                    confirm = Some(Confirm::Remove {
                                        label: d.label.clone(),
                                        handle,
                                        fp: fp.clone(),
                                        pin,
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

    ratatui::restore();
    result
}

/// Shown when a key is pressed on a row it cannot apply to.
const REVOKED_NOTE: &str =
    "This device was removed. It must pair again with a new identity — there is no way back in.";
const NO_SEND_NOTE: &str =
    "This device only connects in to you. Add it as a device to cross to it.";
const NO_CLIPBOARD_NOTE: &str = "This device is not paired, so it has no clipboard to switch.";

/// The request a confirmation answered `y` sends, if any.
fn confirmed(confirm: Confirm) -> Option<FrontendRequest> {
    match confirm {
        // Deleting the outgoing client is the whole removal: the daemon
        // tombstones the pinned fingerprint with it. Only a peer we have no
        // client for needs the allowlist request.
        Confirm::Remove {
            handle: Some(h),
            pin,
            ..
        } => Some(FrontendRequest::Delete {
            handle: h,
            fingerprint: pin,
        }),
        Confirm::Remove { fp, .. } => fp.map(FrontendRequest::RemoveAuthorizedKey),
        Confirm::ClipboardOff { fp, .. } => Some(FrontendRequest::DisableClipboard(fp)),
    }
}

/// The clipboard with a listed device, if a pairing holds one.
fn clipboard_of(model: &AppModel, d: &Device) -> Option<Clipboard> {
    d.fingerprint.as_deref().and_then(|fp| model.clipboard(fp))
}

/// What `c` does on a paired row: the per-device clipboard switch (#182).
enum ClipboardKey {
    /// Ask before turning it off.
    AskOff(Confirm),
    /// Turn it back on, which the daemon does in the directions the pairing
    /// drives, and refuses while a peer drives this machine (#107).
    TurnOn(FrontendRequest),
}

/// What `c` does on the selected row: ask before turning its clipboard off,
/// turn an off one back on, or say why there is no clipboard to switch.
fn clipboard_key(
    model: &AppModel,
    selected: Option<&Device>,
) -> Result<ClipboardKey, &'static str> {
    let Some(d) = selected else {
        return Err(NO_CLIPBOARD_NOTE);
    };
    match (d.fingerprint.clone(), clipboard_of(model, d)) {
        (Some(fp), Some(c)) if c.is_on() => Ok(ClipboardKey::AskOff(Confirm::ClipboardOff {
            label: d.label.clone(),
            fp,
        })),
        (Some(fp), Some(_)) => Ok(ClipboardKey::TurnOn(FrontendRequest::EnableClipboard(fp))),
        _ => Err(NO_CLIPBOARD_NOTE),
    }
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

/// The peer's build id, from the `Hello` proto event.
///
/// The daemon has always known what build the machine on the other end is
/// running, and no frontend showed it. Every "which build is each box on?"
/// question this month cost an SSH round trip to go and ask — and on the night
/// the Windows box's SSH was unreachable, the answer was sitting in memory on
/// this side the whole time (#45).
///
/// `None` means no `Hello` yet: a fresh connection, or a peer predating the
/// event. Render that as `build ?` rather than blank, so "we do not know" is
/// visibly different from "there is nothing to show".
fn peer_build(d: &Device) -> String {
    match d.send.as_ref().and_then(|s| s.state.peer_commit) {
        Some(c) => format!("@{}", String::from_utf8_lossy(&c)),
        None => "@?".to_string(),
    }
}

/// The model's latest error, if it arrived since `seen`, which is advanced.
fn new_error(model: &AppModel, seen: &mut u64) -> Option<String> {
    if model.error_seq == *seen {
        return None;
    }
    *seen = model.error_seq;
    model.latest_error().map(str::to_owned)
}

/// One row of the unified device list.
///
/// The two facets a device can have — we cross *to* it, it may connect *in* to
/// us — are shown as one arrow badge rather than as membership of two different
/// lists, which is the whole point of the projection.
/// `live` is false while no daemon is connected: the row is then what was
/// last known, not what is, and is drawn muted with a hollow dot (#34).
fn device_row(
    d: &Device,
    clipboard: Option<Clipboard>,
    theme: &Theme,
    live: bool,
) -> ListItem<'static> {
    let muted = Style::default().fg(col(theme.muted));
    let revoked = d.trust == TrustState::Revoked;

    let dot = if revoked {
        Span::styled("⊘", Style::default().fg(col(theme.error)))
    } else if d.refuses_our_input() {
        // Checked BEFORE the green arm. `online` is about the inbound
        // direction and must not mask a device that will refuse our input
        // (#92).
        Span::styled("●", Style::default().fg(col(theme.error)))
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
        return row_item(spans, live, theme);
    }

    spans.push(Span::styled(
        match &d.fingerprint {
            Some(fp) => format!("{}  ", short_fp(fp)),
            None => "not yet identified  ".to_string(),
        },
        muted,
    ));

    if let Some(s) = &d.send {
        spans.push(Span::styled(format!("{} ", peer_build(d)), muted));
        spans.push(Span::raw(format!("{} ", send_addr(s))));
        spans.push(Span::styled(
            format!("({}) ", s.config.pos),
            Style::default().fg(col(theme.accent)),
        ));
        spans.push(Span::styled(
            if d.refuses_our_input() {
                // The dot alone cannot say WHY. This is the fact the user needs:
                // the far end is up and refusing, not unreachable (#92).
                " not accepting input"
            } else if s.state.active {
                " active"
            } else {
                " off"
            },
            if d.refuses_our_input() {
                Style::default().fg(col(theme.error))
            } else if s.state.active {
                Style::default().fg(col(theme.foreground))
            } else {
                muted
            },
        ));
    } else {
        spans.push(Span::styled("connects in only", muted));
    }
    // Off is said as plainly as on: there is no way to turn it back on from
    // here yet, so the row is the one place the user learns which it is.
    if let Some(c) = clipboard {
        spans.push(Span::styled(
            format!("  {}", c.describe()),
            if c.is_on() {
                Style::default().fg(col(theme.foreground))
            } else {
                muted
            },
        ));
    }

    row_item(spans, live, theme)
}

/// A device row's spans as a list item: as built while a daemon is
/// connected, and all muted, the dot hollow, while none is.
fn row_item(spans: Vec<Span<'static>>, live: bool, theme: &Theme) -> ListItem<'static> {
    if live {
        return ListItem::new(Line::from(spans));
    }
    let muted = Style::default().fg(col(theme.muted));
    let spans: Vec<Span<'static>> = spans
        .into_iter()
        .enumerate()
        .map(|(i, span)| match i {
            0 => Span::styled("○", muted),
            _ => Span::styled(span.content, muted),
        })
        .collect();
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
    pairing: Option<&PairingAttempt>,
    answers: &PairingAnswers,
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

    // header: connection + capture/emulation status
    let conn = if model.connected {
        Span::styled("● connected", Style::default().fg(col(theme.success)))
    } else {
        Span::styled("○ connecting…", Style::default().fg(col(theme.warn)))
    };
    let status = Line::from(vec![
        conn,
        Span::raw("   capture: "),
        capture_span(&model.capture, theme),
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
    // What is wrong with the service: a start that did not come up, or a
    // daemon of another build. Wrapped under the status line.
    let mut header = vec![status];
    // Why capture, which should run, does not (#91).
    if let Some(problem) = model.capture_problem() {
        header.push(Line::from(Span::styled(
            problem,
            Style::default().fg(col(theme.warn)),
        )));
    }
    if let Some(problem) = model.service_problem() {
        for line in problem.lines() {
            header.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(col(theme.warn)),
            )));
        }
    }
    let title = format!(" hops · {} ", theme.name);
    let header = Paragraph::new(header)
        .wrap(Wrap { trim: false })
        .style(base)
        .block(panel(Span::styled(title, accent), false));
    // Sized by the same word wrapping that renders it, so its last line (a
    // log path, say) is never cut off. The device list keeps three rows.
    let header_rows = u16::try_from(header.line_count(f.area().width.saturating_sub(2)))
        .unwrap_or(u16::MAX)
        .min(f.area().height.saturating_sub(6 + 3))
        .max(3);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_rows),
            Constraint::Min(0),
            Constraint::Length(6),
        ])
        .split(f.area());
    f.render_widget(header, chunks[0]);

    // body: one row per physical peer, both directions on the same line
    let rows: Vec<ListItem> = if devices.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no devices yet — press a to add the machine you want to cross to",
            muted,
        )))]
    } else {
        devices
            .iter()
            .map(|d| device_row(d, clipboard_of(model, d), theme, model.connected))
            .collect()
    };
    f.render_stateful_widget(
        List::new(rows)
            .block(panel(
                if model.connected || devices.is_empty() {
                    Span::styled(" devices ", accent)
                } else {
                    Span::styled(" devices · last known, not connected ", muted)
                },
                true,
            ))
            .highlight_style(highlight)
            .highlight_symbol("▶ "),
        chunks[1],
        list_state,
    );

    // footer: input / confirm / notice / keymap, plus our own fingerprint
    let selected = devices.get(selected_index(list_state));
    let line1 = footer_line(
        input,
        confirm,
        notice,
        selected,
        selected.and_then(|d| clipboard_of(model, d)),
        theme,
    );
    let fp = model.fingerprint.as_deref().unwrap_or("—");
    let mut footer = vec![
        line1,
        Line::from(vec![
            Span::styled("this device: ", muted),
            Span::styled(fp.to_string(), Style::default().fg(col(theme.accent))),
        ]),
    ];
    // Stays after the add prompt closes: the other machine can still answer
    // until the window runs out, and this is the only sign that it can.
    if let Some(left) = model.pairing_seconds_left(Instant::now()) {
        footer.push(Line::from(vec![
            Span::styled(
                format!("pairing open · {}:{:02}", left / 60, left % 60),
                Style::default().fg(col(theme.accent)),
            ),
            Span::styled(" — open add device on the other machine too", muted),
        ]));
    }
    f.render_widget(
        Paragraph::new(footer)
            .style(base)
            .wrap(Wrap { trim: false })
            .block(panel(Span::styled("", accent), false)),
        chunks[2],
    );

    // overlays (only when nothing else is capturing input): the number card
    // first, then a pairing request
    if let Some(check) = model.pairing_check() {
        if input.is_none() && confirm.is_none() {
            check_popup(f, check, theme);
        }
    } else if let Some(attempt) = pairing {
        if input.is_none() && confirm.is_none() {
            // The shown machine's own origin and address, not the latest
            // request's: they are different machines when two are waiting.
            pairing_popup(
                f,
                &attempt.fingerprint,
                Some(attempt.origin),
                attempt.addr,
                answers,
                theme,
            );
        }
    } else if show_log && input.is_none() && confirm.is_none() {
        log_overlay(f, &model.messages, theme);
    }
}

fn selected_index(state: &ListState) -> usize {
    state.selected().unwrap_or(0)
}

/// The notice the TUI opens with: that the front door restarted a service of
/// another build (#222). It is also in the log.
fn opening_notice(launch: &Launch, now: Instant) -> Option<(String, Instant)> {
    launch.restarted.clone().map(|note| (note, now))
}

/// Build the footer's first line: an active text-input, a confirmation, a
/// transient notice, or the keymap for the selected row.
fn footer_line(
    input: Option<&Input>,
    confirm: Option<&Confirm>,
    notice: Option<&str>,
    selected: Option<&Device>,
    clipboard: Option<Clipboard>,
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
            Input::Name { handle, buf } => (format!("name [{handle}]: "), buf.clone()),
            Input::Hostname { handle, buf, .. } => (format!("address [{handle}]: "), buf.clone()),
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
    if let Some(Confirm::ClipboardOff { label, .. }) = confirm {
        return Line::from(vec![
            Span::styled(format!("turn the clipboard off for {label}? "), warn),
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
                for (k, label) in [("h", " address  "), ("p", " pos  "), ("spc", " on/off  ")] {
                    spans.push(Span::styled(k, key));
                    spans.push(Span::raw(label));
                }
            }
            if let Some(c) = clipboard {
                spans.push(Span::styled("c", key));
                spans.push(Span::raw(if c.is_on() {
                    " clipboard off  "
                } else {
                    " clipboard on  "
                }));
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
        // Offered only where the switch can happen (#173).
        if k == "g" && !hops_frontend_core::prefs::CAN_SWITCH {
            continue;
        }
        spans.push(Span::styled(k, key));
        spans.push(Span::raw(label));
    }
    Line::from(spans)
}

/// Render a centered approve/deny popup for an untrusted incoming peer.
fn pairing_popup(
    f: &mut Frame,
    fp: &str,
    origin: Option<AttemptOrigin>,
    addr: Option<std::net::SocketAddr>,
    answers: &PairingAnswers,
    theme: &Theme,
) {
    let ours = origin == Some(AttemptOrigin::OutboundDial);
    // one extra row when there is an address line to render
    let area = centered_rect(70, if addr.is_some() { 13 } else { 12 }, f.area());
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
        .title(Span::styled(
            // Say which. A prompt the console SUMMONED by dialling out must not
            // read the same as a peer knocking (#61).
            if ours {
                " we dialled this device "
            } else {
                " pairing request "
            },
            warn,
        ));
    let mut body = vec![
        Line::from(Span::styled(
            if ours {
                // We went looking for it. Nobody knocked — do not imply they did.
                "This machine dialled out and found an untrusted device:"
            } else {
                "An untrusted device asks to pair with this machine:"
            },
            base,
        )),
        // Before the fingerprint, and brighter than it: the address is the only
        // part of this a human can check against what they typed (#93). The
        // fingerprint is opaque to them.
        Line::from(Span::styled(fp.to_string(), muted)),
        Line::from(Span::raw("")),
        // Asked, never assumed (#220): nothing is marked until a key is
        // pressed, and approving waits for it.
        Line::from(Span::styled("Which machine is in control?", base)),
    ];
    for (i, c) in Controller::ALL.into_iter().enumerate() {
        let chosen = answers.controller == Some(c);
        body.push(Line::from(vec![
            Span::styled(format!("  {} ", i + 1), key),
            Span::styled(
                if chosen { "(*) " } else { "( ) " },
                if chosen { key } else { muted },
            ),
            Span::styled(c.describe(), if chosen { base } else { muted }),
        ]));
    }
    body.push(Line::from(vec![
        Span::styled("  c ", key),
        Span::styled(
            if answers.clipboard { "[x] " } else { "[ ] " },
            if answers.clipboard { key } else { muted },
        ),
        Span::styled(
            if answers.clipboard {
                "share the clipboard: yes, the way control goes"
            } else {
                "share the clipboard: no"
            },
            if answers.clipboard { base } else { muted },
        ),
    ]));
    body.push(Line::from(Span::raw("")));
    body.push(if answers.controller.is_some() {
        Line::from(vec![
            Span::styled("y", key),
            Span::styled(" trust & name      ", muted),
            Span::styled("n", key),
            Span::styled(" deny (for now)", muted),
        ])
    } else {
        Line::from(vec![
            Span::styled("1 2 3", key),
            Span::styled(" choose first      ", muted),
            Span::styled("n", key),
            Span::styled(" deny (for now)", muted),
        ])
    });
    if let Some(a) = addr {
        // our dial: the address that answered (#93); a knock: where from (#83)
        let line = if ours {
            format!("{a} answered")
        } else {
            format!("from {a}")
        };
        body.insert(1, Line::from(Span::styled(line, key)));
    }
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .style(base)
            .block(block),
        area,
    );
}

/// Render the number card (#11, #167): on the machine adding the other, the
/// number and a confirm; on the machine being added, three numbers to pick
/// from. Nothing moves until both machines answered.
fn check_popup(f: &mut Frame, card: &PairingCheckCard, theme: &Theme) {
    let base = Style::default()
        .bg(col(theme.background))
        .fg(col(theme.foreground));
    let accent = Style::default()
        .fg(col(theme.accent))
        .bg(col(theme.background));
    let muted = Style::default()
        .fg(col(theme.muted))
        .bg(col(theme.background));
    let number = base.add_modifier(Modifier::BOLD);
    let show = matches!(card.check, PairingCheck::Show(_));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(accent)
        .style(base)
        .title(Span::styled(
            if show {
                " pairing · confirm the number "
            } else {
                " pairing · pick the number "
            },
            accent,
        ));
    let numbers = match &card.check {
        PairingCheck::Show(n) => Line::from(Span::styled(spaced_number(n), number)),
        PairingCheck::Pick(choices) => Line::from(
            choices
                .iter()
                .enumerate()
                .flat_map(|(i, n)| {
                    [
                        Span::styled(if i == 0 { "" } else { "    " }, base),
                        Span::styled(format!("{}", i + 1), accent),
                        Span::styled(format!(" {}", spaced_number(n)), number),
                    ]
                })
                .collect::<Vec<_>>(),
        ),
    }
    .centered();
    let say = match (show, card.answered) {
        (true, false) => {
            "The other machine asks which of three numbers it sees. Once this one is picked \
             there, confirm here."
        }
        (true, true) => "Confirmed here. Waiting for the other machine to pick it.",
        (false, false) => {
            "Which number does the other machine show? A wrong pick ends the pairing."
        }
        (false, true) => "Picked. Waiting for the other machine to confirm.",
    };
    let keys = match (show, card.answered) {
        (_, true) => vec![Span::styled("n", accent), Span::styled(" cancel", muted)],
        (true, false) => vec![
            Span::styled("y", accent),
            Span::styled(" confirm      ", muted),
            Span::styled("n", accent),
            Span::styled(" cancel", muted),
        ],
        (false, false) => vec![
            Span::styled("1-3", accent),
            Span::styled(" pick      ", muted),
            Span::styled("n", accent),
            Span::styled(" none of these", muted),
        ],
    };
    let mut body = vec![Line::from(Span::styled(card.from(), muted)), Line::from("")];
    // Once picked, the three are gone: there is nothing left to choose.
    if show || !card.answered {
        body.extend([numbers, Line::from("")]);
    }
    body.extend([
        Line::from(Span::styled(say, base)),
        Line::from(""),
        Line::from(keys),
    ]);
    // As tall as what it says: the explanation wraps on a narrow terminal.
    let inner = centered_rect(70, 0, f.area())
        .width
        .saturating_sub(2)
        .max(1) as usize;
    let wrapped = say.chars().count().div_ceil(inner).saturating_sub(1);
    let area = centered_rect(70, (body.len() + wrapped + 2) as u16, f.area());
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

/// Capture's state: a capture that failed reads apart from one that is off.
fn capture_span(s: &CaptureState, theme: &Theme) -> Span<'static> {
    match s {
        CaptureState::Enabled => status_span(Status::Enabled, theme),
        CaptureState::Disabled => status_span(Status::Disabled, theme),
        CaptureState::Failed(_) => Span::styled("failed", Style::default().fg(col(theme.error))),
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
    use hops_frontend_core::{ClientConfig, ClientState, FrontendEvent, RevokedEntry};
    use ratatui::{Terminal, backend::TestBackend};

    const FP: &str = "1e:19:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8";
    const OTHER_FP: &str = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

    // LEDGER T531 | class B | 1 return value + requests passed to stage_add's sender
    /// An add no daemon took stages nothing: the first handles a daemon
    /// reports later are the existing devices', and one of them would take
    /// this address and edge.
    #[test]
    fn an_add_no_daemon_took_stages_nothing() {
        let mut sent = Vec::new();
        let staged = stage_add(
            |r| {
                sent.push(r);
                None
            },
            ("desk-pc.local".into(), 4242, Position::Left),
        );
        assert!(
            matches!(sent.as_slice(), [FrontendRequest::Create]),
            "the add did not ask the daemon for a handle: {sent:?}"
        );
        assert_eq!(
            staged, None,
            "an add that never reached a daemon was left waiting for a handle"
        );
        assert_eq!(
            stage_add(|_| Some(2), ("desk-pc.local".into(), 4242, Position::Left)),
            Some((2, ("desk-pc.local".into(), 4242, Position::Left))),
            "an add a daemon took must wait for its handle on that connection"
        );
    }

    // LEDGER T532 | class B | 1 return value + 6 struct state: claim_add and its staged add
    /// An add waits for its handle on the connection that took it, and is
    /// dropped once that connection is lost (#34).
    #[test]
    fn an_add_is_claimed_once_and_only_on_its_connection() {
        let add = || Some((0, ("desk-pc.local".to_string(), 4242, Position::Left)));

        let mut staged = add();
        assert_eq!(claim_add(&mut staged, 0, None), None);
        assert_eq!(
            staged,
            add(),
            "an add whose handle has not come yet was lost"
        );
        assert_eq!(
            claim_add(&mut staged, 0, Some(7)),
            Some((7, ("desk-pc.local".to_string(), 4242, Position::Left)))
        );
        assert_eq!(
            staged, None,
            "a claimed add would configure the next handle too"
        );

        let mut staged = add();
        assert_eq!(
            claim_add(&mut staged, 1, Some(7)),
            None,
            "an add staged before the daemon was lost gave its address, edge and \
             a switch-on to the next handle to appear"
        );
        assert_eq!(
            staged, None,
            "an add from a lost connection stayed staged, to claim a later handle"
        );
    }

    // LEDGER T15 | class B | 6 struct state: the TUI's armed Confirm and Input after drop_stale
    /// An armed delete and an open rename go once their device changes, and
    /// stay while it does not (#94).
    #[test]
    fn an_armed_delete_or_rename_is_dropped_when_its_device_changes() {
        let pinned = |fp: &str| ClientState {
            peer_fingerprint: Some(fp.to_string()),
            ..Default::default()
        };
        let mut model = AppModel::default();
        model.apply(FrontendEvent::Created(
            3,
            ClientConfig::default(),
            pinned(FP),
        ));
        let arm = || {
            (
                Some(Confirm::Remove {
                    label: "desk".into(),
                    handle: Some(3),
                    fp: Some(FP.into()),
                    pin: Some(FP.into()),
                    destructive: true,
                }),
                Some(Input::Hostname {
                    handle: 3,
                    pin: Some(FP.into()),
                    buf: String::new(),
                }),
            )
        };

        let (mut confirm, mut input) = arm();
        assert!(
            !drop_stale(&model, &mut confirm, &mut input) && confirm.is_some() && input.is_some(),
            "nothing about the device changed, and the armed actions were dropped"
        );

        model.apply(FrontendEvent::State(
            3,
            ClientConfig::default(),
            pinned(OTHER_FP),
        ));
        let (mut confirm, mut input) = arm();
        assert!(
            drop_stale(&model, &mut confirm, &mut input) && confirm.is_none() && input.is_none(),
            "the device is pinned to another machine now; confirming would act \
             on a machine this prompt never showed"
        );

        model.apply(FrontendEvent::Deleted(3));
        let (mut confirm, mut input) = arm();
        assert!(
            drop_stale(&model, &mut confirm, &mut input) && confirm.is_none() && input.is_none(),
            "the device is gone, and its armed actions stayed"
        );
    }

    /// Render `ui` into an off-screen terminal and return the visible text, one
    /// String per row. Rendering is the only way to catch a row that the
    /// projection produces but the view silently filters out — a logic-level
    /// assertion on `devices()` would have passed for every bug below.
    fn render(model: &AppModel, sel: usize) -> Vec<String> {
        render_at(model, sel, 120, 24)
    }

    fn render_at(model: &AppModel, sel: usize, width: u16, height: u16) -> Vec<String> {
        let devices = listable(model);
        let mut state = ListState::default();
        if !devices.is_empty() {
            state.select(Some(sel));
        }
        let theme = theme::default_theme();
        let mut term = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        term.draw(|f| {
            ui(
                f,
                model,
                &devices,
                &mut state,
                None,
                None,
                None,
                &Default::default(),
                None,
                false,
                &theme,
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

    /// With no daemon connected the rows are what was last known, and are
    /// drawn that way rather than live (#34).
    // LEDGER T521 | class B | 3 widget tree: ui() rendered to a test terminal
    #[test]
    fn with_no_daemon_the_rows_are_hollow_and_say_last_known() {
        let mut model = AppModel::default();
        model.connected = true;
        let live = ClientState {
            active: true,
            alive: true,
            active_addr: Some("192.0.2.5:4242".parse().expect("addr")),
            peer_fingerprint: Some(FP.into()),
            ..Default::default()
        };
        let config = ClientConfig {
            hostname: Some("studio-pc".into()),
            ..Default::default()
        };
        model.apply(FrontendEvent::Enumerate(vec![(0, config, live)]));
        let row = |m: &AppModel| {
            render(m, 0)
                .into_iter()
                .find(|l| l.contains("studio-pc"))
                .expect("the device row is on screen")
        };
        assert!(
            row(&model).contains('●'),
            "precondition: a live row has a solid dot"
        );

        model.connected = false;
        let out = screen(&model, 0);
        assert!(
            row(&model).contains('○') && !row(&model).contains('●'),
            "with no daemon the row still has a live dot:\n{out}"
        );
        assert!(
            out.contains("last known"),
            "with no daemon nothing says the list is the last known one:\n{out}"
        );
    }

    /// A refused request, and an error from the daemon, reach the footer
    /// once each (#34).
    // LEDGER T522 | class B | 1 return value: new_error over AppModel::apply
    #[test]
    fn each_new_error_reaches_the_footer_once() {
        let mut model = AppModel::default();
        let mut seen = 0;
        assert_eq!(new_error(&model, &mut seen), None);
        model.apply(FrontendEvent::Error("could not resolve studio-pc".into()));
        assert_eq!(
            new_error(&model, &mut seen).as_deref(),
            Some("could not resolve studio-pc")
        );
        assert_eq!(
            new_error(&model, &mut seen),
            None,
            "the same error was raised again"
        );
        model.apply(FrontendEvent::Error("could not resolve studio-pc".into()));
        assert!(
            new_error(&model, &mut seen).is_some(),
            "a repeat of the failure was not raised"
        );
    }

    /// A machine that may already drive this one answers this machine's dial.
    /// The TUI asks whether this machine may drive it: one approval grants one
    /// direction, so the reverse needs its own card (#166).
    // LEDGER T8 | class B | 3 widget tree: PairingCard::show, ui() into a TestBackend
    #[test]
    fn the_card_for_the_second_direction_is_shown() {
        use hops_frontend_core::{AttemptOrigin, FrontendEvent};
        let mut model = AppModel::default();
        model.apply(FrontendEvent::AuthorizedUpdated(
            [(FP.to_owned(), "desk mac".to_owned())].into(),
        ));
        model.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: FP.into(),
            origin: AttemptOrigin::OutboundDial,
            addr: Some("10.0.0.5:4242".parse().expect("addr")),
        });

        let pairing = PairingCard::default()
            .show(&model, Instant::now(), |_| false)
            .cloned();
        let devices = listable(&model);
        let mut state = ListState::default();
        let theme = theme::default_theme();
        let mut term = Terminal::new(TestBackend::new(120, 24)).expect("test terminal");
        term.draw(|f| {
            ui(
                f,
                &model,
                &devices,
                &mut state,
                None,
                None,
                pairing.as_ref(),
                &Default::default(),
                None,
                false,
                &theme,
            )
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let out = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            out.contains("we dialled this device") && out.contains("10.0.0.5:4242 answered"),
            "no card asks whether this machine may drive a peer that may \
             already drive it:\n{out}"
        );
    }

    /// The pairing prompt asks which machine is in control and whether to
    /// share the clipboard (#220, #182). Nothing is chosen until a key says
    /// so, `y` waits for a direction, and the answers go with the name to
    /// the approval, for the machine on the prompt only.
    // LEDGER E2b-3 | class B | 3 render + 1 return value: ui() on ratatui TestBackend, answer_key, approve_prompt
    #[test]
    fn the_pairing_prompt_asks_which_machine_is_in_control() {
        let mut model = AppModel::default();
        model.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: FP.into(),
            origin: AttemptOrigin::Inbound,
            addr: Some("10.0.0.7:51234".parse().expect("addr")),
        });
        let t0 = Instant::now();
        let mut card = PairingCard::default();
        let shown = card.show(&model, t0, |_| false).cloned().expect("a prompt");
        let theme = theme::default_theme();
        let render = |answers: &PairingAnswers, width: u16, height: u16| {
            let mut term = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
            term.draw(|f| {
                ui(
                    f,
                    &model,
                    &[],
                    &mut ListState::default(),
                    None,
                    None,
                    Some(&shown),
                    answers,
                    None,
                    false,
                    &theme,
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
                .collect::<Vec<_>>()
                .join("\n")
        };
        // Written out when asked, to be looked at.
        let keep = |name: &str, out: &str| {
            if let Some(dir) = std::env::var_os("HOPS_TUI_RENDERS") {
                let _ = std::fs::write(std::path::Path::new(&dir).join(name), out);
            }
        };

        let mut answers = PairingAnswers::default();
        answers.for_card(FP);
        let fresh = render(&answers, 100, 30);
        keep("tui-pairing-unanswered-100x30.txt", &fresh);
        keep(
            "tui-pairing-unanswered-80x24.txt",
            &render(&answers, 80, 24),
        );
        for line in Controller::ALL.map(|c| c.describe()) {
            assert!(
                fresh.contains(&format!("( ) {line}")),
                "the prompt does not offer \"{line}\" unchosen:\n{fresh}"
            );
        }
        assert!(
            fresh.contains("Which machine is in control?")
                && fresh.contains("share the clipboard: no")
                && fresh.contains("choose first")
                && !fresh.contains("(*)"),
            "a fresh prompt reads as answered, or does not ask:\n{fresh}"
        );
        assert!(
            matches!(
                approve_prompt(&card, &answers, FP.into(), t0 + Duration::from_secs(2)),
                Err(ApprovalRefused::NoController)
            ),
            "y approved before anyone chose which way control goes"
        );

        assert!(answer_key(answers.for_card(FP), KeyCode::Char('2')));
        assert!(answer_key(answers.for_card(FP), KeyCode::Char('c')));
        let answered = render(&answers, 100, 30);
        keep("tui-pairing-answered-100x30.txt", &answered);
        keep("tui-pairing-answered-80x24.txt", &render(&answers, 80, 24));
        assert!(
            answered.contains("(*) That machine controls this one")
                && answered.contains("[x] share the clipboard: yes")
                && answered.contains("trust & name"),
            "the answers given are not shown as given:\n{answered}"
        );
        match approve_prompt(&card, &answers, FP.into(), t0 + Duration::from_secs(2)) {
            Ok(Input::TrustedName { fp, grant, .. }) => assert_eq!(
                (fp.as_str(), grant),
                (FP, Some((Controller::ThatMachine, true))),
                "the name prompt is not bound to the answers given"
            ),
            _ => panic!("y with a direction chosen did not open the name prompt"),
        }

        // Another machine on the prompt starts with nothing answered.
        answers.for_card(OTHER_FP);
        assert_eq!(
            (answers.controller, answers.clipboard),
            (None, false),
            "answers given for one machine were kept for another"
        );
    }

    /// The pairing prompt names the machine it shows by that machine's own
    /// origin and address. The prompt can show an earlier request than the
    /// latest (#168), and the latest one's details were what it printed.
    // LEDGER T12 | class B | 3 render: ui() on ratatui TestBackend, PairingCard::show
    #[test]
    fn the_pairing_prompt_describes_the_machine_it_shows() {
        let mut model = AppModel::default();
        let knocked: std::net::SocketAddr = "10.0.0.7:51234".parse().expect("addr");
        let dialled: std::net::SocketAddr = "10.0.0.9:4242".parse().expect("addr");
        model.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: FP.into(),
            origin: AttemptOrigin::Inbound,
            addr: Some(knocked),
        });
        model.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: OTHER_FP.into(),
            origin: AttemptOrigin::OutboundDial,
            addr: Some(dialled),
        });
        let shown = PairingCard::default()
            .show(&model, Instant::now(), |_| false)
            .cloned()
            .expect("a prompt");
        assert_eq!(shown.fingerprint, FP);
        let theme = theme::default_theme();
        let mut term = Terminal::new(TestBackend::new(120, 24)).expect("test terminal");
        term.draw(|f| {
            ui(
                f,
                &model,
                &[],
                &mut ListState::default(),
                None,
                None,
                Some(&shown),
                &Default::default(),
                None,
                false,
                &theme,
            )
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let out: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            out.contains("pairing request") && out.contains("from 10.0.0.7:51234"),
            "the prompt for a machine that knocked from 10.0.0.7:51234 does not say so:\n{out}"
        );
        assert!(
            !out.contains("10.0.0.9") && !out.contains("we dialled"),
            "the prompt described the other waiting machine:\n{out}"
        );
    }

    /// While pairing prompts may appear here, the footer says so and for how
    /// long; once the window closes, the line goes (#195).
    #[test]
    fn the_footer_counts_down_the_pairing_window() {
        let mut model = AppModel::default();
        assert!(
            !screen(&model, 0).contains("pairing open"),
            "a closed pairing window was shown as open"
        );
        model.pairing_open_until = Some(Instant::now() + Duration::from_secs(102));
        let out = screen(&model, 0);
        assert!(
            out.contains("pairing open · 1:42") || out.contains("pairing open · 1:41"),
            "the open pairing window is not shown with its time left:\n{out}"
        );
        assert!(out.contains("open add device on the other machine too"));
    }

    /// The service's trouble is on screen, not only in a log: a start that
    /// did not come up (#189), or a daemon of another build.
    // LEDGER T62 | class B | 3 widget tree rendered to a test terminal
    #[test]
    fn the_header_says_what_is_wrong_with_the_service() {
        let mut model = AppModel::default();
        model.start_problem = Some(
            "The hops service started and stopped again before it answered. \
             Its log says why:\n/tmp/hops/daemon.log"
                .into(),
        );
        let out = screen(&model, 0);
        assert!(
            out.contains("stopped again") && out.contains("daemon.log"),
            "a failed start is not on screen:\n{out}"
        );

        model.connected = true;
        model.start_problem = None;
        model.this_build = Some(hops_frontend_core::Build {
            version: "0.13.0".into(),
            commit: "abcd1234".into(),
        });
        model.apply(hops_frontend_core::FrontendEvent::Enumerate(vec![]));
        let out = screen(&model, 0);
        assert!(
            out.contains("older build"),
            "a daemon of an older build is not on screen:\n{out}"
        );

        model.apply(hops_frontend_core::FrontendEvent::DaemonBuild(
            hops_frontend_core::Build {
                version: "0.13.0".into(),
                commit: "abcd1234".into(),
            },
        ));
        let out = screen(&model, 0);
        assert!(
            !out.contains("older build") && !out.contains("This app is"),
            "the same build is reported as a problem:\n{out}"
        );
    }

    /// The header grows by the rows its text wraps to at word boundaries, so
    /// the last line of a problem is on screen at every width. That line is
    /// the log path a failed start exists to show (#189).
    // LEDGER T72 | class B | 3 widget tree rendered at many terminal widths
    #[test]
    fn the_whole_service_problem_is_on_screen_at_every_width() {
        let mut failed = AppModel::default();
        failed.start_problem = Some(
            "The hops service started and stopped again before it answered. \
             Its log says why:\n/tmp/hops/daemon.log"
                .into(),
        );
        let mut mismatch = AppModel::default();
        mismatch.connected = true;
        mismatch.this_build = Some(hops_frontend_core::Build {
            version: "0.13.0".into(),
            commit: "abcd1234".into(),
        });
        mismatch.apply(hops_frontend_core::FrontendEvent::Enumerate(vec![]));
        // Another build the app left running, with the reason (#222).
        let mut left = mismatch.clone();
        left.left_running = Some(
            "hops did not restart it, because it was started from a terminal. Stop it, \
             then open hops again."
                .into(),
        );

        // The words inside the header box, in order, with the wrapping undone.
        let header_words = |model: &AppModel, width: u16| -> String {
            render_at(model, 0, width, 30)
                .iter()
                .skip(1)
                .take_while(|row| !row.starts_with('└'))
                .flat_map(|row| row.trim_matches('│').split_whitespace().map(str::to_owned))
                .collect::<Vec<_>>()
                .join(" ")
        };
        // The same, before the app connects: a daemon from before the token
        // cannot be connected to at all.
        let mut left_unreached = AppModel::default();
        left_unreached.start_problem = Some(
            "The hops service is running hops 0.12.0 (1111111), not this version. hops \
             did not restart it, because the hops service runs another copy of hops, \
             /Applications/hops.app/Contents/MacOS/hops. Stop it, then open hops again."
                .into(),
        );
        if let Some(out) = std::env::var_os("HOPS_TUI_RENDER") {
            let _ = std::fs::write(out, render_at(&left_unreached, 0, 80, 24).join("\n"));
        }
        let clipped: Vec<(u16, Vec<u16>)> = [&failed, &mismatch, &left, &left_unreached]
            .into_iter()
            .zip([0, 1, 2, 3])
            .map(|(model, case)| {
                let problem = model.service_problem().expect("a problem to show");
                let problem = problem.split_whitespace().collect::<Vec<_>>().join(" ");
                let widths = (50..=120)
                    .filter(|&width| !header_words(model, width).ends_with(&problem))
                    .collect();
                (case, widths)
            })
            .collect();
        assert!(
            clipped.iter().all(|(_, widths)| widths.is_empty()),
            "the header ends before the problem's last line, (case, widths): {clipped:?}\n{}",
            render_at(&failed, 0, 66, 30).join("\n")
        );
    }

    /// A capture that failed reads as failed, not off, with what to change
    /// under the status line (#91).
    // LEDGER T11 | class B | 3 widget tree: ui() rendered into a TestBackend
    #[test]
    fn a_capture_that_failed_says_so_and_what_to_change() {
        use hops_frontend_core::{CaptureFault, CaptureState, FrontendEvent, Permission};
        let mut model = AppModel::default();
        model.connected = true;
        model.apply(FrontendEvent::CaptureStatus(CaptureState::Failed(
            CaptureFault::Missing(vec![Permission::InputMonitoring]),
        )));
        let rows = render_at(&model, 0, 120, 30);
        if let Some(out) = std::env::var_os("HOPS_TUI_RENDER_CAPTURE") {
            let _ = std::fs::write(out, render_at(&model, 0, 80, 24).join("\n"));
        }
        let words = rows
            .iter()
            .flat_map(|row| row.trim_matches('│').split_whitespace().map(str::to_owned))
            .collect::<Vec<_>>()
            .join(" ");
        let problem = model.capture_problem().expect("a problem to show");
        let problem = problem.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains("capture: failed") && words.contains(&problem),
            "the header must say capture failed and why:\n{}",
            rows.join("\n")
        );
    }

    /// A service the front door restarted is said in the footer as the TUI
    /// opens (#222), whole, at the width of a default terminal.
    // LEDGER T2231 | class B | 3 widget tree: opening_notice, ui() into a TestBackend
    #[test]
    fn a_restarted_service_is_said_in_the_footer_as_the_tui_opens() {
        let note = "hops restarted its service because it was running hops 0.12.0 \
                    (1111111), not this version.";
        let launch = Launch {
            restarted: Some(note.into()),
            ..Launch::default()
        };
        let (notice, _) = opening_notice(&launch, Instant::now()).expect("a notice");
        let model = AppModel::launched(launch);
        let theme = theme::default_theme();
        let mut state = ListState::default();
        let mut term = Terminal::new(TestBackend::new(80, 24)).expect("test terminal");
        term.draw(|f| {
            ui(
                f,
                &model,
                &[],
                &mut state,
                None,
                None,
                None,
                &Default::default(),
                Some(&notice),
                false,
                &theme,
            )
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let rows: Vec<String> = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        let words = rows
            .iter()
            .flat_map(|row| row.trim_matches('│').split_whitespace().map(str::to_owned))
            .collect::<Vec<_>>()
            .join(" ");
        let said = note.split_whitespace().collect::<Vec<_>>().join(" ");
        if let Some(out) = std::env::var_os("HOPS_TUI_RENDER") {
            let _ = std::fs::write(out, rows.join("\n"));
        }
        assert!(
            words.contains(&said),
            "the restart is not on screen whole:\n{}",
            rows.join("\n")
        );
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
                    hostname: Some("WINDOWS-PC".into()),
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
        model.authorized.insert(FP.into(), "WINDOWS-PC".into());

        let out = screen(&model, 0);
        assert_eq!(
            out.matches("WINDOWS-PC").count(),
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
        model.authorized.insert(FP.into(), "Work MBP".into());
        let out = screen(&model, 0);
        assert!(out.contains("Work MBP"), "missing peer:\n{out}");
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

    // LEDGER T9911 | class B | 1 return value: name_input and name_request, what `n` opens and what saving it sends; 3 render: footer_line in ui() on a TestBackend
    /// `n` on a device this machine dials names it, and saving sends that
    /// name only; its address has a key of its own (#13). `n` used to edit
    /// the hostname, which is where the device dials.
    #[test]
    fn naming_a_device_this_machine_dials_changes_its_name_and_not_its_address() {
        let mut model = AppModel::default();
        model.clients.insert(
            4,
            (
                ClientConfig {
                    hostname: Some("desk-mac.local".into()),
                    ..Default::default()
                },
                ClientState {
                    peer_fingerprint: Some(FP.into()),
                    ..Default::default()
                },
            ),
        );
        model.authorized.insert(FP.into(), "desk mac".into());
        let devices = listable(&model);
        let opened = devices.first().and_then(name_input);
        assert!(
            matches!(&opened, Some(Input::Name { handle: 4, buf }) if buf == "desk-mac.local"),
            "n on a device this machine dials has to open its name, not its \
             address"
        );
        assert_eq!(
            (name_request(4, "  den "), name_request(4, " ")),
            (
                FrontendRequest::UpdateLabel(4, Some("den".into())),
                FrontendRequest::UpdateLabel(4, None)
            ),
            "saving a name has to send the name, or clear it when blank"
        );
        let shown = screen(&model, 0);
        assert!(
            shown.contains("h address") && shown.contains("n name"),
            "the keymap has to offer the name and the address apart:\n{shown}"
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

    /// The peer's build must be visible without an SSH round trip (#45).
    #[test]
    fn a_connected_peer_shows_the_build_it_is_running() {
        let mut model = AppModel::default();
        model.clients.insert(
            0,
            (
                ClientConfig {
                    hostname: Some("WINDOWS-PC".into()),
                    ..Default::default()
                },
                ClientState {
                    peer_fingerprint: Some(FP.into()),
                    peer_commit: Some(*b"9061273c"),
                    active: true,
                    alive: true,
                    ..Default::default()
                },
            ),
        );
        let out = screen(&model, 0);
        assert!(
            out.contains("@9061273c"),
            "the peer's build should be on the row:\n{out}"
        );
    }

    /// "we have not been told" must look different from "nothing to show" —
    /// a blank would read as agreement.
    #[test]
    fn an_unknown_peer_build_is_shown_as_unknown_not_blank() {
        let mut model = AppModel::default();
        model.clients.insert(
            0,
            (
                ClientConfig {
                    hostname: Some("new-box".into()),
                    ..Default::default()
                },
                // no Hello yet -> peer_commit is None
                ClientState::default(),
            ),
        );
        let out = screen(&model, 0);
        assert!(out.contains("@?"), "unknown build must be explicit:\n{out}");
    }
    /// Each paired row says whether its clipboard is on, off included, and
    /// `c` is its switch: on a row whose clipboard is on it asks before
    /// sending the one request that turns it off, and on a row whose
    /// clipboard is off it sends the one request that turns it back on, and
    /// the keymap says which (#182).
    // LEDGER E2A-10 | class B | 3 render + 2 return value: ui() into a TestBackend, clipboard_key, confirmed
    #[test]
    fn the_clipboard_switch_turns_it_off_and_back_on() {
        use hops_frontend_core::{FrontendEvent, PeerTrust};
        const LAPTOP: &str = "2e:29:2b:3c:4d:5e:6f:70:81:92:a3:b4:c5:d6:e7:f8";
        let mut model = AppModel::default();
        model.apply(FrontendEvent::AuthorizedUpdated(
            [
                (FP.to_owned(), "desk mac".to_owned()),
                (LAPTOP.to_owned(), "laptop".to_owned()),
            ]
            .into(),
        ));
        model.apply(FrontendEvent::TrustUpdated(
            [
                (
                    FP.to_owned(),
                    PeerTrust {
                        clipboard_from: true,
                        clipboard_to: false,
                        pending: false,
                    },
                ),
                (LAPTOP.to_owned(), PeerTrust::default()),
            ]
            .into(),
        ));
        let devices = listable(&model);
        let at = |label: &str| {
            devices
                .iter()
                .position(|d| d.label == label)
                .unwrap_or_else(|| panic!("{label} is not listed"))
        };
        let row = |out: &str, label: &str| {
            out.lines()
                .find(|l| l.contains(label))
                .unwrap_or_else(|| panic!("no row for {label}:\n{out}"))
                .to_owned()
        };

        let on = screen(&model, at("desk mac"));
        assert!(
            row(&on, "desk mac").contains("clipboard from it"),
            "the row does not say its clipboard is on:\n{on}"
        );
        assert!(
            row(&on, "laptop").contains("clipboard off"),
            "the row does not say its clipboard is off:\n{on}"
        );
        assert!(
            on.contains("c clipboard off"),
            "the keymap does not offer to turn the clipboard off:\n{on}"
        );
        let ask = match clipboard_key(&model, devices.get(at("desk mac"))) {
            Ok(ClipboardKey::AskOff(ask)) => ask,
            Ok(ClipboardKey::TurnOn(request)) => {
                panic!("c on a clipboard that is on sent {request:?}")
            }
            Err(why) => panic!("c asked nothing: {why}"),
        };
        let theme = theme::default_theme();
        let mut state = ListState::default();
        state.select(Some(at("desk mac")));
        let mut term = Terminal::new(TestBackend::new(120, 24)).expect("test terminal");
        term.draw(|f| {
            ui(
                f,
                &model,
                &devices,
                &mut state,
                None,
                Some(&ask),
                None,
                &Default::default(),
                None,
                false,
                &theme,
            )
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let asking: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
                    + "\n"
            })
            .collect();
        assert!(
            asking.contains("turn the clipboard off for desk mac? y yes"),
            "the question does not say what y does:\n{asking}"
        );
        assert!(
            !asking.contains("cannot be turned back on"),
            "the question still says the clipboard cannot be turned back on:\n{asking}"
        );
        assert_eq!(
            confirmed(ask),
            Some(FrontendRequest::DisableClipboard(FP.to_owned())),
            "answering y does not turn this device's clipboard off"
        );

        let off = screen(&model, at("laptop"));
        assert!(
            off.contains("c clipboard on"),
            "the keymap does not offer to turn an off clipboard back on:\n{off}"
        );
        assert!(
            matches!(
                clipboard_key(&model, devices.get(at("laptop"))),
                Ok(ClipboardKey::TurnOn(FrontendRequest::EnableClipboard(fp))) if fp == LAPTOP
            ),
            "c on a device whose clipboard is off must send the request that turns \
             that device's clipboard back on"
        );
    }

    /// `model` drawn at `width` columns with `notice` in the footer, as the
    /// run loop draws it.
    fn render_with_notice(model: &AppModel, notice: &str, width: u16) -> String {
        let devices = listable(model);
        let mut state = ListState::default();
        state.select(Some(0));
        let theme = theme::default_theme();
        let mut term = Terminal::new(TestBackend::new(width, 24)).expect("test terminal");
        term.draw(|f| {
            ui(
                f,
                model,
                &devices,
                &mut state,
                None,
                None,
                None,
                &Default::default(),
                Some(notice),
                false,
                &theme,
            )
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
                    + "\n"
            })
            .collect()
    }

    // LEDGER T115-9 | class B | 3 render: ui() on a ratatui TestBackend, its notice from new_error after AppModel::apply
    /// A crossing that left the pointer on this machine is said in the
    /// footer, the device and the reason first, so an 80-column terminal
    /// still shows why (#115).
    #[test]
    fn a_refused_crossing_is_said_in_the_footer() {
        let mut model = AppModel::default();
        model.connected = true;
        model.apply(FrontendEvent::Created(
            0,
            ClientConfig {
                hostname: Some("studio-pc".into()),
                ..Default::default()
            },
            ClientState::default(),
        ));
        let mut seen = model.error_seq;
        model.apply(FrontendEvent::CrossingRefused {
            handle: 0,
            reason: hops_frontend_core::CrossingRefusal::NotConnected,
        });
        let notice = new_error(&model, &mut seen).expect("a refused crossing raises a notice");

        let screen = render_with_notice(&model, &notice, 80);
        assert!(
            screen.contains("studio-pc is not paired yet, so the pointer stayed here."),
            "the footer does not say why the pointer stayed here:\n{screen}"
        );
    }

    /// A model with the number card for FP open in `check`, answered or not.
    fn checking(check: PairingCheck, answered: bool) -> AppModel {
        let mut model = AppModel::default();
        model.connected = true;
        model.apply(FrontendEvent::PairingCheck {
            fingerprint: FP.into(),
            addr: Some("192.0.2.7:4242".parse().expect("addr")),
            check,
            answered,
        });
        model
    }

    fn picking() -> PairingCheck {
        PairingCheck::Pick(vec!["318204".into(), "042917".into(), "775061".into()])
    }

    /// The number card is drawn in each of its four states: the adding
    /// machine's number with its confirm, the three numbers the machine being
    /// added picks from, and each once answered here (#11, #167). It is drawn
    /// over an approval card, which the number replaces.
    // LEDGER G-20 | class B | 3 widget tree: ui() into a TestBackend
    #[test]
    fn the_number_card_shows_the_number_or_three_to_pick() {
        let cases = [
            ("show", PairingCheck::Show("042917".into()), false),
            ("show-answered", PairingCheck::Show("042917".into()), true),
            ("pick", picking(), false),
            ("pick-answered", picking(), true),
        ];
        for (name, check, answered) in cases {
            let mut model = checking(check, answered);
            model.apply(FrontendEvent::ConnectionAttempt {
                fingerprint: "ab:ab:ab".into(),
                origin: AttemptOrigin::Inbound,
                addr: None,
            });
            // Another machine's request is live too, so its approval card
            // would be drawn if the number card did not come first.
            let approval = PairingCard::default()
                .show(&model, Instant::now(), |_| false)
                .cloned();
            assert!(approval.is_some(), "{name}: precondition: an approval card");
            // at the width of a default terminal, where the card is narrowest
            let devices = listable(&model);
            let mut state = ListState::default();
            let theme = theme::default_theme();
            let mut term = Terminal::new(TestBackend::new(80, 24)).expect("test terminal");
            term.draw(|f| {
                ui(
                    f,
                    &model,
                    &devices,
                    &mut state,
                    None,
                    None,
                    approval.as_ref(),
                    &Default::default(),
                    None,
                    false,
                    &theme,
                )
            })
            .expect("draw");
            let buf = term.backend().buffer().clone();
            let out = (0..buf.area.height)
                .map(|y| {
                    (0..buf.area.width)
                        .map(|x| buf[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            if let Some(dir) = std::env::var_os("HOPS_TUI_RENDER_DIR") {
                let path = std::path::Path::new(&dir).join(format!("tui-check-{name}.txt"));
                let _ = std::fs::write(path, &out);
            }
            let show = name.starts_with("show");
            let title = if show {
                "pairing · confirm the number"
            } else {
                "pairing · pick the number"
            };
            assert!(out.contains(title), "{name}: no number card:\n{out}");
            assert!(
                !out.contains("pairing request"),
                "{name}: the approval card is drawn over the number:\n{out}"
            );
            assert!(
                out.contains("192.0.2.7:4242"),
                "{name}: not said where from:\n{out}"
            );
            match (show, answered) {
                (true, false) => assert!(
                    out.contains("042 917") && out.contains("y confirm"),
                    "{name}: the number or its confirm is missing:\n{out}"
                ),
                (false, false) => assert!(
                    out.contains("1 318 204")
                        && out.contains("2 042 917")
                        && out.contains("3 775 061")
                        && out.contains("none of these"),
                    "{name}: the three numbers are not offered by key:\n{out}"
                ),
                (_, true) => assert!(
                    out.contains("Waiting for the other machine")
                        && !out.contains("y confirm")
                        && !out.contains("1-3 pick"),
                    "{name}: an answered card still asks:\n{out}"
                ),
            }
        }
    }

    /// The keys on the number card send the answer the daemon compares: the
    /// number shown for `y`, the picked one for `1` to `3`, a cancel for `n`
    /// or Esc; nothing but a cancel once answered (#11).
    // LEDGER G-21 | class B | 1 return value: check_key
    #[test]
    fn the_number_card_keys_answer_it() {
        let answer = |n: &str| FrontendRequest::ConfirmPairing {
            fingerprint: FP.into(),
            number: n.into(),
        };
        let cancel = FrontendRequest::CancelPairing(FP.into());
        let show = checking(PairingCheck::Show("042917".into()), false);
        let card = show.pairing_check().expect("a card");
        assert_eq!(check_key(card, KeyCode::Char('y')), Some(answer("042917")));
        assert_eq!(check_key(card, KeyCode::Char('2')), None);
        assert_eq!(check_key(card, KeyCode::Esc), Some(cancel.clone()));

        let pick = checking(picking(), false);
        let card = pick.pairing_check().expect("a card");
        for (key, n) in [('1', "318204"), ('2', "042917"), ('3', "775061")] {
            assert_eq!(
                check_key(card, KeyCode::Char(key)),
                Some(answer(n)),
                "key {key}"
            );
        }
        assert_eq!(check_key(card, KeyCode::Char('4')), None);
        assert_eq!(
            check_key(card, KeyCode::Char('y')),
            None,
            "y picked a number"
        );
        assert_eq!(check_key(card, KeyCode::Char('n')), Some(cancel.clone()));

        let answered = checking(picking(), true);
        let card = answered.pairing_check().expect("a card");
        assert_eq!(check_key(card, KeyCode::Char('2')), None, "answered twice");
        assert_eq!(check_key(card, KeyCode::Esc), Some(cancel));
    }
}

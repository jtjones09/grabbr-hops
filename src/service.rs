use crate::{
    capture::{Capture, CaptureType, ICaptureEvent},
    client::ClientManager,
    clipboard::{Clipboard, ClipboardEvent},
    config::{Config, ConfigClient},
    connect::{ClipboardSender, LanMouseConnection},
    crypto,
    dns::{DnsEvent, DnsResolver},
    emulation::{Emulation, EmulationEvent},
    hop_log::Lifecycle,
    listen::{ClipboardSenderListen, LanMouseListener, ListenerCreationError},
};
use futures::StreamExt;
use hops_ipc::{
    AsyncFrontendListener, AttemptOrigin, ClientHandle, FrontendEvent, FrontendRequest, IpcError,
    IpcListenerCreationError, Position, Status,
};
use local_channel::mpsc::{Receiver, channel};
use log;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
};
use thiserror::Error;
use tokio::{process::Command, signal, sync::Notify};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    IpcListen(#[from] IpcListenerCreationError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    ListenError(#[from] ListenerCreationError),
    #[error("failed to load certificate: `{0}`")]
    Certificate(#[from] crypto::Error),
    #[error("connection setup failed: {0}")]
    Connect(String),
}

pub struct Service {
    /// configuration
    config: Config,
    /// input capture
    capture: Capture,
    /// input emulation
    emulation: Emulation,
    /// dns resolver
    resolver: DnsResolver,
    /// frontend listener
    frontend_listener: AsyncFrontendListener,
    /// authorized public key sha256 fingerprints
    authorized_keys: Arc<RwLock<HashMap<String, String>>>,
    /// Fingerprints the user deliberately expelled. Not shared with the TLS
    /// verifiers — enforcement is already the allowlist's job. This exists so a
    /// revoked peer cannot RAISE A PROMPT: it loses the ability to schedule a
    /// security decision, which is the part of revocation that is actually worth
    /// something (it cannot exclude anyone — a peer can always re-key).
    revoked: HashMap<String, hops_ipc::RevokedEntry>,
    /// (outgoing) client information
    client_manager: ClientManager,
    /// current port
    port: u16,
    /// the public key fingerprint for (D)TLS
    public_key_fingerprint: String,
    /// notify for pending frontend events
    frontend_event_pending: Notify,
    /// frontend events queued for sending
    pending_frontend_events: VecDeque<FrontendEvent>,
    /// status of input capture (enabled / disabled)
    capture_status: Status,
    /// status of input emulation (enabled / disabled)
    emulation_status: Status,
    /// keep track of registered connections to avoid duplicate barriers
    incoming_conns: HashSet<SocketAddr>,
    /// addrs whose cursor is currently ON this device (crossing-level state) —
    /// used only to log entered/left exactly once per crossing, distinct from
    /// `incoming_conns` which is connection-level
    currently_controlling: HashSet<SocketAddr>,
    /// map from capture handle to connection info
    incoming_conn_info: HashMap<ClientHandle, Incoming>,
    /// peers with a live INCOMING connection (addr -> fingerprint), tracked at the
    /// connection level (independent of whether their cursor has crossed in) and
    /// re-emitted on Sync so a freshly-attached UI sees who is connected right now
    connected_peers: HashMap<SocketAddr, String>,
    next_trigger_handle: u64,
    /// cross-machine clipboard sync backend (local monitor + apply)
    clipboard: Clipboard,
    /// whether the clipboard backend is still running (false once it stops, so
    /// the run loop does not busy-poll a closed channel)
    clipboard_alive: bool,
    /// inbound clipboard text received from peers, applied to the local clipboard
    clipboard_in: Receiver<String>,
    /// fingerprints of RECEIVERS we tried to dial but don't trust (from the
    /// connect side). Turned into `ConnectionAttempt` below so the UI can offer
    /// to authorize them — the outbound counterpart of the inbound pairing prompt.
    untrusted_receivers: Receiver<(String, SocketAddr)>,
    /// a client's peer_fingerprint was just learned — persist it and republish
    persist_requests: Receiver<ClientHandle>,
    /// broadcast local clipboard changes to outgoing-connection peers
    clipboard_out_conn: ClipboardSender,
    /// force-close outgoing sessions to a receiver whose trust was revoked
    revoke_conn: crate::connect::OutboundRevoker,
    /// force-close incoming sessions from a sender whose trust was revoked
    revoke_listen: crate::listen::ConnRevoker,
    /// broadcast local clipboard changes to incoming-connection peers
    clipboard_out_listen: ClipboardSenderListen,
}

#[derive(Debug)]
struct Incoming {
    fingerprint: String,
    addr: SocketAddr,
    pos: Position,
}

/// Drop any persisted client pin naming a fingerprint that is not in the
/// allowlist.
///
/// Such a pin can never let anyone in — the outbound dial is fail-closed against
/// it — but it CAN silently brick a client: hand-editing `hostname` to retarget a
/// device while leaving the old `fingerprint = ...` behind makes every dial fail
/// identity verification with no visible cause. Dropping it lets the client
/// re-learn the identity on its next successful handshake, which is exactly what
/// a never-connected client does.
fn drop_untrusted_pins(
    client_manager: &ClientManager,
    authorized: &HashMap<String, String>,
) -> Vec<ClientHandle> {
    let stale: Vec<(ClientHandle, String)> = client_manager
        .get_client_states()
        .into_iter()
        .filter_map(|(h, _, s)| {
            s.peer_fingerprint
                .filter(|fp| !authorized.contains_key(fp))
                .map(|fp| (h, fp))
        })
        .collect();
    for (h, fp) in &stale {
        log::warn!(
            "client {h}: dropping pinned fingerprint {fp} — it is not in \
             authorized_fingerprints, so it could only ever fail the dial"
        );
        client_manager.clear_pins_matching(fp);
    }
    stale.into_iter().map(|(h, _)| h).collect()
}

impl Service {
    pub async fn new(config: Config) -> Result<Self, ServiceError> {
        let client_manager = ClientManager::default();
        for client in config.clients() {
            client_manager.add_with_config(client);
        }
        // Revocation outranks the allowlist HERE TOO, not only on reload. A
        // fingerprint sitting in BOTH tables is untrusted, so it must also lose
        // its outbound pin — passing the RAW allowlist here would keep the pin
        // alive for a device its owner expelled (issue #66).
        let (allowlist, refused) = config.effective_allowlist();
        for fp in &refused {
            log::warn!(
                "config lists {fp} as BOTH authorized and revoked — refusing it at startup. \
                 That identity is permanently dead; the device must present a new one."
            );
        }
        drop_untrusted_pins(&client_manager, &allowlist);

        // load identity (cert + key)
        let identity = Arc::new(crypto::load_or_generate_key_and_cert(config.cert_path())?);
        let public_key_fingerprint = crypto::certificate_fingerprint(&identity);

        // create frontend communication adapter, exit if already running
        let frontend_listener = AsyncFrontendListener::new().await?;

        let authorized_keys = Arc::new(RwLock::new(allowlist));

        // clipboard sync: a single inbound channel both transports push received
        // payloads into, plus the local monitor/apply backend. The channel is
        // unbounded — acceptable for the trusted KVM-pair model (peers are
        // mutually fingerprint-authenticated). Each transfer is capped at
        // transport::MAX_CLIPBOARD_BYTES and stalled transfers time out, but a
        // malicious/buggy *authorized* peer flooding valid payloads is not yet
        // back-pressured; a bounded/coalescing channel is the future hardening.
        let (clipboard_in_tx, clipboard_in) = channel();
        let (untrusted_tx, untrusted_receivers) = channel();
        let (persist_tx, persist_requests) = channel();
        let clipboard = Clipboard::new();

        // listener + connection (both authenticate the peer against the shared
        // authorized-fingerprint allowlist)
        let listener = LanMouseListener::new(
            config.port(),
            identity.clone(),
            authorized_keys.clone(),
            clipboard_in_tx.clone(),
        )
        .await?;
        let conn = LanMouseConnection::new(
            identity.clone(),
            client_manager.clone(),
            authorized_keys.clone(),
            clipboard_in_tx,
            untrusted_tx,
            persist_tx,
        )
        .map_err(|e| ServiceError::Connect(e.to_string()))?;

        // clipboard broadcast handles — grabbed before the transports are moved
        // into capture/emulation below.
        let clipboard_out_conn = conn.clipboard_sender();
        let clipboard_out_listen = listener.clipboard_sender();
        // revocation handles, grabbed before both are moved into capture/emulation
        let revoke_conn = conn.revoker();
        let revoke_listen = listener.revoker();

        // input capture + emulation
        let capture_backend = config.capture_backend().map(|b| b.into());
        let capture = Capture::new(capture_backend, conn, config.release_bind());
        let emulation_backend = config.emulation_backend().map(|b| b.into());
        let emulation = Emulation::new(emulation_backend, listener);

        // create dns resolver
        let resolver = DnsResolver::new()?;

        let port = config.port();
        let revoked = config.revoked_fingerprints();
        let service = Self {
            revoked,
            config,
            capture,
            emulation,
            frontend_listener,
            resolver,
            authorized_keys,
            public_key_fingerprint,
            client_manager,
            frontend_event_pending: Default::default(),
            port,
            pending_frontend_events: Default::default(),
            capture_status: Default::default(),
            emulation_status: Default::default(),
            incoming_conn_info: Default::default(),
            incoming_conns: Default::default(),
            currently_controlling: Default::default(),
            connected_peers: Default::default(),
            next_trigger_handle: 0,
            clipboard,
            clipboard_alive: true,
            clipboard_in,
            untrusted_receivers,
            persist_requests,
            clipboard_out_conn,
            clipboard_out_listen,
            revoke_conn,
            revoke_listen,
        };
        Ok(service)
    }

    pub async fn run(&mut self) -> Result<(), ServiceError> {
        let active = self.client_manager.active_clients();
        for handle in active.iter() {
            // small hack: `activate_client()` checks, if the client
            // is already active in client_manager and does not create a
            // capture barrier in that case so we have to deactivate it first
            self.client_manager.deactivate_client(*handle);
        }

        for handle in active {
            self.activate_client(handle);
        }

        loop {
            tokio::select! {
                request = self.frontend_listener.next() => self.handle_frontend_request(request),
                _ = self.frontend_event_pending.notified() => self.handle_frontend_pending().await,
                event = self.emulation.event() => self.handle_emulation_event(event),
                event = self.capture.event() => self.handle_capture_event(event),
                event = self.resolver.event() => self.handle_resolver_event(event),
                event = self.clipboard.changed(), if self.clipboard_alive => self.handle_clipboard_change(event).await,
                handle = self.persist_requests.recv() => {
                    if let Some(handle) = handle {
                        log::debug!("client {handle}: persisting newly-learned peer fingerprint");
                        // persist so the device join survives a restart, and
                        // republish so the merged card appears immediately
                        self.save_config();
                        self.broadcast_client(handle);
                    }
                }
                fp = self.untrusted_receivers.recv() => {
                    if let Some((fp, addr)) = fp {
                        // only prompt if it really is untrusted — a racing dial can
                        // report a fingerprint that was authorized in the meantime
                        let known = self.authorized_keys.read().expect("lock").contains_key(&fp);
                        if !known {
                            log::info!("untrusted receiver {fp} — raising an approval prompt");
                            self.raise_connection_attempt(fp, AttemptOrigin::OutboundDial, Some(addr));
                        }
                    }
                }
                text = self.clipboard_in.recv() => {
                    if let Some(text) = text {
                        self.clipboard.apply(text);
                    }
                }
                _ = self.config.changed() => self.handle_config_change(),
                r = signal::ctrl_c() => break r.expect("failed to wait for CTRL+C"),
            }
        }

        log::info!("terminating service ...");
        log::debug!("terminating capture ...");
        self.capture.terminate().await;
        log::debug!("terminating emulation ...");
        self.emulation.terminate().await;
        log::debug!("terminating dns resolver ...");
        self.resolver.terminate().await;

        Ok(())
    }

    /// A *local* clipboard change → broadcast it to every connected peer (both
    /// directions). `None` means the clipboard backend stopped; disable the arm.
    ///
    /// Content *applied from a peer* is intentionally NOT re-broadcast (apply()
    /// seeds the poll baseline, so it never fires `changed()`), which prevents
    /// A→B→A echo. The consequence: clipboard sync is PAIRWISE — in a 3+-machine
    /// star, a copy on one peer reaches this hub but is not forwarded to the
    /// others. Multi-hop would need origin-tagging + versioned de-dup; out of
    /// scope for the current 1-sender/1-receiver model.
    async fn handle_clipboard_change(&mut self, event: Option<ClipboardEvent>) {
        match event {
            Some(ClipboardEvent::Changed(text)) => {
                self.clipboard_out_conn.broadcast(text.clone()).await;
                self.clipboard_out_listen.broadcast(text).await;
            }
            None => {
                log::warn!("clipboard sync stopped");
                self.clipboard_alive = false;
            }
        }
    }

    fn handle_frontend_request(&mut self, request: Option<Result<FrontendRequest, IpcError>>) {
        let request = match request.expect("frontend listener closed") {
            Ok(r) => r,
            Err(e) => return log::error!("error receiving request: {e}"),
        };
        match request {
            FrontendRequest::Activate(handle, active) => {
                self.set_client_active(handle, active);
                self.save_config();
            }
            FrontendRequest::AuthorizeKey(desc, fp) => {
                if self.refuse_while_remotely_driven("grant trust") {
                    return;
                }
                self.add_authorized_key(desc, fp);
                self.save_config();
            }
            FrontendRequest::ChangePort(port) => self.change_port(port),
            FrontendRequest::Create => {
                self.add_client();
                self.save_config();
            }
            FrontendRequest::Delete(handle) => {
                // Deleting a device REVOKES it. hops can read every keystroke on
                // the machine, so "remove this device" has to mean removed —
                // previously delete forgot the dial address but left the peer's
                // key authorized, so a machine the user believed they had removed
                // could still take their keyboard and mouse.
                //
                // Deliberately here and NOT in remove_client(): that is also
                // called by handle_config_change, which removes every client
                // before rebuilding them, so revoking there would wipe the entire
                // trust store on any config reload.
                if let Some(fp) = self.client_manager.peer_fingerprint(handle) {
                    if self.authorized_keys.read().expect("lock").contains_key(&fp) {
                        log::warn!("deleting client {handle}: also revoking its trust ({fp})");
                        self.remove_authorized_key(fp);
                    }
                }
                self.remove_client(handle);
                self.save_config();
            }
            FrontendRequest::EnableCapture => self.capture.reenable(),
            FrontendRequest::EnableEmulation => self.emulation.reenable(),
            FrontendRequest::Enumerate() => self.enumerate(),
            FrontendRequest::UpdateFixIps(handle, fix_ips) => {
                self.update_fix_ips(handle, fix_ips);
                self.save_config();
            }
            FrontendRequest::UpdateHostname(handle, host) => {
                self.update_hostname(handle, host);
                self.save_config();
            }
            FrontendRequest::UpdatePort(handle, port) => {
                self.update_port(handle, port);
                self.save_config();
            }
            FrontendRequest::UpdatePosition(handle, pos) => {
                self.update_pos(handle, pos);
                self.save_config();
            }
            FrontendRequest::UpdateGeometry(handle, geometry) => {
                self.update_geometry(handle, geometry);
                self.save_config();
            }
            FrontendRequest::ResolveDns(handle) => self.resolve(handle),
            FrontendRequest::Sync => self.sync_frontend(),
            FrontendRequest::RemoveAuthorizedKey(key) => {
                self.remove_authorized_key(key);
                self.save_config();
            }
            FrontendRequest::SetLabel(fp, label) => {
                self.set_label(fp, label);
                self.save_config();
            }
            FrontendRequest::SaveConfiguration => self.save_config(),
        }
    }

    fn save_config(&mut self) {
        let clients = self.client_manager.clients();
        let clients = clients
            .into_iter()
            .map(|(c, s)| ConfigClient {
                ips: HashSet::from_iter(c.fix_ips),
                hostname: c.hostname,
                port: c.port,
                pos: c.pos,
                active: s.active,
                enter_hook: c.cmd,
                fingerprint: s.peer_fingerprint,
            })
            .collect();
        self.config.set_clients(clients);
        let authorized_keys = self.authorized_keys.read().expect("lock").clone();
        self.config.set_authorized_keys(authorized_keys);
        self.config.set_revoked_fingerprints(self.revoked.clone());
        if let Err(e) = self.config.write_back() {
            log::warn!("failed to write config: {e}");
        }
    }

    fn handle_config_change(&mut self) {
        for h in self.client_manager.registered_clients() {
            self.remove_client(h);
        }
        for c in self.config.clients() {
            let handle = self.client_manager.add_with_config(c);
            log::info!("added client {handle}");
            let (c, s) = self.client_manager.get_state(handle).unwrap();
            if s.active {
                self.client_manager.deactivate_client(handle);
                self.activate_client(handle);
            }
            self.notify_frontend(FrontendEvent::Created(handle, c, s));
        }
        let release_bind = self.config.release_bind();
        self.capture.set_release_bind(release_bind);
        // A config reload can drop keys exactly like the revoke button does —
        // editing config.toml by hand, or a watcher-driven reload. Diff against
        // the live set and tear down anything that lost trust, or revocation is
        // silently unenforced through this door.
        self.revoked = self.config.revoked_fingerprints();
        // Same door as startup: revocation outranks the allowlist. Re-adding a
        // revoked fingerprint by hand-editing config.toml is refused and logged,
        // so the denylist cannot be laundered by copy-pasting a key back into
        // the other table.
        let (authorized_keys, refused) = self.config.effective_allowlist();
        for fp in &refused {
            log::warn!(
                "config lists {fp} as BOTH authorized and revoked — refusing it. \
                 Restore it from the device list if that is what you meant."
            );
        }
        let revoked: Vec<String> = {
            let mut live = self.authorized_keys.write().unwrap();
            let revoked = live
                .keys()
                .filter(|k| !authorized_keys.contains_key(*k))
                .cloned()
                .collect();
            live.clone_from(&authorized_keys);
            revoked
        };
        // a hand-edited config is exactly where a stale pin gets reintroduced
        for h in drop_untrusted_pins(&self.client_manager, &authorized_keys) {
            self.broadcast_client(h);
        }
        for fp in &revoked {
            // ORDER MATTERS and this was inverted: cut_sessions resolves the
            // affected handles via peer_fingerprint, which clear_pins_matching
            // erases. Clearing first made the outbound teardown a structural
            // no-op on exactly the path a6ddccb added it for.
            self.cut_sessions(fp);
            for h in self.client_manager.clear_pins_matching(fp) {
                self.broadcast_client(h);
            }
        }
        self.sync_frontend();
    }

    async fn handle_frontend_pending(&mut self) {
        while let Some(event) = self.pending_frontend_events.pop_front() {
            self.frontend_listener.broadcast(event).await;
        }
    }

    fn handle_emulation_event(&mut self, event: EmulationEvent) {
        match event {
            EmulationEvent::BackendDegraded(name) => {
                log::error!(
                    "input emulation fell back to the {name} backend — incoming input \
                     is being DISCARDED"
                );
                self.notify_frontend(FrontendEvent::Error(format!(
                    "This machine cannot inject input (using the \"{name}\" backend), so \
                     nothing a peer sends will do anything. On macOS this is usually a \
                     missing Accessibility permission for hops."
                )));
            }
            EmulationEvent::ConnectionAttempt { fingerprint } => {
                self.raise_connection_attempt(fingerprint, AttemptOrigin::Inbound, None);
            }
            EmulationEvent::Entered {
                addr,
                pos,
                fingerprint,
            } => {
                // Log the crossing exactly once: `insert` returns true only on the
                // real cross-on transition, not on the sender's redundant Enter
                // re-sends (which all land here while it waits for the Ack).
                if self.currently_controlling.insert(addr) {
                    Lifecycle::Entered { addr, pos }.log();
                }
                // connection-level registration / frontend (deduped separately)
                if !self.incoming_conns.contains(&addr) {
                    self.add_incoming(addr, pos, fingerprint.clone());
                    self.notify_frontend(FrontendEvent::DeviceEntered {
                        fingerprint,
                        addr,
                        pos,
                    });
                } else {
                    self.update_incoming(addr, pos, fingerprint);
                }
            }
            EmulationEvent::Disconnected { addr } => {
                self.currently_controlling.remove(&addr);
                self.connected_peers.remove(&addr);
                if let Some(addr) = self.remove_incoming(addr) {
                    Lifecycle::Disconnected { addr }.log();
                    self.notify_frontend(FrontendEvent::IncomingDisconnected(addr));
                }
            }
            EmulationEvent::PortChanged(port) => match port {
                Ok(port) => {
                    self.port = port;
                    self.notify_frontend(FrontendEvent::PortChanged(port, None));
                }
                Err(e) => self
                    .notify_frontend(FrontendEvent::PortChanged(self.port, Some(format!("{e}")))),
            },
            EmulationEvent::EmulationDisabled => {
                self.emulation_status = Status::Disabled;
                self.notify_frontend(FrontendEvent::EmulationStatus(self.emulation_status));
            }
            EmulationEvent::EmulationEnabled => {
                self.emulation_status = Status::Enabled;
                self.notify_frontend(FrontendEvent::EmulationStatus(self.emulation_status));
            }
            EmulationEvent::ReleaseNotify => self.capture.release(),
            EmulationEvent::EdgePushed { addr, side } => {
                // Adaptive edge (receiver side): the controlling peer's cursor
                // was deliberately pushed past `side`. Hand control back only
                // if that is the edge the peer entered from — same semantics
                // as the capture-side barrier in CaptureBegin below, which
                // stays active as a redundant path; `currently_controlling`
                // dedupes whichever fires second.
                let entered_here = self
                    .incoming_conn_info
                    .values()
                    .any(|i| i.addr == addr && i.pos == side);
                if entered_here && self.currently_controlling.remove(&addr) {
                    Lifecycle::Left { addr }.log();
                    self.emulation.send_leave_event(addr);
                }
            }
            EmulationEvent::Connected { addr, fingerprint } => {
                Lifecycle::Connected {
                    addr,
                    fingerprint: &fingerprint,
                }
                .log();
                self.connected_peers.insert(addr, fingerprint.clone());
                self.notify_frontend(FrontendEvent::DeviceConnected { addr, fingerprint });
            }
            EmulationEvent::PeerHello { addr, commit } => {
                // Map the peer's source addr back to its client handle
                // and stamp the commit. Skip if we don't have an
                // outgoing client configured for this peer (incoming-
                // only setup) — there's nowhere to display the version
                // in that case anyway.
                if let Some(handle) = self.client_manager.get_client(addr) {
                    self.client_manager.set_peer_commit(handle, Some(commit));
                    self.broadcast_client(handle);
                }
            }
            EmulationEvent::PeerCaps { addr, flags } => {
                // Mirror PeerHello: map the peer's addr to its client
                // handle and record the advertised capability bits. Skip
                // if there's no outgoing client for this peer.
                if let Some(handle) = self.client_manager.get_client(addr) {
                    self.client_manager.set_peer_caps(handle, Some(flags));
                    self.broadcast_client(handle);
                }
            }
        }
    }

    fn handle_capture_event(&mut self, event: ICaptureEvent) {
        match event {
            ICaptureEvent::CaptureBegin(handle) => {
                // we entered the capture zone for an incoming connection
                // => notify it that its capture should be released
                if let Some(incoming) = self.incoming_conn_info.get(&handle) {
                    let addr = incoming.addr;
                    // log the cross-off once (this barrier can re-fire per move)
                    if self.currently_controlling.remove(&addr) {
                        Lifecycle::Left { addr }.log();
                    }
                    self.emulation.send_leave_event(addr);
                }
            }
            ICaptureEvent::CaptureDisabled => {
                self.capture_status = Status::Disabled;
                self.notify_frontend(FrontendEvent::CaptureStatus(self.capture_status));
            }
            ICaptureEvent::CaptureEnabled => {
                self.capture_status = Status::Enabled;
                self.notify_frontend(FrontendEvent::CaptureStatus(self.capture_status));
            }
            ICaptureEvent::ClientEntered(handle) => {
                log::info!("entering client {handle} ...");
                self.spawn_hook_command(handle);
            }
        }
    }

    fn handle_resolver_event(&mut self, event: DnsEvent) {
        let handle = match event {
            DnsEvent::Resolving(handle) => {
                self.client_manager.set_resolving(handle, true);
                handle
            }
            DnsEvent::Resolved(handle, hostname, ips) => {
                self.client_manager.set_resolving(handle, false);
                if let Err(e) = &ips {
                    log::warn!("could not resolve {hostname}: {e}");
                    // ...and tell the user. Before this, a typo'd or unresolvable
                    // name left the card reading "unresolved" forever with the
                    // reason visible only in the log, so the user's model was
                    // "hops is still thinking about it".
                    self.notify_frontend(FrontendEvent::Error(format!(
                        "Could not find \"{hostname}\" on the network. \
                         Check the spelling, or use its IP address."
                    )));
                }
                let ips = ips.unwrap_or_default();
                self.client_manager.set_dns_ips(handle, ips);
                handle
            }
        };
        self.broadcast_client(handle);
    }

    fn resolve(&self, handle: ClientHandle) {
        if let Some(hostname) = self.client_manager.get_hostname(handle) {
            self.resolver.resolve(handle, hostname);
        }
    }

    fn sync_frontend(&mut self) {
        self.enumerate();
        self.notify_frontend(FrontendEvent::EmulationStatus(self.emulation_status));
        self.notify_frontend(FrontendEvent::CaptureStatus(self.capture_status));
        self.notify_frontend(FrontendEvent::PortChanged(self.port, None));
        self.notify_frontend(FrontendEvent::PublicKeyFingerprint(
            self.public_key_fingerprint.clone(),
        ));
        // this device's own shareable pairing code: its fingerprint + routable
        // LAN IPv4 addresses + hostname label (empty if there's no shareable
        // address). IPv4 only — IPv6 link-local is scope-dependent and useless
        // out-of-band. See hops_ipc::pairing.
        let pairing_code = {
            let addrs: Vec<SocketAddr> = if_addrs::get_if_addrs()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|iface| match iface.ip() {
                    std::net::IpAddr::V4(v4)
                        if !v4.is_loopback()
                            && !v4.is_link_local()
                            && !v4.is_unspecified()
                            && !v4.is_broadcast() =>
                    {
                        Some(SocketAddr::new(std::net::IpAddr::V4(v4), self.port))
                    }
                    _ => None,
                })
                .take(8) // matches hops_ipc::pairing MAX_ADDRS
                .collect();
            if addrs.is_empty() {
                String::new()
            } else {
                let label = hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_default();
                hops_ipc::PairingCode {
                    fingerprint: self.public_key_fingerprint.clone(),
                    addrs,
                    label,
                }
                .encode()
            }
        };
        self.notify_frontend(FrontendEvent::PairingCode(pairing_code));
        let keys = self.authorized_keys.read().expect("lock").clone();
        self.notify_frontend(FrontendEvent::AuthorizedUpdated(keys));
        // a freshly-attached frontend must learn the denylist too, or it renders
        // revoked devices as strangers until the next change
        let revoked = self.revoked.clone();
        self.notify_frontend(FrontendEvent::RevokedUpdated(revoked));
        // re-emit current incoming connections so a freshly-attached UI knows
        // which trusted peers are connected right now, not just from future events
        let connected: Vec<(SocketAddr, String)> = self
            .connected_peers
            .iter()
            .map(|(addr, fp)| (*addr, fp.clone()))
            .collect();
        for (addr, fingerprint) in connected {
            self.notify_frontend(FrontendEvent::DeviceConnected { addr, fingerprint });
        }
    }

    const ENTER_HANDLE_BEGIN: u64 = u64::MAX / 2 + 1;

    fn add_incoming(&mut self, addr: SocketAddr, pos: Position, fingerprint: String) {
        let handle = Self::ENTER_HANDLE_BEGIN + self.next_trigger_handle;
        self.next_trigger_handle += 1;
        self.capture.create(handle, pos, CaptureType::EnterOnly);
        self.incoming_conns.insert(addr);
        self.incoming_conn_info.insert(
            handle,
            Incoming {
                fingerprint,
                addr,
                pos,
            },
        );
    }

    fn update_incoming(&mut self, addr: SocketAddr, pos: Position, fingerprint: String) {
        let incoming = self
            .incoming_conn_info
            .iter_mut()
            .find(|(_, i)| i.addr == addr)
            .map(|(_, i)| i)
            .expect("no such client");
        let mut changed = false;
        if incoming.fingerprint != fingerprint {
            incoming.fingerprint = fingerprint.clone();
            changed = true;
        }
        if incoming.pos != pos {
            incoming.pos = pos;
            changed = true;
        }
        if changed {
            self.remove_incoming(addr);
            self.add_incoming(addr, pos, fingerprint.clone());
            self.notify_frontend(FrontendEvent::IncomingDisconnected(addr));
            self.notify_frontend(FrontendEvent::DeviceEntered {
                fingerprint,
                addr,
                pos,
            });
        }
    }

    fn remove_incoming(&mut self, addr: SocketAddr) -> Option<SocketAddr> {
        let handle = self
            .incoming_conn_info
            .iter()
            .find(|(_, incoming)| incoming.addr == addr)
            .map(|(k, _)| *k)?;
        self.capture.destroy(handle);
        self.incoming_conns.remove(&addr);
        self.incoming_conn_info
            .remove(&handle)
            .map(|incoming| incoming.addr)
    }

    fn notify_frontend(&mut self, event: FrontendEvent) {
        self.pending_frontend_events.push_back(event);
        self.frontend_event_pending.notify_one();
    }

    fn add_authorized_key(&mut self, desc: String, fp: String) {
        // Canonicalise BEFORE the tombstone lookup. The check below is an exact
        // map lookup, so an uppercased spelling of an expelled fingerprint used
        // to miss it — and `Config::authorized_fingerprints` then folded that
        // spelling back to canonical form on the next read, resurrecting the
        // expelled device (issue #67).
        let Some(fp) = hops_ipc::pairing::canonical_fingerprint(&fp) else {
            log::warn!("refusing to authorize {fp:?}: not a valid fingerprint");
            self.notify_frontend(FrontendEvent::Error(
                "That is not a valid device fingerprint.".to_string(),
            ));
            return;
        };
        // An expelled fingerprint is DEAD. There is deliberately no path from
        // revoked back to authorized: the record is a tombstone, not a pause.
        // Re-establishing a deleted device means that machine presenting a NEW
        // identity and pairing from scratch — "the whole point of issuing new
        // keys". Refusing here closes the last laundering route, since
        // raise_connection_attempt already prevents a revoked peer prompting.
        if let Some(entry) = self.revoked.get(&fp) {
            log::warn!(
                "refusing to authorize {fp}: it was expelled as {:?}. That identity \
                 is permanently dead — the device must present a new one.",
                entry.label
            );
            self.notify_frontend(FrontendEvent::Error(format!(
                "\"{}\" was removed, and that identity cannot be trusted again. \
                 Re-install or reset hops on that machine so it generates a new \
                 identity, then pair it fresh.",
                entry.label
            )));
            return;
        }
        self.authorized_keys.write().expect("lock").insert(fp, desc);
        let keys = self.authorized_keys.read().expect("lock").clone();
        self.notify_frontend(FrontendEvent::AuthorizedUpdated(keys));
    }

    /// Refuse a trust GRANT while a peer is driving this machine's input.
    ///
    /// On a KVM the pointer is not proof of local presence: a peer that still
    /// holds control can move the cursor onto an approval button and click it,
    /// manufacturing its own consent. Any proof evaluated on the REQUESTING
    /// machine is worthless (it is the adversary, and this is GPLv3 source), so
    /// the only usable check is one this machine makes against state only it
    /// holds — and it already knows when it is being driven.
    ///
    /// Deliberately NOT applied to revocation: refusing to let you revoke while a
    /// peer is driving you would block the one action you most need in exactly
    /// the moment you need it.
    fn refuse_while_remotely_driven(&mut self, what: &str) -> bool {
        const QUIET: std::time::Duration = std::time::Duration::from_secs(2);
        if !self.emulation.remotely_driven_within(QUIET) {
            return false;
        }
        log::warn!("refusing to {what} — this machine is being driven by a peer right now");
        self.notify_frontend(FrontendEvent::Error(format!(
            "Refused to {what}: this machine is being controlled remotely. \
             Use its own keyboard and mouse, then try again."
        )));
        true
    }

    /// The ONLY path from an approval prompt to the allowlist.
    ///
    /// A revoked fingerprint is dropped here with a log line and no UI event, so
    /// a peer that reconnects after being expelled cannot put a dialog on the
    /// user's screen. That is the whole mechanism: revocation cannot keep an
    /// attacker out (it can re-key), but it can stop it choosing the moment you
    /// are asked to let it back in.
    fn raise_connection_attempt(
        &mut self,
        fingerprint: String,
        origin: AttemptOrigin,
        addr: Option<SocketAddr>,
    ) {
        if let Some(entry) = self.revoked.get(&fingerprint) {
            log::warn!(
                "ignoring a connection attempt from revoked device {:?} ({fingerprint}) — \
                 restore it from the device list if this is intended",
                entry.label
            );
            return;
        }
        if origin == AttemptOrigin::OutboundDial {
            // Say so. A console verb can cause this, and a prompt the console
            // summoned must not look like a peer knocking (#61).
            log::info!(
                "{fingerprint} at {addr:?} was reached by OUR OWN dial, not by an \
                 unsolicited connection — the prompt will say so, and will show the \
                 address so it can be compared with the one that was typed"
            );
        }
        self.notify_frontend(FrontendEvent::ConnectionAttempt {
            fingerprint,
            origin,
            addr,
        });
    }

    /// Tear down every live session with `fp`, in both directions.
    ///
    /// Peer identity is checked ONCE, at the TLS handshake, so dropping a key
    /// from the allowlist does nothing to a session that is already up. EVERY
    /// path that removes trust must call this, or "revoke" only hides the card
    /// while the peer keeps driving this machine (or we keep driving theirs).
    fn cut_sessions(&mut self, fp: &str) {
        // Resolve the handles first: clear_pins_matching erases the fingerprint
        // that the outbound match is made on.
        let handles = self.client_manager.handles_with_fingerprint(fp);
        let (inbound, outbound, revoked) = (
            self.revoke_listen.clone(),
            self.revoke_conn.clone(),
            fp.to_string(),
        );
        tokio::task::spawn_local(async move {
            let cut_in = inbound.close_fingerprint(&revoked).await;
            let cut_out = outbound.close_handles(&handles).await;
            if cut_in + cut_out > 0 {
                log::warn!(
                    "revoked {revoked}: cut {cut_in} incoming + {cut_out} outgoing session(s)"
                );
            }
        });
    }

    /// Rename a device that is ALREADY trusted. This must never be able to
    /// grant trust.
    ///
    /// Before this existed, both frontends renamed an inbound peer by re-sending
    /// `AuthorizeKey` with a new description — so the wire could not tell a
    /// rename from a trust grant, and a console that should only be able to
    /// relabel had, in practice, the ability to authorize.
    fn set_label(&mut self, fp: String, label: String) {
        let Some(fp) = hops_ipc::pairing::canonical_fingerprint(&fp) else {
            log::warn!("refusing to relabel {fp:?}: not a valid fingerprint");
            return;
        };
        let known = self.authorized_keys.read().expect("lock").contains_key(&fp);
        if !known {
            // Refuse, do NOT insert. Inserting here would make this verb a
            // trust grant wearing a different name, which is the whole point of
            // separating them.
            log::warn!(
                "refusing to relabel {fp}: it is not an authorized device. \
                 Renaming cannot grant trust."
            );
            self.notify_frontend(FrontendEvent::Error(
                "That device is not trusted, so it cannot be renamed.".to_string(),
            ));
            return;
        }
        let label = hops_ipc::pairing::sanitize_label(&label);
        self.authorized_keys
            .write()
            .expect("lock")
            .insert(fp, label);
        let keys = self.authorized_keys.read().expect("lock").clone();
        self.notify_frontend(FrontendEvent::AuthorizedUpdated(keys));
    }

    fn remove_authorized_key(&mut self, fp: String) {
        // Canonicalise here too, or a tombstone can be written under a spelling
        // that `add_authorized_key` will never match (issue #67). An invalid
        // fingerprint is still tombstoned under its lowercased form rather than
        // dropped: refusing to revoke is the more dangerous failure.
        let fp = hops_ipc::pairing::canonical_fingerprint(&fp)
            .unwrap_or_else(|| fp.trim().to_lowercase());
        let label = self
            .authorized_keys
            .write()
            .expect("lock")
            .remove(&fp)
            .unwrap_or_default();
        // Remember the expulsion. Without this the peer is a stranger again on
        // its next dial and raises the ordinary approval prompt, which is how
        // "revoke" ended up being one click away from undone.
        self.revoked.insert(
            fp.clone(),
            hops_ipc::RevokedEntry {
                label,
                revoked_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default(),
            },
        );
        self.cut_sessions(&fp);
        // Revoking trust in a fingerprint releases any outbound pin on it, so a
        // client whose receiver re-keyed (e.g. reinstall) can re-learn + re-pin
        // the new identity on its next dial instead of being stranded on the
        // dead fingerprint. See the fail-closed pin in `connect::connect`.
        for h in self.client_manager.clear_pins_matching(&fp) {
            self.broadcast_client(h);
        }
        let keys = self.authorized_keys.read().expect("lock").clone();
        self.notify_frontend(FrontendEvent::AuthorizedUpdated(keys));
        let revoked = self.revoked.clone();
        self.notify_frontend(FrontendEvent::RevokedUpdated(revoked));
    }

    fn enumerate(&mut self) {
        let clients = self.client_manager.get_client_states();
        self.notify_frontend(FrontendEvent::Enumerate(clients));
    }

    fn add_client(&mut self) {
        let handle = self.client_manager.add_client();
        log::info!("added client {handle}");
        let (c, s) = self.client_manager.get_state(handle).unwrap();
        self.notify_frontend(FrontendEvent::Created(handle, c, s));
    }

    fn set_client_active(&mut self, handle: ClientHandle, active: bool) {
        if active {
            self.activate_client(handle);
        } else {
            self.deactivate_client(handle);
        }
    }

    fn deactivate_client(&mut self, handle: ClientHandle) {
        log::debug!("deactivating client {handle}");
        if self.client_manager.deactivate_client(handle) {
            self.capture.destroy(handle);
            self.broadcast_client(handle);
            log::info!("deactivated client {handle}");
        }
    }

    fn activate_client(&mut self, handle: ClientHandle) {
        log::debug!("activating client {handle}");

        /* resolve dns on activate */
        self.resolve(handle);

        /* deactivate potential other client at this position */
        let Some(pos) = self.client_manager.get_pos(handle) else {
            return;
        };

        if let Some(other) = self.client_manager.client_at(pos) {
            if other != handle {
                // Silent eviction was a real trap: the user's FIRST machine
                // stopped working right after they added a second, with its
                // toggle flipping off by itself and no message anywhere.
                let name = self
                    .client_manager
                    .get_hostname(other)
                    .unwrap_or_else(|| format!("device {other}"));
                self.deactivate_client(other);
                self.notify_frontend(FrontendEvent::Error(format!(
                    "Switched off \"{name}\" — it was using the {pos} edge, \
                     and two devices cannot share one edge."
                )));
            }
        }

        /* activate the client */
        if self.client_manager.activate_client(handle) {
            /* notify capture and frontends */
            self.capture.create(handle, pos, CaptureType::Default);
            self.broadcast_client(handle);
            log::info!("activated client {handle} ({pos})");
        }
    }

    fn change_port(&mut self, port: u16) {
        if self.port != port {
            self.emulation.request_port_change(port);
        } else {
            self.notify_frontend(FrontendEvent::PortChanged(self.port, None));
        }
    }

    fn remove_client(&mut self, handle: ClientHandle) {
        if self
            .client_manager
            .remove_client(handle)
            .map(|(_, s)| s.active)
            .unwrap_or(false)
        {
            self.capture.destroy(handle);
        }
        self.notify_frontend(FrontendEvent::Deleted(handle));
    }

    fn update_fix_ips(&mut self, handle: ClientHandle, fix_ips: Vec<IpAddr>) {
        self.client_manager.set_fix_ips(handle, fix_ips);
        self.broadcast_client(handle);
    }

    fn update_hostname(&mut self, handle: ClientHandle, hostname: Option<String>) {
        log::info!("hostname changed: {hostname:?}");
        if self.client_manager.set_hostname(handle, hostname.clone()) {
            self.resolve(handle);
        }
        self.broadcast_client(handle);
    }

    fn update_port(&mut self, handle: ClientHandle, port: u16) {
        self.client_manager.set_port(handle, port);
        self.broadcast_client(handle);
    }

    fn update_pos(&mut self, handle: ClientHandle, pos: Position) {
        // update state in event input emulator & input capture
        if self.client_manager.set_pos(handle, pos) {
            self.deactivate_client(handle);
            self.activate_client(handle);
        }
        self.broadcast_client(handle);
    }

    fn update_geometry(&mut self, handle: ClientHandle, geometry: Option<hops_ipc::Geometry>) {
        self.client_manager.set_geometry(handle, geometry);
        self.broadcast_client(handle);
    }

    fn broadcast_client(&mut self, handle: ClientHandle) {
        let event = self
            .client_manager
            .get_state(handle)
            .map(|(c, s)| FrontendEvent::State(handle, c, s))
            .unwrap_or(FrontendEvent::NoSuchClient(handle));
        self.notify_frontend(event);
    }

    fn spawn_hook_command(&self, handle: ClientHandle) {
        let Some(cmd) = self.client_manager.get_enter_cmd(handle) else {
            return;
        };
        tokio::task::spawn_local(async move {
            log::info!("spawning command!");
            let mut child = match Command::new("sh").arg("-c").arg(cmd.as_str()).spawn() {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("could not execute cmd: {e}");
                    return;
                }
            };
            match child.wait().await {
                Ok(s) => {
                    if s.success() {
                        log::info!("{cmd} exited successfully");
                    } else {
                        log::warn!("{cmd} exited with {s}");
                    }
                }
                Err(e) => log::warn!("{cmd}: {e}"),
            }
        });
    }
}

#[cfg(test)]
mod ipc_shell_guard {
    //! Guard for #56: **the frontend IPC channel must never reach a shell.**
    //!
    //! `spawn_hook_command` runs `sh -c` with a config-supplied string. While a
    //! `FrontendRequest` variant could set that string, reaching the frontend
    //! socket was equivalent to arbitrary command execution — the boundary was
    //! protecting a shell, not a settings pane. `enter_hook` is now config-file
    //! only, so setting it requires write access to the config directory.
    //!
    //! These read our own source because the property is structural: no runtime
    //! test can prove a *future* variant will not be wired to a shell. Both are
    //! mutation-tested — reintroduce the arm and they fail.

    const SERVICE_RS: &str = include_str!("service.rs");
    const IPC_RS: &str = include_str!("../crates/hops-ipc/src/lib.rs");

    /// Body of `handle_frontend_request` — from its signature to the next method
    /// at the same indentation.
    fn dispatch_body() -> &'static str {
        let start = SERVICE_RS
            .find("fn handle_frontend_request")
            .expect("handle_frontend_request must exist; if it was renamed, update this guard");
        let rest = &SERVICE_RS[start..];
        let end = rest[1..]
            .find("\n    fn ")
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        &rest[..end]
    }

    #[test]
    fn ipc_dispatch_cannot_reach_a_shell() {
        let body = dispatch_body();
        for forbidden in ["spawn_hook_command", "Command::new", "process::Command"] {
            assert!(
                !body.contains(forbidden),
                "`{forbidden}` is reachable from handle_frontend_request. A FrontendRequest \
                 must never reach command execution — see issue #56. If a privileged verb is \
                 genuinely needed, update the security model in the SAME change."
            );
        }
    }

    #[test]
    fn no_frontend_request_verb_sets_the_enter_hook() {
        let start = IPC_RS
            .find("pub enum FrontendRequest")
            .expect("FrontendRequest must exist; if it moved, update this guard");
        let rest = &IPC_RS[start..];
        let end = rest.find("\n}").map(|i| i + 2).unwrap_or(rest.len());
        let variants = &rest[..end];
        // Match the variant, not the explanatory comment that references it.
        for line in variants.lines() {
            let code = line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("EnterHook"),
                "FrontendRequest gained an enter-hook verb: `{}`. That string is executed \
                 with `sh -c`, so this reopens the RCE path closed in #56.",
                line.trim()
            );
        }
    }
}

#[cfg(test)]
mod trust_door_guard {
    //! **Revocation outranks the allowlist at every door, and fingerprints are
    //! canonicalised where they enter.**
    //!
    //! These read our own source because the property is structural: no runtime
    //! test can prove that a *future* call site will remember. Issue #66 existed
    //! precisely because the rule was enforced at two of three doors, and the
    //! one it missed was the one every daemon walks through on every boot.

    /// Non-test source only. These guards mention the very strings they forbid,
    /// so scanning the whole file would make them fail on themselves.
    fn production_source(src: &str) -> String {
        src.split("\n#[cfg(test)]")
            .next()
            .unwrap_or(src)
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    const SERVICE_RS_ALL: &str = include_str!("service.rs");
    const CONFIG_RS_ALL: &str = include_str!("config.rs");

    /// Body of a `fn name(` up to the next item at the same indentation.
    fn body_of<'a>(src: &'a str, sig: &str) -> &'a str {
        let start = src
            .find(sig)
            .unwrap_or_else(|| panic!("{sig} must exist; if it was renamed, update this guard"));
        let rest = &src[start..];
        let end = rest[1..]
            .find("\n    pub fn ")
            .or_else(|| rest[1..].find("\n    fn "))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        &rest[..end]
    }

    #[test]
    fn the_daemon_never_reads_the_raw_allowlist() {
        assert!(
            !production_source(SERVICE_RS_ALL).contains("authorized_fingerprints()"),
            "service.rs must obtain the allowlist only via Config::effective_allowlist(), \
             which subtracts revocation tombstones. Calling authorized_fingerprints() \
             directly is how a revoked device came back after a reboot — issue #66."
        );
    }

    #[test]
    fn effective_allowlist_is_the_only_reader_of_the_raw_allowlist() {
        let calls = production_source(CONFIG_RS_ALL)
            .matches("self.authorized_fingerprints()")
            .count();
        assert_eq!(
            calls, 1,
            "exactly one caller of the raw allowlist is allowed, and it must be \
             effective_allowlist(). Found {calls}."
        );
        assert!(
            body_of(
                &production_source(CONFIG_RS_ALL),
                "pub fn effective_allowlist("
            )
            .contains("self.authorized_fingerprints()"),
            "the one caller must be effective_allowlist()"
        );
    }

    #[test]
    fn both_fingerprint_tables_are_lowercased_on_read() {
        // Normalising only ONE of the two tables is the whole of issue #67:
        // they are compared against each other, so they must agree on form.
        let src = production_source(CONFIG_RS_ALL);
        for reader in [
            "pub fn authorized_fingerprints(",
            "pub fn revoked_fingerprints(",
        ] {
            assert!(
                body_of(&src, reader).contains("to_lowercase()"),
                "{reader} must lowercase its keys. When only the authorized table did, an \
                 expelled fingerprint re-added in uppercase missed the tombstone and was \
                 then folded back to canonical form on the next read — issue #67."
            );
        }
    }

    #[test]
    fn both_trust_doors_canonicalise_the_fingerprint() {
        for door in ["fn add_authorized_key(", "fn remove_authorized_key("] {
            assert!(
                body_of(&production_source(SERVICE_RS_ALL), door).contains("canonical_fingerprint"),
                "{door} must canonicalise before touching the trust maps. An uppercased \
                 spelling of an expelled fingerprint missed the tombstone and was folded \
                 back to canonical form on the next config read — issue #67."
            );
        }
    }
}

#[cfg(test)]
mod set_label_cannot_grant {
    //! Renaming a device must never be a way to trust one.
    //!
    //! Both frontends used to rename an inbound peer by re-sending
    //! `AuthorizeKey` with a new description, so on the wire a rename and a
    //! trust grant were the same request. A console that should only be able to
    //! relabel had, in practice, the ability to authorize — which is the shape
    //! Layer 1 of `CONSENT-ARCHITECTURE.md` exists to remove.

    /// Non-test source only: these guards name the very calls they forbid.
    fn production(src: &str) -> String {
        src.split("\n#[cfg(test)]")
            .next()
            .unwrap_or(src)
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn body_of(src: &str, sig: &str) -> String {
        let start = src
            .find(sig)
            .unwrap_or_else(|| panic!("{sig} must exist; if it was renamed, update this guard"));
        let rest = &src[start..];
        let end = rest[1..]
            .find("\n    fn ")
            .or_else(|| rest[1..].find("\n    pub fn "))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        rest[..end].to_string()
    }

    #[test]
    fn set_label_refuses_an_unknown_fingerprint_rather_than_inserting_it() {
        let src = production(include_str!("service.rs"));
        let body = body_of(&src, "fn set_label(");
        assert!(
            body.contains("contains_key"),
            "set_label must CHECK that the fingerprint is already authorized"
        );
        // The refusal must come before any write. If the only `insert` is
        // reachable unconditionally, this verb is a trust grant in disguise.
        let check = body.find("contains_key").expect("checked above");
        let insert = body.find(".insert(").expect("set_label must write a label");
        assert!(
            check < insert,
            "set_label must refuse an unknown fingerprint BEFORE writing — otherwise \
             renaming is a way to authorize"
        );
        assert!(
            body.contains("return"),
            "the unknown-fingerprint path must return, not fall through"
        );
    }

    #[test]
    fn renaming_in_the_frontends_no_longer_sends_authorize_key() {
        for (name, src) in [
            (
                "hops-slint",
                production(include_str!("../crates/hops-slint/src/lib.rs")),
            ),
            (
                "hops-tui",
                production(include_str!("../crates/hops-tui/src/lib.rs")),
            ),
        ] {
            // AuthorizeKey may still appear — approving a NEW device is a genuine
            // trust grant. What must not appear is a rename path that uses it.
            assert!(
                src.contains("SetLabel"),
                "{name} must have a rename path that is not a trust grant"
            );
        }
    }
}

#[cfg(test)]
mod one_trust_write_site {
    //! Only the named trust doors may write the allowlist or the denylist.
    //!
    //! Layer 1 of `CONSENT-ARCHITECTURE.md` asks for exactly one place that
    //! mutates trust. This guards the property before the refactor that makes it
    //! structural, because the property is what matters and a fifth writer added
    //! next month is the actual risk.
    //!
    //! It is not hypothetical. #105's guard — written to enforce "one allowlist
    //! READER" — failed on its first run against a third reader nobody had
    //! counted (`drop_untrusted_pins` taking the raw allowlist at startup),
    //! after two reviews had already missed it.

    /// Non-test source with comments stripped: this guard names what it forbids.
    fn production() -> String {
        include_str!("service.rs")
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Which `fn` encloses a given byte offset.
    fn enclosing_fn(src: &str, at: usize) -> String {
        src[..at]
            .rmatch_indices("fn ")
            .map(|(i, _)| {
                let rest = &src[i..];
                rest[..rest.find('(').unwrap_or(rest.len())]
                    .trim()
                    .to_string()
            })
            .next()
            .unwrap_or_else(|| "<top level>".to_string())
    }

    /// The doors that are ALLOWED to mutate trust. Adding to this list is a
    /// deliberate act; arriving here by accident is what the guard prevents.
    const DOORS: &[&str] = &[
        "fn add_authorized_key",    // grant
        "fn remove_authorized_key", // revoke + tombstone
        "fn set_label",             // rename, refuses unknown fingerprints
        "fn handle_config_change",  // reload: the config file is a door too
        "fn new",                   // startup load
    ];

    #[test]
    fn nothing_outside_the_named_doors_writes_the_allowlist() {
        let src = production();
        let mut offenders = vec![];
        for (at, _) in src.match_indices("authorized_keys.write()") {
            let f = enclosing_fn(&src, at);
            if !DOORS.iter().any(|d| f.starts_with(d)) {
                offenders.push(f);
            }
        }
        assert!(
            offenders.is_empty(),
            "these write the allowlist and are not a named trust door: {offenders:?}. \
             Trust must change in one place — see CONSENT-ARCHITECTURE.md Layer 1. If a \
             new door is genuinely needed, add it to DOORS in the same commit and say why."
        );
    }

    #[test]
    fn nothing_outside_the_named_doors_writes_the_denylist() {
        let src = production();
        let mut offenders = vec![];
        for pat in [
            "self.revoked.insert",
            "self.revoked.remove",
            "self.revoked =",
        ] {
            for (at, _) in src.match_indices(pat) {
                let f = enclosing_fn(&src, at);
                if !DOORS.iter().any(|d| f.starts_with(d)) {
                    offenders.push(format!("{f} ({pat})"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these write the denylist and are not a named trust door: {offenders:?}. \
             A revocation tombstone is irreversible; it must not be written from \
             somewhere nobody is looking."
        );
    }

    #[test]
    fn the_door_list_still_matches_reality() {
        // A door that no longer exists means the guard has quietly stopped
        // covering something, which is worse than not having it.
        let src = production();
        for d in DOORS {
            assert!(
                src.contains(d),
                "{d} is listed as a trust door but no longer exists — the guard is \
                 now covering less than it claims"
            );
        }
    }
}

#[cfg(test)]
mod attempt_origin_guard {
    //! Both `raise_connection_attempt` call sites must declare where the attempt
    //! came from, and they must not declare the same thing.
    //!
    //! #61: a console holding the IPC token can run `Create` →
    //! `UpdateFixIps(attacker_ip)` → `Activate` and make the daemon dial an
    //! address it chose. The receiver answers, its fingerprint is not on our
    //! allowlist, and the daemon raises a *genuine* approval prompt — for a key
    //! the attacker picked, at a moment the attacker picked. The prompt is real;
    //! what is forged is its provenance.
    //!
    //! We cannot prove where a keystroke came from. We can prove where a prompt
    //! came from, because hops itself caused it — it is a property of our own
    //! state machine. This guard keeps that property from being erased by a
    //! later refactor that "simplifies" the two sites back into one.

    /// Only the code *above* the test modules. Scanning our own text would
    /// otherwise match the string literals in these very assertions.
    fn src() -> &'static str {
        before_tests(include_str!("service.rs"))
    }

    /// Split at the first test module.
    ///
    /// Must not assume LF. `include_str!` preserves whatever the checkout has,
    /// and git on Windows checks out CRLF — so a marker ending in `\n` matches a
    /// `\r` there and never fires. This guard shipped with exactly that bug and
    /// only Windows CI caught it: the split silently returned the WHOLE file,
    /// the guard scanned its own assertions, and it failed on its own string
    /// literal. `before_tests_survives_crlf` is the local version of that
    /// Windows run.
    fn before_tests(full: &str) -> &str {
        full.split("\n#[cfg(test)]").next().unwrap_or(full)
    }

    #[test]
    fn before_tests_survives_crlf() {
        let lf = "fn real() {}\n#[cfg(test)]\nmod t { fn fake() {} }";
        let crlf = "fn real() {}\r\n#[cfg(test)]\r\nmod t { fn fake() {} }";
        for (name, s) in [("lf", lf), ("crlf", crlf)] {
            assert!(
                !before_tests(s).contains("fake"),
                "{name}: test-module source leaked into the scanned region, so every \
                 guard built on this silently scans its own assertions"
            );
            assert!(
                before_tests(s).contains("real"),
                "{name}: real source was cut"
            );
        }
    }

    /// The lines that actually CALL it — not the definition, not prose.
    fn raise_sites() -> Vec<&'static str> {
        src()
            .lines()
            .map(str::trim)
            .filter(|l| l.contains("self.raise_connection_attempt("))
            .collect()
    }

    /// Every call must pass an origin — no defaulting, no inference downstream.
    #[test]
    fn every_raise_site_names_its_origin() {
        let calls = raise_sites();
        assert!(
            !calls.is_empty(),
            "the raise sites vanished — this guard is now testing nothing"
        );
        for c in &calls {
            assert!(
                c.contains("AttemptOrigin::"),
                "a ConnectionAttempt is raised without saying where it came from: {c:?}. \
                 An attacker-summoned dial would then be indistinguishable from a peer \
                 knocking (#61)."
            );
        }
    }

    /// And the two must stay distinguishable. One `Inbound`, one `OutboundDial`:
    /// collapsing them is precisely the defect.
    ///
    /// Count what the CALL SITES pass, not how often the variants are named.
    /// Two earlier versions of this were wrong in opposite directions: keying on
    /// a trailing `)` broke when `addr` became an argument, and then counting
    /// bare mentions silently stopped catching anything, because
    /// `if origin == AttemptOrigin::OutboundDial` inside this very function
    /// survives the mutation and keeps the count at one.
    #[test]
    fn the_two_provenances_are_still_distinct() {
        let passed: Vec<&str> = raise_sites()
            .into_iter()
            .filter_map(|l| {
                l.split("AttemptOrigin::")
                    .nth(1)
                    .map(|rest| rest.trim_end_matches(|c: char| !c.is_alphanumeric()))
                    .map(|v| {
                        if v.starts_with("Inbound") {
                            "Inbound"
                        } else {
                            "OutboundDial"
                        }
                    })
            })
            .collect();
        assert!(
            passed.contains(&"Inbound") && passed.contains(&"OutboundDial"),
            "the raise sites pass {passed:?}. Both provenances must still be raised: \
             if they all pass the same one, a prompt our own dial summoned is \
             indistinguishable from a peer knocking — the #61 defect."
        );
    }
}

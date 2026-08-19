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
    AsyncFrontendListener, ClientHandle, FrontendEvent, FrontendRequest, IpcError,
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
    untrusted_receivers: Receiver<String>,
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
        drop_untrusted_pins(&client_manager, &config.authorized_fingerprints());

        // load identity (cert + key)
        let identity = Arc::new(crypto::load_or_generate_key_and_cert(config.cert_path())?);
        let public_key_fingerprint = crypto::certificate_fingerprint(&identity);

        // create frontend communication adapter, exit if already running
        let frontend_listener = AsyncFrontendListener::new().await?;

        let authorized_keys = Arc::new(RwLock::new(config.authorized_fingerprints()));

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
                    if let Some(fp) = fp {
                        // only prompt if it really is untrusted — a racing dial can
                        // report a fingerprint that was authorized in the meantime
                        let known = self.authorized_keys.read().expect("lock").contains_key(&fp);
                        if !known {
                            log::info!("untrusted receiver {fp} — raising an approval prompt");
                            self.raise_connection_attempt(fp);
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
            FrontendRequest::UpdateEnterHook(handle, enter_hook) => {
                self.update_enter_hook(handle, enter_hook)
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
        let mut authorized_keys = self.config.authorized_fingerprints();
        // Revocation outranks the allowlist. Re-adding a revoked fingerprint by
        // hand-editing config.toml is refused and logged, so the denylist cannot
        // be laundered around by copy-pasting a key back into the other table.
        for fp in self.revoked.keys() {
            if authorized_keys.remove(fp).is_some() {
                log::warn!(
                    "config lists {fp} as BOTH authorized and revoked — refusing it. \
                     Restore it from the device list if that is what you meant."
                );
            }
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
                self.raise_connection_attempt(fingerprint);
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
    fn raise_connection_attempt(&mut self, fingerprint: String) {
        if let Some(entry) = self.revoked.get(&fingerprint) {
            log::warn!(
                "ignoring a connection attempt from revoked device {:?} ({fingerprint}) — \
                 restore it from the device list if this is intended",
                entry.label
            );
            return;
        }
        self.notify_frontend(FrontendEvent::ConnectionAttempt { fingerprint });
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

    fn remove_authorized_key(&mut self, fp: String) {
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

    fn update_enter_hook(&mut self, handle: ClientHandle, enter_hook: Option<String>) {
        self.client_manager.set_enter_hook(handle, enter_hook);
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

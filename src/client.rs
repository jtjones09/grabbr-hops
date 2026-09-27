use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashSet},
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

use hops_ipc::{ClientConfig, ClientHandle, ClientState, Geometry, Position};

use crate::config::ConfigClient;

#[derive(Clone, Default)]
pub struct ClientManager {
    clients: Rc<RefCell<Clients>>,
}

/// Every device, under a handle that is never handed out twice.
///
/// Work that outlives a request holds a handle across an await: a dial reads
/// the device's address, waits for the handshake, then writes the identity and
/// link it got back through the handle. The handles used to be slab indexes, so
/// a freed one went straight to the next device, and a late write landed on
/// whichever machine held the index by then (#97). A handle that is never
/// reused makes every such write to a removed device a no-op.
#[derive(Default)]
struct Clients {
    next: ClientHandle,
    entries: BTreeMap<ClientHandle, (ClientConfig, ClientState)>,
    /// Each device's last pin, kept when an edit to its address or name
    /// clears the pin and replaced only by the next pin. The device switch
    /// gates the machine it names (#218), so an edit cannot lift the switch.
    last_pins: BTreeMap<ClientHandle, String>,
    /// Devices whose peer has answered a ping on the link it has now. Until
    /// it has, `alive` false says only that it has not answered yet, not
    /// that it refuses input.
    answered: BTreeSet<ClientHandle>,
}

impl Clients {
    fn get(&self, handle: ClientHandle) -> Option<&(ClientConfig, ClientState)> {
        self.entries.get(&handle)
    }

    fn get_mut(&mut self, handle: ClientHandle) -> Option<&mut (ClientConfig, ClientState)> {
        self.entries.get_mut(&handle)
    }

    fn iter(&self) -> impl Iterator<Item = (ClientHandle, &(ClientConfig, ClientState))> {
        self.entries.iter().map(|(h, c)| (*h, c))
    }

    fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (ClientHandle, &mut (ClientConfig, ClientState))> {
        self.entries.iter_mut().map(|(h, c)| (*h, c))
    }
}

/// What a config reload changes: the devices whose entry is gone or edited,
/// and the entries to add for them. An entry the file still holds unchanged
/// keeps its device, handle and connection.
pub(crate) struct Reload {
    pub(crate) stale: Vec<ClientHandle>,
    pub(crate) fresh: Vec<ConfigClient>,
}

impl ClientManager {
    /// get all clients
    pub fn clients(&self) -> Vec<(ClientConfig, ClientState)> {
        self.clients
            .borrow()
            .iter()
            .map(|(_, c)| c.clone())
            .collect::<Vec<_>>()
    }

    pub fn add_with_config(&self, config_client: ConfigClient) -> ClientHandle {
        let config = ClientConfig {
            hostname: config_client.hostname,
            fix_ips: config_client.ips.into_iter().collect(),
            port: config_client.port,
            pos: config_client.pos,
            cmd: config_client.enter_hook,
            geometry: None,
        };
        let state = ClientState {
            active: config_client.active,
            ips: HashSet::from_iter(config.fix_ips.iter().cloned()),
            // seed the pin from config so the device view can join this client to
            // its authorized_fingerprints entry from a COLD START, and so the
            // fail-closed dial pin survives a restart
            peer_fingerprint: config_client.fingerprint,
            ..Default::default()
        };
        let handle = self.add_client();
        self.set_config(handle, config);
        self.set_state(handle, state);
        handle
    }

    /// add a new client to this manager
    pub fn add_client(&self) -> ClientHandle {
        let mut clients = self.clients.borrow_mut();
        let handle = clients.next;
        clients.next += 1;
        clients.entries.insert(handle, Default::default());
        handle
    }

    /// set the config of the given client
    pub fn set_config(&self, handle: ClientHandle, config: ClientConfig) {
        if let Some((c, _)) = self.clients.borrow_mut().get_mut(handle) {
            *c = config;
        }
    }

    /// set the state of the given client
    pub fn set_state(&self, handle: ClientHandle, state: ClientState) {
        let mut clients = self.clients.borrow_mut();
        let pin = state.peer_fingerprint.clone();
        if let Some((_, s)) = clients.get_mut(handle) {
            *s = state;
            if let Some(pin) = pin {
                clients.last_pins.insert(handle, pin);
            }
        }
    }

    /// activate the given client
    /// returns, whether the client was activated
    pub fn activate_client(&self, handle: ClientHandle) -> bool {
        let mut clients = self.clients.borrow_mut();
        match clients.get_mut(handle) {
            Some((_, s)) if !s.active => {
                s.active = true;
                true
            }
            _ => false,
        }
    }

    /// deactivate the given client
    /// returns, whether the client was deactivated
    pub fn deactivate_client(&self, handle: ClientHandle) -> bool {
        let mut clients = self.clients.borrow_mut();
        match clients.get_mut(handle) {
            Some((_, s)) if s.active => {
                s.active = false;
                true
            }
            _ => false,
        }
    }

    /// find a client by its address
    pub fn get_client(&self, addr: SocketAddr) -> Option<ClientHandle> {
        // since there shouldn't be more than a handful of clients at any given
        // time this is likely faster than using a HashMap
        self.clients
            .borrow()
            .iter()
            .find_map(|(k, (_, s))| (s.active && s.ips.contains(&addr.ip())).then_some(k))
    }

    /// get the client at the given position
    pub fn client_at(&self, pos: Position) -> Option<ClientHandle> {
        self.clients
            .borrow()
            .iter()
            .find_map(|(k, (c, s))| (s.active && c.pos == pos).then_some(k))
    }

    pub(crate) fn get_hostname(&self, handle: ClientHandle) -> Option<String> {
        self.clients
            .borrow_mut()
            .get_mut(handle)
            .and_then(|(c, _)| c.hostname.clone())
    }

    /// get the position of the corresponding client
    pub(crate) fn get_pos(&self, handle: ClientHandle) -> Option<Position> {
        self.clients.borrow().get(handle).map(|(c, _)| c.pos)
    }

    /// remove a client from the list
    pub fn remove_client(&self, client: ClientHandle) -> Option<(ClientConfig, ClientState)> {
        let mut clients = self.clients.borrow_mut();
        clients.last_pins.remove(&client);
        clients.answered.remove(&client);
        clients.entries.remove(&client)
    }

    /// get the config & state of the given client
    pub fn get_state(&self, handle: ClientHandle) -> Option<(ClientConfig, ClientState)> {
        self.clients.borrow().get(handle).cloned()
    }

    /// get the current config & state of all clients
    pub fn get_client_states(&self) -> Vec<(ClientHandle, ClientConfig, ClientState)> {
        self.clients
            .borrow()
            .iter()
            .map(|(k, v)| (k, v.0.clone(), v.1.clone()))
            .collect()
    }

    /// update the fix ips of the client
    pub fn set_fix_ips(&self, handle: ClientHandle, fix_ips: Vec<IpAddr>) {
        if let Some((c, s)) = self.clients.borrow_mut().get_mut(handle) {
            // only forget the learned identity if the target set actually changed
            // — an additive/no-op re-push shouldn't drop a good pin and re-open
            // the unpinned race. A fresh handshake re-learns + re-pins it.
            if c.fix_ips != fix_ips {
                s.peer_fingerprint = None;
            }
            c.fix_ips = fix_ips;
        }
        self.update_ips(handle);
    }

    /// update the dns-ips of the client
    pub fn set_dns_ips(&self, handle: ClientHandle, dns_ips: Vec<IpAddr>) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle) {
            s.dns_ips = dns_ips
        }
        self.update_ips(handle);
    }

    fn update_ips(&self, handle: ClientHandle) {
        if let Some((c, s)) = self.clients.borrow_mut().get_mut(handle) {
            s.ips = c
                .fix_ips
                .iter()
                .cloned()
                .chain(s.dns_ips.iter().cloned())
                .collect::<HashSet<_>>();
        }
    }

    /// update the hostname of the given client
    /// this automatically clears the active ip address and ips from dns
    pub fn set_hostname(&self, handle: ClientHandle, hostname: Option<String>) -> bool {
        let mut clients = self.clients.borrow_mut();
        let Some((c, s)) = clients.get_mut(handle) else {
            return false;
        };

        // hostname changed
        if c.hostname != hostname {
            c.hostname = hostname;
            s.active_addr = None;
            s.dns_ips.clear();
            // a new hostname may resolve to a different machine — forget the
            // learned identity so the pin re-learns it on the next handshake.
            s.peer_fingerprint = None;
            drop(clients);
            self.update_ips(handle);
            true
        } else {
            false
        }
    }

    /// update the port of the client
    pub(crate) fn set_port(&self, handle: ClientHandle, port: u16) {
        match self.clients.borrow_mut().get_mut(handle) {
            Some((c, s)) if c.port != port => {
                c.port = port;
                s.active_addr = s.active_addr.map(|a| SocketAddr::new(a.ip(), port));
            }
            _ => {}
        };
    }

    /// update the position of the client
    /// returns true, if a change in capture position is required (pos changed & client is active)
    pub(crate) fn set_pos(&self, handle: ClientHandle, pos: Position) -> bool {
        match self.clients.borrow_mut().get_mut(handle) {
            Some((c, s)) if c.pos != pos => {
                log::info!("update pos {handle} {} -> {}", c.pos, pos);
                c.pos = pos;
                s.active
            }
            _ => false,
        }
    }

    /// update the spatial layout rect of the client (the drag-to-arrange
    /// canvas). Purely additive/storage — unlike `set_pos`, this does NOT
    /// affect capture activation; coordinate-based crossing is a separate,
    /// not-yet-built behavior change that reads this field later.
    pub(crate) fn set_geometry(&self, handle: ClientHandle, geometry: Option<Geometry>) {
        if let Some((c, _s)) = self.clients.borrow_mut().get_mut(handle) {
            c.geometry = geometry;
        }
    }

    /// set resolving status of the client
    pub(crate) fn set_resolving(&self, handle: ClientHandle, status: bool) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle) {
            s.resolving = status;
        }
    }

    /// get the enter hook command
    pub(crate) fn get_enter_cmd(&self, handle: ClientHandle) -> Option<String> {
        self.clients
            .borrow()
            .get(handle)
            .and_then(|(c, _)| c.cmd.clone())
    }

    /// Match a reloaded config against the devices already here.
    ///
    /// Each entry in the file claims a device whose own entry reads exactly
    /// the same, so a reload that changed nothing about a device leaves it
    /// alone: same handle, same connection, same capture. Anything else is
    /// replaced, and the replacement gets a handle never used before, so
    /// nothing a frontend or a dial holds for the old one can reach it. The
    /// file's order does not matter: reordering the entries moves nothing.
    ///
    /// Reloads used to remove every device and add them all back, which gave
    /// the handles out again in a different order and aimed a frontend's
    /// armed delete at another machine (#94).
    pub(crate) fn plan_reload(&self, entries: Vec<ConfigClient>) -> Reload {
        let mut unclaimed: Vec<(ClientHandle, ConfigClient)> = self
            .clients
            .borrow()
            .iter()
            .map(|(h, (c, s))| (h, config_entry(c, s)))
            .collect();
        let mut fresh = Vec::new();
        for entry in entries {
            match unclaimed.iter().position(|(_, e)| *e == entry) {
                Some(at) => {
                    unclaimed.remove(at);
                }
                None => fresh.push(entry),
            }
        }
        Reload {
            stale: unclaimed.into_iter().map(|(h, _)| h).collect(),
            fresh,
        }
    }

    /// Whether `handle` is still a device, and still dials `addr`: the check
    /// a dial makes before it writes what it found back onto the device.
    pub(crate) fn targets(&self, handle: ClientHandle, addr: SocketAddr) -> bool {
        self.clients
            .borrow()
            .get(handle)
            .is_some_and(|(c, s)| c.port == addr.port() && s.ips.contains(&addr.ip()))
    }

    /// Whether `handle` is a device and is switched on.
    pub(crate) fn is_on(&self, handle: ClientHandle) -> bool {
        self.clients
            .borrow()
            .get(handle)
            .is_some_and(|(_, s)| s.active)
    }

    /// The devices whose connection is open to `addr`.
    pub(crate) fn handles_at(&self, addr: SocketAddr) -> Vec<ClientHandle> {
        self.clients
            .borrow()
            .iter()
            .filter(|(_, (_, s))| s.active_addr == Some(addr))
            .map(|(h, _)| h)
            .collect()
    }

    /// returns all clients that are currently active
    pub(crate) fn active_clients(&self) -> Vec<ClientHandle> {
        self.clients
            .borrow()
            .iter()
            .filter(|(_, (_, s))| s.active)
            .map(|(h, _)| h)
            .collect()
    }

    pub(crate) fn set_active_addr(&self, handle: ClientHandle, addr: Option<SocketAddr>) {
        let mut clients = self.clients.borrow_mut();
        if addr.is_none() {
            clients.answered.remove(&handle);
        }
        if let Some((_, s)) = clients.get_mut(handle) {
            s.active_addr = addr;
        }
    }

    /// `handle`'s peer answered a ping, saying whether it injects input.
    /// Returns whether this changed `alive`, as [`Self::set_alive`] does.
    pub(crate) fn answered_ping(&self, handle: ClientHandle, alive: bool) -> bool {
        {
            let mut clients = self.clients.borrow_mut();
            if clients.entries.contains_key(&handle) {
                clients.answered.insert(handle);
            }
        }
        self.set_alive(handle, alive)
    }

    /// Whether `handle`'s peer has answered a ping on its current link.
    pub(crate) fn answered(&self, handle: ClientHandle) -> bool {
        self.clients.borrow().answered.contains(&handle)
    }

    /// Returns whether this actually changed `alive`.
    ///
    /// The caller republishes on a change and stays quiet otherwise: pongs
    /// arrive about twice a second per client, and the frontend only needs to
    /// hear when the answer is different. Without a signal at all, the sender's
    /// row keeps whatever it learned first — so a peer whose input emulation
    /// was broken and has since recovered still reads "not accepting input",
    /// forever, because nothing republishes the state that says otherwise.
    pub(crate) fn set_alive(&self, handle: ClientHandle, alive: bool) -> bool {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle) {
            return std::mem::replace(&mut s.alive, alive) != alive;
        }
        false
    }

    pub(crate) fn set_peer_commit(&self, handle: ClientHandle, commit: Option<[u8; 8]>) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle) {
            s.peer_commit = commit;
        }
    }

    pub(crate) fn set_peer_caps(&self, handle: ClientHandle, caps: Option<u32>) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle) {
            s.peer_caps = caps;
        }
    }

    pub(crate) fn set_peer_fingerprint(&self, handle: ClientHandle, fingerprint: Option<String>) {
        let mut clients = self.clients.borrow_mut();
        if let Some((_, s)) = clients.get_mut(handle) {
            s.peer_fingerprint = fingerprint.clone();
            if let Some(pin) = fingerprint {
                clients.last_pins.insert(handle, pin);
            }
        }
    }

    /// The receiver's last-known leaf-cert fingerprint for this client
    /// (process-local; learned at handshake, not persisted), or `None` if it has
    /// never connected this run or the target address / trust changed since.
    /// Used to pin the outbound dial (fail closed).
    pub(crate) fn peer_fingerprint(&self, handle: ClientHandle) -> Option<String> {
        self.clients
            .borrow()
            .get(handle)
            .and_then(|(_, s)| s.peer_fingerprint.clone())
    }

    /// Whether the device switch lets clipboard text move between this
    /// machine and the one that proved `fingerprint`: sent to it or applied
    /// from it, over a link either machine opened (#218). `dialled_for` is
    /// the device this machine dialled the link for, `None` for a link the
    /// peer opened.
    ///
    /// Not over a link dialled for a device that is switched off or gone:
    /// renaming or re-addressing a device clears its pin, and its link is
    /// still its link. Not when any device switched off is, or was last,
    /// pinned to that fingerprint, even if another entry for the same machine
    /// is on: off fails closed, and an edit that clears the pin, before the
    /// switch or while it is off, leaves the machine switched off. A device
    /// never pinned names no machine for links it did not dial. The
    /// pairing's own clipboard grant is a separate check, and both have to
    /// allow.
    pub(crate) fn switch_allows_clipboard(
        &self,
        fingerprint: &str,
        dialled_for: Option<ClientHandle>,
    ) -> bool {
        let clients = self.clients.borrow();
        let names =
            |pin: Option<&str>| pin.is_some_and(|pin| pin.eq_ignore_ascii_case(fingerprint));
        dialled_for.is_none_or(|handle| self.is_on(handle))
            && !clients.iter().any(|(h, (_, s))| {
                !s.active
                    && (names(s.peer_fingerprint.as_deref())
                        || names(clients.last_pins.get(&h).map(String::as_str)))
            })
    }

    /// Clear the pin on any client currently pinned to `fingerprint`, so its
    /// next dial re-learns identity. Called when trust in that fingerprint is
    /// revoked (`remove_authorized_key`) — e.g. a receiver re-keyed on reinstall
    /// and the operator authorized the new key.
    ///
    /// Returns the handles whose pin was cleared, so the caller can republish
    /// them — otherwise the frontend keeps rendering a fingerprint the daemon
    /// has already dropped.
    pub(crate) fn clear_pins_matching(&self, fingerprint: &str) -> Vec<ClientHandle> {
        let mut cleared = vec![];
        for (h, (_, s)) in self.clients.borrow_mut().iter_mut() {
            if s.peer_fingerprint.as_deref() == Some(fingerprint) {
                s.peer_fingerprint = None;
                cleared.push(h);
            }
        }
        cleared
    }

    /// Capability bits the peer advertised via the Capability handshake, or
    /// `0` if none received yet (older peer / not-yet-negotiated) — so every
    /// gate degrades to the pre-capability behavior.
    pub(crate) fn peer_caps(&self, handle: ClientHandle) -> u32 {
        self.clients
            .borrow()
            .get(handle)
            .and_then(|(_, s)| s.peer_caps)
            .unwrap_or(0)
    }

    pub(crate) fn active_addr(&self, handle: ClientHandle) -> Option<SocketAddr> {
        self.clients
            .borrow()
            .get(handle)
            .and_then(|(_, s)| s.active_addr)
    }

    pub(crate) fn alive(&self, handle: ClientHandle) -> bool {
        self.clients
            .borrow()
            .get(handle)
            .map(|(_, s)| s.alive)
            .unwrap_or(false)
    }

    pub(crate) fn get_port(&self, handle: ClientHandle) -> Option<u16> {
        self.clients.borrow().get(handle).map(|(c, _)| c.port)
    }

    pub(crate) fn get_ips(&self, handle: ClientHandle) -> Option<HashSet<IpAddr>> {
        self.clients
            .borrow()
            .get(handle)
            .map(|(_, s)| s.ips.clone())
    }
}

/// A device as its `[[clients]]` entry reads: what `save_config` writes, and
/// what a reload compares the file against.
pub(crate) fn config_entry(config: &ClientConfig, state: &ClientState) -> ConfigClient {
    ConfigClient {
        ips: HashSet::from_iter(config.fix_ips.iter().copied()),
        hostname: config.hostname.clone(),
        port: config.port,
        pos: config.pos,
        active: state.active,
        enter_hook: config.cmd.clone(),
        fingerprint: state.peer_fingerprint.clone(),
    }
}

#[cfg(test)]
mod reload_permutation {
    //! A config reload must not move a handle onto another device.
    //!
    //! #94: the reload removed every client and re-added them from the file.
    //! `Slab`'s free list is LIFO, so removing 0,1,2 and re-inserting three
    //! entries handed back 2,1,0: the mapping was **reversed**, and reversed
    //! again on the next reload. Resetting the allocator fixed that one order
    //! and left the rest: a file whose entries were reordered still renumbered
    //! every device.
    //!
    //! That matters because a frontend holds a handle between showing a device
    //! and acting on it, and `Delete` revokes the device's fingerprint. An
    //! external write to `config.toml` (a hand edit, an editor save, a synced
    //! home directory) is the reachable trigger; hops' own saves unwatch first.
    //!
    //! These drive `plan_reload`, the function the service's reload applies;
    //! `tests/device_edits.rs` drives the reload itself, through the daemon.

    use super::*;

    fn entry(name: &str) -> ConfigClient {
        ConfigClient {
            ips: HashSet::new(),
            hostname: Some(name.to_string()),
            port: hops_ipc::DEFAULT_PORT,
            pos: Position::default(),
            active: false,
            enter_hook: None,
            fingerprint: None,
        }
    }

    fn seed(m: &ClientManager, names: &[&str]) -> Vec<ClientHandle> {
        names.iter().map(|n| m.add_with_config(entry(n))).collect()
    }

    fn mapping(m: &ClientManager) -> Vec<(ClientHandle, Option<String>)> {
        m.get_client_states()
            .into_iter()
            .map(|(h, c, _)| (h, c.hostname))
            .collect()
    }

    /// What the service's reload does with a plan.
    fn reload(m: &ClientManager, names: &[&str]) {
        let plan = m.plan_reload(names.iter().map(|n| entry(n)).collect());
        for h in plan.stale {
            m.remove_client(h);
        }
        for c in plan.fresh {
            m.add_with_config(c);
        }
    }

    // LEDGER T2 | class B | 1 return value: ClientManager::plan_reload, 6 struct state after applying it
    #[test]
    fn a_reload_does_not_renumber_the_devices() {
        let m = ClientManager::default();
        seed(&m, &["A", "B", "C"]);
        let before = mapping(&m);
        reload(&m, &["A", "B", "C"]);
        assert_eq!(
            mapping(&m),
            before,
            "a config reload that changed nothing renumbered the devices. A \
             frontend that armed \"delete handle 0\" before the reload now \
             aims it at a different machine (#94)."
        );
    }

    // LEDGER T2 | class B | 1 return value: ClientManager::plan_reload, 6 struct state after applying it
    /// And it must not alternate. "It stabilises after two reloads" would still
    /// be wrong half the time; the point is that it never moves at all.
    #[test]
    fn repeated_reloads_do_not_alternate() {
        let m = ClientManager::default();
        seed(&m, &["A", "B", "C", "D"]);
        let before = mapping(&m);
        for i in 1..=4 {
            reload(&m, &["A", "B", "C", "D"]);
            assert_eq!(mapping(&m), before, "mapping moved on reload {i}");
        }
    }

    // LEDGER T3 | class B | 1 return value: ClientManager::plan_reload
    /// The case #134 left open: the same entries in another order.
    #[test]
    fn a_reordered_config_keeps_every_handle_on_its_device() {
        let m = ClientManager::default();
        seed(&m, &["A", "B", "C"]);
        let plan = m.plan_reload(vec![entry("C"), entry("A"), entry("B")]);
        assert_eq!(
            (plan.stale, plan.fresh.len()),
            (vec![], 0),
            "(devices replaced, devices added) for a config whose entries were \
             only reordered. Nothing about any device changed, so nothing may \
             move: a replaced device's handle is one a frontend may be about to \
             delete."
        );
    }

    // LEDGER T4 | class B | 1 return value: ClientManager::plan_reload, 6 struct state after applying it
    /// An edited entry is a different device as far as the daemon can tell,
    /// so it replaces the old one under a handle nothing has held.
    #[test]
    fn an_edited_entry_gets_a_handle_never_used_before() {
        let m = ClientManager::default();
        let handles = seed(&m, &["A", "B"]);
        let plan = m.plan_reload(vec![entry("A"), entry("B2")]);
        assert_eq!(plan.stale, vec![handles[1]], "B's entry was edited");
        reload(&m, &["A", "B2"]);
        let after = mapping(&m);
        assert_eq!(after[0], (handles[0], Some("A".to_string())), "A untouched");
        assert!(
            !handles.contains(&after[1].0),
            "the edited entry came back under a handle already used ({:?}), so \
             a delete or a dial held for the old entry reaches the new one",
            after[1].0
        );
    }
}

#[cfg(test)]
mod alive_transitions {
    //! A sender kept saying "not accepting input" about a peer that had recovered.
    //!
    //! `alive` is written by the transport task on every pong — about twice a
    //! second per client — and nothing republished the client after its first
    //! publication. So whatever the sender learned when the link came up was
    //! what it kept showing. A receiver whose input emulation was genuinely
    //! broken, then fixed, still read as refusing, indefinitely.
    //!
    //! The fix is a republish on CHANGE, which needs `set_alive` to say whether
    //! anything changed. Republishing on every pong instead would put 2 IPC
    //! messages per second per client on the wire to say nothing.

    use super::*;

    #[test]
    fn only_a_change_is_worth_republishing() {
        let m = ClientManager::default();
        let h = m.add_client();

        assert!(
            m.set_alive(h, true),
            "false -> true is a change: this is the peer coming up, and the \
             frontend has to hear it"
        );
        assert!(
            !m.set_alive(h, true),
            "true -> true is a pong repeating itself. Reporting it would put \
             two IPC messages a second per client on the wire to say nothing \
             changed."
        );
        assert!(
            m.set_alive(h, false),
            "true -> false is the peer going away, and must reach the frontend"
        );
        assert!(!m.set_alive(h, false));
    }

    #[test]
    fn the_value_is_actually_stored() {
        let m = ClientManager::default();
        let h = m.add_client();
        m.set_alive(h, true);
        assert_eq!(
            m.get_state(h).map(|(_, s)| s.alive),
            Some(true),
            "reporting the transition must not come at the cost of recording it"
        );
    }

    // LEDGER T115-13 | class B | 6 struct state: ClientManager::answered_ping, set_active_addr, answered
    /// A peer answered on one link has said nothing on the next: until it
    /// answers there, `alive` false is silence, not a refusal (#115).
    #[test]
    fn an_answer_is_forgotten_with_the_link_it_came_on() {
        let m = ClientManager::default();
        let h = m.add_client();
        let addr = "192.0.2.1:4242".parse().expect("addr");
        m.set_active_addr(h, Some(addr));
        assert!(!m.answered(h), "a link nobody has answered on yet");

        m.answered_ping(h, false);
        assert!(m.answered(h), "the peer answered a ping");
        assert_eq!(m.get_state(h).map(|(_, s)| s.alive), Some(false));

        m.set_active_addr(h, None);
        m.set_active_addr(h, Some(addr));
        assert!(
            !m.answered(h),
            "an answer given on a link that went down was kept for the next one"
        );
    }

    #[test]
    fn an_unknown_handle_is_not_a_change() {
        let m = ClientManager::default();
        assert!(
            !m.set_alive(9999, true),
            "a handle that does not exist changed nothing; republishing it \
             would emit NoSuchClient at the pong rate"
        );
    }
}

#[cfg(test)]
mod handles_are_never_reused {
    //! A handle names one device for as long as the daemon runs (#97).
    //!
    //! Async work holds a handle across an await: a dial reads the device's
    //! address, waits for the handshake, then writes what it learned back
    //! through the handle. If a freed handle is handed to the next device, that
    //! late write lands on a different machine's entry.

    use super::*;

    // LEDGER T1 | class B | 6 struct state: ClientManager::add_client, remove_client, set_peer_fingerprint, set_active_addr
    #[test]
    fn a_write_through_a_removed_handle_changes_no_other_device() {
        let m = ClientManager::default();
        let deleted = m.add_client();
        assert!(m.remove_client(deleted).is_some(), "precondition");
        let added = m.add_client();

        // A dial for the deleted device finishing late.
        m.set_peer_fingerprint(deleted, Some("aa".repeat(32)));
        m.set_active_addr(deleted, Some("192.0.2.1:4242".parse().expect("addr")));

        let (_, s) = m.get_state(added).expect("the added device");
        assert_eq!(
            (added == deleted, s.peer_fingerprint, s.active_addr),
            (false, None, None),
            "(the handle was reused, pin, address) of a device added after \
             another was deleted. A reused handle lets a late write for the \
             deleted device land on the new one."
        );
    }
}

#[cfg(test)]
mod the_switch_gates_clipboard_by_fingerprint {
    //! Off means off (#218): no clipboard moves to or from a machine a device
    //! pinned to it is switched off for. These ask the one function both
    //! directions ask; `clipboard::clipboard_follows_the_switch` watches the
    //! text itself.

    use super::*;

    const A: &str = "aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa";
    const B: &str = "bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb";

    fn device(m: &ClientManager, pin: Option<&str>, on: bool) -> ClientHandle {
        m.add_with_config(ConfigClient {
            ips: HashSet::new(),
            hostname: None,
            port: hops_ipc::DEFAULT_PORT,
            pos: Position::default(),
            active: on,
            enter_hook: None,
            fingerprint: pin.map(str::to_string),
        })
    }

    // LEDGER T2180 | class B | 1 return value: ClientManager::switch_allows_clipboard
    #[test]
    fn a_machine_switched_off_under_any_of_its_entries_gets_no_clipboard() {
        let m = ClientManager::default();
        let a = device(&m, Some(A), true);
        device(&m, Some(B), true);
        assert!(
            m.switch_allows_clipboard(A, None) && m.switch_allows_clipboard(B, None),
            "a device that is on stopped clipboard"
        );

        m.deactivate_client(a);
        assert_eq!(
            (
                m.switch_allows_clipboard(A, None),
                m.switch_allows_clipboard(B, None)
            ),
            (false, true),
            "(switched off, still on): switching one device off must stop its \
             clipboard and only its"
        );

        // A second entry for the same machine, switched on, does not reopen it.
        device(&m, Some(A), true);
        assert!(
            !m.switch_allows_clipboard(A, None),
            "one entry for a machine is on and another is off, and clipboard \
             flowed: off has to fail closed"
        );

        // A device with no pin names no machine, except over a link dialled
        // for it: an edit that cleared its pin left that link up.
        const C: &str = "cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc";
        let unpinned = device(&m, None, false);
        m.activate_client(a);
        assert!(
            m.switch_allows_clipboard(A, None) && m.switch_allows_clipboard(A, Some(a)),
            "switching the device back on left its clipboard stopped"
        );
        assert!(
            m.switch_allows_clipboard(C, None),
            "a device with no pin, switched off, stopped clipboard with a machine \
             no device names"
        );
        assert!(
            !m.switch_allows_clipboard(C, Some(unpinned)),
            "clipboard moved over a link dialled for a device that is switched \
             off, because the device had lost its pin"
        );
        m.remove_client(unpinned);
        assert!(
            !m.switch_allows_clipboard(C, Some(unpinned)),
            "clipboard moved over a link dialled for a device that is gone"
        );
    }
}

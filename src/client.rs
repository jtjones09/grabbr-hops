use std::{
    cell::RefCell,
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

use slab::Slab;

use hops_ipc::{ClientConfig, ClientHandle, ClientState, Geometry, Position};

use crate::config::ConfigClient;

#[derive(Clone, Default)]
pub struct ClientManager {
    clients: Rc<RefCell<Slab<(ClientConfig, ClientState)>>>,
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
        self.clients.borrow_mut().insert(Default::default()) as ClientHandle
    }

    /// set the config of the given client
    pub fn set_config(&self, handle: ClientHandle, config: ClientConfig) {
        if let Some((c, _)) = self.clients.borrow_mut().get_mut(handle as usize) {
            *c = config;
        }
    }

    /// set the state of the given client
    pub fn set_state(&self, handle: ClientHandle, state: ClientState) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
            *s = state;
        }
    }

    /// activate the given client
    /// returns, whether the client was activated
    pub fn activate_client(&self, handle: ClientHandle) -> bool {
        let mut clients = self.clients.borrow_mut();
        match clients.get_mut(handle as usize) {
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
        match clients.get_mut(handle as usize) {
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
            .find_map(|(k, (_, s))| {
                if s.active && s.ips.contains(&addr.ip()) {
                    Some(k)
                } else {
                    None
                }
            })
            .map(|p| p as ClientHandle)
    }

    /// get the client at the given position
    pub fn client_at(&self, pos: Position) -> Option<ClientHandle> {
        self.clients
            .borrow()
            .iter()
            .find_map(|(k, (c, s))| {
                if s.active && c.pos == pos {
                    Some(k)
                } else {
                    None
                }
            })
            .map(|p| p as ClientHandle)
    }

    pub(crate) fn get_hostname(&self, handle: ClientHandle) -> Option<String> {
        self.clients
            .borrow_mut()
            .get_mut(handle as usize)
            .and_then(|(c, _)| c.hostname.clone())
    }

    /// get the position of the corresponding client
    pub(crate) fn get_pos(&self, handle: ClientHandle) -> Option<Position> {
        self.clients
            .borrow()
            .get(handle as usize)
            .map(|(c, _)| c.pos)
    }

    /// remove a client from the list
    pub fn remove_client(&self, client: ClientHandle) -> Option<(ClientConfig, ClientState)> {
        // remove id from occupied ids
        self.clients.borrow_mut().try_remove(client as usize)
    }

    /// get the config & state of the given client
    pub fn get_state(&self, handle: ClientHandle) -> Option<(ClientConfig, ClientState)> {
        self.clients.borrow().get(handle as usize).cloned()
    }

    /// get the current config & state of all clients
    pub fn get_client_states(&self) -> Vec<(ClientHandle, ClientConfig, ClientState)> {
        self.clients
            .borrow()
            .iter()
            .map(|(k, v)| (k as ClientHandle, v.0.clone(), v.1.clone()))
            .collect()
    }

    /// update the fix ips of the client
    pub fn set_fix_ips(&self, handle: ClientHandle, fix_ips: Vec<IpAddr>) {
        if let Some((c, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
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
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
            s.dns_ips = dns_ips
        }
        self.update_ips(handle);
    }

    fn update_ips(&self, handle: ClientHandle) {
        if let Some((c, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
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
        let Some((c, s)) = clients.get_mut(handle as usize) else {
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
        match self.clients.borrow_mut().get_mut(handle as usize) {
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
        match self.clients.borrow_mut().get_mut(handle as usize) {
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
        if let Some((c, _s)) = self.clients.borrow_mut().get_mut(handle as usize) {
            c.geometry = geometry;
        }
    }

    /// set resolving status of the client
    pub(crate) fn set_resolving(&self, handle: ClientHandle, status: bool) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
            s.resolving = status;
        }
    }

    /// get the enter hook command
    pub(crate) fn get_enter_cmd(&self, handle: ClientHandle) -> Option<String> {
        self.clients
            .borrow()
            .get(handle as usize)
            .and_then(|(c, _)| c.cmd.clone())
    }

    /// returns all clients that are currently registered
    /// Reset handle allocation so the next `add_client` hands out 0 again.
    ///
    /// `Slab` reuses freed keys from a LIFO free list, so removing 0,1,2 and
    /// re-inserting three clients hands back 2,1,0 — a config reload REVERSED
    /// the device numbering, and reversed it back on the next reload, so it was
    /// wrong roughly half the time forever (#94). Every destructive verb is
    /// keyed by handle and `Delete` tombstones the fingerprint irreversibly, so
    /// a frontend that armed "delete handle 0" before a reload aimed it at a
    /// different machine after one, silently.
    ///
    /// `clear()` resets the free-list head as well as the contents, which makes
    /// the next allocations 0,1,2… in insertion order. Called only from the
    /// reload path, after every client has already been removed through the
    /// normal teardown — this changes the NUMBERING, not the lifecycle.
    pub(crate) fn reset_handle_allocation(&self) {
        let mut clients = self.clients.borrow_mut();
        debug_assert!(
            clients.is_empty(),
            "reset_handle_allocation drops any remaining clients without tearing \
             them down; remove them first"
        );
        clients.clear();
    }

    pub(crate) fn registered_clients(&self) -> Vec<ClientHandle> {
        self.clients
            .borrow()
            .iter()
            .map(|(h, _)| h as ClientHandle)
            .collect()
    }

    /// returns all clients that are currently active
    pub(crate) fn active_clients(&self) -> Vec<ClientHandle> {
        self.clients
            .borrow()
            .iter()
            .filter(|(_, (_, s))| s.active)
            .map(|(h, _)| h as ClientHandle)
            .collect()
    }

    pub(crate) fn set_active_addr(&self, handle: ClientHandle, addr: Option<SocketAddr>) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
            s.active_addr = addr;
        }
    }

    pub(crate) fn set_alive(&self, handle: ClientHandle, alive: bool) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
            s.alive = alive;
        }
    }

    pub(crate) fn set_peer_commit(&self, handle: ClientHandle, commit: Option<[u8; 8]>) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
            s.peer_commit = commit;
        }
    }

    pub(crate) fn set_peer_caps(&self, handle: ClientHandle, caps: Option<u32>) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
            s.peer_caps = caps;
        }
    }

    pub(crate) fn set_peer_fingerprint(&self, handle: ClientHandle, fingerprint: Option<String>) {
        if let Some((_, s)) = self.clients.borrow_mut().get_mut(handle as usize) {
            s.peer_fingerprint = fingerprint;
        }
    }

    /// The receiver's last-known leaf-cert fingerprint for this client
    /// (process-local; learned at handshake, not persisted), or `None` if it has
    /// never connected this run or the target address / trust changed since.
    /// Used to pin the outbound dial (fail closed).
    pub(crate) fn peer_fingerprint(&self, handle: ClientHandle) -> Option<String> {
        self.clients
            .borrow()
            .get(handle as usize)
            .and_then(|(_, s)| s.peer_fingerprint.clone())
    }

    /// Clear the pin on any client currently pinned to `fingerprint`, so its
    /// next dial re-learns identity. Called when trust in that fingerprint is
    /// revoked (`remove_authorized_key`) — e.g. a receiver re-keyed on reinstall
    /// and the operator authorized the new key.
    /// Handles whose last-known receiver identity is `fingerprint`. Must be
    /// called BEFORE `clear_pins_matching`, which erases what this matches on.
    pub(crate) fn handles_with_fingerprint(&self, fingerprint: &str) -> Vec<ClientHandle> {
        self.clients
            .borrow()
            .iter()
            .filter(|(_, (_, s))| s.peer_fingerprint.as_deref() == Some(fingerprint))
            .map(|(h, _)| h as ClientHandle)
            .collect()
    }

    /// Returns the handles whose pin was cleared, so the caller can republish
    /// them — otherwise the frontend keeps rendering a fingerprint the daemon
    /// has already dropped.
    pub(crate) fn clear_pins_matching(&self, fingerprint: &str) -> Vec<ClientHandle> {
        let mut cleared = vec![];
        for (h, (_, s)) in self.clients.borrow_mut().iter_mut() {
            if s.peer_fingerprint.as_deref() == Some(fingerprint) {
                s.peer_fingerprint = None;
                cleared.push(h as ClientHandle);
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
            .get(handle as usize)
            .and_then(|(_, s)| s.peer_caps)
            .unwrap_or(0)
    }

    pub(crate) fn active_addr(&self, handle: ClientHandle) -> Option<SocketAddr> {
        self.clients
            .borrow()
            .get(handle as usize)
            .and_then(|(_, s)| s.active_addr)
    }

    pub(crate) fn alive(&self, handle: ClientHandle) -> bool {
        self.clients
            .borrow()
            .get(handle as usize)
            .map(|(_, s)| s.alive)
            .unwrap_or(false)
    }

    pub(crate) fn get_port(&self, handle: ClientHandle) -> Option<u16> {
        self.clients
            .borrow()
            .get(handle as usize)
            .map(|(c, _)| c.port)
    }

    pub(crate) fn get_ips(&self, handle: ClientHandle) -> Option<HashSet<IpAddr>> {
        self.clients
            .borrow()
            .get(handle as usize)
            .map(|(_, s)| s.ips.clone())
    }
}

#[cfg(test)]
mod reload_permutation {
    //! A config reload must not renumber the devices.
    //!
    //! #94: `handle_config_change` removes every client and re-adds them from
    //! the config file. `Slab`'s free list is LIFO, so removing 0,1,2 and
    //! re-inserting three entries hands back 2,1,0 — the mapping is **reversed**,
    //! and because it reverses again on the next reload it is wrong roughly half
    //! the time, forever, rather than settling.
    //!
    //! That matters because every destructive verb in `FrontendRequest` is keyed
    //! by handle, and `Delete` now tombstones the fingerprint irreversibly. A
    //! frontend that armed "delete device 0" before a reload aims it at a
    //! different machine after one, with no warning logged.
    //!
    //! An external write to `config.toml` is the reachable trigger — a hand
    //! edit, an editor save, a synced home directory. hops' own saves unwatch
    //! first, so they do not fire it.

    use super::*;

    fn mapping(m: &ClientManager) -> Vec<(ClientHandle, Option<String>)> {
        let mut v: Vec<_> = m
            .registered_clients()
            .into_iter()
            .map(|h| (h, m.get_state(h).and_then(|(c, _)| c.hostname)))
            .collect();
        v.sort_by_key(|(h, _)| *h);
        v
    }

    fn seed(m: &ClientManager, names: &[&str]) {
        for n in names {
            let h = m.add_client();
            m.set_config(
                h,
                ClientConfig {
                    hostname: Some((*n).to_string()),
                    ..Default::default()
                },
            );
        }
    }

    /// Exactly what `handle_config_change` does: drop every client, then re-add
    /// them in config-file order (which is slab-ascending, since `save_config`
    /// writes `clients()` in that order).
    fn reload(m: &ClientManager) {
        let names: Vec<Option<String>> = m
            .registered_clients()
            .into_iter()
            .map(|h| m.get_state(h).and_then(|(c, _)| c.hostname))
            .collect();
        for h in m.registered_clients() {
            m.remove_client(h);
        }
        m.reset_handle_allocation();
        for n in names {
            let h = m.add_client();
            m.set_config(
                h,
                ClientConfig {
                    hostname: n,
                    ..Default::default()
                },
            );
        }
    }

    #[test]
    fn a_reload_does_not_renumber_the_devices() {
        let m = ClientManager::default();
        seed(&m, &["A", "B", "C"]);
        let before = mapping(&m);
        reload(&m);
        assert_eq!(
            mapping(&m),
            before,
            "a config reload renumbered the devices. Every destructive verb is \
             keyed by handle and Delete tombstones irreversibly, so a frontend \
             that armed \"delete handle 0\" before the reload now aims it at a \
             different machine (#94)."
        );
    }

    /// And it must not alternate. "It stabilises after two reloads" would still
    /// be wrong half the time; the point is that it never moves at all.
    #[test]
    fn repeated_reloads_do_not_alternate() {
        let m = ClientManager::default();
        seed(&m, &["A", "B", "C", "D"]);
        let before = mapping(&m);
        for i in 1..=4 {
            reload(&m);
            assert_eq!(mapping(&m), before, "mapping moved on reload {i}");
        }
    }
}

//! Find other hops machines on the local network, and be findable.
//!
//! Adding a device meant typing an IP address. That is the *hardest* rung of
//! the pairing ladder, and it was the only one — the easiest path should be
//! "the machine is already in a list, click it" (#136).
//!
//! # The fingerprint in the TXT record is a CLAIM, not an identity
//!
//! Anything on the LAN can advertise `_hops._udp.local.` with any fingerprint
//! it likes, including one it copied from a real machine. Nothing here is
//! authenticated and nothing here grants anything. A discovered peer is a
//! **suggestion of an address to dial**, no more.
//!
//! Identity is still decided exactly where it was before: the TLS leaf
//! certificate presented during the QUIC handshake, checked against the
//! allowlist in `listen.rs` and `connect.rs`. The claimed fingerprint is useful
//! for two honest things — labelling a row before we have ever connected, and
//! hiding machines already paired — and for one security check: if the
//! certificate a machine actually presents differs from the one it advertised,
//! something is wrong and the user should be told rather than quietly dialled.
//!
//! So: never write a claimed fingerprint into the allowlist, never use it to
//! skip an approval, and never let it be the reason a connection is trusted.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use local_channel::mpsc::{Receiver, Sender, channel};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::task::{JoinHandle, spawn_local};
use tokio_util::sync::CancellationToken;

/// The DNS-SD service type. `_udp` because the transport is QUIC.
const SERVICE_TYPE: &str = "_hops._udp.local.";
/// TXT key carrying the advertised certificate fingerprint (a claim).
const TXT_FINGERPRINT: &str = "fp";
/// TXT key carrying the wire-protocol version, so a future incompatible hops
/// can be filtered out of the list instead of failing confusingly on dial.
const TXT_VERSION: &str = "v";
const PROTOCOL_VERSION: &str = "1";

/// A machine seen on the local network. Not trusted, not verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// The fingerprint it CLAIMS, from its TXT record. Unauthenticated — see
    /// the module docs. Never a basis for trust.
    pub claimed_fingerprint: Option<String>,
    /// Its advertised instance name, for display only.
    pub label: String,
    /// Addresses to try. hops already dials several addresses for one device
    /// and reconciles the identities that answer, so handing it more than one
    /// is the normal case rather than a special one.
    pub addrs: Vec<SocketAddr>,
}

pub enum DiscoveryEvent {
    /// A peer appeared, or its record changed.
    Found(DiscoveredPeer),
    /// A peer stopped advertising. Carries the instance label it was listed by.
    Lost(String),
}

pub struct Discovery {
    cancellation_token: CancellationToken,
    task: Option<JoinHandle<()>>,
    event_rx: Receiver<DiscoveryEvent>,
    /// Held so the responder keeps advertising for as long as we run; dropping
    /// the daemon withdraws the advertisement.
    daemon: Option<ServiceDaemon>,
}

impl Discovery {
    /// Start advertising and browsing. `fingerprint` is our own leaf-cert
    /// fingerprint, advertised so peers can label us and detect a mismatch.
    ///
    /// Returns `Ok(None)` when discovery is switched off in config, so the
    /// caller has one branch rather than an Option-of-Result.
    pub fn new(enabled: bool, port: u16, fingerprint: &str, instance: &str) -> Option<Self> {
        if !enabled {
            log::info!(
                "network discovery is off (discovery = false); devices must be added by address"
            );
            return None;
        }
        let daemon = match ServiceDaemon::new() {
            Ok(d) => d,
            Err(e) => {
                // Not fatal. Discovery is a convenience; typing an address still
                // works, and a KVM that refuses to start because mDNS is
                // unavailable would be worse than one that is merely harder to
                // set up.
                log::warn!(
                    "could not start network discovery ({e}) — hops still works, \
                     but devices must be added by address"
                );
                return None;
            }
        };

        let addrs = local_addresses();
        if addrs.is_empty() {
            log::warn!("no local addresses to advertise — discovery will browse but not announce");
        }
        let props = [
            (TXT_FINGERPRINT, fingerprint),
            (TXT_VERSION, PROTOCOL_VERSION),
        ];
        match ServiceInfo::new(
            SERVICE_TYPE,
            instance,
            &format!("{instance}.local."),
            &addrs[..],
            port,
            &props[..],
        ) {
            Ok(info) => match daemon.register(info) {
                Ok(()) => log::info!(
                    "announcing this machine on the local network as {instance:?} \
                     ({} address(es), port {port})",
                    addrs.len()
                ),
                Err(e) => log::warn!("could not announce on the local network: {e}"),
            },
            Err(e) => log::warn!("could not build the network announcement: {e}"),
        }

        let browse = match daemon.browse(SERVICE_TYPE) {
            Ok(rx) => rx,
            Err(e) => {
                log::warn!("could not browse the local network: {e}");
                return None;
            }
        };

        let (event_tx, event_rx) = channel();
        let cancellation_token = CancellationToken::new();
        let token = cancellation_token.clone();
        let ours = fingerprint.to_lowercase();
        let task = Some(spawn_local(async move {
            tokio::select! {
                _ = pump(browse, event_tx, ours) => {},
                _ = token.cancelled() => {},
            }
        }));

        Some(Self {
            cancellation_token,
            task,
            event_rx,
            daemon: Some(daemon),
        })
    }

    pub async fn event(&mut self) -> Option<DiscoveryEvent> {
        self.event_rx.recv().await
    }

    pub async fn terminate(&mut self) {
        self.cancellation_token.cancel();
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
        // Withdraw the advertisement rather than leaving a stale record for
        // peers to dial after we are gone.
        if let Some(d) = self.daemon.take() {
            let _ = d.shutdown();
        }
    }
}

/// Forward resolved services into the service loop, skipping ourselves.
async fn pump(
    browse: mdns_sd::Receiver<ServiceEvent>,
    event_tx: Sender<DiscoveryEvent>,
    our_fingerprint: String,
) {
    while let Ok(event) = browse.recv_async().await {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let port = info.get_port();
                let announcement = Announcement {
                    fullname: info.get_fullname().to_string(),
                    claimed_fingerprint: info
                        .get_property_val_str(TXT_FINGERPRINT)
                        .map(String::from),
                    version: info.get_property_val_str(TXT_VERSION).map(String::from),
                    addrs: info
                        .get_addresses()
                        .iter()
                        .map(|a| SocketAddr::new(a.to_ip_addr(), port))
                        .collect(),
                };
                let Some(peer) = classify(announcement, &our_fingerprint) else {
                    continue;
                };
                if event_tx.send(DiscoveryEvent::Found(peer)).is_err() {
                    return;
                }
            }
            ServiceEvent::ServiceRemoved(_, fullname) => {
                if event_tx
                    .send(DiscoveryEvent::Lost(instance_label(&fullname)))
                    .is_err()
                {
                    return;
                }
            }
            _ => {}
        }
    }
}

/// What a peer put on the wire, before we decide what to make of it.
///
/// Split out from `pump` so the decisions below can be tested without a
/// network — the filtering is where the security-relevant judgement lives, and
/// a test that needs multicast would not run in CI.
#[derive(Debug, Clone)]
pub(crate) struct Announcement {
    pub(crate) fullname: String,
    pub claimed_fingerprint: Option<String>,
    pub(crate) version: Option<String>,
    pub addrs: Vec<SocketAddr>,
}

/// Decide whether an announcement is a peer worth showing.
///
/// Returns `None` for our own echo, an incompatible protocol version, or an
/// announcement with nowhere to dial. Note what is NOT filtered here: an
/// unknown or duplicated fingerprint is still shown, because this list is
/// "addresses you could try", and hiding a machine because it claims someone
/// else's fingerprint would hide the very case worth seeing.
pub(crate) fn classify(a: Announcement, our_fingerprint: &str) -> Option<DiscoveredPeer> {
    let claimed = a.claimed_fingerprint.map(|f| f.trim().to_lowercase());
    // Our own announcement comes back to us; it is not a peer.
    if claimed.as_deref() == Some(our_fingerprint) {
        return None;
    }
    if a.version.as_deref() != Some(PROTOCOL_VERSION) {
        log::debug!(
            "ignoring {} — it announces protocol version {:?}, we speak {PROTOCOL_VERSION}",
            a.fullname,
            a.version
        );
        return None;
    }
    if a.addrs.is_empty() {
        return None;
    }
    Some(DiscoveredPeer {
        claimed_fingerprint: claimed,
        label: instance_label(&a.fullname),
        addrs: a.addrs,
    })
}

/// The key a discovered peer is filed under.
///
/// The **claimed fingerprint** when there is one, not the label. mDNS renames
/// on conflict — announcing from several interfaces produced `peer-alpha` and
/// `peer-alpha (2)` for one machine on this rig — so keying by label lists the
/// same machine twice. The claim is unauthenticated, but it is only being used
/// to group rows; the worst case is two machines that claim the same
/// fingerprint sharing a row, which is a thing worth seeing anyway.
pub fn peer_key(p: &DiscoveredPeer) -> String {
    p.claimed_fingerprint
        .clone()
        .unwrap_or_else(|| p.label.clone())
}

/// Fold a new announcement into what we already knew.
///
/// Announcements arrive **per interface and piecemeal**: on this rig one peer
/// was reported five times with different subsets of its addresses in
/// different orders. Replacing wholesale made the list flicker and lose
/// addresses; comparing unsorted vectors reported a change every time. So
/// addresses are unioned and sorted, and the label prefers the form without
/// mDNS's ` (N)` conflict suffix.
///
/// Returns `true` if anything actually changed, so a re-announcement that
/// tells us nothing new does not wake the frontend.
pub fn merge(into: &mut DiscoveredPeer, new: DiscoveredPeer) -> bool {
    let before = into.clone();
    for a in new.addrs {
        if !into.addrs.contains(&a) {
            into.addrs.push(a);
        }
    }
    into.addrs.sort();
    // Prefer the un-suffixed name: mDNS appends " (2)", " (3)" on conflict.
    if new.label.len() < into.label.len() {
        into.label = new.label;
    }
    if into.claimed_fingerprint.is_none() {
        into.claimed_fingerprint = new.claimed_fingerprint;
    }
    *into != before
}

/// `studio-pc._hops._udp.local.` -> `studio-pc`.
///
/// Kept as a free function so it can be tested without a network.
pub(crate) fn instance_label(fullname: &str) -> String {
    fullname
        .split_once(&format!(".{SERVICE_TYPE}"))
        .map(|(name, _)| name)
        .unwrap_or(fullname)
        .to_string()
}

/// Every non-loopback local address.
///
/// Deliberately not "the best" address: hops already dials several addresses
/// for one device and reconciles which identity answers, and on this rig a
/// single machine legitimately has three (two LAN subnets plus a tunnel).
/// Choosing one here would be guessing which the peer can reach.
fn local_addresses() -> Vec<IpAddr> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut seen = HashMap::new();
    for i in ifaces {
        if i.is_loopback() {
            continue;
        }
        seen.insert(i.ip(), ());
    }
    seen.into_keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = "aa:bb:cc";

    fn ann(fp: Option<&str>, version: Option<&str>, addrs: &[&str]) -> Announcement {
        Announcement {
            fullname: format!("studio-pc.{SERVICE_TYPE}"),
            claimed_fingerprint: fp.map(String::from),
            version: version.map(String::from),
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn a_peer_becomes_a_row() {
        let p = classify(ann(Some("11:22:33"), Some("1"), &["10.0.0.5:4242"]), OURS)
            .expect("a well-formed peer must be listed");
        assert_eq!(
            p.label, "studio-pc",
            "the service suffix is not part of a name"
        );
        assert_eq!(p.claimed_fingerprint.as_deref(), Some("11:22:33"));
        assert_eq!(p.addrs.len(), 1);
    }

    /// Our own announcement comes back to us on every interface. Listing
    /// ourselves as a device to add would be the first thing anyone noticed.
    #[test]
    fn we_are_not_our_own_peer() {
        assert!(classify(ann(Some(OURS), Some("1"), &["10.0.0.5:4242"]), OURS).is_none());
    }

    /// Fingerprints are compared lowercase everywhere else in hops for exactly
    /// this reason (#67/#100); an uppercase echo of ourselves is still us.
    #[test]
    fn our_own_echo_is_recognised_in_any_case() {
        assert!(
            classify(ann(Some("AA:BB:CC"), Some("1"), &["10.0.0.5:4242"]), OURS).is_none(),
            "an uppercased echo of our own fingerprint must still be recognised as us"
        );
    }

    /// A future hops with an incompatible wire format should not appear as
    /// something to click — dialling it would fail confusingly.
    #[test]
    fn an_incompatible_version_is_not_offered() {
        assert!(classify(ann(Some("11:22:33"), Some("2"), &["10.0.0.5:4242"]), OURS).is_none());
        assert!(
            classify(ann(Some("11:22:33"), None, &["10.0.0.5:4242"]), OURS).is_none(),
            "something advertising our service type with no version is not us"
        );
    }

    #[test]
    fn an_announcement_with_nowhere_to_dial_is_dropped() {
        assert!(classify(ann(Some("11:22:33"), Some("1"), &[]), OURS).is_none());
    }

    /// Deliberate: a machine claiming a fingerprint we already know, or none at
    /// all, is STILL listed. This list means "addresses you could try", and
    /// suppressing a duplicate claim would hide the one case a user most needs
    /// to see. The claim grants nothing either way — trust is the TLS leaf.
    #[test]
    fn a_missing_or_duplicated_claim_is_still_listed() {
        assert!(classify(ann(None, Some("1"), &["10.0.0.5:4242"]), OURS).is_some());
        let twin = classify(ann(Some("11:22:33"), Some("1"), &["10.0.0.9:4242"]), OURS);
        assert!(
            twin.is_some(),
            "a machine claiming another's fingerprint must be visible"
        );
    }

    fn peer(label: &str, fp: Option<&str>, addrs: &[&str]) -> DiscoveredPeer {
        DiscoveredPeer {
            claimed_fingerprint: fp.map(String::from),
            label: label.into(),
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    /// Observed on the rig: one machine announcing on several interfaces was
    /// renamed by mDNS to `peer-alpha` AND `peer-alpha (2)`, so a label-keyed
    /// list showed it twice.
    #[test]
    fn one_machine_on_several_interfaces_is_one_row() {
        let a = peer("peer-alpha", Some("aa:aa"), &["10.0.0.1:4242"]);
        let b = peer("peer-alpha (2)", Some("aa:aa"), &["10.0.0.2:4242"]);
        assert_eq!(
            peer_key(&a),
            peer_key(&b),
            "the same machine must share a key"
        );
    }

    /// Also observed: five announcements for one peer, each with a different
    /// subset of its addresses, in different orders. Addresses must accumulate
    /// rather than replace, or the list flickers and loses reachable routes.
    #[test]
    fn addresses_accumulate_across_announcements() {
        let mut known = peer("p", Some("aa:aa"), &["10.0.0.1:4242"]);
        assert!(merge(
            &mut known,
            peer("p", Some("aa:aa"), &["10.0.0.2:4242"])
        ));
        assert!(merge(
            &mut known,
            peer("p", Some("aa:aa"), &["172.16.0.9:4242"])
        ));
        assert_eq!(
            known.addrs.len(),
            3,
            "every route seen must be kept: {:?}",
            known.addrs
        );
    }

    /// The same set in a different order is not news. Without this the daemon
    /// republishes to the frontend on every mDNS re-announcement, forever.
    #[test]
    fn a_reannouncement_that_says_nothing_new_is_not_a_change() {
        let mut known = peer("p", Some("aa:aa"), &["10.0.0.1:4242", "10.0.0.2:4242"]);
        merge(&mut known, peer("p", Some("aa:aa"), &["10.0.0.1:4242"]));
        let repeat = peer("p", Some("aa:aa"), &["10.0.0.2:4242", "10.0.0.1:4242"]);
        assert!(
            !merge(&mut known, repeat),
            "the same addresses in a different order must not count as a change"
        );
    }

    #[test]
    fn the_unsuffixed_name_wins() {
        let mut known = peer("peer-alpha (2)", Some("aa:aa"), &["10.0.0.1:4242"]);
        merge(
            &mut known,
            peer("peer-alpha", Some("aa:aa"), &["10.0.0.1:4242"]),
        );
        assert_eq!(
            known.label, "peer-alpha",
            "mDNS's conflict suffix must not become the device's name"
        );
    }

    #[test]
    fn a_peer_with_no_claim_is_keyed_by_name() {
        assert_eq!(
            peer_key(&peer("nameless", None, &["10.0.0.1:4242"])),
            "nameless"
        );
    }

    #[test]
    fn a_name_without_the_service_suffix_survives_intact() {
        assert_eq!(instance_label("bare-name"), "bare-name");
    }
}

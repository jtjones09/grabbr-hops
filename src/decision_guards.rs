//! Guards for decisions this project has already made — and, three times now,
//! rebuilt anyway.
//!
//! # Why this file exists
//!
//! The decision record says *why* each rule holds. It has not been enough. The
//! restore path was built, objected to, answered, and built again; the second
//! time, the decision text had been read aloud in the same session, hours
//! before the code was written. Reading is not the mechanism. A test that fails
//! when the code drifts back is the mechanism.
//!
//! # The bar every guard here is held to
//!
//! * **It calls the code.** This repository already carries roughly fifty
//!   source-scanning tests, and they found none of the six defects the
//!   maintainer found by opening the app. A scan can show that one file says
//!   the right thing; it cannot show that two files agree, and two files
//!   disagreeing is this project's entire defect class. Where a scan is used it
//!   is because the invariant is genuinely about *shipped text* — a sentence in
//!   a doc comment, a string a user reads — and it says so at the call site.
//! * **It does not scan itself.** Every scan below runs over a file that is not
//!   this one. That is structural, not a convention: the needles live here and
//!   the haystacks live elsewhere, so a guard cannot satisfy itself the way
//!   `nothing_outside_the_named_doors_writes_the_allowlist` did.
//! * **Its name is the guarantee, written as a sentence**, so a failing test
//!   name states what broke without opening the file.
//! * **Its failure message explains the consequence.** The person reading it is
//!   deciding whether to delete the test.
//!
//! # Guards that are RED on purpose
//!
//! Some rules below are decided, binding, and not yet implemented. They are in
//! the pre-v0.14 block. Their guards are written against the intended
//! behaviour, not today's, and each failure message names the issue. Softening
//! one of them to match current code would convert a scheduled fix into a
//! silently accepted defect, which is the exact move the 2026-09-05 release
//! rule forbids. Marked `RED TODAY` in the doc comment.

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// Source-scanning helpers.
///
/// Used ONLY where an invariant is about text a human reads — a doc comment, a
/// user-facing string, a licence notice. Never as a stand-in for calling the
/// code. Every function here takes source belonging to some *other* file.
mod scan {
    /// Non-test source with `//` comments stripped.
    ///
    /// Splits on `\n#[cfg(test)]` — deliberately without a trailing newline in
    /// the pattern, because `include_str!` preserves CRLF on a Windows checkout
    /// and a `\n#[cfg(test)]\n` pattern silently matches nothing there, turning
    /// the guard into a scan of the whole file including its own tests.
    pub fn code_only(src: &str) -> String {
        without_comments(before_tests(src))
    }

    /// All of `src`, test modules included, with `//` comments stripped.
    pub fn without_comments(src: &str) -> String {
        src.lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn before_tests(src: &str) -> &str {
        src.split("\n#[cfg(test)]").next().unwrap_or(src)
    }

    /// `(line number, line)` for every line of `src` containing `needle`.
    /// 1-indexed, so the output pastes straight into an editor.
    pub fn hits<'a>(src: &'a str, needle: &str) -> Vec<(usize, &'a str)> {
        src.lines()
            .enumerate()
            .filter(|(_, l)| l.contains(needle))
            .map(|(i, l)| (i + 1, l.trim()))
            .collect()
    }

    /// The `fn` enclosing byte offset `at`.
    pub fn enclosing_fn(src: &str, at: usize) -> String {
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

    #[test]
    fn the_splitter_survives_a_windows_checkout() {
        let lf = "fn real() {}\n#[cfg(test)]\nmod t { fn fake() {} }";
        let crlf = "fn real() {}\r\n#[cfg(test)]\r\nmod t { fn fake() {} }";
        for (name, src) in [("lf", lf), ("crlf", crlf)] {
            assert!(
                !code_only(src).contains("fake"),
                "{name}: the test-module splitter let test source through. Every \
                 scan in this file would then be scanning assertions instead of \
                 product code, and would pass no matter what the product did."
            );
        }
    }
}

/// A canonical 32-byte fingerprint made of one repeated byte, for tests.
fn fp32(byte: u8) -> String {
    (0..32)
        .map(|_| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ---------------------------------------------------------------------------
// #130 — direction is per-grant, and an outbound approval is not an inbound one
// ---------------------------------------------------------------------------

mod a_grant_carries_only_the_direction_that_was_approved {
    //! **Decided 2026-09-05 (#130).** A trust grant produced by approving an
    //! outbound dial never admits that peer on the inbound accept path.
    //!
    //! **Why.** Approving "yes, that is the machine I meant to send my keyboard
    //! to" currently also grants that machine the right to type into this one.
    //! Nobody is asked the second question. One flat map was handed to both TLS
    //! verifiers; it shipped unchanged in v0.11 and v0.12, and the one-click
    //! discovery default raised the exposure with the last release. A KVM
    //! reaches every button in every application, so an over-grant here is an
    //! over-grant of everything.
    //!
    //! **Ancestry, so nobody re-derives the old shape in good faith.** The
    //! 2026-07-24 entry still states "one approval establishes trust in BOTH
    //! directions" as a goal. That clause is superseded. Trust is per-machine
    //! AND per-direction.
    //!
    //! **Amended 2026-09-26 (#220).** The direction is no longer taken from
    //! how the other machine arrived: the person approving chooses it on the
    //! card (this machine controls that one, that one controls this one, or
    //! both), and the lease records the choice as its origin, which the store
    //! checks. What stands from #130: nothing grants a direction nobody was
    //! asked about.

    use crate::trust::{Caps, Origin, TrustStore};

    use super::fp32;

    /// **RED TODAY (#130).**
    ///
    /// The store records the origin of every lease and the capabilities it
    /// carries, and it is the last place that can refuse a combination the user
    /// was never asked about. Today `issue_with_origin` accepts any pairing:
    /// the single production caller (`Service::add_authorized_key`) hardcodes
    /// `Caps::INBOUND` for both prompts, so approving an outbound dial mints
    /// `DRIVE_ME | CLIPBOARD_FROM` — inbound keyboard control of your machine.
    ///
    /// Do not soften this to match today's code. The direction split was built
    /// in the store and never wired to the door; this test is the wire.
    #[test]
    fn approving_our_own_dial_never_lets_that_machine_type_into_this_one() {
        let ours = fp32(0x01);
        let receiver = fp32(0x22);
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");

        // The approval a user gives to "connect out to that machine".
        let _ = store.issue_with_origin(
            &receiver,
            "the laptop I am sending my keyboard to",
            Caps::INBOUND,
            Origin::OutboundDial,
        );

        assert!(
            !store.may_drive_us(&receiver),
            "an OutboundDial approval minted the inbound right to drive this \
             machine (#130). The user consented to send their keyboard to that \
             box; they were never asked whether that box may type into theirs. \
             A KVM reaches sudo, the browser, and every MFA prompt, so this is \
             not a narrow over-grant. Fix the door, not this test: the grant \
             must derive its capabilities from the approval's origin."
        );
    }

    /// **RED TODAY (#130).** The mirror. An inbound knock that the user admits
    /// grants that peer the right to drive this machine — it does not grant
    /// this machine the right to drive it.
    #[test]
    fn admitting_an_inbound_knock_never_lets_us_start_driving_that_machine() {
        let ours = fp32(0x01);
        let stranger = fp32(0x33);
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");

        let _ = store.issue_with_origin(
            &stranger,
            "the box that knocked",
            Caps::OUTBOUND,
            Origin::Inbound,
        );

        assert!(
            !store.we_may_drive(&stranger),
            "an Inbound approval minted the outbound right to drive that peer \
             (#130). Direction is a capability, not a synonym for membership; \
             the two questions have different answers and different blast radii."
        );
    }

    /// The two tests above ask the store. This asks the grant the door makes
    /// (`Service::add_authorized_key` through `service::grant_for_attempt`).
    ///
    /// **Amended 2026-09-26 (#220).** The direction is what the person
    /// approving chose on the card, never how the other machine arrived:
    /// either attempt can be approved in any direction, and the lease drives
    /// in exactly that one, recorded as the origin the store checks. The
    /// clipboard is shared only on a yes, the way control goes (#182). An
    /// approval with no attempt behind it still grants nothing.
    // LEDGER T11 | class B | 1 return value + 6 struct state: service::grant_for_attempt, TrustStore::capabilities, TrustStore::lease
    #[test]
    fn the_grant_door_mints_the_direction_the_person_chose_and_nothing_without_an_attempt() {
        use crate::service::{GrantRefused, grant_for_attempt};
        use crate::trust::{drive_of, existing_pairing_clipboard};
        use hops_ipc::{AttemptOrigin, Controller};

        let peer = fp32(0x44);
        let fresh = || TrustStore::new(&fp32(0x01), 0).expect("our own fingerprint");

        let mut store = fresh();
        assert_eq!(
            grant_for_attempt(
                &mut store,
                &peer,
                "no prompt behind this",
                None,
                Controller::Both,
                true
            ),
            Err(GrantRefused::NoAttempt),
            "an approval with no pending attempt must be refused"
        );
        assert_eq!(
            store.capabilities(&peer),
            Caps::NONE,
            "and it must grant nothing"
        );

        for arrived in [AttemptOrigin::Inbound, AttemptOrigin::OutboundDial] {
            for chosen in Controller::ALL {
                for clipboard in [false, true] {
                    let mut store = fresh();
                    grant_for_attempt(&mut store, &peer, "desk", Some(arrived), chosen, clipboard)
                        .expect("grant");
                    assert_eq!(
                        store.capabilities(&peer),
                        Caps::NONE,
                        "an approval alone grants nothing until both machines confirm \
                         the number (#167)"
                    );
                    store.confirm(&peer).expect("confirm");
                    let drive = drive_of(chosen);
                    let shared = if clipboard {
                        existing_pairing_clipboard(drive)
                    } else {
                        Caps::NONE
                    };
                    assert_eq!(
                        (
                            store.capabilities(&peer),
                            store.lease(&peer).map(|l| l.origin)
                        ),
                        (drive | shared, Some(Origin::Chosen(chosen))),
                        "approving a {arrived:?} attempt as {chosen:?}, clipboard \
                         {clipboard}: the pairing grants something other than what the \
                         person chose, or does not record the choice. Which machine \
                         dialled says nothing about which way control goes (#220), and \
                         the clipboard is shared only on a yes (#182)."
                    );
                }
            }
        }
    }

    /// The store is the last place that can refuse a direction nobody chose,
    /// and it does at both of its doors: a grant, and a record replayed off
    /// disk (#220).
    // LEDGER T11b | class B | 1 error: TrustStore::issue_with_origin, TrustStore::admit
    #[test]
    fn a_lease_recorded_as_chosen_drives_in_exactly_that_direction() {
        use crate::trust::{Expiry, Lease, TrustError};
        use hops_ipc::Controller;

        let ours = fp32(0x01);
        let peer = fp32(0x45);
        for (chosen, caps) in [
            (Controller::ThisMachine, Caps::DRIVE_ME),
            (Controller::ThisMachine, Caps::DRIVE_ME | Caps::I_MAY_DRIVE),
            (Controller::ThatMachine, Caps::I_MAY_DRIVE),
            (Controller::Both, Caps::DRIVE_ME),
            (Controller::Both, Caps::CLIPBOARD_FROM),
        ] {
            let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");
            let granted = store.issue_with_origin(&peer, "desk", caps, Origin::Chosen(chosen));
            assert!(
                matches!(granted, Err(TrustError::NotAsChosen { .. })),
                "a grant recorded as {chosen:?} carrying {caps:?} was not refused: \
                 {granted:?}"
            );
            let replayed = store.admit(Lease {
                peer: peer.clone(),
                issued_to: ours.clone(),
                label: "desk".into(),
                caps,
                origin: Origin::Chosen(chosen),
                issued_at: 1,
                expiry: Expiry::Never,
                clipboard_chosen: true,
                confirmed: true,
            });
            assert!(
                matches!(replayed, Err(TrustError::NotAsChosen { .. })),
                "a record recorded as {chosen:?} carrying {caps:?} was loaded: {replayed:?}"
            );
            assert!(store.capabilities(&peer).is_empty());
        }
    }

    /// The property the two verifiers must keep, checked by calling both of
    /// them rather than by reading either one.
    ///
    /// This is the check a source scan structurally cannot make: it shows that
    /// `FpServerVerifier` and `FpClientVerifier` — two types, two call sites,
    /// two files — reach *opposite* answers from one store. A grep can show
    /// that `transport.rs` mentions `we_may_drive`; only this can show that the
    /// inbound door refuses what the outbound door allows.
    #[test]
    fn the_inbound_and_outbound_tls_doors_ask_genuinely_different_questions() {
        use crate::transport::{FpClientVerifier, FpServerVerifier};
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{ServerName, UnixTime};
        use rustls::server::danger::ClientCertVerifier;
        use std::sync::{Arc, Mutex, RwLock};

        crate::transport::install_crypto_provider();

        let peer = super::a_test_certificate();
        let peer_fp = crate::transport::fingerprint_of(&peer);
        let ours = fp32(0x01);

        // A receiver we confirmed our own dial reached: outbound only.
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");
        store
            .issue_confirmed(&peer_fp, "a receiver", Caps::OUTBOUND)
            .expect("issue an outbound-only lease");
        let trust = Arc::new(RwLock::new(store));

        let outbound = FpServerVerifier::new(trust.clone(), Arc::new(Mutex::new(None)));
        let inbound = FpClientVerifier::new(trust, Arc::new(Mutex::new(None)));
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));

        assert!(
            outbound
                .verify_server_cert(
                    &peer,
                    &[],
                    &ServerName::try_from("grabbr").expect("server name"),
                    &[],
                    now,
                )
                .is_ok(),
            "the OUTBOUND verifier refused a peer we hold a live outbound lease \
             on. Dialling a receiver we were told we may drive must succeed, or \
             pairing by typing an address stops working."
        );
        assert!(
            inbound.verify_client_cert(&peer, &[], now).is_err(),
            "the INBOUND verifier admitted a peer holding an OUTBOUND-only \
             lease. Both verifiers are reading the same question again, which \
             is the v0.11/v0.12 defect (#130) exactly: a machine you agreed to \
             send your keyboard to may now send its keyboard to you."
        );
    }
}

mod an_upgrade_mints_no_permission_the_old_config_never_granted {
    //! **Decided 2026-09-05 (#130).** The carried-forward over-grant retires at
    //! migration; the upgrade must not create a direction the user never gave.
    //!
    //! **Why.** `[authorized_fingerprints]` membership was *necessary and not
    //! sufficient* for outbound: a dial also needed a `[[clients]]` entry aimed
    //! at that peer. A fingerprint that was allowlisted and never a dial target
    //! held outbound permission in theory and never once in practice. Minting
    //! it at upgrade would be a capability the user never granted, created by
    //! the very code that claims to retire that defect.
    //!
    //! **What makes this urgent rather than theoretical.** Two migrations exist
    //! in this tree, they disagree, and the tested one is not the one that runs.

    use std::collections::{HashMap, HashSet};

    use crate::trust::{Caps, TrustStore, system_seconds};
    use crate::trust_file::rebuild;
    use hops_ipc::RevokedEntry;

    use super::fp32;

    /// Migration stamps `issued_at` from the caller and the store enforces
    /// expiry against `max(system clock, floor)`. A hardcoded timestamp is
    /// therefore a lease that has already lapsed by the time anyone runs this,
    /// and the guard then fails for the wrong reason — which is worse than not
    /// having it, because the message would name #130 for a clock problem.
    fn upgrading_now() -> u64 {
        system_seconds()
    }

    fn old_allowlist(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(fp, label)| ((*fp).to_string(), (*label).to_string()))
            .collect()
    }

    /// **RED TODAY (#130).**
    ///
    /// This was RED when written: the migration the daemon ran handed every
    /// carried-forward fingerprint both directions unconditionally, for four
    /// hundred days. That duplicate has been deleted and the daemon now
    /// migrates through the store.
    #[test]
    fn a_fingerprint_the_old_config_never_dialled_gets_no_outbound_permission() {
        let ours = fp32(0x01);
        let never_dialled = fp32(0x44);

        let now = upgrading_now();
        let mut migrated = TrustStore::new(&ours, 0).expect("our own fingerprint");
        migrated.migrate_from_config(
            &old_allowlist(&[(&never_dialled, "a box that only ever knocked")]),
            &HashMap::<String, RevokedEntry>::new(),
            &HashSet::new(),
            now,
        );
        // Through disk, because the round trip is where an upgrade actually
        // lands and where a widening would show up.
        let (store, refused) = rebuild(&ours, now, &crate::trust_file::records_of(&migrated))
            .expect("rebuild the migrated store");

        assert!(
            refused.is_empty(),
            "the migrated records did not survive their own rebuild: {refused:?}. \
             An upgrade that cannot load what it just wrote locks the user out."
        );
        assert!(
            store.may_drive_us(&never_dialled),
            "the upgrade dropped an inbound grant that was live yesterday. \
             Carrying inbound forward is the whole reason migration exists — \
             without it every paired machine silently stops working on upgrade."
        );
        assert!(
            !store.we_may_drive(&never_dialled),
            "the upgrade MINTED outbound permission for a fingerprint the old \
             config never dialled (#130). Old membership was necessary and not \
             sufficient for outbound — a dial also needed a [[clients]] entry — \
             so this is a capability the user never granted, created at upgrade \
             time by the code whose job is to retire exactly this defect. \
             Restricting to the dialled set is not a narrowing anyone can feel: \
             the mouse keeps crossing to precisely the machines it crossed to \
             yesterday."
        );
    }

    /// **RED TODAY (#130).** Two migrations, one rule.
    ///
    /// `TrustStore::migrate_from_config` gets this right and has zero
    /// production callers. `trust_file::migrate` gets it wrong and is the one
    /// the daemon runs. Their own tests pass in isolation, which is why nobody
    /// noticed: the guarded one is dead code.
    ///
    /// This asserts they AGREE, because "two files disagree and each is
    /// internally consistent" is the failure a per-file test can never see.
    /// The duplicate this guard was written to catch has since been deleted, so
    /// the assertion changed from "the two agree" to "the one that survives is
    /// the one with the rule". Kept rather than removed: the failure it guards
    /// against is a second migration reappearing, and a test named for the rule
    /// still fails if the surviving one starts granting outbound to everything.
    #[test]
    fn there_is_one_migration_and_it_grants_outbound_only_to_a_dialled_peer() {
        let ours = fp32(0x01);
        let dialled = fp32(0x55);
        let never_dialled = fp32(0x66);
        let now = upgrading_now();

        let authorized =
            old_allowlist(&[(&dialled, "the receiver"), (&never_dialled, "a knocker")]);
        let revoked = HashMap::<String, RevokedEntry>::new();

        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");
        let dial_targets: HashSet<String> = [dialled.clone()].into_iter().collect();
        store.migrate_from_config(&authorized, &revoked, &dial_targets, now);

        assert!(
            store.capabilities(&dialled).contains(Caps::I_MAY_DRIVE),
            "a fingerprint the old config actually dialled must keep outbound, \
             or the mouse stops crossing to a machine it crossed to yesterday"
        );
        assert!(
            !store
                .capabilities(&never_dialled)
                .contains(Caps::I_MAY_DRIVE),
            "a fingerprint that was allowlisted but never dialled must NOT get \
             outbound at upgrade. Allowlist membership was necessary and not \
             sufficient for a dial, so minting it now creates a capability the \
             user never granted, at upgrade, by the code that exists to retire \
             exactly that defect"
        );
        assert!(
            store.capabilities(&never_dialled).contains(Caps::DRIVE_ME),
            "it must still keep inbound, or an upgrade silently drops peers"
        );

        // The round trip through disk must not widen anything.
        let (reloaded, _) =
            rebuild(&ours, now, &crate::trust_file::records_of(&store)).expect("rebuild");
        for fp in [&dialled, &never_dialled] {
            assert_eq!(
                reloaded.capabilities(fp),
                store.capabilities(fp),
                "sealing and reloading changed what {fp} is permitted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// #186 — pairings made before #182 keep the clipboard direction their lease
// grants
// ---------------------------------------------------------------------------

mod pairings_made_before_182_keep_the_clipboard_direction_their_lease_grants {
    //! **Decided 2026-09-16 (#186).** A pairing made before #182 asks about the
    //! clipboard keeps what its lease already carries: text copied on the
    //! machine doing the driving reaches the machine being driven, and nothing
    //! flows the other way. Nothing on disk changes; enforcement starts
    //! reading bits that were already there.
    //!
    //! **Why not the alternatives.** Keeping both directions leaves a flow
    //! nobody granted. Switching it off for every existing pairing breaks
    //! working setups silently.
    //!
    //! The choice is one function, `trust::existing_pairing_clipboard`, which
    //! the on arm of the per-device switch also turns a clipboard back on by, and
    //! this runs both machines' real transports over loopback, so swapping the
    //! direction there fails here.

    use std::collections::{HashMap, HashSet};

    use hops_ipc::RevokedEntry;

    use crate::test_harness::{
        ARRIVES_WITHIN, Machine, NEVER_WITHIN, applied_within, clipboard_pair, machine, run_local,
    };
    use crate::trust::{Caps, TrustStore, existing_pairing_clipboard};
    use crate::trust_file::{
        DiskCap, DiskOrigin, DiskState, LeaseRecord, expiry_older_builds_accept, rebuild,
        records_of,
    };

    /// Through disk, as every start after the one that made the pairing
    /// loads it. The start that made it runs on the store in memory, so each
    /// pairing is checked both ways.
    fn reloaded(store: &TrustStore) -> TrustStore {
        let (loaded, refused) =
            rebuild(store.ours(), store.now(), &records_of(store)).expect("rebuild");
        assert!(
            refused.is_empty(),
            "the store refused its own records: {refused:?}"
        );
        loaded
    }

    /// Paired on a build with the trust store and before #182: each machine
    /// approved the other's prompt once, and the grant was shaped by how the
    /// other machine arrived, its clipboard following the drive bits, which
    /// is what such a build wrote. Nobody chose a clipboard.
    fn approved(driven: &Machine, driver: &Machine) -> (TrustStore, TrustStore) {
        let before_182 = |me: &Machine, peer: &Machine, drive: Caps| {
            let mut store = TrustStore::new(&me.fingerprint, 0).expect("ours");
            store
                .issue(
                    &peer.fingerprint,
                    "peer",
                    drive | existing_pairing_clipboard(drive),
                )
                .expect("grant");
            store.confirm(&peer.fingerprint).expect("confirm");
            store
        };
        (
            before_182(driven, driver, Caps::DRIVE_ME),
            before_182(driver, driven, Caps::I_MAY_DRIVE),
        )
    }

    /// Paired on v0.12, which kept one flat allowlist: each machine listed the
    /// other, and only the driver had a client entry dialling its peer.
    fn migrated(driven: &Machine, driver: &Machine) -> (TrustStore, TrustStore) {
        let migrate = |me: &Machine, peer: &Machine, dialled: bool| {
            let mut store = TrustStore::new(&me.fingerprint, 0).expect("ours");
            let authorized: HashMap<String, String> =
                [(peer.fingerprint.clone(), "peer".to_string())].into();
            let dialled: HashSet<String> = if dialled {
                [peer.fingerprint.clone()].into()
            } else {
                HashSet::new()
            };
            let now = store.now();
            store.migrate_from_config(
                &authorized,
                &HashMap::<String, RevokedEntry>::new(),
                &dialled,
                now,
            );
            store
        };
        (
            migrate(driven, driver, false),
            migrate(driver, driven, true),
        )
    }

    // LEDGER T1861 | class B | 1 return value: ClipboardInbox::next over the queue transport::clipboard_accept_loop fills; ClipboardSender::broadcast, ClipboardSenderListen::broadcast, grant_for_attempt, migrate_from_config, trust_file::rebuild
    #[test]
    fn existing_pairings_keep_their_clipboard_direction() {
        run_local(async {
            type Pairing = fn(&Machine, &Machine) -> (TrustStore, TrustStore);
            let pairings: [(&str, Pairing, bool); 4] = [
                ("approved, in the run that approved it", approved, false),
                ("approved, loaded at a later start", approved, true),
                (
                    "carried forward from a v0.12 config, in the upgrade's run",
                    migrated,
                    false,
                ),
                (
                    "carried forward from a v0.12 config, loaded at a later start",
                    migrated,
                    true,
                ),
            ];
            for (how, pair_up, reload) in pairings {
                let (driven, driver) = (machine(), machine());
                let (mut on_driven, mut on_driver) = pair_up(&driven, &driver);
                if reload {
                    (on_driven, on_driver) = (reloaded(&on_driven), reloaded(&on_driver));
                }
                let mut pair = clipboard_pair(driven, on_driven, driver, on_driver).await;
                // What each machine's service would apply, through the check
                // it makes first.
                let (mut on_driven, mut on_driver) = pair.inboxes();

                pair.driver_sends
                    .broadcast("copied on the driver".to_string())
                    .await;
                assert_eq!(
                    applied_within(&mut on_driven, ARRIVES_WITHIN)
                        .await
                        .as_deref(),
                    Some("copied on the driver"),
                    "{how}: text copied on the machine doing the driving no longer \
                     reaches the machine it drives. #186 keeps that direction for \
                     every existing pairing; losing it breaks a working setup with \
                     nothing on screen to explain it."
                );

                pair.driven_sends
                    .broadcast("copied on the driven machine".to_string())
                    .await;
                assert_eq!(
                    applied_within(&mut on_driver, NEVER_WITHIN)
                        .await
                        .as_deref(),
                    None,
                    "{how}: text copied on the machine being driven reached the \
                     machine driving it. Nobody granted that direction: the lease \
                     carries clipboard from the driver to the driven machine only, \
                     and #186 stops the reverse (issues #182, #186)."
                );
            }
        });
    }

    // LEDGER E2b-5 | class B | 1 return value: trust_file::rebuild, trust_file::records_of, TrustStore::capabilities
    /// A store an earlier build saved, each of its pairings made before #182:
    /// loaded by this build and saved again, every record is as it was, and
    /// each still grants the clipboard its drive bits did (#186). #220 and
    /// #182 change what a new pairing is, never what an old one holds.
    #[test]
    fn a_store_saved_before_182_loads_and_saves_unchanged() {
        let ours = machine().fingerprint;
        let issued_at = 1_780_000_000;
        let record = |origin: DiskOrigin, caps: Vec<DiskCap>| LeaseRecord {
            fingerprint: machine().fingerprint,
            label: format!("{origin:?}"),
            state: DiskState::Active,
            origin,
            issued_at,
            expires_at: Some(expiry_older_builds_accept(issued_at)),
            revoked_at: None,
            caps,
            confirmed: true,
            clipboard: None,
        };
        let mut saved = vec![
            record(DiskOrigin::Inbound, vec![DiskCap::Inbound]),
            record(DiskOrigin::OutboundDial, vec![DiskCap::Outbound]),
            record(
                DiskOrigin::Migrated,
                vec![DiskCap::Inbound, DiskCap::Outbound],
            ),
        ];
        saved.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let (store, refused) = rebuild(&ours, issued_at + 60, &saved).expect("rebuild");
        assert!(
            refused.is_empty(),
            "an older build's store was refused: {refused:?}"
        );
        let mut again = records_of(&store);
        again.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        assert_eq!(
            again, saved,
            "this build rewrote a pairing an older build saved. The upgrade writes \
             nothing new and rewrites no lease (#186)."
        );
        for r in &saved {
            let drive = r.caps.iter().fold(Caps::NONE, |acc, c| {
                acc | match c {
                    DiskCap::Inbound => Caps::DRIVE_ME,
                    DiskCap::Outbound => Caps::I_MAY_DRIVE,
                }
            });
            assert_eq!(
                store.capabilities(&r.fingerprint),
                drive | existing_pairing_clipboard(drive),
                "a pairing made before #182 ({:?}) lost, or gained, clipboard it held",
                r.origin
            );
        }
    }
}

// ---------------------------------------------------------------------------
// #183 — no pairing expires until renewal exists
// ---------------------------------------------------------------------------

mod no_pairing_expires_until_renewal_exists {
    //! **Decided 2026-09-16 (#183).** The 30-day lease term is dropped for this
    //! release. A pairing made today, and one already on disk with a term,
    //! keeps working until the user removes the device.
    //!
    //! **Why.** Nothing renews a lease yet, so a term was a date on which a
    //! working device stopped, with pairing again as the only way back.
    //!
    //! **Not settled by this.** How long trust should last is open (#185), and
    //! a permanent grant fails differently from a lapsing one. Choosing a term
    //! means changing `trust::DEFAULT_TERM`, `trust_file::rebuild` and the
    //! store schema together, and this guard with them, in the same commit.
    //!
    //! **A stored term needs a new schema, not only a changed `rebuild`.**
    //! Every `expires_at` in a store, version 1 or 2, is a placeholder and
    //! must never be enforced. This build writes 400 days after pairing for a
    //! lease that does not lapse, the date version 1 stores carried for a
    //! build from before #183, and nothing tells that date apart from a real
    //! 400-day term. A build that enforced it
    //! would end every pairing made under this build at day 400, the outage
    //! #183 removes. Enforcing a stored term (#185) takes a `SCHEMA_VERSION`
    //! bump or a new field.
    //!
    //! **Why the grant door is covered without building a `Service`.** The
    //! door (`Service::add_authorized_key`) makes its grant through
    //! `service::grant_for_attempt`, and this test grants through that call.
    //! It calls `TrustStore::issue`, which takes no term; the version that
    //! takes one is `cfg(test)`.
    //!
    //! **Why admission alone is not enough.** A door that checks nothing also
    //! admits a pairing ten years on. The sibling test shows each door still
    //! refuses a removed device and a lapsed term, so the admission here is the
    //! store's answer and not a door that stopped asking.
    //!
    //! Leases already sealed with a 30-day or 400-day term are covered by
    //! `trust_file`'s `a_sealed_store_holding_thirty_and_four_hundred_day_terms_…`.

    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Duration;

    use hops_ipc::AttemptOrigin;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::server::danger::ClientCertVerifier;

    use crate::service::grant_for_attempt;
    use crate::transport::{FpClientVerifier, FpServerVerifier};
    use crate::trust::{Caps, Term, TrustStore, system_seconds};

    const TEN_YEARS: u64 = 10 * 365 * 86_400;
    const HOUR: u64 = 3_600;

    /// The doors a live session passes besides the sweep.
    const DOORS: [&str; 3] = [
        "the inbound TLS verifier",
        "the outbound TLS verifier",
        "the per-event injection check",
    ];

    /// Which of [`DOORS`] let `peer` through right now: the inbound verifier
    /// and the injection check against `receiving`, the outbound verifier
    /// against `sending`.
    fn doors_that_admit(
        peer: &CertificateDer<'static>,
        receiving: &crate::transport::Trust,
        sending: &crate::transport::Trust,
    ) -> Vec<&'static str> {
        let peer_fp = crate::transport::fingerprint_of(peer);
        let mut admitted = Vec::new();
        let tls_now =
            UnixTime::since_unix_epoch(Duration::from_secs(receiving.read().expect("lock").now()));
        let inbound = FpClientVerifier::new(receiving.clone(), Arc::new(Mutex::new(None)));
        if inbound.verify_client_cert(peer, &[], tls_now).is_ok() {
            admitted.push(DOORS[0]);
        }
        let outbound = FpServerVerifier::new(sending.clone(), Arc::new(Mutex::new(None)));
        let name = ServerName::try_from("grabbr").expect("server name");
        if outbound
            .verify_server_cert(peer, &[], &name, &[], tls_now)
            .is_ok()
        {
            admitted.push(DOORS[1]);
        }
        let addr: SocketAddr = "192.0.2.7:4242".parse().expect("addr");
        let peer_of = HashMap::from([(addr, peer_fp)]);
        if crate::emulation::input_permitted(&peer_of, receiving, addr) {
            admitted.push(DOORS[2]);
        }
        admitted
    }

    /// Every door a live session passes, asked ten years after the pairing:
    /// the sweep on the daemon's timer, both TLS verifiers, and the check made
    /// on every injected input event.
    // LEDGER T1 | class B | 1 return value + 6 struct state: service::grant_for_attempt, TrustStore::sweep, FpClientVerifier, FpServerVerifier, emulation::input_permitted
    #[test]
    fn a_pairing_made_today_is_admitted_at_every_door_ten_years_on() {
        crate::transport::install_crypto_provider();
        let peer = super::a_test_certificate();
        let peer_fp = crate::transport::fingerprint_of(&peer);

        let mut receiving = TrustStore::new(&super::fp32(0x01), 0).expect("ours");
        grant_for_attempt(
            &mut receiving,
            &peer_fp,
            "a sender",
            Some(AttemptOrigin::Inbound),
            hops_ipc::Controller::ThatMachine,
            false,
        )
        .expect("the grant door grants an approved inbound attempt");
        let mut sending = TrustStore::new(&super::fp32(0x02), 0).expect("ours");
        grant_for_attempt(
            &mut sending,
            &peer_fp,
            "a receiver",
            Some(AttemptOrigin::OutboundDial),
            hops_ipc::Controller::ThisMachine,
            false,
        )
        .expect("the grant door grants an approved outbound dial");
        // and both machines confirmed the number (#167)
        receiving.confirm(&peer_fp).expect("confirm");
        sending.confirm(&peer_fp).expect("confirm");

        let mut refused = Vec::new();

        // What `Service::sweep_lapsed_leases` does on its timer. Whatever it
        // returns, the daemon cuts that peer's sessions.
        let later = system_seconds() + TEN_YEARS;
        for (side, store) in [("receiving", &mut receiving), ("sending", &mut sending)] {
            let lapsed = store.sweep(later);
            if !lapsed.is_empty() {
                refused.push(format!(
                    "the {side} sweep reported {} lapse(s)",
                    lapsed.len()
                ));
            }
            assert_eq!(
                store.now(),
                later,
                "precondition: the store is ten years on"
            );
        }
        let receiving = Arc::new(RwLock::new(receiving));
        let sending = Arc::new(RwLock::new(sending));

        let admitted = doors_that_admit(&peer, &receiving, &sending);
        for door in DOORS {
            if !admitted.contains(&door) {
                refused.push(format!("{door} refused the peer"));
            }
        }

        assert!(
            refused.is_empty(),
            "a pairing made today stopped working ten years on (#183):\n  {}\n\
             Nothing renews a lease yet, so a lapse is a working device that can \
             only come back by pairing again. If a term is being reintroduced, \
             that is #185, and it arrives with renewal — not as a constant \
             changed on its own.",
            refused.join("\n  ")
        );
    }

    /// Each door the ten-years-on test asks still refuses a removed device and
    /// a lapsed term. Without this, a door that stopped checking the store
    /// passes that test exactly as a correct one does.
    // LEDGER T10 | class B | 1 return value: emulation::input_permitted, FpClientVerifier::verify_client_cert, FpServerVerifier::verify_server_cert, TrustStore::sweep
    #[test]
    fn every_door_still_refuses_a_removed_device_and_a_lapsed_term() {
        crate::transport::install_crypto_provider();
        let peer = super::a_test_certificate();
        let peer_fp = crate::transport::fingerprint_of(&peer);
        let pair = |term: Option<Term>| {
            let mut receiving = TrustStore::new(&super::fp32(0x01), 0).expect("ours");
            let mut sending = TrustStore::new(&super::fp32(0x02), 0).expect("ours");
            match term {
                None => {
                    grant_for_attempt(
                        &mut receiving,
                        &peer_fp,
                        "a sender",
                        Some(AttemptOrigin::Inbound),
                        hops_ipc::Controller::ThatMachine,
                        false,
                    )
                    .expect("grant");
                    grant_for_attempt(
                        &mut sending,
                        &peer_fp,
                        "a receiver",
                        Some(AttemptOrigin::OutboundDial),
                        hops_ipc::Controller::ThisMachine,
                        false,
                    )
                    .expect("grant");
                    receiving.confirm(&peer_fp).expect("confirm");
                    sending.confirm(&peer_fp).expect("confirm");
                }
                Some(term) => {
                    receiving
                        .issue_with_term(&peer_fp, "a sender", Caps::INBOUND, term)
                        .expect("issue");
                    sending
                        .issue_with_term(&peer_fp, "a receiver", Caps::OUTBOUND, term)
                        .expect("issue");
                }
            }
            (receiving, sending)
        };
        let shared = |s: TrustStore| Arc::new(RwLock::new(s));

        // Removed.
        let (receiving, sending) = pair(None);
        let (receiving, sending) = (shared(receiving), shared(sending));
        assert_eq!(
            doors_that_admit(&peer, &receiving, &sending),
            DOORS,
            "precondition: a live pairing gets through every door"
        );
        receiving.write().expect("lock").forget(&peer_fp);
        sending.write().expect("lock").forget(&peer_fp);
        let admitted = doors_that_admit(&peer, &receiving, &sending);
        assert!(
            admitted.is_empty(),
            "a removed device still gets through {admitted:?}. Removal has to bite \
             at every door, the per-event check included, or a session opened \
             before the removal keeps typing into this machine."
        );

        // Lapsed. No production lease has a term (#183); the check that would
        // enforce one is kept for #185, so it is exercised with a test-only term.
        let (receiving, sending) = pair(Some(Term::Secs(HOUR)));
        let (receiving, sending) = (shared(receiving), shared(sending));
        assert_eq!(
            doors_that_admit(&peer, &receiving, &sending),
            DOORS,
            "precondition: a term still running gets through every door"
        );
        let later = system_seconds() + 2 * HOUR;
        for (side, store) in [("receiving", &receiving), ("sending", &sending)] {
            assert_eq!(
                store.write().expect("lock").sweep(later).len(),
                1,
                "the {side} sweep did not report the lapsed term, so the daemon \
                 would leave that peer's quiet session open"
            );
        }
        let admitted = doors_that_admit(&peer, &receiving, &sending);
        assert!(
            admitted.is_empty(),
            "a lapsed term still gets through {admitted:?}"
        );
    }
}

mod a_build_before_schema_2_refuses_this_store_and_leaves_it_unchanged {
    //! **Decided 2026-09-17 (#187).** The trust file's schema moves once:
    //! each lease records whether both machines confirmed it and, once chosen,
    //! its clipboard. Builds of main from #158 up read only version 1, and
    //! they refuse to start on the new store until they are updated. A copy of
    //! the version 1 files is kept at migration for them, and deleted at the
    //! first removal after it.
    //!
    //! **Why this guard replaces the one before it.** That guard held the
    //! opposite rule, #183's: an older build must keep starting on a store
    //! this build saves, which pushed toward a second signed file kept in step
    //! with the first. The decision reversed it. What still has to hold is
    //! that an older build fails safely and can be brought back:
    //!
    //! * it refuses `trust.toml` as not a store it wrote, rather than reading
    //!   part of it, and writes nothing while refusing, so the newer build
    //!   still starts on the same files afterwards;
    //! * it parses the floor, so moving `trust.toml` aside is enough for it to
    //!   start again;
    //! * it accepts the copies once they are put back in place, with the
    //!   pairings they held.
    //!
    //! **The older build is frozen here**, reproduced from `trust_file::open`
    //! as it was before version 2 and from the daemon's start, which refuses
    //! on an error from `open` and writes only when no store is found. It must
    //! not follow later changes to `trust_file`: the builds it stands for will
    //! never change.

    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use serde::{Deserialize, Serialize};

    use crate::authority::{AUTHORITY_KEY_FILE_NAME, Authority, SignatureAlg, SoftwareAuthority};
    use crate::trust::TrustStore;
    use crate::trust_file::{
        FLOOR_FILE_NAME, FLOOR_V1_COPY_NAME, Loaded, TRUST_FILE_NAME, TRUST_V1_COPY_NAME,
        TrustFile, records_of, start,
    };

    use super::fp32;

    /// The older build: its on-disk shapes, byte for byte what it parses.
    mod older {
        use super::*;

        pub const TRUST_DOMAIN: &[u8] = b"hops.trust-store.v1\x00";
        pub const FLOOR_DOMAIN: &[u8] = b"hops.trust-floor.v1\x00";
        pub const SEPARATOR: &str = "\n[signature]\n";

        #[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
        #[serde(rename_all = "kebab-case")]
        pub enum Cap {
            Inbound,
            Outbound,
        }

        #[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
        #[serde(rename_all = "kebab-case")]
        pub enum State {
            Active,
            Revoked,
        }

        #[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
        #[serde(rename_all = "kebab-case")]
        pub enum Origin {
            Inbound,
            OutboundDial,
            Migrated,
        }

        #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
        #[serde(deny_unknown_fields)]
        pub struct Lease {
            pub fingerprint: String,
            pub label: String,
            pub state: State,
            pub origin: Origin,
            pub issued_at: u64,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub expires_at: Option<u64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub revoked_at: Option<u64>,
            pub caps: Vec<Cap>,
        }

        #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
        #[serde(deny_unknown_fields)]
        pub struct AuthorityBlock {
            pub alg: String,
            pub public_key: String,
        }

        #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
        #[serde(deny_unknown_fields)]
        pub struct TrustBody {
            pub version: u32,
            pub serial: u64,
            pub written_at: u64,
            pub authority: AuthorityBlock,
            #[serde(default)]
            pub leases: Vec<Lease>,
        }

        #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
        #[serde(deny_unknown_fields)]
        pub struct FloorBody {
            pub version: u32,
            pub seconds: u64,
            pub serial: u64,
            pub authority: AuthorityBlock,
        }

        #[derive(Deserialize)]
        struct SignatureBlock {
            value: String,
        }

        #[derive(Deserialize)]
        struct JustTheAuthority {
            authority: AuthorityBlock,
        }

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        fn unhex(s: &str) -> Option<Vec<u8>> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
                .collect()
        }

        pub fn authority_block(auth: &dyn Authority) -> AuthorityBlock {
            AuthorityBlock {
                alg: auth.algorithm().as_str().to_owned(),
                public_key: hex(auth.public_key()),
            }
        }

        fn seal<T: Serialize>(body: &T, domain: &[u8], auth: &dyn Authority) -> String {
            let text = toml_edit::ser::to_string_pretty(body).expect("serialise");
            let text = text.trim_end_matches('\n').to_owned();
            let mut msg = domain.to_vec();
            msg.extend_from_slice(text.as_bytes());
            let sig = auth.sign(&msg).expect("sign");
            format!("{text}{SEPARATOR}value = \"{}\"\n", hex(&sig))
        }

        /// Its `read_sealed`: absent is `None`; another authority, a bad
        /// signature or an unreadable body is an error naming the file.
        fn read_sealed<T: serde::de::DeserializeOwned>(
            path: &Path,
            domain: &[u8],
            expect: &AuthorityBlock,
        ) -> Result<Option<T>, String> {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(format!("{}: {e}", path.display())),
            };
            let untrusted = |why: String| format!("{} is untrusted: {why}", path.display());
            let (body, tail) = text
                .rsplit_once(SEPARATOR)
                .ok_or_else(|| untrusted("no signature block".into()))?;
            let declared: JustTheAuthority =
                toml_edit::de::from_str(body).map_err(|e| untrusted(format!("{e}")))?;
            if declared.authority != *expect {
                return Err(untrusted("another authority".into()));
            }
            let block: SignatureBlock =
                toml_edit::de::from_str(tail).map_err(|e| untrusted(format!("{e}")))?;
            let sig = unhex(&block.value).ok_or_else(|| untrusted("signature not hex".into()))?;
            let key = unhex(&expect.public_key).ok_or_else(|| untrusted("key not hex".into()))?;
            let alg = SignatureAlg::parse(&expect.alg).map_err(|e| untrusted(format!("{e}")))?;
            let mut msg = domain.to_vec();
            msg.extend_from_slice(body.as_bytes());
            crate::authority::verify(alg, &key, &msg, &sig)
                .map_err(|_| untrusted("edited".into()))?;
            toml_edit::de::from_str(body)
                .map(Some)
                .map_err(|e| untrusted(format!("unreadable body: {e}")))
        }

        /// Its `TrustFile::open`: the floor, then the store, its version, the
        /// rollback check and the structural checks. `Ok(None)` is no store.
        pub fn open(dir: &Path, auth: &dyn Authority) -> Result<Option<Vec<Lease>>, String> {
            let expect = authority_block(auth);
            let floor: Option<FloorBody> =
                read_sealed(&dir.join(FLOOR_FILE_NAME), FLOOR_DOMAIN, &expect)?;
            let floor_serial = floor.map_or(0, |f| f.serial);
            let trust_path = dir.join(TRUST_FILE_NAME);
            let Some(body) = read_sealed::<TrustBody>(&trust_path, TRUST_DOMAIN, &expect)? else {
                return Ok(None);
            };
            if body.version != 1 {
                return Err(format!(
                    "{} is untrusted: schema version {}",
                    trust_path.display(),
                    body.version
                ));
            }
            if body.serial < floor_serial {
                return Err(format!("{} is untrusted: a rollback", trust_path.display()));
            }
            let mut seen = std::collections::HashSet::new();
            for l in &body.leases {
                if !seen.insert(l.fingerprint.clone()) {
                    return Err(format!(
                        "{} is untrusted: a duplicate",
                        trust_path.display()
                    ));
                }
                if l.state == State::Revoked && !l.caps.is_empty() {
                    return Err(format!(
                        "{} is untrusted: a revoked grant",
                        trust_path.display()
                    ));
                }
            }
            Ok(Some(body.leases))
        }

        /// Its save: the store, then the floor, each sealed.
        pub fn save(dir: &Path, auth: &dyn Authority, serial: u64, leases: Vec<Lease>) {
            let body = TrustBody {
                version: 1,
                serial,
                written_at: crate::trust::system_seconds(),
                authority: authority_block(auth),
                leases,
            };
            let floor = FloorBody {
                version: 1,
                seconds: body.written_at,
                serial,
                authority: authority_block(auth),
            };
            std::fs::write(dir.join(TRUST_FILE_NAME), seal(&body, TRUST_DOMAIN, auth))
                .expect("write the store");
            std::fs::write(dir.join(FLOOR_FILE_NAME), seal(&floor, FLOOR_DOMAIN, auth))
                .expect("write the floor");
        }

        /// Its daemon's start: an error from `open` stops it before any
        /// write; with no store it migrates and saves one.
        pub fn start(dir: &Path, auth: &dyn Authority) -> Result<Vec<Lease>, String> {
            match open(dir, auth)? {
                Some(leases) => Ok(leases),
                None => {
                    save(dir, auth, 1, Vec::new());
                    Ok(Vec::new())
                }
            }
        }
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("hops-guard-schema-2-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// A scratch directory holding a machine's trust authority.
    fn scratch(tag: &str) -> (PathBuf, Arc<dyn Authority>) {
        let d = scratch_dir(tag);
        let auth: Arc<dyn Authority> = Arc::new(
            SoftwareAuthority::load_or_generate(&d.join(AUTHORITY_KEY_FILE_NAME))
                .expect("authority"),
        );
        (d, auth)
    }

    /// Every file either build reads or writes, by name, as bytes.
    fn files(dir: &Path) -> BTreeMap<&'static str, Option<Vec<u8>>> {
        [
            TRUST_FILE_NAME,
            FLOOR_FILE_NAME,
            TRUST_V1_COPY_NAME,
            FLOOR_V1_COPY_NAME,
        ]
        .into_iter()
        .map(|name| (name, std::fs::read(dir.join(name)).ok()))
        .collect()
    }

    fn lease(fp: &str, state: older::State, caps: &[older::Cap]) -> older::Lease {
        older::Lease {
            fingerprint: fp.to_owned(),
            label: format!("device {}", &fp[..2]),
            state,
            origin: older::Origin::Migrated,
            issued_at: 1_788_579_979,
            expires_at: (state == older::State::Active).then_some(1_788_579_979 + 400 * 86_400),
            revoked_at: (state == older::State::Revoked).then_some(1_788_579_979),
            caps: caps.to_vec(),
        }
    }

    // LEDGER E2A-8 | class B | 4 file on disk: TrustFile::open, trust_file::start, TrustFile::save, and a frozen older build's open, save and start
    #[test]
    fn a_build_before_schema_2_refuses_this_store_and_leaves_it_unchanged() {
        use older::{Cap, State};

        // A store holding no pairing is refused, by its version alone.
        let (empty, auth) = scratch("empty");
        let (mut file, _) = TrustFile::open(&empty, auth.clone()).expect("open");
        file.save(&records_of(
            &TrustStore::new(&fp32(0x01), file.now()).expect("ours"),
        ))
        .expect("save an empty store");
        assert!(
            older::start(&empty, auth.as_ref()).is_err(),
            "a build that reads only version 1 started on an empty store this build \
             saved: the version must say it is not a store that build can read"
        );

        // A store an older build wrote, and this build's first start on it.
        // It holds no removal: one is dropped at that start, and the copy
        // holding it goes with it, so no removed device survives there
        // (#184; `trust_file`'s
        // `a_removal_an_earlier_build_kept_is_dropped_and_that_device_pairs_again`).
        let (dir, auth) = scratch("migrated");
        let held = vec![
            lease(&fp32(0x11), State::Active, &[Cap::Inbound]),
            lease(&fp32(0x12), State::Active, &[Cap::Outbound]),
        ];
        older::save(&dir, auth.as_ref(), 4, held.clone());
        assert_eq!(
            older::start(&dir, auth.as_ref()).as_ref(),
            Ok(&held),
            "precondition: the older build starts on its own store"
        );
        let (mut file, loaded) = TrustFile::open(&dir, auth.clone()).expect("this build opens it");
        let Loaded::Present { leases, .. } = loaded else {
            panic!("the store must be found");
        };
        start(&mut file, &fp32(0x01), &leases).expect("this build starts");

        // The older build refuses the store this build saved, blames the
        // store and not the floor, and writes nothing.
        let before = files(&dir);
        let refused = older::start(&dir, auth.as_ref());
        let store_path = dir.join(TRUST_FILE_NAME).display().to_string();
        match &refused {
            Err(why) if why.starts_with(&format!("{store_path} is untrusted")) => {}
            other => panic!(
                "a build that reads only version 1 must refuse {TRUST_FILE_NAME} as a \
                 store it did not write, and parse the floor on the way; it gave {other:?}"
            ),
        }
        assert_eq!(
            files(&dir),
            before,
            "the older build changed a file while refusing, so this build may no longer \
             start on them"
        );
        let (_, reopened) = TrustFile::open(&dir, auth.clone()).expect("this build reopens it");
        assert!(
            matches!(reopened, Loaded::Present { .. }),
            "this build no longer finds its store after the older build refused it"
        );

        // The copies, put back in place, are a store the older build starts on.
        let restored = scratch_dir("restored");
        std::fs::copy(
            dir.join(AUTHORITY_KEY_FILE_NAME),
            restored.join(AUTHORITY_KEY_FILE_NAME),
        )
        .expect("the same machine");
        for (copy, name) in [
            (TRUST_V1_COPY_NAME, TRUST_FILE_NAME),
            (FLOOR_V1_COPY_NAME, FLOOR_FILE_NAME),
        ] {
            std::fs::copy(dir.join(copy), restored.join(name)).expect("put the copy back");
        }
        assert_eq!(
            older::start(&restored, auth.as_ref()).as_ref(),
            Ok(&held),
            "the version 1 copies, restored, are not the store the older build wrote"
        );

        // With trust.toml moved aside, the older build starts again on the
        // floor this build wrote.
        std::fs::rename(dir.join(TRUST_FILE_NAME), dir.join("trust.toml.aside"))
            .expect("move the store aside");
        assert_eq!(
            older::open(&dir, auth.as_ref()),
            Ok(None),
            "with {TRUST_FILE_NAME} moved aside, a build that reads only version 1 must \
             find no store and start fresh; it cannot read the floor this build wrote"
        );

        for d in [dir, restored, empty] {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

// ---------------------------------------------------------------------------
// removing a device forgets it
// ---------------------------------------------------------------------------

mod removing_a_device_forgets_it {
    //! **Decided 2026-09-16 (#184), correcting how 2026-08-19 was built.**
    //! Removing a device drops its lease, its address and any record of its
    //! identity. There is no tombstone, no restore verb and no reset: the
    //! machine is unknown again, and adding it back is an ordinary pairing.
    //!
    //! **What stands in for the tombstone.** A removed machine returns only
    //! through the full pairing: a prompt, which appears only after someone
    //! opened add device on this machine (#195); an approval here, which
    //! grants nothing on its own; and the same number confirmed on both
    //! machines (#11, #167).
    //!
    //! **Superseded, and it is not a tidy-up to bring back.** The rule these
    //! guards replace recorded the removed identity for good, so that machine
    //! could only come back under a new one, and the app told people to
    //! reinstall to get one. Recording removals again reverses the 2026-09-16
    //! decision: take it to the decision record first.

    use crate::service::{GrantRefused, grant_for_attempt};
    use crate::trust::{Caps, TrustStore};
    use hops_ipc::AttemptOrigin;

    use super::fp32;

    fn paired_with(peer: &str, kept: &str) -> TrustStore {
        let mut store = TrustStore::new(&fp32(0x01), 0).expect("our own fingerprint");
        store
            .issue_confirmed(peer, "the sold laptop", Caps::KNOWN)
            .expect("issue");
        store
            .issue_confirmed(kept, "the desk mac", Caps::INBOUND)
            .expect("issue");
        store
    }

    /// Nothing about a removed device is left anywhere the store answers
    /// from or writes to: not a lease, not its name, not a row on disk, not
    /// the allowlist cache an older build reads.
    // LEDGER R184-2 | class B | 1 return value + 6 struct state: TrustStore::forget, records_of, config_cache
    #[test]
    fn removal_leaves_no_record_of_the_device() {
        let (peer, kept) = (fp32(0x77), fp32(0x78));
        let mut store = paired_with(&peer, &kept);

        assert!(store.forget(&peer), "the removal found nothing to remove");

        assert!(
            !store.is_known(&peer),
            "the store still holds a record of a removed device. Removing a \
             device forgets it (decided 2026-09-16, #184): no tombstone, no \
             name, nothing a reset would have to undo."
        );
        assert_eq!(store.label(&peer), None, "its name was kept");
        assert!(
            store.entries().all(|(fp, _)| fp != peer),
            "a record of it is still listed"
        );
        assert!(
            crate::trust_file::records_of(&store)
                .iter()
                .all(|r| r.fingerprint != peer),
            "the store would write a record of it to disk"
        );
        assert!(
            !store.config_cache().contains_key(&peer),
            "the config file would still list it"
        );
        assert!(
            store.may_drive_us(&kept),
            "removing one device took another's pairing with it"
        );
    }

    /// A removed device comes back through the full pairing and no other
    /// way. Every verb short of it leaves the device with nothing; the grant
    /// door refuses without a prompt a pairing window admitted; an approval
    /// grants nothing until both machines confirm the number.
    ///
    /// Written as an enumeration so a verb added next month that hands a
    /// removed device something short of the pairing fails here by name.
    // LEDGER R184-3 | class B | 1 return value: TrustStore verbs, service::grant_for_attempt
    #[test]
    fn a_removed_device_returns_only_through_the_full_pairing() {
        let (peer, kept) = (fp32(0x77), fp32(0x78));

        type Verb = (&'static str, fn(&mut TrustStore, &str));
        let verbs: [Verb; 7] = [
            ("renew", |s, fp| {
                let _ = s.renew(fp);
            }),
            ("set_label", |s, fp| {
                let _ = s.set_label(fp, "back please");
            }),
            ("drop_capabilities", |s, fp| {
                let _ = s.drop_capabilities(fp, Caps::NONE);
            }),
            ("disable_clipboard", |s, fp| {
                let _ = s.disable_clipboard(fp);
            }),
            ("enable_clipboard", |s, fp| {
                let _ = s.enable_clipboard(fp);
            }),
            ("confirm", |s, fp| {
                let _ = s.confirm(fp);
            }),
            ("forget_unconfirmed", |s, fp| {
                let _ = s.forget_unconfirmed(fp);
            }),
        ];
        for (verb, apply) in verbs {
            let mut store = paired_with(&peer, &kept);
            store.forget(&peer);
            apply(&mut store, &peer);
            assert!(
                !store.is_known(&peer) && store.capabilities(&peer) == Caps::NONE,
                "`{verb}` gave a removed device a record or a capability without \
                 the full pairing (#184, #195, #167)"
            );
        }

        let mut store = paired_with(&peer, &kept);
        store.forget(&peer);
        assert!(
            matches!(
                grant_for_attempt(
                    &mut store,
                    &peer,
                    "back please",
                    None,
                    hops_ipc::Controller::ThatMachine,
                    false
                ),
                Err(GrantRefused::NoAttempt)
            ),
            "the grant door approved a removed device with no prompt a pairing \
             window admitted (#195)"
        );
        assert!(!store.is_known(&peer), "a refused grant left a record");

        grant_for_attempt(
            &mut store,
            &peer,
            "back please",
            Some(AttemptOrigin::Inbound),
            hops_ipc::Controller::ThatMachine,
            false,
        )
        .expect("a prompt a window admitted is approved like any first contact");
        assert_eq!(
            store.capabilities(&peer),
            Caps::NONE,
            "an approval alone gave a removed device back its pairing: the \
             number was never confirmed (#11, #167)"
        );
        assert!(
            store.awaits(&peer, Caps::DRIVE_ME),
            "the approval does not let the number be compared"
        );
        store
            .confirm(&peer)
            .expect("both machines confirmed the number");
        assert!(
            store.may_drive_us(&peer),
            "the full pairing did not pair a removed device again (#161)"
        );
    }

    /// What a pairing card recorded goes with the removal (#184, #220): a
    /// machine paired as each controlling the other with the clipboard
    /// shared, removed, and paired again as controlling this one with the
    /// clipboard off, holds exactly the second card's answers. A grant to a
    /// pairing in force adds to it (#166), so a removal that left anything
    /// in force would hand the old direction and clipboard back.
    // LEDGER R184-18 | class B | 1 return value + 6 struct state: TrustStore::forget, service::grant_for_attempt, TrustStore::lease
    #[test]
    fn a_removal_drops_what_the_pairing_card_recorded() {
        use crate::trust::{Origin, drive_of};
        use hops_ipc::Controller;
        let (peer, kept) = (fp32(0x77), fp32(0x78));
        let mut store = paired_with(&peer, &kept);
        store.forget(&peer);

        grant_for_attempt(
            &mut store,
            &peer,
            "desk",
            Some(AttemptOrigin::OutboundDial),
            Controller::Both,
            true,
        )
        .expect("the first card's approval");
        store.confirm(&peer).expect("both machines confirmed");
        assert!(
            store.we_may_drive(&peer) && store.may_drive_us(&peer) && store.clipboard_from(&peer),
            "precondition: the first card paired both ways with the clipboard shared"
        );

        assert!(store.forget(&peer), "the removal found nothing to remove");
        grant_for_attempt(
            &mut store,
            &peer,
            "desk",
            Some(AttemptOrigin::Inbound),
            Controller::ThatMachine,
            false,
        )
        .expect("a removed machine is approved like any first contact");
        assert_eq!(
            store.capabilities(&peer),
            Caps::NONE,
            "the second approval granted something before its number was confirmed"
        );
        store.confirm(&peer).expect("both machines confirmed again");
        assert_eq!(
            (
                store.capabilities(&peer),
                store.lease(&peer).map(|l| l.origin),
            ),
            (
                drive_of(Controller::ThatMachine),
                Some(Origin::Chosen(Controller::ThatMachine))
            ),
            "the pairing after a removal kept something the removed pairing's card \
             chose: a direction or a clipboard nobody chose this time"
        );
    }

    /// A removal an earlier build kept on file is not carried into the store
    /// this build answers from (#184, #161).
    // LEDGER R184-4 | class B | 1 return value: trust_file::rebuild
    #[test]
    fn a_removal_an_earlier_build_kept_is_not_carried_forward() {
        use crate::trust_file::{DiskOrigin, DiskState, LeaseRecord, rebuild};
        let peer = fp32(0x77);
        let kept = LeaseRecord {
            fingerprint: peer.clone(),
            label: "the sold laptop".into(),
            state: DiskState::Revoked,
            origin: DiskOrigin::Migrated,
            issued_at: 1,
            expires_at: None,
            revoked_at: Some(1),
            caps: Vec::new(),
            confirmed: true,
            clipboard: None,
        };
        let (store, _) = rebuild(&fp32(0x01), 2, &[kept]).expect("rebuild");
        assert!(
            !store.is_known(&peer),
            "a removal an earlier build recorded is still in force here"
        );
    }
}

// ---------------------------------------------------------------------------
// the quiet window, and the asymmetry that looks like an oversight
// ---------------------------------------------------------------------------

mod taking_trust_away_is_never_gated_the_way_giving_it_is {
    //! **Decided 2026-08-05, two rules.** (1) A trust grant is refused while a
    //! peer is injecting input into this machine. (2) Revoke and delete succeed
    //! while a peer is driving this machine — the quiet window gates grants
    //! only. Turning a pairing's clipboard off (#182) takes permission away
    //! too, and is held to the same rule; turning it on widens, and is gated
    //! like a grant (#107).
    //!
    //! **Why the asymmetry is deliberate.** On a KVM the pointer is not proof
    //! of local presence: a peer that still holds control can move the cursor
    //! onto an approval button and click it, manufacturing its own consent. But
    //! refusing to let the user revoke while a peer drives them blocks the one
    //! action most needed at exactly that moment.
    //!
    //! **The named failure mode.** This looks like an oversight to a tidy
    //! reader. A symmetry cleanup that applies the grant gate to both verbs is
    //! the exact regression the record warns about, by name.

    use crate::trust::{Caps, TrustStore};

    use super::fp32;

    /// The structural half, checked by calling the store: removal takes no
    /// authority and cannot fail, so there is nothing for a future gate to hook
    /// into without changing the signature — which a reviewer would see.
    #[test]
    fn revocation_needs_no_authority_and_has_no_failure_path_to_gate() {
        let ours = fp32(0x01);
        let peer = fp32(0xaa);
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");
        store
            .issue_confirmed(&peer, "driving me right now", Caps::KNOWN)
            .expect("issue");

        // No Result, no authority argument, no clock argument: `forget`
        // returns whether there was a record and nothing else can be threaded
        // into it.
        let removed: bool = store.forget(&peer);

        assert!(removed, "the removal found nothing");
        assert_eq!(
            store.capabilities(&peer),
            Caps::NONE,
            "removal left capabilities behind. Removal must be reachable and \
             total from a machine that is CURRENTLY being driven by the peer \
             being removed — that is the moment it exists for."
        );

        // Removing something already removed, and something never known, must
        // also not fail: a user hammering the button while a peer drives them
        // must not hit an error path.
        let _ = store.forget(&peer);
        let _ = store.forget(&fp32(0xbb));
    }

    /// **Text invariant, and it is about placement rather than behaviour.**
    ///
    /// `Service::refuse_while_remotely_driven` is a private method on a type
    /// that needs a TLS identity, an IPC socket, QUIC in both directions, and
    /// capture plus emulation backends before it can be constructed, so there
    /// is no way to call it from a test today. What CAN be checked without that
    /// machinery is which dispatch arms consult it — and that is exactly the
    /// thing a symmetry cleanup would change. See the gap note in the handover:
    /// this becomes a real behavioural test the moment the gate is a free
    /// function over an "am I being driven" predicate.
    ///
    /// Scans `service.rs`, never this file. What the gated arms do while a
    /// peer drives is observed, not scanned, by
    /// `a_frontend_widens_trust_only_by_approving_a_prompt_or_turning_the_clipboard_on`.
    #[test]
    fn only_the_arms_that_widen_trust_consult_the_quiet_window() {
        let src = super::scan::code_only(include_str!("service.rs"));
        let gate = "refuse_while_remotely_driven";

        let dispatch_start = src
            .find("fn handle_frontend_request")
            .expect("handle_frontend_request must exist; if it was renamed, update this guard");
        let dispatch = &src[dispatch_start..];
        let dispatch_end = dispatch[1..]
            .find("\n    fn ")
            .map(|i| i + 1)
            .unwrap_or(dispatch.len());
        let dispatch = &dispatch[..dispatch_end];

        assert!(
            dispatch.contains(gate),
            "the frontend dispatch no longer consults the quiet window at all. A \
             peer that holds your keyboard can move the cursor onto an approval \
             button and click it; any proof evaluated on the REQUESTING machine \
             is worthless, because that machine is the adversary and this is \
             GPLv3 source. The only usable check is one this machine makes \
             against state only it holds."
        );

        // The arms that MUST consult the gate: they widen trust. Confirming
        // a pairing's number is what makes an approval grant (#167).
        for arm in ["AuthorizeKey", "EnableClipboard", "ConfirmPairing"] {
            let at = dispatch
                .find(&format!("FrontendRequest::{arm}"))
                .unwrap_or_else(|| panic!("{arm} must be dispatched; update this guard"));
            let after = &dispatch[at..];
            let arm_end = after[1..]
                .find("FrontendRequest::")
                .map(|i| i + 1)
                .unwrap_or(after.len());
            assert!(
                after[..arm_end].contains(gate),
                "the {arm} arm no longer refuses while a peer is driving this \
                 machine. On a KVM the pointer is not proof of local presence: \
                 the peer holding your keyboard can move the cursor onto the \
                 approval button and click it, manufacturing its own consent. \
                 Widening trust is what a remote peer can usefully click for \
                 itself."
            );
        }

        for arm in [
            "RemoveAuthorizedKey",
            "Delete",
            "DisableClipboard",
            "CancelPairing",
        ] {
            let at = dispatch
                .find(&format!("FrontendRequest::{arm}"))
                .unwrap_or_else(|| panic!("{arm} must be dispatched; update this guard"));
            let after = &dispatch[at..];
            let arm_end = after[1..]
                .find("FrontendRequest::")
                .map(|i| i + 1)
                .unwrap_or(after.len());
            assert!(
                !after[..arm_end].contains(gate),
                "the {arm} arm now refuses while a peer is driving this machine. \
                 That is a SYMMETRY CLEANUP, and it is the regression the \
                 2026-08-05 decision names by name: blocking revoke while a peer \
                 drives you blocks the one action most needed at that moment. \
                 The asymmetry is deliberate and only looks like an oversight."
            );
        }
    }
}

mod removing_a_device_takes_its_key_and_not_merely_its_address {
    //! **Decided 2026-08-19.** `delete` removes the peer's key authorisation as
    //! well as its dial entry; `revoke` drops trust and keeps the address, for
    //! a device intended to be re-paired.
    //!
    //! **Why.** Before this, delete forgot the address but left the key
    //! authorised — so a machine the user believed they had removed could still
    //! drive their keyboard and mouse.
    //!
    //! **And where the untrust must live.** Inside the `Delete` dispatch arm,
    //! NOT inside `remove_client()`. `remove_client` is also called by
    //! `handle_config_change`, which removes every client before rebuilding
    //! them — so revoking there wipes the entire trust store on any config
    //! reload. The dated entry states the behaviour and omits the placement;
    //! the catastrophic half is recorded in only one file, which is why it is
    //! asserted here.

    use crate::trust::{Caps, TrustStore};

    use super::fp32;

    /// The behavioural half: removing trust is total, and it survives being
    /// asked twice.
    #[test]
    fn a_deleted_device_keeps_no_authorisation_of_any_kind() {
        let ours = fp32(0x01);
        let peer = fp32(0xcc);
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");
        store
            .issue_confirmed(&peer, "the sold laptop", Caps::KNOWN)
            .expect("issue");
        assert!(store.may_drive_us(&peer), "precondition: it was trusted");

        store.forget(&peer);

        assert_eq!(
            store.capabilities(&peer),
            Caps::NONE,
            "a removed device kept a capability. Removing a device has to mean \
             removed: hops can read every keystroke on this machine, and delete \
             used to forget the dial address while leaving the key authorised, \
             so a machine the user believed they had removed could still take \
             their keyboard and mouse."
        );
        assert!(
            !store.is_known(&peer),
            "a removed device left a record behind; removing it forgets it (#184)"
        );
    }

    /// **Text invariant about placement.** The daemon type cannot be
    /// constructed in a unit test, and this half of the rule is *where* a call
    /// sits, not what it computes. Scans `service.rs`, never this file.
    #[test]
    fn untrusting_on_delete_happens_in_the_delete_arm_and_never_in_remove_client() {
        let src = super::scan::code_only(include_str!("service.rs"));

        let start = src
            .find("fn remove_client(")
            .expect("remove_client must exist; if it was renamed, update this guard");
        let rest = &src[start..];
        let end = rest[1..]
            .find("\n    fn ")
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let body = &rest[..end];

        for forbidden in ["remove_authorized_key", ".forget("] {
            assert!(
                !body.contains(forbidden),
                "remove_client() calls `{forbidden}`. remove_client is ALSO called \
                 by handle_config_change, which removes every client before \
                 rebuilding them — so revoking here wipes the ENTIRE trust store \
                 on any config reload, including a reload triggered by saving an \
                 unrelated setting. The untrust belongs in the Delete dispatch \
                 arm, which is reached only by a user deleting one device."
            );
        }
    }
}

mod an_edited_device_still_dials_only_the_machine_it_is_pinned_to {
    //! **Decided 2026-09-26 (#99).** Editing a device's address or hostname
    //! keeps its fingerprint pin. The machine answering at the new address
    //! has to present the same fingerprint; a different machine is refused.
    //! This reverses the clearing that went with #22.
    //!
    //! **Why.** The pin is the only thing that says "this device is that
    //! machine". Without it a dial accepts any machine this one may drive, so
    //! clearing it on an edit widened the check from one machine to all of
    //! them, and the dial then pinned and saved whichever answered, with no
    //! prompt and the old name still on the card. An address says where to
    //! dial, never who is trusted there.

    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use hops_ipc::Position;
    use hops_proto::ProtoEvent;

    use crate::client::ClientManager;
    use crate::test_harness::{Dialer, Door, Machine, dialer, door, machine, run_local, trust};
    use crate::trust::Caps;

    use super::fp32;

    const PATIENCE: Duration = Duration::from_secs(10);

    /// Somewhere nothing answers (TEST-NET-1), where the device was before.
    const OLD_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    /// A device pinned to `pinned`, at [`OLD_ADDRESS`] on `door`'s port, then
    /// moved to the address `door` answers on, and dialled.
    async fn moved_to(
        door: &Door,
        sender: &Machine,
        pinned: &Machine,
        known: &[&Machine],
    ) -> Dialer {
        let d = dialer(
            sender,
            trust(sender, known, Caps::OUTBOUND),
            door.port,
            Position::Left,
        );
        d.clients.set_fix_ips(d.handle, vec![OLD_ADDRESS]);
        d.clients
            .set_peer_fingerprint(d.handle, Some(pinned.fingerprint.clone()));
        d.clients
            .set_fix_ips(d.handle, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        let _ = d.conn.send(ProtoEvent::Ping, d.handle).await;
        let started = tokio::time::Instant::now();
        while door.closed() == 0
            && d.conn.active_addr(d.handle).is_none()
            && started.elapsed() < PATIENCE
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        d
    }

    /// The rule itself, for both edits, at the one place that holds the pin.
    #[test]
    fn a_new_address_or_name_leaves_the_pin_where_it_was() {
        let clients = ClientManager::default();
        let handle = clients.add_client();
        let pin = fp32(0xd1);
        clients.set_peer_fingerprint(handle, Some(pin.clone()));

        clients.set_fix_ips(handle, vec![OLD_ADDRESS]);
        assert_eq!(
            clients.peer_fingerprint(handle),
            Some(pin.clone()),
            "a new address cleared the device's pin, so its next dial accepts any \
             machine this one may drive and pins whichever answers (#99)"
        );
        clients.set_hostname(handle, Some("desk mac.invalid".into()));
        assert_eq!(
            clients.peer_fingerprint(handle),
            Some(pin),
            "a new hostname cleared the device's pin, so its next dial accepts \
             any machine this one may drive and pins whichever answers (#99)"
        );
    }

    /// A different machine answering at the new address is refused, though
    /// this machine may drive it.
    #[test]
    fn another_machine_at_the_new_address_is_refused() {
        run_local(async {
            let (sender, desk, other) = (machine(), machine(), machine());
            let answering = door(&other);
            answering.open();
            let d = moved_to(&answering, &sender, &desk, &[&desk, &other]).await;

            assert_eq!(
                (
                    d.conn.active_addr(d.handle).is_some(),
                    d.clients.peer_fingerprint(d.handle) == Some(desk.fingerprint.clone()),
                    answering.streams(),
                ),
                (false, true, 0),
                "(linked, still pinned to the desk, streams opened): the device \
                 was pinned to the desk and moved to an address where another \
                 machine this one may drive answers. That machine has to be \
                 refused and the pin kept (#99); a link or a new pin means input \
                 meant for the desk goes to it."
            );
            assert!(
                answering.closed() > 0,
                "the other machine's connection was left open"
            );
        });
    }

    /// The same machine at its new address is still reached: keeping the pin
    /// does not stop an address edit from working.
    #[test]
    fn the_same_machine_at_the_new_address_is_reached() {
        run_local(async {
            let (sender, desk) = (machine(), machine());
            let answering = door(&desk);
            answering.open();
            let d = moved_to(&answering, &sender, &desk, &[&desk]).await;

            assert!(
                d.conn.active_addr(d.handle).is_some(),
                "the device was moved to the address its own machine answers on, \
                 and no link came up"
            );
            assert_eq!(
                d.clients.peer_fingerprint(d.handle),
                Some(desk.fingerprint),
                "the device's pin changed on reaching its own machine"
            );
        });
    }
}

// ---------------------------------------------------------------------------
// no UI is trusted; nothing reaches a shell
// ---------------------------------------------------------------------------

mod a_frontend_widens_trust_only_by_approving_a_prompt_or_turning_the_clipboard_on {
    //! **Decided 2026-09-26 (#107): retired, as a stated limit.** It replaces
    //! 2026-08-30's rule that no frontend can cause a trust write, whose two
    //! guards stood red until the grant verb left the IPC channel. It stays.
    //!
    //! **The limit.** Three frontend requests widen trust, and nothing else
    //! a frontend can send does: `AuthorizeKey`, which approves a prompt the
    //! daemon raised for a machine that arrived while the pairing window was
    //! open, with the card's answers, which way control goes (#220) and a yes
    //! or no to the clipboard (#182), so a yes is refused while driven with
    //! the approval it is part of; `ConfirmPairing`, which answers the number that approval's
    //! pairing compares, and without which the approval grants nothing
    //! (#167); and `EnableClipboard`, which turns a paired machine's
    //! clipboard back on in the directions it already drives. The daemon
    //! refuses all three while a peer is driving this machine, so the machine
    //! holding the keyboard and pointer cannot click its own approval.
    //!
    //! **Why it is a limit and not a boundary.** Anything running as the user
    //! can read the IPC token, send all three, open add device and add a device to
    //! dial, and re-sign the trust store on disk (`src/authority.rs`). The
    //! channel cannot defend against that program, so the rule is stated
    //! where a reader finds it (the `hops_ipc` crate docs) and pinned here, so
    //! a fourth widening request, or any of the three without the driving
    //! check, fails a test instead of passing review.
    //!
    //! **Behavioural.** The whole daemon runs in this process with a real
    //! frontend on its IPC socket and real peers on loopback QUIC: one drives
    //! it, two knock while add device is open, and one of those compares its
    //! number. The store read is the daemon's own.
    #![cfg(unix)]

    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use hops_ipc::{ClientHandle, FrontendEvent, FrontendRequest, Position};
    use hops_proto::ProtoEvent;
    use input_emulation::recording::{Recorded, Recording};
    use input_event::{Event, PointerEvent};

    use crate::service::in_process::{
        DEADLINE, Daemon, compare_number, prompt_from, trusting, until_paired,
    };
    use crate::test_harness::{dialer, machine, run_local};
    use crate::transport::Trust;
    use crate::trust::Caps;

    /// Whether a request can widen trust. There is no wildcard: a new request
    /// fails to compile here until it is placed on one side, and one placed
    /// on the `false` side must be in [`every_other_request`] as well, which
    /// `every_request_is_sent_by_the_sweep` checks.
    fn widens(request: &FrontendRequest) -> bool {
        use FrontendRequest as R;
        match request {
            R::AuthorizeKey { .. } | R::EnableClipboard(_) | R::ConfirmPairing { .. } => true,
            R::Activate(..)
            | R::Create(_)
            | R::ChangePort(_)
            | R::Delete { .. }
            | R::Enumerate()
            | R::ResolveDns(_)
            | R::UpdateHostname { .. }
            | R::UpdateLabel(..)
            | R::UpdatePort(..)
            | R::UpdatePosition(..)
            | R::UpdateGeometry(..)
            | R::UpdateFixIps(..)
            | R::EnableCapture
            | R::EnableEmulation
            | R::Sync
            | R::RemoveAuthorizedKey(_)
            | R::SetLabel(..)
            | R::SaveConfiguration
            | R::OpenPairing
            | R::DisableClipboard(_)
            | R::CancelPairing(_)
            | R::Barrier(_) => false,
        }
    }

    /// One of every request that does not widen trust, each aimed where a
    /// widening would show: at the machine whose prompt is waiting, at the
    /// paired machine whose clipboard is off, and at a device added here,
    /// which is pointed at a port nothing answers on. The one removal is aimed
    /// at a machine never paired, so the pairings above are still there to
    /// widen afterwards.
    fn every_other_request(
        stranger: &str,
        paired: &str,
        added: ClientHandle,
        port: u16,
        nowhere: u16,
    ) -> Vec<FrontendRequest> {
        use FrontendRequest as R;
        let loopback = std::net::IpAddr::from([127, 0, 0, 1]);
        vec![
            R::OpenPairing,
            R::UpdateLabel(added, Some("renamed".into())),
            R::UpdateFixIps(added, vec![loopback]),
            R::UpdatePort(added, nowhere),
            R::UpdateHostname {
                handle: added,
                hostname: None,
                fingerprint: None,
            },
            R::UpdatePosition(added, Position::Right),
            R::UpdateGeometry(added, None),
            R::Activate(added, true),
            R::ResolveDns(added),
            R::Enumerate(),
            R::Sync,
            R::ChangePort(port),
            R::EnableCapture,
            R::EnableEmulation,
            R::SetLabel(stranger.to_owned(), "a stranger, renamed".to_owned()),
            R::SetLabel(paired.to_owned(), "desk mac, renamed".to_owned()),
            R::DisableClipboard(paired.to_owned()),
            R::DisableClipboard(stranger.to_owned()),
            R::CancelPairing(stranger.to_owned()),
            R::CancelPairing(paired.to_owned()),
            R::SaveConfiguration,
            R::Barrier(u64::MAX),
            R::Activate(added, false),
            R::Delete {
                handle: added,
                fingerprint: None,
            },
            R::RemoveAuthorizedKey(super::fp32(0x5e)),
        ]
    }

    /// A device added here, pointed at `port` on loopback, where nothing
    /// answers when `port` is the sweep's `nowhere`.
    fn new_device(port: u16) -> hops_ipc::NewDevice {
        hops_ipc::NewDevice {
            hostname: None,
            fix_ips: vec![std::net::IpAddr::from([127, 0, 0, 1])],
            port,
            pos: Position::Left,
        }
    }

    /// What the daemon's store grants each machine it holds a pairing for.
    fn granted(trust: &Trust) -> BTreeMap<String, Caps> {
        trust.read().expect("lock").pairings().into_iter().collect()
    }

    /// The machines approved here whose number is not yet confirmed: they
    /// are admitted at TLS, far enough to compare it (#167). A request that
    /// adds one has widened trust as surely as one that adds a pairing.
    fn waiting(trust: &Trust) -> BTreeSet<String> {
        trust
            .read()
            .expect("lock")
            .unconfirmed()
            .into_iter()
            .collect()
    }

    /// The notices that refused a request because this machine was driven.
    fn refusals(events: &[FrontendEvent]) -> Vec<&str> {
        events
            .iter()
            .filter_map(|e| match e {
                FrontendEvent::Error(text) if text.contains("controlled remotely") => {
                    Some(text.as_str())
                }
                _ => None,
            })
            .collect()
    }

    /// The name a request goes by on the IPC channel.
    fn name(request: &FrontendRequest) -> String {
        match serde_json::to_value(request).expect("a request serialises") {
            serde_json::Value::String(name) => name,
            serde_json::Value::Object(map) if map.len() == 1 => {
                map.into_iter().next().expect("one entry").0
            }
            other => panic!("a request serialised as neither a name nor one entry: {other}"),
        }
    }

    /// Every request the IPC channel carries, by name: the decoder lists them
    /// when it is handed one it does not know.
    fn every_request_name() -> BTreeSet<String> {
        let refused = serde_json::from_str::<FrontendRequest>("\"NoSuchRequest\"")
            .expect_err("no request is called NoSuchRequest")
            .to_string();
        let (_, expected) = refused
            .split_once("expected one of")
            .unwrap_or_else(|| panic!("the decoder no longer lists the requests: {refused}"));
        expected
            .split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    }

    // LEDGER EN-5 | class B | 1 return value: the requests the IPC decoder accepts, against the guard's own tables
    /// The sweep below proves nothing about a request it never sends. Every
    /// request is one of the three that widen, `Create` (sent first for the
    /// handle the others aim at), or in [`every_other_request`].
    #[test]
    fn every_request_is_sent_by_the_sweep() {
        use FrontendRequest as R;
        let fp = super::fp32(0x5f);
        let widening = [
            crate::test_harness::approval("", &fp, hops_ipc::Controller::Both),
            R::ConfirmPairing {
                fingerprint: fp.clone(),
                number: String::new(),
            },
            R::EnableClipboard(fp.clone()),
        ];
        assert!(widening.iter().all(widens));
        let others = every_other_request(&fp, &fp, 0, 1, 2);
        let mut sent: BTreeSet<String> = others.iter().map(name).collect();
        sent.extend(widening.iter().map(name));
        sent.insert(name(&R::Create(new_device(1))));
        assert_eq!(
            sent,
            every_request_name(),
            "a request the IPC channel carries is missing from every_other_request, \
             so the sweep never checks whether it widens trust. Add it there, aimed \
             where a widening would show."
        );
    }

    // LEDGER EN-3 | class B | 5 process-in-test + 1 struct state: FrontendRequest over the daemon's IPC socket, a peer driving it over loopback QUIC, the daemon's trust store
    #[test]
    fn only_approving_a_prompt_or_turning_the_clipboard_on_widens_trust_and_neither_while_driven() {
        run_local(async {
            let (desk, laptop, stranger, newcomer) = (machine(), machine(), machine(), machine());
            let tables = format!(
                "[authorized_fingerprints]\n\"{}\" = \"desk mac\"\n\"{}\" = \"laptop\"\n",
                desk.fingerprint, laptop.fingerprint
            );
            let recording = Recording::new();
            let daemon = Daemon::start("widen", &tables, recording.backend()).await;
            let (ours, port, trust, ipc) = (
                daemon.fingerprint(),
                daemon.port(),
                daemon.trust(),
                daemon.ipc(),
            );
            // Held for the whole test, so nothing else can answer on it.
            let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a silent port");
            let nowhere = silent.local_addr().expect("its address").port();
            let (desk_fp, laptop_fp, stranger_fp, newcomer_fp) = (
                desk.fingerprint.clone(),
                laptop.fingerprint.clone(),
                stranger.fingerprint.clone(),
                newcomer.fingerprint.clone(),
            );

            daemon
                .run_while(async {
                    use FrontendRequest as R;
                    let mut app = ipc.connect().await;
                    app.exchange(&[
                        R::OpenPairing,
                        R::DisableClipboard(desk_fp.clone()),
                        R::DisableClipboard(laptop_fp.clone()),
                    ])
                    .await;
                    prompt_from(&mut app, &stranger, port, &ours).await;
                    // A second machine is approved while nobody drives this
                    // one, and compares its number: what is left is the answer
                    // that makes its approval grant (#167).
                    prompt_from(&mut app, &newcomer, port, &ours).await;
                    app.exchange(&[crate::test_harness::approval(
                        "newcomer",
                        &newcomer_fp,
                        hops_ipc::Controller::ThatMachine,
                    )])
                    .await;
                    let comparing = compare_number(&mut app, &newcomer, port, &ours).await;
                    let before = granted(&trust);
                    let waiting_before = waiting(&trust);
                    assert!(
                        !before[&desk_fp].intersects(Caps::CLIPBOARD)
                            && !before.contains_key(&stranger_fp)
                            && !before.contains_key(&newcomer_fp),
                        "precondition: the paired machine's clipboard is off and the \
                         prompting ones hold nothing: {before:?}"
                    );
                    assert_eq!(
                        waiting_before,
                        BTreeSet::from([newcomer_fp.clone()]),
                        "precondition: only the approved machine waits for its number"
                    );

                    // Driven: the paired machine crosses onto this one and keeps
                    // moving the pointer while all three widening requests are sent.
                    let driver = dialer(&desk, trusting(&desk, &ours), port, Position::Left);
                    driver.until_alive().await;
                    driver
                        .send(ProtoEvent::Enter(hops_proto::Position::Right))
                        .await;
                    let motion = Event::Pointer(PointerEvent::Motion {
                        time: 0,
                        dx: 1.0,
                        dy: 0.0,
                    });
                    let driving = async {
                        loop {
                            driver.send(ProtoEvent::Input(motion)).await;
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    };
                    let asked = async {
                        crate::test_harness::wait_until("the pointer moves", DEADLINE, || {
                            recording
                                .calls()
                                .iter()
                                .any(|c| matches!(c, Recorded::Consume(e, _) if *e == motion))
                        })
                        .await;
                        app.exchange(&[
                            R::AuthorizeKey {
                                label: "new laptop".to_owned(),
                                fingerprint: stranger_fp.clone(),
                                controller: hops_ipc::Controller::ThatMachine,
                                clipboard: true,
                            },
                            R::EnableClipboard(desk_fp.clone()),
                            R::ConfirmPairing {
                                fingerprint: newcomer_fp.clone(),
                                number: comparing.number.clone(),
                            },
                        ])
                        .await
                    };
                    let events = tokio::select! {
                        () = driving => unreachable!("the driver stops only with the test"),
                        events = asked => events,
                    };
                    assert_eq!(
                        granted(&trust),
                        before,
                        "a request sent while a peer drove this machine widened trust. \
                         On a KVM the pointer is not proof that anyone is at this \
                         machine: the peer holding it can move it onto the approval \
                         and click, manufacturing its own consent. Refusals: {:?}",
                        refusals(&events)
                    );
                    assert_eq!(
                        waiting(&trust),
                        waiting_before,
                        "a request sent while a peer drove this machine approved a machine \
                         to compare a number. Refusals: {:?}",
                        refusals(&events)
                    );
                    let refused = refusals(&events);
                    let grants = refused
                        .iter()
                        .filter(|r| r.starts_with(hops_ipc::GRANT_REFUSED))
                        .count();
                    assert!(
                        refused.len() == 3 && grants == 1,
                        "all three widening requests must be refused, each saying why, while \
                         a peer drives this machine, and only the grant's refusal may begin \
                         as a refused grant: `hops cli authorize-key` reads any notice \
                         that does as its own grant refused. The app was told {refused:?}"
                    );

                    // No longer driven: once the quiet window has passed, a
                    // widening request on a third pairing is honoured.
                    let deadline = tokio::time::Instant::now() + DEADLINE;
                    while !trust.read().expect("lock").clipboard_from(&laptop_fp) {
                        assert!(
                            tokio::time::Instant::now() < deadline,
                            "turning a clipboard on was still refused long after the \
                             peer stopped driving"
                        );
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        app.exchange(&[R::EnableClipboard(laptop_fp.clone())]).await;
                    }
                    // Long enough for a confirmation that was honoured to have
                    // finished the pairing: the other machine's answer is read
                    // after the request is handled, not before.
                    assert!(
                        !granted(&trust).contains_key(&newcomer_fp),
                        "the number answered while a peer drove this machine finished \
                         the pairing"
                    );
                    let before = granted(&trust);
                    let waiting_before = waiting(&trust);

                    // Everything else, aimed where a widening would show.
                    let created = app.exchange(&[R::Create(new_device(nowhere))]).await;
                    let added = created
                        .iter()
                        .find_map(|e| match e {
                            FrontendEvent::Created(handle, ..) => Some(*handle),
                            _ => None,
                        })
                        .expect("a device added from the app is announced");
                    let others = every_other_request(&stranger_fp, &desk_fp, added, port, nowhere);
                    assert!(
                        !others.iter().any(widens),
                        "every_other_request holds a request that widens trust"
                    );
                    // Turning a clipboard on for a machine that is not paired,
                    // one prompting and one never seen, widens nothing either.
                    let unpaired = [
                        R::EnableClipboard(stranger_fp.clone()),
                        R::EnableClipboard(super::fp32(0x5f)),
                    ];
                    // One at a time, checked after each: a later request that
                    // narrows must not hide an earlier one that widened.
                    for request in unpaired.into_iter().chain(others) {
                        app.exchange(std::slice::from_ref(&request)).await;
                        let admitted: Vec<_> = waiting(&trust)
                            .difference(&waiting_before)
                            .cloned()
                            .collect();
                        assert!(
                            admitted.is_empty(),
                            "{request:?} approved {admitted:?} to compare a number. Only \
                             approving a prompt may."
                        );
                        let after = granted(&trust);
                        let widened: Vec<_> = after
                            .iter()
                            .filter(|(fp, caps)| {
                                !before.get(*fp).is_some_and(|b| b.contains(**caps))
                            })
                            .collect();
                        assert!(
                            widened.is_empty(),
                            "{request:?} widened trust: {widened:?} (before: {before:?}). \
                             Only approving a prompt, confirming its number, and turning \
                             on the clipboard of a paired machine, may. \
                             A same-user program holding the IPC token can send any of \
                             them, and the stated limit is that it can do exactly those \
                             things to trust, none while this machine is driven. Another \
                             is a new verb for that program; if one is genuinely \
                             needed, it goes through the driving check and into the \
                             stated limit in the same change."
                        );
                    }

                    // And the three that widen, do: the steps above could have
                    // seen a widening. An approval pairs once both machines
                    // confirm its number (#167).
                    app.exchange(&[
                        R::AuthorizeKey {
                            label: "new laptop".to_owned(),
                            fingerprint: stranger_fp.clone(),
                            controller: hops_ipc::Controller::ThatMachine,
                            clipboard: true,
                        },
                        R::EnableClipboard(desk_fp.clone()),
                        R::ConfirmPairing {
                            fingerprint: newcomer_fp.clone(),
                            number: comparing.number.clone(),
                        },
                    ])
                    .await;
                    let knocked = compare_number(&mut app, &stranger, port, &ours).await;
                    app.exchange(&[R::ConfirmPairing {
                        fingerprint: stranger_fp.clone(),
                        number: knocked.number.clone(),
                    }])
                    .await;
                    until_paired(&trust, &stranger_fp).await;
                    until_paired(&trust, &newcomer_fp).await;
                    let now = granted(&trust);
                    assert_eq!(
                        now.get(&newcomer_fp).copied(),
                        Some(Caps::INBOUND),
                        "confirming the number of an approval made while nobody drove \
                         this machine must pair the machine that knocked"
                    );
                    assert_eq!(
                        (now.get(&stranger_fp).copied(), now.get(&desk_fp).copied()),
                        (
                            Some(Caps::DRIVE_ME | Caps::CLIPBOARD_FROM),
                            Some(Caps::DRIVE_ME | Caps::CLIPBOARD_FROM)
                        ),
                        "approving the prompt as the machine that controls this one, \
                         with a yes to the clipboard, must pair it so and share the \
                         clipboard the way control goes (#220, #182); and turning the \
                         clipboard on must give the paired machine the clipboard its \
                         drive bits allow and nothing else"
                    );
                })
                .await;
        });
    }
}

mod every_trust_mutation_happens_at_a_named_door {
    //! **Decided 2026-08-30, and this replaces a guard that had gone silent.**
    //!
    //! `nothing_outside_the_named_doors_writes_the_allowlist` and its denylist
    //! twin scan for `authorized_keys.write()`, `self.revoked.insert` and
    //! friends. Those fields no longer exist — the store became `self.trust` —
    //! so the needles match nothing in production source and the guards pass on
    //! an empty match set. `the_door_list_still_matches_reality` does not catch
    //! it, because it checks that the door FUNCTION NAMES still exist, not that
    //! the needles still match anything.
    //!
    //! The property still holds in fact. It is the canary that stopped singing.
    //!
    //! **Text invariant, deliberately**, for the same reason the original was:
    //! it is a statement about which functions in one file contain a call. The
    //! difference from the original is the canary below, which fails if the
    //! needle stops matching.

    const DOORS: &[&str] = &[
        "fn add_authorized_key",    // grant
        "fn remove_authorized_key", // removal: forgets the device (#184)
        "fn set_label",             // rename; refuses unknown fingerprints
        "fn handle_config_change",  // reload: the config file is a door too
        "fn new",                   // startup load
        // Added 2026-09-06 with the sweep. It is a door because it drops what
        // has lapsed, which is a trust change — but it is the one door no human
        // opens: it mints nothing, narrows only, and runs on a timer. Listed so
        // the addition is visible in the diff rather than discovered later.
        "fn sweep_lapsed_leases",
        // Added with the clipboard off switch (#182, #187). It narrows only,
        // dropping the clipboard bits of one lease, and needs no authority.
        "fn disable_clipboard",
        // Added with pick-the-number pairing (#11, #167). The one door that
        // makes an approval grant: both machines confirmed the number. It
        // cannot create a lease, only confirm one an approval here issued.
        "fn settle_pairing",
        // Drops a lease an approval here issued that was never confirmed:
        // a wrong pick, a cancel, a close, or no number in time. Narrows only.
        "fn forget_pairing",
        // Added with the on arm (#182, #107). It widens one lease's clipboard
        // to what its drive bits allow, and its caller refuses it while a peer
        // drives this machine.
        "fn enable_clipboard",
        // Added with #184. A paired machine removed this one and said so on a
        // live link that proved its identity, so this one forgets it too. It
        // narrows only, and only the pairing with the machine that said so.
        "fn forget_machine_that_removed_this_one",
    ];

    /// The needle a scan must actually find. If the store is renamed again,
    /// this fails and names the successor guard's job — instead of quietly
    /// passing forever like the one it replaces.
    const MUTATION: &str = "trust.write()";

    #[test]
    fn the_scan_for_trust_writes_still_matches_something() {
        let src = super::scan::code_only(include_str!("service.rs"));
        let found = src.matches(MUTATION).count();
        assert!(
            found > 0,
            "no production line in service.rs contains `{MUTATION}`, so every \
             guard built on that needle is now passing on an empty match set. \
             This is not hypothetical: the previous pair of door guards scanned \
             for `authorized_keys.write()` and `self.revoked.insert`, both of \
             which stopped existing when the trust store was rewritten, and all \
             three tests stayed green through a full suite run. Find the new \
             mutation primitive and update MUTATION in the same commit."
        );
    }

    #[test]
    fn nothing_outside_the_named_doors_mutates_the_trust_store() {
        let src = super::scan::code_only(include_str!("service.rs"));
        let mut offenders = Vec::new();
        for (at, _) in src.match_indices(MUTATION) {
            let f = super::scan::enclosing_fn(&src, at);
            if !DOORS.iter().any(|d| f.starts_with(d)) {
                offenders.push(f);
            }
        }
        assert!(
            offenders.is_empty(),
            "these mutate the trust store and are not a named door: {offenders:?}. \
             Trust must change in one place. This matters more than tidiness: \
             the earlier version of this rule — 'one allowlist READER' — failed \
             on its first run against a third reader nobody had counted, after \
             two reviews had already missed it. If a new door is genuinely \
             needed, add it to DOORS in the same commit as the code, so the \
             addition is visible in the diff."
        );
    }
}

// ---------------------------------------------------------------------------
// discovery is a convenience plane, never a precondition and never trust
// ---------------------------------------------------------------------------

mod discovery_can_fail_without_taking_anything_with_it {
    //! **Decided 2026-09-01.** mDNS failing to start logs and the daemon
    //! continues; no pairing, connection, or startup path requires discovery to
    //! have succeeded.
    //!
    //! **Decided 2026-07-24.** A discovery result is only ever an untrusted
    //! candidate address to dial. An advertised fingerprint may never be
    //! written to the allowlist, may never let a connection skip an approval,
    //! and may never be the reason a peer is trusted.
    //!
    //! **Why.** Anything on the LAN can advertise `_hops._udp.local.` with any
    //! fingerprint it likes, including one copied from a real machine. mDNS is
    //! unauthenticated by construction, so a discovery path that can grant
    //! trust is a LAN-wide takeover primitive. "It's already on the network,
    //! just connect to it" is the shape this comes back in.

    use crate::discovery::{DiscoveredPeer, Discovery, merge, peer_key};
    use crate::trust::TrustStore;

    use super::fp32;

    /// Calls the constructor. Its return type is the guarantee: `Option`, not
    /// `Result` — there is no error for a caller to propagate with `?`, so a
    /// startup path cannot accidentally become conditional on discovery.
    #[test]
    fn switching_discovery_off_yields_a_daemon_that_still_starts() {
        let off: Option<Discovery> = Discovery::new(false, 4242, &fp32(0x01), "this machine");
        assert!(
            off.is_none(),
            "discovery disabled in config must yield None rather than a running \
             responder — one config line is meant to switch the whole plane off."
        );
        // The type-level half: if this ever becomes Result, `?` appears at the
        // call site and one network that drops multicast makes hops unable to
        // pair at all. Discovery is a convenience plane; the trust plane must
        // not depend on it.
        let _: Option<Discovery> = off;
    }

    /// The trust-plane separation, checked by driving every discovery helper
    /// that touches a peer record and then asking the store what it permits.
    ///
    /// This is the check the existing coverage does not make: the two guards
    /// nearest this boundary are source scans over `service.rs`'s own text and
    /// cannot say anything about what a discovered fingerprint does to a store.
    #[test]
    fn an_advertised_fingerprint_grants_nothing_no_matter_how_it_is_handled() {
        let ours = fp32(0x01);
        let impersonated = fp32(0xee);
        let store = TrustStore::new(&ours, 0).expect("our own fingerprint");

        // A hostile advertisement claiming a fingerprint it does not hold.
        let mut claim = DiscoveredPeer {
            claimed_fingerprint: Some(impersonated.clone()),
            label: "totally the office mac".to_string(),
            addrs: vec!["10.0.0.9:4242".parse().expect("addr")],
        };
        let second = DiscoveredPeer {
            claimed_fingerprint: Some(impersonated.clone()),
            label: "totally the office mac (2)".to_string(),
            addrs: vec!["10.0.0.10:4242".parse().expect("addr")],
        };

        let _ = peer_key(&claim);
        let _ = merge(&mut claim, second);

        assert!(
            !store.is_known(&impersonated),
            "handling a discovery advertisement put its claimed fingerprint into \
             the trust store. Anything on the LAN can advertise \
             _hops._udp.local. with any fingerprint it likes, including one \
             copied off a real machine — mDNS is unauthenticated by \
             construction. A discovery path that can grant trust is a LAN-wide \
             takeover primitive, which is why auto-connect was killed."
        );
        assert!(
            !store.may_drive_us(&impersonated) && !store.we_may_drive(&impersonated),
            "a discovered peer ended up permitted in some direction. Identity is \
             decided in exactly one place: the certificate presented during the \
             QUIC handshake. A discovery result is a candidate ADDRESS to dial \
             and nothing else."
        );
    }

    /// The half the test above cannot reach, and the reason it is needed.
    ///
    /// Driving today's helpers proves today's helpers grant nothing. It says
    /// nothing about a helper added next month — which is the actual risk,
    /// because "it's already on the network, just connect to it" is the shape
    /// this comes back in. So this asserts the weaker but wider property: the
    /// discovery module cannot even NAME the trust vocabulary, so a path from
    /// an advertisement to a grant cannot be written here without deleting this
    /// guard first.
    ///
    /// A source fact about one module's API, scanned over `discovery.rs` and
    /// never over this file.
    #[test]
    fn the_discovery_module_cannot_reach_the_trust_store_at_all() {
        let code = super::scan::code_only(include_str!("discovery.rs"));
        for reach in ["TrustStore", "Caps::", "issue(", "authorized"] {
            assert!(
                !code.contains(reach),
                "src/discovery.rs now references `{reach}`. Discovery is a \
                 convenience plane, deliberately separate from the trust plane. \
                 Anything on the LAN can advertise _hops._udp.local. with any \
                 fingerprint it likes, including one copied off a real machine, \
                 so a discovery path that can grant trust is a LAN-wide takeover \
                 primitive — which is why auto-connect was killed by the review \
                 that shaped this design. An advertised fingerprint is a CLAIM. \
                 The only thing a discovery result may become is a candidate \
                 address to dial; identity stays decided by the certificate \
                 presented during the QUIC handshake."
            );
        }
    }
}

mod typing_an_address_still_pairs_a_device {
    //! **Decided 2026-09-01.** Typing a peer's address remains a working way to
    //! pair a device, and no discovery work removes it or puts a precondition
    //! in front of it.
    //!
    //! **Why, with the measurement.** The "easy" path measured harder than the
    //! fallback: the pairing code, since retired (#14), was 228-415 characters
    //! and needed a text channel between two machines that do not yet share a
    //! keyboard — which is the thing being set up. Typing an address is 15
    //! characters. User flows are a fallback ladder, and the bottom rung is the
    //! one that always works.

    use crate::client::ClientManager;
    use hops_ipc::Position;

    /// Calls the client model with nothing but a typed address — no discovery
    /// result, no fingerprint known in advance — and checks a
    /// dialable client comes out the far side.
    #[test]
    fn a_client_can_be_created_from_a_typed_address_alone() {
        let clients = ClientManager::default();
        let handle = clients.add_client();

        clients.set_fix_ips(handle, vec!["10.0.0.42".parse().expect("a typed address")]);
        clients.set_port(handle, 4242);
        clients.set_pos(handle, Position::Right);
        let activated = clients.activate_client(handle);

        assert!(
            activated,
            "a client built from a typed address alone could not be activated. \
             Manual entry is the bottom rung of the pairing ladder and nothing \
             may be put in front of it — the measured alternative is a 228-415 \
             character code that needs a text channel between two machines that \
             do not yet share a keyboard."
        );

        let (config, state) = clients.get_state(handle).expect("the client exists");
        assert!(
            config.fix_ips.contains(&"10.0.0.42".parse().expect("addr")),
            "the typed address did not survive into the client's config"
        );
        assert!(
            state.active,
            "the client is not active, so nothing will dial it"
        );
        assert!(
            state.peer_fingerprint.is_none(),
            "a freshly typed address must NOT carry a fingerprint. Requiring one \
             up front would make manual entry depend on already knowing the \
             peer's identity — which is a precondition, and the whole point of \
             the bottom rung is that it has none. The fingerprint is learned and \
             pinned on the first dial."
        );
    }
}

// ---------------------------------------------------------------------------
// where security mechanisms may and may not live; what may be claimed
// ---------------------------------------------------------------------------

mod no_security_mechanism_lives_where_it_cannot_be_tested {
    //! **Decided 2026-08-30.** No trust, allowlist, or consent decision is
    //! taken inside `crates/input-capture`.
    //!
    //! **Why.** `macos.rs`, `layer_shell.rs` and `windows/event_thread.rs` have
    //! zero tests and structurally cannot get CI ones — they need a real
    //! display server, a real HID stack, and a real user session. A mechanism
    //! placed there is unverifiable forever. This is why the swallowed-input
    //! consent gate was rejected despite being the strongest primitive found.
    //!
    //! **Two instruments, both about facts rather than behaviour**: the crate's
    //! manifest (a dependency fact, read from `Cargo.toml`) and its source text.
    //! There is nothing to call, because the rule is that a certain kind of code
    //! is ABSENT — and you cannot call code that is not there.

    #[test]
    fn input_capture_does_not_even_depend_on_the_trust_machinery() {
        let manifest = include_str!("../crates/input-capture/Cargo.toml");
        for crate_name in ["hops-ipc", "rustls", "sha2", "rcgen", "quinn"] {
            assert!(
                !manifest.contains(crate_name),
                "crates/input-capture now depends on `{crate_name}`. Trust, \
                 identity and consent decisions may not be taken in that crate: \
                 its platform backends have zero tests and structurally cannot \
                 get CI ones, so anything decided there is unverifiable forever. \
                 A dependency on the trust machinery is how the decision arrives."
            );
        }
    }

    #[test]
    fn no_trust_vocabulary_appears_in_input_capture_source() {
        let code = super::scan::code_only(include_str!("../crates/input-capture/src/lib.rs"));
        for word in ["authorized", "allowlist", "revoke", "fingerprint"] {
            assert!(
                !code.contains(word),
                "crates/input-capture/src/lib.rs mentions `{word}` in executable \
                 code. A consent or trust decision taken here can never be \
                 covered by a test — the backends need a display server and a \
                 live user session — so it would be a security mechanism nobody \
                 can ever prove works. Move the decision to the trust service \
                 and pass this crate a plain signal."
            );
        }
    }
}

mod the_project_claims_only_what_it_can_defend {
    //! **Decided 2026-08-30.** No shipped string, doc, or release note claims
    //! that a human physically typed something, or that the core is privileged.
    //!
    //! **Why, measured.** `kCGEventSourceStateID` was forged two ways from an
    //! unprivileged process, including rewriting the source PID after the fact.
    //! The binary is mode 755 owned by the same account it protects, so what
    //! hops has is a remote-and-renderer control, not a privilege boundary. The
    //! defensible claim is that a compromised browser page or a remote peer
    //! cannot grant trust.
    //!
    //! **This is a text invariant by nature**: the rule is about the words that
    //! ship. It scans product source and the public docs — never this file.

    #[test]
    fn nothing_shipped_claims_a_privilege_boundary_this_binary_does_not_have() {
        const FORBIDDEN: &[&str] = &[
            "physically typed",
            "physically present at the keyboard",
            "the privileged core",
            "a privileged process",
            "proves a human",
            "proof that a human",
        ];
        const SOURCES: &[(&str, &str)] = &[
            ("src/service.rs", include_str!("service.rs")),
            ("src/trust.rs", include_str!("trust.rs")),
            ("src/transport.rs", include_str!("transport.rs")),
            ("README.md", include_str!("../README.md")),
            ("NOTICE.md", include_str!("../NOTICE.md")),
        ];

        let mut offenders = Vec::new();
        for (file, src) in SOURCES {
            for needle in FORBIDDEN {
                for (line, text) in super::scan::hits(src, needle) {
                    offenders.push(format!("{file}:{line} — {text}"));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "shipped text overclaims the trust boundary:\n    {}\n\n\
             kCGEventSourceStateID was forged two ways from an UNPRIVILEGED \
             process, including rewriting the source PID after the fact, and the \
             binary is mode 755 owned by the same account it protects. So hops \
             cannot claim a human typed anything, and cannot call its core \
             privileged. What it CAN claim, and what it should say instead, is \
             that a compromised browser page or a remote peer cannot grant \
             trust. An overclaim in a security product is worse than silence: it \
             tells a user a control exists that does not.",
            offenders.join("\n    ")
        );
    }
}

// ---------------------------------------------------------------------------
// the wire contract, and the names that must never be tidied
// ---------------------------------------------------------------------------

mod the_wire_contract_is_frozen {
    //! **Decided 2026-07-04.** The wire ALPN stays the exact byte string
    //! `grabbr-hop/1`.
    //!
    //! **Amended 2026-09-26 (#15).** A second ALPN, `grabbr-hop/1-driven`,
    //! sits beside it, for a machine that dials the machine that controls it,
    //! so each side knows its role when the handshake ends. A v0.12 peer
    //! refuses it. The two are the whole list a listener serves.
    //!
    //! **Decided 2026-07-28, corrected 2026-09-15 (#16).** Traversal is about
    //! connection direction, not the port, so 443 may never be scheduled as a
    //! traversal requirement. The default port moves from 4242, inherited from
    //! upstream, to 4722, in the same release as #15, as one breaking change.
    //!
    //! **Decided 2026-08-24.** Capability flag bits are never reassigned or
    //! removed, and a peer that advertises no capabilities is handled as having
    //! none rather than refused.
    //!
    //! **Why the ALPN in particular.** It looks like leftover branding to
    //! anyone tidying up after the rename, and it is load-bearing: renaming it
    //! means two peers never complete a handshake unless both ends are rebuilt
    //! and redeployed together — a silent, total outage with no error that
    //! names the cause. `src/transport.rs` carries this warning in a doc
    //! comment, and a comment is not a guard.

    /// Reads the real constant. The value IS the rule.
    #[test]
    fn the_alpn_is_still_the_exact_byte_string_two_peers_agreed_on() {
        assert_eq!(
            crate::transport::ALPN,
            b"grabbr-hop/1",
            "the wire ALPN changed. This is a protocol identifier, not a display \
             name: every already-deployed peer offers the old string, so a \
             rename means no handshake completes anywhere until both ends are \
             rebuilt and redeployed together — a total outage whose error \
             message names TLS, not the rename. If this is a deliberate protocol \
             bump, bump the version suffix and say so in the release notes."
        );
    }

    /// The consequence, demonstrated rather than asserted: a peer offering a
    /// different ALPN cannot complete a handshake with a peer offering ours.
    ///
    /// This is what makes the constant-equality test above meaningful — it
    /// proves the string is load-bearing rather than decorative, so nobody can
    /// argue the freeze is superstition.
    ///
    /// **What it does not prove.** `listen::server_config` and
    /// `connect::client_config` are private, so this builds both ends itself
    /// from `transport::ALPN`. It therefore demonstrates the CONSEQUENCE of a
    /// rename; the test above is what pins the production value, and
    /// `the_production_listener_completes_a_handshake_for_the_two_alpns_and_no_other`
    /// runs the real server config.
    #[test]
    fn a_peer_offering_a_different_alpn_cannot_complete_a_handshake() {
        use crate::transport::{self, FpClientVerifier, FpServerVerifier};
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use quinn::{ClientConfig, Endpoint, ServerConfig};
        use std::net::SocketAddr;
        use std::sync::{Arc, Mutex, RwLock};
        use std::time::Duration;

        transport::install_crypto_provider();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        rt.block_on(async {
            let server = super::a_test_identity();
            let client = super::a_test_identity();
            let server_fp = transport::fingerprint_of(&server.cert);
            let client_fp = transport::fingerprint_of(&client.cert);

            // Both ends trust each other outright, so the ONLY thing that can
            // refuse the handshake is the protocol name.
            let server_trust = {
                let mut s = crate::trust::TrustStore::new(&server_fp, 0).expect("ours");
                s.issue_confirmed(&client_fp, "peer", crate::trust::Caps::KNOWN)
                    .expect("issue");
                Arc::new(RwLock::new(s))
            };
            let client_trust = {
                let mut s = crate::trust::TrustStore::new(&client_fp, 0).expect("ours");
                s.issue_confirmed(&server_fp, "peer", crate::trust::Caps::KNOWN)
                    .expect("issue");
                Arc::new(RwLock::new(s))
            };

            let mut server_crypto = rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(FpClientVerifier::new(
                    server_trust,
                    Arc::new(Mutex::new(None)),
                )))
                .with_single_cert(vec![server.cert.clone()], server.key.clone_key())
                .expect("server cert");
            server_crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
            let server_cfg = ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(server_crypto).expect("quic server"),
            ));
            let endpoint = Endpoint::server(
                server_cfg,
                "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
            )
            .expect("server endpoint");
            let addr = endpoint.local_addr().expect("local addr");
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let _ = incoming.await;
                }
            });

            let dial = |alpn: Vec<u8>| {
                let mut crypto = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(FpServerVerifier::new(
                        client_trust.clone(),
                        Arc::new(Mutex::new(None)),
                    )))
                    .with_client_auth_cert(vec![client.cert.clone()], client.key.clone_key())
                    .expect("client auth");
                crypto.alpn_protocols = vec![alpn];
                let cfg = ClientConfig::new(Arc::new(
                    QuicClientConfig::try_from(crypto).expect("quic client"),
                ));
                let mut ep = Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().expect("addr"))
                    .expect("client endpoint");
                ep.set_default_client_config(cfg);
                ep
            };

            let matching = dial(transport::ALPN.to_vec());
            let ok = tokio::time::timeout(
                Duration::from_secs(5),
                matching.connect(addr, "grabbr").expect("connect"),
            )
            .await;
            assert!(
                matches!(ok, Ok(Ok(_))),
                "two peers offering the SAME ALPN could not complete a \
                 handshake, so this test proves nothing about renaming it. \
                 Fix the harness before trusting the assertion below."
            );

            let renamed = dial(b"hops/1".to_vec());
            let bad = tokio::time::timeout(
                Duration::from_secs(5),
                renamed.connect(addr, "grabbr").expect("connect"),
            )
            .await;
            assert!(
                !matches!(bad, Ok(Ok(_))),
                "a peer offering `hops/1` completed a handshake against a peer \
                 offering `{}`. Either the ALPN is no longer enforced — in which \
                 case a stray QUIC peer can reach this daemon — or someone has \
                 started accepting both names during a rename, which is the \
                 halfway state that turns a protocol bump into a silent \
                 downgrade.",
                String::from_utf8_lossy(transport::ALPN)
            );
        });
    }

    /// Reads the real constants. The values ARE the rule.
    #[test]
    fn the_quic_listen_port_is_4722_and_the_alpns_are_the_pair_both_ends_serve() {
        assert_eq!(
            hops_ipc::DEFAULT_PORT,
            4722,
            "the default QUIC port moved off 4722. It moved from 4242 once, in the \
             release that let a controlled machine dial out (#15, #16), as one \
             breaking change both machines take together. It is above 1024, so \
             either machine binds it unprivileged. If it moved to 443 to 'fix \
             traversal', that fixes nothing: traversal was MEASURED to be about \
             connection direction, not the port."
        );
        assert_eq!(
            hops_ipc::PORT_BEFORE_V013,
            4242,
            "the port older versions listened on is what a dial that finds nothing \
             asks, to say an older hops is there. It is a fact about v0.12, not a \
             setting."
        );
        assert_eq!(
            crate::transport::ALPN_DRIVEN,
            b"grabbr-hop/1-driven",
            "the ALPN a controlled machine dials with changed. Like grabbr-hop/1, \
             it is a wire identifier every deployed peer must match byte for byte."
        );
        assert_eq!(
            crate::transport::served_alpns(),
            vec![
                crate::transport::ALPN.to_vec(),
                crate::transport::ALPN_DRIVEN.to_vec()
            ],
            "a listener serves exactly the two ALPNs, the forward one first. The \
             order is how rustls chooses for a client offering both, and the \
             certificate resolver mirrors it to pick the question the TLS door \
             asks: a third, or a new order, changes which question is asked."
        );
    }

    /// The consequence, on the production listener config: a dialler
    /// offering either ALPN completes a handshake, and one offering anything
    /// else does not.
    #[test]
    fn the_production_listener_completes_a_handshake_for_the_two_alpns_and_no_other() {
        use crate::transport::{self, Dialler};
        use std::net::SocketAddr;
        use std::sync::{Arc, Mutex, RwLock};
        use std::time::Duration;

        transport::install_crypto_provider();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let server = super::a_test_identity();
            let client = super::a_test_identity();
            let server_fp = transport::fingerprint_of(&server.cert);
            let client_fp = transport::fingerprint_of(&client.cert);
            let trusting = |ours: &str, theirs: &str| {
                let mut s = crate::trust::TrustStore::new(ours, 0).expect("ours");
                s.issue_confirmed(theirs, "peer", crate::trust::Caps::KNOWN)
                    .expect("issue");
                Arc::new(RwLock::new(s))
            };
            let cfg = crate::listen::server_config(
                &server,
                trusting(&server_fp, &client_fp),
                Default::default(),
            )
            .expect("the production server config");
            let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().expect("addr"))
                .expect("server endpoint");
            let addr = endpoint.local_addr().expect("local addr");
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            conn.closed().await;
                        }
                    });
                }
            });
            let client_trust = trusting(&client_fp, &server_fp);
            let dial = |alpn: &[u8], role: Dialler| {
                let mut crypto = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(
                        transport::FpServerVerifier::for_role(
                            client_trust.clone(),
                            Arc::new(Mutex::new(None)),
                            role,
                        ),
                    ))
                    .with_client_auth_cert(vec![client.cert.clone()], client.key.clone_key())
                    .expect("client auth");
                crypto.alpn_protocols = vec![alpn.to_vec()];
                let cfg = quinn::ClientConfig::new(Arc::new(
                    quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic client"),
                ));
                let ep =
                    quinn::Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().expect("addr"))
                        .expect("client endpoint");
                (ep, cfg)
            };
            for (alpn, role, completes) in [
                (transport::ALPN, Dialler::Drives, true),
                (transport::ALPN_DRIVEN, Dialler::IsDriven, true),
                (&b"grabbr-hop/2"[..], Dialler::Drives, false),
                (&b"hops/1"[..], Dialler::Drives, false),
            ] {
                let (ep, cfg) = dial(alpn, role);
                let done = tokio::time::timeout(
                    Duration::from_secs(5),
                    ep.connect_with(cfg, addr, "grabbr").expect("connect"),
                )
                .await;
                assert_eq!(
                    matches!(done, Ok(Ok(_))),
                    completes,
                    "a dialler offering `{}` {} a handshake with the production \
                     listener",
                    String::from_utf8_lossy(alpn),
                    if completes {
                        "could not complete"
                    } else {
                        "completed"
                    }
                );
            }
        });
    }

    /// Reads the real constants. Append-only means the VALUES are the contract,
    /// not just the names.
    #[test]
    fn capability_bits_keep_the_values_already_on_the_wire() {
        use hops_proto::caps;

        assert_eq!(
            caps::ABSOLUTE_MOTION,
            1 << 0,
            "ABSOLUTE_MOTION changed value. Capability bits are a permanent wire \
             contract: a peer running last month's build advertises the old bit \
             and would now be read as advertising a different feature — so it \
             gets sent events it silently drops. Only ever APPEND."
        );
        assert_eq!(
            caps::TRUELOOP_REPORT,
            1 << 1,
            "TRUELOOP_REPORT changed value. See above — reassigning a bit is \
             indistinguishable, on the wire, from a peer lying about what it \
             supports."
        );
        assert_eq!(
            caps::ABSOLUTE_MOTION & caps::TRUELOOP_REPORT,
            0,
            "two capability bits now overlap, so advertising one advertises the \
             other. Each bit must be its own power of two."
        );
    }

    /// Silence is not rejection. An older peer that predates the handshake
    /// sends no `Capability` at all, which must read as "no bits set" rather
    /// than as a reason to refuse it.
    #[test]
    fn a_peer_that_advertises_nothing_is_read_as_having_no_capabilities() {
        use hops_proto::{MAX_EVENT_SIZE, ProtoEvent, caps};

        let (buf, _len): ([u8; MAX_EVENT_SIZE], usize) = ProtoEvent::Capability { flags: 0 }.into();
        let decoded = ProtoEvent::try_from(buf).expect(
            "a Capability event advertising nothing must DECODE. If silence is a \
             parse error, every peer built before the handshake existed breaks \
             on upgrade — and the capability channel is the only way a sender \
             can declare its conventions.",
        );
        match decoded {
            ProtoEvent::Capability { flags } => {
                assert_eq!(flags, 0);
                assert_eq!(
                    flags & caps::ABSOLUTE_MOTION,
                    0,
                    "an empty advertisement read as supporting a feature"
                );
            }
            other => panic!("Capability decoded as {other:?}"),
        }

        // Forward compatibility: a bit this build has never heard of must
        // survive the round trip rather than being rejected, or a NEWER peer
        // cannot talk to this one either.
        let future = 1u32 << 30;
        let (buf, _len): ([u8; MAX_EVENT_SIZE], usize) =
            ProtoEvent::Capability { flags: future }.into();
        match ProtoEvent::try_from(buf)
            .expect("an unknown capability bit must not be a parse error")
        {
            ProtoEvent::Capability { flags } => assert_eq!(
                flags, future,
                "an unrecognised capability bit was altered in transit. Append-only \
                 only works if a build passes through bits it does not understand."
            ),
            other => panic!("Capability decoded as {other:?}"),
        }
    }
}

mod the_transport_and_the_state_directory_keep_their_names {
    //! **Decided 2026-07-24.** hops speaks QUIC and only QUIC; a TCP/TLS-443
    //! fallback is a separate transport initiative and is never folded into
    //! device-model, discovery, or traversal work.
    //!
    //! **Decided 2026-07-28.** Corporate traversal is reversed connection
    //! direction and nothing else: no TCP transport, no move to 443, no
    //! privileged-port or socket-activation work, no static route.
    //!
    //! **Decided 2026-07-04.** On-disk state stays under `~/.config/lan-mouse/`.
    //!
    //! **Why QUIC-only.** A second transport doubles the surface where trust is
    //! enforced, and enforcement living in exactly one place per direction is
    //! what the TLS-resumption defect taught. Every argument for TCP so far has
    //! been a traversal argument, and traversal was measured to be about
    //! connection direction, not protocol.
    //!
    //! **Why the directory name.** It looks like leftover branding. Renaming it
    //! orphans every existing config, theme, trust file and edge-state file on
    //! every paired machine — and the six sites that compute it are independent
    //! string literals in five crates with no shared constant, so a PARTIAL
    //! rename leaves five of them green.

    /// Behavioural: calls the one state-directory helper that is public, and
    /// checks the frozen component is actually in the path it returns.
    #[test]
    fn the_ipc_token_still_lands_in_the_frozen_state_directory() {
        let Ok(path) = hops_ipc::token::token_path() else {
            // No HOME / no XDG_CONFIG_HOME / no LOCALAPPDATA. Nothing to check,
            // and failing here would make the guard about the environment.
            return;
        };
        assert!(
            path.components()
                .any(|c| c.as_os_str() == std::ffi::OsStr::new("lan-mouse")),
            "the IPC token no longer lands under a `lan-mouse` directory: {}. \
             The on-disk state directory is frozen. Renaming it to match the \
             product orphans every existing config, theme, trust file and \
             edge-state file on every already-paired machine — silently, with \
             the daemon coming up looking freshly installed.",
            path.display()
        );
        assert!(
            path.parent()
                .is_some_and(|p| p.file_name() == Some(std::ffi::OsStr::new("lan-mouse"))),
            "the token is under `lan-mouse` but not directly inside it: {}. The \
             token must sit beside config.toml — deliberately NOT beside the \
             socket, because on macOS the socket lives under ~/Library/Caches, \
             which the OS may purge; a token that vanishes while the daemon \
             still holds it in memory locks every frontend out with no obvious \
             cause.",
            path.display()
        );
    }

    /// **Text invariant, and the reason it has to be one is the finding.** Five
    /// of the six sites that compute this directory are private helpers in
    /// other crates with no public accessor, so there is nothing to call. That
    /// is itself the defect: one frozen name, six independent literals, one
    /// behavioural test. Until they share a constant, this is the only
    /// instrument that can see a partial rename.
    #[test]
    fn every_site_that_computes_the_state_directory_still_spells_it_lan_mouse() {
        const SITES: &[(&str, &str)] = &[
            ("src/config.rs", include_str!("config.rs")),
            (
                "crates/hops-ipc/src/token.rs",
                include_str!("../crates/hops-ipc/src/token.rs"),
            ),
            (
                "crates/hops-frontend-core/src/prefs.rs",
                include_str!("../crates/hops-frontend-core/src/prefs.rs"),
            ),
            (
                "crates/hops-frontend-core/src/theme.rs",
                include_str!("../crates/hops-frontend-core/src/theme.rs"),
            ),
        ];
        for (file, src) in SITES {
            assert!(
                super::scan::code_only(src).contains("lan-mouse"),
                "{file} no longer names the frozen state directory. There are \
                 FOUR independent literals for one directory across three \
                 crates, and only one of them (the IPC token path) has a \
                 behavioural test — so a partial rename leaves the others green \
                 while config, themes, the trust file and edge state each land \
                 somewhere different. If you are consolidating these into a \
                 shared constant, that is the right fix: update this guard to \
                 assert the constant instead of deleting it."
            );
        }
    }

    /// Dependency and source fact: the root crate reaches the network over
    /// QUIC, and the only TCP in the tree is loopback IPC.
    #[test]
    fn the_only_network_transport_in_the_daemon_is_quic() {
        for (file, src) in [
            ("src/listen.rs", include_str!("listen.rs")),
            ("src/connect.rs", include_str!("connect.rs")),
            ("src/transport.rs", include_str!("transport.rs")),
        ] {
            let code = super::scan::code_only(src);
            for tcp in ["TcpListener", "TcpStream", "TcpSocket"] {
                assert!(
                    !code.contains(tcp),
                    "{file} now uses `{tcp}`. hops speaks QUIC and only QUIC. A \
                     second transport doubles the surface where trust is \
                     enforced, and enforcement living in exactly ONE place per \
                     direction is what the TLS-resumption defect taught — a \
                     resumed handshake skipped the fingerprint verifier entirely \
                     and a revoked sender was back one second after its session \
                     was cut. Every argument for TCP so far has been a traversal \
                     argument, and traversal was MEASURED to be about connection \
                     direction: the SASE client is stateful, blocking \
                     unsolicited inbound flows rather than ports. If TCP is ever \
                     built it gets its own decision, not a rider on someone \
                     else's."
                );
            }
        }
    }

    /// The traversal decision's negative half: none of the several-times-larger
    /// project it displaced has crept back in.
    #[test]
    fn no_traversal_workaround_was_built_instead_of_reversing_the_dial() {
        const SOURCES: &[(&str, &str)] = &[
            ("src/listen.rs", include_str!("listen.rs")),
            ("src/connect.rs", include_str!("connect.rs")),
            ("src/config.rs", include_str!("config.rs")),
            ("src/main.rs", include_str!("main.rs")),
        ];
        for (file, src) in SOURCES {
            let code = super::scan::code_only(src);
            for marker in [
                "CAP_NET_BIND",
                "setcap",
                "ip route add",
                "socket_activation",
            ] {
                assert!(
                    !code.contains(marker),
                    "{file} contains `{marker}`. Corporate traversal is reversed \
                     connection direction and NOTHING else — measured on the rig: \
                     the SASE network extension is stateful, so it blocks \
                     unsolicited INBOUND flows, not ports, and everything the \
                     managed machine itself initiated succeeded including UDP on \
                     an arbitrary port. An earlier version of that finding said \
                     '443 plus reversal'; it rested on one test contaminated by a \
                     self-inflicted static route, and it implied a project several \
                     times larger. Building any of it spends weeks on a cause \
                     measurement already refuted."
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// dependency-graph facts
// ---------------------------------------------------------------------------

mod the_dependency_graph_stays_buildable_on_a_managed_machine {
    //! **Decided 2026-07-06, twice.** No libgit2 anywhere in the dependency
    //! graph — the build commit is read by shelling out to `git rev-parse`. And
    //! one TOML library: no first-party crate declares a dependency on the
    //! `toml` crate.
    //!
    //! **Why libgit2.** On a corporate-managed Mac, an EDR agent flagged clang
    //! compiling libgit2's `credential.c`, pulled in transitively by
    //! `shadow-rs -> git2 -> libgit2-sys`. The only thing that dependency bought
    //! was a commit hash. Re-adding it for richer build metadata makes hops
    //! un-buildable on precisely the EDR-managed machines the traversal work
    //! exists to serve.
    //!
    //! **Why one TOML parser.** `toml_edit` is required anyway for comment- and
    //! format-preserving config edits, so a second parser means two parsers that
    //! can disagree about the same file — and that file sits beside the trust
    //! store.
    //!
    //! These read manifests and the lockfile: dependency FACTS, not source text.

    #[test]
    fn no_libgit2_reaches_the_dependency_graph() {
        let lock = include_str!("../Cargo.lock");
        for pkg in ["libgit2-sys", "shadow-rs"] {
            assert!(
                !lock.contains(&format!("name = \"{pkg}\"")),
                "`{pkg}` is back in Cargo.lock. It pulls libgit2, whose \
                 credential.c an EDR agent flagged mid-compile on a managed Mac — \
                 making hops un-buildable on exactly the machines the corporate \
                 traversal work exists to serve. Everything that dependency \
                 bought was a commit hash, which build.rs gets by shelling out to \
                 `git rev-parse --short=8 HEAD`."
            );
        }
        assert!(
            !lock.contains("name = \"git2\"\n"),
            "`git2` is back in Cargo.lock — see above; it is the crate that \
             pulls libgit2-sys."
        );
    }

    #[test]
    fn the_build_commit_still_comes_from_shelling_out_to_git() {
        let build = super::scan::code_only(include_str!("../build.rs"));
        assert!(
            build.contains("rev-parse"),
            "build.rs no longer shells out to `git rev-parse` for the build \
             commit. The alternative is a crate that pulls libgit2, which an EDR \
             agent flags mid-compile on managed machines. If the fallback outside \
             a checkout stopped working, fix the fallback — do not take the \
             dependency."
        );
    }

    #[test]
    fn no_first_party_crate_declares_a_second_toml_parser() {
        const MANIFESTS: &[(&str, &str)] = &[
            ("Cargo.toml", include_str!("../Cargo.toml")),
            (
                "crates/hops-ipc/Cargo.toml",
                include_str!("../crates/hops-ipc/Cargo.toml"),
            ),
            (
                "crates/hops-cli/Cargo.toml",
                include_str!("../crates/hops-cli/Cargo.toml"),
            ),
            (
                "crates/hops-proto/Cargo.toml",
                include_str!("../crates/hops-proto/Cargo.toml"),
            ),
            (
                "crates/hops-frontend-core/Cargo.toml",
                include_str!("../crates/hops-frontend-core/Cargo.toml"),
            ),
            (
                "crates/hops-tui/Cargo.toml",
                include_str!("../crates/hops-tui/Cargo.toml"),
            ),
            (
                "crates/hops-slint/Cargo.toml",
                include_str!("../crates/hops-slint/Cargo.toml"),
            ),
            (
                "crates/input-capture/Cargo.toml",
                include_str!("../crates/input-capture/Cargo.toml"),
            ),
            (
                "crates/input-emulation/Cargo.toml",
                include_str!("../crates/input-emulation/Cargo.toml"),
            ),
            (
                "crates/input-event/Cargo.toml",
                include_str!("../crates/input-event/Cargo.toml"),
            ),
        ];
        for (file, manifest) in MANIFESTS {
            // A dependency line, not a mention: `toml_edit` and
            // `[package.metadata]` must not trip this.
            let declares_toml = manifest.lines().map(str::trim).any(|l| {
                (l.starts_with("toml ") || l.starts_with("toml=") || l.starts_with("toml\t"))
                    && !l.starts_with("toml_edit")
            });
            assert!(
                !declares_toml,
                "{file} declares a dependency on the `toml` crate. hops uses \
                 toml_edit everywhere — it is required anyway, for comment- and \
                 format-preserving config edits — so a second parser means two \
                 parsers that can disagree about one file, and that file sits \
                 beside the trust store. Note for whoever revisits this: `toml` \
                 IS present in Cargo.lock, pulled transitively under Slint, so a \
                 lockfile check would be wrong here; the rule is about what \
                 first-party crates DECLARE."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// the daemon's lifetime, and the tray
// ---------------------------------------------------------------------------

mod a_frontend_attaches_and_never_starts_a_daemon {
    //! **Decided 2026-06-28.** The TUI, the Slint GUI and the CLI attach to an
    //! already-running daemon over IPC and must never spawn, fork, launch or
    //! auto-start one; they retry connecting and report that nothing is there.
    //!
    //! **Amended 2026-09-16 (#159)** for the app's front door, `hops` with no
    //! subcommand, which may now start the service; see the next module. The
    //! frontend crates still attach only, and the test below holds them to it.
    //!
    //! **Why.** "Just start the daemon if it isn't running" is the most
    //! natural-looking UX improvement in this product and it is forbidden. The
    //! daemon holds the private identity key, the trust store, every
    //! input-emulation backend and the IPC socket. A frontend that can start it
    //! makes the highest-privilege process on the machine a UI-triggerable
    //! event, and makes daemon lifetime depend on whoever can talk to a
    //! frontend.

    /// The frontend crates themselves, checked as source facts: none of them
    /// contains process-spawning machinery at all.
    #[test]
    fn no_frontend_crate_contains_the_machinery_to_start_a_daemon() {
        const FRONTENDS: &[(&str, &str)] = &[
            (
                "crates/hops-cli",
                include_str!("../crates/hops-cli/src/lib.rs"),
            ),
            (
                "crates/hops-tui",
                include_str!("../crates/hops-tui/src/lib.rs"),
            ),
            (
                "crates/hops-slint",
                include_str!("../crates/hops-slint/src/lib.rs"),
            ),
        ];
        for (name, src) in FRONTENDS {
            let code = super::scan::code_only(src);
            for spawn in ["Command::new", "launchctl", "setsid", "CommandExt"] {
                assert!(
                    !code.contains(spawn),
                    "{name} contains `{spawn}`. A frontend attaches to a running \
                     daemon and never starts one. The daemon holds the private \
                     identity key, the trust store, every input-emulation backend \
                     and the IPC socket — a frontend that can start it makes the \
                     highest-privilege process on this machine a UI-triggerable \
                     event. If the user experience of 'nothing is running' is \
                     bad, fix the message, not the lifetime."
                );
            }
        }
    }
}

mod the_front_door_starts_a_daemon_only_when_none_answers {
    //! **Decided 2026-09-16 (#159), amending 2026-06-28.** `hops` with no
    //! subcommand may start the service when none is running: on Linux and
    //! Windows as a detached process, on macOS through the launchd service.
    //! The rule is "at most one daemon, started only when none answers".
    //!
    //! **Why a second one is not harmless.** Before #159 the Windows front door
    //! never asked whether a daemon was running: its probe answered "no"
    //! without connecting, so every launch started another `hops daemon`
    //! beside the one serving input, and that one loaded the identity key
    //! before it found the IPC port taken.
    //!
    //! **Amended 2026-09-26 (#222):** the app may also restart the service
    //! it installed when the daemon that answers is another build, or states
    //! none. That case, and nothing else, is guarded in the next module.
    //!
    //! The rule has two halves, tested where each one lives:
    //!
    //! * **Started only when none answers.** The decision, here, against real
    //!   listeners standing in for a daemon; and the front door's own probe
    //!   against the daemon's real listener on this platform's real endpoint,
    //!   in `tests/front_door_probe.rs`.
    //! * **At most one daemon.** A probe and a start are two steps, so a second
    //!   start can still happen: two launches together, or a login service
    //!   starting one meanwhile. The daemon's claim on its IPC endpoint settles
    //!   it before the config or any key is read (`hops-ipc` `listen.rs`,
    //!   `service.rs`, and `tests/second_daemon.rs` on the built binary).

    use crate::daemon_start::{DaemonStart, Watch, start_unless_running};
    use hops_ipc::{DaemonEndpoint, SocketPathError};
    use std::cell::Cell;
    use std::time::Duration;

    /// The process id the stand-in start reports.
    const STARTED: u32 = 4242;

    /// A started daemon that serves frontends at once. Waiting for a daemon to
    /// come up is tested in `daemon_start`; this module is about whether one
    /// is started at all.
    struct ServesAtOnce;

    impl Watch for ServesAtOnce {
        fn serves(&mut self, _: &DaemonEndpoint, _: Duration) -> bool {
            true
        }
        fn ended(&mut self, _: u32) -> bool {
            false
        }
        fn log_file(&self) -> Option<std::path::PathBuf> {
            None
        }
    }

    /// Run the front door's decision against `endpoint`, counting the starts
    /// it asks for.
    fn decide(endpoint: Result<DaemonEndpoint, SocketPathError>) -> (DaemonStart, u32) {
        let starts = Cell::new(0);
        let start = || {
            starts.set(starts.get() + 1);
            Ok(STARTED)
        };
        let outcome =
            start_unless_running(endpoint, start, &mut ServesAtOnce, Duration::from_secs(1));
        (outcome, starts.get())
    }

    /// A loopback port nothing listens on: bound and released in one statement.
    fn released_port() -> DaemonEndpoint {
        DaemonEndpoint::Tcp(
            std::net::TcpListener::bind("127.0.0.1:0")
                .and_then(|l| l.local_addr())
                .expect("a loopback port"),
        )
    }

    /// A socket path short enough for `sun_path` (about 104 bytes on macOS),
    /// unique to this test process.
    #[cfg(unix)]
    fn socket_path(tag: &str) -> std::path::PathBuf {
        let name = format!("hops-front-door-{tag}-{}.sock", std::process::id());
        let in_tmp = std::env::temp_dir().join(&name);
        if in_tmp.as_os_str().len() < 100 {
            in_tmp
        } else {
            std::path::Path::new("/tmp").join(name)
        }
    }

    /// A daemon answering on loopback TCP, the transport Windows used before
    /// its pipe, is left alone rather than a second started. Checked on every
    /// platform.
    // LEDGER T1 | class B | 1 return value
    #[test]
    fn a_daemon_answering_on_loopback_tcp_is_left_alone() {
        let daemon = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let endpoint = DaemonEndpoint::Tcp(daemon.local_addr().expect("its address"));

        let decided = decide(Ok(endpoint));
        drop(daemon);

        assert_eq!(
            decided,
            (DaemonStart::AlreadyRunning, 0),
            "a daemon was listening on its loopback TCP endpoint and the front \
             door still asked for another to be started. That is the Windows \
             front door before #159: its probe answered 'not running' without \
             connecting, so every launch started a second `hops daemon`."
        );
    }

    /// The macOS and Linux transport: a Unix socket.
    // LEDGER T2 | class B | 1 return value
    #[cfg(unix)]
    #[test]
    fn a_daemon_answering_on_its_unix_socket_is_left_alone() {
        let path = socket_path("live");
        let _ = std::fs::remove_file(&path);
        let daemon = std::os::unix::net::UnixListener::bind(&path).expect("a unix listener");

        let decided = decide(Ok(DaemonEndpoint::Unix(path.clone())));
        drop(daemon);
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            decided,
            (DaemonStart::AlreadyRunning, 0),
            "a daemon was listening on its Unix socket and the front door still \
             asked for another to be started. On macOS that can bootstrap the \
             launchd service beside a daemon started some other way; on Linux \
             it forks a second daemon."
        );
    }

    /// The other half of the rule: when nothing answers, the app may start the
    /// service, and asks for exactly one.
    // LEDGER T3 | class B | 1 return value
    #[test]
    fn with_nothing_answering_exactly_one_start_is_requested() {
        #[allow(unused_mut)] // only Unix adds cases
        let mut cases: Vec<(&str, DaemonEndpoint)> =
            vec![("a loopback port nothing listens on", released_port())];
        #[cfg(unix)]
        let stale = {
            let stale = socket_path("stale");
            let _ = std::fs::remove_file(&stale);
            // Dropping a listener leaves its file behind, as a crashed daemon does.
            drop(std::os::unix::net::UnixListener::bind(&stale).expect("a unix listener"));
            cases.push((
                "a socket file left by a daemon that is gone",
                DaemonEndpoint::Unix(stale.clone()),
            ));
            cases.push((
                "a socket path with no file at all",
                DaemonEndpoint::Unix(socket_path("absent")),
            ));
            stale
        };

        let decided: Vec<_> = cases
            .into_iter()
            .map(|(what, endpoint)| (what, decide(Ok(endpoint))))
            .collect();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&stale);

        for (what, got) in decided {
            assert_eq!(
                got,
                (DaemonStart::Started(STARTED), 1),
                "{what}: no daemon was answering, so the front door must ask for \
                 exactly one start. Asking for none leaves the app open onto a \
                 service that is not running."
            );
        }
    }

    /// With no `$HOME` or `$XDG_RUNTIME_DIR` there is nothing to ask. A daemon
    /// started from that environment fails on the same missing variable, so a
    /// start could only add a process that exits, while a daemon started
    /// elsewhere with its own environment may be running.
    // LEDGER T4 | class B | 1 return value
    #[test]
    fn an_endpoint_that_cannot_be_worked_out_starts_nothing() {
        let got = decide(Err(SocketPathError::HomeDirNotFound(
            std::env::VarError::NotPresent,
        )));
        assert_eq!(
            got,
            (DaemonStart::CannotProbe, 0),
            "the front door could not work out where a daemon listens, and still \
             asked for one to be started. That daemon cannot bind the endpoint \
             either, so it can only fail, and it may do so beside a daemon that \
             a login service started with its own environment."
        );
    }

    /// A start that fails is reported as failed, not as a start.
    // LEDGER T5 | class B | 1 return value
    #[test]
    fn a_start_that_fails_is_reported_as_failed() {
        let starts = Cell::new(0);
        let start = || {
            starts.set(starts.get() + 1);
            Err(std::io::Error::other("the executable is gone"))
        };
        let got = start_unless_running(
            Ok(released_port()),
            start,
            &mut ServesAtOnce,
            Duration::from_secs(1),
        );
        assert_eq!(
            (got, starts.get()),
            (DaemonStart::StartFailed, 1),
            "a start that failed was reported as a start. The front door then \
             opens onto a service that never started, and nothing says why."
        );
    }

    /// A backstop, as source text, for what the behavioural tests cannot call:
    /// `src/main.rs` itself. Running the binary's front door would start a real
    /// daemon or bootstrap the real launchd service.
    ///
    /// It checks two absences over the whole file with comments stripped (not
    /// cut at the first test module, which would hide product code placed after
    /// it): no process-launching machinery at all, and no call to `run_daemon`
    /// or `run_service` outside `run` and `run_daemon`. The in-process daemon
    /// `run` starts (for `hops daemon`, and for `hops` in a build without a
    /// frontend) is held to one instance by its endpoint claim, not by a probe.
    ///
    /// Paired with `tests/front_door_probe.rs`, which calls the decision
    /// `front_door` runs against the real listener.
    // LEDGER T11 | class S | source text
    #[test]
    fn main_rs_launches_no_process_and_runs_the_daemon_only_from_run() {
        let code = super::scan::without_comments(include_str!("main.rs"));
        for launch in ["Command::new", "launchctl", "setsid", "CommandExt", "spawn"] {
            assert!(
                !code.contains(launch),
                "src/main.rs contains `{launch}`. Starting the daemon belongs in \
                 src/daemon_start.rs, behind the check that none is already \
                 answering. A start added anywhere else can run beside a daemon \
                 that is serving input, and no test here would see it."
            );
        }
        for (call, allowed_in) in [("run_daemon(", "fn run"), ("run_service(", "fn run_daemon")] {
            let calls: Vec<usize> = code
                .match_indices(call)
                .map(|(at, _)| at)
                .filter(|&at| !code[..at].ends_with("fn "))
                .collect();
            assert!(
                !calls.is_empty(),
                "found no call to `{call}..)` in src/main.rs, so this check compared \
                 nothing. If the daemon's entry point moved, point the check there."
            );
            for at in calls {
                let caller = super::scan::enclosing_fn(&code, at);
                assert_eq!(
                    caller, allowed_in,
                    "src/main.rs calls `{call}..)` from `{caller}`. The daemon runs \
                     in-process only for `hops daemon`, or for `hops` in a build \
                     with no frontend. Anywhere else it starts beside the front \
                     door's own check."
                );
            }
        }
    }
}

mod the_front_door_restarts_only_an_outdated_service_it_installed {
    //! **Decided 2026-09-26 (#222), amending 2026-09-16 (#159).** The app may
    //! restart the service it installed when the daemon that answers is a
    //! different build from the app, or reports no build. A daemon of the same
    //! build is never restarted by the app, and a daemon the service did not
    //! start (one run from a terminal, say) is never restarted: the app says
    //! so instead.
    //!
    //! **Why.** An app replaced in place attaches to whatever daemon answers.
    //! Without this the previous release's daemon went on serving the new app
    //! until the next login, with its fixes, security fixes included, not
    //! running. And a restart is not free: it drops every connected peer and
    //! any key held on this machine, which is why a daemon of this build is
    //! never touched.

    use crate::daemon_start::{Origin, Verdict, verdict};
    use hops_ipc::{Build, StatedBuild};
    use std::cell::Cell;

    fn build(version: &str, commit: &str) -> Build {
        Build {
            version: version.into(),
            commit: commit.into(),
        }
    }

    /// The decision itself, for every kind of daemon that can answer.
    // LEDGER T2223 | class B | 1 return value: daemon_start::verdict
    #[test]
    fn only_another_build_that_the_service_started_is_restarted() {
        let this = build("0.13.0", "abcd123");
        let same = StatedBuild::Is(this.clone());
        let same_version_other_commit = StatedBuild::Is(build("0.13.0", "ffff000"));
        let older = StatedBuild::Is(build("0.12.0", "1111111"));
        let terminal = || Origin::Other("it was started from a terminal".into());

        let asked = Cell::new(0);
        let service = || {
            asked.set(asked.get() + 1);
            Origin::Service(4444)
        };
        assert_eq!(
            (verdict(&this, Some(&same), service), asked.get()),
            (Verdict::Keep, 0),
            "a daemon of this build must be kept without even asking who started \
             it. Restarting it drops every peer and every held key for nothing."
        );
        for (what, stated) in [
            (
                "another commit of the same version",
                &same_version_other_commit,
            ),
            ("an older release", &older),
            ("a daemon that states no build", &StatedBuild::Unstated),
        ] {
            assert_eq!(
                verdict(&this, Some(stated), || Origin::Service(4444)),
                Verdict::Restart(4444),
                "{what}, started by the hops service, was not restarted. It goes on \
                 serving the new app with the old build's code."
            );
            assert_eq!(
                verdict(&this, Some(stated), terminal),
                Verdict::LeaveOutdated("it was started from a terminal".into()),
                "{what}, NOT started by the hops service, must be left running with \
                 the reason: the app has no business stopping it."
            );
        }
        assert_eq!(
            verdict(&this, None, || Origin::Service(4444)),
            Verdict::Keep,
            "a daemon that said nothing may be one of this build still starting"
        );
    }

    /// A backstop over `src/daemon_start.rs` as source text, for what the
    /// behavioural tests cannot show: that nothing ELSE in the front door can
    /// stop a daemon. Every way of stopping one there (a launchd bootout,
    /// `stop`, `unload`, `remove` or `kill`, a `kickstart -k`, a signal, a
    /// `kill` command) must sit inside `stop_service_daemon`, whose
    /// callers are the restart of an outdated service and the reload of a
    /// rewritten plist. Scans product code with comments stripped, never this
    /// file. Paired with T2223 above and T2225 in `daemon_start`, which run the
    /// restart and the start against a scripted `launchctl`.
    // LEDGER T2226 | class S | source text | pair T2223, T2225
    #[test]
    fn nothing_but_the_one_stop_function_can_stop_a_daemon() {
        const ALLOWED_IN: &str = "fn stop_service_daemon";
        let code = super::scan::code_only(include_str!("daemon_start.rs"));
        assert!(
            code.contains(&format!("{ALLOWED_IN}(")),
            "`{ALLOWED_IN}` is gone from src/daemon_start.rs, so this check compares \
             nothing. If it was renamed, point the check at the new name."
        );
        for stop in [
            "bootout",
            "\"-k\"",
            "kickstart -k",
            "kill(",
            "\"kill\"",
            "\"stop\"",
            "\"unload\"",
            "\"remove\"",
            "pidfd_send_signal",
            "SIGTERM",
            "SIGKILL",
            "SIGINT",
            "SIGQUIT",
            "TerminateProcess",
            "taskkill",
        ] {
            for (at, _) in code.match_indices(stop) {
                let inside = super::scan::enclosing_fn(&code, at);
                assert_eq!(
                    inside, ALLOWED_IN,
                    "src/daemon_start.rs has `{stop}` in `{inside}`. The front door \
                     stops a daemon only through `stop_service_daemon`, to restart a \
                     service running another build or reload a rewritten plist. A \
                     stop anywhere else can end the daemon serving input, of this \
                     build, which the app must never restart."
                );
            }
        }
        let main = super::scan::without_comments(include_str!("main.rs"));
        for stop in ["bootout", "kill(", "SIGTERM", "TerminateProcess"] {
            assert!(
                !main.contains(stop),
                "src/main.rs has `{stop}`. Stopping a daemon belongs in \
                 `stop_service_daemon`, behind the build check."
            );
        }
    }
}

mod the_tray_is_the_toolkits_and_the_licence_is_upstreams {
    //! **Decided 2026-07-04, two rules.** The menu-bar/tray is declared in
    //! `.slint` using Slint's `SystemTrayIcon`; hops does not hand-write
    //! `NSStatusItem`, `Shell_NotifyIcon` or `StatusNotifierItem` FFI. And
    //! upstream authorship and lan-mouse's GPLv3 attribution stay in NOTICE.md
    //! and in file headers.
    //!
    //! **Why the tray.** One declarative tray plus callbacks gets the same Mac
    //! menu-bar model on Windows and Linux, maintained by the toolkit. Three
    //! hand-written platform trays is three platform bugs to own forever, on
    //! three OS versions this project does not all test on.
    //!
    //! **Why the attribution.** GPLv3 requires it and the repository is public.
    //! This is a licence obligation, not a courtesy — stripping it during a
    //! rename or a header cleanup is a licence violation on a public fork.
    //! Licence text is text; a scan is the correct instrument.

    #[test]
    fn the_tray_is_declared_with_slints_native_element_and_no_platform_ffi() {
        let tray = include_str!("../crates/hops-slint/ui/tray.slint");
        assert!(
            tray.contains("inherits SystemTrayIcon"),
            "the tray is no longer Slint's SystemTrayIcon. Hand-rolling \
             NSStatusItem, Shell_NotifyIcon and StatusNotifierItem is three \
             platform trays to own forever, on three OS versions this project \
             does not all test on — which is what the declarative element \
             replaced."
        );
        let code = super::scan::code_only(include_str!("../crates/hops-slint/src/lib.rs"));
        for ffi in ["NSStatusItem", "Shell_NotifyIcon", "StatusNotifierItem"] {
            assert!(
                !code.contains(ffi),
                "crates/hops-slint hand-writes `{ffi}`. See above: the toolkit \
                 maintains this across three platforms and hops does not."
            );
        }
    }

    #[test]
    fn upstream_authorship_and_the_gplv3_notice_are_still_shipped() {
        let notice = include_str!("../NOTICE.md");
        for required in ["feschber", "lan-mouse", "GNU General Public License"] {
            assert!(
                notice.contains(required),
                "NOTICE.md no longer mentions `{required}`. This is a GPLv3 \
                 obligation on a public fork, not a courtesy: stripping upstream \
                 attribution during a rename or a header cleanup is a licence \
                 violation. Original copyright also stays in the git history."
            );
        }
        const FORKED: &str = include_str!("../crates/input-emulation/src/macos.rs");
        assert!(
            FORKED.contains("lan-mouse"),
            "crates/input-emulation/src/macos.rs lost its upstream provenance \
             marker. Forked files keep their headers; see NOTICE.md."
        );
    }
}

// ---------------------------------------------------------------------------
// edge crossing has no user-facing knob
// ---------------------------------------------------------------------------

mod edge_crossing_is_never_a_setting_the_user_has_to_tune {
    //! **Decided 2026-07-07.** Cross-back is decided in the emulation layer
    //! from true pre-clamp motion and live display bounds accumulating into a
    //! per-edge pressure whose threshold self-tunes from regret — never by
    //! comparing cursor position against a barrier constant, and never by
    //! exposing a sensitivity setting.
    //!
    //! **Why no knob.** Every constant-based mitigation shifts with screen
    //! size, DPI and refresh rate, against an explicit constraint that screens
    //! vary. Adding a slider hands the user a problem the system is supposed to
    //! learn.
    //!
    //! The behavioural half of this rule — that the decision is made from
    //! blocked motion rather than from cursor position — lives beside the
    //! detector it tests, in `crates/input-emulation/src/macos.rs`, because
    //! `EdgePressureDetector::update` is private to that file. This half is
    //! about the *config surface*, which lives here.

    #[test]
    fn no_edge_sensitivity_knob_reaches_the_config_file_or_the_ui() {
        const SURFACES: &[(&str, &str)] = &[
            ("src/config.rs", include_str!("config.rs")),
            (
                "config.example.toml",
                include_str!("../config.example.toml"),
            ),
            (
                "crates/hops-slint/ui/app.slint",
                include_str!("../crates/hops-slint/ui/app.slint"),
            ),
        ];
        for (file, src) in SURFACES {
            for knob in ["edge_threshold", "edge_sensitivity", "crossing_sensitivity"] {
                assert!(
                    !src.contains(knob),
                    "{file} exposes `{knob}` as a user setting. Edge crossing is \
                     intent and momentum, learned from regret — not a number the \
                     user tunes. Every constant-based mitigation shifts with \
                     screen size, DPI and refresh rate, against an explicit \
                     constraint that screens vary, so a slider hands the user a \
                     problem the system is supposed to solve for them. The \
                     environment variables used for A/B measurement are \
                     deliberately NOT config keys and must stay that way."
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// shared fixtures
// ---------------------------------------------------------------------------

/// A throwaway self-signed identity, shaped like the ones `crypto::Identity`
/// loads. Mirrors the helper in `listen.rs`'s test module; duplicated rather
/// than exported, because a test fixture reaching into another module's private
/// test scope is how fixtures end up in production code.
fn a_test_identity() -> crate::crypto::Identity {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let mut params = rcgen::CertificateParams::new(vec!["grabbr".to_owned()]).expect("params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "grabbr-hop");
    let cert = params.self_signed(&key_pair).expect("self signed");
    crate::crypto::Identity {
        cert: cert.der().clone(),
        key: rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).expect("key der"),
    }
}

fn a_test_certificate() -> rustls::pki_types::CertificateDer<'static> {
    a_test_identity().cert
}

// ---------------------------------------------------------------------------
// the bundle declares what the code actually browses
// ---------------------------------------------------------------------------

mod discovery_is_declared_to_the_operating_system {
    //! **Decided 2026-09-06, after the fact.** The macOS bundle must declare
    //! every Bonjour service type the code browses, and must carry a Local
    //! Network usage string.
    //!
    //! **Why this is a rule and not a packaging detail.** Both keys were absent.
    //! macOS then permitted the outbound announcement and silently dropped every
    //! response: hops advertised itself correctly, discovered nothing, and
    //! rendered an empty list with no error on any surface. Launched from a
    //! terminal it worked, because it inherited the terminal's grant — so the
    //! failure only appeared in the deployment everyone actually uses, and
    //! looked unreproducible for weeks.
    //!
    //! `NSBonjourServices` is the trap. Recent macOS requires an app to declare
    //! the service types it browses; without the declaration the browse is
    //! blocked whether or not Local Network is granted, and NO PROMPT IS EVER
    //! SHOWN — so there is nothing in System Settings for a user to switch on.
    //!
    //! This is the cross-fragment class: two files, each internally consistent,
    //! disagreeing. A test of either alone sees nothing wrong.

    /// The ONE generator both the release bundle and the dev launcher use.
    /// Pointing the guard at the shared script rather than the release path is
    /// the point: a dev build that declares less than the shipped app is the
    /// gap that hid this for weeks.
    const PACKAGING: &str = include_str!("../scripts/macos-app-bundle.sh");

    /// The value the OS needs: the browsed type without mDNS's trailing domain.
    fn declared_form() -> String {
        crate::discovery::SERVICE_TYPE
            .trim_end_matches('.')
            .trim_end_matches(".local")
            .to_string()
    }

    #[test]
    fn the_bundle_declares_the_service_type_the_code_browses() {
        let needed = declared_form();
        assert!(
            PACKAGING.contains(&format!("<string>{needed}</string>"))
                && PACKAGING.contains("<key>NSBonjourServices</key>"),
            "the code browses {:?} but the app bundle does not declare {needed:?} \
             in NSBonjourServices. macOS blocks an undeclared browse and shows no \
             prompt, so discovery returns nothing forever and there is nothing a \
             user can grant. If the service type changed, change it in both \
             places — that is the whole point of this test.",
            crate::discovery::SERVICE_TYPE
        );
    }

    #[test]
    fn the_bundle_asks_for_local_network_access() {
        assert!(
            // The full plist key form, not a substring: a bare `contains` of
            // the name also matches a typo'd or suffixed key, which is exactly
            // the mistake that would leave the prompt broken.
            PACKAGING.contains("<key>NSLocalNetworkUsageDescription</key>"),
            "the bundle carries no NSLocalNetworkUsageDescription, so macOS has \
             no sentence to show when it asks for Local Network access. Without \
             it the daemon can announce and cannot receive, which reads as \
             'discovery finds nothing' with no error anywhere."
        );
    }

    /// The release path must not grow a second Info.plist.
    ///
    /// Having two is what caused this: the packaged app declared permissions
    /// the dev build did not, so the build being tested was not the build being
    /// shipped, and a missing declaration only showed up for users.
    #[test]
    fn the_release_packaging_uses_the_one_generator_rather_than_its_own_plist() {
        const RELEASE: &str = include_str!("../scripts/package-macos.sh");
        assert!(
            RELEASE.contains("macos-app-bundle.sh"),
            "package-macos.sh no longer calls the shared bundle generator. Two \
             ways to build the same bundle is how the tested artifact stops \
             being the shipped one."
        );
        assert!(
            !RELEASE.contains("<key>CFBundleIdentifier</key>"),
            "package-macos.sh has grown its own Info.plist again. There must be \
             exactly one, or a permission added for the release will be absent \
             from every dev build and nobody will notice until a user reports it."
        );
    }

    #[test]
    fn the_declared_form_drops_the_mdns_domain_and_nothing_else() {
        assert_eq!(
            declared_form(),
            "_hops._udp",
            "NSBonjourServices takes the bare service type. Leaving the trailing \
             `.local.` on it makes the declaration silently fail to match."
        );
    }
}

mod no_log_line_in_the_input_path_names_a_key {
    //! **#117.** A log line may say that a key went down or up, never which
    //! key. Raising the log level to look at a handshake must not record what
    //! someone types, and a warn line is written with no level raised at all.
    //! Key identity goes to the opt-in, time-boxed `keylog` file instead.
    //!
    //! **Why a text scan.** The type every event log line prints through is
    //! covered by calling it (`input_event`'s `no_key_identity` tests), and
    //! the daemon's own lines by running two machines over loopback
    //! (`a_key_released_at_teardown_is_not_named_in_the_log`,
    //! `keys_captured_and_sent_are_not_named_in_the_log`). What is left are
    //! the platform backends: wlroots, libei, the Windows hook and the macOS
    //! HID path compile only on their own OS and act only in a live session,
    //! so no test here can run them. For those, this checks that no log call
    //! formats a variable that holds a key.

    /// Names that hold a key, a scancode, a keysym, a modifier set, or a raw
    /// libei event (whose Debug prints the key).
    const KEY_HOLDERS: &[&str] = &[
        "key",
        "keys",
        "keycode",
        "key_code",
        "linux_keycode",
        "scancode",
        "scan_code",
        "scan",
        "win_scan_code",
        "linux_scan_code",
        "linux_scancode",
        "windows_scancode",
        "scanCode",
        "vkCode",
        "vk",
        "nx_keytype",
        "keysym",
        "mods",
        "ei_event",
    ];

    /// Every source file on the input path that logs.
    const FILES: &[(&str, &str)] = &[
        (
            "crates/input-capture/src/lib.rs",
            include_str!("../crates/input-capture/src/lib.rs"),
        ),
        (
            "crates/input-capture/src/libei.rs",
            include_str!("../crates/input-capture/src/libei.rs"),
        ),
        (
            "crates/input-capture/src/macos.rs",
            include_str!("../crates/input-capture/src/macos.rs"),
        ),
        (
            "crates/input-capture/src/layer_shell.rs",
            include_str!("../crates/input-capture/src/layer_shell.rs"),
        ),
        (
            "crates/input-capture/src/windows/event_thread.rs",
            include_str!("../crates/input-capture/src/windows/event_thread.rs"),
        ),
        (
            "crates/input-capture/src/event_queue.rs",
            include_str!("../crates/input-capture/src/event_queue.rs"),
        ),
        (
            "crates/input-emulation/src/lib.rs",
            include_str!("../crates/input-emulation/src/lib.rs"),
        ),
        (
            "crates/input-emulation/src/dummy.rs",
            include_str!("../crates/input-emulation/src/dummy.rs"),
        ),
        (
            "crates/input-emulation/src/libei.rs",
            include_str!("../crates/input-emulation/src/libei.rs"),
        ),
        (
            "crates/input-emulation/src/macos.rs",
            include_str!("../crates/input-emulation/src/macos.rs"),
        ),
        (
            "crates/input-emulation/src/windows.rs",
            include_str!("../crates/input-emulation/src/windows.rs"),
        ),
        (
            "crates/input-emulation/src/wlroots.rs",
            include_str!("../crates/input-emulation/src/wlroots.rs"),
        ),
        (
            "crates/input-emulation/src/xdg_desktop_portal.rs",
            include_str!("../crates/input-emulation/src/xdg_desktop_portal.rs"),
        ),
        (
            "crates/input-event/src/keylog.rs",
            include_str!("../crates/input-event/src/keylog.rs"),
        ),
        ("src/capture.rs", include_str!("capture.rs")),
        ("src/emulation.rs", include_str!("emulation.rs")),
        ("src/connect.rs", include_str!("connect.rs")),
        ("src/listen.rs", include_str!("listen.rs")),
    ];

    const LEVELS: &[&str] = &["trace!(", "debug!(", "info!(", "warn!(", "error!(", "log!("];

    /// Each `log::…!( … )` call in `code`: its line and the text between the
    /// parentheses. `Err` names a call whose closing parenthesis was not found,
    /// which would otherwise hide every call after it.
    fn log_calls(code: &str) -> Result<Vec<(usize, &str)>, usize> {
        let mut calls = vec![];
        for (at, _) in code.match_indices("log::") {
            let rest = &code[at + "log::".len()..];
            let Some(level) = LEVELS.iter().find(|l| rest.starts_with(**l)) else {
                continue;
            };
            let line = code[..at].matches('\n').count() + 1;
            let open = at + "log::".len() + level.len();
            let close = closing(&code[open..]).ok_or(line)?;
            calls.push((line, &code[open..open + close]));
        }
        Ok(calls)
    }

    /// Offset of the `)` closing an already-open parenthesis, outside strings.
    fn closing(s: &str) -> Option<usize> {
        let (mut depth, mut in_str, mut escaped) = (0usize, false, false);
        for (i, c) in s.char_indices() {
            if in_str {
                match c {
                    _ if escaped => escaped = false,
                    '\\' => escaped = true,
                    '"' => in_str = false,
                    _ => {}
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                '(' | '[' | '{' => depth += 1,
                ')' if depth == 0 => return Some(i),
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        None
    }

    /// The arguments of a call, split on commas outside strings and brackets.
    fn arguments(body: &str) -> Vec<&str> {
        let (mut args, mut start) = (vec![], 0);
        let (mut depth, mut in_str, mut escaped) = (0usize, false, false);
        for (i, c) in body.char_indices() {
            if in_str {
                match c {
                    _ if escaped => escaped = false,
                    '\\' => escaped = true,
                    '"' => in_str = false,
                    _ => {}
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    args.push(body[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            }
        }
        args.push(body[start..].trim());
        args.retain(|a| !a.is_empty());
        args
    }

    /// The names a log call prints: `{name}` captures in its format string,
    /// and arguments that are a plain variable or field, cast or not. A
    /// function call is not a name: it is how a value is printed without its
    /// key.
    fn printed(body: &str) -> Vec<String> {
        let mut args = arguments(body).into_iter().peekable();
        if args.peek().is_some_and(|a| a.starts_with("target:")) {
            args.next();
        }
        // `log::log!(level, "…")` names its level first.
        if args.peek().is_some_and(|a| !a.starts_with('"')) {
            args.next();
        }
        let mut names = vec![];
        if let Some(format) = args.next() {
            let mut rest = format;
            while let Some(open) = rest.find('{') {
                rest = &rest[open + 1..];
                if let Some(escaped) = rest.strip_prefix('{') {
                    rest = escaped;
                    continue;
                }
                let end = rest.find('}').unwrap_or(rest.len());
                let name = rest[..end].split(':').next().unwrap_or("").trim();
                if !name.is_empty() && !name.chars().all(|c| c.is_ascii_digit()) {
                    names.push(name.to_owned());
                }
                rest = &rest[end..];
            }
        }
        for arg in args {
            let value = arg.split_once('=').map_or(arg, |(_, v)| v).trim();
            let value = uncast(value.trim_start_matches(['&', '*']));
            if value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            {
                if let Some(last) = value.rsplit('.').next() {
                    names.push(last.to_owned());
                }
            }
        }
        names
    }

    /// `x as u16`, `(x as u32)`: a cast prints `x`.
    fn uncast(mut value: &str) -> &str {
        loop {
            let inner = value
                .strip_prefix('(')
                .and_then(|v| v.strip_suffix(')'))
                .map(str::trim);
            let bare = match value.rsplit_once(" as ") {
                Some((head, ty))
                    if ty
                        .trim()
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':') =>
                {
                    Some(head.trim())
                }
                _ => None,
            };
            match inner.or(bare) {
                Some(next) => value = next.trim_start_matches(['&', '*']),
                None => return value,
            }
        }
    }

    #[test]
    fn the_scan_reads_calls_the_way_the_compiler_does() {
        let code = "log::trace!(\"{key:#?} is not a modifier\");\n\
                    log::warn!(\n    \"a (b) {} (vk={:#04x})\",\n    scan_code,\n    hook.vkCode\n);\n\
                    log::debug!(\"{}\", describe(&key));\n\
                    log::log!(level, \"{{literal}} {n} {0}\", mods);\n\
                    log::info!(\"released {} stuck key(s)\", keys.len());\n\
                    log::warn!(\"no scancode: {} {}\", linux_keycode as u16, (key as u32));";
        let calls = log_calls(code).expect("every call closes");
        let names: Vec<Vec<String>> = calls.iter().map(|(_, b)| printed(b)).collect();
        assert_eq!(
            names,
            vec![
                vec!["key".to_owned()],
                vec!["scan_code".to_owned(), "vkCode".to_owned()],
                vec![],
                vec!["n".to_owned(), "mods".to_owned()],
                vec![],
                vec!["linux_keycode".to_owned(), "key".to_owned()],
            ],
            "the scan misreads a log call, so the guard below would miss a key \
             printed that way"
        );
        assert_eq!(
            calls.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
            vec![1, 2, 7, 8, 9, 10]
        );
    }

    #[test]
    fn no_log_call_on_the_input_path_prints_a_key() {
        let mut offenders = vec![];
        let mut seen = 0;
        for (file, src) in FILES {
            let code = super::scan::code_only(src);
            let calls = log_calls(&code).unwrap_or_else(|line| {
                panic!("{file}:{line}: a log call with no closing parenthesis")
            });
            assert!(
                !calls.is_empty(),
                "{file}: no log call found. It logs, so the scan is not reading it \
                 and would pass whatever it printed."
            );
            seen += calls.len();
            for (line, body) in calls {
                for name in printed(body) {
                    if KEY_HOLDERS.contains(&name.as_str()) {
                        offenders.push(format!("{file}:{line} prints `{name}`"));
                    }
                }
            }
        }
        assert!(
            seen > 200,
            "only {seen} log calls read; files have gone missing"
        );
        assert!(
            offenders.is_empty(),
            "log calls on the input path print which key was pressed:\n  {}\n\n\
             Anyone who raises HOPS_LOG_LEVEL to look at something else would \
             start recording what is typed, and a warn line does it with no \
             level raised at all (#117). Say that a key went down or up; send \
             its identity to `input_event::keylog::key`, which is compiled out \
             of release builds and time-boxed when armed.",
            offenders.join("\n  ")
        );
    }
}

// ---------------------------------------------------------------------------
// the daemon runs as the user
// ---------------------------------------------------------------------------

mod the_windows_daemon_is_never_installed_elevated {
    //! **Decided 2026-09-15 (#109).** The Windows daemon runs as the user and
    //! is never elevated. An administrator process started from a folder the
    //! user can write hands administrator to anything that can replace the
    //! file, and its enter hook comes from a config file the user can write.
    //!
    //! The runtime half is `crate::enter_hook`, which refuses the hook in an
    //! elevated process and is tested by calling it. This half is about the
    //! words that ship: the install script and the instructions for it. No CI
    //! runner registers a Windows scheduled task, so the text is what can be
    //! checked.

    const SCRIPT: &str = include_str!("../service/windows/install-hops-daemon.ps1");
    const README: &str = include_str!("../service/README.md");

    /// PowerShell with `#` comments removed, lower-cased, since PowerShell
    /// reads its parameter names without regard to case.
    fn powershell_code(src: &str) -> String {
        src.lines()
            .map(|l| l.split('#').next().unwrap_or("").to_lowercase())
            .collect::<Vec<_>>()
            .join("\n")
    }

    // LEDGER T69 | class S | source text
    #[test]
    fn the_install_script_and_its_instructions_never_ask_for_elevation() {
        let code = powershell_code(SCRIPT);
        let run_levels: Vec<&str> = code
            .split("-runlevel")
            .skip(1)
            .map(|after| after.split_whitespace().next().unwrap_or(""))
            .collect();
        assert!(
            !run_levels.is_empty() && run_levels.iter().all(|level| *level == "limited"),
            "install-hops-daemon.ps1 registers the daemon's task with run level \
             {run_levels:?}; it must name `-RunLevel Limited` and nothing else. \
             A task with the highest run level runs hops as an administrator from \
             a folder the user can write, and runs its enter hook from a config \
             file the user can write."
        );

        let mut asks = Vec::new();
        for (file, text) in [
            ("service/windows/install-hops-daemon.ps1", SCRIPT),
            ("service/README.md", README),
        ] {
            let lower = text.to_lowercase();
            for phrase in ["run as administrator", "elevated powershell"] {
                if lower.contains(phrase) {
                    asks.push(format!("{file}: \"{phrase}\""));
                }
            }
        }
        assert!(
            asks.is_empty(),
            "the Windows install instructions still ask for elevation: {asks:?}. \
             The daemon runs as the user, so its install needs no administrator, \
             and telling users to use one invites the elevated install that \
             2026-09-15 took out."
        );
    }
}

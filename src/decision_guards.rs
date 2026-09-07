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
//! Four rules below are decided, binding, and not yet implemented. They are in
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
        before_tests(src)
            .lines()
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

    use crate::trust::{Caps, DEFAULT_TERM_SECS, Origin, TrustStore};

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
            DEFAULT_TERM_SECS,
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
            DEFAULT_TERM_SECS,
            Origin::Inbound,
        );

        assert!(
            !store.we_may_drive(&stranger),
            "an Inbound approval minted the outbound right to drive that peer \
             (#130). Direction is a capability, not a synonym for membership; \
             the two questions have different answers and different blast radii."
        );
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
        use std::collections::VecDeque;
        use std::sync::{Arc, Mutex, RwLock};

        crate::transport::install_crypto_provider();

        let peer = super::a_test_certificate();
        let peer_fp = crate::transport::fingerprint_of(&peer);
        let ours = fp32(0x01);

        // A receiver we confirmed our own dial reached: outbound only.
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");
        store
            .issue(&peer_fp, "a receiver", Caps::OUTBOUND, DEFAULT_TERM_SECS)
            .expect("issue an outbound-only lease");
        let trust = Arc::new(RwLock::new(store));

        let outbound = FpServerVerifier::new(trust.clone(), Arc::new(Mutex::new(None)));
        let inbound = FpClientVerifier::new(trust, Arc::new(Mutex::new(VecDeque::new())));
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
// expulsion is permanent — the rule this project has now rebuilt three times
// ---------------------------------------------------------------------------

mod an_expelled_fingerprint_is_never_re_authorised {
    //! **Decided 2026-08-19.** No code path re-authorises a fingerprint that
    //! carries a denial. No restore verb exists in the IPC enum, the CLI, or
    //! any frontend. Recovery is the other machine generating a NEW identity
    //! and pairing from scratch.
    //!
    //! **This reverses an earlier decision, and the direction matters.** On
    //! 2026-08-05 re-trust was a distinct verb with a confirm step. On
    //! 2026-08-19 that clause — and only that clause — was overturned. Anyone
    //! citing the August 5th entry to justify a restore path, a suspend state,
    //! or a `Restored` origin is citing a decision that was reversed two weeks
    //! later. The rest of the August 5th entry still stands.
    //!
    //! **Why the rule is worth a test.** A stored one-request path from
    //! expelled back to full keyboard control is a capability sitting in the
    //! daemon for a convenience worth almost nothing, since re-pairing is a
    //! single approval. The reason to remove it was never that it was
    //! reachable — it was that it existed at all.

    use crate::trust::{Caps, DEFAULT_TERM_SECS, Denial, Lease, Origin, TrustStore};

    use super::fp32;

    fn expelled_store() -> (TrustStore, String, String) {
        let ours = fp32(0x01);
        let peer = fp32(0x77);
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");
        store
            .issue(&peer, "a machine", Caps::INBOUND, DEFAULT_TERM_SECS)
            .expect("issue");
        store.revoke(&peer);
        (store, ours, peer)
    }

    /// The whole public surface of the store, tried one verb at a time against
    /// a removed device.
    ///
    /// Written as an enumeration rather than as one test per verb on purpose:
    /// the failure mode is a NEW verb, added next month, that happens to clear
    /// a denial. A test per existing verb passes happily on the day that lands.
    /// This one at least fails the moment an existing verb starts laundering,
    /// and its name tells whoever adds the new verb what the rule is.
    #[test]
    fn no_verb_in_the_trust_store_can_lift_a_removal() {
        let (mut store, ours, peer) = expelled_store();

        /// One attempt to lift a removal: the verb's name, and the call.
        type Attempt = (&'static str, Box<dyn FnOnce(&mut TrustStore)>);

        let attempts: Vec<Attempt> = vec![
            (
                "issue",
                Box::new(|s: &mut TrustStore| {
                    let _ = s.issue(&fp32(0x77), "back please", Caps::KNOWN, DEFAULT_TERM_SECS);
                }),
            ),
            (
                "issue_with_origin",
                Box::new(|s: &mut TrustStore| {
                    let _ = s.issue_with_origin(
                        &fp32(0x77),
                        "back please",
                        Caps::KNOWN,
                        DEFAULT_TERM_SECS,
                        Origin::Inbound,
                    );
                }),
            ),
            (
                "renew",
                Box::new(|s: &mut TrustStore| {
                    let _ = s.renew(&fp32(0x77), DEFAULT_TERM_SECS);
                }),
            ),
            (
                "set_label",
                Box::new(|s: &mut TrustStore| {
                    let _ = s.set_label(&fp32(0x77), "renamed");
                }),
            ),
            (
                "drop_capabilities",
                Box::new(|s: &mut TrustStore| {
                    let _ = s.drop_capabilities(&fp32(0x77), Caps::NONE);
                }),
            ),
            (
                "admit (the disk-replay door)",
                Box::new(move |s: &mut TrustStore| {
                    let _ = s.admit(Lease {
                        peer: fp32(0x77),
                        issued_to: fp32(0x01),
                        label: "replayed off disk".to_string(),
                        caps: Caps::KNOWN,
                        origin: Origin::Inbound,
                        issued_at: 0,
                        not_after: DEFAULT_TERM_SECS,
                    });
                }),
            ),
            (
                "admit_denial (a second removal)",
                Box::new(|s: &mut TrustStore| {
                    s.admit_denial(
                        &fp32(0x77),
                        Denial {
                            label: "again".to_string(),
                            at: 1,
                        },
                    );
                }),
            ),
        ];

        for (verb, apply) in attempts {
            apply(&mut store);
            assert_eq!(
                store.capabilities(&peer),
                Caps::NONE,
                "`{verb}` re-authorised a removed device. Removal is permanent \
                 (decided 2026-08-19, reversing the 2026-08-05 restore verb). \
                 The recovery path is the other machine generating a NEW \
                 identity and pairing from scratch — a single approval. A \
                 one-request route from expelled back to full keyboard control \
                 is a capability sitting in the daemon for nothing. This has \
                 been rebuilt twice already after the objection was answered; \
                 if you are here because a restore feature was requested, the \
                 answer is a new identity, not a new verb."
            );
            assert!(
                store.is_denied(&peer),
                "`{verb}` erased the removal record for {peer}. The tombstone is \
                 what keeps an expelled machine distinguishable from a stranger \
                 on its next dial; without it the peer is simply unknown again \
                 and one click from readmitted."
            );
            assert!(
                !store.may_drive_us(&peer) && !store.we_may_drive(&peer),
                "`{verb}` left {peer} able to drive a machine in some direction \
                 after removal, on a store owned by {ours}."
            );
        }
    }

    /// The grant door's *return value*, not just its effect. A door that
    /// silently no-ops looks identical to a door that worked, and the UI would
    /// then show a device the daemon does not trust.
    #[test]
    fn granting_to_a_removed_device_fails_loudly_rather_than_quietly() {
        use crate::trust::TrustError;
        let (mut store, _, peer) = expelled_store();
        match store.issue(&peer, "back please", Caps::INBOUND, DEFAULT_TERM_SECS) {
            Err(TrustError::Expelled { fingerprint }) => assert_eq!(fingerprint, peer),
            other => panic!(
                "granting to a removed device returned {other:?}. It must return \
                 TrustError::Expelled so the caller can tell the user that \
                 identity is dead and the machine needs a new one. A silent \
                 no-op leaves the frontend showing a grant that did not happen."
            ),
        }
    }

    /// **Decided 2026-08-30.** No commit adds a restore or suspend path while
    /// the written tombstone rationale is still present in the source.
    ///
    /// **This one is a text invariant, deliberately.** The rule IS about a
    /// comment: the mechanism is that an author who wants the restore path back
    /// must consciously delete a paragraph explaining why it is gone, which
    /// turns a silent regression into a deliberate act someone has to justify
    /// in a diff. There is nothing to call. The scan runs over `trust.rs` and
    /// `trust_file.rs`, never over this file.
    #[test]
    fn the_negative_space_comment_that_makes_a_rebuild_deliberate_is_still_there() {
        for (file, src) in [
            ("src/trust.rs", include_str!("trust.rs")),
            ("src/trust_file.rs", include_str!("trust_file.rs")),
        ] {
            assert!(
                src.contains("No `Restored`"),
                "{file} no longer carries the `No \\`Restored\\`` note beside its \
                 origin enum. That note is not decoration: it is the thing an \
                 author has to delete on purpose before adding the variant back, \
                 which is what converts a silent regression into a reviewable \
                 act. If you removed it because you are adding a restore path, \
                 the 2026-08-19 decision says the path may not exist — take it \
                 to the decision record first."
            );
        }
        let door = include_str!("trust.rs");
        assert!(
            door.contains("There is deliberately no restore verb anywhere"),
            "src/trust.rs no longer states, at the admit door, that no restore \
             verb exists above it. The door is the only place a reader learns \
             that the refusal is intentional rather than an oversight — and an \
             oversight is what somebody tidies up."
        );
    }

    /// **RED TODAY.** A text invariant, and the right instrument for it: the
    /// defect is prose, not behaviour.
    ///
    /// The executable code obeys the 2026-08-19 decision. The documentation
    /// around it teaches the 2026-08-05 rule that was overturned — including
    /// two rustdoc intra-doc links to `TrustStore::restore`, a method that does
    /// not exist, in the module header, which is the first thing any reader
    /// sees. That prose is the reseeding mechanism this whole exercise exists
    /// to stop: the assistant that rebuilt `restore()` was working from a
    /// framing it had constructed in between reading the record and writing the
    /// code, and the framing is sitting in the file, naming the verb.
    ///
    /// A guard cannot outrank documentation that tells the next reader the
    /// guard is wrong.
    #[test]
    fn no_shipped_prose_teaches_the_superseded_rule_that_removal_is_reversible() {
        // Precise phrases, not the bare word: legitimate uses exist nearby —
        // "no restore verb", "a dotfiles restore could launder", "irreversible",
        // and the TUI's own `the_footer_advertises_no_restore` guard. Each
        // needle below was checked to match only sites that assert the
        // SUPERSEDED position as current design.
        const FORBIDDEN: &[(&str, &str)] = &[
            (
                "`TrustStore::restore`",
                "a rustdoc link to a method that does not exist, offered as the verb that undoes a removal",
            ),
            (
                "makes removal reversible",
                "states the overturned 2026-08-05 position as current design",
            ),
            (
                "removal is reversible",
                "states the overturned 2026-08-05 position as current design",
            ),
            (
                "restore it before granting",
                "a user-facing error string pointing at an affordance that does not exist",
            ),
            (
                "so `restore`",
                "a guard's own failure message arguing that the forbidden verb is legitimate",
            ),
            (
                "what makes it reversible",
                "states the overturned 2026-08-05 position as current design",
            ),
            (
                "user can now restore",
                "the migration doc comment asserting the reversed rule",
            ),
        ];

        // Whole-file, including test modules, ON PURPOSE: one of the offenders
        // is a guard's own failure message, and a failure message read by
        // somebody about to delete the guard is exactly where this rule matters
        // most.
        let mut offenders = Vec::new();
        for (file, src) in [
            ("src/trust.rs", include_str!("trust.rs")),
            ("src/trust_file.rs", include_str!("trust_file.rs")),
            ("src/service.rs", include_str!("service.rs")),
        ] {
            for (needle, why) in FORBIDDEN {
                for (line, text) in super::scan::hits(src, needle) {
                    offenders.push(format!("{file}:{line} — {why}\n      {text}"));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "shipped prose still teaches that a removed device can be restored, \
             in {} place(s):\n\n    {}\n\n\
             Removal is permanent — decided 2026-08-19, REVERSING the 2026-08-05 \
             entry that made re-trust a distinct verb. The code already obeys \
             this; only the words disagree, and the words are what the next \
             author reads. The restore path has been built twice against an \
             objection that had already been answered, both times by someone \
             working from a framing built between reading the record and writing \
             the code. Two of these are broken rustdoc intra-doc links, so \
             `cargo doc` will not resolve them either. Rewrite the prose to say \
             what the code does: a denial outranks the lease it sits beside, and \
             the machine returns by generating a new identity.",
            offenders.len(),
            offenders.join("\n    ")
        );
    }

    /// **Decided 2026-08-05, still standing.** A revoked fingerprint produces
    /// no approval prompt, inbound or outbound.
    ///
    /// **Why.** Revocation cut the session, the peer reconnected, and its
    /// failed handshake raised the approval prompt — one click restored full
    /// control, at a moment the peer chose, repeatable until a misclick.
    /// Revocation cannot keep an attacker out (it can re-key); what it can do
    /// is stop the attacker choosing the moment you are asked.
    ///
    /// This calls both predicates because the production path
    /// (`raise_connection_attempt`) gates on `denial()` while the store exposes
    /// `may_prompt()` — two answers to one question, and the audit found
    /// `may_prompt` has no production caller. If they ever disagree, one of
    /// them is a prompt gate that is not gating.
    #[test]
    fn a_removed_device_can_never_put_a_prompt_on_the_screen_and_a_lapsed_one_still_can() {
        use crate::trust::MAX_TERM_SECS;

        let ours = fp32(0x01);
        let expelled = fp32(0x88);
        let lapsed = fp32(0x99);
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");

        store
            .issue(&expelled, "removed", Caps::INBOUND, DEFAULT_TERM_SECS)
            .expect("issue");
        store.revoke(&expelled);

        store
            .issue(&lapsed, "lapsed", Caps::INBOUND, 10)
            .expect("issue");

        assert!(
            !store.may_prompt(&expelled),
            "a removed device may raise an approval prompt. That is the whole \
             readmission loop: revoke cuts the session, the peer redials, its \
             failed handshake raises a dialog, and one click hands back full \
             keyboard control — at a moment the peer picked, repeatable until a \
             misclick."
        );
        assert_eq!(
            store.denial(&expelled).is_some(),
            !store.may_prompt(&expelled),
            "the store's `may_prompt` and the `denial()` lookup that \
             `Service::raise_connection_attempt` actually uses disagree about \
             {expelled}. Two predicates, one question, and only one of them is \
             wired to the screen — so the tested one can be right while the \
             running one is wrong."
        );

        // Roll the clock past the lease. `Clock` is max(reading, floor), so
        // observe() is how time moves for the store.
        store.clock().observe(MAX_TERM_SECS);
        assert!(
            store.may_prompt(&lapsed),
            "a device whose lease merely LAPSED was refused a prompt. A lapse is \
             not an expulsion: a lapsed machine may knock again and be renewed, \
             an expelled one may not even ask. Collapsing the two makes expiry \
             indistinguishable from removal, and then nobody dares let a lease \
             expire."
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
    //! only.
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

    use crate::trust::{Caps, DEFAULT_TERM_SECS, TrustStore};

    use super::fp32;

    /// The structural half, checked by calling the store: revocation takes no
    /// authority and cannot fail, so there is nothing for a future gate to hook
    /// into without changing the signature — which a reviewer would see.
    #[test]
    fn revocation_needs_no_authority_and_has_no_failure_path_to_gate() {
        let ours = fp32(0x01);
        let peer = fp32(0xaa);
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");
        store
            .issue(
                &peer,
                "driving me right now",
                Caps::KNOWN,
                DEFAULT_TERM_SECS,
            )
            .expect("issue");

        // No Result, no authority argument, no clock argument: `revoke` returns
        // the label it removed and nothing else can be threaded into it.
        let label: String = store.revoke(&peer);

        assert_eq!(label, "driving me right now");
        assert_eq!(
            store.capabilities(&peer),
            Caps::NONE,
            "revoke left capabilities behind. Revocation must be reachable and \
             total from a machine that is CURRENTLY being driven by the peer \
             being revoked — that is the moment it exists for."
        );

        // Revoking something already revoked, and something never known, must
        // also not fail: a user hammering the button while a peer drives them
        // must not hit an error path.
        let _ = store.revoke(&peer);
        let _ = store.revoke(&fp32(0xbb));
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
    /// Scans `service.rs`, never this file.
    #[test]
    fn only_the_grant_arm_consults_the_quiet_window() {
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

        // The one arm that MUST consult the gate.
        {
            const GRANT: &str = "FrontendRequest::AuthorizeKey";
            let at = dispatch
                .find(GRANT)
                .unwrap_or_else(|| panic!("{GRANT} must be dispatched; update this guard"));
            let after = &dispatch[at..];
            let arm_end = after[1..]
                .find("FrontendRequest::")
                .map(|i| i + 1)
                .unwrap_or(after.len());
            assert!(
                after[..arm_end].contains(gate),
                "the AuthorizeKey arm no longer refuses while a peer is driving \
                 this machine. On a KVM the pointer is not proof of local \
                 presence: the peer holding your keyboard can move the cursor \
                 onto the approval button and click it, manufacturing its own \
                 consent. Granting trust is the one verb a remote peer can \
                 usefully click for itself."
            );
        }

        for arm in ["RemoveAuthorizedKey", "Delete"] {
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

    use crate::trust::{Caps, DEFAULT_TERM_SECS, TrustStore};

    use super::fp32;

    /// The behavioural half: removing trust is total, and it survives being
    /// asked twice.
    #[test]
    fn a_deleted_device_keeps_no_authorisation_of_any_kind() {
        let ours = fp32(0x01);
        let peer = fp32(0xcc);
        let mut store = TrustStore::new(&ours, 0).expect("our own fingerprint");
        store
            .issue(&peer, "the sold laptop", Caps::KNOWN, DEFAULT_TERM_SECS)
            .expect("issue");
        assert!(store.may_drive_us(&peer), "precondition: it was trusted");

        store.revoke(&peer);

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
            store.is_denied(&peer),
            "a removed device left no expulsion record, so on its next dial it \
             is a stranger rather than a machine you already threw out — and a \
             stranger is one click from readmitted."
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

        for forbidden in ["remove_authorized_key", "revoke("] {
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

// ---------------------------------------------------------------------------
// no UI is trusted; nothing reaches a shell
// ---------------------------------------------------------------------------

mod no_frontend_can_cause_a_trust_write {
    //! **Decided 2026-08-30 (#107).** No frontend — Slint, TUI, CLI, or a
    //! served page — can cause a trust write; a privileged verb is not
    //! serialisable over the frontend IPC socket.
    //!
    //! **Why.** lan-mouse assumed the frontend is trusted; hops does not.
    //! `Create`, then `UpdateFixIps(attacker_ip)`, then `Activate` makes the
    //! daemon dial an attacker and raise a genuine approval prompt for a
    //! fingerprint the attacker chose, at a moment the attacker chose.

    /// **RED TODAY (#107).**
    ///
    /// Type-level and behavioural: it constructs the verb and serialises it. If
    /// `AuthorizeKey` cannot be built and put on the wire, this stops compiling
    /// — which is the point. The failure message tells you to delete the test
    /// along with the variant.
    #[test]
    #[ignore = "RED: AuthorizeKey is still a frontend IPC verb. Closed by #107. Kept red-and-visible rather than deleted: this is the decision with the fullest documented attack chain behind it."]
    fn no_privileged_verb_can_be_serialised_over_the_frontend_socket() {
        use hops_ipc::FrontendRequest;

        let grant = FrontendRequest::AuthorizeKey("a device".to_string(), super::fp32(0xdd));
        let on_the_wire = serde_json::to_string(&grant).expect("serialise");

        assert!(
            !on_the_wire.contains("AuthorizeKey"),
            "the trust grant is still a frontend IPC verb, serialisable as \
             {on_the_wire} (#107). Anything that can write a line to that socket \
             can grant keyboard control of this machine — and the full chain is \
             intact beside it: Create, then UpdateFixIps(attacker_ip), then \
             Activate makes the daemon dial an address of the attacker's \
             choosing and raise a GENUINE approval prompt for a fingerprint the \
             attacker chose, at a moment the attacker chose. When the grant verb \
             moves off this socket, delete the variant and this test together."
        );
    }

    /// **Also RED TODAY, and the reason the #130 door cannot be fixed in
    /// isolation.** The approval message carries a description and a
    /// fingerprint and nothing else — so the wire itself cannot say whether the
    /// user was answering an inbound knock or their own outbound dial, and the
    /// door has no origin to derive capabilities from.
    ///
    /// This is why `approving_our_own_dial_never_lets_that_machine_type_into_this_one`
    /// is red: the information needed to fix it does not reach the door.
    #[test]
    #[ignore = "RED: FrontendRequest::AuthorizeKey carries no origin, so the wire cannot express which act was approved. Closed by #107, which moves the grant verb off IPC entirely. The store now refuses an incoherent grant, so this is a wire gap rather than a live over-grant."]
    fn an_approval_says_which_act_it_is_approving() {
        use hops_ipc::FrontendRequest;

        let grant = FrontendRequest::AuthorizeKey("a device".to_string(), super::fp32(0xdd));
        let on_the_wire = serde_json::to_string(&grant).expect("serialise");

        assert!(
            on_the_wire.contains("Inbound")
                || on_the_wire.contains("OutboundDial")
                || on_the_wire.contains("origin"),
            "the approval message {on_the_wire} carries no origin, so the grant \
             door cannot tell an inbound knock from our own dial and hardcodes \
             one direction for both (#130). Direction is a capability; a message \
             that cannot express which act was approved cannot mint the right \
             one."
        );
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
        "fn remove_authorized_key", // revoke + tombstone
        "fn set_label",             // rename; refuses unknown fingerprints
        "fn handle_config_change",  // reload: the config file is a door too
        "fn new",                   // startup load
        // Added 2026-09-06 with the sweep. It is a door because it drops what
        // has lapsed, which is a trust change — but it is the one door no human
        // opens: it mints nothing, narrows only, and runs on a timer. Listed so
        // the addition is visible in the diff rather than discovered later.
        "fn sweep_lapsed_leases",
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
    //! pair a device, and no discovery or pairing-code work removes it or puts
    //! a precondition in front of it.
    //!
    //! **Why, with the measurement.** The "easy" path measured harder than the
    //! fallback: the pairing code is 228-415 characters and needs a text
    //! channel between two machines that do not yet share a keyboard — which is
    //! the thing being set up. Typing an address is 15 characters. User flows
    //! are a fallback ladder, and the bottom rung is the one that always works.

    use crate::client::ClientManager;
    use hops_ipc::Position;

    /// Calls the client model with nothing but a typed address — no discovery
    /// result, no pairing code, no fingerprint known in advance — and checks a
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
    //! **Decided 2026-07-28.** The QUIC listen port stays 4242, and moving to
    //! 443 may never be scheduled as a traversal requirement.
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
    /// rename; the test above is what pins the production value. A change that
    /// made the real server offer two ALPNs during a migration would slip past
    /// this one — that needs the config builders to be reachable.
    #[test]
    fn a_peer_offering_a_different_alpn_cannot_complete_a_handshake() {
        use crate::transport::{self, FpClientVerifier, FpServerVerifier};
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use quinn::{ClientConfig, Endpoint, ServerConfig};
        use std::collections::VecDeque;
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
                s.issue(
                    &client_fp,
                    "peer",
                    crate::trust::Caps::KNOWN,
                    crate::trust::DEFAULT_TERM_SECS,
                )
                .expect("issue");
                Arc::new(RwLock::new(s))
            };
            let client_trust = {
                let mut s = crate::trust::TrustStore::new(&client_fp, 0).expect("ours");
                s.issue(
                    &server_fp,
                    "peer",
                    crate::trust::Caps::KNOWN,
                    crate::trust::DEFAULT_TERM_SECS,
                )
                .expect("issue");
                Arc::new(RwLock::new(s))
            };

            let mut server_crypto = rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(FpClientVerifier::new(
                    server_trust,
                    Arc::new(Mutex::new(VecDeque::new())),
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

    #[test]
    fn the_quic_listen_port_is_still_4242() {
        assert_eq!(
            hops_ipc::DEFAULT_PORT,
            4242,
            "the default QUIC port moved. 4242 is arbitrary, inherited from \
             upstream, and deliberately not worth changing: it is above 1024, so \
             either machine binds it unprivileged and the macOS TCC-versus-root \
             conflict never arises. If this moved to 443 to 'fix traversal', it \
             fixes nothing — traversal was MEASURED to be about connection \
             direction, not the port: the SASE client is stateful and blocks \
             unsolicited inbound flows, not ports. Moving to 443 re-imports the \
             privileged-bind conflict plus installer work to solve a problem \
             that does not exist."
        );
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

    /// **RED TODAY.** The binary's front door — `hops` with no subcommand,
    /// which is what double-clicking the app runs — ensures the daemon is up
    /// before opening any frontend.
    ///
    /// The code carries a reasoned defence (a frontend-spawned daemon can land
    /// on the dummy backend if its path lacks the Accessibility grant, so it
    /// bootstraps the GRANTED launchd service instead), and it is genuinely
    /// narrower than naive drift: the frontend crates spawn nothing, and
    /// launchd owns the lifetime on macOS. But the decision has no front-door
    /// carve-out, and its stated harm — making the highest-privilege process a
    /// UI-triggerable event — is not avoided by routing through launchd. On
    /// macOS it goes further than the decision contemplates, self-installing a
    /// LaunchAgent so the daemon starts at every login.
    ///
    /// Either the code or the decision is wrong. This test says so out loud
    /// instead of letting a green suite imply the rule holds.
    #[test]
    #[ignore = "RED: `hops` with no subcommand calls ensure_daemon_running() before opening the frontend, which the 2026-06-28 decision forbids in as many words. Tracked in #159 — do not delete this guard to make the suite green."]
    fn the_front_door_does_not_bring_the_daemon_up_before_attaching() {
        let code = super::scan::code_only(include_str!("main.rs"));
        let mut found = Vec::new();
        for marker in [
            "ensure_daemon_running",
            "start_detached_daemon",
            "launchctl",
        ] {
            if code.contains(marker) {
                found.push(marker);
            }
        }
        assert!(
            found.is_empty(),
            "the front door starts the daemon: {found:?}. The 2026-06-28 decision \
             says a frontend attaches to a running daemon and must NEVER spawn, \
             fork, launch or auto-start one, and it has no front-door carve-out. \
             The code's defence is real — the frontend CRATES spawn nothing, and \
             routing through launchd avoids the dummy-backend trap that a \
             self-spawned daemon falls into — but routing through launchd does \
             not avoid the harm the decision names, which is that the \
             highest-privilege process on the machine becomes a UI-triggerable \
             event. On macOS it goes further still, self-installing a LaunchAgent \
             so the daemon starts at every login. This needs a decision, not a \
             patch: either the entry gets an explicit front-door exception with \
             its reasoning, or the front door stops doing this. Do not soften \
             this test to match the code without that entry."
        );
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

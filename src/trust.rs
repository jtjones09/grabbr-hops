//! Trust as a **lease**: who may do what to this machine, and until when.
//!
//! # Why a lease and not a grant
//!
//! The allowlist this replaces was a `fingerprint -> label` map that persisted
//! until somebody deleted the row. Nothing in that shape ever expires, so the
//! trust store only grows, and it grows in the direction of machines you no
//! longer own: the laptop you sold, the VM you deleted, the box a contractor
//! used once. A KVM is the highest-privilege software on a machine — whatever
//! is in that map can type into it — so "until removed" is the wrong default
//! for membership. A lease says the opposite: access lapses on its own, and
//! staying in the circle is something the user re-affirms rather than something
//! nobody ever gets around to undoing.
//!
//! Expiry is also the reason a lapse must never be mistaken for an expulsion.
//! A lapsed lease is a device that may knock again and be renewed; an explicit
//! denial is a device that may not even ask. Those are different states here,
//! and the difference is load-bearing everywhere downstream — a lapsed device
//! is discoverable again and may raise a prompt, a denied one is neither.
//!
//! # Direction is a capability, not a second table
//!
//! There used to be exactly one map and one question: is this fingerprint in
//! it. Approving an outbound dial — "yes, that is the machine I meant to send
//! my keyboard to" — wrote the same row that admits inbound control, so it also
//! granted that machine the right to type into *this* one. Nobody was asked
//! that second question. Splitting trust into two maps would have fixed that
//! one case and left the next one (clipboard) to be discovered later, so
//! direction and channel are [`Caps`] bits on the lease instead. A lease that
//! carries [`Caps::I_MAY_DRIVE`] and not [`Caps::DRIVE_ME`] is a machine we may
//! send input to that may not send input to us, and it is expressible because
//! permission and identity are different fields.
//!
//! Every bit here is enforced at a real door in the same commit that adds it:
//! the two input bits in the TLS verifiers, the two clipboard bits in the
//! clipboard accept loops. A capability that is stored and never checked is a
//! lie about what the store decides, and it is worse than not having the bit,
//! because the UI would show it.
//!
//! # One record per identity
//!
//! An [`Entry`] holds an optional [`Lease`] and an optional [`Denial`] under one
//! canonical fingerprint. There is no second map to rank against the first:
//! precedence lives in [`effective_capabilities`] and nowhere else, so a reader
//! cannot reconcile the two differently from the way the last reader did. The
//! previous shape needed that rule restated at four separate doors, and the one
//! it was missing was the boot path (#66).
//!
//! Keeping the lease *under* a denial is what makes removal reversible (#125).
//! Revocation does not erase what was granted; it outranks it. So the single
//! verb that undoes a removal is [`TrustStore::restore`], and it hands back
//! exactly the capabilities that existed — never a bit more, because it does not
//! mint anything.
//!
//! # The clock is an input an attacker can reach
//!
//! Expiry is only as honest as the clock, and the receiver's wall clock is
//! writable by anyone who can inject into it — which, on a KVM, is exactly the
//! peer whose lease is expiring. So enforcement never reads the system clock
//! directly: it goes through [`Clock`], which is `max(reading, floor)` with a
//! floor that only ever increases. Wind the clock backwards and the floor wins,
//! so an expired lease stays expired. Wind it forwards and leases expire early —
//! trust is lost, never gained. That asymmetry is the whole point: the failure
//! mode of a manipulated clock is being locked out, not letting somebody in.
//!
//! The floor lives behind an [`std::sync::Arc`], so a [`Clock`] handed to a TLS
//! verifier at startup sees every later advance. A clock that captured the floor
//! by value would freeze at whatever the floor was when it was cloned, and the
//! defence would quietly be gone for the life of the process.
//!
//! # Denial is reachable without authority; a grant is not
//!
//! [`TrustStore::revoke`] needs nothing signed and cannot fail. It must stay
//! reachable from a machine that is currently being driven by a peer, because
//! that is precisely when a user needs to cut somebody off, and refusing to let
//! them would remove the one action most needed at the moment it is needed.
//! [`TrustStore::issue`] and [`TrustStore::restore`] are the opposite: issuing,
//! widening or un-blocking is a grant, so the caller gates them on local
//! presence before they get here. This module does not know about that gate; it
//! only makes sure the verbs are separable.
//!
//! # What is authoritative and what is cache
//!
//! **Authoritative:** every [`Entry`] and the persisted clock floor — what
//! `crate::trust_file` seals and what this store holds.
//!
//! **Cache, never read back as authority:** the `[authorized_fingerprints]` and
//! `[revoked_fingerprints]` tables in `config.toml`. The daemon keeps writing
//! them so existing tooling still sees who is trusted, but a hand-edit there
//! grants nothing, because after [`TrustStore::migrate_from_config`] has run
//! once no code path reads them to make a decision. Also cache: the per-client
//! `fingerprint` pin in `[[clients]]`, which is address routing — where to dial
//! and who we expect to answer — not permission. A pin without a lease dials and
//! is refused, which is the correct outcome.
//!
//! # Who signs a lease, and where the key lives
//!
//! Sealing and verifying the store is `crate::trust_file`'s job, against
//! whatever fills the *authority* role — today a keypair generated at first run
//! and stored on disk, later possibly a TPM, a Secure Enclave or a FIDO2 key.
//! Nothing in this module knows, asks, or branches on where a signer's key
//! lives, and nothing downstream may either: key residency cannot be proven to a
//! remote peer, so a check on it would be a check on a self-report — worse than
//! no check, because it would look like one.
//!
//! # Constructibility
//!
//! [`TrustStore::new`] needs a fingerprint and a number. No certificate, no
//! socket, no backend, no runtime, no authority, no filesystem — and nothing
//! here logs, so every refusal is *returned* and the caller decides what the
//! user is told. That is deliberate: the trust core was previously reachable
//! only through a service that first loaded a certificate, bound an IPC socket,
//! started QUIC in both directions and spun up capture and emulation, which is
//! why it had no behavioural tests at all and was guarded by scanning its own
//! source text (#127).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use hops_ipc::RevokedEntry;
use hops_ipc::pairing::{canonical_fingerprint, sanitize_label};
use thiserror::Error;

/// Term offered when a user approves a device: 30 days.
///
/// Long enough that a machine in weekly use is never interrupted, short enough
/// that a machine you stopped using drops out within a month without anybody
/// remembering to remove it.
pub const DEFAULT_TERM_SECS: u64 = 30 * 86_400;

/// Term given to a lease carried forward from the old allowlist: 400 days.
///
/// Never-expiring would be the old permanent grant wearing a lease's clothes.
/// 30 days is right for a decision the user made this week and wrong for one
/// they made eight months ago — an upgrade must not silently arm a deadline the
/// user was never shown. 400 days clears a full annual cycle with room, so every
/// user meets the renewal prompt at least a year out, with the fleet up and the
/// device in front of them.
pub const MIGRATION_TERM_SECS: u64 = 400 * 86_400;

/// Hard ceiling on a lease window.
///
/// Without a ceiling, "membership is a lease" is a naming convention — one
/// issuance with a hundred-year window restores exactly the shape being removed.
/// Renewal is cheap and is the intended way to stay trusted, so the ceiling
/// costs nothing legitimate.
///
/// It has to be at least [`MIGRATION_TERM_SECS`] or the upgrade admits nothing
/// and the whole fleet goes dark on the first boot after it. The two constants
/// disagreed in an earlier draft (366 versus 400), which is exactly that
/// failure, so the assertion below is a compile error rather than a comment.
pub const MAX_TERM_SECS: u64 = 400 * 86_400;

const _: () = assert!(MIGRATION_TERM_SECS <= MAX_TERM_SECS);
const _: () = assert!(DEFAULT_TERM_SECS <= MAX_TERM_SECS);

/// How long before a lease lapses the UI should start asking to renew it.
///
/// The term is only half of the promise. A device that stops working with no
/// warning is indistinguishable from a bug, so the prompt has to precede the
/// outage rather than explain it.
pub const RENEW_WINDOW_SECS: u64 = 14 * 86_400;

/// How long a removed or lapsed device keeps its NAME on file.
///
/// Enforcing a removal needs the fingerprint and nothing else. A fingerprint is
/// public — this machine multicasts its own in every mDNS announcement — so
/// retaining one leaks nothing. The label does not have that property: it is the
/// user's own name for their own machine, and a store that keeps every label
/// forever is an inventory of every device the user has ever paired, with their
/// names for them and the dates each relationship began and ended, in a file
/// readable by anything running as that user.
///
/// That inventory buys one thing: the interface can say "you removed *living
/// room* in March" rather than showing bare hex. Worth keeping while the user
/// might still act on it, not worth keeping for the life of the installation.
///
/// After this window the name is dropped and the fingerprint stays, so the
/// removal keeps biting and the archive stops growing.
pub const NAME_RETENTION_SECS: u64 = 180 * 86_400;

/// How long a LAPSED lease — expired, never removed — is kept at all.
///
/// A lapsed lease grants nothing, and re-adding the device is the same flow as
/// adding it for the first time. Nothing depends on the record, so it is dropped
/// whole rather than redacted. A removal is never dropped: that record is what
/// stops a restored backup re-granting an expelled device.
pub const LAPSED_RETENTION_SECS: u64 = 90 * 86_400;

// ---------------------------------------------------------------------------
// fingerprints
// ---------------------------------------------------------------------------

/// The one spelling of an identity, computed once at every door.
///
/// A valid fingerprint becomes its canonical `aa:bb:..` form. Anything else
/// becomes trimmed lowercase and is kept, because it can still be *denied*: a
/// removal recorded under a junk string matches nothing and grants nothing,
/// while refusing to record it would be the more dangerous failure. It can never
/// match a lease, since a lease cannot be built from a fingerprint that is not
/// canonical.
///
/// Every public entry point — reader and writer alike — goes through this. The
/// previous store canonicalised on the write side only and compared "as given"
/// on the read side, on the grounds that a non-canonical lookup matches nothing
/// and therefore fails closed. That is true where the answer is a capability set
/// and **false where the answer is a boolean denial**: matching nothing there
/// means *not denied*, so shouting the fingerprint walked straight past an
/// expulsion (#67, reopened). One rule, applied everywhere, has no polarity to
/// get wrong.
fn key(fingerprint: &str) -> String {
    canonical_fingerprint(fingerprint).unwrap_or_else(|| fingerprint.trim().to_lowercase())
}

// ---------------------------------------------------------------------------
// capabilities
// ---------------------------------------------------------------------------

/// What a lease permits, as bits.
///
/// Direction is stated from *this* machine's point of view, and both directions
/// are named after who ends up being driven, so a reader never has to work out
/// whose keyboard is whose: [`Caps::DRIVE_ME`] lets the peer type here,
/// [`Caps::I_MAY_DRIVE`] lets us type there.
///
/// A plain `u16` rather than a bitflags dependency — the whole vocabulary is
/// four bits and `contains` is one mask. Unknown bits are **dropped at
/// construction**, never carried: on disk the capabilities are kebab-case names,
/// so an unknown capability is a deserialisation failure there, and the only way
/// an unknown bit reaches memory is a caller inventing one. Truncating is the
/// fail-closed answer; carrying it would leave a value in the store that reads
/// as permission to something.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Caps(u16);

impl Caps {
    /// Permits nothing. The value every decision falls back to.
    pub const NONE: Caps = Caps(0x0000);
    /// The peer may inject input into this machine.
    pub const DRIVE_ME: Caps = Caps(0x0001);
    /// This machine may inject input into the peer.
    pub const I_MAY_DRIVE: Caps = Caps(0x0002);
    /// Accept clipboard contents sent by the peer.
    pub const CLIPBOARD_FROM: Caps = Caps(0x0004);
    /// Send this machine's clipboard to the peer.
    pub const CLIPBOARD_TO: Caps = Caps(0x0008);

    /// Everything this build understands and enforces.
    pub const KNOWN: Caps = Caps(0x000f);

    /// Everything the peer may do to us. The set a user is agreeing to when they
    /// answer an unsolicited knock at the door.
    pub const INBOUND: Caps = Caps(0x0005);
    /// Everything we may do to the peer. The set a user is agreeing to when they
    /// confirm the receiver our own dial reached.
    pub const OUTBOUND: Caps = Caps(0x000a);

    /// Name/bit pairs, for rendering, logging and the on-disk mapping.
    pub const NAMED: [(Caps, &'static str); 4] = [
        (Caps::DRIVE_ME, "drive-me"),
        (Caps::I_MAY_DRIVE, "i-may-drive"),
        (Caps::CLIPBOARD_FROM, "clipboard-from"),
        (Caps::CLIPBOARD_TO, "clipboard-to"),
    ];

    /// Wrap raw bits, dropping anything this build does not enforce.
    ///
    /// There is deliberately no non-truncating constructor. A bit nothing checks
    /// must never be able to sit in a lease looking like a permission.
    pub const fn from_bits_truncating(bits: u16) -> Caps {
        Caps(bits & Caps::KNOWN.0)
    }

    /// The raw bits, for crossing a process boundary.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// True iff **every** bit of `other` is present. An empty `other` is
    /// trivially contained, so callers must not read `contains(Caps::NONE)` as
    /// "has some permission"; [`TrustStore::permits`] refuses that question.
    pub const fn contains(self, other: Caps) -> bool {
        self.0 & other.0 == other.0
    }

    /// True iff any bit of `other` is present.
    pub const fn intersects(self, other: Caps) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn union(self, other: Caps) -> Caps {
        Caps(self.0 | other.0)
    }

    /// `self` with every bit of `other` cleared. Narrowing — always safe.
    pub const fn without(self, other: Caps) -> Caps {
        Caps(self.0 & !other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for Caps {
    type Output = Caps;
    fn bitor(self, rhs: Caps) -> Caps {
        self.union(rhs)
    }
}

impl fmt::Display for Caps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }
        let mut first = true;
        for (bit, name) in Caps::NAMED {
            if self.contains(bit) {
                if !first {
                    f.write_str("+")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Caps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Caps({self})")
    }
}

// ---------------------------------------------------------------------------
// the clock
// ---------------------------------------------------------------------------

/// The system clock in unix seconds.
///
/// Never use this for a decision — feed it to [`Clock::at`]. A machine whose RTC
/// reads before the epoch reports `0` here, which is below every plausible floor
/// and therefore fails closed.
pub fn system_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `now = max(reading, floor)`, with a floor that only ever increases.
///
/// Shared, not copied: the floor is an `Arc<AtomicU64>` so a handle taken at
/// startup — by a TLS verifier, say — sees every later advance. A `Copy` clock
/// carrying the floor by value looks identical at the call site and silently
/// freezes at whatever the floor was when it was taken, which removes the
/// defence for the life of the process.
#[derive(Clone, Default)]
pub struct Clock {
    floor: Arc<AtomicU64>,
}

impl Clock {
    /// A clock whose floor starts at `floor` — the value read back off disk.
    pub fn new(floor: u64) -> Clock {
        Clock {
            floor: Arc::new(AtomicU64::new(floor)),
        }
    }

    /// Enforcement time for `reading`. Pure: this never advances the floor, so
    /// the read path needs no write lock and no atomic store.
    pub fn at(&self, reading: u64) -> u64 {
        reading.max(self.floor())
    }

    /// Enforcement time for the real system clock.
    pub fn now(&self) -> u64 {
        self.at(system_seconds())
    }

    pub fn floor(&self) -> u64 {
        self.floor.load(Ordering::Relaxed)
    }

    /// Record that time has been seen to reach `reading`, and return the
    /// resulting enforcement time. Never moves the floor backwards, whatever the
    /// argument.
    pub fn observe(&self, reading: u64) -> u64 {
        self.floor
            .fetch_max(reading, Ordering::Relaxed)
            .max(reading)
    }
}

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Clock")
            .field("floor", &self.floor())
            .finish()
    }
}

impl PartialEq for Clock {
    fn eq(&self, other: &Clock) -> bool {
        self.floor() == other.floor()
    }
}

impl Eq for Clock {}

// ---------------------------------------------------------------------------
// the records
// ---------------------------------------------------------------------------

/// What act produced a lease.
///
/// Recorded because under #130 the provenance of an approval is what decides
/// which direction it may mint, and an audit that cannot say where a capability
/// came from is not an audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// A peer connected to us unsolicited and the user approved the prompt.
    Inbound,
    /// Our own dial reached this peer and the user approved the prompt.
    OutboundDial,
    /// Carried forward from `[authorized_fingerprints]`.
    Migrated,
    /// The user restored a device they had removed.
    Restored,
}

/// One machine's membership: what `peer` may do to `issued_to`, until when.
///
/// `peer` and `issued_to` are both leaf-certificate SHA-256 fingerprints in the
/// canonical lowercase `aa:bb:..` form — the same string used as the client pin
/// and as the discovery join key, so the identity namespace stays one namespace.
/// `issued_to` is *this* machine: a lease names who it was issued for, so a
/// lease lifted off one machine and dropped onto another is refused rather than
/// honoured.
///
/// The window is half-open, `[issued_at, not_after)`, in unix seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    /// The machine this lease is about.
    pub peer: String,
    /// The machine this lease was issued for — us.
    pub issued_to: String,
    /// Display name. Attacker-influenced (it can arrive over IPC from a peer's
    /// suggested label), so it is sanitised at the door and is never part of a
    /// decision.
    pub label: String,
    pub caps: Caps,
    pub origin: Origin,
    pub issued_at: u64,
    /// First second the lease is **no longer** valid.
    pub not_after: u64,
}

impl Lease {
    /// Normalise and check a lease from any door — a caller's struct literal or
    /// a record replayed off disk. Both are untrusted: the fields are public so
    /// the persistence layer can build one, which means nothing may assume a
    /// `Lease` value came from a verb.
    pub fn canonicalized(self) -> Result<Lease, TrustError> {
        let peer = canonical_fingerprint(&self.peer)
            .ok_or_else(|| TrustError::BadFingerprint(self.peer.clone()))?;
        let issued_to = canonical_fingerprint(&self.issued_to)
            .ok_or_else(|| TrustError::BadFingerprint(self.issued_to.clone()))?;
        if self.not_after <= self.issued_at {
            return Err(TrustError::EmptyTerm {
                issued_at: self.issued_at,
                not_after: self.not_after,
            });
        }
        let term = self.not_after - self.issued_at;
        if term > MAX_TERM_SECS {
            return Err(TrustError::TermTooLong {
                term,
                max: MAX_TERM_SECS,
            });
        }
        let caps = Caps::from_bits_truncating(self.caps.bits());
        if caps.is_empty() {
            // A lease that permits nothing is either a typo in a hand-written
            // record or a lease from a build whose capabilities this one does
            // not understand. Either way it decides nothing, and refusing it
            // says so instead of leaving an inert row that reads as trust.
            return Err(TrustError::NoCapabilities);
        }
        Ok(Lease {
            peer,
            issued_to,
            label: sanitize_label(&self.label),
            caps,
            ..self
        })
    }

    /// Is this lease inside its window at `now`? `now` must come from a
    /// [`Clock`], never straight from the system clock.
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.not_after
    }

    /// Seconds until this lease lapses; zero once it has. For a renewal nudge,
    /// not for a decision.
    pub fn expires_in(&self, now: u64) -> u64 {
        self.not_after.saturating_sub(now)
    }

    /// Still valid, but close enough to lapsing that the user should be asked.
    pub fn is_expiring(&self, now: u64) -> bool {
        self.is_valid_at(now) && self.expires_in(now) <= RENEW_WINDOW_SECS
    }
}

/// A deliberate expulsion. Outranks any lease under the same fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    /// What the device was called when trust was withdrawn, so an expelled
    /// machine stays distinguishable from a stranger.
    pub label: String,
    /// Unix seconds.
    pub at: u64,
}

/// Everything this machine knows about one identity.
///
/// Both fields optional and both kept: a denial does not erase the lease it
/// outranks, which is what makes removal reversible with one verb.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub lease: Option<Lease>,
    pub denial: Option<Denial>,
}

/// The one decision function: what `entry` permits on machine `ours` at `now`.
///
/// Pure, and the only place precedence is expressed. Every question the store
/// answers is this function with a different mask, so there is nothing left for
/// a reader somewhere else to reconcile differently.
pub fn effective_capabilities(entry: &Entry, ours: &str, now: u64) -> Caps {
    if entry.denial.is_some() {
        return Caps::NONE;
    }
    match &entry.lease {
        Some(lease) if lease.issued_to == ours && lease.is_valid_at(now) => lease.caps,
        _ => Caps::NONE,
    }
}

/// Why a verb refused. Returned, never logged here, so the caller chooses
/// between a user-facing message and a log line.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TrustError {
    #[error("{0:?} is not a valid device fingerprint")]
    BadFingerprint(String),
    #[error("this machine holds no record of {0}")]
    Unknown(String),
    #[error("{0} was removed; restore it before granting it anything")]
    Denied(String),
    #[error("this lease was issued to {found}, but this machine is {ours}")]
    WrongMachine { ours: String, found: String },
    #[error("a lease that ends at or before it begins ({issued_at}..{not_after}) is never valid")]
    EmptyTerm { issued_at: u64, not_after: u64 },
    #[error("a lease may not run for {term}s; the ceiling is {max}s")]
    TermTooLong { term: u64, max: u64 },
    #[error("a lease that permits nothing is not a lease")]
    NoCapabilities,
}

// ---------------------------------------------------------------------------
// the store
// ---------------------------------------------------------------------------

/// Every trust decision this machine makes, and the state behind them.
///
/// Shared behind an `Arc<RwLock<_>>` by both TLS verifiers, both clipboard
/// loops and the service, so the read path is a lock and a lookup — no
/// allocation beyond canonicalising the key, no I/O, nothing that can block a
/// handshake.
#[derive(Debug, PartialEq, Eq)]
pub struct TrustStore {
    /// This machine's own fingerprint. Every lease must name it.
    ours: String,
    clock: Clock,
    /// One record per identity, ordered so the file this serialises to does not
    /// churn between saves for no reason.
    entries: BTreeMap<String, Entry>,
}

impl TrustStore {
    /// A store that knows who it is and how far time has got. Nothing else.
    ///
    /// No certificate, no socket, no backend, no runtime, no authority. That is
    /// #127: the reason the daemon had not one behavioural trust test was that
    /// reaching the trust code meant standing up all five.
    pub fn new(ours: &str, floor: u64) -> Result<TrustStore, TrustError> {
        let ours = canonical_fingerprint(ours)
            .ok_or_else(|| TrustError::BadFingerprint(ours.to_string()))?;
        Ok(TrustStore {
            ours,
            clock: Clock::new(floor),
            entries: BTreeMap::new(),
        })
    }

    /// This machine's fingerprint.
    pub fn ours(&self) -> &str {
        &self.ours
    }

    /// A handle on the floor. Cloning it shares the floor rather than snapshotting
    /// it, so a long-lived holder tracks every advance.
    pub fn clock(&self) -> Clock {
        self.clock.clone()
    }

    /// Enforcement time right now.
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    // -- the verbs ---------------------------------------------------------

    /// Replay a lease into the store without touching any denial.
    ///
    /// The load door: `crate::trust_file` rebuilds the store through it, so disk
    /// is not a way around canonicalisation. It deliberately does **not** clear
    /// a denial — a stored record may legitimately hold both, and a load that
    /// silently un-blocked a device would be the laundering route the seal
    /// exists to close.
    pub fn admit(&mut self, lease: Lease) -> Result<(), TrustError> {
        let lease = lease.canonicalized()?;
        if lease.issued_to != self.ours {
            return Err(TrustError::WrongMachine {
                ours: self.ours.clone(),
                found: lease.issued_to,
            });
        }
        let peer = lease.peer.clone();
        self.entries.entry(peer).or_default().lease = Some(lease);
        Ok(())
    }

    /// Replay a denial into the store without touching any lease.
    pub fn admit_denial(&mut self, fingerprint: &str, denial: Denial) {
        let denial = Denial {
            label: sanitize_label(&denial.label),
            ..denial
        };
        self.entries.entry(key(fingerprint)).or_default().denial = Some(denial);
    }

    /// Issue (or renew, or widen) a lease. The user-facing grant.
    ///
    /// Issuing **clears any denial** of that fingerprint. That is the whole of
    /// "removal is reversible": there is no tombstone to launder around, because
    /// the record of an expulsion is not a separate table that has to outrank
    /// this one — it is a field this verb clears. A user who removed a machine
    /// by mistake pairs it again; the machine does not have to burn its identity
    /// and come back as a stranger (#125).
    ///
    /// This is a grant, so the caller is responsible for refusing it while a
    /// peer is driving this machine. The store cannot see that, and a check it
    /// cannot make is a check it must not pretend to make.
    pub fn issue(
        &mut self,
        fingerprint: &str,
        label: &str,
        caps: Caps,
        term_secs: u64,
    ) -> Result<(), TrustError> {
        self.issue_with_origin(fingerprint, label, caps, term_secs, Origin::Inbound)
    }

    /// [`TrustStore::issue`], recording which act produced the lease.
    pub fn issue_with_origin(
        &mut self,
        fingerprint: &str,
        label: &str,
        caps: Caps,
        term_secs: u64,
        origin: Origin,
    ) -> Result<(), TrustError> {
        let now = self.now();
        let term = term_secs.min(MAX_TERM_SECS);
        let lease = Lease {
            peer: fingerprint.to_string(),
            issued_to: self.ours.clone(),
            label: label.to_string(),
            caps,
            origin,
            issued_at: now,
            not_after: now.saturating_add(term),
        }
        .canonicalized()?;
        let peer = lease.peer.clone();
        let entry = self.entries.entry(peer).or_default();
        entry.denial = None;
        entry.lease = Some(lease);
        Ok(())
    }

    /// Extend an existing lease to a fresh term. Never widens capabilities, and
    /// never un-blocks a removed device.
    pub fn renew(&mut self, fingerprint: &str, term_secs: u64) -> Result<(), TrustError> {
        let fp = key(fingerprint);
        let now = self.now();
        let term = term_secs.min(MAX_TERM_SECS);
        let Some(entry) = self.entries.get_mut(&fp) else {
            return Err(TrustError::Unknown(fp));
        };
        if entry.denial.is_some() {
            return Err(TrustError::Denied(fp));
        }
        let Some(lease) = entry.lease.as_mut() else {
            return Err(TrustError::Unknown(fp));
        };
        lease.issued_at = lease.issued_at.min(now);
        lease.not_after = now.saturating_add(term);
        Ok(())
    }

    /// Drop capabilities from an existing lease without ending the record.
    ///
    /// The narrow half of the two verbs: taking permission away needs no
    /// authority, so this is safe to reach from anywhere the user can act.
    /// Forgetting a machine's dial configuration drops the outbound bits and
    /// leaves the inbound lease alone, which is the case that used to be
    /// impossible to express (#130). Narrowing to nothing ends the lease — but
    /// it does **not** record a denial, so the device lapses rather than being
    /// expelled.
    ///
    /// Returns the remaining capabilities, or `None` if there was no lease.
    pub fn drop_capabilities(&mut self, fingerprint: &str, drop: Caps) -> Option<Caps> {
        let fp = key(fingerprint);
        let entry = self.entries.get_mut(&fp)?;
        let lease = entry.lease.as_mut()?;
        lease.caps = lease.caps.without(drop);
        let left = lease.caps;
        if left.is_empty() {
            entry.lease = None;
            if entry.denial.is_none() {
                self.entries.remove(&fp);
            }
        }
        Some(left)
    }

    /// Rename a device we already hold a record for. Must never grant anything:
    /// the label used to be the allowlist's map value, so a rename and a grant
    /// were the same write and only a runtime check separated them.
    pub fn set_label(&mut self, fingerprint: &str, label: &str) -> Result<(), TrustError> {
        let fp = key(fingerprint);
        let label = sanitize_label(label);
        let Some(entry) = self.entries.get_mut(&fp) else {
            return Err(TrustError::Unknown(fp));
        };
        if let Some(lease) = entry.lease.as_mut() {
            lease.label = label.clone();
        }
        if let Some(denial) = entry.denial.as_mut() {
            denial.label = label;
        }
        Ok(())
    }

    /// Expel a device: record the denial, keep the lease it outranks.
    ///
    /// Returns the label it had, so the caller can name the device in what it
    /// tells the user. Sessions are the caller's job: identity is checked once,
    /// at the handshake, so denying does nothing to a connection already up.
    ///
    /// Needs no authority and cannot fail. An unparseable fingerprint is denied
    /// under its trimmed lowercase form rather than rejected — it will simply
    /// never match a lease, and refusing to record an expulsion is the more
    /// dangerous failure of the two.
    pub fn revoke(&mut self, fingerprint: &str) -> String {
        let fp = key(fingerprint);
        let at = self.now();
        let entry = self.entries.entry(fp).or_default();
        let label = entry
            .lease
            .as_ref()
            .map(|l| l.label.clone())
            .or_else(|| entry.denial.as_ref().map(|d| d.label.clone()))
            .unwrap_or_default();
        entry.denial = Some(Denial {
            label: label.clone(),
            at,
        });
        label
    }

    /// Undo a removal. The reversible half of #125, and one verb.
    ///
    /// Clears the denial and nothing else: whatever lease was underneath comes
    /// back exactly as it was, which is why this cannot widen anything. If the
    /// lease had already lapsed, the device is renewable rather than trusted —
    /// still the right outcome, and still not a grant.
    ///
    /// A grant nonetheless, in the sense that matters: it removes a block the
    /// user put there. The caller gates it on local presence.
    pub fn restore(&mut self, fingerprint: &str) -> bool {
        let fp = key(fingerprint);
        let Some(entry) = self.entries.get_mut(&fp) else {
            return false;
        };
        let had = entry.denial.take().is_some();
        if entry.lease.is_none() {
            self.entries.remove(&fp);
        }
        had
    }

    /// Drop the record entirely — no lease, no denial, no memory of either.
    ///
    /// Distinct from [`TrustStore::revoke`] on purpose. Revoking says "this
    /// machine may not come back"; forgetting says "I do not want to look at
    /// this row any more", and turns the device back into a stranger who may
    /// knock. Only ever called because a user asked.
    pub fn forget(&mut self, fingerprint: &str) -> bool {
        self.entries.remove(&key(fingerprint)).is_some()
    }

    // -- decisions ---------------------------------------------------------

    /// Effective capabilities of `fingerprint` right now.
    pub fn capabilities(&self, fingerprint: &str) -> Caps {
        let now = self.now();
        match self.entries.get(&key(fingerprint)) {
            Some(entry) => effective_capabilities(entry, &self.ours, now),
            None => Caps::NONE,
        }
    }

    /// Does this peer hold **every** capability in `want`, right now?
    ///
    /// An empty request, or one naming a bit this build does not enforce, is
    /// refused rather than trivially granted. `contains(NONE)` is true of every
    /// capability set, so a caller that reached here with nothing to ask would
    /// otherwise be told yes about a machine it holds no lease for.
    pub fn permits(&self, fingerprint: &str, want: Caps) -> bool {
        if want.is_empty() || want.bits() & !Caps::KNOWN.bits() != 0 {
            return false;
        }
        self.capabilities(fingerprint).contains(want)
    }

    /// May this peer inject input into us? The inbound admission decision.
    pub fn may_drive_us(&self, fingerprint: &str) -> bool {
        self.permits(fingerprint, Caps::DRIVE_ME)
    }

    /// May we inject input into this peer? The outbound admission decision.
    /// Answering it separately from the one above is the point of the split.
    pub fn we_may_drive(&self, fingerprint: &str) -> bool {
        self.permits(fingerprint, Caps::I_MAY_DRIVE)
    }

    /// May we accept clipboard contents from this peer?
    pub fn clipboard_from(&self, fingerprint: &str) -> bool {
        self.permits(fingerprint, Caps::CLIPBOARD_FROM)
    }

    /// May we send our clipboard to this peer?
    pub fn clipboard_to(&self, fingerprint: &str) -> bool {
        self.permits(fingerprint, Caps::CLIPBOARD_TO)
    }

    /// Has this device been expelled?
    ///
    /// The suppression test for the approval prompt: a denied peer may not put a
    /// dialog on the user's screen, which is the one thing expulsion can
    /// actually enforce — it cannot keep an attacker out, since it can re-key,
    /// but it can stop that peer choosing the moment the user is asked.
    ///
    /// A **lapsed** lease is deliberately not a denial. A device whose lease ran
    /// out must still be able to ask for a renewal, or letting a lease expire
    /// would brick it permanently.
    pub fn is_denied(&self, fingerprint: &str) -> bool {
        self.entries
            .get(&key(fingerprint))
            .is_some_and(|e| e.denial.is_some())
    }

    /// Do we hold any record of this device — lease, denial, lapsed or live?
    ///
    /// The pin test. A lapsed lease must keep its outbound pin, or a device one
    /// renewal away from working is stranded on an address we have forgotten.
    pub fn is_known(&self, fingerprint: &str) -> bool {
        self.entries.contains_key(&key(fingerprint))
    }

    /// May this device raise an approval prompt? Everything but an expelled one.
    pub fn may_prompt(&self, fingerprint: &str) -> bool {
        !self.is_denied(fingerprint)
    }

    /// Does this device hold a lease that is in force right now?
    ///
    /// The "do we already know this machine" test for suppressing a pairing
    /// prompt and for hiding a device from the discovery list. Both must answer
    /// *no* once a lease lapses: a lapsed device is one the user should be
    /// offered again, not one that has quietly vanished from the UI.
    pub fn has_live_lease(&self, fingerprint: &str) -> bool {
        !self.capabilities(fingerprint).is_empty()
    }

    /// Whatever this device is called — the live lease's name, or the name it
    /// had when it was expelled.
    pub fn label(&self, fingerprint: &str) -> Option<String> {
        let entry = self.entries.get(&key(fingerprint))?;
        entry
            .lease
            .as_ref()
            .map(|l| l.label.clone())
            .or_else(|| entry.denial.as_ref().map(|d| d.label.clone()))
    }

    /// The lease held under this fingerprint, in force or not. For rendering — a
    /// lapsed lease still has a label and an expiry worth showing.
    pub fn lease(&self, fingerprint: &str) -> Option<&Lease> {
        self.entries.get(&key(fingerprint))?.lease.as_ref()
    }

    /// The denial recorded against this fingerprint, if any.
    pub fn denial(&self, fingerprint: &str) -> Option<&Denial> {
        self.entries.get(&key(fingerprint))?.denial.as_ref()
    }

    /// Is this device inside its renewal window — trusted now, lapsing soon?
    pub fn is_expiring(&self, fingerprint: &str) -> bool {
        let now = self.now();
        self.lease(fingerprint).is_some_and(|l| l.is_expiring(now)) && !self.is_denied(fingerprint)
    }

    /// Every record, in fingerprint order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &Entry)> {
        self.entries.iter().map(|(fp, e)| (fp.as_str(), e))
    }

    /// Number of records held — lapsed leases and denials included.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when there is nothing here at all.
    ///
    /// One pair of functions that answer the same question. An earlier draft had
    /// `len()` count leases while `is_empty()` also considered denials, so a
    /// writer gating on `len() == 0` would serialise over a file holding every
    /// expulsion — and clippy's `len_without_is_empty` is satisfied by that,
    /// so nothing would have said a word.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // -- expiry ------------------------------------------------------------

    /// Advance the floor to `reading` and report the leases that lapsed since
    /// the last time anybody looked.
    ///
    /// Returns them so the caller can cut their live sessions — expiry has to
    /// bite an established connection exactly as an explicit removal does, or a
    /// lease is only a label. What the caller must **not** do with them is clear
    /// the outbound pin: a lapsed device is renewable, and forgetting which
    /// identity to expect at its address would strand it.
    ///
    /// The records stay. Lapsing is not expulsion and it is not forgetting: the
    /// label, the term and the capabilities are exactly what a renewal needs, and
    /// deleting them turns "renew this device" back into "pair it again".
    ///
    /// Each lease is reported once, because the window is `(old floor, reading]`
    /// and the floor only climbs.
    /// Drops what the store no longer needs to answer its own questions.
    ///
    /// Two different rules, because the two records are not the same kind of
    /// thing. A lapsed lease grants nothing and nothing depends on it, so it
    /// goes whole. A removal is load-bearing forever — it is what stops a
    /// restored backup re-granting an expelled device — so the fingerprint
    /// stays and only the user's name for the machine is dropped.
    ///
    /// Returns how many records were redacted and how many were dropped, so the
    /// caller can decide whether the store is worth rewriting.
    pub fn forget_stale_names(&mut self, reading: u64) -> (usize, usize) {
        let now = self.clock.observe(reading);
        let mut redacted = 0;
        let mut dropped = 0;

        self.entries.retain(|_, e| {
            // A lapsed lease with no removal beside it: nothing refers to it.
            if let (Some(l), None) = (e.lease.as_ref(), e.denial.as_ref()) {
                if l.not_after <= now.saturating_sub(LAPSED_RETENTION_SECS) {
                    dropped += 1;
                    return false;
                }
            }
            true
        });

        for e in self.entries.values_mut() {
            if let Some(d) = e.denial.as_mut() {
                if !d.label.is_empty() && d.at <= now.saturating_sub(NAME_RETENTION_SECS) {
                    d.label.clear();
                    redacted += 1;
                }
            }
            if let Some(l) = e.lease.as_mut() {
                if !l.label.is_empty()
                    && l.not_after <= now.saturating_sub(NAME_RETENTION_SECS)
                    && !l.is_valid_at(now)
                {
                    l.label.clear();
                    redacted += 1;
                }
            }
        }

        (redacted, dropped)
    }

    pub fn sweep(&mut self, reading: u64) -> Vec<Lease> {
        let since = self.clock.floor();
        let now = self.clock.observe(reading);
        self.entries
            .values()
            .filter_map(|e| e.lease.as_ref())
            .filter(|l| l.not_after > since && l.not_after <= now)
            .cloned()
            .collect()
    }

    // -- migration ---------------------------------------------------------

    /// Turn the two legacy `config.toml` tables into records. Runs once per
    /// installation; afterwards those tables are a cache nothing reads.
    ///
    /// # Capabilities a carried-forward fingerprint gets
    ///
    /// [`Caps::INBOUND`] always. [`Caps::OUTBOUND`] only when `dialled` names it
    /// — that is, when a `[[clients]]` entry actually pinned that fingerprint.
    ///
    /// The tempting answer is "both, because the old flat map fed both
    /// verifiers." It fed both, but membership was **necessary and not
    /// sufficient** for outbound: a dial also needs a client entry aimed at that
    /// peer. A fingerprint that was allowlisted and never a dial target had
    /// outbound permission in theory and never once in practice, so minting it
    /// now would be a capability the user never granted, created at upgrade, by
    /// the code that claims to retire exactly that defect (#130).
    ///
    /// Restricting to the dialled set is therefore not a narrowing anyone can
    /// feel: the mouse keeps crossing to precisely the machines it crossed to
    /// yesterday. What it removes is a permission that was never exercised.
    ///
    /// # Revocations
    ///
    /// Preserved as denials, label and date intact — a tombstone that vanished
    /// would be a denial a dotfiles restore could launder. `revoked_at` is
    /// untrusted input off disk, so it is clamped to `now` (a removal cannot
    /// have happened tomorrow) and is deliberately **not** fed to the clock
    /// floor: one hand-written `revoked_at = 4102444800` would otherwise pin
    /// this machine's clock in 2100 and expire every lease on it instantly.
    ///
    /// # Malformed fingerprints are asymmetric, on purpose
    ///
    /// A malformed *authorized* key is dropped: computed leaf-cert fingerprints
    /// are always canonical, so it could never have matched a peer and dropping
    /// it takes nothing away. A malformed *revoked* key is kept, because the old
    /// revoke door deliberately tombstoned even an invalid string on the grounds
    /// that refusing to record a removal is the more dangerous failure, and
    /// dropping them here would launder exactly the denials that reasoning
    /// protects.
    ///
    /// # Term
    ///
    /// [`MIGRATION_TERM_SECS`], so the carried-forward grant becomes a scheduled
    /// visible decision instead of a permanent invisible one, and so the first
    /// time anyone is asked the direction question is a renewal prompt with the
    /// device in front of them.
    pub fn migrate_from_config(
        &mut self,
        authorized: &HashMap<String, String>,
        revoked: &HashMap<String, RevokedEntry>,
        dialled: &HashSet<String>,
        now: u64,
    ) -> MigrationReport {
        let mut report = MigrationReport::default();

        // Denials first, so the allowlist pass can see them. This IS
        // `subtract_revoked`, applied one final time at the moment the two
        // tables become one record set. After this there is nothing left to rank
        // and nothing left that could disagree.
        for (fp, entry) in revoked {
            let fp = key(fp);
            self.admit_denial(
                &fp,
                Denial {
                    label: entry.label.clone(),
                    at: entry.revoked_at.min(now),
                },
            );
            if !report.denied.contains(&fp) {
                report.denied.push(fp);
            }
        }

        let dialled: HashSet<String> = dialled.iter().map(|fp| key(fp)).collect();

        for (fp, label) in authorized {
            // Both legacy readers lowercase but neither trims, so two spellings
            // of one identity can arrive as two map entries and collapse to one
            // record here. Keyed insertion is what makes that harmless; an
            // earlier draft pushed to a vector and produced a duplicate row that
            // the store's own validator then refused, so the upgrade could not
            // complete at all.
            let Some(fp) = canonical_fingerprint(fp) else {
                report.dropped.push(fp.clone());
                continue;
            };
            if self.is_denied(&fp) {
                if !report.refused.contains(&fp) {
                    report.refused.push(fp);
                }
                continue;
            }
            let caps = if dialled.contains(&fp) {
                Caps::INBOUND | Caps::OUTBOUND
            } else {
                Caps::INBOUND
            };
            let lease = Lease {
                peer: fp.clone(),
                issued_to: self.ours.clone(),
                // The old grant door never sanitised its description — only the
                // rename did — so every label from that door, the CLI included,
                // reaches this point unsanitised.
                label: label.clone(),
                caps,
                origin: Origin::Migrated,
                issued_at: now,
                not_after: now.saturating_add(MIGRATION_TERM_SECS),
            };
            match self.admit(lease) {
                Ok(()) if !report.leased.contains(&fp) => report.leased.push(fp),
                Ok(()) => {}
                Err(_) => report.dropped.push(fp),
            }
        }

        report.leased.sort();
        report.denied.sort();
        report.refused.sort();
        report.dropped.sort();
        report
    }
}

/// What the migration did, for the caller to log. Every list here answers a
/// question a user will ask after upgrading.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Fingerprints that became live leases.
    pub leased: Vec<String>,
    /// Removals preserved.
    pub denied: Vec<String>,
    /// Authorized entries a removal outranked.
    pub refused: Vec<String>,
    /// Authorized entries whose fingerprint could never have matched a peer.
    pub dropped: Vec<String>,
}

#[cfg(test)]
mod tests {
    //! Behavioural coverage for the lease store.
    //!
    //! Everything here calls the code. Nothing reads this repository's own
    //! source text, because the defect class this module exists to catch is *two
    //! fragments disagreeing*, and a grep cannot see disagreement — each fragment
    //! contains its own text, so both guards pass while the product is broken.
    //! The trust core this replaces had eighteen such greps, zero calls, and none
    //! of them could have caught #130, #107 or #125.
    //!
    //! # Why every time here is in the far future
    //!
    //! Enforcement is `max(reading, floor)`. A test that picked a time in the
    //! past would be measuring the machine it runs on rather than the code, so
    //! the base instant sits past any real clock and the floor is seeded there.
    //! `Clock::at` — the same function `Clock::now` calls with a real reading —
    //! is how a test moves time.

    use super::*;

    /// Well past any real system clock, so `max(reading, floor)` is the floor.
    const T0: u64 = 4_000_000_000;
    const HOUR: u64 = 3_600;
    const DAY: u64 = 86_400;
    /// The instant the live config's one removal was recorded.
    const REMOVED_AT: u64 = 1_788_579_979;

    /// A distinct, valid, canonical fingerprint per tag.
    fn fp(tag: u8) -> String {
        (0u8..32)
            .map(|i| format!("{:02x}", tag.wrapping_add(i)))
            .collect::<Vec<_>>()
            .join(":")
    }

    fn us() -> String {
        fp(0x01)
    }

    /// No certificate, no socket, no backend, no runtime, no authority (#127).
    fn store() -> TrustStore {
        TrustStore::new(&us(), T0).expect("a fingerprint and a number is the whole of it")
    }

    fn allow(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(f, l)| ((*f).to_string(), (*l).to_string()))
            .collect()
    }

    fn removed(pairs: &[(&str, u64)]) -> HashMap<String, RevokedEntry> {
        pairs
            .iter()
            .map(|(f, at)| {
                (
                    (*f).to_string(),
                    RevokedEntry {
                        label: "old".to_string(),
                        revoked_at: *at,
                    },
                )
            })
            .collect()
    }

    fn dialled(fps: &[&str]) -> HashSet<String> {
        fps.iter().map(|f| (*f).to_string()).collect()
    }

    // ------------------------------------------------------------ direction

    #[test]
    fn a_store_needs_nothing_to_exist_and_permits_nothing() {
        let s = store();
        let peer = fp(0x10);
        assert!(!s.may_drive_us(&peer));
        assert!(!s.we_may_drive(&peer));
        assert!(!s.clipboard_from(&peer));
        assert!(!s.clipboard_to(&peer));
        assert!(!s.has_live_lease(&peer));
        assert!(!s.is_known(&peer));
        assert!(s.is_empty());
    }

    #[test]
    fn a_peer_that_may_drive_us_is_not_thereby_one_we_may_drive() {
        // Issue #130 in one assertion pair. The old store had a single map whose
        // membership answered both verifiers, so approving a peer in either
        // direction handed it the other one for free.
        let mut s = store();
        let peer = fp(0x11);
        s.issue(&peer, "shop floor pc", Caps::DRIVE_ME, DAY)
            .expect("issue");

        assert!(s.may_drive_us(&peer));
        assert!(
            !s.we_may_drive(&peer),
            "the same peer must NOT become one we may drive — that grant was \
             never made"
        );
    }

    /// A removal must keep biting forever. The user's NAME for the machine
    /// must not.
    ///
    /// The fingerprint is public — this machine multicasts its own in every
    /// mDNS announcement — so keeping one leaks nothing. The label is the
    /// user's own name for their own machine, and keeping every label forever
    /// turns the store into an inventory of every device ever paired.
    #[test]
    fn an_old_removal_keeps_biting_after_its_name_is_forgotten() {
        let mut s = store();
        let gone = fp(0x31);
        s.issue(&gone, "living room", Caps::INBOUND, DAY)
            .expect("issue");
        s.revoke(&gone);

        let far_future = s.now() + NAME_RETENTION_SECS + DAY;
        let (redacted, dropped) = s.forget_stale_names(far_future);
        assert_eq!(
            (redacted, dropped),
            (2, 0),
            "both names go — a removal keeps the lease beside it so `restore` \
             can bring it back, and the lease carries the same name — but \
             nothing is dropped"
        );

        assert!(
            s.denial(&gone).is_some(),
            "the removal itself must survive — it is what stops a restored \
             backup re-granting an expelled device"
        );
        assert_eq!(
            s.denial(&gone).map(|d| d.label.as_str()),
            Some(""),
            "the user's name for the machine is gone"
        );
        assert_eq!(
            s.entries()
                .find(|(k, _)| *k == gone)
                .and_then(|(_, e)| e.lease.as_ref())
                .map(|l| l.label.as_str()),
            Some(""),
            "the copy kept for restore must not survive as the inventory the \
             redaction exists to remove"
        );
        assert!(!s.may_drive_us(&gone), "and it still permits nothing");
    }

    /// A lapsed lease grants nothing and nothing refers to it, so it goes whole
    /// rather than lingering as a redacted row.
    #[test]
    fn a_long_lapsed_lease_is_dropped_rather_than_kept_as_an_empty_row() {
        let mut s = store();
        let old = fp(0x32);
        s.issue(&old, "old laptop", Caps::INBOUND, DAY)
            .expect("issue");

        let far_future = s.now() + LAPSED_RETENTION_SECS + DAY;
        let (_, dropped) = s.forget_stale_names(far_future);
        assert_eq!(dropped, 1);
        assert!(
            !s.entries().any(|(k, _)| k == old),
            "nothing depends on a lapsed lease"
        );
    }

    /// The pass must never touch a device that is still working.
    #[test]
    fn a_live_lease_keeps_its_name_however_old_the_store_is() {
        let mut s = store();
        let live = fp(0x33);
        s.issue(&live, "desk mac", Caps::INBOUND, MAX_TERM_SECS)
            .expect("issue");

        let later = s.now() + NAME_RETENTION_SECS + DAY;
        let (redacted, dropped) = s.forget_stale_names(later);
        assert_eq!((redacted, dropped), (0, 0));
        assert!(s.may_drive_us(&live));
        assert_eq!(
            s.entries()
                .find(|(k, _)| *k == live)
                .and_then(|(_, e)| e.lease.as_ref())
                .map(|l| l.label.as_str()),
            Some("desk mac"),
            "a machine still in use keeps its name"
        );
    }

    #[test]
    fn approving_an_outbound_dial_does_not_grant_that_machine_inbound_control() {
        let mut s = store();
        let receiver = fp(0x12);
        s.issue_with_origin(
            &receiver,
            "living room",
            Caps::OUTBOUND,
            DAY,
            Origin::OutboundDial,
        )
        .expect("issue");

        assert!(s.we_may_drive(&receiver));
        assert!(s.clipboard_to(&receiver));
        assert!(
            !s.may_drive_us(&receiver),
            "confirming the receiver OUR OWN dial reached must never let it \
             drive us — nobody was asked that question"
        );
        assert!(!s.clipboard_from(&receiver));
        assert_eq!(s.capabilities(&receiver), Caps::OUTBOUND);
    }

    #[test]
    fn asking_for_no_capability_is_not_a_grant() {
        let s = store();
        assert!(
            !s.permits(&fp(0x13), Caps::NONE),
            "`contains(NONE)` is true of every capability set, so an empty \
             request must be refused rather than trivially answered yes"
        );
    }

    #[test]
    fn asking_for_a_capability_this_build_does_not_enforce_is_refused() {
        let mut s = store();
        let peer = fp(0x14);
        s.issue(&peer, "peer", Caps::DRIVE_ME, DAY).expect("issue");
        assert!(!s.permits(&peer, Caps(0x4000)));
        assert!(!s.permits(&peer, Caps::DRIVE_ME.union(Caps(0x4000))));
    }

    #[test]
    fn contains_means_every_bit_not_any_bit() {
        let half = Caps::INBOUND | Caps::I_MAY_DRIVE;
        assert!(half.intersects(Caps::OUTBOUND));
        assert!(
            !half.contains(Caps::OUTBOUND),
            "holding one bit of a direction is not holding the direction"
        );
        assert!(half.contains(Caps::INBOUND));
    }

    #[test]
    fn capability_bits_this_build_does_not_enforce_are_dropped_not_stored() {
        assert_eq!(Caps::from_bits_truncating(u16::MAX), Caps::KNOWN);
        assert!(Caps::from_bits_truncating(0x4000).is_empty());
        let mut s = store();
        let peer = fp(0x15);
        s.issue(&peer, "future", Caps::DRIVE_ME.union(Caps(0x4000)), DAY)
            .expect("issue");
        assert_eq!(
            s.lease(&peer).expect("lease").caps,
            Caps::DRIVE_ME,
            "a bit nothing checks must never sit in a lease looking like \
             permission — the UI would show it"
        );
    }

    #[test]
    fn capabilities_render_for_a_human() {
        assert_eq!(Caps::NONE.to_string(), "none");
        assert_eq!(Caps::INBOUND.to_string(), "drive-me+clipboard-from");
        assert_eq!(Caps::OUTBOUND.to_string(), "i-may-drive+clipboard-to");
    }

    // ---------------------------------------------------------------- expiry

    #[test]
    fn an_expired_lease_permits_nothing_at_all() {
        let mut s = store();
        let peer = fp(0x20);
        s.issue(&peer, "laptop", Caps::KNOWN, HOUR).expect("issue");

        s.clock().observe(T0 + HOUR - 1);
        assert!(
            s.may_drive_us(&peer),
            "one second before expiry the lease is still good"
        );

        s.clock().observe(T0 + HOUR);
        assert_eq!(
            s.capabilities(&peer),
            Caps::NONE,
            "at not_after the lease is over — the boundary fails closed, it does \
             not grant one last second"
        );
        assert!(!s.may_drive_us(&peer));
        assert!(!s.we_may_drive(&peer));
        assert!(!s.clipboard_from(&peer));
    }

    #[test]
    fn expiry_is_decided_when_the_question_is_asked_not_by_a_sweep() {
        // If expiry were a sweep, a lease would stay honoured until the sweep
        // next ran, and a daemon that never got to run it would honour it
        // forever. The decision function refuses on its own, against a record
        // nothing has touched.
        let entry = Entry {
            lease: Some(Lease {
                peer: fp(0x21),
                issued_to: us(),
                label: "peer".to_string(),
                caps: Caps::DRIVE_ME,
                origin: Origin::Inbound,
                issued_at: T0,
                not_after: T0 + HOUR,
            }),
            denial: None,
        };

        assert!(effective_capabilities(&entry, &us(), T0 + HOUR - 1).contains(Caps::DRIVE_ME));
        assert_eq!(
            effective_capabilities(&entry, &us(), T0 + HOUR),
            Caps::NONE,
            "the same record grants nothing after not_after, with no sweep having \
             run and no state having changed"
        );
        assert!(
            entry.lease.is_some(),
            "the record is untouched — the refusal is computed, not stored"
        );
    }

    #[test]
    fn a_sweep_reports_each_lapse_exactly_once() {
        let mut s = store();
        let (a, b) = (fp(0x22), fp(0x23));
        s.issue(&a, "a", Caps::DRIVE_ME, HOUR).expect("issue");
        s.issue(&b, "b", Caps::DRIVE_ME, DAY).expect("issue");

        assert!(s.sweep(T0 + 60).is_empty(), "nothing has lapsed yet");

        let lapsed = s.sweep(T0 + HOUR);
        assert_eq!(lapsed.len(), 1);
        assert_eq!(lapsed[0].peer, a);
        assert_eq!(lapsed[0].label, "a");

        assert!(
            s.sweep(T0 + HOUR + 60).is_empty(),
            "reporting a lapse twice would cut the same sessions twice and log \
             the same warning forever"
        );

        let lapsed = s.sweep(T0 + DAY);
        assert_eq!(lapsed.len(), 1);
        assert_eq!(lapsed[0].peer, b);
    }

    #[test]
    fn a_lapsed_lease_keeps_everything_needed_to_renew_it() {
        let mut s = store();
        let peer = fp(0x24);
        s.issue(&peer, "workshop", Caps::INBOUND, HOUR)
            .expect("issue");
        s.sweep(T0 + DAY);

        assert!(!s.may_drive_us(&peer), "it has lapsed");
        assert!(
            s.is_known(&peer),
            "but the record survives — deleting it turns `renew this device` \
             back into `pair it again`, and strands its outbound pin"
        );
        assert_eq!(s.label(&peer).as_deref(), Some("workshop"));
        assert_eq!(s.lease(&peer).expect("lease").caps, Caps::INBOUND);
        assert!(!s.is_denied(&peer), "a lapse is not an expulsion");
        assert!(s.may_prompt(&peer));

        s.renew(&peer, DAY).expect("renew");
        assert!(s.may_drive_us(&peer));
    }

    #[test]
    fn an_upgraded_fleet_is_not_dead_the_next_morning_and_is_warned_before_it_is() {
        let mut s = store();
        let peer = fp(0x25);
        let mut config = HashMap::new();
        config.insert(peer.clone(), "desk".to_string());
        s.migrate_from_config(&config, &HashMap::new(), &HashSet::new(), T0);

        s.clock().observe(T0 + 365 * DAY);
        assert!(
            s.may_drive_us(&peer),
            "a year of not thinking about it must still work"
        );
        assert!(!s.is_expiring(&peer), "and must not nag for most of it");

        s.clock().observe(T0 + 395 * DAY);
        assert!(
            s.is_expiring(&peer),
            "the warning must come before the outage, not explain it afterwards"
        );
        assert!(s.may_drive_us(&peer));

        s.clock().observe(T0 + MIGRATION_TERM_SECS);
        assert!(!s.may_drive_us(&peer));
        assert!(
            !s.is_expiring(&peer),
            "past the term there is nothing to warn"
        );
    }

    // ----------------------------------------------------------------- clock

    #[test]
    fn rolling_the_system_clock_backward_extends_nothing() {
        let mut s = store();
        let peer = fp(0x30);
        s.issue(&peer, "kiosk", Caps::DRIVE_ME, HOUR)
            .expect("issue");

        s.clock().observe(T0 + HOUR);
        assert!(!s.may_drive_us(&peer), "the lease has lapsed");

        let clock = s.clock();
        assert_eq!(
            clock.at(T0 - DAY),
            T0 + HOUR,
            "a backward reading must not move enforcement time — the floor only \
             ever increases"
        );
        assert_eq!(clock.observe(T0 - DAY), T0 + HOUR);
        assert_eq!(clock.floor(), T0 + HOUR);
        assert!(
            !s.may_drive_us(&peer),
            "winding the receiver's wall clock back is exactly the move an \
             injector makes; it must buy nothing"
        );
    }

    #[test]
    fn a_lease_that_lapsed_before_the_floor_is_refused_at_a_backdated_reading() {
        // The floor rule, isolated from the store, so deleting `max(reading,
        // floor)` from `Clock::at` fails here and not only somewhere downstream.
        let clock = Clock::new(T0);
        assert_eq!(clock.at(T0 - 1_000), T0);
        let lease = Lease {
            peer: fp(0x31),
            issued_to: us(),
            label: "kiosk".to_string(),
            caps: Caps::DRIVE_ME,
            origin: Origin::Inbound,
            issued_at: T0 - 2_000,
            not_after: T0 - 500,
        };
        let entry = Entry {
            lease: Some(lease),
            denial: None,
        };
        assert_eq!(
            effective_capabilities(&entry, &us(), clock.at(T0 - 1_000)),
            Caps::NONE,
            "a lease that expired before the floor must stay expired however far \
             back the wall clock is wound"
        );
    }

    #[test]
    fn rolling_the_system_clock_forward_expires_a_lease_early_rather_than_late() {
        let mut s = store();
        let peer = fp(0x32);
        s.issue(&peer, "kiosk", Caps::DRIVE_ME, DAY).expect("issue");
        assert!(s.may_drive_us(&peer));

        s.clock().observe(T0 + DAY + 1);
        assert!(
            !s.may_drive_us(&peer),
            "a forward jump must end the lease, not be ignored — over-strict is a \
             bug report, over-permissive is an incident"
        );

        s.clock().observe(T0 + 1);
        assert!(
            !s.may_drive_us(&peer),
            "and correcting the clock afterwards must not resurrect it"
        );
    }

    #[test]
    fn a_clock_taken_at_startup_sees_the_floor_advance() {
        // The TLS verifiers take a clock once and hold it for the life of the
        // process. One that captured the floor by value would freeze at whatever
        // it was then — `now()` would be the raw system clock forever, and the
        // defence would be gone with nothing to see at the call site.
        let mut s = store();
        let held = s.clock();
        assert_eq!(held.floor(), T0);
        s.sweep(T0 + DAY);
        assert_eq!(
            held.floor(),
            T0 + DAY,
            "a held clock must track the store's floor, not a snapshot of it"
        );
        assert_eq!(held.at(T0), T0 + DAY);
    }

    #[test]
    fn the_system_clock_helper_is_plausible_and_the_floor_swallows_a_broken_one() {
        // Not a test of this machine's clock: only that the helper reports a real
        // second count, and that the floor rule wins either way.
        assert!(system_seconds() > 1_700_000_000, "got {}", system_seconds());
        let clock = Clock::new(T0);
        assert_eq!(
            clock.now(),
            T0,
            "a real clock is behind our far-future floor"
        );
        assert_eq!(clock.at(0), T0, "a dead RTC reporting the epoch loses");
    }

    // ------------------------------------------------------- removal + return

    #[test]
    fn a_device_removed_and_added_again_is_trusted() {
        // Issue #125. The old store refused this outright: the grant door checked
        // the tombstone and returned, telling the user to reinstall hops on the
        // other machine so it would generate a new identity.
        let mut s = store();
        let peer = fp(0x40);
        s.issue(&peer, "old thinkpad", Caps::DRIVE_ME, DAY)
            .expect("issue");
        s.revoke(&peer);
        assert!(!s.may_drive_us(&peer), "removal must bite immediately");

        s.issue(&peer, "old thinkpad", Caps::DRIVE_ME, DAY)
            .expect("re-adding a removed device must be possible — that is #125");
        assert!(s.may_drive_us(&peer));
        assert!(
            !s.is_denied(&peer),
            "the removal must not survive the re-add"
        );
    }

    #[test]
    fn restoring_a_removed_device_brings_back_the_lease_it_had() {
        // One verb, and it is reversible. The lease is not erased by removal —
        // the denial outranks it — so undoing the removal restores exactly the
        // capabilities that were granted, and not a bit more.
        let mut s = store();
        let peer = fp(0x41);
        s.issue(&peer, "desk mac", Caps::INBOUND, DAY)
            .expect("issue");
        s.revoke(&peer);
        assert!(s.restore(&peer), "there was a removal to undo");

        assert!(s.may_drive_us(&peer));
        assert!(s.clipboard_from(&peer));
        assert!(
            !s.we_may_drive(&peer),
            "restoring must return the lease that existed, never widen it"
        );
        assert!(!s.restore(&peer), "and undoing nothing reports nothing");
    }

    #[test]
    fn restoring_a_device_whose_lease_had_lapsed_does_not_mint_one() {
        let mut s = store();
        let peer = fp(0x42);
        s.issue(&peer, "kiosk", Caps::DRIVE_ME, HOUR)
            .expect("issue");
        s.revoke(&peer);
        s.clock().observe(T0 + DAY);

        assert!(s.restore(&peer));
        assert!(
            !s.may_drive_us(&peer),
            "lifting the block clears the block; it does not grant anything"
        );
        assert!(s.may_prompt(&peer), "it may ask to be renewed");
        assert!(s.is_known(&peer));
    }

    #[test]
    fn a_removal_outranks_an_unexpired_lease() {
        let mut s = store();
        let peer = fp(0x43);
        s.issue(&peer, "kiosk", Caps::KNOWN, DAY).expect("issue");
        assert_eq!(s.revoke(&peer), "kiosk", "the name comes back for the log");

        assert!(
            s.is_known(&peer),
            "the lease is still on file — a removal outranks it rather than \
             erasing it, which is what makes it reversible"
        );
        assert_eq!(s.capabilities(&peer), Caps::NONE);
        assert!(!s.clipboard_from(&peer));
        assert!(!s.clipboard_to(&peer));
    }

    #[test]
    fn only_an_explicit_local_verb_clears_a_removal() {
        let mut s = store();
        let peer = fp(0x44);
        s.issue(&peer, "kiosk", Caps::INBOUND, DAY).expect("issue");
        s.revoke(&peer);

        assert_eq!(s.renew(&peer, DAY), Err(TrustError::Denied(peer.clone())));
        s.set_label(&peer, "friendly name").expect("rename is fine");
        s.drop_capabilities(&peer, Caps::CLIPBOARD_FROM);
        assert!(
            s.is_denied(&peer),
            "extending, renaming and narrowing must all leave the removal standing"
        );

        assert!(s.restore(&peer));
        assert!(!s.is_denied(&peer));
    }

    #[test]
    fn an_expelled_device_may_not_summon_a_prompt_but_a_lapsed_one_may() {
        let mut s = store();
        let (lapsed, expelled) = (fp(0x45), fp(0x46));
        s.issue(&lapsed, "laptop", Caps::DRIVE_ME, HOUR)
            .expect("issue");
        s.issue(&expelled, "kiosk", Caps::DRIVE_ME, DAY)
            .expect("issue");
        s.revoke(&expelled);
        s.clock().observe(T0 + DAY);

        assert!(
            s.may_prompt(&lapsed),
            "a lapsed device must be able to ask again, or letting a lease \
             expire would brick it for good"
        );
        assert!(
            !s.may_prompt(&expelled),
            "an expelled peer cannot be excluded — it can re-key — but it must \
             not get to choose the moment the user is asked a security question"
        );
    }

    #[test]
    fn forgetting_a_device_is_not_the_same_verb_as_removing_it() {
        let mut s = store();
        let peer = fp(0x47);
        s.issue(&peer, "kiosk", Caps::DRIVE_ME, DAY).expect("issue");
        s.revoke(&peer);
        assert!(s.forget(&peer));
        assert!(
            !s.is_known(&peer) && !s.is_denied(&peer),
            "forgetting drops the row entirely; the machine becomes a stranger \
             who may knock, which is a different thing from being expelled"
        );
        assert!(!s.forget(&peer));
    }

    // ------------------------------------------------------------- the machine

    #[test]
    fn a_lease_issued_to_another_machine_is_ignored() {
        let peer = fp(0x50);
        let mine = Entry {
            lease: Some(Lease {
                peer: peer.clone(),
                issued_to: us(),
                label: "peer".to_string(),
                caps: Caps::DRIVE_ME,
                origin: Origin::Inbound,
                issued_at: T0,
                not_after: T0 + DAY,
            }),
            denial: None,
        };
        assert!(
            effective_capabilities(&mine, &us(), T0).contains(Caps::DRIVE_ME),
            "a lease issued to us is honoured, so the next assertion cannot pass \
             by accident"
        );

        let theirs = Entry {
            lease: Some(Lease {
                issued_to: fp(0x02),
                ..mine.lease.clone().expect("built above")
            }),
            denial: None,
        };
        assert_eq!(
            effective_capabilities(&theirs, &us(), T0),
            Caps::NONE,
            "a lease minted for a different machine must not be replayable into \
             this one"
        );
    }

    #[test]
    fn admitting_a_lease_issued_to_another_machine_is_refused_at_the_door() {
        let mut s = store();
        let err = s
            .admit(Lease {
                peer: fp(0x51),
                issued_to: fp(0x02),
                label: "borrowed".to_string(),
                caps: Caps::DRIVE_ME,
                origin: Origin::Inbound,
                issued_at: T0,
                not_after: T0 + DAY,
            })
            .expect_err("a lease naming another machine is not a lease here");
        assert!(matches!(err, TrustError::WrongMachine { .. }));
        assert!(!s.may_drive_us(&fp(0x51)));
    }

    // -------------------------------------------------------- capability bits

    #[test]
    fn turning_off_the_clipboard_leaves_input_untouched() {
        let mut s = store();
        let peer = fp(0x60);
        s.issue(&peer, "desk mac", Caps::INBOUND, DAY)
            .expect("issue");
        assert_eq!(
            s.drop_capabilities(&peer, Caps::CLIPBOARD_FROM),
            Some(Caps::DRIVE_ME)
        );

        assert!(s.may_drive_us(&peer));
        assert!(!s.clipboard_from(&peer));
        assert!(!s.is_denied(&peer), "narrowing is not expulsion");
    }

    #[test]
    fn forgetting_a_dial_drops_the_outbound_half_and_leaves_the_inbound_lease() {
        // The case that used to be impossible to express: deleting a device's
        // dial configuration revoked its key outright, so a machine you only
        // wanted to stop sending to also stopped being able to reach you.
        let mut s = store();
        let peer = fp(0x61);
        s.issue(&peer, "both ways", Caps::INBOUND | Caps::OUTBOUND, DAY)
            .expect("issue");
        assert_eq!(
            s.drop_capabilities(&peer, Caps::OUTBOUND),
            Some(Caps::INBOUND)
        );
        assert!(s.may_drive_us(&peer));
        assert!(!s.we_may_drive(&peer));
        assert!(!s.is_denied(&peer));
    }

    #[test]
    fn narrowing_everything_ends_the_lease_without_expelling() {
        let mut s = store();
        let peer = fp(0x62);
        s.issue(&peer, "one way", Caps::DRIVE_ME, DAY)
            .expect("issue");
        assert_eq!(s.drop_capabilities(&peer, Caps::KNOWN), Some(Caps::NONE));
        assert!(s.lease(&peer).is_none());
        assert!(!s.is_denied(&peer));
        assert!(!s.is_known(&peer));
    }

    #[test]
    fn narrowing_a_removed_device_keeps_the_removal_on_file() {
        let mut s = store();
        let peer = fp(0x63);
        s.issue(&peer, "kiosk", Caps::DRIVE_ME, DAY).expect("issue");
        s.revoke(&peer);
        assert_eq!(s.drop_capabilities(&peer, Caps::KNOWN), Some(Caps::NONE));
        assert!(
            s.is_denied(&peer),
            "the lease going away must not take the expulsion with it"
        );
        assert_eq!(s.label(&peer).as_deref(), Some("kiosk"));
    }

    // ------------------------------------------------------- canonicalisation

    #[test]
    fn an_uppercase_fingerprint_cannot_evade_a_removal() {
        // The exact shape of #67, and the shape it came back in: the write side
        // canonicalised and the read side compared "as given", on the grounds
        // that a non-canonical lookup matches nothing and so fails closed. That
        // is true where the answer is a capability set and FALSE where the
        // answer is a boolean denial — matching nothing there means NOT denied.
        let mut s = store();
        let peer = fp(0x70);
        s.issue(&peer, "expelled", Caps::DRIVE_ME, DAY)
            .expect("issue");
        s.revoke(&peer);

        let shouted = peer.to_uppercase();
        assert!(
            s.is_denied(&shouted),
            "shouting the fingerprint must not walk past the expulsion"
        );
        assert!(!s.may_drive_us(&shouted));
        assert!(
            !s.may_prompt(&shouted),
            "and it must not buy back the ability to summon a prompt"
        );

        // Both directions: recorded shouted, asked quietly.
        let other = fp(0x71);
        s.revoke(&other.to_uppercase());
        assert!(s.is_denied(&other));
        assert!(!s.may_prompt(&other));
    }

    #[test]
    fn a_removal_verb_under_a_shouted_spelling_still_removes() {
        // A capability-removal verb that silently no-ops is worse than one that
        // errors: the caller reads `None` as "nothing to do" and the peer keeps
        // the permission it was supposed to lose.
        let mut s = store();
        let peer = fp(0x72);
        s.issue(&peer, "both ways", Caps::INBOUND | Caps::OUTBOUND, DAY)
            .expect("issue");
        assert_eq!(
            s.drop_capabilities(&peer.to_uppercase(), Caps::OUTBOUND),
            Some(Caps::INBOUND)
        );
        assert!(!s.we_may_drive(&peer));
        s.set_label(&peer.to_uppercase(), "renamed")
            .expect("rename under either spelling");
        assert_eq!(s.label(&peer).as_deref(), Some("renamed"));
        assert!(s.lease(&peer.to_uppercase()).is_some());
    }

    #[test]
    fn one_record_answers_the_same_however_the_fingerprint_is_spelled() {
        let mut s = store();
        let peer = fp(0x73);
        s.issue(&peer.to_uppercase(), "shouty", Caps::DRIVE_ME, DAY)
            .expect("issue");
        assert_eq!(s.len(), 1, "two spellings must not become two records");
        assert!(s.may_drive_us(&peer) && s.may_drive_us(&peer.to_uppercase()));
        assert_eq!(
            s.capabilities(&peer),
            s.capabilities(&peer.to_uppercase()),
            "a caller that normalises differently must not see a different answer"
        );
    }

    #[test]
    fn a_string_that_is_not_a_fingerprint_cannot_be_granted_anything() {
        let mut s = store();
        assert_eq!(
            s.issue("not-a-fingerprint", "x", Caps::DRIVE_ME, DAY),
            Err(TrustError::BadFingerprint("not-a-fingerprint".to_string()))
        );
        assert!(!s.permits("not-a-fingerprint", Caps::DRIVE_ME));
        assert!(!s.is_known("not-a-fingerprint"));

        // ...but it can still be expelled. Refusing to record a removal is the
        // more dangerous failure, and a junk denial matches no lease anyway.
        s.revoke("  NOT-a-Fingerprint  ");
        assert!(s.is_denied("not-a-fingerprint"));
    }

    #[test]
    fn a_lease_may_not_outlive_the_ceiling() {
        let mut s = store();
        let peer = fp(0x74);
        s.issue(&peer, "forever", Caps::DRIVE_ME, u64::MAX)
            .expect("an over-long request is clamped, not refused");
        assert_eq!(
            s.lease(&peer).expect("lease").not_after,
            T0 + MAX_TERM_SECS,
            "an unbounded lease is the shape being removed"
        );

        let err = s
            .admit(Lease {
                peer: fp(0x75),
                issued_to: us(),
                label: "forever".to_string(),
                caps: Caps::DRIVE_ME,
                origin: Origin::Migrated,
                issued_at: T0,
                not_after: T0 + MAX_TERM_SECS + 1,
            })
            .expect_err("a replayed record may not exceed it either");
        assert!(matches!(err, TrustError::TermTooLong { .. }));
    }

    #[test]
    fn the_migration_term_fits_under_the_ceiling() {
        // These two constants disagreed in an earlier draft (366 against 400),
        // which meant every migrated lease was refused and the whole fleet went
        // dark on the first boot after the upgrade — silently, because a refused
        // lease looks exactly like a device nobody ever trusted.
        let mut s = store();
        let peer = fp(0x76);
        s.admit(Lease {
            peer: peer.clone(),
            issued_to: us(),
            label: "carried".to_string(),
            caps: Caps::INBOUND,
            origin: Origin::Migrated,
            issued_at: T0,
            not_after: T0 + MIGRATION_TERM_SECS,
        })
        .expect("a migrated lease must be admissible");
        assert!(s.may_drive_us(&peer));
    }

    #[test]
    fn a_lease_that_permits_nothing_is_refused() {
        let mut s = store();
        assert_eq!(
            s.issue(&fp(0x77), "", Caps::NONE, DAY),
            Err(TrustError::NoCapabilities)
        );
        assert_eq!(
            s.issue(&fp(0x77), "", Caps(0x4000), DAY),
            Err(TrustError::NoCapabilities),
            "a lease made only of bits this build does not enforce decides \
             nothing, and must say so rather than sit there reading as trust"
        );
    }

    #[test]
    fn a_label_is_sanitised_when_a_lease_is_issued_not_only_when_it_is_renamed() {
        // The old grant path inserted the caller's description verbatim, so a
        // bidi override or a control character reached the config file, the logs
        // and both UIs. Only the rename verb cleaned it.
        let mut s = store();
        let peer = fp(0x78);
        s.issue(&peer, "ev\u{202e}il\u{0007}\u{200b}", Caps::DRIVE_ME, DAY)
            .expect("issue");
        assert_eq!(s.label(&peer).as_deref(), Some("evil"));

        let other = fp(0x79);
        s.revoke(&other);
        s.set_label(&other, "ex\u{202e}pelled").expect("rename");
        assert_eq!(
            s.label(&other).as_deref(),
            Some("expelled"),
            "an expelled device's name is rendered too"
        );
    }

    #[test]
    fn renaming_a_device_grants_it_nothing() {
        let mut s = store();
        let stranger = fp(0x7a);
        assert_eq!(
            s.set_label(&stranger, "trusted laptop"),
            Err(TrustError::Unknown(stranger.clone()))
        );
        assert_eq!(s.capabilities(&stranger), Caps::NONE);
        assert!(
            !s.is_known(&stranger),
            "refuse, do NOT insert — inserting here makes the rename verb a \
             trust grant wearing a different name"
        );

        let known = fp(0x7b);
        s.issue(&known, "old name", Caps::DRIVE_ME, DAY)
            .expect("issue");
        s.set_label(&known, "new name").expect("rename");
        assert_eq!(s.label(&known).as_deref(), Some("new name"));
        assert_eq!(s.capabilities(&known), Caps::DRIVE_ME);
    }

    #[test]
    fn the_two_counters_answer_the_same_question() {
        let mut s = store();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        s.revoke(&fp(0x7c));
        assert_eq!(s.len(), 1);
        assert!(
            !s.is_empty(),
            "a store holding an expulsion is not an empty store — a writer that \
             gated on the other counter would serialise over every removal, and \
             clippy's len_without_is_empty is satisfied either way"
        );
    }

    // --------------------------------------------------------------- migration

    #[test]
    fn migration_grants_outbound_only_to_a_peer_the_old_config_actually_dialled() {
        // The flat allowlist fed both TLS verifiers, so "it was already both
        // directions" is tempting. It was necessary and not sufficient: an
        // outbound dial also needed a [[clients]] entry aimed at that peer, so a
        // fingerprint that was never a dial target had outbound in theory and
        // never once in practice. Minting it now would be a capability the user
        // never granted, created at upgrade, by the code that retires #130.
        let (both, inbound_only) = (fp(0x80), fp(0x81));
        let mut s = store();
        let report = s.migrate_from_config(
            &allow(&[(&both, "receiver"), (&inbound_only, "sender")]),
            &HashMap::new(),
            &dialled(&[&both]),
            T0,
        );

        assert_eq!(report.leased.len(), 2);
        assert!(s.may_drive_us(&both) && s.we_may_drive(&both));
        assert!(
            s.may_drive_us(&inbound_only),
            "a peer that connected in must keep connecting in — this is the \
             direction the fleet was actually using"
        );
        assert!(
            !s.we_may_drive(&inbound_only),
            "and the direction it never exercised must not be minted at upgrade"
        );
    }

    #[test]
    fn a_removed_fingerprint_gets_no_capabilities_at_migration() {
        let peer = fp(0x82);
        let mut s = store();
        let report = s.migrate_from_config(
            &allow(&[(&peer, "attacker")]),
            &removed(&[(&peer, REMOVED_AT)]),
            &dialled(&[&peer]),
            T0,
        );
        assert_eq!(report.refused, vec![peer.clone()]);
        assert_eq!(
            s.capabilities(&peer),
            Caps::NONE,
            "a fingerprint in BOTH legacy tables must not be trusted — the rule \
             that used to be restated at four doors is applied here, once"
        );
        assert!(!s.may_prompt(&peer));
    }

    #[test]
    fn case_does_not_launder_a_removal_at_migration() {
        let peer = fp(0x83);
        let mut s = store();
        s.migrate_from_config(
            &allow(&[(&peer.to_uppercase(), "attacker")]),
            &removed(&[(&peer, REMOVED_AT)]),
            &HashSet::new(),
            T0,
        );
        assert_eq!(
            s.capabilities(&peer),
            Caps::NONE,
            "uppercasing a removed fingerprint must not resurrect it"
        );
    }

    #[test]
    fn a_removal_written_in_uppercase_still_bites_at_migration() {
        let peer = fp(0x84);
        let mut s = store();
        s.migrate_from_config(
            &allow(&[(&peer, "attacker")]),
            &removed(&[(&peer.to_uppercase(), REMOVED_AT)]),
            &HashSet::new(),
            T0,
        );
        assert_eq!(s.capabilities(&peer), Caps::NONE);
        assert!(s.is_denied(&peer));
    }

    #[test]
    fn two_spellings_of_one_fingerprint_collapse_to_one_record() {
        // Neither legacy reader trims, so a TOML key with a leading space is a
        // separate map entry that lands on the same identity here. An earlier
        // draft emitted both and the store's own validator then refused the
        // migration's output, so the upgrade could not complete at all.
        let peer = fp(0x85);
        let spaced = format!("  {}  ", peer.to_uppercase());
        let mut s = store();
        s.migrate_from_config(
            &allow(&[(&peer, "a"), (&spaced, "b")]),
            &removed(&[(&peer, REMOVED_AT), (&spaced, REMOVED_AT)]),
            &HashSet::new(),
            T0,
        );
        assert_eq!(s.len(), 1, "one identity, one record");
        assert!(s.is_denied(&peer));
    }

    #[test]
    fn a_malformed_authorized_fingerprint_is_dropped_but_a_malformed_removal_is_kept() {
        let mut s = store();
        let report = s.migrate_from_config(
            &allow(&[("not-a-fingerprint", "junk")]),
            &removed(&[("also-not-one", REMOVED_AT)]),
            &HashSet::new(),
            T0,
        );
        assert_eq!(report.dropped, vec!["not-a-fingerprint".to_string()]);
        assert!(
            s.is_denied("also-not-one"),
            "an unmatchable GRANT is inert and dropping it takes nothing away; \
             an unmatchable REMOVAL is still a decision the user made, and \
             dropping it would launder exactly the denials that reasoning protects"
        );
    }

    #[test]
    fn a_removal_survives_migration_with_its_label_and_its_date() {
        let peer = fp(0x86);
        let mut s = store();
        let long_ago = T0 - 90 * DAY;
        s.migrate_from_config(
            &HashMap::new(),
            &HashMap::from([(
                peer.clone(),
                RevokedEntry {
                    label: "workshop".to_string(),
                    revoked_at: long_ago,
                },
            )]),
            &HashSet::new(),
            T0,
        );
        let denial = s.denial(&peer).expect("the removal survived");
        assert_eq!(denial.label, "workshop");
        assert_eq!(
            denial.at, long_ago,
            "a past date must be preserved unchanged, or the clamp is \
             indistinguishable from stamping everything with now"
        );
    }

    #[test]
    fn a_future_dated_removal_cannot_poison_the_clock() {
        let peer = fp(0x87);
        let mut s = store();
        s.migrate_from_config(
            &HashMap::new(),
            &removed(&[(&peer, T0 + 1_000 * DAY)]),
            &HashSet::new(),
            T0,
        );
        assert_eq!(
            s.denial(&peer).expect("removal").at,
            T0,
            "a removal cannot have been recorded tomorrow"
        );
        assert_eq!(
            s.clock().floor(),
            T0,
            "and it must never reach the floor — one hand-written revoked_at in \
             2100 would pin this machine's clock there and expire every lease on \
             it instantly"
        );
    }

    #[test]
    fn the_live_config_migrates_to_no_trust_and_a_removal_that_can_be_undone() {
        // The state actually on disk before the upgrade: no clients, an empty
        // `[authorized_fingerprints]`, one removal. Under the old store that
        // machine could never come back.
        let expelled = fp(0x88);
        let mut s = store();
        let report = s.migrate_from_config(
            &HashMap::new(),
            &HashMap::from([(
                expelled.clone(),
                RevokedEntry {
                    label: "workshop".to_string(),
                    revoked_at: REMOVED_AT,
                },
            )]),
            &HashSet::new(),
            T0,
        );

        assert!(
            report.leased.is_empty(),
            "an empty allowlist must migrate to no leases at all"
        );
        assert_eq!(report.denied, vec![expelled.clone()]);
        assert_eq!(s.capabilities(&expelled), Caps::NONE);
        assert!(!s.may_prompt(&expelled));
        assert_eq!(
            s.label(&expelled).as_deref(),
            Some("workshop"),
            "the name it had when it was expelled must survive, or a device you \
             just kicked out is indistinguishable from a stranger"
        );

        assert!(
            s.restore(&expelled),
            "a migrated removal must be reversible — that is #125"
        );
        assert!(s.may_prompt(&expelled));
        assert_eq!(
            s.capabilities(&expelled),
            Caps::NONE,
            "lifting the removal clears the block; it does not mint trust"
        );
    }

    #[test]
    fn a_migrated_label_is_sanitised_on_the_way_in() {
        let peer = fp(0x89);
        let mut s = store();
        s.migrate_from_config(
            &allow(&[(&peer, "ev\u{202e}il")]),
            &HashMap::new(),
            &HashSet::new(),
            T0,
        );
        assert_eq!(s.label(&peer).as_deref(), Some("evil"));
    }
}

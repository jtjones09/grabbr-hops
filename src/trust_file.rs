//! On-disk persistence for the lease store, and the one-time migration off
//! `[authorized_fingerprints]` / `[revoked_fingerprints]`.
//!
//! # Why a separate file and not `[[leases]]` in `config.toml`
//!
//! Five reasons, in the order they matter.
//!
//! 1. **It is what actually closes the config-reload door.** The whole point of
//!    demoting `[authorized_fingerprints]` to a cache is that a config change
//!    stops being a trust change. If leases lived in `config.toml`,
//!    `handle_config_change` would still have to decide, on every `port = …`
//!    edit, whether the trust half also changed — and the door would be shut by
//!    a careful `if`, not by construction. Two files shut it structurally: the
//!    watcher watches `config.toml`, and a `config.toml` event never reaches
//!    the lease store at all.
//!
//! 2. **`write_back` rewrites the whole document on every save.** It
//!    re-serialises the entire `ConfigToml` from memory, and eleven distinct
//!    `FrontendRequest` arms call it. That is eleven code paths per release
//!    that can lose a lease to a bug in something unrelated — the exact shape
//!    of the phantom-client bug already documented on `set_clients`. Trust
//!    should be written when trust changes, and at no other time.
//!
//! 3. **The signature needs stable bytes.** The store is authenticated (see
//!    below), so the signature has to cover an exact byte range. A table inside
//!    a document that `toml_edit` re-emits whenever an unrelated key changes
//!    would need a canonicalisation pass over a sub-document. A whole file
//!    minus one trailing block needs none: the signed bytes are literally the
//!    bytes on disk.
//!
//! 4. **They are different kinds of document.** `config.toml` ships with a
//!    documented example and the user is invited to edit it. This file is
//!    machine state that a hand-edit invalidates. Saying so is much easier when
//!    they are not the same file.
//!
//! 5. **They fail differently.** A broken `config.toml` means "fix your port".
//!    A broken trust store means "this is not the store this machine wrote".
//!    Different errors deserve different messages and different recoveries.
//!
//! The real cost of splitting is skew: a lease can name a fingerprint that
//! `config.toml`'s client pins no longer mention. That skew already exists —
//! `drop_untrusted_pins` is the reconciliation for it — and it is handled by
//! reconciling, not by co-location.
//!
//! # Fail-closed, restated
//!
//! A hand-edit of the store must not be able to grant anything. With one
//! store there is no second table to rank against it, so the property rests on
//! the file itself, in four parts:
//!
//! * **Authentication.** The file is signed by this machine's authority (see
//!   [`crate::authority`]). An edited body, or a store copied in from another
//!   installation, does not verify and the daemon refuses to start.
//! * **Exists-but-unparseable is fatal.** Identical to the rule `Config::new`
//!   already enforces, and for the identical reason: an absent file
//!   legitimately means defaults, a corrupt one never does.
//! * **Rollback.** A signature does not stop restoring an *older, validly
//!   signed* store that still grants a device you have since removed. A
//!   monotonic `serial`, mirrored in a separate signed floor file that only
//!   ever advances, refuses that file.
//! * **Restoring both files.** Restoring both files together is
//!   indistinguishable from a legitimate whole-directory restore, and no
//!   software-only scheme can tell them apart — that residual is what a
//!   hardware monotonic counter closes later, behind the same
//!   [`crate::authority::Authority`] trait. Lease terms used to bound it: a
//!   restored store older than its terms came back already lapsed. No lease
//!   has a term in this release (#183), so today nothing bounds it, and a
//!   restored pair of files grants whatever it held until #185 decides how
//!   long trust lasts.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::trust::{
    Caps, Expiry, Lease, Origin, TrustError, TrustStore, existing_pairing_clipboard,
};

use hops_ipc::Controller;
use hops_ipc::identity::canonical_fingerprint;

use crate::authority::{Authority, AuthorityError, SignatureAlg, verify};
use crate::config::write_atomically;

/// The lease store. TOML so it can be *read* by a human even though editing it
/// invalidates it, and so it uses the parser already in the tree.
pub const TRUST_FILE_NAME: &str = "trust.toml";

/// The monotonic clock/serial floor. A separate file because it advances on a
/// different cadence, and because a floor kept inside the store it protects
/// would roll back with it.
///
/// Named `trust-floor.toml` rather than `trust.floor` on purpose:
/// [`write_atomically`] derives its temp sibling with
/// `with_extension("toml.tmp")`, and `trust.floor` would collide with
/// `trust.toml`'s temp file on exactly that name.
pub const FLOOR_FILE_NAME: &str = "trust-floor.toml";

/// Bumped when the file layout changes incompatibly. A build that meets a
/// version it does not know refuses the file rather than guessing.
///
/// Version 2 (#187) records on each lease whether both machines confirmed the
/// pairing and, once someone chose it, its clipboard. This build reads
/// version 1 as well and writes version 2 at its first save, keeping a copy of
/// the version 1 files beside it ([`TRUST_V1_COPY_NAME`]). Builds that read
/// only version 1, from #158 up, refuse a version 2 store and do not start.
pub const SCHEMA_VERSION: u32 = 2;

/// The version the floor file declares. Its layout did not change with the
/// store's: a build that reads only version 1 parses it, which is what lets
/// such a build start again once `trust.toml` is moved aside.
const FLOOR_VERSION: u32 = 1;

/// Where the save that moves a version 1 store to [`SCHEMA_VERSION`] keeps the
/// store as it was, for a build that reads only version 1. Deleted, with
/// [`FLOOR_V1_COPY_NAME`], by the first save that drops any record it holds,
/// so no removed device survives in it (#184, #187).
pub const TRUST_V1_COPY_NAME: &str = "trust.v1.toml";

/// The floor as it was beside the version 1 store, copied with it: restoring
/// the store alone over a newer floor would be refused as a rollback.
pub const FLOOR_V1_COPY_NAME: &str = "trust-floor.v1.toml";

/// The longest lease a build from before #183 admits: its `MAX_TERM_SECS`,
/// unchanged from #158, which added the trust store, until #183.
/// Copied rather than read from [`crate::trust::MAX_TERM_SECS`], so choosing a
/// ceiling here (#185) cannot move the date those builds are handed.
const OLDER_BUILD_CEILING_SECS: u64 = 400 * 86_400;

/// The `expires_at` saved for a lease that does not lapse: the latest date a
/// build from before #183 accepts for a lease issued at `issued_at`.
///
/// Such a build refuses to start on an active lease with no `expires_at`, and
/// drops, then erases at its next save, a lease dated more than
/// [`OLDER_BUILD_CEILING_SECS`] after `issued_at`. Version 1 stores carried it
/// so builds on both sides of #183 could share one config directory. Version 2
/// keeps writing the same date, which no build reads: [`rebuild`] makes every
/// active lease [`Expiry::Never`].
pub(crate) fn expiry_older_builds_accept(issued_at: u64) -> u64 {
    issued_at.saturating_add(OLDER_BUILD_CEILING_SECS)
}

const TRUST_DOMAIN: &[u8] = b"hops.trust-store.v1\x00";
const FLOOR_DOMAIN: &[u8] = b"hops.trust-floor.v1\x00";
const SIGNATURE_SEPARATOR: &str = "\n[signature]\n";

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum TrustFileError {
    #[error("reading or writing {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Exists but is not what this machine wrote. Always fatal — the daemon
    /// must not fall back to "no trust", because an empty store is
    /// indistinguishable from a widened one to a user who cannot see either.
    #[error(
        "{path} exists but is not a trust store this machine wrote: {reason}\n\
         Refusing to start. hops will not guess at who is allowed to drive this \
         keyboard. If this file came from a backup or another machine, move it \
         aside and pair again."
    )]
    Untrusted { path: PathBuf, reason: String },
    #[error("serialising the trust store: {0}")]
    Serialize(String),
    #[error(transparent)]
    Authority(#[from] AuthorityError),
}

impl TrustFileError {
    fn untrusted(path: &Path, reason: impl Into<String>) -> Self {
        Self::Untrusted {
            path: path.to_path_buf(),
            reason: reason.into(),
        }
    }

    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

// ---------------------------------------------------------------------------
// on-disk shapes
//
// These are DELIBERATELY separate types from the live `Lease` / `Caps` in
// `crate::trust`. The disk schema is a compatibility contract; the in-memory
// type is not. Deriving `Serialize` straight onto the live type would make a
// field rename a silent format change, and would make the format follow
// whatever the store found convenient this quarter. The conversion between the
// two is one `impl` block at the seam and nothing else.
// ---------------------------------------------------------------------------

/// A direction the lease permits. Kebab-case names rather than a bitfield: the
/// file is meant to be readable, and an unknown *name* is a deserialisation
/// error (fail closed), where an unknown *bit* in an integer is silently
/// masked off (fail open).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DiskCap {
    /// This peer may connect to us and drive this machine.
    Inbound,
    /// We may connect to this peer and drive it.
    Outbound,
}

/// Lease state. Expiry is *not* a state: the store decides it
/// ([`crate::trust::Expiry`]), so it cannot drift out of sync with a stored
/// flag.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DiskState {
    /// Carries whatever `caps` says. See [`LeaseRecord::expires_at`].
    Active,
    /// A removal a build before #184 recorded. Carries no capability. Read,
    /// and dropped as the store loads: removing a device now forgets it, so
    /// this build never writes one.
    Revoked,
    /// A machine a build before the trust store listed, to be paired again
    /// (#231). Carries no capability and never loads as a lease: it names
    /// the machine so the app can offer to pair it again or remove it.
    PairAgain,
}

/// What act produced this lease. Recorded because under #130 the provenance of
/// an approval is what decides which direction it may mint, and an audit that
/// cannot say where a capability came from is not an audit.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DiskOrigin {
    /// The peer connected to us and the user approved the prompt.
    Inbound,
    /// Our dial reached this peer and the user approved the prompt.
    OutboundDial,
    /// Carried forward from `[authorized_fingerprints]` by [`TrustStore::migrate_from_config`].
    Migrated,
    /// The person approving chose that this machine controls the peer
    /// (#220). The lease drives in exactly the chosen direction; a record
    /// whose capabilities say otherwise is refused when the store loads.
    ChosenIMayDrive,
    /// The person approving chose that the peer controls this machine.
    ChosenDriveMe,
    /// The person approving chose that each controls the other.
    ChosenBoth,
    // No `Restored`. Removal forgets the machine, so one that comes back is a
    // first contact: it arrives as `Inbound` or `OutboundDial` (#184).
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    /// Canonical `aa:bb:…` leaf-cert fingerprint — the same string the TLS
    /// verifiers compute, so this is the join key with everything else.
    pub fingerprint: String,
    /// Display name. Sanitised on every write; see
    /// [`hops_ipc::identity::sanitize_label`].
    pub label: String,
    pub state: DiskState,
    pub origin: DiskOrigin,
    /// Unix seconds, from `max(system clock, floor)`.
    pub issued_at: u64,
    /// Unix seconds. Not enforced on load: [`rebuild`] makes every active
    /// lease [`Expiry::Never`] (#183).
    ///
    /// Written for every active lease all the same, as 400 days after
    /// `issued_at` ([`expiry_older_builds_accept`]): in version 1 so a build
    /// from before #183 still started on a store a later build saved, and
    /// unchanged in version 2. A date a version 1 store holds may instead be
    /// a term a build from before #183 chose (30 days for an approval); the
    /// next save replaces it.
    ///
    /// **A placeholder, never to be enforced.** Nothing in either version
    /// tells this date apart from a real 400-day term. A build that enforced
    /// it would end every pairing on day 400, the outage #183 removes. A
    /// stored term (#185) needs a schema bump or a new field.
    ///
    /// Absent on a revoked record. Absent on an active lease also loads and
    /// grants, because no stored date decides anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    /// Empty for a revoked record.
    pub caps: Vec<DiskCap>,
    /// Both machines confirmed this pairing (#11, #167). A lease that is not
    /// confirmed is a pairing interrupted before it finished: it is dropped
    /// when the store loads, and the device is added again ([`start`]).
    /// Every lease a version 1 store held predates the confirmation and is
    /// confirmed.
    ///
    /// Required, so no build can read a record without saying what it is.
    pub confirmed: bool,
    /// The clipboard directions someone chose for this pairing: the off
    /// switch writes `[]`. Absent when nobody chose, for a pairing made
    /// before #182: it then loads as the directions the pairing drives
    /// ([`crate::trust::existing_pairing_clipboard`], #186).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clipboard: Option<Vec<DiskClipboard>>,
}

/// A direction the clipboard moves. Names, not bits, for the reason
/// [`DiskCap`] gives.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DiskClipboard {
    /// Accept the peer's clipboard.
    From,
    /// Send the peer this machine's clipboard.
    To,
}

/// The version 1 shapes, read and never written. A version 1 store is read
/// once, by the start that moves it to [`SCHEMA_VERSION`], and its copy is
/// read to learn what records it holds.
mod v1 {
    use super::{AuthorityBlock, DiskCap, DiskOrigin, DiskState, LeaseRecord};
    use serde::Deserialize;

    #[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
    #[cfg_attr(test, derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub(super) struct LeaseRecordV1 {
        pub(super) fingerprint: String,
        pub(super) label: String,
        pub(super) state: DiskState,
        pub(super) origin: DiskOrigin,
        pub(super) issued_at: u64,
        #[serde(default)]
        #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
        pub(super) expires_at: Option<u64>,
        #[serde(default)]
        #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
        pub(super) revoked_at: Option<u64>,
        pub(super) caps: Vec<DiskCap>,
    }

    #[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
    #[cfg_attr(test, derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub(super) struct TrustBodyV1 {
        pub(super) version: u32,
        pub(super) serial: u64,
        pub(super) written_at: u64,
        pub(super) authority: AuthorityBlock,
        #[serde(default)]
        pub(super) leases: Vec<LeaseRecordV1>,
    }

    impl From<LeaseRecordV1> for LeaseRecord {
        /// Confirmed, because version 1 predates the confirmation and a
        /// person cannot compare a number they were never shown (#11, #167).
        /// No clipboard, because nobody chose one (#186).
        fn from(r: LeaseRecordV1) -> Self {
            LeaseRecord {
                fingerprint: r.fingerprint,
                label: r.label,
                state: r.state,
                origin: r.origin,
                issued_at: r.issued_at,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
                caps: r.caps,
                confirmed: true,
                clipboard: None,
            }
        }
    }
}

// There is deliberately no decision function over a `LeaseRecord` here.
//
// There was one — `effective_caps`, `permits`, `is_expired`, `is_expiring` —
// with no production caller, and when #183 stopped enforcing a stored
// `expires_at` it would have gone on reporting those pairings as lapsed. What a
// record grants is decided in one place: `rebuild` it and ask the store.

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct AuthorityBlock {
    alg: String,
    /// Lowercase hex. Inside the signed body on purpose: in the trailing
    /// signature block an attacker could swap key and signature together and
    /// the file would still verify.
    public_key: String,
}

/// Scalars first, then the table, then the array of tables — TOML requires that
/// emission order and `toml_edit`'s serializer enforces it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct TrustBody {
    version: u32,
    /// Monotonic. Every save increments it; the floor refuses anything lower.
    serial: u64,
    written_at: u64,
    authority: AuthorityBlock,
    #[serde(default)]
    leases: Vec<LeaseRecord>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct FloorBody {
    version: u32,
    /// High-water mark of the wall clock. Never decreases.
    seconds: u64,
    /// High-water mark of [`TrustBody::serial`]. Never decreases.
    serial: u64,
    authority: AuthorityBlock,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureBlock {
    /// Lowercase hex of the raw signature.
    value: String,
}

// ---------------------------------------------------------------------------
// hex
//
// Not base64: no crate here depends on base64, and hex is already this
// project's on-disk encoding for key material — it is how
// `generate_fingerprint` renders a SHA-256. One convention, no new crate.
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Strict: lowercase only, even length. Uppercase is rejected rather than
/// accepted-and-normalised for the same reason `valid_fingerprint` rejects it —
/// the encoder emits one form, so a second form on disk means the file was
/// written by something other than us, and saying so beats quietly coping.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    debug_assert!(rest.is_empty(), "length is a multiple of two");
    let mut out = Vec::with_capacity(pairs.len());
    for &[hi, lo] in pairs {
        out.push(hex_nibble(hi)? << 4 | hex_nibble(lo)?);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// signed-document envelope, shared by both files
// ---------------------------------------------------------------------------

/// Render `body` as `<toml>\n[signature]\nvalue = "<hex>"\n`.
///
/// The signed bytes are exactly the body text — no canonicalisation step, no
/// second serialisation, nothing to disagree about. `domain` is prepended
/// before signing (never written to disk) so a floor signature can never be
/// replayed as a store signature.
fn seal<T: Serialize>(
    body: &T,
    domain: &[u8],
    authority: &dyn Authority,
) -> Result<String, TrustFileError> {
    let text = toml_edit::ser::to_string_pretty(body)
        .map_err(|e| TrustFileError::Serialize(e.to_string()))?;
    let text = text.trim_end_matches('\n').to_owned();
    let signature = authority.sign(&domain_separated(domain, text.as_bytes()))?;
    Ok(format!(
        "{text}{SIGNATURE_SEPARATOR}value = \"{}\"\n",
        hex_encode(&signature)
    ))
}

/// Split, verify, then parse — in that order. Parsing first would run the TOML
/// deserialiser over bytes nothing has vouched for.
fn unseal<T: DeserializeOwned>(
    text: &str,
    domain: &[u8],
    path: &Path,
    expect: &AuthorityBlock,
) -> Result<T, TrustFileError> {
    parse_body(verified_body(text, domain, path, expect)?, path)
}

/// The signed body of `text`, once its signature is checked against `expect`.
fn verified_body<'a>(
    text: &'a str,
    domain: &[u8],
    path: &Path,
    expect: &AuthorityBlock,
) -> Result<&'a str, TrustFileError> {
    // Last occurrence: the real block is emitted last, and a TOML string value
    // can never contain a raw newline (the serialiser escapes it), so a lease
    // label cannot forge one. If one somehow appeared earlier, splitting last
    // means the body includes the forgery and the signature fails — closed.
    let (body, tail) = text
        .rsplit_once(SIGNATURE_SEPARATOR)
        .ok_or_else(|| TrustFileError::untrusted(path, "it carries no signature block"))?;

    let block: SignatureBlock = toml_edit::de::from_str(tail)
        .map_err(|e| TrustFileError::untrusted(path, format!("unreadable signature block: {e}")))?;
    let signature = hex_decode(&block.value)
        .ok_or_else(|| TrustFileError::untrusted(path, "the signature is not hex"))?;

    let alg = SignatureAlg::parse(&expect.alg)?;
    let public_key = hex_decode(&expect.public_key)
        .ok_or_else(|| TrustFileError::untrusted(path, "the authority key is not hex"))?;
    verify(
        alg,
        &public_key,
        &domain_separated(domain, body.as_bytes()),
        &signature,
    )
    .map_err(|_| {
        TrustFileError::untrusted(
            path,
            "the signature does not match its contents — the file has been edited",
        )
    })?;
    Ok(body)
}

/// Parse a body [`verified_body`] vouched for.
fn parse_body<T: DeserializeOwned>(body: &str, path: &Path) -> Result<T, TrustFileError> {
    toml_edit::de::from_str(body)
        .map_err(|e| TrustFileError::untrusted(path, format!("unreadable body: {e}")))
}

/// Peek at the declared authority *before* verifying, so the two failures stay
/// distinguishable: "written by a different installation" is a completely
/// different user problem from "someone edited this file".
fn declared_authority(text: &str, path: &Path) -> Result<AuthorityBlock, TrustFileError> {
    #[derive(Deserialize)]
    struct JustTheAuthority {
        authority: AuthorityBlock,
    }
    let body = text
        .rsplit_once(SIGNATURE_SEPARATOR)
        .map(|(b, _)| b)
        .ok_or_else(|| TrustFileError::untrusted(path, "it carries no signature block"))?;
    let peeked: JustTheAuthority = toml_edit::de::from_str(body)
        .map_err(|e| TrustFileError::untrusted(path, format!("unreadable body: {e}")))?;
    Ok(peeked.authority)
}

fn domain_separated(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(domain.len() + body.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(body);
    msg
}

// ---------------------------------------------------------------------------
// clock
// ---------------------------------------------------------------------------

fn system_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `now = max(system_clock, persisted_floor)`.
///
/// The receiver's wall clock is writable by anyone who can inject input into
/// it, and a KVM's whole job is to let a peer inject input. Backdating the
/// clock would otherwise un-expire every lapsed lease on the machine.
///
/// The floor only ever increases, which makes the failure asymmetric on
/// purpose: a floor that is wrong-forward expires things *early* — visible,
/// annoying, recoverable with one renewal — while a clock that is wrong-back
/// would extend trust silently. Over-strict is a bug report; over-permissive is
/// an incident.
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    floor: u64,
}

impl Clock {
    pub fn now(self) -> u64 {
        system_seconds().max(self.floor)
    }

    pub fn floor(self) -> u64 {
        self.floor
    }
}

// ---------------------------------------------------------------------------
// the store file
// ---------------------------------------------------------------------------

/// What [`TrustFile::open`] found.
#[derive(Debug)]
pub enum Loaded {
    /// No store yet: a fresh install, or one that predates leases. The caller
    /// runs [`TrustStore::migrate_from_config`] and saves the result. This is
    /// the ONLY non-fatal "nothing here" — every other way of failing to read a
    /// store is an error.
    Absent,
    Present {
        serial: u64,
        written_at: u64,
        leases: Vec<LeaseRecord>,
    },
}

pub struct TrustFile {
    trust_path: PathBuf,
    floor_path: PathBuf,
    authority: Arc<dyn Authority>,
    serial: u64,
    floor_seconds: u64,
    /// The store and floor files as [`TrustFile::open`] found them when the
    /// store was version 1, until the save that writes version 2 has copied
    /// them aside.
    v1_found: Option<V1Files>,
    /// What the version 1 copy holds while one is kept, read from the copy
    /// itself: each record's fingerprint and state.
    v1_copy: Option<Vec<(String, DiskState)>>,
}

/// A version 1 store's files, byte for byte.
struct V1Files {
    trust: String,
    floor: Option<String>,
}

impl std::fmt::Debug for TrustFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustFile")
            .field("trust_path", &self.trust_path)
            .field("serial", &self.serial)
            .field("floor_seconds", &self.floor_seconds)
            .field("v1_found", &self.v1_found.is_some())
            .field("v1_copy", &self.v1_copy)
            .finish_non_exhaustive()
    }
}

impl TrustFile {
    /// Open the store in `config_dir`.
    ///
    /// Constructible with nothing but a directory and an authority: no
    /// certificate, no socket, no backends, no runtime. That is issue #127 — the
    /// reason there is not one behavioural trust test in the daemon today is
    /// that reaching the trust code required standing up all five.
    ///
    /// Reads a version 1 store as well as a version 2 one, and refuses any
    /// other. A version 1 store's leases come back confirmed and with no
    /// clipboard chosen; the next [`TrustFile::save`] writes version 2.
    pub fn open(
        config_dir: &Path,
        authority: Arc<dyn Authority>,
    ) -> Result<(Self, Loaded), TrustFileError> {
        let trust_path = config_dir.join(TRUST_FILE_NAME);
        let floor_path = config_dir.join(FLOOR_FILE_NAME);
        let expect = AuthorityBlock {
            alg: authority.algorithm().as_str().to_owned(),
            public_key: hex_encode(authority.public_key()),
        };

        let floor_text = read_text(&floor_path)?;
        let floor: Option<FloorBody> = match &floor_text {
            Some(text) => {
                check_authority(text, &floor_path, &expect)?;
                Some(unseal(text, FLOOR_DOMAIN, &floor_path, &expect)?)
            }
            None => None,
        };
        let (floor_seconds, floor_serial) = floor.map_or((0, 0), |f| (f.seconds, f.serial));

        let trust_text = read_text(&trust_path)?;
        let body = match &trust_text {
            Some(text) => {
                check_authority(text, &trust_path, &expect)?;
                Some(verified_body(text, TRUST_DOMAIN, &trust_path, &expect)?)
            }
            None => None,
        };

        let mut store = Self {
            trust_path,
            floor_path,
            authority,
            serial: floor_serial,
            floor_seconds,
            v1_found: None,
            v1_copy: read_v1_copy(config_dir, &expect),
        };

        let Some(body) = body else {
            return Ok((store, Loaded::Absent));
        };

        let (serial, written_at, leases) = match declared_version(body, &store.trust_path)? {
            1 => {
                let v1: v1::TrustBodyV1 = parse_body(body, &store.trust_path)?;
                store.v1_found = trust_text.clone().map(|trust| V1Files {
                    trust,
                    floor: floor_text.clone(),
                });
                (
                    v1.serial,
                    v1.written_at,
                    v1.leases.into_iter().map(LeaseRecord::from).collect(),
                )
            }
            SCHEMA_VERSION => {
                let v2: TrustBody = parse_body(body, &store.trust_path)?;
                (v2.serial, v2.written_at, v2.leases)
            }
            other => {
                return Err(TrustFileError::untrusted(
                    &store.trust_path,
                    format!(
                        "schema version {other} — this build understands 1 and {SCHEMA_VERSION}. \
                         A newer hops wrote this store; run that one, or move the file aside."
                    ),
                ));
            }
        };

        // Rollback. A signature proves who wrote a file, never when. Without
        // this, restoring yesterday's store re-grants a device removed today
        // and every check above still passes.
        if serial < floor_serial {
            return Err(TrustFileError::untrusted(
                &store.trust_path,
                format!(
                    "serial {serial} is older than the {floor_serial} this machine has already \
                     written — it is a restored copy of an earlier trust store"
                ),
            ));
        }

        validate(&leases, &store.trust_path)?;

        store.serial = store.serial.max(serial);
        store.floor_seconds = store.floor_seconds.max(written_at);
        Ok((
            store,
            Loaded::Present {
                serial,
                written_at,
                leases,
            },
        ))
    }

    pub fn clock(&self) -> Clock {
        Clock {
            floor: self.floor_seconds,
        }
    }

    pub fn now(&self) -> u64 {
        self.clock().now()
    }

    pub fn path(&self) -> &Path {
        &self.trust_path
    }

    /// The store [`TrustFile::open`] found is version 1, and no save has
    /// written version 2 over it yet.
    pub fn is_version_1(&self) -> bool {
        self.v1_found.is_some()
    }

    /// Replace the store with `leases`, then advance the floor.
    ///
    /// Order is load-bearing and is the opposite of the intuitive one. If the
    /// floor were written first and the process died before the store landed,
    /// the floor would sit *ahead* of the file on disk and the next start would
    /// refuse this machine's own trust store as a rollback — self-inflicted,
    /// unrecoverable without deleting a file by hand. Store first means the
    /// worst crash outcome is a floor one serial behind, which the next save
    /// corrects and which refuses nothing.
    ///
    /// Over a version 1 store, both files are first copied aside
    /// ([`TRUST_V1_COPY_NAME`], [`FLOOR_V1_COPY_NAME`]), never over a copy
    /// already there; a copy that cannot be made fails the save, so the store
    /// never moves to version 2 without one. While a copy is kept, a save
    /// that drops any record it holds, a removal or a removal an earlier
    /// build recorded, deletes both copies before writing (#187, #184).
    pub fn save(&mut self, leases: &[LeaseRecord]) -> Result<(), TrustFileError> {
        validate(leases, &self.trust_path)?;

        let config_dir = self
            .trust_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        if let Some(found) = &self.v1_found {
            keep_copy(&config_dir.join(TRUST_V1_COPY_NAME), &found.trust)?;
            if let Some(floor) = &found.floor {
                keep_copy(&config_dir.join(FLOOR_V1_COPY_NAME), floor)?;
            }
            let expect = AuthorityBlock {
                alg: self.authority.algorithm().as_str().to_owned(),
                public_key: hex_encode(self.authority.public_key()),
            };
            self.v1_copy = read_v1_copy(&config_dir, &expect);
        }
        self.delete_v1_copy_if_dropped(&config_dir, leases);

        let now = self.now();
        self.serial += 1;
        let authority = AuthorityBlock {
            alg: self.authority.algorithm().as_str().to_owned(),
            public_key: hex_encode(self.authority.public_key()),
        };

        let body = TrustBody {
            version: SCHEMA_VERSION,
            serial: self.serial,
            written_at: now,
            authority: authority.clone(),
            leases: leases.to_vec(),
        };
        let sealed = seal(&body, TRUST_DOMAIN, self.authority.as_ref())?;
        // Same atomicity and permission story as `config.toml`: temp sibling at
        // 0600, fsync, rename, fsync the directory. A kill mid-write leaves the
        // whole old file or the whole new one.
        write_atomically(&self.trust_path, sealed.as_bytes())
            .map_err(|e| TrustFileError::io(&self.trust_path, e))?;
        self.v1_found = None;

        self.floor_seconds = self.floor_seconds.max(now);
        let floor = FloorBody {
            version: FLOOR_VERSION,
            seconds: self.floor_seconds,
            serial: self.serial,
            authority,
        };
        let sealed = seal(&floor, FLOOR_DOMAIN, self.authority.as_ref())?;
        write_atomically(&self.floor_path, sealed.as_bytes())
            .map_err(|e| TrustFileError::io(&self.floor_path, e))?;
        Ok(())
    }

    /// Delete both version 1 copies when `leases` no longer hold, in the same
    /// state, a record the copy holds. Before the save writes, so no crash
    /// leaves a copy granting a device the store on disk has removed.
    ///
    /// A copy that cannot be deleted is logged and tried again at the next
    /// save; the save itself goes ahead, since the store is the file this
    /// build reads.
    fn delete_v1_copy_if_dropped(&mut self, config_dir: &Path, leases: &[LeaseRecord]) {
        let Some(held) = &self.v1_copy else {
            return;
        };
        let dropped: Vec<&str> = held
            .iter()
            .filter(|(fp, state)| {
                !leases
                    .iter()
                    .any(|r| r.state == *state && same_fingerprint(&r.fingerprint, fp))
            })
            .map(|(fp, _)| fp.as_str())
            .collect();
        if dropped.is_empty() {
            return;
        }
        let mut failed = false;
        for name in [TRUST_V1_COPY_NAME, FLOOR_V1_COPY_NAME] {
            let path = config_dir.join(name);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    failed = true;
                    log::error!(
                        "trust store: could not delete {}, which still holds {} a removal \
                         dropped; trying again at the next save: {e}",
                        path.display(),
                        dropped.join(", ")
                    );
                }
            }
        }
        if !failed {
            log::warn!(
                "trust store: deleted {TRUST_V1_COPY_NAME} and {FLOOR_V1_COPY_NAME}, the copy \
                 kept for builds that read only version 1 stores, because it still held {}, \
                 which this store no longer holds. Such a build no longer starts here until \
                 it is updated, or {TRUST_FILE_NAME} is moved aside",
                dropped.join(", ")
            );
            self.v1_copy = None;
        }
    }
}

fn read_sealed<T: DeserializeOwned>(
    path: &Path,
    domain: &[u8],
    expect: &AuthorityBlock,
) -> Result<Option<T>, TrustFileError> {
    let Some(text) = read_text(path)? else {
        return Ok(None);
    };
    check_authority(&text, path, expect)?;
    unseal(&text, domain, path, expect).map(Some)
}

/// The file at `path`, or `None` when there is none.
fn read_text(path: &Path) -> Result<Option<String>, TrustFileError> {
    match fs::read_to_string(path) {
        Ok(t) => Ok(Some(t)),
        // Absent legitimately means "nothing yet". Every other IO failure —
        // permissions, a directory in the way, a bad disk — is fatal, because
        // continuing would come up with no trust and then persist that.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TrustFileError::io(path, e)),
    }
}

fn check_authority(text: &str, path: &Path, expect: &AuthorityBlock) -> Result<(), TrustFileError> {
    let declared = declared_authority(text, path)?;
    if declared != *expect {
        return Err(TrustFileError::untrusted(
            path,
            "it was signed by a different authority key — this file belongs to \
             another hops installation, not this one",
        ));
    }
    Ok(())
}

/// The version a verified store body declares, read before the body is
/// parsed as either version's shape.
fn declared_version(body: &str, path: &Path) -> Result<u32, TrustFileError> {
    #[derive(Deserialize)]
    struct JustTheVersion {
        version: u32,
    }
    parse_body::<JustTheVersion>(body, path).map(|v| v.version)
}

/// What the version 1 copy in `config_dir` holds: each record's fingerprint
/// and state. `None` when there is no copy, or none this machine can read,
/// which no build could restore either.
fn read_v1_copy(config_dir: &Path, expect: &AuthorityBlock) -> Option<Vec<(String, DiskState)>> {
    let path = config_dir.join(TRUST_V1_COPY_NAME);
    match read_sealed::<v1::TrustBodyV1>(&path, TRUST_DOMAIN, expect) {
        Ok(copy) => copy.map(|b| {
            b.leases
                .into_iter()
                .map(|r| (r.fingerprint, r.state))
                .collect()
        }),
        Err(e) => {
            log::warn!(
                "trust store: the copy of the version 1 store cannot be read, so no build \
                 can restore it, and it is left as it is: {e}"
            );
            None
        }
    }
}

/// Put `contents` at `path` unless a file is already there. A copy is never
/// written over: the first one is the store as it was before any build wrote
/// version 2.
fn keep_copy(path: &Path, contents: &str) -> Result<(), TrustFileError> {
    match crate::new_file::create_whole(
        path,
        contents.as_bytes(),
        crate::new_file::Access::OwnerReadWrite,
    ) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        other => other.map_err(|e| TrustFileError::io(path, e)),
    }
}

/// The form a fingerprint is keyed by in the store, so a record written in
/// another spelling is still the same record.
fn same_fingerprint(a: &str, b: &str) -> bool {
    let key = |fp: &str| canonical_fingerprint(fp).unwrap_or_else(|| fp.trim().to_lowercase());
    key(a) == key(b)
}

/// Structural checks every record must pass before the store is believed.
///
/// A record that fails these is not "one bad row to skip". It means the file is
/// not what we wrote, so the whole file is refused.
fn validate(leases: &[LeaseRecord], path: &Path) -> Result<(), TrustFileError> {
    let mut seen: HashMap<&str, ()> = HashMap::with_capacity(leases.len());
    for lease in leases {
        if seen.insert(lease.fingerprint.as_str(), ()).is_some() {
            return Err(TrustFileError::untrusted(
                path,
                format!(
                    "two leases name {} — which one wins is not a question a trust store gets to leave open",
                    lease.fingerprint
                ),
            ));
        }
        match lease.state {
            // A fingerprint that can ADMIT a peer must be in the exact form the
            // TLS verifiers compute, or the entry is unmatchable and its
            // presence is a lie about who is trusted.
            DiskState::Active => {
                if canonical_fingerprint(&lease.fingerprint).as_deref()
                    != Some(lease.fingerprint.as_str())
                {
                    return Err(TrustFileError::untrusted(
                        path,
                        format!("{} is not a canonical fingerprint", lease.fingerprint),
                    ));
                }
                // An absent `expires_at` used to be refused here. No stored
                // date is enforced now (#183), so absent and present grant the
                // same, and refusing one would stop the daemon over a field
                // that decides nothing.
            }
            // A removal an earlier build recorded, dropped as the store
            // loads. It need not be matchable, since it grants nothing, but a
            // record claiming both states is not one this machine wrote.
            DiskState::Revoked => {
                if !lease.caps.is_empty() {
                    return Err(TrustFileError::untrusted(
                        path,
                        format!(
                            "{} is revoked but still carries capabilities",
                            lease.fingerprint
                        ),
                    ));
                }
            }
            // Listed to be paired again: it grants nothing, so a record that
            // claims a capability or a clipboard, or a confirmed pairing, is
            // not one this machine wrote.
            DiskState::PairAgain => {
                if !lease.caps.is_empty() || lease.clipboard.is_some() || lease.confirmed {
                    return Err(TrustFileError::untrusted(
                        path,
                        format!(
                            "{} is listed to be paired again but claims a pairing",
                            lease.fingerprint
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// migration
// ---------------------------------------------------------------------------

/// What the migration did, for the caller to log. Every number here answers a
/// question a user will ask after upgrading.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Migration {
    pub leases: Vec<LeaseRecord>,
    /// Authorized fingerprints that became active leases.
    pub carried_forward: usize,
    /// Authorized entries the removals table also named, not carried
    /// forward. `subtract_revoked`, run one last time, at the boundary.
    pub refused: Vec<String>,
    /// Authorized entries whose fingerprint was malformed and could never have
    /// matched a peer.
    pub dropped: Vec<String>,
}

/// Rebuilds the in-memory store from the records on disk.
///
/// The disk and memory shapes are deliberately different. On disk a record is a
/// flat row with a state and a capability list, because that is what survives a
/// hand-edit legibly and what a signature covers. In memory a lease is a thing
/// with a validity window that answers questions. This is the one place they
/// meet, so a mismatch shows up here rather than as a peer that mysteriously
/// cannot connect.
///
/// A record that cannot be admitted is REPORTED, never dropped silently — the
/// caller logs it. Silently dropping a row is how a device loses trust with no
/// explanation, which is the failure this whole rework exists to remove.
///
/// A stored `expires_at` is not carried into the store: every active lease is
/// rebuilt as [`Expiry::Never`] (#183). See [`LeaseRecord::expires_at`].
pub fn rebuild(
    ours: &str,
    floor: u64,
    records: &[LeaseRecord],
) -> Result<(TrustStore, Vec<String>), TrustError> {
    let mut store = TrustStore::new(ours, floor)?;
    let mut refused = Vec::new();

    for r in records {
        match r.state {
            // A removal an earlier build recorded. Removing a device now
            // forgets it (#184), so the record is dropped, and the machine is
            // a stranger that can pair again in full. `start` saves the store
            // without it. Named in the log by fingerprint only: its name is
            // exactly what removal drops.
            DiskState::Revoked => {
                refused.push(format!(
                    "{}: a removal an earlier build kept on file is dropped; removing a \
                     device now forgets it, and it can be paired again",
                    r.fingerprint
                ));
            }
            // A machine to pair again (#231). Listed, and never a lease.
            DiskState::PairAgain => {
                if let Err(e) = store.list_to_pair_again(&r.fingerprint, &r.label, r.issued_at) {
                    refused.push(format!("{}: {e}", r.fingerprint));
                }
            }
            // A pairing interrupted before both machines confirmed it. The
            // number it was confirmed with died with that session, and a
            // reconnect must not summon the comparison again, so it is dropped
            // and the device added again (#11, #167). `start` saves the store
            // without it.
            DiskState::Active if !r.confirmed => {
                refused.push(format!(
                    "{} ({:?}): its pairing was never confirmed on both machines, so it \
                     is dropped; add the device again to pair it",
                    r.fingerprint, r.label
                ));
            }
            DiskState::Active => {
                let mut drive = Caps::NONE;
                for c in &r.caps {
                    drive = drive
                        | match c {
                            DiskCap::Inbound => Caps::DRIVE_ME,
                            DiskCap::Outbound => Caps::I_MAY_DRIVE,
                        };
                }
                // Nobody chose a clipboard for a pairing made before #182, and
                // it keeps the one its lease always granted (#186). One that
                // was chosen, the off switch included, is exactly what was
                // chosen.
                let clipboard = match &r.clipboard {
                    None => existing_pairing_clipboard(drive),
                    Some(chosen) => chosen.iter().fold(Caps::NONE, |acc, c| {
                        acc | match c {
                            DiskClipboard::From => Caps::CLIPBOARD_FROM,
                            DiskClipboard::To => Caps::CLIPBOARD_TO,
                        }
                    }),
                };
                let caps = drive | clipboard;
                let lease = Lease {
                    peer: r.fingerprint.clone(),
                    issued_to: ours.to_string(),
                    label: r.label.clone(),
                    caps,
                    origin: match r.origin {
                        DiskOrigin::Inbound => Origin::Inbound,
                        DiskOrigin::OutboundDial => Origin::OutboundDial,
                        DiskOrigin::Migrated => Origin::Migrated,
                        DiskOrigin::ChosenIMayDrive => Origin::Chosen(Controller::ThisMachine),
                        DiskOrigin::ChosenDriveMe => Origin::Chosen(Controller::ThatMachine),
                        DiskOrigin::ChosenBoth => Origin::Chosen(Controller::Both),
                    },
                    issued_at: r.issued_at,
                    // Not `r.expires_at`. Builds from before #183 wrote 30
                    // days, or 400 for a migrated lease, and this one writes
                    // the date those builds accept. Nothing renews a lease
                    // yet, so honouring any of them would take a working
                    // device away with no way back but pairing again (#183).
                    expiry: Expiry::Never,
                    clipboard_chosen: r.clipboard.is_some(),
                    // Only a confirmed record reaches here: one that was not
                    // is dropped above.
                    confirmed: true,
                };
                if let Err(e) = store.admit(lease) {
                    refused.push(format!("{}: {e}", r.fingerprint));
                }
            }
        }
    }

    Ok((store, refused))
}

/// The store the daemon starts with, from the records [`TrustFile::open`]
/// found.
///
/// Rebuilds them and logs what a user may need to know. Then, when the file
/// must change before anything else happens, saves at once: a version 1 store
/// moves to [`SCHEMA_VERSION`], its copy kept for older builds, a pairing
/// never confirmed on both machines is dropped (#187), and a removal an
/// earlier build kept on file is dropped (#184). A save that fails is
/// logged, not fatal: the store in memory is right, and the daemon's next
/// save, at the latest its first minute sweep, writes it.
pub fn start(
    file: &mut TrustFile,
    ours: &str,
    records: &[LeaseRecord],
) -> Result<TrustStore, TrustError> {
    let (store, refused) = rebuild(ours, file.now(), records)?;
    for why in &refused {
        // Reported, never dropped silently: a device losing trust with no
        // explanation is the failure this rework removes.
        log::warn!("trust store: {why}");
    }
    for (level, line) in stored_terms(records, &store).log_lines() {
        log::log!(level, "{line}");
    }
    let unconfirmed = records
        .iter()
        .any(|r| r.state == DiskState::Active && !r.confirmed);
    let removals = records.iter().any(|r| r.state == DiskState::Revoked);
    let why = if file.is_version_1() {
        Some(format!(
            "moving it to version {SCHEMA_VERSION}, with a copy of version 1 kept as \
             {TRUST_V1_COPY_NAME} and {FLOOR_V1_COPY_NAME}"
        ))
    } else if unconfirmed || removals {
        Some("dropping the pairings never confirmed and the removals kept on file".to_string())
    } else {
        None
    };
    if let Some(why) = why {
        match file.save(&records_of(&store)) {
            Ok(()) => log::info!("trust store: saved, {why}"),
            Err(e) => log::error!(
                "trust store: could not save it, {why}: {e}. It is in effect in memory, and \
                 the next save tries again"
            ),
        }
    }
    Ok(store)
}

/// Stored expiry dates worth a line in the load log, sorted by what they mean.
///
/// [`rebuild`] enforces none of them (#183); a build from before #183 enforces
/// every one. The date [`records_of`] writes, 400 days after pairing, is not
/// listed, whether or not it has passed: this build wrote it, and the next
/// save writes it again, so it is not news on any start. A store this build
/// saved therefore logs nothing on later starts, however old its pairings.
///
/// That skip also covers a lease a build from before #183 migrated, which it
/// dated the same way, so such a lease is not named when its date passes. On a
/// correct clock that is 400 days after #158 added the trust store, at the
/// earliest.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StoredTerms<'a> {
    /// Enforcement time when the store was loaded.
    pub now: u64,
    /// Granting, with a date still ahead at load that an older build chose.
    /// The next save replaces it with the date this build writes.
    pub replaced: Vec<&'a LeaseRecord>,
    /// Granting, with a date an older build chose that was at or before
    /// enforcement time at load. That build had stopped admitting this
    /// pairing and this one admits it. That build reads only the version 1
    /// copy kept at the save that moves the store to version 2, which keeps
    /// the date it saved, so it goes on refusing this pairing.
    pub passed: Vec<&'a LeaseRecord>,
}

impl StoredTerms<'_> {
    /// The lines the daemon logs about these dates when it loads the store.
    ///
    /// A pairing whose date has passed is named at warn rather than counted:
    /// it had stopped working on an older build and works on this one, which
    /// is a grant the user may not expect.
    pub fn log_lines(&self) -> Vec<(log::Level, String)> {
        let mut lines = Vec::new();
        if !self.replaced.is_empty() {
            lines.push((
                log::Level::Info,
                format!(
                    "trust store: {} pairing(s) carry an expiry date an older build chose; \
                     pairings no longer expire, so it is ignored",
                    self.replaced.len(),
                ),
            ));
        }
        for r in &self.passed {
            lines.push((
                log::Level::Warn,
                format!(
                    "trust store: {} ({:?}) had passed the expiry date an older hops build \
                     saved for it, so that build had stopped admitting it. Pairings no longer \
                     expire, so this build admits it. Remove it if that machine should not \
                     have access",
                    r.fingerprint, r.label
                ),
            ));
        }
        lines
    }
}

/// Sort the active records carrying an `expires_at` against `store`, the
/// store [`rebuild`] made from them. Records it did not admit are not listed:
/// the caller already reports those as refused.
pub fn stored_terms<'a>(records: &'a [LeaseRecord], store: &TrustStore) -> StoredTerms<'a> {
    let now = store.now();
    let mut out = StoredTerms {
        now,
        ..StoredTerms::default()
    };
    for r in records {
        let Some(end) = r.expires_at else { continue };
        if r.state != DiskState::Active || !store.has_live_lease(&r.fingerprint) {
            continue;
        }
        if end == expiry_older_builds_accept(r.issued_at) {
            continue;
        }
        if end <= now {
            out.passed.push(r);
        } else {
            out.replaced.push(r);
        }
    }
    out
}

/// The store, flattened back to the rows that go on disk.
///
/// The inverse of [`rebuild`], and the pair must round-trip: a store written and
/// read back has to answer every question identically, or a device silently
/// loses trust across a restart. That round trip is tested.
///
/// Every active lease is written with an `expires_at` and read back as
/// [`Expiry::Never`] (#183). [`Expiry::Never`] is written as the latest date a
/// build from before #183 accepts ([`expiry_older_builds_accept`]), the date
/// version 1 stores carried. [`Expiry::At`], which nothing in this build
/// issues, is written with its own date.
///
/// A lease's `clipboard` is written when it was chosen, and when the lease
/// holds other clipboard bits than an absent field loads as.
pub fn records_of(store: &TrustStore) -> Vec<LeaseRecord> {
    let mut out: Vec<LeaseRecord> = Vec::new();
    for (fp, e) in store.entries() {
        if let Some(l) = e.lease.as_ref() {
            // A machine to pair again, approved here and waiting for its
            // number, is written as the listing alone: one row per
            // fingerprint, and the unconfirmed lease would be dropped as the
            // store loads anyway, which leaves the listing as it was (#231).
            if !l.confirmed && store.to_pair_again(fp).is_some() {
                continue;
            }
            let mut caps = Vec::new();
            if l.caps.contains(Caps::DRIVE_ME) {
                caps.push(DiskCap::Inbound);
            }
            if l.caps.contains(Caps::I_MAY_DRIVE) {
                caps.push(DiskCap::Outbound);
            }
            // Written when someone chose it, and also whenever the lease holds
            // other clipboard bits than its absence loads as, so no narrowing
            // is undone by a restart, whichever verb made it.
            let held = l.caps.intersection(Caps::CLIPBOARD);
            let clipboard = (l.clipboard_chosen || held != existing_pairing_clipboard(l.caps))
                .then(|| {
                    let mut chosen = Vec::new();
                    if held.contains(Caps::CLIPBOARD_FROM) {
                        chosen.push(DiskClipboard::From);
                    }
                    if held.contains(Caps::CLIPBOARD_TO) {
                        chosen.push(DiskClipboard::To);
                    }
                    chosen
                });
            out.push(LeaseRecord {
                fingerprint: fp.to_string(),
                label: l.label.clone(),
                state: DiskState::Active,
                origin: match l.origin {
                    Origin::Inbound => DiskOrigin::Inbound,
                    Origin::OutboundDial => DiskOrigin::OutboundDial,
                    Origin::Migrated => DiskOrigin::Migrated,
                    Origin::Chosen(Controller::ThisMachine) => DiskOrigin::ChosenIMayDrive,
                    Origin::Chosen(Controller::ThatMachine) => DiskOrigin::ChosenDriveMe,
                    Origin::Chosen(Controller::Both) => DiskOrigin::ChosenBoth,
                },
                issued_at: l.issued_at,
                // Never absent. A build from before #183 refuses to start on
                // an active lease without one, and it may share this config
                // directory with this build.
                expires_at: Some(match l.expiry {
                    Expiry::Never => expiry_older_builds_accept(l.issued_at),
                    Expiry::At(end) => end,
                }),
                revoked_at: None,
                caps,
                // As it is. One not yet confirmed on both machines is written
                // so, and dropped when the store next loads: the number it
                // waits on dies with the connection it was compared on.
                confirmed: l.confirmed,
                clipboard,
            });
        }
    }
    // A machine to pair again: its name and when the upgrade found it, and
    // nothing it may do (#231).
    for (fp, p) in store.every_to_pair_again() {
        out.push(LeaseRecord {
            fingerprint: fp.to_string(),
            label: p.label.clone(),
            state: DiskState::PairAgain,
            origin: DiskOrigin::Migrated,
            issued_at: p.since,
            expires_at: None,
            revoked_at: None,
            caps: vec![],
            confirmed: false,
            clipboard: None,
        });
    }
    // Stable order so an unchanged store produces an identical file, and a diff
    // of the file shows what actually changed.
    out.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    out
}
// There is deliberately no `migrate` here.
//
// There were two, and they disagreed: this one granted every carried-forward
// fingerprint BOTH directions unconditionally, while `TrustStore::migrate_from_config`
// explained why minting a direction nobody chose is a capability the user never
// granted, created at upgrade. It now grants none at all (#231).
//
// The one with the reasoning and the tests had zero production callers. The one
// that ran had none of either. Two implementations of one rule is how that
// happens, so there is now one: the daemon migrates through the store and calls
// `records_of` to get the rows to seal.

impl Migration {
    /// One line per fact a user might otherwise have to guess at.
    pub fn log(&self) {
        log::info!(
            "migrated the trust store: {} device(s) carried forward",
            self.carried_forward,
        );
        for fp in &self.refused {
            log::warn!("not carrying {fp} forward: it was removed");
        }
        for fp in &self.dropped {
            log::warn!(
                "dropping malformed authorized fingerprint {fp:?}: it could never have matched a peer"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{AUTHORITY_KEY_FILE_NAME, SoftwareAuthority};
    use hops_ipc::RevokedEntry;

    const A: &str = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:\
10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
    const B: &str = "1e:19:1b:c4:a8:40:f5:26:37:39:9d:c7:c7:75:fe:17:\
4f:03:d5:a9:76:49:cd:b1:12:d1:2f:6c:1f:d2:22:c5";

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_788_579_979; // the timestamp in the live config

    fn tmpdir(name: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("hops-trustfile-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("mkdir");
        d
    }

    fn authority(dir: &Path) -> Arc<dyn Authority> {
        Arc::new(
            SoftwareAuthority::load_or_generate(&dir.join(AUTHORITY_KEY_FILE_NAME))
                .expect("authority"),
        )
    }

    fn allow(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_lowercase(), (*v).to_owned()))
            .collect()
    }

    fn removals(pairs: &[(&str, u64)]) -> HashMap<String, RevokedEntry> {
        pairs
            .iter()
            .map(|(k, at)| {
                (
                    k.to_lowercase(),
                    RevokedEntry {
                        label: "removed".into(),
                        revoked_at: *at,
                    },
                )
            })
            .collect()
    }

    /// Test-only shim with the shape the old duplicate had, routed through the
    /// ONE migration that survives. These tests are about persistence — sealing,
    /// round-tripping, rollback — and only ever used a migration as a convenient
    /// way to produce rows. They keep doing that, against the implementation
    /// that actually runs.
    ///
    /// A carried-forward fingerprint is listed to be paired again and
    /// granted nothing (#231).
    fn migrate(
        authorized: HashMap<String, String>,
        revoked: HashMap<String, RevokedEntry>,
        now: u64,
    ) -> Migration {
        let mut store = TrustStore::new(&ours(), now).expect("ours");
        let report = store.migrate_from_config(&authorized, &revoked, now);
        Migration {
            leases: records_of(&store),
            carried_forward: report.to_pair_again.len(),
            refused: report.refused,
            dropped: report.dropped,
        }
    }

    /// The rows of a store holding one pairing with `fp`, approved and
    /// confirmed on both machines, granting `caps`.
    fn approved(fp: &str, label: &str, caps: Caps, now: u64) -> Vec<LeaseRecord> {
        let mut store = TrustStore::new(&ours(), now).expect("ours");
        store.issue_confirmed(fp, label, caps).expect("a pairing");
        records_of(&store)
    }

    /// The machine the shim migrates for.
    fn ours() -> String {
        vec!["aa"; 32].join(":")
    }

    /// The rows read back the way the daemon reads them, so a test asks the
    /// store what they grant rather than reading a record's fields.
    fn rebuilt(rows: &[LeaseRecord], floor: u64) -> TrustStore {
        let (store, refused) = rebuild(&ours(), floor, rows).expect("rebuild");
        assert!(refused.is_empty(), "rows refused on rebuild: {refused:?}");
        store
    }

    fn find<'a>(m: &'a Migration, fp: &str) -> Option<&'a LeaseRecord> {
        m.leases.iter().find(|l| l.fingerprint == fp)
    }

    /// A removal as a build before #184 recorded it, which this build reads
    /// and never writes.
    fn removal_on_file(fp: &str, at: u64) -> LeaseRecord {
        LeaseRecord {
            fingerprint: fp.to_owned(),
            label: "workshop".into(),
            state: DiskState::Revoked,
            origin: DiskOrigin::Migrated,
            issued_at: at,
            expires_at: None,
            revoked_at: Some(at),
            caps: vec![],
            confirmed: true,
            clipboard: None,
        }
    }

    // -- the ported `subtract_revoked` tests ------------------------------
    //
    // A fingerprint both old tables named was removed, so it is not carried
    // forward, under any spelling. Removal forgets (#184), so nothing is
    // recorded for it either.

    #[test]
    fn a_fingerprint_both_tables_name_is_neither_carried_nor_recorded() {
        let m = migrate(allow(&[(A, "old-thinkpad")]), removals(&[(A, NOW)]), NOW);
        assert!(find(&m, A).is_none(), "a record of the removal was written");
        assert_eq!(
            rebuilt(&m.leases, NOW).capabilities(A),
            Caps::NONE,
            "a fingerprint in BOTH tables must not be trusted after migration"
        );
        assert_eq!(m.refused, vec![A.to_string()], "and it must be reportable");
        assert_eq!(m.carried_forward, 0);
    }

    #[test]
    fn case_does_not_carry_a_removed_fingerprint_forward() {
        // Issue #67's exact shape: removed lowercase, re-added uppercase.
        let m = migrate(
            allow(&[(&A.to_uppercase(), "attacker")]),
            removals(&[(A, NOW)]),
            NOW,
        );
        assert_eq!(m.carried_forward, 0, "uppercasing must not resurrect it");
        assert!(m.leases.is_empty(), "a record was written");
    }

    #[test]
    fn a_removal_written_in_uppercase_still_leaves_it_out() {
        let m = migrate(
            allow(&[(A, "attacker")]),
            removals(&[(&A.to_uppercase(), NOW)]),
            NOW,
        );
        assert_eq!(m.carried_forward, 0);
        assert!(m.leases.is_empty(), "a record was written");
    }

    /// This asserted inbound carried forward, and before that both
    /// directions. The old list never said which machine controls which, so
    /// the upgrade grants neither (#231): the fingerprint is saved as a
    /// machine to pair again, with nothing it may do, and reads back so.
    // LEDGER R231-8 | class B | 1 return value: records_of, rebuild, to_pair_again
    #[test]
    fn an_unrevoked_fingerprint_is_listed_to_pair_again_and_granted_nothing() {
        let m = migrate(allow(&[(A, "laptop")]), removals(&[]), NOW);
        let record = find(&m, A).expect("listed");
        assert_eq!(
            (
                record.state,
                record.caps.as_slice(),
                record.confirmed,
                &record.clipboard
            ),
            (DiskState::PairAgain, &[][..], false, &None),
            "the upgrade saved a pairing for a machine the old list named"
        );
        let store = rebuilt(&m.leases, NOW);
        assert_eq!(store.capabilities(A), Caps::NONE, "it grants something");
        assert_eq!(
            store.to_pair_again(A).map(|p| p.label.as_str()),
            Some("laptop"),
            "it is no longer listed, or lost its name, once saved and read back"
        );
        assert!(m.refused.is_empty());
    }

    // LEDGER R231-9 | class B | 1 return value: validate, TrustFile::open
    /// A machine listed to pair again, edited on disk to claim a capability,
    /// is refused before the signature is even read, and by it after.
    #[test]
    fn a_hand_edit_that_turns_a_listing_into_a_grant_is_refused() {
        let d = tmpdir("relist");
        let m = migrate(allow(&[(A, "laptop")]), removals(&[]), NOW);
        let (mut file, _) = TrustFile::open(&d, authority(&d)).expect("open");
        file.save(&m.leases).expect("save");

        let p = d.join(TRUST_FILE_NAME);
        let text = fs::read_to_string(&p).expect("read");
        let widened = text.replace("caps = []", "caps = [\"inbound\"]");
        assert_ne!(widened, text, "precondition: the edit applied");
        let forged: TrustBody =
            toml_edit::de::from_str(widened.rsplit_once(SIGNATURE_SEPARATOR).expect("body").0)
                .expect("the forgery parses");
        assert!(
            validate(&forged.leases, &p).is_err(),
            "a listing that claims a capability passed the structural checks"
        );
        fs::write(&p, &widened).expect("write");
        let err = TrustFile::open(&d, authority(&d)).expect_err("must refuse");
        assert!(matches!(err, TrustFileError::Untrusted { .. }), "{err}");
        let _ = fs::remove_dir_all(&d);
    }

    // LEDGER R231-10 | class B | 1 return value: records_of, TrustFile::save, TrustFile::open, rebuild
    /// A machine to pair again, approved here and waiting for its number,
    /// is saved: as the listing alone, which reads back listed and granting
    /// nothing, as a restart before the number is confirmed leaves it.
    #[test]
    fn a_listed_machine_approved_again_is_saved_as_still_listed() {
        let d = tmpdir("reapprove");
        let mut store = TrustStore::new(&ours(), NOW).expect("store");
        store.list_to_pair_again(A, "laptop", NOW).expect("listed");
        store
            .issue_answered(A, "laptop", Controller::Both, false)
            .expect("approved");
        let (mut file, _) = TrustFile::open(&d, authority(&d)).expect("open");
        if let Err(e) = file.save(&records_of(&store)) {
            panic!("approving a machine listed to pair again could not be saved: {e}");
        }
        let (_, loaded) = TrustFile::open(&d, authority(&d)).expect("reopen");
        let Loaded::Present { leases, .. } = loaded else {
            panic!("the store must be found on the second open");
        };
        let (back, refused) = rebuild(&ours(), NOW, &leases).expect("rebuild");
        assert_eq!(
            (
                back.capabilities(A),
                back.to_pair_again(A).map(|p| p.label.as_str()),
                refused
            ),
            (Caps::NONE, Some("laptop"), Vec::<String>::new()),
            "an approval not yet confirmed, read back"
        );
        let _ = fs::remove_dir_all(&d);
    }

    // -- the three questions the brief asks the migration to answer ---------

    /// This asserted a warning at 395 days and a lapse at 401. A lease does
    /// not lapse (#183); its saved date is there for older builds.
    // LEDGER T5 | class B | 1 return value: records_of, rebuild
    #[test]
    fn a_pairing_is_still_working_ten_years_on() {
        let rows = approved(A, "laptop", Caps::INBOUND, NOW);
        let lease = rows.iter().find(|l| l.fingerprint == A).expect("saved");
        let at = lease.issued_at;
        assert_eq!(
            lease.expires_at,
            Some(at + 400 * DAY),
            "a lease that does not lapse is saved with the latest date a build \
             from before #183 accepts, or that build refuses to start"
        );
        let mut store = rebuilt(&rows, NOW);
        for later in [at + 395 * DAY, at + 401 * DAY, at + 10 * 365 * DAY] {
            assert!(store.sweep(later).is_empty(), "lapsed at {later}");
            assert!(store.may_drive_us(A), "stopped working at {later}");
            assert!(!store.is_expiring(A), "asked to renew at {later}");
        }
    }

    /// Replaces `a_lapsed_lease_keeps_everything_needed_to_renew_it`, which
    /// asserted a migrated record granted nothing at 401 days. Real stores
    /// already hold 30-day and 400-day terms; those pairings must not lapse,
    /// and the next save dates both 400 days after pairing.
    // LEDGER T6 | class B | 1 return value + 6 struct state: rebuild, records_of
    #[test]
    fn a_term_an_earlier_build_wrote_is_not_enforced_and_the_next_save_replaces_it() {
        let issued = NOW - 20 * DAY;
        let written_before = |fp: &str, origin, term_days: u64| LeaseRecord {
            fingerprint: fp.to_owned(),
            label: format!("{term_days}-day"),
            state: DiskState::Active,
            origin,
            issued_at: issued,
            expires_at: Some(issued + term_days * DAY),
            revoked_at: None,
            caps: vec![DiskCap::Inbound],
            confirmed: true,
            clipboard: None,
        };
        let rows = vec![
            written_before(A, DiskOrigin::Inbound, 30),
            written_before(B, DiskOrigin::Migrated, 400),
        ];

        let mut store = rebuilt(&rows, NOW);
        for later in [NOW + 11 * DAY, NOW + 381 * DAY, NOW + 10 * 365 * DAY] {
            assert!(
                store.sweep(later).is_empty(),
                "a stored term lapsed at {later}: the daemon would cut that \
                 device's sessions and it could only come back by pairing again. \
                 Every expires_at in a schema-v1 store is a placeholder; enforcing \
                 a stored term (#185) needs a schema bump or a new field, not a \
                 change to rebuild or to this test"
            );
            assert!(
                store.may_drive_us(A),
                "the 30-day pairing stopped at {later}"
            );
            assert!(
                store.may_drive_us(B),
                "the 400-day pairing stopped at {later}"
            );
        }

        let rewritten = records_of(&store);
        let labels: Vec<&str> = rewritten.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, ["30-day", "400-day"], "a name was lost");
        for row in &rewritten {
            assert_eq!(
                row.state,
                DiskState::Active,
                "{}: expiry is not a state",
                row.label
            );
            assert_eq!(
                row.expires_at,
                Some(issued + 400 * DAY),
                "{}: the next save must write the latest date a build from before \
                 #183 accepts, not the term that build chose. That date is a \
                 placeholder no later build may enforce (#185)",
                row.label
            );
            assert_eq!(
                row.caps,
                vec![DiskCap::Inbound],
                "{}: caps changed",
                row.label
            );
            assert_eq!(row.issued_at, issued, "{}: issue date changed", row.label);
        }
    }

    #[test]
    fn a_malformed_authorized_fingerprint_is_dropped() {
        let m = migrate(
            allow(&[("not-a-fingerprint", "whatever")]),
            removals(&[("also-not-a-fingerprint", 0)]),
            NOW,
        );
        assert_eq!(m.dropped, vec!["not-a-fingerprint".to_string()]);
        assert_eq!(m.carried_forward, 0);
        assert!(m.leases.is_empty(), "a record was written");
    }

    /// The state on disk on a machine that removed a device before the
    /// upgrade: an empty allowlist and one removal. It migrates to a store
    /// that holds nothing at all (#184, #161).
    #[test]
    fn the_live_config_migrates_to_an_empty_store() {
        let m = migrate(allow(&[]), removals(&[(B, 1_788_579_979)]), NOW);
        assert!(m.leases.is_empty(), "the removal was kept: {:?}", m.leases);
        assert_eq!(m.carried_forward, 0);
    }

    #[test]
    fn a_label_with_bidi_control_characters_is_sanitised_on_the_way_in() {
        let m = migrate(allow(&[(A, "laptop\u{202e}evil")]), removals(&[]), NOW);
        assert_eq!(
            find(&m, A).expect("carried").label,
            "laptopevil",
            "the grant door never sanitised its description; this one does"
        );
    }

    // -- persistence --------------------------------------------------------

    #[test]
    fn a_store_round_trips_through_disk() {
        let d = tmpdir("roundtrip");
        let m = migrate(allow(&[(A, "laptop"), (B, "desk")]), removals(&[]), NOW);

        let (mut file, loaded) = TrustFile::open(&d, authority(&d)).expect("open");
        assert!(matches!(loaded, Loaded::Absent), "nothing there yet");
        file.save(&m.leases).expect("save");

        let (_, loaded) = TrustFile::open(&d, authority(&d)).expect("reopen");
        let Loaded::Present { leases, .. } = loaded else {
            panic!("the store must be found on the second open");
        };
        assert_eq!(leases, m.leases);
        let _ = fs::remove_dir_all(&d);
    }

    /// The #66 move, translated to one store: reach in and turn a removal an
    /// earlier build kept on file back into a grant.
    ///
    /// The edit is deliberately COMPLETE — real caps, and no expiry, which this
    /// build accepts on an active lease — so that `validate` accepts every
    /// field and the signature is the only thing left that can refuse it. An
    /// incomplete edit would be caught by the structural checks and this test
    /// would pass without observing the signature at all.
    #[test]
    fn a_hand_edit_that_launders_a_revocation_is_refused() {
        let d = tmpdir("handedit");
        let (mut file, _) = TrustFile::open(&d, authority(&d)).expect("open");
        file.save(&[removal_on_file(B, NOW)]).expect("save");

        let p = d.join(TRUST_FILE_NAME);
        let text = fs::read_to_string(&p).expect("read");
        let widened = text
            .replace("state = \"revoked\"", "state = \"active\"")
            .replace("caps = []", "caps = [\"inbound\", \"outbound\"]");
        assert_ne!(widened, text, "precondition: the edit applied");
        // Precondition: the forged body is structurally impeccable, so nothing
        // but the signature stands between it and being honoured.
        let forged: TrustBody =
            toml_edit::de::from_str(widened.rsplit_once(SIGNATURE_SEPARATOR).expect("body").0)
                .expect("the forgery parses");
        validate(&forged.leases, &p).expect("the forgery passes every structural check");
        assert!(
            rebuilt(&forged.leases, NOW).may_drive_us(B),
            "it really is a grant"
        );

        fs::write(&p, &widened).expect("write");
        let err = TrustFile::open(&d, authority(&d)).expect_err("must refuse");
        assert!(
            matches!(err, TrustFileError::Untrusted { .. }),
            "a hand-edited store must be refused, not honoured: {err}"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// The other half: widening a lease you already hold. Passes every
    /// structural check by construction — it is the same record with one more
    /// capability — so again only the signature can catch it.
    ///
    /// This extended `expires_at` by a century. A stored expiry is no longer
    /// enforced (#183), so extending it grants nothing here, and the edit that
    /// grants more is now a wider capability list.
    #[test]
    fn a_hand_edit_that_widens_a_lease_is_refused() {
        let d = tmpdir("widen");
        let rows = approved(A, "laptop", Caps::INBOUND, NOW);
        let (mut file, _) = TrustFile::open(&d, authority(&d)).expect("open");
        file.save(&rows).expect("save");

        let p = d.join(TRUST_FILE_NAME);
        let text = fs::read_to_string(&p).expect("read");
        let widened = text.replace("caps = [\"inbound\"]", "caps = [\"inbound\", \"outbound\"]");
        assert_ne!(widened, text, "precondition: the edit applied");
        let forged: TrustBody =
            toml_edit::de::from_str(widened.rsplit_once(SIGNATURE_SEPARATOR).expect("body").0)
                .expect("the forgery parses");
        validate(&forged.leases, &p).expect("the forgery passes every structural check");
        assert!(
            rebuilt(&forged.leases, NOW).we_may_drive(A),
            "precondition: it really does grant more"
        );
        fs::write(&p, &widened).expect("write");

        let err = TrustFile::open(&d, authority(&d)).expect_err("must refuse");
        assert!(matches!(err, TrustFileError::Untrusted { .. }), "{err}");
        let _ = fs::remove_dir_all(&d);
    }

    /// The authority-key comparison is defence in depth — the signature check
    /// behind it would refuse this file anyway. What it uniquely provides is a
    /// DIFFERENT ANSWER: "this store belongs to another installation" is a
    /// thing the user can act on; "the file has been edited" sends them looking
    /// for an attacker who is not there. So the assertion is on the message.
    #[test]
    fn a_store_from_another_machine_says_so_rather_than_calling_it_an_edit() {
        let (mine, theirs) = (tmpdir("named-mine"), tmpdir("named-theirs"));
        let m = migrate(allow(&[(A, "laptop")]), removals(&[]), NOW);
        let (mut file, _) = TrustFile::open(&theirs, authority(&theirs)).expect("open");
        file.save(&m.leases).expect("save");

        fs::copy(theirs.join(TRUST_FILE_NAME), mine.join(TRUST_FILE_NAME)).expect("copy");
        let msg = TrustFile::open(&mine, authority(&mine))
            .expect_err("must refuse")
            .to_string();
        assert!(
            msg.contains("another hops installation"),
            "the user must be told which problem they have: {msg}"
        );
        let _ = fs::remove_dir_all(&mine);
        let _ = fs::remove_dir_all(&theirs);
    }

    #[test]
    fn a_store_from_another_machine_is_refused() {
        let (mine, theirs) = (tmpdir("mine"), tmpdir("theirs"));
        let m = migrate(allow(&[(A, "laptop")]), removals(&[]), NOW);
        let (mut file, _) = TrustFile::open(&theirs, authority(&theirs)).expect("open");
        file.save(&m.leases).expect("save");

        fs::copy(theirs.join(TRUST_FILE_NAME), mine.join(TRUST_FILE_NAME)).expect("copy");
        let err = TrustFile::open(&mine, authority(&mine)).expect_err("must refuse");
        assert!(matches!(err, TrustFileError::Untrusted { .. }), "{err}");
        let _ = fs::remove_dir_all(&mine);
        let _ = fs::remove_dir_all(&theirs);
    }

    #[test]
    fn restoring_an_older_store_is_refused_as_a_rollback() {
        let d = tmpdir("rollback");
        let auth = authority(&d);

        // Trusted, then removed — the sequence a backup would undo.
        let trusted = migrate(allow(&[(A, "laptop")]), removals(&[]), NOW);
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        file.save(&trusted.leases).expect("save v1");
        let v1 = fs::read_to_string(d.join(TRUST_FILE_NAME)).expect("read v1");

        let removed = migrate(allow(&[]), removals(&[(A, NOW)]), NOW);
        file.save(&removed.leases).expect("save v2");

        fs::write(d.join(TRUST_FILE_NAME), &v1).expect("restore the backup");
        let err = TrustFile::open(&d, auth).expect_err("must refuse");
        assert!(
            matches!(err, TrustFileError::Untrusted { .. }),
            "a validly signed but SUPERSEDED store must not re-grant a removed \
             device: {err}"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_truncated_store_is_fatal_rather_than_empty() {
        let d = tmpdir("truncated");
        let m = migrate(allow(&[(A, "laptop")]), removals(&[]), NOW);
        let (mut file, _) = TrustFile::open(&d, authority(&d)).expect("open");
        file.save(&m.leases).expect("save");

        let p = d.join(TRUST_FILE_NAME);
        let text = fs::read_to_string(&p).expect("read");
        fs::write(&p, &text[..text.len() / 2]).expect("truncate");

        let err = TrustFile::open(&d, authority(&d)).expect_err("must refuse");
        assert!(
            matches!(err, TrustFileError::Untrusted { .. }),
            "issue #69, restated for the new file: a partial store is not an \
             empty one: {err}"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_floor_file_put_in_the_stores_place_is_refused() {
        let d = tmpdir("swap");
        let m = migrate(allow(&[(A, "laptop")]), removals(&[]), NOW);
        let (mut file, _) = TrustFile::open(&d, authority(&d)).expect("open");
        file.save(&m.leases).expect("save");

        fs::copy(d.join(FLOOR_FILE_NAME), d.join(TRUST_FILE_NAME)).expect("swap");
        let err = TrustFile::open(&d, authority(&d)).expect_err("must refuse");
        assert!(matches!(err, TrustFileError::Untrusted { .. }), "{err}");
        let _ = fs::remove_dir_all(&d);
    }

    /// The test above passes even with domain separation removed, because a
    /// floor body does not deserialise as a store body — it observes the shape,
    /// not the domain. This one isolates the domain: a perfectly well-formed
    /// STORE body, signed under the FLOOR domain. Nothing but the domain
    /// separator can refuse it, so removing the separator makes this fail.
    #[test]
    fn a_signature_made_for_the_floor_is_not_valid_on_the_store() {
        let d = tmpdir("domain");
        let auth = authority(&d);
        let m = migrate(allow(&[(A, "laptop")]), removals(&[]), NOW);
        let body = TrustBody {
            version: SCHEMA_VERSION,
            serial: 1,
            written_at: NOW,
            authority: AuthorityBlock {
                alg: auth.algorithm().as_str().to_owned(),
                public_key: hex_encode(auth.public_key()),
            },
            leases: m.leases,
        };
        let sealed = seal(&body, FLOOR_DOMAIN, auth.as_ref()).expect("seal");
        fs::write(d.join(TRUST_FILE_NAME), sealed).expect("write");

        let err = TrustFile::open(&d, auth.clone()).expect_err("must refuse");
        assert!(matches!(err, TrustFileError::Untrusted { .. }), "{err}");

        // ...and prove the body itself was fine, so the refusal above is the
        // domain and nothing else.
        let same_body_right_domain = seal(&body, TRUST_DOMAIN, auth.as_ref()).expect("seal");
        fs::write(d.join(TRUST_FILE_NAME), same_body_right_domain).expect("write");
        assert!(
            TrustFile::open(&d, auth).is_ok(),
            "the body was well-formed"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_backdated_system_clock_cannot_un_expire_a_lease() {
        let d = tmpdir("clock");
        let (mut file, _) = TrustFile::open(&d, authority(&d)).expect("open");
        file.save(&[]).expect("save, which seeds the floor");

        let (file, _) = TrustFile::open(&d, authority(&d)).expect("reopen");
        assert!(
            file.now() >= file.clock().floor(),
            "now must never fall below the persisted floor"
        );
        assert!(file.clock().floor() > 0, "the floor must have been seeded");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_duplicate_fingerprint_is_refused_rather_than_resolved() {
        let one = LeaseRecord {
            fingerprint: A.to_owned(),
            label: "a".into(),
            state: DiskState::Active,
            origin: DiskOrigin::Migrated,
            issued_at: NOW,
            expires_at: Some(NOW + DAY),
            revoked_at: None,
            caps: vec![DiskCap::Inbound],
            confirmed: true,
            clipboard: None,
        };
        let mut two = one.clone();
        two.caps = vec![DiskCap::Outbound];
        assert!(validate(&[one, two], Path::new("trust.toml")).is_err());
    }

    /// This asserted the opposite: that `validate` refuses an active lease with
    /// no expiry. No stored date is enforced now (#183), so an absent one
    /// grants exactly what a present one does, and refusing it would stop the
    /// daemon over a field that decides nothing.
    #[test]
    fn an_active_lease_with_no_expiry_is_accepted_and_grants() {
        let unbounded = LeaseRecord {
            fingerprint: A.to_owned(),
            label: "a".into(),
            state: DiskState::Active,
            origin: DiskOrigin::Inbound,
            issued_at: NOW,
            expires_at: None,
            revoked_at: None,
            caps: vec![DiskCap::Inbound],
            confirmed: true,
            clipboard: None,
        };
        validate(std::slice::from_ref(&unbounded), Path::new("trust.toml"))
            .expect("an active lease with no expiry is a valid record");
        let (store, refused) = rebuild(&ours(), NOW, &[unbounded]).expect("rebuild");
        assert!(refused.is_empty(), "refused on rebuild: {refused:?}");
        assert!(store.may_drive_us(A));
    }

    /// Real stores hold leases written since #158 with a 30-day term, and
    /// migrated ones with 400 days, sealed by the build before this one. They
    /// must load, grant ten years on, and come back from
    /// the next save dated 400 days after pairing.
    // LEDGER T7 | class B | 4 file on disk: TrustFile::save, TrustFile::open, records_of
    #[test]
    fn a_sealed_store_holding_thirty_and_four_hundred_day_terms_loads_and_none_of_them_lapse() {
        let d = tmpdir("legacy-terms");
        let auth = authority(&d);
        let issued = system_seconds() - 20 * DAY;
        let active = |fp: &str, origin, cap, term_days: u64| LeaseRecord {
            fingerprint: fp.to_owned(),
            label: format!("{term_days}-day"),
            state: DiskState::Active,
            origin,
            issued_at: issued,
            expires_at: Some(issued + term_days * DAY),
            revoked_at: None,
            caps: vec![cap],
            confirmed: true,
            clipboard: None,
        };
        let rows = vec![
            active(A, DiskOrigin::Inbound, DiskCap::Inbound, 30),
            active(B, DiskOrigin::Migrated, DiskCap::Outbound, 400),
        ];
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        file.save(&rows)
            .expect("seal the store as the earlier build wrote it");
        assert!(
            fs::read_to_string(d.join(TRUST_FILE_NAME))
                .expect("read")
                .contains(&format!("expires_at = {}", issued + 30 * DAY)),
            "precondition: the file on disk carries the 30-day term"
        );

        let load = |dir: &Path| {
            let (file, loaded) = TrustFile::open(dir, auth.clone()).expect("the store loads");
            let Loaded::Present { leases, .. } = loaded else {
                panic!("the store must be found");
            };
            let (store, refused) = rebuild(&ours(), file.now(), &leases).expect("rebuild");
            assert!(
                refused.is_empty(),
                "a pairing was refused on load: {refused:?}"
            );
            (file, store)
        };

        let (mut file, mut store) = load(&d);
        let now = file.now();
        for later in [issued + 30 * DAY, issued + 400 * DAY, now + 10 * 365 * DAY] {
            assert!(
                store.sweep(later).is_empty(),
                "a stored term lapsed at {later}. Every expires_at in a schema-v1 \
                 store is a placeholder; enforcing a stored term (#185) needs a \
                 schema bump or a new field, not a change to rebuild or to this test"
            );
            assert!(
                store.may_drive_us(A),
                "the 30-day pairing stopped at {later} (see #185 before changing this)"
            );
            assert!(
                store.we_may_drive(B),
                "the 400-day pairing stopped at {later} (see #185 before changing this)"
            );
        }

        file.save(&records_of(&store)).expect("the next save");
        let text = fs::read_to_string(d.join(TRUST_FILE_NAME)).expect("read");
        assert!(
            !text.contains(&format!("expires_at = {}", issued + 30 * DAY)),
            "the next save still writes the 30-day term:\n{text}"
        );
        assert_eq!(
            text.matches(&format!("expires_at = {}\n", issued + 400 * DAY))
                .count(),
            2,
            "the next save must date both pairings 400 days after pairing, the \
             latest a build from before #183 accepts, as a placeholder no later \
             build may enforce (#185):\n{text}"
        );
        let (_, mut store) = load(&d);
        assert!(store.sweep(now + 10 * 365 * DAY).is_empty());
        assert!(store.may_drive_us(A) && store.we_may_drive(B));
        let _ = fs::remove_dir_all(&d);
    }

    /// A stored date that had already passed by load. On the build that wrote
    /// it, that pairing had stopped admitting its peer. Nothing enforces the
    /// date now (#183), so it admits again, and because that is a grant coming
    /// back the load names it apart from a pairing whose date is still ahead.
    // LEDGER T2 | class B | 4 file on disk + 1 return value
    #[test]
    fn a_pairing_whose_stored_date_had_passed_works_again_and_is_named() {
        let d = tmpdir("passed-term");
        let auth = authority(&d);
        let now = system_seconds();
        let row = |fp: &str, label: &str, issued_at: u64| LeaseRecord {
            fingerprint: fp.to_owned(),
            label: label.into(),
            state: DiskState::Active,
            origin: DiskOrigin::Inbound,
            issued_at,
            expires_at: Some(issued_at + 30 * DAY),
            revoked_at: None,
            caps: vec![DiskCap::Inbound],
            confirmed: true,
            clipboard: None,
        };
        let rows = vec![
            row(A, "expired", now - 40 * DAY),
            row(B, "current", now - 20 * DAY),
        ];
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        file.save(&rows)
            .expect("seal the store as the earlier build wrote it");

        let (file, loaded) = TrustFile::open(&d, auth).expect("the store loads");
        let Loaded::Present { leases, .. } = loaded else {
            panic!("the store must be found");
        };
        let (mut store, refused) = rebuild(&ours(), file.now(), &leases).expect("rebuild");
        assert!(refused.is_empty(), "refused on load: {refused:?}");
        let expired = leases.iter().find(|r| r.fingerprint == A).expect("row");
        assert!(
            expired.expires_at.is_some_and(|end| end <= store.now()),
            "precondition: that date had passed by load"
        );

        // Sorted at load, before the sweeps below move the clock on.
        let terms = stored_terms(&leases, &store);

        for later in [store.now(), store.now() + 10 * 365 * DAY] {
            assert!(store.sweep(later).is_empty(), "lapsed at {later}");
            assert!(
                store.may_drive_us(A),
                "the pairing whose date had passed does not admit at {later}"
            );
            assert!(
                store.may_drive_us(B),
                "the current pairing stopped at {later}"
            );
        }

        let named = |rows: &[&LeaseRecord]| {
            rows.iter()
                .map(|r| r.fingerprint.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            named(&terms.passed),
            [A],
            "a pairing that had stopped working and works again must be named"
        );
        assert_eq!(named(&terms.replaced), [B]);
        let _ = fs::remove_dir_all(&d);
    }

    /// Enforcement time is `max(system clock, floor)`, and the floor can sit
    /// ahead of the system clock. A stored date at the floor is the boundary:
    /// a build from before #183 stops admitting that pairing at exactly that
    /// second. This release admits it, and one dated below it (#183), and the
    /// load log names both. A date still ahead that this build wrote logs
    /// nothing, so a store it saved does not warn on every start.
    // LEDGER T4 | class B | 1 return value + 6 struct state: TrustFile::open, rebuild, stored_terms, StoredTerms::log_lines
    #[test]
    fn a_pairing_dated_at_or_below_the_clock_floor_is_granted_on_load_and_named_in_the_load_log() {
        // Year 2096: ahead of any real clock, so enforcement time is the floor.
        const FLOOR: u64 = 4_000_000_000;
        const C: &str = "c0:c1:c2:c3:c4:c5:c6:c7:c8:c9:ca:cb:cc:cd:ce:cf:\
d0:d1:d2:d3:d4:d5:d6:d7:d8:d9:da:db:dc:dd:de:df";
        const D: &str = "d0:d1:d2:d3:d4:d5:d6:d7:d8:d9:da:db:dc:dd:de:df:\
e0:e1:e2:e3:e4:e5:e6:e7:e8:e9:ea:eb:ec:ed:ee:ef";
        let d = tmpdir("floor-dated");
        let auth = authority(&d);
        let row = |fp: &str, label: &str, issued_at: u64, expires_at: u64| LeaseRecord {
            fingerprint: fp.to_owned(),
            label: label.into(),
            state: DiskState::Active,
            origin: DiskOrigin::Inbound,
            issued_at,
            expires_at: Some(expires_at),
            revoked_at: None,
            caps: vec![DiskCap::Inbound],
            confirmed: true,
            clipboard: None,
        };
        let saved_by_this_build = FLOOR - 20 * DAY;
        let rows = vec![
            row(A, "dated at the floor", FLOOR - 30 * DAY, FLOOR),
            row(
                B,
                "dated before the floor",
                FLOOR - 40 * DAY,
                FLOOR - 10 * DAY,
            ),
            row(C, "a term still ahead", FLOOR - 20 * DAY, FLOOR + 10 * DAY),
            row(
                D,
                "saved by this build",
                saved_by_this_build,
                saved_by_this_build + 400 * DAY,
            ),
        ];
        // Sealed as a store saved when enforcement time was the floor: opening
        // it raises the floor to its `written_at`.
        let body = TrustBody {
            version: SCHEMA_VERSION,
            serial: 1,
            written_at: FLOOR,
            authority: AuthorityBlock {
                alg: auth.algorithm().as_str().to_owned(),
                public_key: hex_encode(auth.public_key()),
            },
            leases: rows,
        };
        let sealed = seal(&body, TRUST_DOMAIN, auth.as_ref()).expect("seal");
        fs::write(d.join(TRUST_FILE_NAME), sealed).expect("write");

        let (file, loaded) = TrustFile::open(&d, auth).expect("the store loads");
        let Loaded::Present { leases, .. } = loaded else {
            panic!("the store must be found");
        };
        assert_eq!(
            file.now(),
            FLOOR,
            "precondition: enforcement time is the floor"
        );
        let (mut store, refused) = rebuild(&ours(), file.now(), &leases).expect("rebuild");
        assert!(refused.is_empty(), "refused on load: {refused:?}");
        let lines = stored_terms(&leases, &store).log_lines();

        for later in [FLOOR, FLOOR + 10 * 365 * DAY] {
            assert!(store.sweep(later).is_empty(), "lapsed at {later}");
            for (fp, label) in [
                (A, "at"),
                (B, "below"),
                (C, "ahead of"),
                (D, "this build's date after"),
            ] {
                assert!(
                    store.may_drive_us(fp),
                    "the pairing dated {label} the floor was not admitted at {later}"
                );
            }
        }

        let warns_about = |fp: &str, label: &str| {
            lines.iter().any(|(level, line)| {
                *level == log::Level::Warn && line.contains(fp) && line.contains(label)
            })
        };
        assert!(
            warns_about(A, "dated at the floor"),
            "the pairing dated exactly at the floor is admitted but not named: {lines:#?}"
        );
        assert!(
            warns_about(B, "dated before the floor"),
            "the pairing dated before the floor is admitted but not named: {lines:#?}"
        );
        let mentioned = |fp: &str| lines.iter().any(|(_, line)| line.contains(fp));
        assert!(
            !mentioned(C) && !mentioned(D),
            "a date still ahead is not a grant coming back: {lines:#?}"
        );
        let infos: Vec<&str> = lines
            .iter()
            .filter(|(level, _)| *level == log::Level::Info)
            .map(|(_, line)| line.as_str())
            .collect();
        assert!(
            infos.len() == 1 && infos[0].contains(" 1 pairing(s) "),
            "one date an older build chose is replaced, and the date this build \
             saved is not counted with it: {infos:#?}"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// The date this build saves, 400 days after pairing, passes on day 400 and
    /// stays passed. A store only this build wrote must still start quietly:
    /// a warn on every start about a pairing the user made reads exactly like
    /// the one real warning, a lapsed pairing coming back.
    // LEDGER T8 | class B | 4 file on disk + 1 return value: records_of, TrustFile::save, TrustFile::open, rebuild, stored_terms, StoredTerms::log_lines
    #[test]
    fn a_store_this_build_saved_logs_nothing_on_later_starts_however_old_its_pairings() {
        const C: &str = "c0:c1:c2:c3:c4:c5:c6:c7:c8:c9:ca:cb:cc:cd:ce:cf:\
d0:d1:d2:d3:d4:d5:d6:d7:d8:d9:da:db:dc:dd:de:df";
        const D: &str = "d0:d1:d2:d3:d4:d5:d6:d7:d8:d9:da:db:dc:dd:de:df:\
e0:e1:e2:e3:e4:e5:e6:e7:e8:e9:ea:eb:ec:ed:ee:ef";
        let d = tmpdir("own-dates");
        let auth = authority(&d);
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        let now = file.now();

        let mut store = TrustStore::new(&ours(), now).expect("ours");
        store
            .issue_confirmed(A, "paired today", Caps::INBOUND)
            .expect("issue");
        for (fp, label, age) in [
            (B, "400 days ago", 400 * DAY),
            (C, "401 days ago", 401 * DAY),
            (D, "two years ago", 2 * 365 * DAY),
        ] {
            store
                .admit(Lease {
                    peer: fp.to_owned(),
                    issued_to: ours(),
                    label: label.into(),
                    caps: Caps::INBOUND,
                    origin: Origin::Inbound,
                    issued_at: now - age,
                    expiry: Expiry::Never,
                    clipboard_chosen: false,
                    confirmed: true,
                })
                .expect("admit");
        }
        file.save(&records_of(&store)).expect("save");

        for start in 1..=3 {
            let (mut file, loaded) = TrustFile::open(&d, auth.clone()).expect("reopen");
            let Loaded::Present { leases, .. } = loaded else {
                panic!("the store must be found");
            };
            assert!(
                leases
                    .iter()
                    .any(|r| r.expires_at.is_some_and(|end| end <= file.now())),
                "precondition: a date this build saved has passed"
            );
            let (store, refused) = rebuild(&ours(), file.now(), &leases).expect("rebuild");
            assert!(refused.is_empty(), "refused on load: {refused:?}");
            for fp in [A, B, C, D] {
                assert!(store.may_drive_us(fp), "{fp} stopped working");
            }
            let lines = stored_terms(&leases, &store).log_lines();
            assert!(
                lines.is_empty(),
                "start {start} logs about dates this build saved itself:\n{lines:#?}"
            );
            file.save(&records_of(&store)).expect("save again");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        assert_eq!(
            hex_decode(&hex_encode(&[0, 1, 0xfe, 0xff])),
            Some(vec![0, 1, 0xfe, 0xff])
        );
        assert_eq!(hex_decode("abc"), None, "odd length");
        assert_eq!(hex_decode("zz"), None, "not hex");
        assert_eq!(hex_decode("AB"), None, "uppercase is not our encoding");
    }

    /// Two machines that drive each other: this one approved B's knock, then
    /// approved B answering this machine's own dial. The second approval adds
    /// a direction to the pairing. It used to replace the lease, so B lost the
    /// right to drive this machine the moment this machine could drive B
    /// (#166). Both directions, both clipboard directions and the name given
    /// at the first approval survive the grant, the save and a restart.
    // LEDGER T1 | class B | 4 file on disk + 1 return value: service::grant_for_attempt, TrustFile::save, TrustFile::open, rebuild, TrustStore::permits
    #[test]
    fn approving_the_second_direction_keeps_the_first() {
        use crate::service::grant_for_attempt;
        use hops_ipc::AttemptOrigin;

        let d = tmpdir("second-direction");
        let auth = authority(&d);
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        let mut store = TrustStore::new(&ours(), file.now()).expect("ours");

        grant_for_attempt(
            &mut store,
            B,
            "desk mac",
            Some(AttemptOrigin::Inbound),
            hops_ipc::Controller::ThatMachine,
            true,
        )
        .expect("the first approval grants");
        store
            .confirm(B)
            .expect("both machines confirmed the number");
        grant_for_attempt(
            &mut store,
            B,
            "b4:ab short name",
            Some(AttemptOrigin::OutboundDial),
            hops_ipc::Controller::ThisMachine,
            false,
        )
        .expect("the second approval grants");
        file.save(&records_of(&store)).expect("save");

        let (file, loaded) = TrustFile::open(&d, auth).expect("reopen");
        let Loaded::Present { leases, .. } = loaded else {
            panic!("the saved store must be found");
        };
        let (store, refused) = rebuild(&ours(), file.now(), &leases).expect("rebuild");
        assert!(refused.is_empty(), "refused on load: {refused:?}");

        // Both directions, and the clipboard the first approval said yes to.
        let lost: Vec<String> = Caps::NAMED
            .iter()
            .filter(|(bit, _)| *bit != Caps::CLIPBOARD_TO && !store.permits(B, *bit))
            .map(|(_, name)| (*name).to_owned())
            .collect();
        assert!(
            lost.is_empty(),
            "after approving both directions and restarting, the pairing no \
             longer permits {lost:?}; it holds {}. A second approval must add \
             to the pairing, not replace it (#166).",
            store.capabilities(B)
        );
        assert_eq!(
            store.label(B).as_deref(),
            Some("desk mac"),
            "the second approval renamed the device; it adds a direction and \
             must keep the name the device already has"
        );
        assert_eq!(
            store.lease(B).map(|l| l.origin),
            Some(Origin::Chosen(hops_ipc::Controller::Both)),
            "a pairing that holds both directions, each chosen, was saved as \
             something else; two chosen directions add up to the choice that \
             names both (#220)"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// Each answer on the pairing card, with and without the clipboard,
    /// survives the save and a restart as it was given (#220, #182): the
    /// direction recorded as chosen, and the store granting what it granted
    /// before. Read back any other way, the store refuses the pairing as not
    /// what was chosen, and it is lost at the next start.
    // LEDGER T12 | class B | 4 file on disk + 1 return value: service::grant_for_attempt, records_of, TrustFile::save, TrustFile::open, rebuild
    #[test]
    fn every_answer_on_the_card_survives_a_restart() {
        use crate::service::grant_for_attempt;
        use hops_ipc::{AttemptOrigin, Controller};

        for (controller, written) in [
            (Controller::ThisMachine, DiskOrigin::ChosenIMayDrive),
            (Controller::ThatMachine, DiskOrigin::ChosenDriveMe),
            (Controller::Both, DiskOrigin::ChosenBoth),
        ] {
            for clipboard in [false, true] {
                let d = tmpdir("every-answer");
                let auth = authority(&d);
                let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
                let mut store = TrustStore::new(&ours(), file.now()).expect("ours");
                grant_for_attempt(
                    &mut store,
                    B,
                    "desk mac",
                    Some(AttemptOrigin::Inbound),
                    controller,
                    clipboard,
                )
                .expect("the approval grants");
                store
                    .confirm(B)
                    .expect("both machines confirmed the number");
                let granted = store.capabilities(B);
                let records = records_of(&store);
                assert_eq!(
                    records
                        .iter()
                        .find(|r| r.fingerprint == B)
                        .map(|r| r.origin),
                    Some(written),
                    "{controller:?}, clipboard {clipboard}: the answer was written as another"
                );
                file.save(&records).expect("save");

                let (file, loaded) = TrustFile::open(&d, auth).expect("reopen");
                let Loaded::Present { leases, .. } = loaded else {
                    panic!("the saved store must be found");
                };
                let (store, refused) = rebuild(&ours(), file.now(), &leases).expect("rebuild");
                assert!(
                    refused.is_empty(),
                    "{controller:?}, clipboard {clipboard}: refused at the next start: \
                     {refused:?}"
                );
                assert_eq!(
                    (store.lease(B).map(|l| l.origin), store.capabilities(B)),
                    (Some(Origin::Chosen(controller)), granted),
                    "{controller:?}, clipboard {clipboard}: a restart changed the pairing"
                );
                let _ = fs::remove_dir_all(&d);
            }
        }
    }

    /// A second approval to a pairing in force asks the clipboard question
    /// again (#182), for the direction it adds: a yes shares the clipboard
    /// that way, and a no leaves the clipboard the first answer gave.
    // LEDGER T13 | class B | 1 return value: service::grant_for_attempt twice, TrustStore::capabilities
    #[test]
    fn a_second_approval_answers_the_clipboard_for_the_direction_it_adds() {
        use crate::service::grant_for_attempt;
        use hops_ipc::{AttemptOrigin, Controller};

        for (first, second, want) in [
            (
                false,
                true,
                Caps::DRIVE_ME | Caps::I_MAY_DRIVE | Caps::CLIPBOARD_TO,
            ),
            (
                true,
                false,
                Caps::DRIVE_ME | Caps::I_MAY_DRIVE | Caps::CLIPBOARD_FROM,
            ),
        ] {
            let mut store = TrustStore::new(&ours(), NOW).expect("ours");
            grant_for_attempt(
                &mut store,
                B,
                "desk mac",
                Some(AttemptOrigin::Inbound),
                Controller::ThatMachine,
                first,
            )
            .expect("the first approval grants");
            store
                .confirm(B)
                .expect("both machines confirmed the number");
            grant_for_attempt(
                &mut store,
                B,
                "desk mac",
                Some(AttemptOrigin::OutboundDial),
                Controller::ThisMachine,
                second,
            )
            .expect("the second approval grants");
            assert_eq!(
                store.capabilities(B),
                want,
                "clipboard {first} on the first approval, then {second} on the second: the \
                 pairing does not share the clipboard the answers gave"
            );
        }
    }
    // -- schema 2 (#187) ----------------------------------------------------

    fn authority_block(auth: &Arc<dyn Authority>) -> AuthorityBlock {
        AuthorityBlock {
            alg: auth.algorithm().as_str().to_owned(),
            public_key: hex_encode(auth.public_key()),
        }
    }

    fn v1_row(fp: &str, state: DiskState, caps: &[DiskCap]) -> v1::LeaseRecordV1 {
        v1::LeaseRecordV1 {
            fingerprint: fp.to_owned(),
            label: format!("device {}", &fp[..2]),
            state,
            origin: DiskOrigin::Migrated,
            issued_at: NOW,
            expires_at: (state == DiskState::Active).then_some(NOW + 400 * DAY),
            revoked_at: (state == DiskState::Revoked).then_some(NOW),
            caps: caps.to_vec(),
        }
    }

    /// Seal `rows` into `dir` as a version 1 build writes its store and its
    /// floor, and return both files' text.
    fn write_v1(
        dir: &Path,
        auth: &Arc<dyn Authority>,
        serial: u64,
        rows: Vec<v1::LeaseRecordV1>,
    ) -> (String, String) {
        let body = v1::TrustBodyV1 {
            version: 1,
            serial,
            written_at: NOW,
            authority: authority_block(auth),
            leases: rows,
        };
        let trust = seal(&body, TRUST_DOMAIN, auth.as_ref()).expect("seal the store");
        let floor = FloorBody {
            version: 1,
            seconds: NOW,
            serial,
            authority: authority_block(auth),
        };
        let floor = seal(&floor, FLOOR_DOMAIN, auth.as_ref()).expect("seal the floor");
        fs::write(dir.join(TRUST_FILE_NAME), &trust).expect("write the store");
        fs::write(dir.join(FLOOR_FILE_NAME), &floor).expect("write the floor");
        (trust, floor)
    }

    /// The store body on disk, verified, as this build's shape.
    fn body_on_disk(dir: &Path, auth: &Arc<dyn Authority>) -> TrustBody {
        let path = dir.join(TRUST_FILE_NAME);
        let text = fs::read_to_string(&path).expect("read the store");
        let body =
            verified_body(&text, TRUST_DOMAIN, &path, &authority_block(auth)).expect("verified");
        parse_body(body, &path).expect("a version 2 body")
    }

    /// Open `dir` the way the daemon starts.
    fn start_in(dir: &Path, auth: &Arc<dyn Authority>) -> (TrustFile, TrustStore) {
        let (mut file, loaded) = TrustFile::open(dir, auth.clone()).expect("open");
        let Loaded::Present { leases, .. } = loaded else {
            panic!("the store must be found");
        };
        let store = start(&mut file, &ours(), &leases).expect("start");
        (file, store)
    }

    fn copies_exist(dir: &Path) -> [bool; 2] {
        [
            dir.join(TRUST_V1_COPY_NAME).exists(),
            dir.join(FLOOR_V1_COPY_NAME).exists(),
        ]
    }

    /// The off switch is the lease's (#187). It used to reach disk as a lease
    /// with no clipboard bits, which the loader reads back through
    /// `Caps::INBOUND` / `Caps::OUTBOUND`, clipboard included, so a restart
    /// turned it back on.
    // LEDGER E2A-1 | class B | 4 file on disk: TrustStore::disable_clipboard, TrustFile::save, TrustFile::open, start
    #[test]
    fn turning_the_clipboard_off_survives_a_restart() {
        let d = tmpdir("clipboard-off");
        let auth = authority(&d);
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        let mut store = TrustStore::new(&ours(), file.now()).expect("ours");
        store
            .issue_confirmed(A, "drives this machine", Caps::INBOUND)
            .expect("issue");
        store
            .issue_confirmed(B, "driven from here", Caps::OUTBOUND)
            .expect("issue");
        for fp in [A, B] {
            assert_eq!(
                store.disable_clipboard(fp),
                Some(true),
                "{fp} has a lease to change"
            );
            assert!(
                !store.capabilities(fp).intersects(Caps::CLIPBOARD),
                "precondition: {fp}'s clipboard is off in memory"
            );
        }
        file.save(&records_of(&store)).expect("save");

        let (_, store) = start_in(&d, &auth);
        for fp in [A, B] {
            assert!(
                !store.capabilities(fp).intersects(Caps::CLIPBOARD),
                "the clipboard of {fp} came back on after a restart: {}",
                store.capabilities(fp)
            );
        }
        assert!(
            store.may_drive_us(A) && store.we_may_drive(B),
            "turning the clipboard off took away a direction to drive"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// A version 1 store loads with every lease confirmed and no clipboard
    /// chosen, the first start writes version 2, and both version 1 files are
    /// kept byte for byte for a build that reads only version 1.
    // LEDGER E2A-2 | class B | 4 file on disk: TrustFile::open, start, TrustFile::save
    #[test]
    fn a_v1_store_migrates_confirmed_without_a_clipboard_field_and_keeps_both_copies() {
        let d = tmpdir("v1-migrates");
        let auth = authority(&d);
        let (trust_v1, floor_v1) = write_v1(
            &d,
            &auth,
            7,
            vec![
                v1_row(A, DiskState::Active, &[DiskCap::Inbound]),
                v1_row(B, DiskState::Active, &[DiskCap::Outbound]),
            ],
        );

        let (file, store) = start_in(&d, &auth);
        assert!(
            !file.is_version_1(),
            "the first start did not write version 2"
        );
        let body = body_on_disk(&d, &auth);
        assert_eq!(body.version, SCHEMA_VERSION, "the store on disk");
        assert_eq!(body.leases.len(), 2, "every lease is carried: {body:?}");
        for r in &body.leases {
            assert!(
                r.confirmed,
                "{} was saved unconfirmed; a pairing made before the \
                 confirmation is confirmed (#11, #167)",
                r.fingerprint
            );
            assert_eq!(
                r.clipboard, None,
                "{} was saved with a clipboard nobody chose",
                r.fingerprint
            );
        }
        assert_eq!(
            fs::read_to_string(d.join(TRUST_V1_COPY_NAME)).ok(),
            Some(trust_v1),
            "the version 1 store was not kept as it was"
        );
        assert_eq!(
            fs::read_to_string(d.join(FLOOR_V1_COPY_NAME)).ok(),
            Some(floor_v1),
            "the version 1 floor was not kept as it was"
        );

        // What the pairings grant is unchanged, before and after a restart.
        let (_, reloaded) = start_in(&d, &auth);
        for s in [&store, &reloaded] {
            assert_eq!(
                s.capabilities(A),
                Caps::DRIVE_ME | existing_pairing_clipboard(Caps::DRIVE_ME),
                "{A}"
            );
            assert_eq!(
                s.capabilities(B),
                Caps::I_MAY_DRIVE | existing_pairing_clipboard(Caps::I_MAY_DRIVE),
                "{B}"
            );
        }
        let _ = fs::remove_dir_all(&d);
    }

    /// Approving the other direction of a pairing adds that direction (#166)
    /// and leaves a clipboard switched off, off: approved in the run that
    /// switched it off, or in a later one that read the choice back from disk,
    /// and across a restart after the approval too. A yes on that approval's
    /// card answers for the direction it adds, and only that one (#182).
    // LEDGER E2A-3 | class B | 4 file on disk: service::grant_for_attempt, TrustStore::disable_clipboard, TrustFile::save, start
    #[test]
    fn approving_the_second_direction_keeps_the_clipboard_off() {
        use crate::service::grant_for_attempt;
        use hops_ipc::AttemptOrigin;

        for (approved, restart_first) in [("in the same run", false), ("after a restart", true)] {
            let d = tmpdir(if restart_first {
                "second-direction-later"
            } else {
                "second-direction-clipboard"
            });
            let auth = authority(&d);
            let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
            let mut store = TrustStore::new(&ours(), file.now()).expect("ours");
            grant_for_attempt(
                &mut store,
                B,
                "desk mac",
                Some(AttemptOrigin::Inbound),
                hops_ipc::Controller::ThatMachine,
                true,
            )
            .expect("the first approval grants");
            store
                .confirm(B)
                .expect("both machines confirmed the number");
            assert_eq!(
                store.disable_clipboard(B),
                Some(true),
                "a lease to switch off"
            );
            if restart_first {
                file.save(&records_of(&store)).expect("save");
                std::mem::drop(file);
                (file, store) = start_in(&d, &auth);
            }
            // A yes to the clipboard, on the approval of the other direction,
            // shares it the way that direction goes, and does not turn back
            // on the clipboard switched off.
            grant_for_attempt(
                &mut store,
                B,
                "desk mac",
                Some(AttemptOrigin::OutboundDial),
                hops_ipc::Controller::ThisMachine,
                true,
            )
            .expect("the second approval grants");
            file.save(&records_of(&store)).expect("save");
            let (_, reloaded) = start_in(&d, &auth);

            for (when, s) in [
                ("after the approval", &store),
                ("after a restart", &reloaded),
            ] {
                assert!(
                    s.may_drive_us(B) && s.we_may_drive(B),
                    "second direction approved {approved}: {when}, the pairing does \
                     not drive both ways: {}",
                    s.capabilities(B)
                );
                assert_eq!(
                    s.capabilities(B).intersection(Caps::CLIPBOARD),
                    Caps::CLIPBOARD_TO,
                    "second direction approved {approved}: {when}, the clipboard is not \
                     what the answers gave: switched off the way the first direction \
                     goes, and a yes for the way the second goes"
                );
            }
            let _ = fs::remove_dir_all(&d);
        }
    }

    // LEDGER G-5 | class B | 4 file on disk + 1 return value: records_of, TrustFile::save, start
    /// Approving the second direction of a confirmed pairing does not ask
    /// for the number again, and the pairing is still confirmed after a
    /// restart: it loads, both ways (#11, #166).
    #[test]
    fn a_grant_to_a_confirmed_pairing_stays_confirmed_across_a_restart() {
        use crate::service::grant_for_attempt;
        use hops_ipc::AttemptOrigin;

        let d = tmpdir("confirmed-second-grant");
        let auth = authority(&d);
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        let mut store = TrustStore::new(&ours(), file.now()).expect("ours");
        grant_for_attempt(
            &mut store,
            B,
            "desk mac",
            Some(AttemptOrigin::Inbound),
            hops_ipc::Controller::ThatMachine,
            false,
        )
        .expect("the first approval");
        store
            .confirm(B)
            .expect("both machines confirmed the number");
        grant_for_attempt(
            &mut store,
            B,
            "desk mac",
            Some(AttemptOrigin::OutboundDial),
            hops_ipc::Controller::ThisMachine,
            false,
        )
        .expect("the second approval");
        assert!(
            !store.is_pairing(B),
            "a second direction asked for the number again"
        );
        file.save(&records_of(&store)).expect("save");
        std::mem::drop(file);

        let (_, reloaded) = start_in(&d, &auth);
        assert!(
            reloaded.may_drive_us(B) && reloaded.we_may_drive(B),
            "after a restart the pairing holds {}; it was saved unconfirmed and \
             dropped",
            reloaded.capabilities(B)
        );
    }

    // LEDGER G-5b | class B | 4 file on disk: records_of, TrustFile::save, start
    /// An approval saved while its pairing waits for the number is written as
    /// unconfirmed, so a restart drops it rather than loading it as trust: the
    /// number it waited on died with the connection (#167, 2026-09-07).
    #[test]
    fn an_approval_saved_before_the_number_is_dropped_at_the_next_start() {
        let d = tmpdir("approved-then-restart");
        let auth = authority(&d);
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        let mut store = TrustStore::new(&ours(), file.now()).expect("ours");
        store
            .issue(A, "desk mac", Caps::INBOUND)
            .expect("the approval");
        assert!(store.is_pairing(A), "precondition: waiting for the number");
        file.save(&records_of(&store)).expect("save");
        std::mem::drop(file);

        let (_, reloaded) = start_in(&d, &auth);
        assert!(
            !reloaded.is_known(A),
            "an approval nobody confirmed loaded after a restart as {}",
            reloaded.capabilities(A)
        );
    }

    /// A pairing interrupted before both machines confirmed it does not load,
    /// the load says so, and the start saves the store without it.
    // LEDGER E2A-4 | class B | 4 file on disk + 1 return value: TrustFile::save, TrustFile::open, rebuild, start
    #[test]
    fn an_unconfirmed_lease_is_dropped_at_the_next_start() {
        let d = tmpdir("unconfirmed");
        let auth = authority(&d);
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        let lease = |fp: &str, confirmed: bool| LeaseRecord {
            fingerprint: fp.to_owned(),
            label: "desk mac".into(),
            state: DiskState::Active,
            origin: DiskOrigin::Inbound,
            issued_at: file.now(),
            expires_at: None,
            revoked_at: None,
            caps: vec![DiskCap::Inbound],
            confirmed,
            clipboard: None,
        };
        let rows = vec![lease(A, true), lease(B, false)];
        file.save(&rows).expect("save");

        let (_, store) = start_in(&d, &auth);
        assert!(store.may_drive_us(A), "the confirmed pairing did not load");
        assert!(
            !store.is_known(B),
            "a pairing never confirmed on both machines loaded: {}",
            store.capabilities(B)
        );
        let saved = body_on_disk(&d, &auth);
        assert!(
            saved.leases.iter().all(|r| r.fingerprint != B),
            "the start did not save the store without it: {saved:?}"
        );
        let (_, refused) = rebuild(&ours(), file.now(), &rows).expect("rebuild");
        assert!(
            refused.iter().any(|why| why.contains(B)),
            "the unconfirmed pairing is dropped without a word: {refused:?}"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// The version 1 copy goes at the first save that drops a record it
    /// holds, so no removed device survives there (#184, #187): a removal,
    /// in the run that migrated or a later one. A save that drops nothing
    /// keeps it.
    // LEDGER E2A-5 | class B | 4 file on disk: start, TrustStore::forget, TrustFile::save
    #[test]
    fn a_removal_after_migration_deletes_the_v1_copies() {
        let rows = || {
            vec![
                v1_row(A, DiskState::Active, &[DiskCap::Inbound]),
                v1_row(B, DiskState::Active, &[DiskCap::Outbound]),
            ]
        };
        let migrated = |tag: &str| {
            let d = tmpdir(tag);
            let auth = authority(&d);
            write_v1(&d, &auth, 3, rows());
            let (file, store) = start_in(&d, &auth);
            assert_eq!(
                copies_exist(&d),
                [true, true],
                "precondition: both copies kept"
            );
            (d, auth, file, store)
        };

        // A save that drops nothing keeps the copies.
        let (d, _, mut file, mut store) = migrated("copy-kept");
        store.set_label(A, "renamed").expect("rename");
        assert_eq!(
            store.disable_clipboard(B),
            Some(true),
            "a lease to switch off"
        );
        file.save(&records_of(&store)).expect("save");
        assert_eq!(
            copies_exist(&d),
            [true, true],
            "a save that dropped nothing deleted the copies"
        );
        let _ = fs::remove_dir_all(&d);

        /// What the case is called, its scratch directory, whether it runs
        /// in a later start than the migration, and what it drops.
        type Case = (&'static str, &'static str, bool, fn(&mut TrustStore));
        let cases: [Case; 2] = [
            ("a removal", "copy-removal", false, |s| {
                s.forget(A);
            }),
            ("a removal in a later run", "copy-later", true, |s| {
                s.forget(B);
            }),
        ];
        for (what, tag, later, change) in cases {
            let (d, auth, mut file, mut store) = migrated(tag);
            if later {
                // A later run: the migration's `TrustFile` is gone, and this
                // build starts again on the files alone.
                std::mem::drop(file);
                (file, store) = start_in(&d, &auth);
            }
            change(&mut store);
            file.save(&records_of(&store)).expect("save");
            assert_eq!(
                copies_exist(&d),
                [false, false],
                "{what} after the migration left the version 1 copy on disk, \
                 where a build that reads it still acts on a record this machine \
                 dropped"
            );
            let _ = fs::remove_dir_all(&d);
        }
    }

    /// A removal an earlier build kept on file is dropped at the first start,
    /// and saved without it, whether the store is version 1 or version 2
    /// (#184). The version 1 copy follows its rule: the save that dropped the
    /// removal is the first save that drops a record the copy holds, so the
    /// copy goes with it and the removed device survives nowhere (#187).
    /// The device can then pair again, and only in full (#161).
    // LEDGER R161-2 | class B | 4 file on disk: TrustFile::open, start, records_of, TrustFile::save
    #[test]
    fn a_removal_an_earlier_build_kept_is_dropped_and_that_device_pairs_again() {
        const Z: &str = "cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:\
cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc:cc";
        for version in [1, 2] {
            let d = tmpdir(&format!("kept-removal-v{version}"));
            let auth = authority(&d);
            if version == 1 {
                write_v1(
                    &d,
                    &auth,
                    3,
                    vec![
                        v1_row(A, DiskState::Active, &[DiskCap::Inbound]),
                        v1_row(Z, DiskState::Revoked, &[]),
                    ],
                );
            } else {
                let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
                let mut store = TrustStore::new(&ours(), file.now()).expect("ours");
                store
                    .issue_confirmed(A, "kept", Caps::INBOUND)
                    .expect("issue");
                let mut rows = records_of(&store);
                rows.push(removal_on_file(Z, NOW));
                file.save(&rows)
                    .expect("the store as an earlier build wrote it");
            }

            let (mut file, mut store) = start_in(&d, &auth);
            assert!(
                !store.is_known(Z),
                "version {version}: a removal an earlier build kept is still on file"
            );
            assert!(
                store.may_drive_us(A),
                "version {version}: {A} lost its pairing"
            );
            let body = body_on_disk(&d, &auth);
            assert!(
                body.leases.iter().all(|r| r.fingerprint != Z),
                "version {version}: the first start did not save the store without \
                 the removal: {body:?}"
            );
            assert_eq!(
                copies_exist(&d),
                [false, false],
                "version {version}: a copy still holds the removed device"
            );

            store
                .issue(Z, "back again", Caps::INBOUND)
                .expect("approving it is an ordinary approval");
            assert_eq!(
                store.capabilities(Z),
                Caps::NONE,
                "version {version}: an approval alone paired it"
            );
            store
                .confirm(Z)
                .expect("both machines confirmed the number");
            file.save(&records_of(&store)).expect("save");
            let (_, reloaded) = start_in(&d, &auth);
            assert!(
                reloaded.may_drive_us(Z),
                "version {version}: the device removed before the upgrade did not \
                 pair again"
            );
            let _ = fs::remove_dir_all(&d);
        }
    }

    /// A version 1 store found again, after the copies were restored for an
    /// older build that then saved, migrates again without writing over the
    /// first copy.
    // LEDGER E2A-6 | class B | 4 file on disk: start, TrustFile::save
    #[test]
    fn a_second_migration_keeps_the_first_copy() {
        let d = tmpdir("second-migration");
        let auth = authority(&d);
        let (first, first_floor) = write_v1(
            &d,
            &auth,
            5,
            vec![v1_row(A, DiskState::Active, &[DiskCap::Inbound])],
        );
        let _ = start_in(&d, &auth);

        // An older build is given the copies back and saves a pairing.
        fs::copy(d.join(TRUST_V1_COPY_NAME), d.join(TRUST_FILE_NAME)).expect("restore");
        fs::copy(d.join(FLOOR_V1_COPY_NAME), d.join(FLOOR_FILE_NAME)).expect("restore");
        write_v1(
            &d,
            &auth,
            6,
            vec![
                v1_row(A, DiskState::Active, &[DiskCap::Inbound]),
                v1_row(B, DiskState::Active, &[DiskCap::Inbound]),
            ],
        );

        let (_, store) = start_in(&d, &auth);
        assert!(
            store.may_drive_us(A) && store.may_drive_us(B),
            "the second migration lost a pairing"
        );
        assert_eq!(body_on_disk(&d, &auth).version, SCHEMA_VERSION);
        assert_eq!(
            fs::read_to_string(d.join(TRUST_V1_COPY_NAME)).ok(),
            Some(first),
            "the second migration wrote over the first copy of the store"
        );
        assert_eq!(
            fs::read_to_string(d.join(FLOOR_V1_COPY_NAME)).ok(),
            Some(first_floor),
            "the second migration wrote over the first copy of the floor"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// Only versions 1 and 2 are read. A store from a later schema is refused
    /// by name rather than parsed as either.
    // LEDGER E2A-7 | class B | 1 return value: TrustFile::open
    #[test]
    fn a_store_of_a_later_schema_is_refused() {
        let d = tmpdir("later-schema");
        let auth = authority(&d);
        let body = TrustBody {
            version: SCHEMA_VERSION + 1,
            serial: 1,
            written_at: NOW,
            authority: authority_block(&auth),
            leases: Vec::new(),
        };
        let sealed = seal(&body, TRUST_DOMAIN, auth.as_ref()).expect("seal");
        fs::write(d.join(TRUST_FILE_NAME), sealed).expect("write");
        let err = TrustFile::open(&d, auth).expect_err("a later schema must be refused");
        assert!(
            matches!(&err, TrustFileError::Untrusted { reason, .. }
                if reason.contains(&format!("schema version {}", SCHEMA_VERSION + 1))),
            "refused for another reason: {err}"
        );
        let _ = fs::remove_dir_all(&d);
    }
}

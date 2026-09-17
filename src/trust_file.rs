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
//! Today, a hand-edit cannot launder a denial because there are two tables and
//! revocation outranks the allowlist ([`crate::config`]'s `subtract_revoked`).
//! With one store that precedence has nothing to rank: deleting a revoked lease
//! and adding an active one is a single coherent edit.
//!
//! So the property is preserved by a different mechanism, in four parts:
//!
//! * **Authentication.** The file is signed by this machine's authority (see
//!   [`crate::authority`]). An edited body, or a store copied in from another
//!   installation, does not verify and the daemon refuses to start.
//! * **Exists-but-unparseable is fatal.** Identical to the rule `Config::new`
//!   already enforces, and for the identical reason: an absent file
//!   legitimately means defaults, a corrupt one never does.
//! * **Rollback.** A signature does not stop restoring an *older, validly
//!   signed* store that still grants a device you have since expelled. A
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

use crate::trust::{Caps, Denial, Expiry, Lease, Origin, TrustError, TrustStore};

use hops_ipc::pairing::canonical_fingerprint;

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
pub const SCHEMA_VERSION: u32 = 1;

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
/// [`OLDER_BUILD_CEILING_SECS`] after `issued_at`. Builds on both sides of #183
/// can share one config directory, so this build writes a date it never reads:
/// [`rebuild`] makes every active lease [`Expiry::Never`].
fn expiry_older_builds_accept(issued_at: u64) -> u64 {
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
    /// Deliberately expelled. Carries no capability, does not lapse, and is
    /// kept rather than deleted so the expulsion stays visible and so a
    /// hand-edit cannot quietly convert it back into a grant.
    Revoked,
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
    // No `Restored`. An expelled fingerprint is never re-authorised — the
    // machine returns by generating a new identity, which arrives as `Inbound`
    // or `OutboundDial` like any other first contact.
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    /// Canonical `aa:bb:…` leaf-cert fingerprint — the same string the TLS
    /// verifiers compute, so this is the join key with everything else.
    pub fingerprint: String,
    /// Display name. Sanitised on every write; see
    /// [`hops_ipc::pairing::sanitize_label`].
    pub label: String,
    pub state: DiskState,
    pub origin: DiskOrigin,
    /// Unix seconds, from `max(system clock, floor)`.
    pub issued_at: u64,
    /// Unix seconds. Not enforced on load: [`rebuild`] makes every active
    /// lease [`Expiry::Never`] (#183).
    ///
    /// Written for every active lease all the same, as 400 days after
    /// `issued_at` ([`expiry_older_builds_accept`]), so a build from before
    /// #183 still starts on a store this build saved. That build does enforce
    /// the date: past it, that build stops admitting the pairing and this one
    /// keeps admitting it. A date already on disk may instead be a term that
    /// build chose (30 days for an approval); the next save replaces it.
    ///
    /// **A placeholder, never to be enforced.** Nothing in a schema-v1 store
    /// tells this date apart from a real 400-day term: [`SCHEMA_VERSION`] did
    /// not change and `deny_unknown_fields` rules out a marker. A build that
    /// enforced it would end every pairing this build made on day 400, the
    /// outage #183 removes. A stored term (#185) needs a schema bump or a new
    /// field.
    ///
    /// Absent on a revoked record, which does not lapse. Absent on an active
    /// lease also loads and grants, because no stored date decides anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    /// Empty for a revoked record.
    pub caps: Vec<DiskCap>,
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
// Not base64: the root crate has no base64 dependency (only `hops-ipc` does),
// and hex is already this project's on-disk encoding for key material — it is
// how `generate_fingerprint` renders a SHA-256. One convention, no new crate.
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
}

impl std::fmt::Debug for TrustFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustFile")
            .field("trust_path", &self.trust_path)
            .field("serial", &self.serial)
            .field("floor_seconds", &self.floor_seconds)
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

        let floor: Option<FloorBody> = read_sealed(&floor_path, FLOOR_DOMAIN, &expect)?;
        let (floor_seconds, floor_serial) = floor.map_or((0, 0), |f| (f.seconds, f.serial));

        let body: Option<TrustBody> = read_sealed(&trust_path, TRUST_DOMAIN, &expect)?;

        let mut store = Self {
            trust_path,
            floor_path,
            authority,
            serial: floor_serial,
            floor_seconds,
        };

        let Some(body) = body else {
            return Ok((store, Loaded::Absent));
        };

        if body.version != SCHEMA_VERSION {
            return Err(TrustFileError::untrusted(
                &store.trust_path,
                format!(
                    "schema version {} — this build understands {SCHEMA_VERSION}. \
                     A newer hops wrote this store; run that one, or move the file aside.",
                    body.version
                ),
            ));
        }

        // Rollback. A signature proves who wrote a file, never when. Without
        // this, restoring yesterday's store re-grants a device expelled today
        // and every check above still passes.
        if body.serial < floor_serial {
            return Err(TrustFileError::untrusted(
                &store.trust_path,
                format!(
                    "serial {} is older than the {floor_serial} this machine has already \
                     written — it is a restored copy of an earlier trust store",
                    body.serial
                ),
            ));
        }

        validate(&body.leases, &store.trust_path)?;

        store.serial = store.serial.max(body.serial);
        store.floor_seconds = store.floor_seconds.max(body.written_at);
        Ok((
            store,
            Loaded::Present {
                serial: body.serial,
                written_at: body.written_at,
                leases: body.leases,
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

    /// Replace the store with `leases`, then advance the floor.
    ///
    /// Order is load-bearing and is the opposite of the intuitive one. If the
    /// floor were written first and the process died before the store landed,
    /// the floor would sit *ahead* of the file on disk and the next start would
    /// refuse this machine's own trust store as a rollback — self-inflicted,
    /// unrecoverable without deleting a file by hand. Store first means the
    /// worst crash outcome is a floor one serial behind, which the next save
    /// corrects and which refuses nothing.
    pub fn save(&mut self, leases: &[LeaseRecord]) -> Result<(), TrustFileError> {
        validate(leases, &self.trust_path)?;

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

        self.floor_seconds = self.floor_seconds.max(now);
        let floor = FloorBody {
            version: SCHEMA_VERSION,
            seconds: self.floor_seconds,
            serial: self.serial,
            authority,
        };
        let sealed = seal(&floor, FLOOR_DOMAIN, self.authority.as_ref())?;
        write_atomically(&self.floor_path, sealed.as_bytes())
            .map_err(|e| TrustFileError::io(&self.floor_path, e))?;
        Ok(())
    }
}

fn read_sealed<T: DeserializeOwned>(
    path: &Path,
    domain: &[u8],
    expect: &AuthorityBlock,
) -> Result<Option<T>, TrustFileError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        // Absent legitimately means "nothing yet". Every other IO failure —
        // permissions, a directory in the way, a bad disk — is fatal, because
        // continuing would come up with no trust and then persist that.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(TrustFileError::io(path, e)),
    };

    let declared = declared_authority(&text, path)?;
    if declared != *expect {
        return Err(TrustFileError::untrusted(
            path,
            "it was signed by a different authority key — this file belongs to \
             another hops installation, not this one",
        ));
    }
    unseal(&text, domain, path, expect).map(Some)
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
            // A fingerprint that can only DENY need not be matchable.
            // `remove_authorized_key` deliberately tombstones even an invalid
            // string, on the grounds that refusing to record a revocation is
            // the more dangerous failure. Dropping those here on the way in
            // would launder exactly the denials that reasoning protects.
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
    /// Revocations preserved.
    pub tombstones: usize,
    /// Authorized entries a tombstone outranked. `subtract_revoked`, run one
    /// last time, at the boundary.
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
            // A revocation is a record, not a grant. It goes in first and
            // nothing later can lift it — `admit` refuses an expelled
            // fingerprint outright.
            DiskState::Revoked => {
                store.admit_denial(
                    &r.fingerprint,
                    Denial {
                        label: r.label.clone(),
                        at: r.revoked_at.unwrap_or(r.issued_at),
                    },
                );
            }
            DiskState::Active => {
                let mut caps = Caps::NONE;
                for c in &r.caps {
                    caps = caps
                        | match c {
                            DiskCap::Inbound => Caps::INBOUND,
                            DiskCap::Outbound => Caps::OUTBOUND,
                        };
                }
                let lease = Lease {
                    peer: r.fingerprint.clone(),
                    issued_to: ours.to_string(),
                    label: r.label.clone(),
                    caps,
                    origin: match r.origin {
                        DiskOrigin::Inbound => Origin::Inbound,
                        DiskOrigin::OutboundDial => Origin::OutboundDial,
                        DiskOrigin::Migrated => Origin::Migrated,
                    },
                    issued_at: r.issued_at,
                    // Not `r.expires_at`. Builds from before #183 wrote 30
                    // days, or 400 for a migrated lease, and this one writes
                    // the date those builds accept. Nothing renews a lease
                    // yet, so honouring any of them would take a working
                    // device away with no way back but pairing again (#183).
                    expiry: Expiry::Never,
                };
                if let Err(e) = store.admit(lease) {
                    refused.push(format!("{}: {e}", r.fingerprint));
                }
            }
        }
    }

    Ok((store, refused))
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
    /// pairing and this one admits it. Once this build saves, the date moves
    /// to 400 days after pairing, and if that is still ahead, that build
    /// admits it again until then.
    pub passed: Vec<&'a LeaseRecord>,
}

impl StoredTerms<'_> {
    /// The lines the daemon logs about these dates when it loads the store.
    ///
    /// A pairing whose date has passed is named at warn rather than counted:
    /// it had stopped working on an older build and works on this one, which
    /// is a grant the user may not expect.
    pub fn log_lines(&self) -> Vec<(log::Level, String)> {
        let ceiling_days = OLDER_BUILD_CEILING_SECS / 86_400;
        let mut lines = Vec::new();
        if !self.replaced.is_empty() {
            lines.push((
                log::Level::Info,
                format!(
                    "trust store: {} pairing(s) carry an expiry date an older build chose; \
                     pairings no longer expire, so it is ignored, and the next save moves it \
                     to {ceiling_days} days after pairing, the latest an older build accepts",
                    self.replaced.len(),
                ),
            ));
        }
        for r in &self.passed {
            let after_save = if expiry_older_builds_accept(r.issued_at) > self.now {
                format!(
                    "once this build saves the store, an older build admits it again until \
                     {ceiling_days} days after pairing"
                )
            } else {
                format!(
                    "it was paired more than {ceiling_days} days ago, so an older build goes \
                     on refusing it after this build saves the store"
                )
            };
            lines.push((
                log::Level::Warn,
                format!(
                    "trust store: {} ({:?}) had passed the expiry date an older hops build \
                     saved for it, so that build had stopped admitting it. Pairings no longer \
                     expire, so this build admits it, and {after_save}. Remove it if that \
                     machine should not have access",
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
/// build from before #183 accepts ([`expiry_older_builds_accept`]), so that
/// build still starts on this store. [`Expiry::At`], which nothing in this
/// build issues, is written with its own date.
pub fn records_of(store: &TrustStore) -> Vec<LeaseRecord> {
    let mut out: Vec<LeaseRecord> = Vec::new();
    for (fp, e) in store.entries() {
        // The expulsion, if there is one. It is a record, not a grant: no
        // capabilities, and it does not lapse.
        if let Some(d) = e.denial.as_ref() {
            out.push(LeaseRecord {
                fingerprint: fp.to_string(),
                label: d.label.clone(),
                state: DiskState::Revoked,
                origin: DiskOrigin::Migrated,
                issued_at: d.at,
                expires_at: None,
                revoked_at: Some(d.at),
                caps: Vec::new(),
            });
            continue;
        }
        if let Some(l) = e.lease.as_ref() {
            let mut caps = Vec::new();
            if l.caps.contains(Caps::DRIVE_ME) {
                caps.push(DiskCap::Inbound);
            }
            if l.caps.contains(Caps::I_MAY_DRIVE) {
                caps.push(DiskCap::Outbound);
            }
            out.push(LeaseRecord {
                fingerprint: fp.to_string(),
                label: l.label.clone(),
                state: DiskState::Active,
                origin: match l.origin {
                    Origin::Inbound => DiskOrigin::Inbound,
                    Origin::OutboundDial => DiskOrigin::OutboundDial,
                    Origin::Migrated => DiskOrigin::Migrated,
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
            });
        }
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
// grants outbound only to a peer the old config actually dialled — and explains
// at length why minting it otherwise is a capability the user never granted,
// created at upgrade, by the code that claims to retire exactly that defect.
//
// The one with the reasoning and the tests had zero production callers. The one
// that ran had none of either. Two implementations of one rule is how that
// happens, so there is now one: the daemon migrates through the store and calls
// `records_of` to get the rows to seal.

impl Migration {
    /// One line per fact a user might otherwise have to guess at.
    pub fn log(&self) {
        log::info!(
            "migrated the trust store: {} device(s) carried forward, {} revocation(s) preserved",
            self.carried_forward,
            self.tombstones
        );
        for fp in &self.refused {
            log::warn!(
                "not carrying {fp} forward: it was revoked, and a revocation outranks the allowlist"
            );
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

    fn tombstones(pairs: &[(&str, u64)]) -> HashMap<String, RevokedEntry> {
        pairs
            .iter()
            .map(|(k, at)| {
                (
                    k.to_lowercase(),
                    RevokedEntry {
                        label: "expelled".into(),
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
    /// `dialled` is empty here, so a carried-forward fingerprint gets INBOUND
    /// only. That is the correct rule and it is why the over-grant test below
    /// changed rather than being deleted.
    fn migrate(
        authorized: HashMap<String, String>,
        revoked: HashMap<String, RevokedEntry>,
        now: u64,
    ) -> Migration {
        let mut store = TrustStore::new(&ours(), now).expect("ours");
        let report = store.migrate_from_config(
            &authorized,
            &revoked,
            &std::collections::HashSet::new(),
            now,
        );
        Migration {
            leases: records_of(&store),
            carried_forward: report.leased.len(),
            tombstones: report.denied.len(),
            refused: report.refused,
            dropped: report.dropped,
        }
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

    // -- the four ported `subtract_revoked` tests ---------------------------
    //
    // The precedence they encode is the invariant that survives the rewrite, so
    // they are ported rather than deleted. They now assert it over the thing
    // that replaced the rule — what the rebuilt store grants — instead of over a
    // map subtraction that no longer exists.

    #[test]
    fn a_revoked_fingerprint_gets_no_capabilities() {
        let m = migrate(allow(&[(A, "old-thinkpad")]), tombstones(&[(A, NOW)]), NOW);
        let lease = find(&m, A).expect("the tombstone is preserved, not deleted");
        assert_eq!(lease.state, DiskState::Revoked);
        assert_eq!(
            rebuilt(&m.leases, NOW).capabilities(A),
            Caps::NONE,
            "a fingerprint in BOTH tables must not be trusted after migration"
        );
        assert_eq!(m.refused, vec![A.to_string()], "and it must be reportable");
        assert_eq!(m.carried_forward, 0);
    }

    #[test]
    fn case_does_not_launder_a_tombstone() {
        // Issue #67's exact shape: expelled lowercase, re-added uppercase.
        let m = migrate(
            allow(&[(&A.to_uppercase(), "attacker")]),
            tombstones(&[(A, NOW)]),
            NOW,
        );
        assert_eq!(m.carried_forward, 0, "uppercasing must not resurrect it");
        assert!(find(&m, A).is_some(), "the record is kept");
        assert_eq!(rebuilt(&m.leases, NOW).capabilities(A), Caps::NONE);
    }

    #[test]
    fn a_tombstone_written_in_uppercase_still_bites() {
        let m = migrate(
            allow(&[(A, "attacker")]),
            tombstones(&[(&A.to_uppercase(), NOW)]),
            NOW,
        );
        assert_eq!(m.carried_forward, 0);
        assert!(find(&m, A).is_some(), "the record is kept");
        assert_eq!(rebuilt(&m.leases, NOW).capabilities(A), Caps::NONE);
    }

    /// This asserted BOTH directions, and was wrong. The flat allowlist did
    /// feed both verifiers, but membership was **necessary and not sufficient**
    /// for outbound: a dial also needed a `[[clients]]` entry aimed at that
    /// peer. A fingerprint that was allowlisted and never dialled had outbound
    /// in theory and never once in practice, so minting it at upgrade creates a
    /// capability the user never granted — by the code whose job is to retire
    /// exactly that defect.
    ///
    /// The shim above migrates with an empty dialled set, so this peer is the
    /// never-dialled case.
    #[test]
    fn an_unrevoked_fingerprint_survives_with_inbound_and_is_not_handed_outbound() {
        let m = migrate(allow(&[(A, "laptop")]), tombstones(&[]), NOW);
        let lease = find(&m, A).expect("carried forward");
        assert_eq!(lease.caps, vec![DiskCap::Inbound]);
        let store = rebuilt(&m.leases, NOW);
        assert!(
            store.may_drive_us(A) && !store.we_may_drive(A),
            "a peer the old config never dialled keeps inbound — dropping that \
             would break a working fleet with nothing in the UI to explain it — \
             and must NOT be handed outbound it never had"
        );
        assert!(m.refused.is_empty());
    }

    // -- the three questions the brief asks the migration to answer ---------

    /// This asserted a warning at 395 days and a lapse at 401. A migrated
    /// lease does not lapse (#183); its saved date is there for older builds.
    // LEDGER T5 | class B | 1 return value: records_of, rebuild
    #[test]
    fn an_upgraded_fleet_is_still_working_ten_years_on() {
        let m = migrate(allow(&[(A, "laptop")]), tombstones(&[]), NOW);
        let lease = find(&m, A).expect("carried forward");
        assert_eq!(
            lease.expires_at,
            Some(NOW + 400 * DAY),
            "a lease that does not lapse is saved with the latest date a build \
             from before #183 accepts, or that build refuses to start"
        );
        let mut store = rebuilt(&m.leases, NOW);
        for later in [NOW + 395 * DAY, NOW + 401 * DAY, NOW + 10 * 365 * DAY] {
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
    fn a_tombstone_survives_migration_with_its_label_and_date() {
        let m = migrate(allow(&[]), tombstones(&[(B, 1_788_579_979)]), NOW);
        let lease = find(&m, B).expect("preserved");
        assert_eq!(lease.state, DiskState::Revoked);
        assert_eq!(lease.revoked_at, Some(1_788_579_979));
        assert_eq!(lease.expires_at, None, "a revocation does not lapse");
        assert!(lease.caps.is_empty());
        assert_eq!(m.tombstones, 1);
    }

    #[test]
    fn a_future_dated_tombstone_cannot_poison_the_clock() {
        let m = migrate(allow(&[]), tombstones(&[(B, 4_102_444_800)]), NOW);
        assert_eq!(
            find(&m, B).expect("preserved").revoked_at,
            Some(NOW),
            "a hand-written year-2100 timestamp must be clamped, not believed"
        );
    }

    #[test]
    fn a_malformed_authorized_fingerprint_is_dropped_but_a_malformed_denial_is_kept() {
        let m = migrate(
            allow(&[("not-a-fingerprint", "whatever")]),
            tombstones(&[("also-not-a-fingerprint", 0)]),
            NOW,
        );
        assert_eq!(m.dropped, vec!["not-a-fingerprint".to_string()]);
        assert_eq!(m.carried_forward, 0);
        assert!(
            find(&m, "also-not-a-fingerprint").is_some(),
            "an unmatchable grant is inert; an unmatchable denial is still a decision"
        );
    }

    #[test]
    fn the_live_config_migrates_to_exactly_one_revoked_lease() {
        // Byte-for-byte the state on disk today: an empty allowlist and one
        // tombstone. The upgrade must produce a store with nothing trusted and
        // that expulsion still recorded.
        let m = migrate(allow(&[]), tombstones(&[(B, 1_788_579_979)]), NOW);
        assert_eq!(m.leases.len(), 1);
        assert_eq!(m.carried_forward, 0);
        assert_eq!(m.leases[0].state, DiskState::Revoked);
        assert_eq!(rebuilt(&m.leases, NOW).capabilities(B), Caps::NONE);
    }

    #[test]
    fn a_label_with_bidi_control_characters_is_sanitised_on_the_way_in() {
        let m = migrate(allow(&[(A, "laptop\u{202e}evil")]), tombstones(&[]), NOW);
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
        let m = migrate(allow(&[(A, "laptop")]), tombstones(&[(B, NOW)]), NOW);

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

    /// The #66 move, translated to one store: reach in and turn the expulsion
    /// back into a grant.
    ///
    /// The edit is deliberately COMPLETE — real caps, and no expiry, which this
    /// build accepts on an active lease — so that `validate` accepts every
    /// field and the signature is the only thing left that can refuse it. An
    /// incomplete edit would be caught by the structural checks and this test
    /// would pass without observing the signature at all.
    #[test]
    fn a_hand_edit_that_launders_a_revocation_is_refused() {
        let d = tmpdir("handedit");
        let m = migrate(allow(&[]), tombstones(&[(B, NOW)]), NOW);
        let (mut file, _) = TrustFile::open(&d, authority(&d)).expect("open");
        file.save(&m.leases).expect("save");

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
        let m = migrate(allow(&[(A, "laptop")]), tombstones(&[]), NOW);
        let (mut file, _) = TrustFile::open(&d, authority(&d)).expect("open");
        file.save(&m.leases).expect("save");

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
        let m = migrate(allow(&[(A, "laptop")]), tombstones(&[]), NOW);
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
        let m = migrate(allow(&[(A, "laptop")]), tombstones(&[]), NOW);
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

        // Trusted, then expelled — the sequence a backup would undo.
        let trusted = migrate(allow(&[(A, "laptop")]), tombstones(&[]), NOW);
        let (mut file, _) = TrustFile::open(&d, auth.clone()).expect("open");
        file.save(&trusted.leases).expect("save v1");
        let v1 = fs::read_to_string(d.join(TRUST_FILE_NAME)).expect("read v1");

        let expelled = migrate(allow(&[]), tombstones(&[(A, NOW)]), NOW);
        file.save(&expelled.leases).expect("save v2");

        fs::write(d.join(TRUST_FILE_NAME), &v1).expect("restore the backup");
        let err = TrustFile::open(&d, auth).expect_err("must refuse");
        assert!(
            matches!(err, TrustFileError::Untrusted { .. }),
            "a validly signed but SUPERSEDED store must not re-grant an expelled \
             device: {err}"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_truncated_store_is_fatal_rather_than_empty() {
        let d = tmpdir("truncated");
        let m = migrate(allow(&[(A, "laptop")]), tombstones(&[]), NOW);
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
        let m = migrate(allow(&[(A, "laptop")]), tombstones(&[]), NOW);
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
        let m = migrate(allow(&[(A, "laptop")]), tombstones(&[]), NOW);
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
        };
        validate(std::slice::from_ref(&unbounded), Path::new("trust.toml"))
            .expect("an active lease with no expiry is a valid record");
        let (store, refused) = rebuild(&ours(), NOW, &[unbounded]).expect("rebuild");
        assert!(refused.is_empty(), "refused on rebuild: {refused:?}");
        assert!(store.may_drive_us(A));
    }

    /// Real stores hold leases written since #158 with a 30-day term, and
    /// migrated ones with 400 days, sealed by the build before this one. They
    /// must load, grant ten years on, keep every removal, and come back from
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
        };
        const C: &str = "c0:c1:c2:c3:c4:c5:c6:c7:c8:c9:ca:cb:cc:cd:ce:cf:\
d0:d1:d2:d3:d4:d5:d6:d7:d8:d9:da:db:dc:dd:de:df";
        let removed = LeaseRecord {
            fingerprint: C.to_owned(),
            label: "removed".into(),
            state: DiskState::Revoked,
            origin: DiskOrigin::Migrated,
            issued_at: issued,
            expires_at: None,
            revoked_at: Some(issued),
            caps: vec![],
        };
        let rows = vec![
            active(A, DiskOrigin::Inbound, DiskCap::Inbound, 30),
            active(B, DiskOrigin::Migrated, DiskCap::Outbound, 400),
            removed,
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
            assert!(store.is_denied(C) && store.capabilities(C) == Caps::NONE);
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
        assert!(store.is_denied(C), "the removal survived the rewrite");
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
            .issue(A, "paired today", Caps::INBOUND)
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
}

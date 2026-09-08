//! The authority that signs this machine's lease set.
//!
//! # What this is for
//!
//! Until now, "is this peer allowed to drive my keyboard?" was answered by
//! reading `[authorized_fingerprints]` out of `config.toml`. That table is a
//! plain, hand-editable document, and the only thing stopping a hand-edit from
//! re-trusting an expelled device was a *precedence rule*: revocation outranks
//! the allowlist, applied at every door (`Config::effective_allowlist`).
//!
//! Precedence works because there are two tables and one of them wins. Once
//! membership becomes a single lease set, there is no second table left to
//! outrank the first — deleting a revoked lease and adding an active one is a
//! single coherent edit of one document. So the fail-closed property has to be
//! re-established by a different mechanism: the lease file is **signed**, and a
//! file this machine did not write is not a trust store, it is a hard error.
//!
//! # What a local signature does and does not buy
//!
//! The private key sits in the same `0700` directory as the file it signs.
//! Against an attacker who already runs code as this user, that is worth
//! nothing, and nothing stored on this disk could be worth anything — they can
//! simply re-sign. This signature is not a defence against that adversary.
//!
//! It *is* a defence against the failures that actually happen, and that
//! already produced issue #66: a dotfiles restore, a Time Machine rollback, a
//! config-sync tool, a copied dotfile directory, a well-meaning hand-edit. Each
//! of those either breaks the signature or presents a public key this
//! installation never generated, and each therefore stops the daemon rather
//! than silently widening trust.
//!
//! # Hardware is a role, not a foundation
//!
//! [`Authority`] is a trait with exactly one implementation here,
//! [`SoftwareAuthority`]. A TPM 2.0, Secure Enclave or FIDO2 authority is a new
//! file implementing the same trait, and changes no caller.
//!
//! The verifying half of this module — [`verify`] — takes an algorithm, a public
//! key, a message and a signature. It has no access to an [`Authority`] at all,
//! so it *cannot* branch on how a signer holds its key even by accident. That
//! is deliberate and structural: key custody is a local fact a machine records
//! about itself for its own user's information. It is never a claim made to a
//! peer, and never an input to a trust decision. Remote attestation of key
//! residency is entitlement-gated on Apple platforms and requesting the
//! entitlement fails notarization, so a verifying machine receives exactly zero
//! bits about where a peer's key lives. A design that read a custody claim off
//! the wire would be reading a self-report.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rustls::SignatureScheme;
use rustls::sign::Signer;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, SignatureVerificationAlgorithm};
use thiserror::Error;

/// File name of the software authority's private key, alongside the TLS
/// identity in the config directory.
pub const AUTHORITY_KEY_FILE_NAME: &str = "authority.pem";

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("reading or writing {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("generating the authority key: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("{path} is not a usable authority key: {reason}")]
    Unusable { path: PathBuf, reason: String },
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("signature algorithm `{0}` is not supported by this build")]
    UnsupportedAlgorithm(String),
    #[error("signature does not verify")]
    BadSignature,
}

/// A signature algorithm the trust store may be signed with.
///
/// The on-disk name is part of the file format, so the mapping below is frozen.
/// A build that meets a name it does not know refuses the file — an unknown
/// algorithm is not a reason to skip verification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SignatureAlg {
    /// ECDSA over NIST P-256 with SHA-256, ASN.1 DER signature encoding.
    ///
    /// Chosen because it is what `rcgen::KeyPair::generate()` already produces
    /// for the TLS identity, so key handling is one pattern rather than two,
    /// and because the `ring` provider rustls is already configured with both
    /// signs and verifies it. No new dependency, no new primitive.
    EcdsaP256Sha256,
}

impl SignatureAlg {
    /// The name written into the file. Frozen.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
        }
    }

    /// Parse a name read off disk. Unknown names are refused, never ignored.
    pub fn parse(s: &str) -> Result<Self, AuthorityError> {
        match s {
            "ecdsa-p256-sha256" => Ok(Self::EcdsaP256Sha256),
            other => Err(AuthorityError::UnsupportedAlgorithm(other.to_owned())),
        }
    }

    fn scheme(self) -> SignatureScheme {
        match self {
            Self::EcdsaP256Sha256 => SignatureScheme::ECDSA_NISTP256_SHA256,
        }
    }
}

impl fmt::Display for SignatureAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a machine holds its own authority key.
///
/// Recorded locally so the user can be told what protects their trust store on
/// *this* machine. It is never serialised into the trust file, never sent to a
/// peer, and never consulted by [`verify`]. `#[non_exhaustive]` so a hardware
/// variant is additive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum KeyCustody {
    /// A private key file in the config directory, protected by filesystem
    /// permissions only.
    SoftwareFile,
}

impl fmt::Display for KeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SoftwareFile => f.write_str("software key file"),
        }
    }
}

/// Something that can sign this machine's lease set.
///
/// Object-safe on purpose: the store holds an `Arc<dyn Authority>` so a
/// hardware implementation drops in without touching a single caller.
pub trait Authority: fmt::Debug + Send + Sync {
    /// Public verification material, in the form [`verify`] expects: the
    /// `subjectPublicKey` bit-string contents of an SPKI, i.e. the raw
    /// uncompressed point for P-256.
    fn public_key(&self) -> &[u8];

    /// Sign `message`. `message` is already domain-separated by the caller.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AuthorityError>;

    fn algorithm(&self) -> SignatureAlg;

    /// Local information only. See [`KeyCustody`].
    fn custody(&self) -> KeyCustody;
}

/// The v0.15 authority: a P-256 key in a `0400` file next to the TLS identity.
pub struct SoftwareAuthority {
    public_key: Vec<u8>,
    signer: Box<dyn Signer>,
    path: PathBuf,
}

impl fmt::Debug for SoftwareAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the key material, not even the public half — this type
        // ends up inside `Debug`-derived structs that get logged.
        f.debug_struct("SoftwareAuthority")
            .field("path", &self.path)
            .field("algorithm", &SignatureAlg::EcdsaP256Sha256.as_str())
            .finish()
    }
}

impl SoftwareAuthority {
    /// Load the authority key from `path`, generating one if it is absent.
    ///
    /// Mirrors [`crate::crypto::load_or_generate_key_and_cert`] deliberately:
    /// same directory, same `rcgen` key type, same `0400` mode, same
    /// generate-on-first-run story. One pattern for both keys.
    pub fn load_or_generate(path: &Path) -> Result<Self, AuthorityError> {
        if path.exists() {
            Self::load(path)
        } else {
            match Self::generate(path) {
                // Another daemon won the race and created it between the
                // `exists()` and the `create_new`. Its key is as good as ours.
                Err(AuthorityError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    Self::load(path)
                }
                other => other,
            }
        }
    }

    fn load(path: &Path) -> Result<Self, AuthorityError> {
        let pem = fs::read_to_string(path).map_err(|source| AuthorityError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let key_pair = rcgen::KeyPair::from_pem(&pem).map_err(|e| AuthorityError::Unusable {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        Self::from_key_pair(&key_pair, path)
    }

    fn generate(path: &Path) -> Result<Self, AuthorityError> {
        let key_pair = rcgen::KeyPair::generate()?; // ECDSA P-256, as the TLS identity
        let pem = key_pair.serialize_pem();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| AuthorityError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        // `create_new` so we never clobber an authority key that already
        // exists: overwriting it would orphan every signed file on this
        // machine, which reads to the user as "hops forgot all my devices".
        // Created at 0600 and tightened to 0400 after the write, so the key is
        // never briefly group- or world-readable — the create-then-chmod window
        // `create_private` exists to avoid for the config file.
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path).map_err(|source| AuthorityError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let write = f
            .write_all(pem.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|source| AuthorityError::Io {
                path: path.to_path_buf(),
                source,
            });
        if let Err(e) = write {
            // A half-written key is not a key. Leaving it behind would make
            // every subsequent start fail on `Unusable` with nothing to do
            // about it but delete the file by hand.
            let _ = fs::remove_file(path);
            return Err(e);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o400));
        }
        log::info!("generated a software trust authority at {}", path.display());

        Self::from_key_pair(&key_pair, path)
    }

    fn from_key_pair(key_pair: &rcgen::KeyPair, path: &Path) -> Result<Self, AuthorityError> {
        let alg = SignatureAlg::EcdsaP256Sha256;
        let pkcs8 = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&pkcs8).map_err(|e| {
            AuthorityError::Unusable {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })?;
        let signer = signing_key.choose_scheme(&[alg.scheme()]).ok_or_else(|| {
            // A P-384 key in this file would land here rather than silently
            // signing with something the reader half cannot check.
            AuthorityError::Unusable {
                path: path.to_path_buf(),
                reason: format!("key cannot sign {alg}"),
            }
        })?;
        Ok(Self {
            public_key: key_pair.public_key_raw().to_vec(),
            signer,
            path: path.to_path_buf(),
        })
    }
}

impl Authority for SoftwareAuthority {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AuthorityError> {
        self.signer
            .sign(message)
            .map_err(|e| AuthorityError::Sign(e.to_string()))
    }

    fn algorithm(&self) -> SignatureAlg {
        SignatureAlg::EcdsaP256Sha256
    }

    fn custody(&self) -> KeyCustody {
        KeyCustody::SoftwareFile
    }
}

/// Verify `signature` over `message` under `public_key`.
///
/// Note the parameter list: an algorithm, a key, a message, a signature. There
/// is no [`Authority`] here and no [`KeyCustody`] here, so this function cannot
/// prefer a hardware-held key, cannot require an assurance level, and cannot
/// refuse a signer for being software-backed. That is the whole hardware-
/// independence constraint, expressed as a type signature rather than as a
/// comment someone has to remember.
pub fn verify(
    alg: SignatureAlg,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), AuthorityError> {
    for candidate in verification_algorithms(alg) {
        if candidate
            .verify_signature(public_key, message, signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(AuthorityError::BadSignature)
}

/// The webpki verification algorithms matching `alg`, taken from the same
/// `ring` provider rustls uses for the QUIC handshake, so there is one crypto
/// backend in the process and not two.
fn verification_algorithms(
    alg: SignatureAlg,
) -> &'static [&'static dyn SignatureVerificationAlgorithm] {
    static P256: OnceLock<&'static [&'static dyn SignatureVerificationAlgorithm]> = OnceLock::new();
    match alg {
        SignatureAlg::EcdsaP256Sha256 => P256.get_or_init(|| {
            let provider = rustls::crypto::ring::default_provider();
            provider
                .signature_verification_algorithms
                .mapping
                .iter()
                .find(|(scheme, _)| *scheme == SignatureAlg::EcdsaP256Sha256.scheme())
                .map(|(_, algs)| *algs)
                .unwrap_or(&[])
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("hops-authority-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// The whole point of the module: a real signature over real bytes, made
    /// and checked by the shipping code path, with no hardware anywhere.
    #[test]
    fn a_software_authority_signs_and_the_verifier_accepts() {
        let d = tmpdir("roundtrip");
        let a = SoftwareAuthority::load_or_generate(&d.join(AUTHORITY_KEY_FILE_NAME))
            .expect("generate");
        let sig = a.sign(b"lease set").expect("sign");
        verify(a.algorithm(), a.public_key(), b"lease set", &sig).expect("verify");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn one_flipped_byte_in_the_message_is_refused() {
        let d = tmpdir("tamper");
        let a = SoftwareAuthority::load_or_generate(&d.join(AUTHORITY_KEY_FILE_NAME))
            .expect("generate");
        let sig = a.sign(b"lease set").expect("sign");
        assert!(
            verify(a.algorithm(), a.public_key(), b"lease sea", &sig).is_err(),
            "an edited body must not verify — this is the hand-edit defence"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn another_installations_key_is_refused() {
        let (d1, d2) = (tmpdir("mine"), tmpdir("theirs"));
        let mine = SoftwareAuthority::load_or_generate(&d1.join(AUTHORITY_KEY_FILE_NAME))
            .expect("generate");
        let theirs = SoftwareAuthority::load_or_generate(&d2.join(AUTHORITY_KEY_FILE_NAME))
            .expect("generate");
        let sig = theirs.sign(b"lease set").expect("sign");
        assert!(
            verify(mine.algorithm(), mine.public_key(), b"lease set", &sig).is_err(),
            "a trust store copied from another machine must not verify here"
        );
        let _ = fs::remove_dir_all(&d1);
        let _ = fs::remove_dir_all(&d2);
    }

    #[test]
    fn the_key_survives_a_restart() {
        let d = tmpdir("reload");
        let p = d.join(AUTHORITY_KEY_FILE_NAME);
        let first = SoftwareAuthority::load_or_generate(&p).expect("generate");
        let expected = first.public_key().to_vec();
        drop(first);
        let second = SoftwareAuthority::load_or_generate(&p).expect("reload");
        assert_eq!(
            second.public_key(),
            expected.as_slice(),
            "regenerating on restart would orphan every signed file on the machine"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn the_authority_key_is_owner_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("mode");
        let p = d.join(AUTHORITY_KEY_FILE_NAME);
        SoftwareAuthority::load_or_generate(&p).expect("generate");
        let mode = fs::metadata(&p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o400,
            "the authority key must never be readable by others"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn an_unknown_algorithm_name_is_refused_rather_than_skipped() {
        assert!(SignatureAlg::parse("ed25519-but-not-yet").is_err());
        assert_eq!(
            SignatureAlg::parse("ecdsa-p256-sha256").expect("known"),
            SignatureAlg::EcdsaP256Sha256
        );
    }
}

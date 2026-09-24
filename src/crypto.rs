use std::io::{self, Read};
use std::path::Path;
use std::{fs::File, io::BufReader};

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),
    #[error("no certificate found in `{0}`")]
    NoCertificate(String),
    #[error("no private key found in `{0}`")]
    NoPrivateKey(String),
    #[error("pem parse error: {0}")]
    Pem(String),
}

/// Our TLS identity: a self-signed leaf certificate plus its private key, in
/// DER form. Replaces the former `webrtc_dtls::crypto::Certificate`.
pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl Identity {
    /// SHA-256 fingerprint of the leaf certificate (the persisted peer identity).
    pub fn fingerprint(&self) -> String {
        generate_fingerprint(self.cert.as_ref())
    }
}

/// SHA-256 fingerprint of `cert`, formatted `aa:bb:..` lowercase.
///
/// This is the persisted peer-identity format and the byte input (the X.509
/// leaf DER) is unchanged from the DTLS implementation, so fingerprints stay
/// comparable across the wire. Do not change.
pub fn generate_fingerprint(cert: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(cert);
    let bytes = hash
        .finalize()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>();
    bytes.join(":").to_lowercase()
}

pub fn certificate_fingerprint(identity: &Identity) -> String {
    identity.fingerprint()
}

/// Load an [`Identity`] (cert + key) from a combined PEM file.
pub fn load_certificate(path: &Path) -> Result<Identity, Error> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut pem = String::new();
    reader.read_to_string(&mut pem)?;
    parse_identity(&pem, &path.display().to_string())
}

fn parse_identity(pem: &str, src: &str) -> Result<Identity, Error> {
    use rustls_pki_types::pem::{self, PemObject};
    // The first certificate and the first private key in the file, whichever
    // kind of key it is (PKCS#8, PKCS#1 or SEC1).
    let cert = match CertificateDer::from_pem_slice(pem.as_bytes()) {
        Ok(cert) => cert,
        Err(pem::Error::NoItemsFound) => return Err(Error::NoCertificate(src.to_owned())),
        Err(e) => return Err(Error::Pem(e.to_string())),
    };
    let key = match PrivateKeyDer::from_pem_slice(pem.as_bytes()) {
        Ok(key) => key,
        Err(pem::Error::NoItemsFound) => return Err(Error::NoPrivateKey(src.to_owned())),
        Err(e) => return Err(Error::Pem(e.to_string())),
    };
    Ok(Identity { cert, key })
}

pub(crate) fn load_or_generate_key_and_cert(path: &Path) -> Result<Identity, Error> {
    // A process that ended part-way through creating the identity can have
    // left a whole private key beside it.
    crate::new_file::remove_abandoned_temporaries(path);
    if path.exists() && path.is_file() {
        load_certificate(path)
    } else {
        match generate_key_and_cert(path) {
            // Another process created it after the `exists()`. Use that one: a
            // running daemon may already hold it in memory.
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => load_certificate(path),
            other => other,
        }
    }
}

pub(crate) fn generate_key_and_cert(path: &Path) -> Result<Identity, Error> {
    let key_pair = rcgen::KeyPair::generate()?; // ECDSA P-256
    let mut params = rcgen::CertificateParams::new(vec!["grabbr".to_owned()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "grabbr-hop");
    // Trust is by fingerprint, not validity dates — use a very wide, fixed
    // window so a persisted cert never becomes a time-bomb and clock skew on
    // either machine is irrelevant.
    params.not_before =
        time::OffsetDateTime::from_unix_timestamp(1_577_836_800).expect("2020-01-01");
    params.not_after =
        time::OffsetDateTime::from_unix_timestamp(4_733_510_400).expect("2120-01-01");
    let cert = params.self_signed(&key_pair)?;

    // Keep the same combined-PEM-on-disk layout (private key then certificate)
    // and path as before.
    let serialized = format!("{}{}", key_pair.serialize_pem(), cert.pem());
    // Whole, and never over an identity another process has just created.
    crate::new_file::create_whole(
        path,
        serialized.as_bytes(),
        crate::new_file::Access::OwnerRead,
    )?;

    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok(Identity {
        cert: cert_der,
        key: key_der,
    })
}

#[cfg(test)]
mod one_identity_on_disk {
    //! The identity key is created once. A daemon holds it in memory for as
    //! long as it runs, so a second writer replacing the file would leave that
    //! daemon presenting an identity that no longer matches the one on disk,
    //! which every paired machine has pinned.

    use super::{generate_fingerprint, load_certificate, load_or_generate_key_and_cert};
    use std::sync::{Arc, Barrier};

    // LEDGER T10 | class B | 1 return value + 4 file on disk
    #[test]
    fn processes_creating_the_identity_at_once_all_end_up_with_the_one_on_disk() {
        const ROUNDS: usize = 10;
        const WRITERS: usize = 8;
        let dir = std::env::temp_dir().join(format!("hops-identity-race-{}", std::process::id()));
        for round in 0..ROUNDS {
            let _ = std::fs::remove_dir_all(&dir);
            let path = dir.join("lan-mouse.pem");
            let start = Arc::new(Barrier::new(WRITERS));
            let got: Vec<Result<String, String>> = (0..WRITERS)
                .map(|_| {
                    let (start, path) = (start.clone(), path.clone());
                    std::thread::spawn(move || {
                        start.wait();
                        load_or_generate_key_and_cert(&path)
                            .map(|id| generate_fingerprint(id.cert.as_ref()))
                            .map_err(|e| e.to_string())
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().expect("a writer thread"))
                .collect();
            let on_disk = load_certificate(&path).map(|id| id.fingerprint());
            let _ = std::fs::remove_dir_all(&dir);

            let on_disk = on_disk.unwrap_or_else(|e| {
                panic!(
                    "round {round}: the identity on disk does not load ({e}); writers got {got:?}"
                )
            });
            assert!(
                got.iter().all(|g| g.as_deref() == Ok(on_disk.as_str())),
                "round {round}: the identity on disk is {on_disk}, and the processes \
                 that created it at the same moment got {got:?}. A daemon holding \
                 an identity other than the one on disk presents a fingerprint that \
                 changes at its next restart, and every paired machine refuses it."
            );
        }
    }
}

#[cfg(test)]
mod reading_an_identity {
    use super::{Error, Identity, parse_identity};

    /// A certificate from a fresh identity, as PEM, to pair with a key.
    fn certificate_pem() -> String {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let params = rcgen::CertificateParams::new(vec!["grabbr".to_owned()]).expect("params");
        params.self_signed(&key).expect("self signed").pem()
    }

    /// hops' own identity file: a certificate and a PKCS#8 key.
    #[test]
    fn an_identity_reads_back_as_the_certificate_and_key_written() {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let params = rcgen::CertificateParams::new(vec!["grabbr".to_owned()]).expect("params");
        let cert = params.self_signed(&key).expect("self signed");
        let pem = format!("{}{}", cert.pem(), key.serialize_pem());

        let identity = parse_identity(&pem, "test").expect("parses");
        assert_eq!(identity.cert.as_ref(), cert.der().as_ref());
        assert_eq!(identity.key.secret_der(), key.serialize_der().as_slice());
    }

    /// The SEC1 key inside a PKCS#8 one: PKCS#8 wraps it as the third element
    /// of its top-level sequence, an octet string.
    fn sec1_pem() -> String {
        fn next(der: &[u8]) -> (&[u8], &[u8]) {
            let (len, at) = match der[1] {
                n if n < 0x80 => (n as usize, 2),
                0x81 => (der[2] as usize, 3),
                _ => (((der[2] as usize) << 8) | der[3] as usize, 4),
            };
            (&der[at..at + len], &der[at + len..])
        }
        let pkcs8 = rcgen::KeyPair::generate().expect("keypair").serialize_der();
        let (outer, _) = next(&pkcs8);
        let (_version, rest) = next(outer);
        let (_algorithm, rest) = next(rest);
        let (sec1, _) = next(rest);

        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for chunk in sec1.chunks(3) {
            let n = chunk.iter().fold(0u32, |n, &b| n << 8 | b as u32) << (8 * (3 - chunk.len()));
            for i in 0..4 {
                b64.push(if i <= chunk.len() {
                    ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char
                } else {
                    '='
                });
            }
        }
        format!("-----BEGIN EC PRIVATE KEY-----\n{b64}\n-----END EC PRIVATE KEY-----\n")
    }

    /// A key file in the older SEC1 form is still accepted. PKCS#1 takes the
    /// same path through the parser; it is not generated here because nothing
    /// in the dependency tree makes RSA keys.
    #[test]
    fn an_older_key_format_is_still_read() {
        let pem = format!("{}{}", certificate_pem(), sec1_pem());
        let identity = parse_identity(&pem, "test");
        assert!(
            matches!(
                identity,
                Ok(Identity {
                    key: rustls_pki_types::PrivateKeyDer::Sec1(_),
                    ..
                })
            ),
            "a SEC1 private key was refused"
        );
    }

    /// A file missing either half says which half is missing.
    #[test]
    fn a_missing_half_is_named() {
        assert!(matches!(
            parse_identity(&sec1_pem(), "f"),
            Err(Error::NoCertificate(_))
        ));
        assert!(matches!(
            parse_identity(&certificate_pem(), "f"),
            Err(Error::NoPrivateKey(_))
        ));
    }
}

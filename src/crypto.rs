use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;
use std::{fs::File, io::BufReader};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
    let mut cert: Option<CertificateDer<'static>> = None;
    let mut key: Option<PrivateKeyDer<'static>> = None;
    let mut bytes = pem.as_bytes();
    for item in rustls_pemfile::read_all(&mut bytes) {
        match item.map_err(|e| Error::Pem(e.to_string()))? {
            rustls_pemfile::Item::X509Certificate(c) if cert.is_none() => cert = Some(c),
            rustls_pemfile::Item::Pkcs8Key(k) if key.is_none() => key = Some(k.into()),
            rustls_pemfile::Item::Pkcs1Key(k) if key.is_none() => key = Some(k.into()),
            rustls_pemfile::Item::Sec1Key(k) if key.is_none() => key = Some(k.into()),
            _ => {}
        }
    }
    let cert = cert.ok_or_else(|| Error::NoCertificate(src.to_owned()))?;
    let key = key.ok_or_else(|| Error::NoPrivateKey(src.to_owned()))?;
    Ok(Identity { cert, key })
}

pub(crate) fn load_or_generate_key_and_cert(path: &Path) -> Result<Identity, Error> {
    if path.exists() && path.is_file() {
        load_certificate(path)
    } else {
        generate_key_and_cert(path)
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
    params.not_before = time::OffsetDateTime::from_unix_timestamp(1_577_836_800).expect("2020-01-01");
    params.not_after = time::OffsetDateTime::from_unix_timestamp(4_733_510_400).expect("2120-01-01");
    let cert = params.self_signed(&key_pair)?;

    // Keep the same combined-PEM-on-disk layout (private key then certificate)
    // and path as before.
    let serialized = format!("{}{}", key_pair.serialize_pem(), cert.pem());
    let parent = path.parent().expect("is a path");
    fs::create_dir_all(parent)?;
    let f = File::create(path)?;
    #[cfg(unix)]
    {
        let mut perm = f.metadata()?.permissions();
        perm.set_mode(0o400); /* r-- --- --- */
        f.set_permissions(perm)?;
    }
    /* FIXME windows permissions */
    let mut writer = BufWriter::new(f);
    writer.write_all(serialized.as_bytes())?;
    writer.flush()?;

    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok(Identity {
        cert: cert_der,
        key: key_der,
    })
}

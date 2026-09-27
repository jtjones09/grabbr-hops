//! The three messages that let both machines arrive at the same six digits.
//!
//! The number itself is built in [`crate::match_code`]; this is only the
//! exchange that feeds it. It runs on a connection whose handshake completed
//! because an approval on this machine admitted the peer far enough to compare
//! a number (#167), so nothing here is reachable by a stranger.
//!
//! # Why a commitment, and why the responder sends it first
//!
//! Both nonces go into the digits, so whichever side speaks last could choose
//! its half after seeing the other's and search for a value that yields any
//! number it likes. A million tries is seconds.
//!
//! So the side that speaks last commits first. The responder sends a hash of
//! its nonce before it learns the initiator's, and reveals only afterwards; the
//! initiator checks that the reveal opens the commitment it already holds. By
//! the time either side could search, it is bound to a value it picked blind.
//!
//! # Roles are positional, never negotiated
//!
//! The responder is the side that accepted the connection, the initiator the
//! side that dialled. Neither is announced on the wire, because a role that can
//! be claimed is a role an attacker claims — being the initiator is the
//! privileged seat here, since it speaks second.
//!
//! # Failure shows no number
//!
//! Every error path returns without a code. A number from a ceremony that did
//! not complete is worse than no number, because the person comparing two
//! screens cannot tell the difference and will confirm a match that means
//! nothing.

use std::time::Duration;

use quinn::Connection;

use crate::match_code::{self, COMMIT_LEN, NONCE_LEN};

/// The exporter label. Distinct from anything else derived from this session.
const EXPORTER_LABEL: &[u8] = b"hops match v1";
/// 32 bytes of session-bound material.
const EXPORTER_LEN: usize = 32;

/// A ceremony must not hold a connection open waiting for a peer that will
/// never answer. Generous, because it is three small messages on an established
/// connection: anything slower than this is a peer that is not taking part,
/// which is what a build from before the ceremony does.
pub(crate) const STEP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(crate) enum CeremonyError {
    /// The peer's build predates the ceremony, or it already trusts this
    /// machine and went straight to sending input.
    NotSupported,
    /// The connection would not give up keying material.
    NoExporter,
    /// This machine could not draw a random nonce.
    NoRandomness,
    /// The reveal did not open the commitment. Either the peer chose its nonce
    /// after seeing ours, or something is rewriting the stream — the two are
    /// indistinguishable from here and both mean the same thing: show nothing.
    CommitmentBroken,
    Io(String),
    /// Failed after this machine's own half went out: the dialler's nonce,
    /// or the reveal. From then on the other machine may hold the number,
    /// so the attempt cannot end as if nothing was compared.
    Late(Box<CeremonyError>),
}

impl CeremonyError {
    /// Whether the other machine may already know the number.
    pub(crate) fn late(&self) -> bool {
        matches!(self, Self::Late(_))
    }
}

/// Mark a failure from here on as [`CeremonyError::Late`].
fn late<T>(r: Result<T, CeremonyError>) -> Result<T, CeremonyError> {
    r.map_err(|e| CeremonyError::Late(Box::new(e)))
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupported => write!(f, "peer did not take part in the match ceremony"),
            Self::NoExporter => write!(f, "no keying material from this connection"),
            Self::NoRandomness => write!(f, "no randomness available on this machine"),
            Self::CommitmentBroken => write!(
                f,
                "the revealed nonce did not open the commitment — no number can be shown"
            ),
            Self::Io(e) => write!(f, "{e}"),
            Self::Late(e) => write!(f, "{e}, after this machine's half was sent"),
        }
    }
}

/// Fill `buf` from the TLS provider's random source. False if it failed.
pub(crate) fn fill_random(buf: &mut [u8]) -> bool {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(buf)
        .is_ok()
}

/// 32 bytes bound to this session and no other.
fn exporter(conn: &Connection) -> Result<[u8; EXPORTER_LEN], CeremonyError> {
    let mut out = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, b"")
        .map_err(|_| CeremonyError::NoExporter)?;
    Ok(out)
}

fn nonce() -> Result<[u8; NONCE_LEN], CeremonyError> {
    let mut n = [0u8; NONCE_LEN];
    if fill_random(&mut n) {
        Ok(n)
    } else {
        Err(CeremonyError::NoRandomness)
    }
}

async fn with_timeout<T>(
    what: &str,
    f: impl std::future::Future<Output = Result<T, CeremonyError>>,
) -> Result<T, CeremonyError> {
    match tokio::time::timeout(STEP_TIMEOUT, f).await {
        Ok(r) => r,
        Err(_) => Err(CeremonyError::Io(format!("timed out waiting for {what}"))),
    }
}

/// The side that ACCEPTED the connection. Commits, then reveals.
pub(crate) async fn as_responder(
    conn: &Connection,
    my_fp: &str,
    peer_fp: &str,
) -> Result<String, CeremonyError> {
    let x = exporter(conn)?;
    let n_r = nonce()?;
    let commitment = match_code::commitment(&x, my_fp, peer_fp, &n_r);

    // The responder opens, because the responder speaks first.
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| CeremonyError::Io(e.to_string()))?;

    with_timeout("the commitment to flush", async {
        send.write_all(&commitment)
            .await
            .map_err(|e| CeremonyError::Io(e.to_string()))
    })
    .await?;

    // A dialler that never answers is one that does not know to: a build from
    // before the ceremony, or one that already trusts this machine.
    let mut n_i = [0u8; NONCE_LEN];
    match tokio::time::timeout(STEP_TIMEOUT, recv.read_exact(&mut n_i)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => return Err(CeremonyError::NotSupported),
    }

    // Only now is the nonce revealed, and by now it is already committed to.
    // Any of it that arrives narrows the number down for the initiator.
    late(
        with_timeout("the reveal to flush", async {
            send.write_all(&n_r)
                .await
                .map_err(|e| CeremonyError::Io(e.to_string()))
        })
        .await,
    )?;
    let _ = send.finish();

    Ok(match_code::code(&x, my_fp, peer_fp, &n_i, &n_r))
}

/// The side that DIALLED. Receives the commitment, answers, then checks the
/// reveal opens it.
pub(crate) async fn as_initiator(
    conn: &Connection,
    my_fp: &str,
    peer_fp: &str,
) -> Result<String, CeremonyError> {
    let x = exporter(conn)?;

    // A receiver that never opens the stream within the step is one that does
    // not know to: a build from before the ceremony, or one that already trusts
    // this machine. The caller says which to check.
    let (mut send, mut recv) = match tokio::time::timeout(STEP_TIMEOUT, conn.accept_bi()).await {
        Ok(Ok(streams)) => streams,
        Ok(Err(_)) | Err(_) => return Err(CeremonyError::NotSupported),
    };

    let mut commitment = [0u8; COMMIT_LEN];
    with_timeout("the commitment", async {
        recv.read_exact(&mut commitment)
            .await
            .map_err(|_| CeremonyError::NotSupported)
    })
    .await?;

    let n_i = nonce()?;
    // From the first byte of our nonce on, the responder, which already has
    // its own half, narrows the number down, and has it before we do.
    late(
        with_timeout("our nonce to flush", async {
            send.write_all(&n_i)
                .await
                .map_err(|e| CeremonyError::Io(e.to_string()))
        })
        .await,
    )?;
    let _ = send.finish();

    let mut n_r = [0u8; NONCE_LEN];
    late(
        with_timeout("the reveal", async {
            recv.read_exact(&mut n_r)
                .await
                .map_err(|e| CeremonyError::Io(format!("{e:?}")))
        })
        .await,
    )?;

    // The whole point of the ordering. Refusing here is what stops the
    // responder picking its half after seeing ours.
    if !match_code::opens(&commitment, &x, my_fp, peer_fp, &n_r) {
        return late(Err(CeremonyError::CommitmentBroken));
    }

    Ok(match_code::code(&x, my_fp, peer_fp, &n_i, &n_r))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two roles must agree, and the ordering must be the thing that makes
    /// the initiator able to refuse. Exercised without a connection by driving
    /// the same steps the wire does.
    #[test]
    fn the_two_roles_reach_the_same_number() {
        let x = [7u8; EXPORTER_LEN];
        let (a, b) = ("aa:bb:cc", "11:22:33");
        let n_r = [1u8; NONCE_LEN];
        let n_i = [2u8; NONCE_LEN];

        // responder computes with (mine, theirs); initiator with the reverse
        let on_responder = match_code::code(&x, a, b, &n_i, &n_r);
        let on_initiator = match_code::code(&x, b, a, &n_i, &n_r);
        assert_eq!(on_responder, on_initiator);

        let c = match_code::commitment(&x, a, b, &n_r);
        assert!(
            match_code::opens(&c, &x, b, a, &n_r),
            "the initiator checks the commitment with the fingerprints in ITS \
             order, so the ordering has to survive the role swap or every \
             ceremony fails closed"
        );
    }

    #[test]
    fn a_responder_that_changes_its_mind_is_caught() {
        let x = [7u8; EXPORTER_LEN];
        let (a, b) = ("aa:bb:cc", "11:22:33");
        let committed = [1u8; NONCE_LEN];
        let c = match_code::commitment(&x, a, b, &committed);
        // It saw the initiator's nonce and now wants a different half.
        let swapped = [9u8; NONCE_LEN];
        assert!(
            !match_code::opens(&c, &x, b, a, &swapped),
            "this is the entire reason the responder commits first — without \
             the check it could search for a nonce yielding any six digits it \
             wanted, in seconds"
        );
    }

    #[test]
    fn every_error_says_what_it_means() {
        // The strings reach a log and, for the unsupported case, a notice —
        // "it failed" is not something a person can act on.
        for e in [
            CeremonyError::NotSupported,
            CeremonyError::NoExporter,
            CeremonyError::NoRandomness,
            CeremonyError::CommitmentBroken,
            CeremonyError::Io("x".into()),
            CeremonyError::Late(Box::new(CeremonyError::Io("x".into()))),
        ] {
            let s = e.to_string();
            assert!(!s.is_empty() && !s.contains("CeremonyError"), "got {s:?}");
        }
    }
}

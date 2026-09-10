//! The three messages that let both machines arrive at the same six digits.
//!
//! The number itself is built in [`crate::match_code`]; this is only the
//! exchange that feeds it. It runs on a connection that has already completed
//! and already passed both authorization checks, so nothing here is reachable
//! by a stranger — a peer must hold a live lease before it gets this far.
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
/// connection: anything slower than this is a peer that is not participating.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum CeremonyError {
    /// The peer's build predates the ceremony, or declined to take part.
    NotSupported,
    /// The connection would not give up keying material.
    NoExporter,
    /// The reveal did not open the commitment. Either the peer chose its nonce
    /// after seeing ours, or something is rewriting the stream — the two are
    /// indistinguishable from here and both mean the same thing: show nothing.
    CommitmentBroken,
    Io(String),
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupported => write!(f, "peer did not take part in the match ceremony"),
            Self::NoExporter => write!(f, "no keying material from this connection"),
            Self::CommitmentBroken => write!(
                f,
                "the revealed nonce did not open the commitment — no number can be shown"
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

/// 32 bytes bound to this session and no other.
fn exporter(conn: &Connection) -> Result<[u8; EXPORTER_LEN], CeremonyError> {
    let mut out = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, b"")
        .map_err(|_| CeremonyError::NoExporter)?;
    Ok(out)
}

fn nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n).expect("system randomness");
    n
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
pub async fn as_responder(
    conn: &Connection,
    my_fp: &str,
    peer_fp: &str,
) -> Result<String, CeremonyError> {
    let x = exporter(conn)?;
    let n_r = nonce();
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

    let mut n_i = [0u8; NONCE_LEN];
    with_timeout("the initiator's nonce", async {
        recv.read_exact(&mut n_i)
            .await
            .map_err(|_| CeremonyError::NotSupported)
    })
    .await?;

    // Only now is the nonce revealed, and by now it is already committed to.
    with_timeout("the reveal to flush", async {
        send.write_all(&n_r)
            .await
            .map_err(|e| CeremonyError::Io(e.to_string()))
    })
    .await?;
    let _ = send.finish();

    Ok(match_code::code(&x, my_fp, peer_fp, &n_i, &n_r))
}

/// The side that DIALLED. Receives the commitment, answers, then checks the
/// reveal opens it.
pub async fn as_initiator(
    conn: &Connection,
    my_fp: &str,
    peer_fp: &str,
) -> Result<String, CeremonyError> {
    let x = exporter(conn)?;

    let (mut send, mut recv) = with_timeout("the peer to open the match stream", async {
        conn.accept_bi()
            .await
            // A peer that never opens it is one that does not know to: an older
            // build, not a hostile one. The caller decides what that is worth.
            .map_err(|_| CeremonyError::NotSupported)
    })
    .await?;

    let mut commitment = [0u8; COMMIT_LEN];
    with_timeout("the commitment", async {
        recv.read_exact(&mut commitment)
            .await
            .map_err(|_| CeremonyError::NotSupported)
    })
    .await?;

    let n_i = nonce();
    with_timeout("our nonce to flush", async {
        send.write_all(&n_i)
            .await
            .map_err(|e| CeremonyError::Io(e.to_string()))
    })
    .await?;
    let _ = send.finish();

    let mut n_r = [0u8; NONCE_LEN];
    with_timeout("the reveal", async {
        recv.read_exact(&mut n_r)
            .await
            .map_err(|e| CeremonyError::Io(format!("{e:?}")))
    })
    .await?;

    // The whole point of the ordering. Refusing here is what stops the
    // responder picking its half after seeing ours.
    if !match_code::opens(&commitment, &x, my_fp, peer_fp, &n_r) {
        return Err(CeremonyError::CommitmentBroken);
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
        // The strings reach a log and, for the unsupported case, a UI branch —
        // "it failed" is not something a person can act on.
        for e in [
            CeremonyError::NotSupported,
            CeremonyError::NoExporter,
            CeremonyError::CommitmentBroken,
            CeremonyError::Io("x".into()),
        ] {
            let s = e.to_string();
            assert!(!s.is_empty() && !s.contains("CeremonyError"), "got {s:?}");
        }
    }
}

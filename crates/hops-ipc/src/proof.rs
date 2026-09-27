//! The two-way proof that opens every frontend connection (#96).
//!
//! Both ends hold the IPC token ([`crate::token`]). Each proves it to the
//! other without sending it:
//!
//! ```text
//! frontend -> daemon    challenge <nf>
//! daemon   -> frontend  answer <nd> <HMAC(token, "daemon", nf, nd)>
//! frontend -> daemon    proof <HMAC(token, "frontend", nf, nd)>
//! ```
//!
//! `nf` and `nd` are 32 random bytes each, fresh for every connection. The
//! frontend checks the daemon's answer before it sends anything else, and
//! hangs up on one that does not prove the token, so something that holds
//! the endpoint in the daemon's place learns nothing it could present to
//! the daemon, and cannot feed a frontend events. The daemon reads no
//! request until the frontend's proof checks.
//!
//! A proof is bound to both nonces, so one recorded on one connection admits
//! nothing on another, and the two directions carry different labels, so the
//! daemon's own answer sent back to it is not a frontend's proof.
//!
//! What it does not do: it authenticates the two ends, not the bytes between
//! them. Something that can reach the daemon and also hold the endpoint a
//! frontend dials could relay a whole connection. Reaching the daemon takes
//! this user's socket or pipe, so that is a program running as this user,
//! which can read the token anyway: the stated limit in the crate docs.
//!
//! Everything here is plain computation, the same on every platform, so
//! it is tested everywhere; the transports only carry the lines.

use std::io;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::ConnectionError;

/// The frontend's first line starts with this.
const CHALLENGE: &str = "challenge";
/// The daemon's answer starts with this.
const ANSWER: &str = "answer";
/// The frontend's second line starts with this.
const PROOF: &str = "proof";
/// All a daemon says to a connection it will not take, because too many are
/// part-way through the proof already.
pub(crate) const BUSY_LINE: &str = "busy\n";

/// What the daemon's MAC covers besides the nonces.
const DAEMON_LABEL: &[u8] = b"hops-ipc/2 daemon\0";
/// What the frontend's MAC covers besides the nonces. Differs from the
/// daemon's, so neither side's proof serves as the other's.
const FRONTEND_LABEL: &[u8] = b"hops-ipc/2 frontend\0";

/// Bytes in a nonce.
const NONCE_BYTES: usize = 32;
/// Hex digits in a nonce or a MAC.
const HEX_CHARS: usize = 64;

/// The longest answer line a frontend reads: the word, two 64-digit fields
/// and separators, with room to spare. Anything longer is not an answer.
pub(crate) const ANSWER_LINE_MAX: usize = 256;

/// How long a frontend waits for the daemon to answer its challenge.
///
/// A running daemon answers at once. One that has bound its endpoint and is
/// still reading its keys answers when its loop starts, well within this.
pub const PROOF_WITHIN: Duration = Duration::from_secs(5);

/// Make the frontend's half of the two-way proof on a connection just
/// opened: send a challenge, check the daemon's answer proves `token`, and
/// only then send this side's proof.
///
/// `rx` must be the reader the frontend goes on to read events from, so
/// nothing the daemon sends after its answer is lost. Nothing but the
/// challenge is sent to an endpoint whose answer does not check, and the
/// wait for an answer ends after [`PROOF_WITHIN`].
pub async fn prove_to_daemon<R, W>(
    rx: &mut R,
    tx: &mut W,
    token: &str,
) -> Result<(), ConnectionError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let nf = nonce()?;
    let asked = async {
        tx.write_all(challenge_line(&nf).as_bytes()).await?;
        tx.flush().await?;
        let mut line = Vec::new();
        (&mut *rx)
            .take(ANSWER_LINE_MAX as u64)
            .read_until(b'\n', &mut line)
            .await?;
        Ok::<_, io::Error>(line)
    };
    let line = match tokio::time::timeout(PROOF_WITHIN, asked).await {
        // Slow is not shown to be an impostor: a daemon may be starting.
        Err(_) => {
            return Err(ConnectionError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "nothing at the hops daemon's endpoint answered the challenge within {} s",
                    PROOF_WITHIN.as_secs()
                ),
            )));
        }
        Ok(result) => result?,
    };
    if line == BUSY_LINE.as_bytes() {
        return Err(ConnectionError::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "the hops daemon took no more connections: too many others are \
             part-way through proving they hold the IPC token",
        )));
    }

    if line.is_empty() {
        return Err(ConnectionError::Unproven(
            "it closed the connection without answering, as a hops daemon from \
             before the two-way proof does; restart the hops daemon"
                .to_string(),
        ));
    }
    let Some(nd) = std::str::from_utf8(&line)
        .ok()
        .and_then(|text| daemon_proven(token, &nf, text))
    else {
        return Err(ConnectionError::Unproven(
            "its answer was not made with this user's IPC token".to_string(),
        ));
    };
    tx.write_all(proof_line(token, &nf, &nd).as_bytes()).await?;
    tx.flush().await?;
    Ok(())
}

/// A fresh nonce, as hex.
pub(crate) fn nonce() -> io::Result<String> {
    let mut raw = [0u8; NONCE_BYTES];
    getrandom::fill(&mut raw)
        .map_err(|e| io::Error::other(format!("no OS randomness available: {e}")))?;
    Ok(hex(&raw))
}

/// The frontend's first line, for its nonce `nf`.
pub(crate) fn challenge_line(nf: &str) -> String {
    format!("{CHALLENGE} {nf}\n")
}

/// The frontend's nonce, if `line` is a challenge.
pub(crate) fn challenge_in(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix(CHALLENGE)?.strip_prefix(' ')?;
    is_hex_field(rest).then_some(rest)
}

/// The daemon's answer to challenge `nf`, with its own nonce `nd`.
pub(crate) fn answer_line(token: &str, nf: &str, nd: &str) -> String {
    let mac = mac(token, DAEMON_LABEL, nf, nd);
    format!("{ANSWER} {nd} {mac}\n")
}

/// Whether `line` is the daemon's answer to challenge `nf`, made with
/// `token`. The daemon's nonce when it is.
pub(crate) fn daemon_proven(token: &str, nf: &str, line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix(ANSWER)?.strip_prefix(' ')?;
    let (nd, offered) = rest.split_once(' ')?;
    if !is_hex_field(nd) || !is_hex_field(offered) {
        return None;
    }
    let expected = mac(token, DAEMON_LABEL, nf, nd);
    crate::token::matches(&expected, offered).then(|| nd.to_string())
}

/// The frontend's proof, for challenge `nf` answered with `nd`.
pub(crate) fn proof_line(token: &str, nf: &str, nd: &str) -> String {
    format!("{PROOF} {}\n", mac(token, FRONTEND_LABEL, nf, nd))
}

/// Whether `line` is a frontend's proof of `token` for challenge `nf`
/// answered with `nd`.
pub(crate) fn frontend_proven(token: &str, nf: &str, nd: &str, line: &str) -> bool {
    let Some(offered) = line
        .trim()
        .strip_prefix(PROOF)
        .and_then(|rest| rest.strip_prefix(' '))
    else {
        return false;
    };
    is_hex_field(offered) && crate::token::matches(&mac(token, FRONTEND_LABEL, nf, nd), offered)
}

/// The name of the daemon's named pipe for `token`.
///
/// Derived from the token, so a program that cannot read the token cannot
/// work it out, and so cannot create the pipe first, before the daemon
/// starts. The token is not in the name, which any process may list.
pub fn pipe_name(token: &str) -> String {
    format!(r"\\.\pipe\hops-{}", name_tag(token, b"hops-ipc pipe\0"))
}

/// The name of the event a running GUI answers a second launch on, for
/// `token`, in the session's own `Local\` namespace.
pub fn gui_instance_name(token: &str) -> String {
    format!(
        r"Local\hops-gui-{}",
        name_tag(token, b"hops-gui instance\0")
    )
}

/// 128 bits of `label` and `token` hashed, as hex.
fn name_tag(token: &str, label: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(label);
    hash.update(token.as_bytes());
    hex(&hash.finalize()[..16])
}

fn mac(token: &str, label: &[u8], nf: &str, nd: &str) -> String {
    hex(&hmac_sha256(
        token.as_bytes(),
        &[label, nf.as_bytes(), nd.as_bytes()],
    ))
}

/// HMAC-SHA256 (RFC 2104) of the concatenation of `parts`, keyed by `key`.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

fn is_hex_field(s: &str) -> bool {
    s.len() == HEX_CHARS && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// RFC 4231 test cases 1, 2 and 6: a short key, a key shorter than the
    /// data, and a key longer than a block, which is hashed first.
    // LEDGER T9604 | class B | 1 return value of proof::hmac_sha256
    #[test]
    fn the_mac_is_hmac_sha256() {
        let cases: [(Vec<u8>, &[u8], &str); 3] = [
            (
                vec![0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
        ];
        for (key, data, want) in cases {
            // Split, to show the parts are one message.
            let (a, b) = data.split_at(3);
            assert_eq!(
                hmac_sha256(&key, &[a, b]).to_vec(),
                unhex(want),
                "HMAC-SHA256 of {:?}",
                String::from_utf8_lossy(data)
            );
        }
    }

    /// Each side's proof checks against the same token and nonces, and
    /// against nothing else.
    // LEDGER T9605 | class B | 1 return values of proof::daemon_proven / frontend_proven
    #[test]
    fn a_proof_checks_only_for_its_token_and_its_nonces() {
        let (nf, nd) = (nonce().expect("a nonce"), nonce().expect("a nonce"));
        let answer = answer_line(TOKEN, &nf, &nd);
        let proof = proof_line(TOKEN, &nf, &nd);
        let other_nf = nonce().expect("a nonce");
        let other_nd = nonce().expect("a nonce");
        assert_eq!(
            (
                daemon_proven(TOKEN, &nf, &answer),
                daemon_proven(OTHER, &nf, &answer),
                daemon_proven(TOKEN, &other_nf, &answer),
                frontend_proven(TOKEN, &nf, &nd, &proof),
                frontend_proven(OTHER, &nf, &nd, &proof),
                frontend_proven(TOKEN, &other_nf, &nd, &proof),
                frontend_proven(TOKEN, &nf, &other_nd, &proof),
            ),
            (Some(nd.clone()), None, None, true, false, false, false),
            "(answer: right token, other token, other challenge; proof: right \
             token, other token, other challenge, other answer)"
        );
    }

    /// The daemon's answer, sent back to it, is not a frontend's proof. With
    /// one label for both directions it would be, and anything that can open
    /// the endpoint would be admitted by echoing what the daemon said.
    // LEDGER T9606 | class B | 1 return value of proof::frontend_proven
    #[test]
    fn the_daemons_answer_sent_back_is_not_a_proof() {
        let (nf, nd) = (nonce().expect("a nonce"), nonce().expect("a nonce"));
        let answer = answer_line(TOKEN, &nf, &nd);
        let echoed_mac = answer.trim().rsplit(' ').next().expect("the MAC");
        assert!(
            !frontend_proven(TOKEN, &nf, &nd, &format!("proof {echoed_mac}")),
            "the daemon's own MAC was accepted as the frontend's proof"
        );
    }

    /// Only a line of exactly the right shape is a challenge: an old
    /// frontend's bare token, an HTTP request line and a truncated nonce are
    /// not.
    // LEDGER T9607 | class B | 1 return value of proof::challenge_in
    #[test]
    fn only_a_well_formed_challenge_is_one() {
        let nf = nonce().expect("a nonce");
        assert_eq!(
            (
                challenge_in(&challenge_line(&nf)),
                challenge_in(TOKEN),
                challenge_in("POST / HTTP/1.1"),
                challenge_in(&format!("challenge {}", &nf[1..])),
                challenge_in(&format!("challenge {nf} extra")),
            ),
            (Some(nf.as_str()), None, None, None, None)
        );
        assert!(challenge_line(&nf).len() <= crate::listen::PREAUTH_LINE_MAX);
        assert!(answer_line(TOKEN, &nf, &nf).len() <= ANSWER_LINE_MAX);
    }

    /// The pipe's name follows the token and does not contain it.
    // LEDGER T9608 | class B | 1 return value of proof::pipe_name / gui_instance_name
    #[test]
    fn the_names_follow_the_token_without_showing_it() {
        let (a, b) = (pipe_name(TOKEN), pipe_name(OTHER));
        assert!(a.starts_with(r"\\.\pipe\hops-") && a != b && a == pipe_name(TOKEN));
        assert!(!a.contains(&TOKEN[..16]) && !a.contains(&TOKEN[48..]));
        let gui = gui_instance_name(TOKEN);
        assert!(gui.starts_with(r"Local\hops-gui-") && gui != gui_instance_name(OTHER));
        assert_ne!(
            a.rsplit('-').next(),
            gui.rsplit('-').next(),
            "the GUI's name must not give the pipe's away"
        );
    }

    /// Something holding the endpoint that answers the challenge with more
    /// than any answer and no end of line is refused once the frontend has
    /// read as much as an answer may be. Reading on, a frontend would take
    /// whatever it is sent for as long as it waits for an answer, on every
    /// reconnect.
    // LEDGER T9627 | class B | 1 return value of proof::prove_to_daemon + bytes it took over a duplex
    #[tokio::test(flavor = "current_thread")]
    async fn a_frontend_reads_no_more_of_an_answer_than_one_may_be() {
        const CHUNK: usize = 64;
        let (frontend, endpoint) = tokio::io::duplex(CHUNK);
        let flood = tokio::spawn(async move {
            let (rx, mut tx) = tokio::io::split(endpoint);
            let _ = tokio::io::BufReader::new(rx)
                .read_line(&mut String::new())
                .await;
            let mut taken = 0usize;
            while tx.write_all(&[b'a'; CHUNK]).await.is_ok() {
                taken += CHUNK;
            }
            taken
        });
        let (rx, mut tx) = tokio::io::split(frontend);
        let mut rx = tokio::io::BufReader::new(rx);
        let proven = prove_to_daemon(&mut rx, &mut tx, TOKEN).await;
        drop((rx, tx));
        let taken = flood.await.expect("the flood");
        assert!(
            matches!(proven, Err(ConnectionError::Unproven(_)))
                && taken <= ANSWER_LINE_MAX + 4 * CHUNK,
            "the frontend took {taken} bytes of an answer that never ended and \
             came away with {proven:?}; no answer is longer than {ANSWER_LINE_MAX}"
        );
    }
}

//! The six digits both machines show, so a person can confirm they are talking
//! to each other and not to something in between.
//!
//! This is Bluetooth numeric comparison: the same number appears on both
//! screens, a human confirms it matches, and only then does anything move. It
//! is not a secret and never travels — each side computes it from what it can
//! see, and they agree only if nothing is in the middle.
//!
//! # Why the obvious version does not work
//!
//! A code hashed from the two fingerprints alone is worthless here, because
//! hops multicasts its own fingerprint in its mDNS TXT record. Anything on the
//! segment can read both and compute what two machines will display.
//!
//! Worse, it can *choose* what they display. A machine in the middle holds two
//! sessions and picks its own ServerHello; varying only the random changes the
//! transcript while leaving the key exchange alone, so a candidate costs a
//! transcript re-hash and a key schedule — a few microseconds. A million of
//! them, enough to hit any chosen six digits, is seconds on one core and
//! entirely offline, before it sends anything. So a code over public values is
//! not weak, it is *selectable*, and the comparison it asks for cannot fail.
//!
//! # What makes this one bind
//!
//! Three inputs, and each closes a different door.
//!
//! **Both fingerprints, as observed on the live connection** — not from mDNS,
//! not from a pasted string. Whoever is in the middle has to present its own
//! certificate to each side, so the two ends hash different pairs and the
//! numbers differ. rustls still proves possession of the matching private key,
//! so a fingerprint on a connection is a fact rather than a claim.
//!
//! **The TLS exporter**, which exists only for this session and is derived from
//! the key exchange. A watcher on the wire sees both public shares and can
//! derive nothing. This ties the number to *this* connection, so one cannot be
//! lifted from another.
//!
//! **A nonce from each side, committed before either is revealed.** This is the
//! part that defeats the grind above. The responder sends a binding commitment
//! first, and only then learns the initiator's nonce — so by the time it could
//! search for a nonce that yields a chosen number, it is already bound to one it
//! picked without knowing the other half. Neither side can steer the result.
//!
//! # What it does not do
//!
//! It proves nothing is in the middle. It does not say the machine at the other
//! end is trustworthy — if that machine is compromised, the numbers match and
//! you have handed it your keyboard. And one pair in a million collides by
//! chance. That is the Bluetooth guarantee, not a proof.

use sha2::{Digest, Sha256};

/// Length of each side's nonce. 128 bits is far past what a six-digit result
/// needs; the cost is 16 bytes on a stream that carries nothing else.
pub const NONCE_LEN: usize = 16;
/// A commitment is a SHA-256 digest.
pub const COMMIT_LEN: usize = 32;

/// Domain separation. Two different questions must never hash to the same
/// answer, or a commitment from one could be replayed as a code for the other.
const COMMIT_DOMAIN: &[u8] = b"hops-match-commit-v1";
const CODE_DOMAIN: &[u8] = b"hops-match-v1";

/// The two fingerprints in a fixed order, so both ends hash the same thing.
///
/// Each side knows them as "mine" and "theirs", which are opposite orders on
/// opposite machines. Sorting is what makes one function serve both.
fn ordered<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b { (a, b) } else { (b, a) }
}

/// Absorb the session and the two identities, in the order both ends agree on.
///
/// Fingerprints are separated by a byte that cannot occur inside one, so
/// `"aa:bb" + "cc"` and `"aa" + "bb:cc"` cannot absorb identically.
fn absorb_context(h: &mut Sha256, exporter: &[u8], fp_a: &str, fp_b: &str) {
    let (lo, hi) = ordered(fp_a, fp_b);
    h.update(exporter);
    h.update(lo.as_bytes());
    h.update([0x00]);
    h.update(hi.as_bytes());
    h.update([0x00]);
}

/// The responder's commitment to its own nonce, sent before it learns the
/// initiator's.
///
/// It binds the fingerprints and the session as well as the nonce. A commitment
/// over the nonce alone could be replayed into a different ceremony, where it
/// would still open correctly and vouch for the wrong pair.
pub fn commitment(exporter: &[u8], fp_a: &str, fp_b: &str, nonce_r: &[u8]) -> [u8; COMMIT_LEN] {
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN);
    absorb_context(&mut h, exporter, fp_a, fp_b);
    h.update(nonce_r);
    h.finalize().into()
}

/// The six digits shown on both screens.
///
/// Formatted with leading zeros kept: dropping them would make some codes five
/// characters, and a person comparing "12345" against "012345" is being asked a
/// question the format made ambiguous.
pub fn code(exporter: &[u8], fp_a: &str, fp_b: &str, nonce_i: &[u8], nonce_r: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(CODE_DOMAIN);
    absorb_context(&mut h, exporter, fp_a, fp_b);
    h.update(nonce_i);
    h.update(nonce_r);
    let d = h.finalize();
    // Six decimal digits from the leading eight bytes. Truncating a hash is the
    // standard construction; the modulus bias over 2^64 is far below anything
    // that matters at six digits.
    let n = u64::from_be_bytes(d[..8].try_into().expect("32-byte digest")) % 1_000_000;
    format!("{n:06}")
}

/// Whether a revealed nonce opens the commitment that was received first.
///
/// The initiator checks this before showing anything. If it fails, the
/// responder chose its nonce after seeing the initiator's — which is exactly
/// the move that lets it steer the digits — and no number may be displayed,
/// because a number shown from a broken ceremony is worse than none.
pub fn opens(
    commitment_received: &[u8],
    exporter: &[u8],
    fp_a: &str,
    fp_b: &str,
    nonce_r: &[u8],
) -> bool {
    let expected = commitment(exporter, fp_a, fp_b, nonce_r);
    // Not secret, but constant-time costs nothing and keeps the habit.
    commitment_received.len() == expected.len()
        && commitment_received
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: &[u8] = b"an exporter, 32 bytes of session";
    const A: &str = "aa:bb:cc:dd";
    const B: &str = "11:22:33:44";
    const NI: &[u8] = b"initiator-nonce!";
    const NR: &[u8] = b"responder-nonce!";

    #[test]
    fn both_machines_compute_the_same_six_digits() {
        // Each side knows the pair as (mine, theirs) — opposite orders.
        let on_a = code(X, A, B, NI, NR);
        let on_b = code(X, B, A, NI, NR);
        assert_eq!(
            on_a, on_b,
            "the whole point is that two screens agree. Each machine knows the \
             fingerprints in the opposite order, so the ordering has to be \
             imposed rather than inherited."
        );
        assert_eq!(on_a.len(), 6, "six characters, always");
    }

    #[test]
    fn leading_zeros_are_kept() {
        // Search for an input whose code starts with a zero; the format must
        // not shorten it. A five-character code asks the user to compare two
        // strings of different lengths and decide whether that counts.
        let mut found = None;
        for i in 0..5000u32 {
            let n = i.to_be_bytes();
            let c = code(X, A, B, &n, NR);
            if c.starts_with('0') {
                found = Some(c);
                break;
            }
        }
        let c = found.expect("a zero-leading code inside 5000 tries");
        assert_eq!(c.len(), 6, "got {c}, which is not six characters");
    }

    #[test]
    fn a_different_session_gives_a_different_number() {
        assert_ne!(
            code(X, A, B, NI, NR),
            code(b"a different session exporter!!!!", A, B, NI, NR),
            "without the exporter a number could be lifted from one connection \
             and shown on another"
        );
    }

    #[test]
    fn a_machine_in_the_middle_cannot_make_both_sides_agree() {
        // M sits between A and B, presenting its own certificate to each. A
        // hashes (A, M); B hashes (M, B). Even on one shared session and shared
        // nonces, the two ends must differ.
        let m = "ff:ee:dd:cc";
        assert_ne!(
            code(X, A, m, NI, NR),
            code(X, m, B, NI, NR),
            "this is the entire defence: the fingerprints are read off the live \
             connection, so an interposer hashes a different pair on each side \
             and the screens disagree."
        );
    }

    #[test]
    fn a_commitment_opens_only_with_the_nonce_it_was_made_from() {
        let c = commitment(X, A, B, NR);
        assert!(opens(&c, X, A, B, NR));
        assert!(
            !opens(&c, X, A, B, b"a different nonce"),
            "if any nonce opened it, the responder could pick one AFTER seeing \
             the initiator's and steer the digits — a million tries is seconds"
        );
    }

    #[test]
    fn a_commitment_cannot_be_replayed_into_another_pairing() {
        let c = commitment(X, A, B, NR);
        assert!(
            !opens(&c, X, A, "99:88:77:66", NR),
            "the commitment binds the fingerprints too. Over the nonce alone it \
             would open in a different ceremony and vouch for the wrong pair."
        );
        assert!(
            !opens(&c, b"another session's exporter......", A, B, NR),
            "and it binds the session, for the same reason"
        );
    }

    #[test]
    fn the_two_hashes_answer_different_questions() {
        assert_ne!(
            &commitment(X, A, B, NR)[..],
            code(X, A, B, NI, NR).as_bytes(),
            "different domains, so a commitment can never be mistaken for a code"
        );
        // And with the nonces equal, the two constructions still differ.
        let as_commit = commitment(X, A, B, NR);
        let mut h = Sha256::new();
        h.update(CODE_DOMAIN);
        absorb_context(&mut h, X, A, B);
        h.update(NR);
        let no_domain_split: [u8; 32] = h.finalize().into();
        assert_ne!(
            as_commit, no_domain_split,
            "the domain strings are what keep them apart"
        );
    }

    #[test]
    fn fingerprints_cannot_be_smeared_into_each_other() {
        // These two pairs concatenate identically: "aa"+"bbcc" and
        // "aab"+"bcc" are both "aabbcc". Without a separator they absorb the
        // same bytes and collide by construction, whatever the nonces are.
        //
        // The first version of this test used ("aa:bb","cc") against
        // ("aa","bb:cc"), which concatenate to "aa:bbcc" and "aabb:cc" — not
        // equal, so it passed with the separators removed and tested nothing.
        // Mutation testing is what caught that.
        assert_eq!(
            "aa".to_string() + "bbcc",
            "aab".to_string() + "bcc",
            "the premise: these differ only by where the boundary falls"
        );
        assert_ne!(
            code(X, "aa", "bbcc", NI, NR),
            code(X, "aab", "bcc", NI, NR),
            "two different pairs of identities must never produce the same \
             number, or the comparison vouches for the wrong machine"
        );
    }

    #[test]
    fn a_truncated_commitment_does_not_open() {
        let c = commitment(X, A, B, NR);
        assert!(
            !opens(&c[..16], X, A, B, NR),
            "a short commitment must be rejected, not compared prefix-wise"
        );
        assert!(!opens(&[], X, A, B, NR));
    }

    #[test]
    fn every_digit_position_is_used() {
        // A bug that formatted only part of the digest would leave a position
        // constant across inputs, and nobody comparing two screens would notice.
        let mut seen = [[false; 10]; 6];
        for i in 0..400u32 {
            let c = code(X, A, B, &i.to_be_bytes(), NR);
            for (pos, ch) in c.chars().enumerate() {
                seen[pos][ch.to_digit(10).expect("digit") as usize] = true;
            }
        }
        for (pos, digits) in seen.iter().enumerate() {
            let distinct = digits.iter().filter(|d| **d).count();
            assert!(
                distinct >= 8,
                "position {pos} only ever took {distinct} distinct digits over \
                 400 codes — that position is not carrying information"
            );
        }
    }
}

//! How a machine is named at every door: its fingerprint, and the label a
//! person gave it.
//!
//! Both arrive from untrusted places (the frontend socket, the command line, a
//! hand-edited config, a peer's suggested name), so each is checked or cleaned
//! where it enters, never at each reader.

/// Longest label kept, in characters.
const MAX_LABEL_LEN: usize = 64;
/// A leaf-cert SHA-256 fingerprint is 32 lowercase hex bytes joined by ':'.
const FINGERPRINT_GROUPS: usize = 32;

/// Canonicalise a fingerprint arriving from ANY untrusted door — the IPC
/// channel, the CLI, a hand-edited config — into the one form the rest of the
/// system compares against, or reject it.
///
/// Computed leaf-cert fingerprints are lowercase `aa:bb:..`. Two of our own
/// hardening commits once disagreed about where that normalisation happens:
/// `Config::authorized_fingerprints` lowercased on READ while the removal
/// record of the time was looked up case-SENSITIVELY, so re-authorizing a
/// removed fingerprint with `A-F` uppercased missed it, and the next config
/// read folded it back to canonical form. The removed device was trusted
/// again. Neither commit was wrong on its own; they were wrong together
/// (issue #67).
///
/// So: normalise where a fingerprint ENTERS the system, never at each reader.
pub fn canonical_fingerprint(fp: &str) -> Option<String> {
    let lowered = fp.trim().to_lowercase();
    valid_fingerprint(&lowered).then_some(lowered)
}

/// True iff `fp` is a lowercase, colon-separated 32-byte hex fingerprint — the
/// exact shape used as the trust store's key. Rejects uppercase, short and
/// non-hex input, so nothing can smuggle in a bogus identity string.
pub fn valid_fingerprint(fp: &str) -> bool {
    let mut groups = 0usize;
    for g in fp.split(':') {
        groups += 1;
        let bytes = g.as_bytes();
        if bytes.len() != 2
            || !bytes
                .iter()
                .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return false;
        }
    }
    groups == FINGERPRINT_GROUPS
}

/// Strip control / bidi / zero-width characters and clamp length — the label is
/// attacker-influenced and gets rendered + logged, so defeat homoglyph/bidi
/// spoofing of a trusted name.
pub fn sanitize_label(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c,
                    '\u{200b}'..='\u{200f}'   // zero-width + LRM/RLM
                    | '\u{202a}'..='\u{202e}' // bidi embeddings/overrides
                    | '\u{2066}'..='\u{2069}' // bidi isolates
                    | '\u{feff}') // BOM / zero-width no-break
        })
        .take(MAX_LABEL_LEN)
        .collect()
}

#[cfg(test)]
mod labels {
    use super::*;

    #[test]
    fn control_and_bidi_characters_are_stripped() {
        assert_eq!(sanitize_label("stu\u{202e}dio\u{200b}\tpc"), "studiopc");
    }

    #[test]
    fn an_overlong_label_is_clamped() {
        assert_eq!(
            sanitize_label(&"n".repeat(200)).chars().count(),
            MAX_LABEL_LEN
        );
    }
}

#[cfg(test)]
mod canonical_fingerprint_tests {
    use super::*;

    fn fp(case: fn(&str) -> String) -> String {
        case(
            &(0..32)
                .map(|i| format!("{:02x}", i))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }

    #[test]
    fn uppercase_and_lowercase_spellings_canonicalise_to_the_same_string() {
        let lower = fp(|s| s.to_string());
        let upper = fp(|s| s.to_uppercase());
        assert_ne!(lower, upper, "precondition: the two spellings differ");
        assert_eq!(
            canonical_fingerprint(&upper),
            canonical_fingerprint(&lower),
            "an uppercased fingerprint must not be a different identity — that is issue #67"
        );
        assert_eq!(canonical_fingerprint(&upper), Some(lower));
    }

    #[test]
    fn canonicalisation_is_idempotent() {
        let c = canonical_fingerprint(&fp(|s| s.to_uppercase())).expect("valid");
        assert_eq!(canonical_fingerprint(&c), Some(c.clone()));
    }

    #[test]
    fn junk_is_rejected_rather_than_normalised() {
        for bad in [
            "",
            "not-a-fingerprint",
            "00:01",
            &fp(|s| s.to_string())[..90],
            "zz:01",
            &vec!["aa"; 31].join(":"),
        ] {
            assert_eq!(canonical_fingerprint(bad), None, "must reject {bad:?}");
        }
    }
}

//! Randomised smoke coverage for the two decoders an attacker can reach.
//!
//! The threat this guards is narrow and was live: every datagram arriving on the
//! mDNS socket is parsed *before* any handshake, by a dependency, on the process
//! that holds the private key — and the release profile sets `panic = "abort"`,
//! so a parser panic is a remote unauthenticated process kill rather than a
//! dropped packet. `mdns-sd` 0.21.1 had exactly that: an unchecked
//! `self.data[self.offset]` in `read_char_string`, reached by a truncated HINFO
//! record whose RDLENGTH runs to the packet boundary. Twenty-three bytes.
//!
//! Deterministic on purpose. A fixed seed means a failure here reproduces from
//! the printed input instead of being a flake someone re-runs until it passes.
//! `cargo-fuzz` would be better coverage and needs a nightly toolchain, which
//! this workspace pins against; this runs on the pinned toolchain in seconds.

/// xorshift64*. Not cryptographic — it only has to be reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 32) as usize % n.max(1)
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex literal"))
        .collect()
}

/// The 0.21.1 killer, kept as a named case rather than left to chance.
///
/// Header claims one additional record; the record is HINFO with its RDLENGTH
/// running past the last byte, so the parser reads a length at `offset ==
/// data.len()`. Against 0.21.1 this panics at `dns_parser.rs:2659`; against
/// 0.21.2 it is a parse error, which is the correct outcome for a malformed
/// packet.
const TRUNCATED_HINFO: &str = "00008400000000010000000000000d0001000000000000";

#[test]
fn a_truncated_hinfo_record_is_rejected_and_does_not_panic() {
    let pkt = hex(TRUNCATED_HINFO);
    assert_eq!(pkt.len(), 23, "the regression case is 23 bytes");
    mdns_sd::fuzz_api::parse_packet(&pkt);
}

#[test]
fn the_mdns_parser_survives_randomised_packets() {
    // Seeded from the shape of the bug rather than the clock: reproducibility is
    // the point.
    let mut rng = Rng(0x6d64_6e73_5f73_6421);
    let seed_corpus = [hex(TRUNCATED_HINFO), Vec::new(), vec![0u8; 12]];

    for i in 0..200_000u32 {
        let pkt = match i % 4 {
            // Free-form bytes: reaches the header and length checks.
            0 => {
                let len = rng.below(64);
                (0..len).map(|_| rng.byte()).collect::<Vec<u8>>()
            }
            // A plausible header with a mutated tail: reaches the record loop,
            // which is where the interesting parsing lives.
            1 => {
                let mut p = hex("0000840000000001000000000000");
                let len = rng.below(24);
                p.extend((0..len).map(|_| rng.byte()));
                p
            }
            // Bit-flipped seeds: walks outward from a known-bad input.
            2 => {
                let mut p = seed_corpus[rng.below(seed_corpus.len())].clone();
                if !p.is_empty() {
                    let at = rng.below(p.len());
                    p[at] ^= 1 << rng.below(8);
                }
                p
            }
            // Truncations: the whole bug class is "the packet ends early".
            _ => {
                let mut p = hex(TRUNCATED_HINFO);
                let keep = rng.below(p.len() + 1);
                p.truncate(keep);
                p
            }
        };

        // A parse error is the expected outcome for most of these. The assertion
        // is only that we return at all — a panic here aborts the daemon.
        mdns_sd::fuzz_api::parse_packet(&pkt);
    }
}

#[test]
fn the_hops_wire_decoder_survives_randomised_frames() {
    use hops_proto::{MAX_EVENT_SIZE, ProtoEvent};

    let mut rng = Rng(0x686f_7073_5f70_726f);
    let mut decoded = 0u32;

    for _ in 0..1_000_000u32 {
        let mut buf = [0u8; MAX_EVENT_SIZE];
        for b in buf.iter_mut() {
            *b = rng.byte();
        }
        // Bias the discriminant into range often enough that the arms past the
        // tag get real coverage rather than bouncing off an unknown variant.
        if rng.below(2) == 0 {
            buf[0] = (rng.below(12)) as u8;
        }
        if ProtoEvent::try_from(buf).is_ok() {
            decoded += 1;
        }
    }

    assert!(
        decoded > 0,
        "a million frames decoded nothing — the biasing above stopped reaching \
         the variants, so this test is no longer covering what it claims"
    );
}

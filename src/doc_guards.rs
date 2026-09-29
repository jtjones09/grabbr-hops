//! The public documents state the network facts the code has.
//!
//! A reviewer deciding whether hops may run on a managed machine reads the
//! port, the ALPNs and the discovery service from the docs, not from the
//! source. A default that moves without the docs sends that reviewer to
//! open the wrong port, as the move from 4242 to 4722 would have. There is
//! no behaviour to observe here, so these read the documents' text, and the
//! values they compare against come from the constants the code uses.

use std::path::{Path, PathBuf};

use hops_ipc::{DEFAULT_PORT, PORT_BEFORE_V013};

/// The multicast DNS port. Not a constant in hops: `mdns-sd` owns it.
const MDNS_PORT: u16 = 5353;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// `rel`'s text with Windows line endings made Unix ones, so a checkout
/// that converted them splits into the same paragraphs.
fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
        .replace("\r\n", "\n")
}

/// Every document a user or reviewer is sent to.
fn documents() -> Vec<(String, String)> {
    let mut rels: Vec<String> = [
        "README.md",
        "SECURITY.md",
        "DOC.md",
        "config.example.toml",
        "service/README.md",
    ]
    .map(String::from)
    .to_vec();
    let mut in_docs: Vec<PathBuf> = std::fs::read_dir(root().join("docs"))
        .expect("the docs directory")
        .map(|e| e.expect("a docs entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    in_docs.sort();
    rels.extend(
        in_docs
            .iter()
            .map(|p| format!("docs/{}", p.file_name().unwrap().to_string_lossy())),
    );
    rels.into_iter()
        .map(|r| {
            let text = read(&r);
            (r, text)
        })
        .collect()
}

/// Every number in `text` that could be a port: four or five digits
/// standing alone. Left out, because they cannot be one: a number that
/// begins with `0` (a file mode such as `0600`), a year from 2000 to 2099,
/// and a number joined to a word, a `-` or a `.` and digit (an advisory id
/// such as `RUSTSEC-2026-0285`, a date, a version). A port written in one
/// of those shapes is not read.
fn numbers_in(text: &str) -> Vec<u32> {
    let bytes = text.as_bytes();
    let joined = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let end = bytes[i..]
            .iter()
            .position(|b| !b.is_ascii_digit())
            .map_or(bytes.len(), |n| i + n);
        let before = i.checked_sub(1).map(|j| bytes[j]);
        let after = bytes.get(end).copied();
        let after_next = bytes.get(end + 1).copied();
        let standalone = !before.is_some_and(|b| joined(b) || b == b'.')
            && !after.is_some_and(joined)
            && !(after == Some(b'.') && after_next.is_some_and(|b| b.is_ascii_digit()));
        let digits = &text[i..end];
        if standalone && (4..=5).contains(&digits.len()) && !digits.starts_with('0') {
            let n: u32 = digits.parse().expect("digits");
            if !(2000..=2099).contains(&n) {
                found.push(n);
            }
        }
        i = end;
    }
    found
}

/// Whether `block` says the port it gives is the one before 0.13: it names
/// version 0.12, says "before 0.13" or "before v0.13", or says "old port".
/// Each must stand as its own words, so `0.120` or "threshold port" does not
/// count, and a paragraph about 0.13 alone does not either.
fn says_old_port(block: &str) -> bool {
    let lower = block.to_lowercase();
    let whole = |needle: &str| {
        lower.match_indices(needle).any(|(at, _)| {
            let before = lower[..at].chars().next_back();
            let after = lower[at + needle.len()..].chars().next();
            !before.is_some_and(|c| c.is_alphanumeric() || c == '.')
                && !after.is_some_and(|c| c.is_alphanumeric())
        })
    };
    whole("0.12")
        || whole("v0.12")
        || whole("before 0.13")
        || whole("before v0.13")
        || whole("old port")
}

#[test]
fn every_port_the_docs_give_is_one_hops_uses() {
    let mut wrong = Vec::new();
    for (rel, text) in documents() {
        // The old port may appear only in a paragraph that says it is old.
        let mut start = 0;
        for block in text.split("\n\n") {
            let old_port_said_old = says_old_port(block);
            for (n, line) in block.lines().enumerate() {
                for port in numbers_in(line) {
                    let known = port == u32::from(DEFAULT_PORT)
                        || port == u32::from(MDNS_PORT)
                        || (port == u32::from(PORT_BEFORE_V013) && old_port_said_old)
                        // The local port a 0.12 daemon answers on, which the
                        // Windows upgrade steps look for.
                        || port == u32::from(crate::daemon_start::OLDER_PORT);
                    if !known {
                        wrong.push(format!("{rel}:{}: {port} in {line:?}", start + n + 1));
                    }
                }
            }
            start += block.lines().count() + 1;
        }
    }
    assert!(
        wrong.is_empty(),
        "a document gives a port hops does not use, or gives {PORT_BEFORE_V013} in a \
         paragraph that does not say it is the port before 0.13 (\"0.12\", \"before 0.13\" \
         or \"old port\"). hops listens on {DEFAULT_PORT} (hops_ipc::DEFAULT_PORT). A \
         four- or five-digit number that is not a port can be written as one of the \
         shapes numbers_in leaves out:\n    {}",
        wrong.join("\n    ")
    );
}

#[test]
fn the_network_page_and_the_readme_name_the_default_port() {
    let port = format!("UDP {DEFAULT_PORT}");
    for rel in ["docs/NETWORK.md", "README.md", "docs/MANAGED-MAC.md"] {
        assert!(
            read(rel).contains(&port),
            "{rel} does not say `{port}`, the port hops listens on by default"
        );
    }
}

#[test]
fn the_network_page_names_the_alpns_and_the_discovery_service_the_code_uses() {
    let page = read("docs/NETWORK.md");
    let alpn = std::str::from_utf8(crate::transport::ALPN).expect("ascii");
    let driven = std::str::from_utf8(crate::transport::ALPN_DRIVEN).expect("ascii");
    for (what, value) in [
        ("the ALPN a controlling machine dials with", alpn),
        ("the ALPN a controlled machine dials out with", driven),
        ("the discovery service type", crate::discovery::SERVICE_TYPE),
    ] {
        assert!(
            page.contains(&format!("`{value}`")),
            "docs/NETWORK.md does not name {what}, `{value}`"
        );
    }
    // Any other `grabbr-hop/...` is an ALPN the code does not offer.
    for (rel, text) in documents() {
        for piece in text.split('`').skip(1).step_by(2) {
            assert!(
                !piece.starts_with("grabbr-hop/") || piece == alpn || piece == driven,
                "{rel} names `{piece}`, which is not an ALPN hops offers ({alpn}, {driven})"
            );
        }
    }
}

#[test]
fn the_architecture_page_describes_quic_not_the_pre_fork_tcp_channel() {
    let doc = read("DOC.md").to_lowercase();
    for stale in ["tcp", "udp event", "request server"] {
        assert!(
            !doc.contains(stale),
            "DOC.md says {stale:?}. Every connection between machines is one QUIC link; \
             there is no TCP request server and no separate UDP event channel"
        );
    }
    assert!(doc.contains("quic"), "DOC.md does not say links are QUIC");
}

#[test]
fn numbers_in_reads_every_standalone_number_and_no_id_date_or_mode() {
    assert_eq!(
        numbers_in("UDP 4722, port = 4242. LocalPort 5353, a.local:4723, is 4724; (4725 unless"),
        vec![4722, 4242, 5353, 4723, 4724, 4725]
    );
    assert!(
        numbers_in("RUSTSEC-2026-0285, 2026-09-29, 0600, v0.13.4242, in 2026, port 80, #231")
            .is_empty()
    );
}

#[test]
fn only_a_paragraph_that_calls_the_port_old_may_give_it() {
    for old in [
        "hops 0.12 listens on 4242.",
        "hops before v0.13 used 4242",
        "the old port, 4242",
        "(v0.12.0) 4242",
    ] {
        assert!(says_old_port(old), "{old:?} says the port is old");
    }
    for current in [
        "In hops 0.13, let UDP 4242 in.",
        "An older hops in a new folder, 4242.",
        "hops 0.120 uses 4242",
        "a threshold port 4242",
    ] {
        assert!(
            !says_old_port(current),
            "{current:?} does not say the port is old"
        );
    }
}

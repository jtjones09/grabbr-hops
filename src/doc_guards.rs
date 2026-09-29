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

/// The numbers `text` gives as a port: after `UDP `, `port `, `port = `,
/// `LocalPort ` or a `host:`.
fn ports_in(text: &str) -> Vec<u32> {
    let mut found = Vec::new();
    for lead in ["UDP ", "port ", "port = ", "LocalPort ", ":"] {
        let mut rest = text;
        while let Some(at) = rest.find(lead) {
            rest = &rest[at + lead.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let next = rest[digits.len()..].chars().next();
            if (4..=5).contains(&digits.len()) && !next.is_some_and(|c| c.is_ascii_alphanumeric()) {
                found.push(digits.parse().expect("digits"));
            }
        }
    }
    found
}

#[test]
fn every_port_the_docs_give_is_one_hops_uses() {
    let mut wrong = Vec::new();
    for (rel, text) in documents() {
        // The old port may appear only in a paragraph that says it is old.
        let mut start = 0;
        for block in text.split("\n\n") {
            let old_port_said_old = ["0.12", "0.13", "older"].iter().any(|w| block.contains(w));
            for (n, line) in block.lines().enumerate() {
                for port in ports_in(line) {
                    let known = port == u32::from(DEFAULT_PORT)
                        || port == u32::from(MDNS_PORT)
                        || (port == u32::from(PORT_BEFORE_V013) && old_port_said_old);
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
        "a document gives a port hops does not use, or gives {PORT_BEFORE_V013} without \
         saying it is the port before 0.13. hops listens on {DEFAULT_PORT} \
         (hops_ipc::DEFAULT_PORT):\n    {}",
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
fn ports_in_reads_each_way_a_document_writes_a_port() {
    assert_eq!(
        ports_in("UDP 4722, port = 4242, LocalPort 5353, a.local:4723, UDP:4724"),
        vec![4722, 4242, 5353, 4723, 4724]
    );
    assert!(ports_in("RUSTSEC-2026-0285, 0600, ~/.config, port 80").is_empty());
}

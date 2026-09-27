//! What the app is told when a machine is refused, and how often a stranger
//! can put a pairing prompt in front of it (#171, #101).
//!
//! Runs the built daemon with dummy capture and emulation, discovery off, a
//! free port, and every path it could touch in a scratch directory. Each
//! stranger is a QUIC client with a certificate the daemon has never seen;
//! the desk mac is a QUIC server that refuses every certificate, as a machine
//! that has not approved this one does. The app is read the way any app reads
//! the daemon: over its IPC socket, one JSON event per line, so an event
//! kind this build adds is read as it goes over the wire.
#![cfg(unix)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use hops_ipc::{DaemonEndpoint, FrontendRequest, Position};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// An app reading the daemon's events as they go over the wire, and sending
/// its requests on the same connection. One connection: the daemon closes an
/// app that stops reading, so a second, unread one would be closed under it.
struct App {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    tx: tokio::net::unix::OwnedWriteHalf,
    /// Every event read so far, oldest first.
    seen: Vec<Value>,
}

impl App {
    async fn connect() -> App {
        let DaemonEndpoint::Unix(path) = DaemonEndpoint::of_this_platform().expect("endpoint")
        else {
            unreachable!("a unix socket")
        };
        let token = hops_ipc::token::read().expect("the token");
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .expect("the daemon's socket");
        let (rx, mut tx) = stream.into_split();
        let mut rx = BufReader::new(rx);
        hops_ipc::prove_to_daemon(&mut rx, &mut tx, &token)
            .await
            .expect("the two-way proof is made");
        App {
            lines: rx.lines(),
            tx,
            seen: Vec::new(),
        }
    }

    async fn request(&mut self, request: FrontendRequest) {
        let mut line = serde_json::to_string(&request).expect("a request encodes");
        line.push('\n');
        self.tx
            .write_all(line.as_bytes())
            .await
            .expect("the request is sent");
    }

    /// Read events until one `pick` accepts, for at most `within`.
    async fn until<T>(
        &mut self,
        within: Duration,
        pick: impl Fn(&Value) -> Option<T>,
    ) -> Option<T> {
        let deadline = tokio::time::Instant::now() + within;
        while let Ok(Ok(Some(line))) =
            tokio::time::timeout_at(deadline, self.lines.next_line()).await
        {
            let Ok(event) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let found = pick(&event);
            self.seen.push(event);
            if found.is_some() {
                return found;
            }
        }
        None
    }

    /// The text of every event of `kind` read so far.
    fn texts(&self, kind: &str) -> Vec<String> {
        self.seen
            .iter()
            .filter_map(|e| e.get(kind).and_then(Value::as_str).map(str::to_owned))
            .collect()
    }

    /// Pairing prompts read so far, as (fingerprint, origin).
    fn prompts(&self) -> Vec<(String, String)> {
        self.seen
            .iter()
            .filter_map(|e| e.get("ConnectionAttempt"))
            .map(|a| {
                (
                    a["fingerprint"].as_str().unwrap_or_default().to_owned(),
                    a["origin"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect()
    }
}

/// The text of `event` if it is of `kind` and `want` accepts it.
fn text_of(event: &Value, kind: &str, want: impl Fn(&str) -> bool) -> Option<String> {
    event
        .get(kind)
        .and_then(Value::as_str)
        .filter(|t| want(t))
        .map(str::to_owned)
}

/// Refuses every certificate, as a machine that has not approved this one.
#[derive(Debug)]
struct RefuseEveryone;

impl ClientCertVerifier for RefuseEveryone {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Err(rustls::Error::General(
            "no lease permits that sender".into(),
        ))
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The desk mac: answers dials on 127.0.0.1 as `me`, and refuses every
/// dialler's certificate. Returns its port.
fn refusing_receiver(me: &common::Identity) -> u16 {
    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(RefuseEveryone))
        .with_single_cert(vec![me.cert.clone()], me.key.clone_key())
        .expect("server cert");
    crypto.alpn_protocols = vec![b"grabbr-hop/1".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic server"),
    ));
    let endpoint =
        quinn::Endpoint::server(config, "127.0.0.1:0".parse().expect("addr")).expect("endpoint");
    let port = endpoint.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await;
            });
        }
    });
    port
}

// LEDGER T2377 | class B | 2 bytes (IPC events) from the built daemon, peers over loopback QUIC
#[tokio::test(flavor = "current_thread")]
async fn refusals_reach_the_app_as_errors_or_activity_and_a_stranger_prompts_once_per_address() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let paired = common::Identity::new();
    let (daemon, port) = common::start(
        "h-refuse",
        &format!(
            "[authorized_fingerprints]\n\"{}\" = \"sentinel\"\n",
            paired.fingerprint()
        ),
    );
    let mut app = App::connect().await;
    // Every property is checked and reported together, so one run says which
    // of them hold rather than stopping at the first.
    let mut failures: Vec<String> = Vec::new();

    // 1. A stranger knocks while add device is closed: refused, and the app's
    // activity log says so. Nobody here asked, so it is not an error.
    let _ = common::Identity::new().dial(port).await;
    let refused = app
        .until(Duration::from_secs(10), |e| {
            text_of(e, "Activity", |t| {
                t.starts_with("Refused a connection from 127.0.0.1")
            })
        })
        .await;
    if refused.is_none() {
        failures.push(format!(
            "1: a stranger refused while add device was closed never reached the app's \
             activity; activity: {:?}",
            app.texts("Activity")
        ));
    }
    if !app.texts("Error").is_empty() {
        failures.push(format!(
            "1: a background refusal raised an error: {:?}",
            app.texts("Error")
        ));
    }

    // 2. With add device open, a stranger minting a key per knock from one
    // address raises one prompt, not one per knock. The paired machine's
    // connection, made after every knock, marks when they have all been
    // handled.
    app.request(FrontendRequest::OpenPairing).await;
    let _ = app
        .until(Duration::from_secs(10), |e| {
            e.get("PairingOpen").map(|_| ())
        })
        .await;
    let before = app.prompts().len();
    const KNOCKS: usize = 20;
    for _ in 0..KNOCKS {
        let _ = common::Identity::new().dial(port).await;
    }
    let sentinel = paired.fingerprint();
    let (_link_ep, _link) = paired
        .dial(port)
        .await
        .unwrap_or_else(|| panic!("the paired machine was refused; log:\n{}", daemon.log()));
    let marked = app
        .until(Duration::from_secs(20), |e| {
            (e.get("DeviceConnected")?.get("fingerprint")?.as_str()? == sentinel).then_some(())
        })
        .await;
    let prompts = app.prompts().len() - before;
    if marked.is_none() {
        failures.push("2: the paired machine's connection never reached the app".into());
    } else if prompts != 1 {
        failures.push(format!(
            "2: {KNOCKS} knocks with fresh keys from one address raised {prompts} prompts; \
             one is the most an address may raise at a time"
        ));
    }

    // 3. Adding the desk mac, which has not approved this machine. Approving
    // it here is half a pairing; its refusal of this machine is expected
    // while it is being added, so it is activity that says what to do there,
    // never an error.
    let desk = common::Identity::new();
    let desk_port = refusing_receiver(&desk);
    app.request(FrontendRequest::Create).await;
    let handle = app
        .until(Duration::from_secs(10), |e| {
            e.get("Created")?.get(0)?.as_u64()
        })
        .await
        .expect("the new device is created") as hops_ipc::ClientHandle;
    for request in [
        FrontendRequest::UpdateFixIps(handle, vec!["127.0.0.1".parse().expect("ip")]),
        FrontendRequest::UpdatePort(handle, desk_port),
        FrontendRequest::UpdatePosition(handle, Position::Left),
        FrontendRequest::OpenPairing,
        FrontendRequest::Activate(handle, true),
    ] {
        app.request(request).await;
    }
    let desk_fp = desk.fingerprint();
    let prompted = app
        .until(Duration::from_secs(20), |e| {
            let a = e.get("ConnectionAttempt")?;
            (a["fingerprint"].as_str()? == desk_fp && a["origin"].as_str()? == "OutboundDial")
                .then_some(())
        })
        .await;
    if prompted.is_none() {
        failures.push(format!(
            "3: adding the desk mac never offered to pair it; prompts: {:?}",
            app.prompts()
        ));
    } else {
        app.request(FrontendRequest::AuthorizeKey {
            label: "desk mac".into(),
            fingerprint: desk_fp.clone(),
            controller: hops_ipc::Controller::ThisMachine,
            clipboard: false,
        })
        .await;
        let waiting = app
            .until(Duration::from_secs(20), |e| {
                text_of(e, "Activity", |t| t.starts_with("Waiting for desk mac"))
            })
            .await;
        match waiting {
            None => failures.push(format!(
                "3: the desk mac refused this machine while it was being added, and the \
                 app was not told; activity: {:?}",
                app.texts("Activity")
            )),
            Some(text) if !text.contains("open add device on desk mac") => failures.push(format!(
                "3: the notice does not say what to do on the desk mac: {text:?}"
            )),
            Some(_) => {}
        }
        let errors: Vec<String> = app
            .texts("Error")
            .into_iter()
            .filter(|t| t.contains("desk mac"))
            .collect();
        if !errors.is_empty() {
            failures.push(format!(
                "3: a refusal expected while adding raised an error: {errors:?}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} propert(ies) failed:\n{}\nlog:\n{}",
        failures.len(),
        failures.join("\n"),
        daemon.log()
    );
}

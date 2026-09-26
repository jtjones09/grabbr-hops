//! Two machines in one test process, talking over loopback QUIC.
//!
//! Everything here is the production code path except the device ends: the
//! receiver injects into [`input_emulation::recording::Recording`] and the
//! sender captures from [`input_capture::scripted::Script`]. The listener binds
//! 127.0.0.1 on a port the OS picks, so a test neither listens on the network
//! nor collides with a daemon running on the same machine. No test here reads
//! or writes the real config, token or trust files.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, RwLock},
    time::Duration,
};

use hops_ipc::{ClientHandle, Position};
use hops_proto::ProtoEvent;
use local_channel::mpsc::{Receiver, channel};

use crate::{
    client::ClientManager,
    connect::LanMouseConnection,
    crypto::Identity,
    transport::{self, Trust},
    trust::{Caps, TrustStore},
};

/// Run `f` the way the daemon runs: one thread, inside a `LocalSet`.
pub(crate) fn run_local<F: Future>(f: F) -> F::Output {
    transport::install_crypto_provider();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&rt, f)
}

/// One machine's identity.
pub(crate) struct Machine {
    pub(crate) identity: Arc<Identity>,
    pub(crate) fingerprint: String,
}

pub(crate) fn machine() -> Machine {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let mut params = rcgen::CertificateParams::new(vec!["grabbr".to_owned()]).expect("params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "grabbr-hop");
    let cert = params.self_signed(&key_pair).expect("self signed");
    let identity = Identity {
        cert: cert.der().clone(),
        key: rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).expect("key der"),
    };
    let fingerprint = transport::fingerprint_of(&identity.cert);
    Machine {
        identity: Arc::new(identity),
        fingerprint,
    }
}

/// `us`'s store, granting each of `peers` exactly `caps` and nothing else.
pub(crate) fn trust(us: &Machine, peers: &[&Machine], caps: Caps) -> Trust {
    let mut store = TrustStore::new(&us.fingerprint, 0).expect("our fingerprint");
    for peer in peers {
        store.issue(&peer.fingerprint, "peer", caps).expect("issue");
    }
    Arc::new(RwLock::new(store))
}

/// A client config for a test that dials the listener itself, with a stream
/// receive window it chooses.
///
/// The real dialler's window is far larger than a test can fill, and a test
/// about a peer that stops reading has to fill one.
pub(crate) fn raw_client_config(
    me: &Machine,
    trust: Trust,
    stream_window: u32,
) -> quinn::ClientConfig {
    let verifier = Arc::new(transport::FpServerVerifier::new(
        trust,
        Arc::new(std::sync::Mutex::new(None)),
    ));
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![me.identity.cert.clone()], me.identity.key.clone_key())
        .expect("client auth");
    crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic client"),
    ));
    let mut transport_config = quinn::TransportConfig::default();
    // MUST be > 0 or the receiver's reply stream is never accepted.
    transport_config.max_concurrent_uni_streams(8u8.into());
    transport_config.stream_receive_window(stream_window.into());
    config.transport_config(Arc::new(transport_config));
    config
}

/// Poll `look` until it answers, and give that answer; panic naming `what` if
/// it does not within `limit`.
pub(crate) async fn wait_for<T, F: Future<Output = Option<T>>>(
    what: &str,
    limit: Duration,
    mut look: impl FnMut() -> F,
) -> T {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if let Some(found) = look().await {
            return found;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Poll `done` until it holds; panic naming `what` if it does not within `limit`.
pub(crate) async fn wait_until(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let started = tokio::time::Instant::now();
    while !done() {
        assert!(
            started.elapsed() < limit,
            "timed out after {limit:?} waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The dialling half: one active client at 127.0.0.1:`port`, and the real
/// connection that dials it on first send.
pub(crate) struct Dialer {
    pub(crate) conn: LanMouseConnection,
    pub(crate) clients: ClientManager,
    pub(crate) handle: ClientHandle,
    /// Where the connection's notifications go. Keep it alive for as long as
    /// the connection is.
    pub(crate) notices: Notices,
}

pub(crate) struct Notices {
    /// Clipboard text this machine's transport received and queued for the
    /// service.
    pub(crate) clipboard: Receiver<crate::transport::PeerClipboard>,
    _untrusted: Receiver<(String, std::net::SocketAddr)>,
    _persist: Receiver<ClientHandle>,
    _state: Receiver<ClientHandle>,
}

pub(crate) fn dialer(me: &Machine, trust: Trust, port: u16, pos: Position) -> Dialer {
    let clients = ClientManager::default();
    let handle = clients.add_client();
    clients.set_fix_ips(handle, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    clients.set_port(handle, port);
    clients.set_pos(handle, pos);
    clients.activate_client(handle);
    let (clipboard_tx, clipboard) = channel();
    let (untrusted_tx, untrusted) = channel();
    let (persist_tx, persist) = channel();
    let (state_tx, state) = channel();
    let conn = LanMouseConnection::new(
        me.identity.clone(),
        clients.clone(),
        trust,
        clipboard_tx,
        untrusted_tx,
        persist_tx,
        state_tx,
    )
    .expect("client endpoint");
    Dialer {
        conn,
        clients,
        handle,
        notices: Notices {
            clipboard,
            _untrusted: untrusted,
            _persist: persist,
            _state: state,
        },
    }
}

impl Dialer {
    /// Dial, and wait until the receiver has answered that it is injecting.
    pub(crate) async fn until_alive(&self) {
        let limit = Duration::from_secs(20);
        let started = tokio::time::Instant::now();
        while !self.clients.alive(self.handle) {
            assert!(
                started.elapsed() < limit,
                "the receiver never reported emulation active within {limit:?}"
            );
            // The first send starts the dial; the ones after it return
            // NotConnected or TargetEmulationDisabled until the Pong lands.
            let _ = self.conn.send(ProtoEvent::Ping, self.handle).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Send one event, which must reach the wire.
    pub(crate) async fn send(&self, event: ProtoEvent) {
        self.conn
            .send(event, self.handle)
            .await
            .unwrap_or_else(|e| panic!("sending {event}: {e}"));
    }
}

/// Two paired machines with a link up between them: `driver` dialled
/// `driven`, as a pairing's first crossing does. Each end's clipboard
/// broadcast is the production one, and each end's queue is what its
/// transport handed on towards the service.
pub(crate) struct ClipboardPair {
    pub(crate) driven: Machine,
    pub(crate) driven_trust: Trust,
    pub(crate) driven_sends: crate::listen::ClipboardSenderListen,
    /// What the driven machine's transport queued for its service.
    pub(crate) driven_heard: Receiver<crate::transport::PeerClipboard>,
    _listener: crate::listen::LanMouseListener,
    pub(crate) driver: Machine,
    pub(crate) driver_trust: Trust,
    pub(crate) driver_sends: crate::connect::ClipboardSender,
    pub(crate) dialer: Dialer,
}

/// [`ClipboardPair`], each machine holding the store given for it.
pub(crate) async fn clipboard_pair(
    driven: Machine,
    driven_store: TrustStore,
    driver: Machine,
    driver_store: TrustStore,
) -> ClipboardPair {
    use futures::StreamExt;
    let driven_trust: Trust = Arc::new(RwLock::new(driven_store));
    let driver_trust: Trust = Arc::new(RwLock::new(driver_store));
    let (heard_tx, driven_heard) = channel();
    let (mut listener, port) = crate::listen::LanMouseListener::bind_loopback(
        driven.identity.clone(),
        driven_trust.clone(),
        heard_tx,
    )
    .await
    .expect("listener");
    let driven_sends = listener.clipboard_sender();
    let dialer = dialer(&driver, driver_trust.clone(), port, Position::Left);
    dialer.conn.dial(dialer.handle).await;
    let accepted = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = listener.next().await {
            if let crate::listen::ListenEvent::Accept { .. } = event {
                return true;
            }
        }
        false
    })
    .await;
    assert!(
        matches!(accepted, Ok(true)),
        "the driven machine never accepted the driver's link"
    );
    wait_until(
        "the driver to hold its link",
        Duration::from_secs(10),
        || dialer.conn.active_addr(dialer.handle).is_some(),
    )
    .await;
    let driver_sends = dialer.conn.clipboard_sender();
    ClipboardPair {
        driven,
        driven_trust,
        driven_sends,
        driven_heard,
        _listener: listener,
        driver,
        driver_trust,
        driver_sends,
        dialer,
    }
}

/// How long a test waits for text that must arrive.
pub(crate) const ARRIVES_WITHIN: Duration = Duration::from_secs(5);
/// How long a test waits before concluding text that must not arrive did not.
/// Loopback delivers in well under a millisecond.
pub(crate) const NEVER_WITHIN: Duration = Duration::from_secs(1);

/// The next item on `rx`, or `None` if nothing came within `limit`.
pub(crate) async fn next_within<T>(rx: &mut Receiver<T>, limit: Duration) -> Option<T> {
    tokio::time::timeout(limit, rx.recv()).await.ok().flatten()
}

/// The text of the next transfer queued on `rx`, and whose it says it is.
pub(crate) async fn heard_within(
    rx: &mut Receiver<crate::transport::PeerClipboard>,
    limit: Duration,
) -> Option<(String, String)> {
    next_within(rx, limit).await.map(|c| (c.text, c.from))
}

impl ClipboardPair {
    /// Each machine's queue behind the check the service makes before it
    /// applies text, driven machine first. Takes the queues: what the
    /// transports hand on is then only seen through the check.
    pub(crate) fn inboxes(
        &mut self,
    ) -> (
        crate::clipboard::ClipboardInbox,
        crate::clipboard::ClipboardInbox,
    ) {
        let driven = std::mem::replace(&mut self.driven_heard, channel().1);
        let driver = std::mem::replace(&mut self.dialer.notices.clipboard, channel().1);
        (
            crate::clipboard::ClipboardInbox::new(driven, self.driven_trust.clone()),
            crate::clipboard::ClipboardInbox::new(driver, self.driver_trust.clone()),
        )
    }
}

/// The next text `inbox` lets through, or `None` if nothing did within `limit`.
pub(crate) async fn applied_within(
    inbox: &mut crate::clipboard::ClipboardInbox,
    limit: Duration,
) -> Option<String> {
    tokio::time::timeout(limit, inbox.next())
        .await
        .ok()
        .flatten()
}

/// What reached the log from this thread, for a test about what the log says.
///
/// One logger for the whole test binary, installed once: `log` takes a global
/// logger and refuses a second one. It keeps the records of a thread holding a
/// [`LogCapture`] and drops everyone else's, so tests running in parallel do
/// not see each other's lines. [`run_local`] runs a whole two-machine session
/// on the test's own thread, so that thread sees all of it.
pub(crate) mod logs {
    use std::cell::RefCell;
    use std::marker::PhantomData;
    use std::net::SocketAddr;
    use std::sync::Once;

    use input_event::scancode;

    /// One record, as the daemon's own log would carry it.
    #[derive(Clone, Debug)]
    pub(crate) struct Line {
        pub(crate) level: log::Level,
        pub(crate) target: String,
        pub(crate) text: String,
    }

    impl Line {
        /// From one of hops' own crates rather than a dependency. A bare
        /// `HOPS_LOG_LEVEL` raises only these; dependencies stay at `warn`.
        pub(crate) fn is_ours(&self) -> bool {
            let crate_name = self.target.split("::").next().unwrap_or_default();
            crate_name == "hops"
                || crate_name.starts_with("hops_")
                || crate_name.starts_with("input_")
        }
    }

    thread_local! {
        static LINES: RefCell<Option<Vec<Line>>> = const { RefCell::new(None) };
    }

    struct ToTheCapturingThread;

    impl log::Log for ToTheCapturingThread {
        fn enabled(&self, _: &log::Metadata) -> bool {
            LINES.try_with(|l| l.borrow().is_some()).unwrap_or(false)
        }

        fn log(&self, record: &log::Record) {
            if !self.enabled(record.metadata()) {
                return;
            }
            // Formatted before the borrow: a Display impl that logs must not
            // find the buffer already borrowed.
            let line = Line {
                level: record.level(),
                target: record.target().to_owned(),
                text: record.args().to_string(),
            };
            let _ = LINES.try_with(|l| {
                if let Some(lines) = l.borrow_mut().as_mut() {
                    lines.push(line);
                }
            });
        }

        fn flush(&self) {}
    }

    static INSTALL: Once = Once::new();

    /// Records this thread's log lines, at every level, until dropped.
    pub(crate) struct LogCapture {
        /// Bound to the thread whose lines it holds.
        _here: PhantomData<*const ()>,
    }

    /// Start keeping this thread's log lines, at trace and above.
    pub(crate) fn capture() -> LogCapture {
        INSTALL.call_once(|| {
            log::set_boxed_logger(Box::new(ToTheCapturingThread))
                .expect("another logger is installed in this test binary");
            log::set_max_level(log::LevelFilter::Trace);
        });
        LINES.with(|l| *l.borrow_mut() = Some(Vec::new()));
        LogCapture { _here: PhantomData }
    }

    impl LogCapture {
        /// Every line so far, oldest first.
        pub(crate) fn lines(&self) -> Vec<Line> {
            LINES.with(|l| l.borrow().clone().unwrap_or_default())
        }

        /// Lines from hops' own crates that name `key`: its scancode name, or
        /// its number anywhere a number stands alone.
        pub(crate) fn naming(&self, key: scancode::Linux) -> Vec<Line> {
            self.lines()
                .into_iter()
                .filter(|l| l.is_ours() && names_key(&l.text, key))
                .collect()
        }
    }

    impl Drop for LogCapture {
        fn drop(&mut self) {
            let _ = LINES.try_with(|l| *l.borrow_mut() = None);
        }
    }

    /// Whether `text` identifies `key`, by name or by number.
    ///
    /// By number means a run of digits equal to the key's code, or a `0x`
    /// hex number equal to it. Addresses,
    /// fingerprints and hex such as a build commit carry digit runs that are
    /// not keys, so they are set aside first; otherwise a port or a
    /// fingerprint byte that happens to read `30` would look like `KEY_A`.
    pub(crate) fn names_key(text: &str, key: scancode::Linux) -> bool {
        if text.contains(&format!("{key:?}")) {
            return true;
        }
        let code = key as u32;
        let tokens = || text.split(|c: char| c.is_whitespace() || "()[]{},;\"'<>=".contains(c));
        let in_hex = tokens().any(|token| {
            let token = token.to_ascii_lowercase();
            token.match_indices("0x").any(|(at, _)| {
                let digits: String = token[at + 2..]
                    .chars()
                    .take_while(char::is_ascii_hexdigit)
                    .collect();
                u32::from_str_radix(&digits, 16) == Ok(code)
            })
        });
        let code = code.to_string();
        in_hex
            || tokens()
                .filter(|token| !carries_other_numbers(token))
                .flat_map(|token| token.split(|c: char| !c.is_ascii_digit()))
                .any(|run| run == code)
    }

    fn carries_other_numbers(token: &str) -> bool {
        let hex_pairs = token.contains(':')
            && token
                .split(':')
                .all(|b| b.len() == 2 && b.chars().all(|c| c.is_ascii_hexdigit()));
        let hex_word = token.chars().all(|c| c.is_ascii_hexdigit())
            && token.chars().any(|c| c.is_ascii_alphabetic());
        token.parse::<SocketAddr>().is_ok() || hex_pairs || hex_word
    }

    #[test]
    fn a_key_is_found_by_name_and_by_number_and_nothing_else_is() {
        let a = scancode::Linux::KeyA; // 30
        assert!(names_key("key(KeyA, 1)", a));
        assert!(names_key("key(30, 1)", a));
        assert!(names_key("Key { time: 0, key: 30, state: 1 }", a));
        assert!(names_key("releasing stuck key: 30", a));
        assert!(names_key("key(0x1e, 0)", a));
        assert!(names_key("key: 0X001E", a));
        for other in [
            "key(<hidden>, 1) <-<-<-<-<- 127.0.0.1:53012",
            "peer 30:1e:19:1b:c4:a8:40:f5:26:37:39:9d:c7:c7:75:fe:17:4f:03:d5:a9:76:49:cd:b1:12:d1:2f:6c:1f:d2:22",
            "Hello(a30f1b2c)",
            "button(left, 1) 0x130",
            "releasing 1 stuck key(s)",
        ] {
            assert!(!names_key(other, a), "{other:?} does not name KeyA");
        }
    }
}

/// A receiver that answers dials only when told to, then records what
/// happens to each connection: how many streams the dialler opened on it and
/// whether it was closed.
///
/// Holding the handshake is what puts a dial "in flight" for as long as a
/// test needs: the dialler has read the device's address and is waiting, and
/// the test can change the device before letting the dial land.
pub(crate) struct Door {
    pub(crate) port: u16,
    knocks: std::rc::Rc<std::cell::Cell<u32>>,
    open: std::rc::Rc<std::cell::Cell<bool>>,
    streams: std::rc::Rc<std::cell::Cell<u32>>,
    closed: std::rc::Rc<std::cell::Cell<u32>>,
}

impl Door {
    /// Dials that have reached the door, answered or not.
    pub(crate) fn knocks(&self) -> u32 {
        self.knocks.get()
    }

    /// Let every dial in, now and from here on.
    pub(crate) fn open(&self) {
        self.open.set(true);
    }

    /// Streams the dialler has opened across every connection. The first on
    /// each connection carries input; any after it carries clipboard text.
    pub(crate) fn streams(&self) -> u32 {
        self.streams.get()
    }

    /// Connections that have been closed, by either end.
    pub(crate) fn closed(&self) -> u32 {
        self.closed.get()
    }
}

/// `me` behind a [`Door`] on 127.0.0.1, shut until [`Door::open`].
pub(crate) fn door(me: &Machine) -> Door {
    use std::{cell::Cell, rc::Rc};
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![me.identity.cert.clone()], me.identity.key.clone_key())
        .expect("server cert");
    crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic server"),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().expect("addr"))
        .expect("server endpoint");
    let port = endpoint.local_addr().expect("local addr").port();
    let door = Door {
        port,
        knocks: Rc::new(Cell::new(0)),
        open: Rc::new(Cell::new(false)),
        streams: Rc::new(Cell::new(0)),
        closed: Rc::new(Cell::new(0)),
    };
    let (knocks, open, streams, closed) = (
        door.knocks.clone(),
        door.open.clone(),
        door.streams.clone(),
        door.closed.clone(),
    );
    tokio::task::spawn_local(async move {
        while let Some(incoming) = endpoint.accept().await {
            knocks.set(knocks.get() + 1);
            let (open, streams, closed) = (open.clone(), streams.clone(), closed.clone());
            tokio::task::spawn_local(async move {
                while !open.get() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let Ok(conn) = incoming.await else { return };
                let counted = streams.clone();
                let accepting = conn.clone();
                tokio::task::spawn_local(async move {
                    while let Ok(mut recv) = accepting.accept_uni().await {
                        counted.set(counted.get() + 1);
                        tokio::task::spawn_local(async move {
                            let _ = recv.read_to_end(usize::MAX).await;
                        });
                    }
                });
                conn.closed().await;
                closed.set(closed.get() + 1);
            });
        }
    });
    door
}

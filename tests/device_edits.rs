//! Editing or removing one device changes that device and nothing else
//! (#94, #97), and removing a connected device closes its link.
//!
//! Runs the built binary with dummy capture and emulation, discovery off, and
//! every path it could touch in a scratch directory. The frontend is the real
//! IPC connector. A receiver is a QUIC server whose certificate the daemon's
//! config already trusts, so the daemon dials it as soon as the dummy capture
//! crosses to it: that backend crosses at the left edge only, continuously.
//!
//! The tests take turns: the frontend finds the daemon's socket and token
//! through the environment, which is process-wide.
#![cfg(unix)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{
    AsyncFrontendEventReader, AsyncFrontendRequestWriter, ClientConfig, ClientState, FrontendEvent,
    FrontendRequest,
};
use sha2::{Digest, Sha256};

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

struct Daemon {
    child: Child,
    dir: PathBuf,
    config: PathBuf,
    log: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Daemon {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Start a daemon on `config`, with `{port}` replaced by its listen port.
    fn start(tag: &str, config: &str) -> Daemon {
        // Short, for `sun_path` (about 104 bytes on macOS), and resolved: on
        // macOS /tmp is a link, and the config watcher matches the path the
        // filesystem reports, which is the resolved one.
        let dir = PathBuf::from(format!("/tmp/h-ed{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let dir = std::fs::canonicalize(&dir).expect("the scratch directory resolves");
        let config_dir = dir.join(".config/lan-mouse");
        std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
        std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
        // SAFETY: the tests in this binary hold ONE_AT_A_TIME, and set these
        // before anything that reads the environment.
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::set_var("XDG_RUNTIME_DIR", &dir);
            std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
        }
        let port = UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .expect("a free port")
            .port();
        let config_path = config_dir.join("config.toml");
        std::fs::write(&config_path, config.replace("{port}", &port.to_string()))
            .expect("a config");
        let log = dir.join("daemon.log");
        let child = Command::new(env!("CARGO_BIN_EXE_hops"))
            .arg("--config")
            .arg(&config_path)
            .arg("--cert-path")
            .arg(config_dir.join("lan-mouse.pem"))
            .arg("daemon")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &dir)
            .env("XDG_RUNTIME_DIR", &dir)
            .env("XDG_CONFIG_HOME", dir.join(".config"))
            .env("XDG_STATE_HOME", &dir)
            .env("HOPS_LOG_FILE", &log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the hops binary starts");
        let daemon = Daemon {
            child,
            dir,
            config: config_path,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        while !daemon.log().contains("service running; stops on") {
            assert!(
                Instant::now() < deadline,
                "the daemon never reported its service loop running; log:\n{}",
                daemon.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        daemon
    }
}

const DUMMY: &str = "port = {port}\ncapture_backend = \"dummy\"\n\
                     emulation_backend = \"dummy\"\ndiscovery = false\n";

/// A machine the daemon's config trusts and dials: a QUIC server that counts
/// the connections it accepts and the ones that are closed.
struct Receiver {
    port: u16,
    fingerprint: String,
    accepted: Rc<Cell<u32>>,
    closed: Rc<Cell<u32>>,
}

impl Receiver {
    fn start() -> Receiver {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let cert = rcgen::CertificateParams::new(vec!["grabbr".to_owned()])
            .expect("params")
            .self_signed(&key)
            .expect("self signed");
        let fingerprint = Sha256::digest(cert.der().as_ref())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).expect("key der"),
            )
            .expect("server cert");
        crypto.alpn_protocols = vec![b"grabbr-hop/1".to_vec()];
        let cfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic server"),
        ));
        let ep =
            quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().expect("addr")).expect("server");
        let port = ep.local_addr().expect("local addr").port();
        let accepted = Rc::new(Cell::new(0));
        let closed = Rc::new(Cell::new(0));
        let (a, c) = (accepted.clone(), closed.clone());
        tokio::task::spawn_local(async move {
            while let Some(incoming) = ep.accept().await {
                let (a, c) = (a.clone(), c.clone());
                tokio::task::spawn_local(async move {
                    let Ok(conn) = incoming.await else { return };
                    a.set(a.get() + 1);
                    conn.closed().await;
                    c.set(c.get() + 1);
                });
            }
        });
        Receiver {
            port,
            fingerprint,
            accepted,
            closed,
        }
    }

    /// A config with one device at the left edge pointing at this receiver,
    /// switched on and trusted in both directions, as an upgrade from a
    /// build that had dialled it leaves it.
    fn config(&self) -> String {
        format!(
            "{DUMMY}\n[[clients]]\nhostname = \"127.0.0.1\"\nips = [\"127.0.0.1\"]\n\
             port = {}\nposition = \"left\"\nactivate_on_startup = true\n\
             fingerprint = \"{fp}\"\n\n[authorized_fingerprints]\n\"{fp}\" = \"receiver\"\n",
            self.port,
            fp = self.fingerprint,
        )
    }
}

struct Frontend {
    events: AsyncFrontendEventReader,
    requests: AsyncFrontendRequestWriter,
}

type Devices = BTreeMap<u64, (ClientConfig, ClientState)>;

impl Frontend {
    async fn attach() -> Frontend {
        let (events, requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
            .await
            .expect("a frontend connects");
        Frontend { events, requests }
    }

    async fn send(&mut self, request: FrontendRequest) {
        self.requests.request(request).await.expect("request sent");
    }

    /// The next event `pick` accepts, skipping the rest.
    async fn next<T>(&mut self, what: &str, mut pick: impl FnMut(FrontendEvent) -> Option<T>) -> T {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            match tokio::time::timeout_at(deadline, self.events.next()).await {
                Ok(Some(Ok(event))) => {
                    if let Some(found) = pick(event) {
                        return found;
                    }
                }
                other => panic!("no {what} from the daemon: {other:?}"),
            }
        }
    }

    /// The device list as the daemon has it now.
    ///
    /// Events carry no request id, and the daemon also publishes the list
    /// unasked (on attach, on a reload). The daemon answers in order, so the
    /// answer to this request is the last list to arrive before it goes quiet.
    async fn devices(&mut self) -> Devices {
        self.send(FrontendRequest::Enumerate()).await;
        let mut last = self
            .next("device list", |e| match e {
                FrontendEvent::Enumerate(list) => Some(list),
                _ => None,
            })
            .await;
        while let Ok(Some(Ok(event))) =
            tokio::time::timeout(Duration::from_millis(500), self.events.next()).await
        {
            if let FrontendEvent::Enumerate(list) = event {
                last = list;
            }
        }
        last.into_iter().map(|(h, c, s)| (h, (c, s))).collect()
    }
}

fn handle_named(devices: &Devices, name: &str) -> u64 {
    devices
        .iter()
        .find(|(_, (c, _))| c.hostname.as_deref() == Some(name))
        .map(|(h, _)| *h)
        .unwrap_or_else(|| panic!("no device named {name}: {devices:?}"))
}

fn names(devices: &Devices) -> Vec<String> {
    let mut v: Vec<String> = devices
        .values()
        .filter_map(|(c, _)| c.hostname.clone())
        .collect();
    v.sort();
    v
}

async fn until(what: &str, limit: Duration, done: impl Fn() -> bool) -> bool {
    let started = tokio::time::Instant::now();
    while !done() {
        if started.elapsed() > limit {
            let _ = what;
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

fn local(test: impl std::future::Future<Output = ()>) {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&rt, test);
}

/// A daemon connected to a receiver, and a frontend attached to it.
async fn connected(tag: &str) -> (Daemon, Receiver, Frontend, u64) {
    let receiver = Receiver::start();
    let daemon = Daemon::start(tag, &receiver.config());
    let mut frontend = Frontend::attach().await;
    let up = until("the daemon to dial", Duration::from_secs(20), || {
        receiver.accepted.get() > 0
    })
    .await;
    assert!(
        up,
        "the daemon never dialled its receiver; log:\n{}",
        daemon.log()
    );
    let handle = handle_named(&frontend.devices().await, "127.0.0.1");
    (daemon, receiver, frontend, handle)
}

// LEDGER T8 | class B | 2 connection closed at a real QUIC receiver, dialled by the hops binary
/// Deleting a device the daemon is connected to closes that connection. It
/// used to stay open: the device was removed before the task that closes its
/// connection looked up the device's address, so the task found none, and
/// clipboard text kept going to the removed machine.
#[test]
fn deleting_a_connected_device_closes_its_link() {
    local(async {
        let (daemon, receiver, mut frontend, handle) = connected("1").await;

        frontend
            .send(FrontendRequest::Delete {
                handle,
                fingerprint: Some(receiver.fingerprint.clone()),
            })
            .await;

        let closed = until("the link to close", Duration::from_secs(5), || {
            receiver.closed.get() > 0
        })
        .await;
        assert!(
            closed,
            "the device was deleted and its connection is still open; log:\n{}",
            daemon.log()
        );
    });
}

// LEDGER T9 | class B | 2 connection closed at a real QUIC receiver, dialled by the hops binary
/// The same after the device's address was edited while it was connected,
/// which clears its pin: the delete then revokes nothing, and closing the
/// link is left to the removal alone.
#[test]
fn deleting_a_connected_device_after_an_address_edit_closes_its_link() {
    local(async {
        let (daemon, receiver, mut frontend, handle) = connected("2").await;
        frontend
            .send(FrontendRequest::UpdateFixIps(
                handle,
                vec!["192.0.2.1".parse().expect("ip")],
            ))
            .await;

        // The edit cleared the pin, and the row shows none.
        frontend
            .send(FrontendRequest::Delete {
                handle,
                fingerprint: None,
            })
            .await;

        let closed = until("the link to close", Duration::from_secs(5), || {
            receiver.closed.get() > 0
        })
        .await;
        assert!(
            closed,
            "the device was re-addressed then deleted, and its connection to \
             the old address is still open; log:\n{}",
            daemon.log()
        );
    });
}

// LEDGER T10 | class B | 2 connection closed at a real QUIC receiver, dialled by the hops binary
/// Revoking a machine closes every connection to it, found by the identity the
/// connection proved rather than by which device last recorded it.
///
/// The device is switched off first. Switching off leaves the connection
/// open, and nothing is sent on it, so nothing else notices the revocation.
#[test]
fn revoking_a_connected_machine_after_an_address_edit_closes_its_link() {
    local(async {
        let (daemon, receiver, mut frontend, handle) = connected("3").await;
        frontend
            .send(FrontendRequest::Activate(handle, false))
            .await;
        // Let capture finish leaving it: its last frames still go out, and
        // one sent after the revocation would close the link by itself.
        tokio::time::sleep(Duration::from_secs(1)).await;
        frontend
            .send(FrontendRequest::UpdateFixIps(
                handle,
                vec!["192.0.2.1".parse().expect("ip")],
            ))
            .await;

        frontend
            .send(FrontendRequest::RemoveAuthorizedKey(
                receiver.fingerprint.clone(),
            ))
            .await;

        let closed = until("the link to close", Duration::from_secs(5), || {
            receiver.closed.get() > 0
        })
        .await;
        assert!(
            closed,
            "the machine was revoked and the connection to it is still open; \
             log:\n{}",
            daemon.log()
        );
    });
}

// LEDGER T11 | class B | 1 device list returned over IPC by the hops binary after a real config reload
/// A frontend shows two devices and the user arms delete on one. The config
/// file is then changed from outside, which reloads it, before the user
/// confirms. The delete must still remove the device the user was shown.
#[test]
fn a_reload_between_showing_and_deleting_deletes_the_device_shown() {
    local(async {
        let entry = |name: &str, pos: &str| {
            format!("\n[[clients]]\nhostname = \"{name}\"\nposition = \"{pos}\"\n")
        };
        let (a, b) = (entry("a.invalid", "left"), entry("b.invalid", "right"));
        let daemon = Daemon::start("4", &format!("{DUMMY}{a}{b}"));
        let mut frontend = Frontend::attach().await;
        let shown = frontend.devices().await;
        let target = handle_named(&shown, "a.invalid");

        // Something else rewrites the file: the same two devices, reordered.
        let port = std::fs::read_to_string(&daemon.config)
            .expect("config")
            .lines()
            .find_map(|l| l.strip_prefix("port = ").map(str::to_string))
            .expect("port line");
        std::fs::write(
            &daemon.config,
            format!("{DUMMY}{b}{a}").replace("{port}", &port),
        )
        .expect("rewrite");
        // The daemon logs this as it takes the change in, in the same step
        // that rebuilds its device list, so a request sent after it is handled
        // after the reload.
        let reloaded = until("the reload", Duration::from_secs(20), || {
            daemon.log().contains("config changed")
        })
        .await;
        assert!(
            reloaded,
            "the daemon never reloaded; log:\n{}",
            daemon.log()
        );

        frontend
            .send(FrontendRequest::Delete {
                handle: target,
                fingerprint: None,
            })
            .await;
        let left = frontend.devices().await;
        assert_eq!(
            names(&left),
            vec!["b.invalid".to_string()],
            "delete was armed on a.invalid (handle {target}) before the reload; \
             after it, the delete removed the wrong device. log:\n{}",
            daemon.log()
        );
    });
}

// LEDGER T12 | class B | 1 device list and error event returned over IPC by the hops binary
/// A delete or rename made for a pin the device no longer has is refused and
/// said so, and the same request with the device's pin goes through.
///
/// A delete revokes the device's pin. Between a frontend drawing a row and the
/// user confirming, the device can learn or lose its pin; acting then would
/// revoke a machine that row never showed.
#[test]
fn a_delete_or_rename_for_a_pin_the_device_no_longer_has_is_refused() {
    local(async {
        let pin = format!("{}11", "11:".repeat(31));
        let shown = format!("{}22", "22:".repeat(31));
        let daemon = Daemon::start(
            "5",
            &format!(
                "{DUMMY}\n[[clients]]\nhostname = \"desk.invalid\"\nposition = \"left\"\n\
                 fingerprint = \"{pin}\"\n\n[authorized_fingerprints]\n\"{pin}\" = \"desk\"\n"
            ),
        );
        let mut frontend = Frontend::attach().await;
        let handle = handle_named(&frontend.devices().await, "desk.invalid");
        let refusal = |e| match e {
            FrontendEvent::Error(m) if m.contains("changed since it was shown") => Some(m),
            _ => None,
        };

        frontend
            .send(FrontendRequest::Delete {
                handle,
                fingerprint: Some(shown.clone()),
            })
            .await;
        frontend.next("the delete's refusal", refusal).await;
        frontend
            .send(FrontendRequest::UpdateHostname {
                handle,
                hostname: Some("renamed.invalid".into()),
                fingerprint: Some(shown.clone()),
            })
            .await;
        frontend.next("the rename's refusal", refusal).await;

        // A request made while the device showed no pin is refused too: the
        // device learnt its pin after the row was drawn, so the pin being
        // revoked is one the user never saw.
        frontend
            .send(FrontendRequest::Delete {
                handle,
                fingerprint: None,
            })
            .await;
        frontend
            .next("the unpinned delete's refusal", refusal)
            .await;
        frontend
            .send(FrontendRequest::UpdateHostname {
                handle,
                hostname: Some("renamed.invalid".into()),
                fingerprint: None,
            })
            .await;
        frontend
            .next("the unpinned rename's refusal", refusal)
            .await;

        let after = frontend.devices().await;
        assert_eq!(
            after
                .get(&handle)
                .map(|(c, s)| (c.hostname.clone(), s.peer_fingerprint.clone())),
            Some((Some("desk.invalid".to_string()), Some(pin.clone()))),
            "a delete or a rename made for another pin, or for none, changed the \
             device; log:\n{}",
            daemon.log()
        );

        // With the device's own pin, both are carried out. The rename clears
        // the pin, as a new name may be another machine.
        frontend
            .send(FrontendRequest::UpdateHostname {
                handle,
                hostname: Some("renamed.invalid".into()),
                fingerprint: Some(pin),
            })
            .await;
        frontend
            .send(FrontendRequest::Delete {
                handle,
                fingerprint: None,
            })
            .await;
        assert!(
            frontend.devices().await.is_empty(),
            "a rename and a delete made for the device's own pin were refused; \
             log:\n{}",
            daemon.log()
        );
    });
}

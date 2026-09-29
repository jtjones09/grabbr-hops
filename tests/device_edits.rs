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

mod common;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use hops_ipc::{
    AsyncFrontendEventReader, AsyncFrontendRequestWriter, ClientConfig, ClientState, FrontendEvent,
    FrontendRequest, Geometry, Position,
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
        Self::start_paired(tag, config, &[])
    }

    /// [`Daemon::start`], already paired with each machine in `pairings`.
    fn start_paired(tag: &str, config: &str, pairings: &[common::Pairing]) -> Daemon {
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
        common::seed_pairings(&config_dir, pairings);
        // SAFETY: the tests in this binary hold ONE_AT_A_TIME, and set these
        // before anything that reads the environment.
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::set_var("XDG_RUNTIME_DIR", &dir);
            std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
        }
        let config_path = config_dir.join("config.toml");
        let log = dir.join("daemon.log");
        let (child, _) = common::launch(
            &config_path,
            |port| config.replace("{port}", &port.to_string()),
            &log,
            || spawn(&dir, &config_path, &log),
        );
        Daemon {
            child,
            dir,
            config: config_path,
            log,
        }
    }

    /// Stop the daemon and start it again on the config it saved, as a
    /// reboot or an upgrade does. Only the listen port is changed.
    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let saved = std::fs::read_to_string(&self.config).expect("the saved config");
        let (child, _) = common::launch(
            &self.config,
            |port| {
                let mut out = String::new();
                let mut done = false;
                for line in saved.lines() {
                    if !done && line.starts_with("port = ") {
                        out.push_str(&format!("port = {port}"));
                        done = true;
                    } else {
                        out.push_str(line);
                    }
                    out.push('\n');
                }
                out
            },
            &self.log,
            || spawn(&self.dir, &self.config, &self.log),
        );
        self.child = child;
    }
}

/// The hops daemon on `config_path`, with every other path it could touch
/// under `dir`.
fn spawn(dir: &std::path::Path, config_path: &std::path::Path, log: &std::path::Path) -> Child {
    let config_dir = config_path.parent().expect("a config directory");
    Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--config")
        .arg(config_path)
        .arg("--cert-path")
        .arg(config_dir.join("lan-mouse.pem"))
        .arg("daemon")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("XDG_CONFIG_HOME", dir.join(".config"))
        .env("XDG_STATE_HOME", dir)
        .env("HOPS_LOG_FILE", log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts")
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
    /// switched on. The pairing with it is [`Receiver::pairing`].
    fn config(&self) -> String {
        format!(
            "{DUMMY}\n[[clients]]\nhostname = \"127.0.0.1\"\nips = [\"127.0.0.1\"]\n\
             port = {}\nposition = \"left\"\nactivate_on_startup = true\n\
             fingerprint = \"{fp}\"\n",
            self.port,
            fp = self.fingerprint,
        )
    }

    /// The daemon's pairing with this receiver: each may drive the other.
    fn pairing(&self) -> [common::Pairing<'_>; 1] {
        [(&self.fingerprint, "receiver", common::BOTH_WAYS)]
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
    let daemon = Daemon::start_paired(tag, &receiver.config(), &receiver.pairing());
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

// LEDGER T9 | class B | 2 connection closed at a real QUIC receiver, dialled by the hops binary; 1 device list returned over IPC
/// The same after the device's address was edited while it was connected.
/// The edit keeps the pin (#99), which the row shows and the delete carries.
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
        let shown = frontend
            .devices()
            .await
            .get(&handle)
            .and_then(|(_, s)| s.peer_fingerprint.clone());
        assert_eq!(
            shown.as_ref(),
            Some(&receiver.fingerprint),
            "a new address cleared the device's pin (#99); log:\n{}",
            daemon.log()
        );

        frontend
            .send(FrontendRequest::Delete {
                handle,
                fingerprint: shown,
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
        let daemon = Daemon::start_paired(
            "5",
            &format!(
                "{DUMMY}\n[[clients]]\nhostname = \"desk.invalid\"\nposition = \"left\"\n\
                 fingerprint = \"{pin}\"\n"
            ),
            &[(&pin, "desk", common::BOTH_WAYS)],
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

        // With the device's own pin, both are carried out. The new name keeps
        // the pin (#99): a machine answering to it has to be the same one.
        frontend
            .send(FrontendRequest::UpdateHostname {
                handle,
                hostname: Some("renamed.invalid".into()),
                fingerprint: Some(pin.clone()),
            })
            .await;
        let renamed = frontend.devices().await;
        assert_eq!(
            renamed
                .get(&handle)
                .map(|(c, s)| (c.hostname.clone(), s.peer_fingerprint.clone())),
            Some((Some("renamed.invalid".to_string()), Some(pin.clone()))),
            "a new hostname for the device did not keep its pin (#99); log:\n{}",
            daemon.log()
        );
        frontend
            .send(FrontendRequest::Delete {
                handle,
                fingerprint: Some(pin),
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

// LEDGER T9904 | class B | 1 error event and device list returned over IPC by the hops binary, dialling a real QUIC receiver
/// A machine added a second time, here by address while it is already a
/// device, is not dialled for the new device, and the user is told which
/// device it already is (#12). It used to be pinned to the machine too, and
/// the two made one card whose name came from one and whose buttons acted
/// on the other.
#[test]
fn a_machine_added_a_second_time_is_refused_and_the_user_is_told() {
    local(async {
        let (daemon, receiver, mut frontend, first) = connected("6").await;
        frontend.send(FrontendRequest::OpenPairing).await;
        frontend
            .send(FrontendRequest::Create(hops_ipc::NewDevice {
                hostname: None,
                fix_ips: vec!["127.0.0.1".parse().expect("ip")],
                port: receiver.port,
                pos: hops_ipc::Position::Right,
            }))
            .await;
        let again = frontend
            .next("the new device", |e| match e {
                FrontendEvent::Created(h, ..) => Some(h),
                _ => None,
            })
            .await;

        let told = frontend
            .next(
                "the notice that the machine is already added",
                |e| match e {
                    FrontendEvent::Error(m) if m.contains("same machine") => Some(m),
                    _ => None,
                },
            )
            .await;
        assert!(
            told.contains("127.0.0.1"),
            "the notice does not name the device already added: {told}"
        );
        let devices = frontend.devices().await;
        assert_eq!(
            (
                devices
                    .get(&first)
                    .and_then(|(_, s)| s.peer_fingerprint.clone()),
                devices
                    .get(&again)
                    .and_then(|(_, s)| s.peer_fingerprint.clone()),
            ),
            (Some(receiver.fingerprint.clone()), None),
            "(first device's pin, second device's pin): only the first device \
             may be pinned to the machine; log:\n{}",
            daemon.log()
        );
    });
}

// LEDGER T9905 | class B | 1 device list returned over IPC by the hops binary after a real config load
/// A config saved before #12 can hold two devices pinned to one machine,
/// shown as one card. Deleting that card removes both: the machine is
/// revoked, and a device left behind would lose its pin to the revocation
/// and dial whatever answers at its address.
#[test]
fn deleting_a_machine_saved_as_two_devices_removes_both() {
    local(async {
        let pin = format!("{}33", "33:".repeat(31));
        let entry = |name: &str, pos: &str| {
            format!(
                "\n[[clients]]\nhostname = \"{name}\"\nposition = \"{pos}\"\n\
                 fingerprint = \"{pin}\"\n"
            )
        };
        let daemon = Daemon::start_paired(
            "7",
            &format!(
                "{DUMMY}{}{}",
                entry("desk.invalid", "top"),
                entry("192.0.2.10", "bottom"),
            ),
            &[(&pin, "desk", common::BOTH_WAYS)],
        );
        let mut frontend = Frontend::attach().await;
        let shown = frontend.devices().await;
        assert_eq!(shown.len(), 2, "precondition: both devices loaded");
        let desk = handle_named(&shown, "desk.invalid");

        frontend
            .send(FrontendRequest::Delete {
                handle: desk,
                fingerprint: Some(pin),
            })
            .await;
        assert_eq!(
            names(&frontend.devices().await),
            Vec::<String>::new(),
            "the machine was deleted and a second device pinned to it is still \
             there; log:\n{}",
            daemon.log()
        );
    });
}

// LEDGER T9910 | class B | 1 device list returned over IPC by the hops binary; 2 connection at a real QUIC receiver; 4 config file written by the hops binary
/// Naming a connected device names it, and nothing else: it is dialled
/// where it was, stays pinned to its machine and keeps its link, and the
/// name is saved beside its address (#13). The name used to be the
/// hostname, so naming a device changed where it dialled.
#[test]
fn naming_a_connected_device_changes_only_its_name() {
    local(async {
        let (daemon, receiver, mut frontend, handle) = connected("n").await;

        frontend
            .send(FrontendRequest::UpdateLabel(handle, Some("den".into())))
            .await;

        let shown = frontend.devices().await;
        assert_eq!(
            shown.get(&handle).map(|(c, s)| (
                c.label.as_deref(),
                c.hostname.as_deref(),
                s.peer_fingerprint.as_deref()
            )),
            Some((
                Some("den"),
                Some("127.0.0.1"),
                Some(receiver.fingerprint.as_str())
            )),
            "(name, where it is dialled, pin) after naming the device den; log:\n{}",
            daemon.log()
        );
        let saved = until("the name to be saved", Duration::from_secs(20), || {
            std::fs::read_to_string(&daemon.config).is_ok_and(|t| t.contains("label = \"den\""))
        })
        .await;
        let file = std::fs::read_to_string(&daemon.config).unwrap_or_default();
        assert!(
            saved
                && file.contains("hostname = \"127.0.0.1\"")
                && file.contains(&format!("fingerprint = \"{}\"", receiver.fingerprint)),
            "the name was not saved beside the device's address and pin:\n{file}"
        );
        // after the daemon has read its own save back
        let _ = frontend.devices().await;
        assert_eq!(
            (receiver.accepted.get(), receiver.closed.get()),
            (1, 0),
            "(links opened, links closed): naming the device touched its link; \
             log:\n{}",
            daemon.log()
        );
    });
}

// LEDGER T174 | class B | 1 device list returned over IPC by the hops binary, before and after a restart and a reload; 4 config file written by the hops binary
/// Where a device is drawn on the arrange canvas is saved, and comes back
/// after a restart and after the file is edited (#174). It used to live in
/// memory only: the config had no field for it, so every restart put every
/// device back where its edge placed it. Drawing a device does not move its
/// edge: crossing still follows `position`.
#[test]
fn an_arranged_layout_survives_a_restart_and_a_reload() {
    local(async {
        let desk = "\n[[clients]]\nhostname = \"desk.invalid\"\nposition = \"left\"\n";
        let mut daemon = Daemon::start("g", &format!("{DUMMY}{desk}"));
        let mut frontend = Frontend::attach().await;
        let handle = handle_named(&frontend.devices().await, "desk.invalid");
        // drawn to the right of this machine, while its edge is the left
        let drawn = Geometry {
            x: 364,
            y: 108,
            width: 96,
            height: 64,
        };
        frontend
            .send(FrontendRequest::UpdateGeometry(handle, Some(drawn)))
            .await;
        let placed = |devices: &Devices| {
            let (c, _) = &devices[&handle_named(devices, "desk.invalid")];
            (c.geometry, c.pos)
        };
        assert_eq!(
            placed(&frontend.devices().await),
            (Some(drawn), Position::Left),
            "(where it is drawn, its edge) after drawing it; log:\n{}",
            daemon.log()
        );
        let saved = until("the layout to be saved", Duration::from_secs(60), || {
            std::fs::read_to_string(&daemon.config).is_ok_and(|t| t.contains("geometry"))
        })
        .await;
        let file = std::fs::read_to_string(&daemon.config).unwrap_or_default();
        assert!(
            saved && file.contains("position = \"left\""),
            "the layout was not saved beside the device's edge:\n{file}"
        );

        drop(frontend);
        daemon.restart();
        let mut frontend = Frontend::attach().await;
        assert_eq!(
            placed(&frontend.devices().await),
            (Some(drawn), Position::Left),
            "(where it is drawn, its edge) after a restart; config:\n{}\nlog:\n{}",
            std::fs::read_to_string(&daemon.config).unwrap_or_default(),
            daemon.log()
        );

        // The file is edited from outside, which reloads it.
        let port = std::fs::read_to_string(&daemon.config)
            .expect("config")
            .lines()
            .find_map(|l| l.strip_prefix("port = ").map(str::to_string))
            .expect("port line");
        let moved = Geometry {
            x: 20,
            y: 16,
            width: 96,
            height: 64,
        };
        std::fs::write(
            &daemon.config,
            format!("{DUMMY}{desk}geometry = {{ x = 20, y = 16, width = 96, height = 64 }}\n")
                .replace("{port}", &port),
        )
        .expect("rewrite");
        // Read the devices until the reload lands, not the log: a "config
        // changed" line can be for an earlier write, and a loaded machine can
        // deliver file events many seconds late.
        let started = tokio::time::Instant::now();
        let mut now = placed(&frontend.devices().await);
        while now != (Some(moved), Position::Left) && started.elapsed() < Duration::from_secs(60) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            now = placed(&frontend.devices().await);
        }
        assert_eq!(
            now,
            (Some(moved), Position::Left),
            "(where it is drawn, its edge) after the file was edited; config:\n{}\nlog:\n{}",
            std::fs::read_to_string(&daemon.config).unwrap_or_default(),
            daemon.log()
        );
    });
}

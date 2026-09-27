//! Two built daemons, paired the way two people pair them, and then one
//! removes the other (#184, #161).
//!
//! Connected, the machine that was removed is told as its link closes and
//! forgets its side too. A device removed by a build that kept removals on
//! file pairs again, in full, once both machines run this one.
//!
//! Each daemon runs with dummy capture and emulation, discovery off, a free
//! port, and every path it could touch in its own scratch directory. The two
//! share one IPC token, so this process can attach a frontend to each through
//! the real connector. The tests in this binary take turns (see
//! [`machines`]).
#![cfg(unix)]

use std::future::Future;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{
    AsyncFrontendEventReader, AsyncFrontendRequestWriter, AttemptOrigin, DaemonEndpoint,
    FrontendEvent, FrontendRequest, PairingCheck, Position,
};

/// How long anything that must happen may take, under a loaded test run.
const WITHIN: Duration = Duration::from_secs(30);

struct Daemon {
    child: Child,
    dir: PathBuf,
    config: PathBuf,
    log: PathBuf,
    port: u16,
    endpoint: DaemonEndpoint,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn saved_config(&self) -> String {
        std::fs::read_to_string(&self.config).unwrap_or_default()
    }

    /// Wait for the service loop; `false` when the daemon stopped because
    /// its port was taken meanwhile, which a busy test run can do between
    /// choosing a free port and binding it.
    fn wait_until_running(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.log().contains("service running; stops on") {
            if self.child.try_wait().ok().flatten().is_some()
                && self.log().contains("Address already in use")
            {
                return false;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon never reported its service loop running; log:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // Let the config watcher drain what starting wrote (see tests/common).
        std::thread::sleep(Duration::from_secs(1));
        true
    }

    async fn attach(&self) -> (AsyncFrontendEventReader, AsyncFrontendRequestWriter) {
        let (events, mut requests) =
            hops_ipc::connect_async_to(&self.endpoint, Some(Duration::from_secs(10)))
                .await
                .expect("a frontend connects");
        requests.request(FrontendRequest::Sync).await.expect("sync");
        (events, requests)
    }
}

fn spawn(dir: &Path, config: &Path, log: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--config")
        .arg(config)
        .arg("--cert-path")
        .arg(dir.join("lan-mouse.pem"))
        .arg("daemon")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("XDG_RUNTIME_DIR", dir)
        // shared, so both daemons keep the one token this process reads
        .env("XDG_CONFIG_HOME", shared_config(dir))
        .env("XDG_STATE_HOME", dir)
        .env("HOPS_LOG_FILE", log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts")
}

fn shared_config(dir: &Path) -> PathBuf {
    dir.parent().expect("the scratch base").join(".config")
}

/// Start a daemon in `base/name`, with `tables` appended to its config. Sets
/// this process's `HOME` and `XDG_RUNTIME_DIR` to find its endpoint, so call
/// it before anything runs alongside.
fn start(base: &Path, name: &str, tables: &str) -> Daemon {
    for _ in 0..5 {
        if let Some(daemon) = try_start(base, name, tables) {
            return daemon;
        }
    }
    panic!("the daemon in {name} never found a free port");
}

fn try_start(base: &Path, name: &str, tables: &str) -> Option<Daemon> {
    let dir = base.join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    let port = UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free port")
        .port();
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\n\
             discovery = false\n\n{tables}"
        ),
    )
    .expect("a config");
    // SAFETY: the tests in this binary take turns (see `machines`), and
    // nothing else reads the environment meanwhile.
    let endpoint = unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        DaemonEndpoint::of_this_platform().expect("an endpoint")
    };
    let log = dir.join("daemon.log");
    let mut daemon = Daemon {
        child: spawn(&dir, &config, &log),
        log,
        dir,
        config,
        port,
        endpoint,
    };
    daemon.wait_until_running().then_some(daemon)
}

/// The first event within `within` that `pick` makes something of.
async fn until<T>(
    events: &mut AsyncFrontendEventReader,
    within: Duration,
    mut pick: impl FnMut(&FrontendEvent) -> Option<T>,
) -> Option<T> {
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.next()).await {
        if let Some(found) = event.ok().as_ref().and_then(&mut pick) {
            return Some(found);
        }
    }
    None
}

fn fingerprint_of(event: &FrontendEvent) -> Option<String> {
    match event {
        FrontendEvent::PublicKeyFingerprint(fp) => Some(fp.clone()),
        _ => None,
    }
}

fn attempt_from(fp: &str, origin: AttemptOrigin) -> impl FnMut(&FrontendEvent) -> Option<()> {
    let fp = fp.to_string();
    move |e| match e {
        FrontendEvent::ConnectionAttempt {
            fingerprint,
            origin: o,
            ..
        } if *fingerprint == fp && *o == origin => Some(()),
        _ => None,
    }
}

async fn ask(requests: &mut AsyncFrontendRequestWriter, request: FrontendRequest) {
    requests.request(request).await.expect("request sent");
}

/// Two machines, each daemon with a frontend attached: the laptop adds the
/// desk, so the laptop drives the desk.
struct Machines {
    laptop: Daemon,
    desk: Daemon,
    fa: AsyncFrontendEventReader,
    ra: AsyncFrontendRequestWriter,
    fb: AsyncFrontendEventReader,
    rb: AsyncFrontendRequestWriter,
    fp_a: String,
    fp_b: String,
}

/// One at a time: each test points this process's environment at its own
/// scratch directory to find its daemons.
static TURN: Mutex<()> = Mutex::new(());

/// Start the laptop, then the desk with `desk_tables` of the laptop's
/// fingerprint appended to its config, attach to both, run `test`, and fail
/// with whatever properties it reports broken.
fn machines<F, Fut>(name: &str, desk_tables: impl FnOnce(&str) -> String, test: F)
where
    F: FnOnce(Machines) -> Fut,
    Fut: Future<Output = Vec<String>>,
{
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let _ = rustls::crypto::ring::default_provider().install_default();
    let base = PathBuf::from(format!("/tmp/h-rm-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("scratch base");
    // SAFETY: the tests in this binary take turns, before anything runs.
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", base.join(".config"));
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let failures = tokio::task::LocalSet::new().block_on(&rt, async {
        let laptop = start(&base, "a", "");
        let (mut fa, ra) = laptop.attach().await;
        let fp_a = until(&mut fa, WITHIN, fingerprint_of)
            .await
            .expect("the laptop's fingerprint");
        let desk = start(&base, "b", &desk_tables(&fp_a));
        let (mut fb, rb) = desk.attach().await;
        let fp_b = until(&mut fb, WITHIN, fingerprint_of)
            .await
            .expect("the desk's fingerprint");
        test(Machines {
            laptop,
            desk,
            fa,
            ra,
            fb,
            rb,
            fp_a,
            fp_b,
        })
        .await
    });
    let _ = std::fs::remove_dir_all(&base);
    assert!(
        failures.is_empty(),
        "{} propert(ies) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Pair the two the way two people do, and wait for the laptop's link to the
/// desk: add device open on both, the laptop adds the desk and dials it, each
/// approves the other, and both confirm the number. The laptop's device for
/// the desk.
async fn pair(m: &mut Machines) -> Result<u64, String> {
    ask(&mut m.ra, FrontendRequest::OpenPairing).await;
    ask(&mut m.rb, FrontendRequest::OpenPairing).await;
    ask(&mut m.ra, FrontendRequest::Create).await;
    let handle = until(&mut m.fa, WITHIN, |e| match e {
        FrontendEvent::Created(handle, _, _) => Some(*handle),
        _ => None,
    })
    .await
    .ok_or("the laptop created no device")?;
    for r in [
        FrontendRequest::UpdateHostname {
            handle,
            hostname: Some("127.0.0.1".into()),
            fingerprint: None,
        },
        FrontendRequest::UpdateFixIps(handle, vec!["127.0.0.1".parse().expect("ip")]),
        FrontendRequest::UpdatePort(handle, m.desk.port),
        // The dummy capture backend crosses at the left edge only: nothing
        // ever crosses to this device, so every dial here comes from adding it.
        FrontendRequest::UpdatePosition(handle, Position::Right),
        FrontendRequest::Activate(handle, true),
    ] {
        ask(&mut m.ra, r).await;
    }
    until(
        &mut m.fa,
        WITHIN,
        attempt_from(&m.fp_b, AttemptOrigin::OutboundDial),
    )
    .await
    .ok_or("the laptop's dial raised no prompt")?;
    ask(
        &mut m.ra,
        FrontendRequest::AuthorizeKey("desk".into(), m.fp_b.clone()),
    )
    .await;
    until(
        &mut m.fb,
        WITHIN,
        attempt_from(&m.fp_a, AttemptOrigin::Inbound),
    )
    .await
    .ok_or_else(|| format!("the desk was never asked; its log:\n{}", m.desk.log()))?;
    ask(
        &mut m.rb,
        FrontendRequest::AuthorizeKey("laptop".into(), m.fp_a.clone()),
    )
    .await;
    let fp_b = m.fp_b.clone();
    let shown = until(&mut m.fa, WITHIN, |e| match e {
        FrontendEvent::PairingCheck {
            fingerprint,
            check: PairingCheck::Show(n),
            ..
        } if *fingerprint == fp_b => Some(n.clone()),
        _ => None,
    })
    .await
    .ok_or_else(|| format!("the laptop showed no number; its log:\n{}", m.laptop.log()))?;
    for (requests, fp) in [(&mut m.rb, m.fp_a.clone()), (&mut m.ra, m.fp_b.clone())] {
        ask(
            requests,
            FrontendRequest::ConfirmPairing {
                fingerprint: fp,
                number: shown.clone(),
            },
        )
        .await;
    }
    let paired = |fp: String| {
        move |e: &FrontendEvent| match e {
            FrontendEvent::PairingEnded {
                fingerprint,
                paired,
            } if *fingerprint == fp => Some(*paired),
            _ => None,
        }
    };
    let on_desk = until(&mut m.fb, WITHIN, paired(m.fp_a.clone())).await;
    let on_laptop = until(&mut m.fa, WITHIN, paired(m.fp_b.clone())).await;
    if on_desk != Some(true) || on_laptop != Some(true) {
        return Err(format!(
            "the two machines did not pair (desk: {on_desk:?}, laptop: {on_laptop:?}); \
             laptop log:\n{}\ndesk log:\n{}",
            m.laptop.log(),
            m.desk.log()
        ));
    }
    until(&mut m.fa, WITHIN, |e| match e {
        FrontendEvent::State(h, _, s) if *h == handle && s.active_addr.is_some() => Some(()),
        _ => None,
    })
    .await
    .ok_or("the laptop never took up its link after pairing")?;
    Ok(handle)
}

/// What a machine was told once the other removed it: whether its pairing
/// with `fp` went, whether its device for it went (when it had one), and
/// the notice naming the removal.
async fn told_it_was_removed(
    events: &mut AsyncFrontendEventReader,
    fp: &str,
    device: Option<u64>,
) -> (bool, bool, Option<String>) {
    let (mut forgotten, mut deleted, mut notice) = (false, device.is_none(), None);
    until(events, WITHIN, |e| {
        match e {
            FrontendEvent::TrustUpdated(map) => forgotten = !map.contains_key(fp),
            FrontendEvent::Deleted(h) if Some(*h) == device => deleted = true,
            FrontendEvent::Error(t) if t.contains("removed this machine") => {
                notice = Some(t.clone())
            }
            _ => {}
        }
        (forgotten && deleted && notice.is_some()).then_some(())
    })
    .await;
    (forgotten, deleted, notice)
}

// LEDGER R184-16 | class B | 5 process: IPC events from two built hops daemons
/// The laptop deletes the desk while its link to the desk is up: the desk is
/// told as the link closes, and forgets the laptop too, across a restart.
#[test]
fn removing_a_connected_receiver_tells_it_and_it_forgets_this_machine() {
    machines(
        "receiver",
        |_| String::new(),
        |mut m| async move {
            let mut failures = Vec::new();
            let handle = match pair(&mut m).await {
                Ok(handle) => handle,
                Err(e) => return vec![e],
            };
            ask(
                &mut m.ra,
                FrontendRequest::Delete {
                    handle,
                    fingerprint: Some(m.fp_b.clone()),
                },
            )
            .await;
            let (forgotten, _, notice) = told_it_was_removed(&mut m.fb, &m.fp_a, None).await;
            if !forgotten || notice.is_none() {
                failures.push(format!(
                    "the desk was not told the laptop removed it (forgot its side: \
                 {forgotten}, notice: {notice:?}); desk log:\n{}",
                    m.desk.log()
                ));
                return failures;
            }

            // Saved: a restart does not bring the pairing back.
            let _ = m.desk.child.kill();
            let _ = m.desk.child.wait();
            m.desk.log = m.desk.dir.join("daemon.again.log");
            m.desk.child = spawn(&m.desk.dir, &m.desk.config, &m.desk.log);
            if !m.desk.wait_until_running() {
                failures.push("the desk's port was taken while it restarted".into());
                return failures;
            }
            let (mut fb, _rb) = m.desk.attach().await;
            let paired = until(&mut fb, WITHIN, |e| match e {
                FrontendEvent::TrustUpdated(map) => Some(map.contains_key(&m.fp_a)),
                _ => None,
            })
            .await;
            if paired != Some(false) {
                failures.push(format!(
                    "after a restart the desk still holds the pairing it was told to drop: \
                 {paired:?}"
                ));
            }
            failures
        },
    );
}

// LEDGER R184-17 | class B | 5 process: IPC events from two built hops daemons
/// The desk removes the laptop while the laptop's link to it is up: the
/// laptop is told as the link closes, and forgets the desk too, device card
/// included.
#[test]
fn a_receiver_removing_a_connected_sender_tells_it_and_it_forgets_that_machine() {
    machines(
        "sender",
        |_| String::new(),
        |mut m| async move {
            let handle = match pair(&mut m).await {
                Ok(handle) => handle,
                Err(e) => return vec![e],
            };
            ask(
                &mut m.rb,
                FrontendRequest::RemoveAuthorizedKey(m.fp_a.clone()),
            )
            .await;
            let (forgotten, deleted, notice) =
                told_it_was_removed(&mut m.fa, &m.fp_b, Some(handle)).await;
            if forgotten && deleted && notice.is_some() {
                return Vec::new();
            }
            vec![format!(
                "the laptop was not told the desk removed it (forgot its side: {forgotten}, \
             deleted its device: {deleted}, notice: {notice:?}); laptop log:\n{}",
                m.laptop.log()
            )]
        },
    );
}

// LEDGER R161-3 | class B | 5 process + 4 file on disk: IPC events from two built hops daemons, the desk's config.toml
/// The desk removed the laptop under a build that kept removals on file.
/// Now both run this build: the laptop pairs with the desk again, in full,
/// and the desk's config keeps no record of the removal.
#[test]
fn a_device_removed_before_the_upgrade_pairs_again() {
    machines(
        "upgrade",
        |fp_a| {
            format!(
                "[revoked_fingerprints.\"{fp_a}\"]\nlabel = \"laptop\"\n\
                 revoked_at = 1788579979\n"
            )
        },
        |mut m| async move {
            if !m.desk.saved_config().contains(&m.fp_a) {
                return vec!["precondition: the desk's config records the removal".into()];
            }
            if let Err(e) = pair(&mut m).await {
                return vec![format!(
                    "a device removed before the upgrade could not pair again: {e}"
                )];
            }
            let saved = m.desk.saved_config();
            if saved.contains("revoked_fingerprints") {
                return vec![format!(
                    "the desk's config still records the removal after pairing again:\n\
                     {saved}"
                )];
            }
            Vec::new()
        },
    );
}

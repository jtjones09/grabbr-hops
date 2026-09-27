//! Two built daemons pair the way two people pair them (#11, #167): add
//! device on both, the adding machine dials, each approves the other, the
//! adding machine shows a number and the machine being added picks it from
//! three, and both confirm.
//!
//! Each daemon runs with dummy capture and emulation, discovery off, a free
//! port, and every path it could touch in its own scratch directory. The two
//! share one IPC token, so this process can attach a frontend to each through
//! the real connector.
//!
//! Runs in its own test binary, so pointing the environment at the scratch
//! directory cannot disturb anything else, and the tests here take turns
//! (see [`machines`]).
#![cfg(unix)]

mod common;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{
    AsyncFrontendEventReader, AsyncFrontendRequestWriter, AttemptOrigin, Controller,
    DaemonEndpoint, FrontendEvent, FrontendRequest, PairingCheck, Position,
};

/// How long anything that must happen may take, under a loaded test run.
const WITHIN: Duration = Duration::from_secs(30);
/// How long number cards stay unchanged before a test reads them as a
/// person would: longer than the one second between add dials, twice over.
const QUIET: Duration = Duration::from_secs(3);

struct Daemon {
    child: Child,
    dir: PathBuf,
    config: PathBuf,
    log: PathBuf,
    port: u16,
    endpoint: DaemonEndpoint,
    starts: u32,
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

    fn spawn(&self) -> Child {
        spawn(&self.dir, &self.config, &self.log)
    }

    fn drain_the_watcher(&self) {
        // Let the config watcher drain what starting wrote (see tests/common).
        std::thread::sleep(Duration::from_secs(1));
    }

    /// Stop it and start it again on the same files.
    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.starts += 1;
        self.log = self.dir.join(format!("daemon.{}.log", self.starts));
        self.child = self.spawn();
        if common::wait_until_running(&mut self.child, &self.log).is_err() {
            panic!(
                "the daemon's port was taken while it restarted; log:\n{}",
                self.log()
            );
        }
        self.drain_the_watcher();
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

/// Start a daemon in `base/name`. Sets this process's `HOME` and
/// `XDG_RUNTIME_DIR` to find its endpoint, so call it before anything runs
/// alongside.
fn start(base: &Path, name: &str) -> Daemon {
    let dir = base.join(name);
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    let config = dir.join("config.toml");
    // SAFETY: the tests in this binary take turns (see `machines`), and
    // nothing else reads the environment meanwhile.
    let endpoint = unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        DaemonEndpoint::of_this_platform().expect("an endpoint")
    };
    let log = dir.join("daemon.log");
    let (child, port) = common::launch(
        &config,
        |port| {
            format!(
                "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n"
            )
        },
        &log,
        || spawn(&dir, &config, &log),
    );
    let daemon = Daemon {
        child,
        log,
        dir,
        config,
        port,
        endpoint,
        starts: 0,
    };
    daemon.drain_the_watcher();
    daemon
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

/// How the attempt with `fp` ended, if it did, and whether the pairing was
/// still listed after it: the last trust update seen names it.
async fn ended_and_kept(events: &mut AsyncFrontendEventReader, fp: &str) -> (Option<bool>, bool) {
    let mut ended = None;
    let mut kept = true;
    until(events, WITHIN, |e| {
        match e {
            FrontendEvent::PairingEnded {
                fingerprint,
                paired,
            } if fingerprint == fp => ended = Some(*paired),
            FrontendEvent::TrustUpdated(map) => kept = map.contains_key(fp),
            _ => {}
        }
        (ended.is_some() && !kept).then_some(())
    })
    .await;
    (ended, kept)
}

async fn add_device(
    events: &mut AsyncFrontendEventReader,
    requests: &mut AsyncFrontendRequestWriter,
    port: u16,
) -> u64 {
    requests
        .request(FrontendRequest::Create(hops_ipc::NewDevice {
            hostname: Some("127.0.0.1".into()),
            fix_ips: vec!["127.0.0.1".parse().expect("ip")],
            port,
            // The dummy capture backend crosses at the left edge only:
            // nothing ever crosses to this device, so every dial here comes
            // from adding it.
            pos: Position::Right,
        }))
        .await
        .expect("create");
    let handle = until(events, WITHIN, |e| match e {
        FrontendEvent::Created(handle, _, _) => Some(*handle),
        _ => None,
    })
    .await
    .expect("a device is created");
    handle
}

/// The approval a person gives on a pairing card, the clipboard left off.
fn approval(label: &str, fp: &str, controller: Controller) -> FrontendRequest {
    FrontendRequest::AuthorizeKey {
        label: label.into(),
        fingerprint: fp.into(),
        controller,
        clipboard: false,
    }
}

async fn ask(requests: &mut AsyncFrontendRequestWriter, request: FrontendRequest) {
    requests.request(request).await.expect("request sent");
}

/// Two machines, each daemon with a frontend attached.
struct Machines {
    adding: Daemon,
    added: Daemon,
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

/// Start two daemons, attach to both, run `test` on them, and fail with
/// whatever properties it reports broken.
fn machines<F, Fut>(name: &str, test: F)
where
    F: FnOnce(Machines) -> Fut,
    Fut: Future<Output = Vec<String>>,
{
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let _ = rustls::crypto::ring::default_provider().install_default();
    let base = PathBuf::from(format!("/tmp/h-pick-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("scratch base");
    // SAFETY: the tests in this binary take turns, before anything runs.
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", base.join(".config"));
    }
    let adding = start(&base, "a");
    let added = start(&base, "b");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let failures = tokio::task::LocalSet::new().block_on(&rt, async {
        let (mut fa, ra) = adding.attach().await;
        let (mut fb, rb) = added.attach().await;
        let fp_a = until(&mut fa, WITHIN, fingerprint_of)
            .await
            .expect("a's fingerprint");
        let fp_b = until(&mut fb, WITHIN, fingerprint_of)
            .await
            .expect("b's fingerprint");
        test(Machines {
            adding,
            added,
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

/// The adding machine's add dial reaches the other machine and each
/// approves the other, in that order: add device open on both first.
async fn both_approve(m: &mut Machines) -> Result<u64, String> {
    ask(&mut m.ra, FrontendRequest::OpenPairing).await;
    ask(&mut m.rb, FrontendRequest::OpenPairing).await;
    let handle = add_device(&mut m.fa, &mut m.ra, m.added.port).await;
    ask(&mut m.ra, FrontendRequest::Activate(handle, true)).await;
    approve_both(m).await?;
    Ok(handle)
}

/// Each machine approves the other once its prompt appears: the adding
/// machine the dial it made, then the one being added the knock it got.
async fn approve_both(m: &mut Machines) -> Result<(), String> {
    until(
        &mut m.fa,
        WITHIN,
        attempt_from(&m.fp_b, AttemptOrigin::OutboundDial),
    )
    .await
    .ok_or("the adding machine's dial raised no prompt")?;
    ask(
        &mut m.ra,
        approval("desk b", &m.fp_b, Controller::ThisMachine),
    )
    .await;
    until(
        &mut m.fb,
        WITHIN,
        attempt_from(&m.fp_a, AttemptOrigin::Inbound),
    )
    .await
    .ok_or_else(|| {
        format!(
            "the machine being added was never asked; its log:\n{}",
            m.added.log()
        )
    })?;
    ask(
        &mut m.rb,
        approval("desk a", &m.fp_a, Controller::ThatMachine),
    )
    .await;
    Ok(())
}

/// The number the adding machine shows and the three the other offers.
async fn the_number(m: &mut Machines) -> Result<(String, Vec<String>), String> {
    let fp_b = m.fp_b.clone();
    let shown = until(&mut m.fa, WITHIN, |e| match e {
        FrontendEvent::PairingCheck {
            fingerprint,
            check: PairingCheck::Show(n),
            ..
        } if *fingerprint == fp_b => Some(n.clone()),
        _ => None,
    })
    .await;
    let fp_a = m.fp_a.clone();
    let offered = until(&mut m.fb, WITHIN, |e| match e {
        FrontendEvent::PairingCheck {
            fingerprint,
            check: PairingCheck::Pick(c),
            ..
        } if *fingerprint == fp_a => Some(c.clone()),
        _ => None,
    })
    .await;
    match (shown, offered) {
        (Some(shown), Some(offered)) => Ok((shown, offered)),
        (shown, offered) => Err(format!(
            "the number did not reach both machines (shown {shown:?}, offered \
             {offered:?}); adding log:\n{}\nadded log:\n{}",
            m.adding.log(),
            m.added.log()
        )),
    }
}

// LEDGER G-4 | class B | 5 process: IPC events from two built hops daemons
// LEDGER G-6c | class B | 5 process + 4 file on disk: AuthorizedUpdated, TrustUpdated, config.toml
/// The adding machine approves first, and the other machine's add device
/// opens only after a knock that came after that approval: the number still
/// appears on both, with no second prompt on the adding machine (#195). The
/// approval waiting for it is not trusted anywhere, the config file an older
/// build reads as its allowlist included.
#[test]
fn a_receiver_that_approves_second_still_reaches_the_number() {
    machines("second", |mut m| async move {
        let mut failures: Vec<String> = Vec::new();
        ask(&mut m.ra, FrontendRequest::OpenPairing).await;
        let handle = add_device(&mut m.fa, &mut m.ra, m.added.port).await;
        ask(&mut m.ra, FrontendRequest::Activate(handle, true)).await;
        if until(
            &mut m.fa,
            WITHIN,
            attempt_from(&m.fp_b, AttemptOrigin::OutboundDial),
        )
        .await
        .is_none()
        {
            return vec!["the adding machine's dial raised no prompt".into()];
        }
        ask(
            &mut m.ra,
            approval("desk b", &m.fp_b, Controller::ThisMachine),
        )
        .await;
        let approved_at = m.adding.log().len();

        // Knocks after that approval, while add device is still closed on
        // the other machine; the adding machine does not prompt again.
        let knocked = Instant::now() + WITHIN;
        while m.adding.log()[approved_at.min(m.adding.log().len())..]
            .matches("connecting ...")
            .count()
            < 4
            && Instant::now() < knocked
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if until(
            &mut m.fa,
            Duration::from_secs(3),
            attempt_from(&m.fp_b, AttemptOrigin::OutboundDial),
        )
        .await
        .is_some()
        {
            failures.push("the adding machine prompted again for a machine it approved".into());
        }

        // Then the other machine opens add device and approves.
        ask(&mut m.rb, FrontendRequest::OpenPairing).await;
        if until(
            &mut m.fb,
            WITHIN,
            attempt_from(&m.fp_a, AttemptOrigin::Inbound),
        )
        .await
        .is_none()
        {
            failures.push(format!(
                "the machine being added was never asked, after opening add device \
                 late; its log:\n{}",
                m.added.log()
            ));
            return failures;
        }
        ask(
            &mut m.rb,
            approval("desk a", &m.fp_a, Controller::ThatMachine),
        )
        .await;
        let mut authorized = None;
        let mut pending = None;
        until(&mut m.fb, WITHIN, |e| {
            match e {
                FrontendEvent::AuthorizedUpdated(map) => authorized = Some(map.clone()),
                FrontendEvent::TrustUpdated(map) => pending = Some(map.clone()),
                _ => {}
            }
            (authorized.is_some() && pending.is_some()).then_some(())
        })
        .await;
        if authorized.as_ref().is_none_or(|a| a.contains_key(&m.fp_a)) {
            failures.push(format!(
                "an approval nobody confirmed is listed as trusted: {authorized:?}"
            ));
        }
        if !pending
            .as_ref()
            .and_then(|p| p.get(&m.fp_a))
            .is_some_and(|t| t.pending && !t.clipboard_from && !t.clipboard_to)
        {
            failures.push(format!(
                "the approval is not shown as a pairing that grants nothing: {pending:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let saved = std::fs::read_to_string(&m.added.config).unwrap_or_default();
        if saved.contains(&m.fp_a) {
            failures.push(format!(
                "config.toml, which an older build reads as its allowlist, names the \
                 machine nobody confirmed:\n{saved}"
            ));
        }

        match the_number(&mut m).await {
            Ok((shown, offered)) => {
                let mut distinct = offered.clone();
                distinct.sort();
                distinct.dedup();
                if distinct.len() != 3 || !offered.contains(&shown) {
                    failures.push(format!(
                        "the machine being added offered {offered:?} for the number {shown}"
                    ));
                }
            }
            Err(e) => failures.push(e),
        }
        failures
    });
}

// LEDGER G-9 | class B | 5 process: PairingEnded, TrustUpdated after a wrong pick
/// A wrong pick on the machine being added ends the attempt on both
/// machines, and neither keeps the approval. Adding the device again then
/// asks both machines again, as a new pairing.
#[test]
fn a_wrong_pick_ends_the_attempt_and_keeps_no_lease() {
    machines("wrong", |mut m| async move {
        let mut failures: Vec<String> = Vec::new();
        let handle = match both_approve(&mut m).await {
            Ok(handle) => handle,
            Err(e) => return vec![e],
        };
        let (shown, offered) = match the_number(&mut m).await {
            Ok(n) => n,
            Err(e) => return vec![e],
        };
        let wrong = offered
            .iter()
            .find(|n| **n != shown)
            .cloned()
            .unwrap_or_default();
        ask(
            &mut m.rb,
            FrontendRequest::ConfirmPairing {
                fingerprint: m.fp_a.clone(),
                number: wrong,
            },
        )
        .await;
        let (ended_b, kept_b) = ended_and_kept(&mut m.fb, &m.fp_a).await;
        if ended_b != Some(false) {
            failures.push(format!(
                "a wrong pick did not end the attempt on the machine being added: {ended_b:?}"
            ));
        }
        if kept_b {
            failures.push("after a wrong pick the machine being added kept the pairing".into());
        }
        let (ended_a, kept_a) = ended_and_kept(&mut m.fa, &m.fp_b).await;
        if ended_a != Some(false) {
            failures.push(format!(
                "after a wrong pick the adding machine did not end its attempt: {ended_a:?}"
            ));
        }
        if kept_a {
            failures.push("after a wrong pick the adding machine kept the pairing".into());
        }

        // Adding it again asks both machines again.
        ask(&mut m.ra, FrontendRequest::OpenPairing).await;
        ask(&mut m.rb, FrontendRequest::OpenPairing).await;
        ask(&mut m.ra, FrontendRequest::Activate(handle, false)).await;
        ask(&mut m.ra, FrontendRequest::Activate(handle, true)).await;
        if let Err(e) = approve_both(&mut m).await {
            failures.push(format!("adding again after a wrong pick: {e}"));
        } else if let Err(e) = the_number(&mut m).await {
            failures.push(format!("adding again after a wrong pick: {e}"));
        }
        failures
    });
}

// LEDGER G-16 | class B | 5 process: both daemons paired, the link up, and paired after a restart
/// The right pick and the confirm pair both machines on the connection the
/// number was compared on: the adding machine takes up its link, and the
/// pairing is still there after the machine being added restarts.
#[test]
fn picking_the_number_pairs_both_machines_and_survives_a_restart() {
    machines("right", |mut m| async move {
        let mut failures: Vec<String> = Vec::new();
        let handle = match both_approve(&mut m).await {
            Ok(handle) => handle,
            Err(e) => return vec![e],
        };
        let (shown, _) = match the_number(&mut m).await {
            Ok(n) => n,
            Err(e) => return vec![e],
        };
        ask(
            &mut m.rb,
            FrontendRequest::ConfirmPairing {
                fingerprint: m.fp_a.clone(),
                number: shown.clone(),
            },
        )
        .await;
        ask(
            &mut m.ra,
            FrontendRequest::ConfirmPairing {
                fingerprint: m.fp_b.clone(),
                number: shown,
            },
        )
        .await;
        let paired = |fp: String| {
            move |e: &FrontendEvent| match e {
                FrontendEvent::PairingEnded {
                    fingerprint,
                    paired,
                } if *fingerprint == fp => Some(*paired),
                _ => None,
            }
        };
        let b_paired = until(&mut m.fb, WITHIN, paired(m.fp_a.clone())).await;
        let a_paired = until(&mut m.fa, WITHIN, paired(m.fp_b.clone())).await;
        if b_paired != Some(true) || a_paired != Some(true) {
            failures.push(format!(
                "the right pick and the confirm did not pair both machines (being \
                 added: {b_paired:?}, adding: {a_paired:?}); adding log:\n{}\n\
                 added log:\n{}",
                m.adding.log(),
                m.added.log()
            ));
            return failures;
        }
        let linked = until(&mut m.fa, WITHIN, |e| match e {
            FrontendEvent::State(h, _, s) if *h == handle && s.active_addr.is_some() => Some(()),
            _ => None,
        })
        .await;
        if linked.is_none() {
            failures.push("the adding machine never took up its link after pairing".into());
        }

        m.added.restart();
        let (mut fb, _rb) = m.added.attach().await;
        let trusted = until(&mut fb, WITHIN, |e| match e {
            FrontendEvent::AuthorizedUpdated(map) => Some(map.contains_key(&m.fp_a)),
            _ => None,
        })
        .await;
        if trusted != Some(true) {
            failures.push(format!(
                "after a restart the machine being added no longer trusts the machine \
                 it paired with: {trusted:?}; log:\n{}",
                m.added.log()
            ));
        }
        failures
    });
}

// LEDGER G-14b | class B | 5 process: PairingEnded and TrustUpdated from two built daemons
/// Removing the other machine while its number is on screen ends the
/// attempt at once, on this machine and on the other, and keeps nothing:
/// the connection it was compared on is in no list the removal reaches
/// otherwise.
#[test]
fn removing_the_machine_mid_pairing_ends_it_on_both() {
    machines("removed", |mut m| async move {
        let mut failures: Vec<String> = Vec::new();
        if let Err(e) = both_approve(&mut m).await {
            return vec![e];
        }
        if let Err(e) = the_number(&mut m).await {
            return vec![e];
        }
        ask(
            &mut m.rb,
            FrontendRequest::RemoveAuthorizedKey(m.fp_a.clone()),
        )
        .await;
        let (ended_b, _) = ended_and_kept(&mut m.fb, &m.fp_a).await;
        if ended_b != Some(false) {
            failures.push(format!(
                "removing the machine mid-pairing left its number card open here: {ended_b:?}"
            ));
        }
        let (ended_a, kept_a) = ended_and_kept(&mut m.fa, &m.fp_b).await;
        if ended_a != Some(false) {
            failures.push(format!(
                "the other machine's attempt did not end when this one removed it: {ended_a:?}"
            ));
        }
        if kept_a {
            failures.push("the other machine kept the pairing after a removal here".into());
        }
        failures
    });
}
/// The number card each machine shows for the other, and how many times
/// each changed: shown, replaced or taken down.
#[derive(Default)]
struct Cards {
    a: Option<PairingCheck>,
    b: Option<PairingCheck>,
    changes: (usize, usize),
}

/// The latest number card each machine shows for the other, read from both
/// frontends at once from `cards`, the ones last seen, until one shows a
/// number the other offers among its three and neither card changed for
/// `quiet`. Cards can change on the way, so only the latest counts. Whether
/// a's card shows the number, and the number.
async fn complementary_cards(
    m: &mut Machines,
    cards: &mut Cards,
    quiet: Duration,
) -> Result<(bool, String), String> {
    let deadline = tokio::time::Instant::now() + WITHIN;
    let mut changed = tokio::time::Instant::now();
    loop {
        let matched = match (&cards.a, &cards.b) {
            (Some(PairingCheck::Show(n)), Some(PairingCheck::Pick(c))) if c.contains(n) => {
                Some((true, n.clone()))
            }
            (Some(PairingCheck::Pick(c)), Some(PairingCheck::Show(n))) if c.contains(n) => {
                Some((false, n.clone()))
            }
            _ => None,
        };
        let until = match &matched {
            Some(_) => (changed + quiet).min(deadline),
            None => deadline,
        };
        let (fp_a, fp_b) = (m.fp_a.clone(), m.fp_b.clone());
        let next = tokio::select! {
            e = m.fa.next() => e.map(|e| (true, e)),
            e = m.fb.next() => e.map(|e| (false, e)),
            () = tokio::time::sleep_until(until) => None,
        };
        let Some((from_a, Ok(event))) = next else {
            if let Some(found) = matched {
                return Ok(found);
            }
            return Err(format!(
                "the two machines never showed matching number cards (a: {:?}, b: \
                 {:?}); a's log:\n{}\nb's log:\n{}",
                cards.a,
                cards.b,
                m.adding.log(),
                m.added.log()
            ));
        };
        let card = match event {
            FrontendEvent::PairingCheck {
                fingerprint, check, ..
            } if (from_a && fingerprint == fp_b) || (!from_a && fingerprint == fp_a) => {
                Some(Some(check))
            }
            FrontendEvent::PairingEnded { fingerprint, .. }
                if (from_a && fingerprint == fp_b) || (!from_a && fingerprint == fp_a) =>
            {
                Some(None)
            }
            _ => None,
        };
        if let Some(card) = card {
            changed = tokio::time::Instant::now();
            if from_a {
                cards.a = card;
                cards.changes.0 += 1;
            } else {
                cards.b = card;
                cards.changes.1 += 1;
            }
        }
    }
}

// LEDGER G-20c | class B | 5 process: number cards, PairingEnded and device state from two built daemons
/// Both machines add each other at the same time, and each approves the
/// dial it made: the two answers make one pairing. One number is compared,
/// on one connection, and it stays on both screens while the people there
/// read it: each machine goes on dialling the other meanwhile, and nothing
/// replaces the number. Afterwards each machine's link to the other is up.
#[test]
fn machines_adding_each_other_pair() {
    machines("crossed", |mut m| async move {
        let mut failures: Vec<String> = Vec::new();
        ask(&mut m.ra, FrontendRequest::OpenPairing).await;
        ask(&mut m.rb, FrontendRequest::OpenPairing).await;
        let on_a = add_device(&mut m.fa, &mut m.ra, m.added.port).await;
        let on_b = add_device(&mut m.fb, &mut m.rb, m.adding.port).await;
        ask(&mut m.ra, FrontendRequest::Activate(on_a, true)).await;
        ask(&mut m.rb, FrontendRequest::Activate(on_b, true)).await;
        // The first dials of two daemons just started: given longer, as a
        // loaded test run can be slow to make them.
        let asked_a = until(
            &mut m.fa,
            WITHIN * 2,
            attempt_from(&m.fp_b, AttemptOrigin::OutboundDial),
        )
        .await;
        let asked_b = until(
            &mut m.fb,
            WITHIN * 2,
            attempt_from(&m.fp_a, AttemptOrigin::OutboundDial),
        )
        .await;
        if asked_a.is_none() || asked_b.is_none() {
            return vec![format!(
                "each machine's own dial did not raise a prompt there (a: {asked_a:?}, \
                 b: {asked_b:?}); a's log:\n{}\nb's log:\n{}",
                m.adding.log(),
                m.added.log()
            )];
        }
        // Together, so neither machine's knock reaches the other first.
        ask(&mut m.ra, approval("desk b", &m.fp_b, Controller::Both)).await;
        ask(&mut m.rb, approval("desk a", &m.fp_a, Controller::Both)).await;
        let mut cards = Cards::default();
        // Read as a person would: after the add dials, one a second, had
        // time to reach the other machine again.
        let (a_shows, number) = match complementary_cards(&mut m, &mut cards, QUIET).await {
            Ok(found) => found,
            Err(e) => return vec![e],
        };
        if cards.changes != (1, 1) {
            failures.push(format!(
                "the number cards changed while the people read them (a: {} changes, b: \
                 {}): one number card each, shown once, is what the people compare",
                cards.changes.0, cards.changes.1
            ));
        }
        // The machine picking answers first, then the one showing confirms.
        let (picker, shower, picker_peer, shower_peer) = if a_shows {
            (&mut m.rb, &mut m.ra, m.fp_a.clone(), m.fp_b.clone())
        } else {
            (&mut m.ra, &mut m.rb, m.fp_b.clone(), m.fp_a.clone())
        };
        ask(
            picker,
            FrontendRequest::ConfirmPairing {
                fingerprint: picker_peer,
                number: number.clone(),
            },
        )
        .await;
        ask(
            shower,
            FrontendRequest::ConfirmPairing {
                fingerprint: shower_peer,
                number,
            },
        )
        .await;
        let paired = |fp: String| {
            move |e: &FrontendEvent| match e {
                FrontendEvent::PairingEnded {
                    fingerprint,
                    paired,
                } if *fingerprint == fp => Some(*paired),
                _ => None,
            }
        };
        let a_paired = until(&mut m.fa, WITHIN, paired(m.fp_b.clone())).await;
        let b_paired = until(&mut m.fb, WITHIN, paired(m.fp_a.clone())).await;
        if a_paired != Some(true) || b_paired != Some(true) {
            failures.push(format!(
                "the machines adding each other did not both pair (a: {a_paired:?}, b: \
                 {b_paired:?}); a's log:\n{}\nb's log:\n{}",
                m.adding.log(),
                m.added.log()
            ));
            return failures;
        }
        for (who, events, handle) in [("a", &mut m.fa, on_a), ("b", &mut m.fb, on_b)] {
            let linked = until(events, WITHIN, |e| match e {
                FrontendEvent::State(h, _, s) if *h == handle && s.active_addr.is_some() => {
                    Some(())
                }
                _ => None,
            })
            .await;
            if linked.is_none() {
                failures.push(format!(
                    "machine {who} never took up its link to the other after pairing both ways"
                ));
            }
        }
        failures
    });
}

// LEDGER G-20d | class B | 5 process: number cards, PairingEnded and device state from two built daemons
/// The machine being added adds the other one too, while their number is on
/// screen. Its dial is turned away while the number is compared, so the
/// number stays, the pairing still finishes, both ways, and the machine
/// that added last takes up its link.
#[test]
fn adding_back_while_the_number_is_on_screen_still_pairs() {
    machines("takeover", |mut m| async move {
        let mut failures: Vec<String> = Vec::new();
        ask(&mut m.ra, FrontendRequest::OpenPairing).await;
        ask(&mut m.rb, FrontendRequest::OpenPairing).await;
        let on_a = add_device(&mut m.fa, &mut m.ra, m.added.port).await;
        ask(&mut m.ra, FrontendRequest::Activate(on_a, true)).await;
        if until(
            &mut m.fa,
            WITHIN,
            attempt_from(&m.fp_b, AttemptOrigin::OutboundDial),
        )
        .await
        .is_none()
        {
            return vec!["the adding machine's dial raised no prompt".into()];
        }
        ask(&mut m.ra, approval("desk b", &m.fp_b, Controller::Both)).await;
        if until(
            &mut m.fb,
            WITHIN,
            attempt_from(&m.fp_a, AttemptOrigin::Inbound),
        )
        .await
        .is_none()
        {
            return vec![format!(
                "the machine being added was never asked; its log:\n{}",
                m.added.log()
            )];
        }
        ask(&mut m.rb, approval("desk a", &m.fp_a, Controller::Both)).await;
        let mut cards = Cards::default();
        let first = match complementary_cards(&mut m, &mut cards, Duration::ZERO).await {
            Ok((_, number)) => number,
            Err(e) => return vec![e],
        };

        // Now the machine being added adds the other one too.
        let on_b = add_device(&mut m.fb, &mut m.rb, m.adding.port).await;
        ask(&mut m.rb, FrontendRequest::Activate(on_b, true)).await;
        // Long enough for its add dial to reach the other machine, twice.
        let (a_shows, number) = match complementary_cards(&mut m, &mut cards, QUIET).await {
            Ok(found) => found,
            Err(e) => return vec![e],
        };
        if number != first || cards.changes != (1, 1) {
            failures.push(format!(
                "adding back replaced the number on screen ({first} then {number}; a: {} \
                 changes, b: {})",
                cards.changes.0, cards.changes.1
            ));
        }
        let (picker, shower, picker_peer, shower_peer) = if a_shows {
            (&mut m.rb, &mut m.ra, m.fp_a.clone(), m.fp_b.clone())
        } else {
            (&mut m.ra, &mut m.rb, m.fp_b.clone(), m.fp_a.clone())
        };
        ask(
            picker,
            FrontendRequest::ConfirmPairing {
                fingerprint: picker_peer,
                number: number.clone(),
            },
        )
        .await;
        ask(
            shower,
            FrontendRequest::ConfirmPairing {
                fingerprint: shower_peer,
                number,
            },
        )
        .await;
        let paired = |fp: String| {
            move |e: &FrontendEvent| match e {
                FrontendEvent::PairingEnded {
                    fingerprint,
                    paired,
                } if *fingerprint == fp => Some(*paired),
                _ => None,
            }
        };
        let a_paired = until(&mut m.fa, WITHIN, paired(m.fp_b.clone())).await;
        let b_paired = until(&mut m.fb, WITHIN, paired(m.fp_a.clone())).await;
        if a_paired != Some(true) || b_paired != Some(true) {
            failures.push(format!(
                "adding back mid-comparison did not pair both machines (a: {a_paired:?}, \
                 b: {b_paired:?}); a's log:\n{}\nb's log:\n{}",
                m.adding.log(),
                m.added.log()
            ));
            return failures;
        }
        let linked = until(&mut m.fb, WITHIN, |e| match e {
            FrontendEvent::State(h, _, s) if *h == on_b && s.active_addr.is_some() => Some(()),
            _ => None,
        })
        .await;
        if linked.is_none() {
            failures.push(format!(
                "the machine that added back never took up its link to the other; its \
                 log:\n{}",
                m.added.log()
            ));
        }
        failures
    });
}

// LEDGER G-20e | class B | 5 process: number cards, PairingEnded, notices and device state from two built daemons
/// Two machines whose people answer that one of them controls the other,
/// adding each other: the machine that adds first is the one controlled,
/// and the machine in control adds it back while the number is on screen.
/// One number pairs them. The machine in control takes up its link; the
/// connection the controlled machine dialled carries nothing and closes, its
/// device for the other never connects, and it says why.
#[test]
fn opposite_answers_link_only_the_way_control_goes() {
    machines("opposite", |mut m| async move {
        let mut failures: Vec<String> = Vec::new();
        ask(&mut m.ra, FrontendRequest::OpenPairing).await;
        ask(&mut m.rb, FrontendRequest::OpenPairing).await;
        let on_a = add_device(&mut m.fa, &mut m.ra, m.added.port).await;
        ask(&mut m.ra, FrontendRequest::Activate(on_a, true)).await;
        if until(
            &mut m.fa,
            WITHIN,
            attempt_from(&m.fp_b, AttemptOrigin::OutboundDial),
        )
        .await
        .is_none()
        {
            return vec!["the adding machine's dial raised no prompt".into()];
        }
        ask(
            &mut m.ra,
            approval("desk b", &m.fp_b, Controller::ThatMachine),
        )
        .await;
        if until(
            &mut m.fb,
            WITHIN,
            attempt_from(&m.fp_a, AttemptOrigin::Inbound),
        )
        .await
        .is_none()
        {
            return vec![format!(
                "the machine being added was never asked; its log:\n{}",
                m.added.log()
            )];
        }
        ask(
            &mut m.rb,
            approval("desk a", &m.fp_a, Controller::ThisMachine),
        )
        .await;
        let mut cards = Cards::default();
        let first = match complementary_cards(&mut m, &mut cards, Duration::ZERO).await {
            Ok((_, number)) => number,
            Err(e) => return vec![e],
        };
        let on_b = add_device(&mut m.fb, &mut m.rb, m.adding.port).await;
        ask(&mut m.rb, FrontendRequest::Activate(on_b, true)).await;
        let (a_shows, number) = match complementary_cards(&mut m, &mut cards, QUIET).await {
            Ok(found) => found,
            Err(e) => return vec![e],
        };
        if !a_shows || number != first || cards.changes != (1, 1) {
            failures.push(format!(
                "the number the machine adding first showed did not stay ({first} then \
                 {number}, shown there: {a_shows}; a: {} changes, b: {})",
                cards.changes.0, cards.changes.1
            ));
        }
        ask(
            &mut m.rb,
            FrontendRequest::ConfirmPairing {
                fingerprint: m.fp_a.clone(),
                number: number.clone(),
            },
        )
        .await;
        ask(
            &mut m.ra,
            FrontendRequest::ConfirmPairing {
                fingerprint: m.fp_b.clone(),
                number,
            },
        )
        .await;
        let paired = |fp: String| {
            move |e: &FrontendEvent| match e {
                FrontendEvent::PairingEnded {
                    fingerprint,
                    paired,
                } if *fingerprint == fp => Some(*paired),
                _ => None,
            }
        };
        let b_paired = until(&mut m.fb, WITHIN, paired(m.fp_a.clone())).await;
        // a's events are read below, whole, for its link and its notice.
        if b_paired != Some(true) {
            failures.push(format!(
                "the machine in control did not pair ({b_paired:?}); its log:\n{}",
                m.added.log()
            ));
            return failures;
        }
        let linked = until(&mut m.fb, WITHIN, |e| match e {
            FrontendEvent::State(h, _, s) if *h == on_b && s.active_addr.is_some() => Some(()),
            _ => None,
        })
        .await;
        if linked.is_none() {
            failures.push(format!(
                "the machine in control never took up its link to the machine it controls; \
                 its log:\n{}",
                m.added.log()
            ));
        }
        // Everything a says until its notice, and for a while after: its
        // device for b must never be linked in that time.
        let (mut a_paired, mut told, mut a_linked) = (None, false, false);
        let mut deadline = tokio::time::Instant::now() + WITHIN;
        while let Ok(Some(event)) = tokio::time::timeout_at(deadline, m.fa.next()).await {
            match event {
                Ok(FrontendEvent::PairingEnded {
                    fingerprint,
                    paired,
                }) if fingerprint == m.fp_b => a_paired = Some(paired),
                Ok(FrontendEvent::State(h, _, s)) if h == on_a && s.active_addr.is_some() => {
                    a_linked = true;
                }
                Ok(FrontendEvent::Activity(text)) if !told && text.contains("does not control") => {
                    told = true;
                    deadline = tokio::time::Instant::now() + QUIET;
                }
                _ => {}
            }
        }
        if a_paired != Some(true) {
            failures.push(format!(
                "the machine controlled did not pair ({a_paired:?}); its log:\n{}",
                m.adding.log()
            ));
        }
        if a_linked {
            failures.push(
                "the machine controlled took up a link to the machine that controls it: its \
                 input could reach a machine nobody chose it to control"
                    .into(),
            );
        }
        if !told {
            failures.push(
                "the machine controlled never said why its device for the other does not \
                 connect"
                    .into(),
            );
        }
        failures
    });
}

//! A macOS permission granted while the daemon runs reaches the daemon
//! (#221), end to end: the whole daemon runs in this process, and only the
//! permission checks and launchd's answer are scripted.
//!
//! Its every file is in a scratch directory, its QUIC listener is on
//! loopback, capture and emulation are the dummy backends or ones that are
//! never created, and discovery is off. Its watch is the one a daemon starts
//! with on a Mac. A side's status changes reach the daemon through its own
//! handlers; what it does then is observed where a user would see it:
//! whether `Service::run` returns, with what, and what a frontend connected
//! over the real IPC socket is told.

use super::{Service, ServiceError};
use crate::capture::ICaptureEvent;
use crate::emulation::EmulationEvent;
use crate::permission_watch::{Permission, PermissionWatch};
use crate::test_harness::run_local;
use hops_ipc::{
    AsyncFrontendListener, CaptureState, DaemonEndpoint, EmulationFault, EmulationState,
    FrontendEvent,
};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

/// How often the scripted watch checks.
const EVERY: Duration = Duration::from_millis(20);
/// What must happen is waited for this long at most.
const DEADLINE: Duration = Duration::from_secs(30);
/// What must not happen is watched for this long: many checks' worth.
const NOTHING_FOR: Duration = Duration::from_millis(500);

/// The permissions macOS reports: `denied` are missing until granted.
struct System {
    denied: Mutex<Vec<Permission>>,
    asked: AtomicUsize,
    /// Every permission asked about.
    asked_for: Mutex<BTreeSet<Permission>>,
}

impl System {
    fn new(denied: &[Permission]) -> Arc<Self> {
        Arc::new(Self {
            denied: Mutex::new(denied.to_vec()),
            asked: AtomicUsize::new(0),
            asked_for: Mutex::new(BTreeSet::new()),
        })
    }

    /// Switched off in System Settings.
    fn deny(&self, permission: Permission) {
        self.denied.lock().expect("lock").push(permission);
    }

    fn grant(&self, permission: Permission) {
        self.denied
            .lock()
            .expect("lock")
            .retain(|&p| p != permission);
    }

    fn grant_all(&self) {
        self.denied.lock().expect("lock").clear();
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }

    /// Resolves once the permissions have been asked `times` times in all.
    async fn asked_at_least(&self, times: usize) {
        while self.asked() < times {
            tokio::time::sleep(EVERY).await;
        }
    }
}

/// The scratch directory, removed with it, and the recording an emulation
/// stand-in writes to, kept for as long as the daemon runs.
struct Scratch {
    dir: PathBuf,
    endpoint: DaemonEndpoint,
    _recording: Option<input_emulation::recording::Recording>,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The backends a daemon is given.
#[derive(Clone, Copy)]
enum Backends {
    /// The dummy ones, which start.
    Dummy,
    /// Ones that fail as they are created, as the macOS ones do while a
    /// permission is missing: neither side ever says it started or stopped.
    NeverCreated,
    /// Dummy capture, and emulation that needs Accessibility while it runs,
    /// as the macOS backend does.
    MacEmulation,
}

impl Backends {
    fn chosen(
        self,
    ) -> (
        input_capture::Backend,
        input_emulation::Backend,
        Option<input_emulation::recording::Recording>,
    ) {
        match self {
            Self::Dummy => (
                input_capture::Backend::Dummy,
                input_emulation::Backend::Dummy,
                None,
            ),
            // Each names a script that is gone by the time it is created.
            Self::NeverCreated => (
                input_capture::scripted::Script::new().backend(),
                input_emulation::recording::Recording::new().backend(),
                None,
            ),
            Self::MacEmulation => {
                let recording = input_emulation::recording::Recording::new();
                recording.needs_accessibility();
                (
                    input_capture::Backend::Dummy,
                    recording.backend(),
                    Some(recording),
                )
            }
        }
    }
}

/// A daemon whose permissions `system` reports, and which launchd starts
/// again after a failure when `restarts`.
async fn daemon(
    tag: &str,
    system: &Arc<System>,
    restarts: bool,
    backends: Backends,
) -> (Service, Scratch) {
    // Short, for a socket path in it (`sun_path`).
    let dir = PathBuf::from(format!("/tmp/h-pg-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        "port = 0\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n",
    )
    .expect("a config");
    let endpoint = DaemonEndpoint::Unix(dir.join("s.sock"));
    let (capture, emulation, recording) = backends.chosen();
    let scratch = Scratch {
        dir: dir.clone(),
        endpoint: endpoint.clone(),
        _recording: recording,
    };
    let frontends = AsyncFrontendListener::at_with_token_file(&endpoint, &dir.join("ipc-token"))
        .await
        .expect("the scratch endpoint");
    let config = crate::config::Config::in_scratch(&config, &dir.join("hops.pem"))
        .expect("the scratch config");
    let mut service = Service::with_backends(config, frontends, Some(capture), Some(emulation))
        .await
        .expect("a daemon in the scratch directory");

    let probe = system.clone();
    service.permission_watch = PermissionWatch::at_daemon_start(
        Arc::new(move |p| {
            probe.asked.fetch_add(1, Ordering::SeqCst);
            probe.asked_for.lock().expect("lock").insert(p);
            !probe.denied.lock().expect("lock").contains(&p)
        }),
        Arc::new(move || restarts),
        EVERY,
    );
    (service, scratch)
}

/// Hand the daemon its backends' events, as its loop does, until both
/// sides run.
async fn until_both_run(service: &mut Service) {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while service.capture_status != CaptureState::Enabled
        || service.emulation_status != EmulationState::Enabled
    {
        tokio::select! {
            event = service.capture.event() => service.handle_capture_event(event),
            event = service.emulation.event() => service.handle_emulation_event(event),
            _ = tokio::time::sleep_until(deadline) => panic!(
                "the dummy backends never both came up: capture {:?}, emulation {:?}",
                service.capture_status, service.emulation_status
            ),
        }
    }
}

/// End a daemon whose loop a test stopped before it ended, as the loop's own
/// end does, so its tasks do not outlive it.
async fn shut_down(mut service: Service) {
    service.capture.terminate().await;
    service.emulation.terminate().await;
    service.resolver.terminate().await;
}

/// A frontend connected to the daemon over its IPC socket.
struct Frontend {
    lines: tokio::io::Lines<BufReader<tokio::net::UnixStream>>,
}

impl Frontend {
    async fn connect(scratch: &Scratch) -> Self {
        let DaemonEndpoint::Unix(path) = &scratch.endpoint else {
            unreachable!("a unix socket")
        };
        let token = std::fs::read_to_string(scratch.dir.join("ipc-token")).expect("the token");
        let mut stream = tokio::net::UnixStream::connect(path)
            .await
            .expect("the daemon's socket");
        {
            let (rx, mut tx) = stream.split();
            let mut rx = BufReader::new(rx);
            hops_ipc::prove_to_daemon(&mut rx, &mut tx, token.trim())
                .await
                .expect("the two-way proof is made");
        }
        Self {
            lines: BufReader::new(stream).lines(),
        }
    }

    /// The first emulation failure it is told of; `None` once the daemon
    /// hangs up.
    async fn emulation_failed(&mut self) -> Option<EmulationFault> {
        while let Ok(Some(line)) = self.lines.next_line().await {
            if let Ok(FrontendEvent::EmulationStatus(EmulationState::Failed(fault))) =
                serde_json::from_str(&line)
            {
                return Some(fault);
            }
        }
        None
    }

    /// Whether it is told emulation runs before the daemon hangs up.
    async fn emulation_enabled(&mut self) -> bool {
        while let Ok(Some(line)) = self.lines.next_line().await {
            if let Ok(FrontendEvent::EmulationStatus(EmulationState::Enabled)) =
                serde_json::from_str(&line)
            {
                return true;
            }
        }
        false
    }

    /// The next error notice it is sent; `None` once the daemon hangs up.
    async fn next_notice(&mut self) -> Option<String> {
        while let Ok(Some(line)) = self.lines.next_line().await {
            if let Ok(FrontendEvent::Error(text)) = serde_json::from_str(&line) {
                return Some(text);
            }
        }
        None
    }
}

/// Emulation stopped because macOS had taken Accessibility away. Once it is
/// granted, the daemon ends with the error that exits unsuccessfully, so
/// that launchd, which restarts it only after a failure, starts a fresh one.
// LEDGER T2242 | class B | 1 return value of Service::run, the whole daemon in-process
#[test]
fn a_grant_to_a_side_that_stopped_ends_the_daemon_for_launchd_to_start_again() {
    run_local(async {
        let system = System::new(&[Permission::Accessibility, Permission::InputMonitoring]);
        let (mut service, _scratch) = daemon("exit", &system, true, Backends::Dummy).await;
        until_both_run(&mut service).await;
        service.handle_emulation_event(EmulationEvent::EmulationDisabled);

        let granter = async {
            // Seen missing twice, then granted.
            system.asked_at_least(4).await;
            system.grant(Permission::Accessibility);
            std::future::pending::<()>().await
        };
        let ended = tokio::select! {
            ended = service.run() => Some(ended),
            _ = granter => None,
            _ = tokio::time::sleep(DEADLINE) => None,
        };
        assert!(
            matches!(
                &ended,
                Some(Err(ServiceError::PermissionGranted(granted)))
                    if granted == input_event::settings_pane::accessibility()
            ),
            "Accessibility was granted after emulation stopped for want of it, and \
             launchd restarts the daemon only after it fails. The daemon must end with \
             the error that exits 1; ending cleanly leaves no daemon until the next \
             login, and not ending leaves emulation off. It ended with {ended:?} \
             (None: it did not end), the permissions asked {} times.",
            system.asked()
        );
    });
}

/// A daemon started without its permissions: macOS refuses both backends,
/// so neither side is ever created, and neither says it stopped. Once the
/// permissions are granted, the daemon ends with the error that exits
/// unsuccessfully, as for a side that stopped while it ran. This is the
/// first start after an install.
// LEDGER T2254 | class B | 1 return value of Service::run, the whole daemon in-process
#[test]
fn a_daemon_started_without_the_permissions_ends_once_they_are_granted() {
    run_local(async {
        let system = System::new(&[Permission::Accessibility, Permission::InputMonitoring]);
        let (mut service, _scratch) = daemon("start", &system, true, Backends::NeverCreated).await;

        let granter = async {
            // Both sides seen missing twice, then granted.
            system.asked_at_least(6).await;
            system.grant_all();
            std::future::pending::<()>().await
        };
        let ended = tokio::select! {
            ended = service.run() => Some(ended),
            _ = granter => None,
            _ = tokio::time::sleep(DEADLINE) => None,
        };
        let ran = (
            service.capture_status.is_enabled(),
            service.emulation_status.is_enabled(),
        );
        assert_eq!(
            ran,
            (false, false),
            "a backend was created, so this did not test a daemon that never started one"
        );
        assert!(
            matches!(
                &ended,
                Some(Err(ServiceError::PermissionGranted(granted)))
                    if *granted == format!(
                        "{} and Input Monitoring",
                        input_event::settings_pane::accessibility()
                    )
            ),
            "Accessibility and Input Monitoring were granted to a daemon that started \
             without them. It must end with the error that exits 1, so launchd starts \
             one that has them; otherwise input stays off until the next login. It \
             ended with {ended:?} (None: it did not end), the permissions asked {} times.",
            system.asked()
        );
    });
}

/// Capture stopped for want of Input Monitoring, and launchd did not start
/// this daemon. Once it is granted, the daemon keeps running and tells the
/// user a restart is what applies it.
// LEDGER T2243 | class B | 2 event over the real IPC socket + 1 Service::run still running
#[test]
fn a_grant_to_a_daemon_launchd_does_not_restart_is_told_and_the_daemon_runs_on() {
    run_local(async {
        let system = System::new(&[Permission::InputMonitoring]);
        let (mut service, scratch) = daemon("tell", &system, false, Backends::Dummy).await;
        until_both_run(&mut service).await;
        service.handle_capture_event(ICaptureEvent::CaptureDisabled);

        let told = async {
            let mut frontend = Frontend::connect(&scratch).await;
            system.asked_at_least(4).await;
            system.grant(Permission::InputMonitoring);
            loop {
                match frontend.next_notice().await {
                    Some(text) if text.contains("now grants hops") => return text,
                    Some(_) => {}
                    None => panic!("the daemon closed the frontend's connection"),
                }
            }
        };
        let told = tokio::select! {
            ended = service.run() => panic!(
                "the daemon ended ({ended:?}) although nothing would start it again"
            ),
            told = told => told,
            _ = tokio::time::sleep(DEADLINE) => panic!(
                "Input Monitoring was granted after capture stopped for want of it, \
                 and the frontend was never told; the permissions were asked {} times",
                system.asked()
            ),
        };
        shut_down(service).await;
        assert!(
            told.starts_with("macOS now grants hops Input Monitoring.")
                && told.contains("restarts"),
            "the notice must say what was granted and that a restart applies it: {told:?}"
        );
    });
}

/// A side that runs is watched only for what it would lose: Accessibility,
/// while emulation runs (#240). A grant never ends a daemon whose sides
/// run: nothing was missing that a restart would bring.
// LEDGER T2244 | class B | 1 Service::run still running + 6 checks the scripted system saw
#[test]
fn sides_that_run_are_watched_only_for_what_they_would_lose() {
    run_local(async {
        let system = System::new(&[Permission::InputMonitoring, Permission::PostEvents]);
        let (mut service, _scratch) = daemon("runs", &system, true, Backends::MacEmulation).await;
        until_both_run(&mut service).await;

        let granter = async {
            tokio::time::sleep(NOTHING_FOR / 2).await;
            system.grant_all();
            tokio::time::sleep(NOTHING_FOR / 2).await;
        };
        let ended = tokio::select! {
            ended = service.run() => Some(ended),
            _ = granter => None,
        };
        let running = service.emulation_status.is_enabled();
        if ended.is_none() {
            shut_down(service).await;
        }
        let asked_for: Vec<Permission> = system
            .asked_for
            .lock()
            .expect("lock")
            .iter()
            .copied()
            .collect();
        assert_eq!(
            (ended.is_some(), running, asked_for),
            (false, true, vec![Permission::Accessibility]),
            "(the daemon ended, emulation still runs, permissions asked) with both \
             sides running and Accessibility granted throughout. Only Accessibility \
             is asked while they run, and a grant must not end a daemon that needs \
             no restart. Ended with {ended:?}."
        );
    });
}

/// Accessibility is switched off while emulation runs on a Mac that is
/// only ever controlled. The app must be told emulation failed for want of
/// it, as when it cannot start, rather than show it on while macOS drops
/// what it posts (#240). Switched on again, the daemon ends for launchd to
/// start it with the grant, as after any grant.
// LEDGER T2437 | class B | 2 EmulationStatus over the real IPC socket + 1 return value of Service::run
#[test]
fn accessibility_switched_off_while_emulation_runs_reaches_the_app_and_its_grant_restarts() {
    run_local(async {
        let system = System::new(&[]);
        let (mut service, scratch) = daemon("revoke", &system, true, Backends::MacEmulation).await;
        until_both_run(&mut service).await;

        let told = RefCell::new(None);
        let script = async {
            let mut frontend = Frontend::connect(&scratch).await;
            // Checked while granted first.
            system.asked_at_least(2).await;
            system.deny(Permission::Accessibility);
            *told.borrow_mut() = frontend.emulation_failed().await;
            system.grant_all();
            std::future::pending::<()>().await
        };
        let ended = tokio::select! {
            ended = service.run() => Some(ended),
            _ = script => None,
            _ = tokio::time::sleep(DEADLINE) => None,
        };
        assert_eq!(
            told.into_inner(),
            Some(EmulationFault::Missing(vec![
                hops_ipc::Permission::Accessibility
            ])),
            "Accessibility was switched off while emulation ran; the app must be told \
             emulation failed for want of it (None: it was never told). The \
             permissions were asked {} times.",
            system.asked()
        );
        assert!(
            matches!(
                &ended,
                Some(Err(ServiceError::PermissionGranted(granted)))
                    if granted == input_event::settings_pane::accessibility()
            ),
            "Accessibility was switched on again; the daemon must end with the error \
             that exits 1, so launchd starts it with the grant. It ended with \
             {ended:?} (None: it did not end)."
        );
    });
}

/// Emulation through `dummy`, chosen on purpose, needs no permission and
/// posts nothing, so a refused probe must not stop it: it starts and stays
/// running on a Mac that does not grant hops Accessibility.
// LEDGER T2438 | class B | 6 Service::emulation_status + 2 what a frontend is told over the real IPC socket
#[test]
fn dummy_emulation_keeps_running_without_accessibility() {
    run_local(async {
        let system = System::new(&[Permission::Accessibility, Permission::PostEvents]);
        let (mut service, scratch) = daemon("dummy", &system, true, Backends::Dummy).await;
        until_both_run(&mut service).await;

        let failed = RefCell::new(None);
        let watched = async {
            let mut frontend = Frontend::connect(&scratch).await;
            *failed.borrow_mut() = frontend.emulation_failed().await;
        };
        let ended = tokio::select! {
            ended = service.run() => Some(ended),
            _ = watched => None,
            _ = tokio::time::sleep(NOTHING_FOR) => None,
        };
        let running = service.emulation_status.is_enabled();
        if ended.is_none() {
            shut_down(service).await;
        }
        assert_eq!(
            (ended.is_some(), running, failed.into_inner()),
            (false, true, None),
            "(the daemon ended, emulation still runs, the failure the app was told) \
             for dummy emulation on a Mac without Accessibility. Ended with {ended:?}."
        );
    });
}

/// Accessibility switched back on, and launchd did not start this daemon:
/// emulation, which stopped for want of it, starts again in this process,
/// as "enable input" would start it.
// LEDGER T2439 | class B | 2 EmulationStatus over the real IPC socket + 1 Service::run still running
#[test]
fn a_grant_to_a_daemon_launchd_does_not_restart_starts_emulation_again() {
    run_local(async {
        let system = System::new(&[]);
        let (mut service, scratch) = daemon("again", &system, false, Backends::MacEmulation).await;
        until_both_run(&mut service).await;

        let script = async {
            let mut frontend = Frontend::connect(&scratch).await;
            system.asked_at_least(2).await;
            system.deny(Permission::Accessibility);
            let failed = frontend.emulation_failed().await;
            system.grant_all();
            (failed, frontend.emulation_enabled().await)
        };
        let (failed, enabled) = tokio::select! {
            ended = service.run() => panic!(
                "the daemon ended ({ended:?}) although nothing would start it again"
            ),
            seen = script => seen,
            _ = tokio::time::sleep(DEADLINE) => (None, false),
        };
        shut_down(service).await;
        assert_eq!(
            (failed.is_some(), enabled),
            (true, true),
            "(emulation was stopped for want of Accessibility, it ran again once \
             granted) in a daemon launchd does not restart"
        );
    });
}

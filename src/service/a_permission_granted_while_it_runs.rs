//! A macOS permission granted while the daemon runs reaches the daemon
//! (#221), end to end: the whole daemon runs in this process, and only the
//! permission checks and launchd's answer are scripted.
//!
//! Its every file is in a scratch directory, its QUIC listener is on
//! loopback, capture and emulation are the dummy backends, and discovery is
//! off. Both sides start out stopped, as on a Mac. A side's status changes
//! reach the daemon through its own handlers; what it does then is observed
//! where a user would see it: whether `Service::run` returns, with what, and
//! what a frontend connected over the real IPC socket is told.

use super::{Service, ServiceError};
use crate::capture::ICaptureEvent;
use crate::emulation::EmulationEvent;
use crate::permission_watch::{Permission, PermissionWatch, Side};
use crate::test_harness::run_local;
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint, FrontendEvent, Status};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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
}

impl System {
    fn new(denied: &[Permission]) -> Arc<Self> {
        Arc::new(Self {
            denied: Mutex::new(denied.to_vec()),
            asked: AtomicUsize::new(0),
        })
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

/// The scratch directory, removed with it.
struct Scratch {
    dir: PathBuf,
    endpoint: DaemonEndpoint,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A daemon whose permissions `system` reports, and which launchd starts
/// again after a failure when `restarts`.
async fn daemon(tag: &str, system: &Arc<System>, restarts: bool) -> (Service, Scratch) {
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
    let scratch = Scratch {
        dir: dir.clone(),
        endpoint: endpoint.clone(),
    };
    let frontends = AsyncFrontendListener::at_with_token_file(&endpoint, &dir.join("ipc-token"))
        .await
        .expect("the scratch endpoint");
    let config = crate::config::Config::in_scratch(&config, &dir.join("hops.pem"))
        .expect("the scratch config");
    let mut service = Service::new(config, frontends)
        .await
        .expect("a daemon in the scratch directory");

    let probe = system.clone();
    let mut watch = PermissionWatch::new(
        Arc::new(move |p| {
            probe.asked.fetch_add(1, Ordering::SeqCst);
            !probe.denied.lock().expect("lock").contains(&p)
        }),
        Arc::new(move || restarts),
        EVERY,
    );
    watch.stopped(Side::Capture);
    watch.stopped(Side::Emulation);
    service.permission_watch = watch;
    (service, scratch)
}

/// Hand the daemon its backends' events, as its loop does, until both
/// sides run.
async fn until_both_run(service: &mut Service) {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while service.capture_status != Status::Enabled || service.emulation_status != Status::Enabled {
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
        stream
            .write_all(format!("{}\n", token.trim()).as_bytes())
            .await
            .expect("the token is sent");
        Self {
            lines: BufReader::new(stream).lines(),
        }
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
        let (mut service, _scratch) = daemon("exit", &system, true).await;
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
                Some(Err(ServiceError::PermissionGranted(granted))) if granted == "Accessibility"
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

/// Capture stopped for want of Input Monitoring, and launchd did not start
/// this daemon. Once it is granted, the daemon keeps running and tells the
/// user a restart is what applies it.
// LEDGER T2243 | class B | 2 event over the real IPC socket + 1 Service::run still running
#[test]
fn a_grant_to_a_daemon_launchd_does_not_restart_is_told_and_the_daemon_runs_on() {
    run_local(async {
        let system = System::new(&[Permission::InputMonitoring]);
        let (mut service, scratch) = daemon("tell", &system, false).await;
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

/// A side that runs is not watched, whatever the checks would say: the
/// daemon neither checks for it nor ends when its permissions change.
// LEDGER T2244 | class B | 1 Service::run still running + 6 checks the scripted system saw
#[test]
fn sides_that_run_are_not_watched() {
    run_local(async {
        let system = System::new(&[
            Permission::Accessibility,
            Permission::InputMonitoring,
            Permission::PostEvents,
        ]);
        let (mut service, _scratch) = daemon("runs", &system, true).await;
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
        if ended.is_none() {
            shut_down(service).await;
        }
        assert_eq!(
            (ended.is_some(), system.asked()),
            (false, 0),
            "(the daemon ended, permissions asked) with both sides running. A side \
             that reports it runs must no longer be watched: its checks cost the \
             system every few seconds, and a grant would end a daemon that needs \
             no restart. Ended with {ended:?}."
        );
    });
}

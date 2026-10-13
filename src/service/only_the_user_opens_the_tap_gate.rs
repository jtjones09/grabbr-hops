//! Only the user opens the daemon's tap gate (#243, #169): the enable
//! requests the app sends when the user clicks enable input or open
//! settings. Whatever the daemon does on its own, starting with a device
//! switched on, a frontend connecting and syncing, and trying both sides
//! again after a grant it cannot restart for, leaves it closed, so a launch
//! creates no event tap and raises no macOS dialog.
//!
//! The whole daemon runs in this process with its own gate; capture and
//! emulation are backends that are never created, as the macOS ones are
//! while a permission is missing, and the permission checks are scripted.

use super::in_process::Daemon;
use crate::permission_watch::PermissionWatch;
use crate::test_harness::run_local;
use hops_ipc::{FrontendEvent, FrontendRequest};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A device switched on at start; nothing answers on port 9.
const SWITCHED_ON: &str = "[[clients]]\nhostname = \"desk-pc\"\nposition = \"left\"\n\
    ips = [\"127.0.0.1\"]\nport = 9\nactivate_on_startup = true\n";

/// What must happen is waited for this long at most.
const DEADLINE: Duration = Duration::from_secs(30);

/// Whether the gate of a daemon that started with a device switched on,
/// was synced by a frontend, and was told of a grant it cannot restart for
/// (so it tried both sides again itself) is open before and after the
/// frontend sends `request`.
fn gate_around(tag: &str, request: FrontendRequest) -> (bool, bool, bool) {
    run_local(async move {
        let mut daemon = Daemon::start_capturing(
            tag,
            SWITCHED_ON,
            input_capture::scripted::Script::new().backend(),
            input_emulation::recording::Recording::new().backend(),
        )
        .await;
        // Missing for a few checks, then granted; launchd would not restart
        // this daemon, so it tries capture and emulation again on its own.
        let checks = Arc::new(AtomicUsize::new(0));
        let counted = checks.clone();
        daemon.watch_permissions_with(PermissionWatch::at_daemon_start(
            Arc::new(move |_| counted.fetch_add(1, Ordering::SeqCst) >= 9),
            Arc::new(|| false),
            Duration::from_millis(20),
        ));
        let (gate, ipc) = (daemon.tap_gate(), daemon.ipc());
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let deadline = tokio::time::Instant::now() + DEADLINE;
                let mut retried = false;
                while !retried && tokio::time::Instant::now() < deadline {
                    let events = app
                        .exchange(&[FrontendRequest::Sync, FrontendRequest::Enumerate()])
                        .await;
                    retried = events.iter().any(
                        |e| matches!(e, FrontendEvent::Error(text) if text.contains("now grants")),
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let before = gate.is_open();
                app.exchange(&[request]).await;
                (retried, before, gate.is_open())
            })
            .await
    })
}

// LEDGER T2454 | class B | 6 Service tap gate state, driven over the real IPC socket and the daemon's own loop
/// Each enable request opens the gate; nothing the daemon or a frontend
/// does on its own does.
#[test]
fn only_an_enable_request_opens_the_tap_gate() {
    let got = [
        gate_around("gate-cap", FrontendRequest::EnableCapture),
        gate_around("gate-emu", FrontendRequest::EnableEmulation),
    ];
    assert_eq!(
        got,
        [(true, false, true), (true, false, true)],
        "(the daemon retried both sides after a grant, gate open before the request, \
         after it) for EnableCapture and EnableEmulation. Start-up with a device \
         switched on, a frontend's sync and the daemon's own retry must not open \
         it; the user's request must"
    );
}

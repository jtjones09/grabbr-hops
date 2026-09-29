//! The built daemon on a Mac holds the real power assertion while a paired
//! device may control it, and none with nothing paired.
//!
//! Runs the hops binary as it runs in use, with `GRABBR_KEEP_AWAKE` unset,
//! and reads what the system lists for the daemon's process. The pairing is
//! made through the config tables an upgrade reads.
#![cfg(target_os = "macos")]

mod common;

use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{FrontendEvent, FrontendRequest};
use input_emulation::macos_keep_awake::{ASSERTION_NAME, held_by};

/// Generous: a daemon started under a loaded test run can be slow.
const DEADLINE: Duration = Duration::from_secs(30);

/// The hops assertions the process `pid` holds, by type.
fn hops_assertions(pid: u32) -> Vec<String> {
    held_by(pid)
        .into_iter()
        .filter(|(_, name)| name == ASSERTION_NAME)
        .map(|(kind, _)| kind)
        .collect()
}

// LEDGER KA-9 | class B | 5 process: IOPMCopyAssertionsByProcess for the built daemon's pid
#[tokio::test(flavor = "current_thread")]
async fn the_daemon_holds_the_assertion_only_while_something_may_control_it() {
    let peer = common::Identity::new();
    let fingerprint = peer.fingerprint();

    // Paired with a device that may control this Mac.
    let (paired, _) = common::start_with(
        common::ports::pick,
        "h-awake-p",
        &format!("[authorized_fingerprints]\n\"{fingerprint}\" = \"desk pc\"\n"),
        common::Power::AsInUse,
    );
    let until = Instant::now() + DEADLINE;
    loop {
        let held = hops_assertions(paired.pid());
        if held == ["PreventUserIdleSystemSleep"] {
            break;
        }
        assert!(
            Instant::now() < until,
            "the daemon paired with a controlling device holds {held:?}, not one \
             PreventUserIdleSystemSleep; log:\n{}",
            paired.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(paired);

    // Nothing paired. A barrier answered over the frontend channel means the
    // daemon's loop has settled the assertion at least once.
    let (lone, _) =
        common::start_with(common::ports::pick, "h-awake-n", "", common::Power::AsInUse);
    let (mut events, mut requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
        .await
        .expect("a frontend connects");
    requests
        .request(FrontendRequest::Barrier(9))
        .await
        .expect("the barrier is sent");
    tokio::time::timeout(DEADLINE, async {
        while let Some(event) = events.next().await {
            if let Ok(FrontendEvent::Barrier(9)) = event {
                return;
            }
        }
        panic!(
            "the daemon closed the frontend channel; log:\n{}",
            lone.log()
        );
    })
    .await
    .unwrap_or_else(|_| panic!("the barrier was never answered; log:\n{}", lone.log()));
    assert_eq!(
        hops_assertions(lone.pid()),
        Vec::<String>::new(),
        "the daemon with nothing paired holds a power assertion; log:\n{}",
        lone.log()
    );
}

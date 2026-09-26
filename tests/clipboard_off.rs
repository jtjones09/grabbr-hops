//! Turning a paired machine's clipboard off reaches the app at once, and it
//! is still off after the daemon restarts (#182, #187).
//!
//! Runs the built daemon. The paired machine is carried forward from the
//! config tables an upgrade reads, which pairs it the way every machine paired
//! before #182 is: it may drive this one, and its clipboard arrives here. The
//! frontend is the real IPC connector.
#![cfg(unix)]

mod common;

use std::time::Duration;

use hops_ipc::{
    AsyncFrontendEventReader, AsyncFrontendRequestWriter, FrontendEvent, FrontendRequest, PeerTrust,
};

const WAIT: Duration = Duration::from_secs(10);

/// A paired machine, "desk mac".
const DESK_MAC: &str = "1e:19:1b:c4:a8:40:f5:26:37:39:9d:c7:c7:75:fe:17:\
4f:03:d5:a9:76:49:cd:b1:12:d1:2f:6c:1f:d2:22:c5";

const OFF: PeerTrust = PeerTrust {
    clipboard_from: false,
    clipboard_to: false,
};

async fn attach() -> (AsyncFrontendEventReader, AsyncFrontendRequestWriter) {
    let (events, mut requests) = hops_ipc::connect_async(Some(WAIT))
        .await
        .expect("a frontend connects");
    requests
        .request(FrontendRequest::Sync)
        .await
        .expect("a sync request");
    (events, requests)
}

/// The next clipboard the daemon reports for the paired machine that `want`
/// accepts, or the last one it reported if none is accepted in time.
async fn reported(
    events: &mut AsyncFrontendEventReader,
    want: impl Fn(PeerTrust) -> bool,
) -> Option<PeerTrust> {
    let mut last = None;
    common::next_matching(events, WAIT, |e| match e {
        FrontendEvent::TrustUpdated(map) => {
            last = map.get(DESK_MAC).copied();
            last.filter(|t| want(*t))
        }
        _ => None,
    })
    .await
    .or(last)
}

// LEDGER E2A-9 | class B | 5 process: FrontendRequest::DisableClipboard into the built daemon, FrontendEvent::TrustUpdated from it, across a restart
#[tokio::test(flavor = "current_thread")]
async fn turning_the_clipboard_off_reaches_the_app_and_survives_a_restart() {
    let (mut daemon, _port) = common::start(
        "h-clip-off",
        &format!("[authorized_fingerprints]\n\"{DESK_MAC}\" = \"desk mac\"\n"),
    );

    let (mut events, mut requests) = attach().await;
    let before = reported(&mut events, |_| true).await;
    assert_eq!(
        before,
        Some(PeerTrust {
            clipboard_from: true,
            clipboard_to: false,
        }),
        "precondition: a machine paired before #182 that may drive this one sends \
         its clipboard here; log:\n{}",
        daemon.log()
    );

    requests
        .request(FrontendRequest::DisableClipboard(DESK_MAC.to_owned()))
        .await
        .expect("the request is sent");
    assert_eq!(
        reported(&mut events, |t| t == OFF).await,
        Some(OFF),
        "the app was not told the clipboard is off; log:\n{}",
        daemon.log()
    );

    drop((events, requests));
    daemon.restart();
    let (mut events, _requests) = attach().await;
    let mut still_drives = false;
    let after = common::next_matching(&mut events, WAIT, |e| match e {
        FrontendEvent::AuthorizedUpdated(map) => {
            still_drives = map.contains_key(DESK_MAC);
            None
        }
        FrontendEvent::TrustUpdated(map) => Some(map.get(DESK_MAC).copied()),
        _ => None,
    })
    .await
    .flatten();
    assert_eq!(
        after,
        Some(OFF),
        "after a restart the clipboard with the paired machine is on again; log:\n{}",
        daemon.log()
    );
    assert!(
        still_drives,
        "turning the clipboard off took away the pairing's right to drive this machine"
    );
}

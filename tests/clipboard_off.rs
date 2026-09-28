//! Turning a paired machine's clipboard off reaches the app at once, turning
//! it off again writes nothing, and it is still off after the daemon restarts
//! (#182, #187).
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
    pending: false,
    label: String::new(),
    we_may_drive: false,
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

/// What a report says of the clipboard, and nothing else it carries.
fn clipboard_only(t: &PeerTrust) -> PeerTrust {
    PeerTrust {
        clipboard_from: t.clipboard_from,
        clipboard_to: t.clipboard_to,
        pending: t.pending,
        ..PeerTrust::default()
    }
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
            last = map.get(DESK_MAC).map(clipboard_only);
            last.clone().filter(|t| want(t.clone()))
        }
        _ => None,
    })
    .await
    .or(last)
}

// LEDGER E2A-9 | class B | 5 process + 4 file on disk: FrontendRequest::DisableClipboard into the built daemon, FrontendEvent::TrustUpdated from it, trust.toml unchanged by a second request, across a restart
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
            pending: false,
            ..PeerTrust::default()
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

    // Asked again, the clipboard is already off and nothing is written. The
    // sync is handled after the request, so its first event says the request
    // was handled too.
    let store = std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME is set"))
        .join(".config/lan-mouse/trust.toml");
    let written = std::fs::read(&store).expect("the trust store is on disk");
    for request in [
        FrontendRequest::DisableClipboard(DESK_MAC.to_owned()),
        FrontendRequest::Sync,
    ] {
        requests
            .request(request)
            .await
            .expect("the request is sent");
    }
    let handled = common::next_matching(&mut events, WAIT, |e| {
        matches!(e, FrontendEvent::DaemonBuild(_)).then_some(())
    })
    .await;
    assert!(
        handled.is_some(),
        "the daemon did not answer a sync; log:\n{}",
        daemon.log()
    );
    assert!(
        std::fs::read(&store).ok() == Some(written),
        "turning an already-off clipboard off wrote the trust store again; log:\n{}",
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
        FrontendEvent::TrustUpdated(map) => Some(map.get(DESK_MAC).map(clipboard_only)),
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

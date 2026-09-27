//! Turning a paired machine's clipboard back on reaches the app at once, in
//! the direction its pairing drives and no other, and is still on after the
//! daemon restarts (#182).
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
const DESK_MAC: &str = "2d:18:1a:c4:a8:40:f5:26:37:39:9d:c7:c7:75:fe:17:\
4f:03:d5:a9:76:49:cd:b1:12:d1:2f:6c:1f:d2:22:c5";

const OFF: PeerTrust = PeerTrust {
    clipboard_from: false,
    clipboard_to: false,
};

/// What a machine that may drive this one, and that this one does not
/// drive, is given: its clipboard arrives here, and nothing goes back.
const FROM_IT: PeerTrust = PeerTrust {
    clipboard_from: true,
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

// LEDGER EN-4 | class B | 5 process + 4 file on disk: FrontendRequest::EnableClipboard into the built daemon, FrontendEvent::TrustUpdated from it, trust.toml unchanged by a second request, across a restart
#[tokio::test(flavor = "current_thread")]
async fn turning_the_clipboard_on_follows_the_drive_direction_and_survives_a_restart() {
    let (mut daemon, _port) = common::start(
        "h-clip-on",
        &format!("[authorized_fingerprints]\n\"{DESK_MAC}\" = \"desk mac\"\n"),
    );

    let (mut events, mut requests) = attach().await;
    requests
        .request(FrontendRequest::DisableClipboard(DESK_MAC.to_owned()))
        .await
        .expect("the request is sent");
    assert_eq!(
        reported(&mut events, |t| t == OFF).await,
        Some(OFF),
        "precondition: the clipboard with the paired machine is off; log:\n{}",
        daemon.log()
    );

    requests
        .request(FrontendRequest::EnableClipboard(DESK_MAC.to_owned()))
        .await
        .expect("the request is sent");
    assert_eq!(
        reported(&mut events, |t| t != OFF).await,
        Some(FROM_IT),
        "turning the clipboard on for a machine that may drive this one must let \
         its clipboard arrive here and send nothing back: this machine does not \
         drive it, so no one granted that direction; log:\n{}",
        daemon.log()
    );

    // Asked again, the clipboard is already on and nothing is written. The
    // sync is handled after the request, so its first event says the request
    // was handled too.
    let store = std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME is set"))
        .join(".config/lan-mouse/trust.toml");
    let written = std::fs::read(&store).expect("the trust store is on disk");
    for request in [
        FrontendRequest::EnableClipboard(DESK_MAC.to_owned()),
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
        "turning an already-on clipboard on wrote the trust store again; log:\n{}",
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
        Some(FROM_IT),
        "after a restart the clipboard with the paired machine is not as it was \
         turned on; log:\n{}",
        daemon.log()
    );
    assert!(
        still_drives,
        "turning the clipboard back on took away the pairing's right to drive \
         this machine"
    );
}

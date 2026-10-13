//! A capture session the portal creates but refuses to set up ends capture
//! with that error at once, rather than leaving capture silently dead until
//! the next client or screen change.
#![cfg(all(unix, not(target_os = "macos"), feature = "libei_capture"))]

mod portal;

use std::time::Duration;

use futures::StreamExt;
use input_capture::{Backend, InputCapture, Position};

// LEDGER | behaviour | InputCapture stream against a stand-in portal that grants CreateSession and refuses ConnectToEIS
#[tokio::test(flavor = "current_thread")]
async fn a_session_the_portal_refuses_to_set_up_ends_capture_at_once() {
    let stand_in = portal::start_creating_capture_sessions("capture-setup");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut capture = tokio::time::timeout(
                Duration::from_secs(60),
                InputCapture::new(Some(Backend::InputCapturePortal)),
            )
            .await
            .unwrap_or_else(|_| panic!("capture did not start: {:?}", stand_in.calls()))
            .unwrap_or_else(|e| panic!("capture did not start: {e}: {:?}", stand_in.calls()));
            // A client to capture for, so a session is set up.
            capture.create(0, Position::Left).await.expect("a client");
            let ended = tokio::time::timeout(Duration::from_secs(10), capture.next()).await;
            let calls = stand_in.calls();
            assert!(
                calls
                    .iter()
                    .any(|c| c.ends_with("InputCapture.ConnectToEIS")),
                "the session was never set up: {calls:?}"
            );
            match ended {
                Ok(Some(Err(_))) => {}
                Ok(other) => panic!("expected capture to end with an error, got {other:?}"),
                Err(_) => panic!(
                    "the portal refused to set the session up and capture said nothing \
                     for 10 s: {calls:?}"
                ),
            }
        })
        .await;
}

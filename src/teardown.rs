//! How long stopping the daemon waits on the tasks that tear its input
//! backends down (#261).

use std::time::Duration;

use tokio::task::JoinHandle;

/// How long the daemon waits for capture, or for emulation, to stop before
/// it aborts the task.
///
/// A clean stop takes milliseconds. A backend waiting on a portal that does
/// not answer, as GNOME's does not while the screen is locked, used to be
/// waited on for good, until systemd killed the daemon at its 90 s stop
/// timeout. The backends bound their own portal calls first (2 s each, the
/// libei capture task 3 s), so this fires only when something below has no
/// bound of its own. A task that does not stop is waited on for this long,
/// then for as long again to be dropped once aborted, which takes a
/// moment. Capture and emulation stop one after the other: a stop waits
/// about 10 s at most, 20 s in theory, inside systemd's 90 s.
pub(crate) const STOP_WITHIN: Duration = Duration::from_secs(5);

/// Waits for `task` to end, for at most `within`. A task still running then
/// is aborted, and logged as `what`, the step that did not finish.
pub(crate) async fn stop_within(what: &str, task: &mut JoinHandle<()>, within: Duration) {
    match tokio::time::timeout(within, &mut *task).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("{what}: {e}"),
        Err(_) => {
            log::warn!("{what} did not stop within {within:?}: aborting it");
            task.abort();
            // The runtime drops an aborted task, and what it owns, when it
            // next runs it: waiting lets it do so before the daemon goes on.
            let _ = tokio::time::timeout(within, task).await;
        }
    }
}

/// Stopping the daemon while a backend's teardown never finishes, as one
/// waiting on a portal that does not answer while the screen is locked.
/// Driven through the real capture and emulation tasks, with the test
/// backends told never to stop, under paused time so the bound takes none.
#[cfg(test)]
mod a_backend_that_never_stops {
    use std::time::Duration;

    use input_capture::scripted::Script;
    use input_emulation::recording::{Recorded, Recording};
    use local_channel::mpsc::channel;

    use super::STOP_WITHIN;
    use crate::{
        capture::{Capture, ICaptureEvent},
        emulation::{Emulation, EmulationEvent},
        listen::LanMouseListener,
        test_harness::{dialer, machine, trust},
        trust::Caps,
    };

    /// Long past the bound: a stop still waiting then waits for good.
    const FOR_GOOD: Duration = Duration::from_secs(60);

    fn run_paused<F: std::future::Future>(f: F) -> F::Output {
        crate::transport::install_crypto_provider();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("runtime");
        tokio::task::LocalSet::new().block_on(&rt, f)
    }

    // LEDGER | behaviour | Capture::terminate over the scripted backend told never to stop, paused time
    #[test]
    fn stopping_capture_gives_up_on_it_within_the_bound() {
        run_paused(async {
            let (us, peer) = (machine(), machine());
            let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a port");
            let port = silent.local_addr().expect("its address").port();
            let d = dialer(
                &us,
                trust(&us, &[&peer], Caps::OUTBOUND),
                port,
                hops_ipc::Position::Left,
            );
            let script = Script::new();
            script.never_stop();
            let mut capture = Capture::new(Some(script.backend()), d.conn, vec![]);
            // Running, so stopping reaches the backend's teardown.
            tokio::time::timeout(FOR_GOOD, async {
                while !matches!(capture.event().await, ICaptureEvent::CaptureEnabled) {}
            })
            .await
            .expect("capture to start");

            let started = tokio::time::Instant::now();
            let stopped = tokio::time::timeout(FOR_GOOD, capture.terminate()).await;
            let took = started.elapsed();
            assert!(
                stopped.is_ok(),
                "stopping capture still waited on its backend after {FOR_GOOD:?}"
            );
            assert!(
                took <= STOP_WITHIN,
                "stopping capture took {took:?}, past its bound"
            );
        });
    }

    // LEDGER | behaviour | Emulation::terminate over the recording backend told never to stop, paused time
    #[test]
    fn stopping_emulation_gives_up_on_it_within_the_bound() {
        run_paused(async {
            let (us, peer) = (machine(), machine());
            let our_trust = trust(&us, &[&peer], Caps::INBOUND);
            let (clipboard_tx, _clipboard) = channel();
            let (listener, _port) = LanMouseListener::bind_loopback(
                us.identity.clone(),
                our_trust.clone(),
                clipboard_tx,
            )
            .await
            .expect("listener");
            let recording = Recording::new();
            recording.never_stop();
            let mut emulation = Emulation::new(Some(recording.backend()), listener, our_trust);
            tokio::time::timeout(FOR_GOOD, async {
                while !matches!(
                    emulation.event().await,
                    EmulationEvent::EmulationEnabled { .. }
                ) {}
            })
            .await
            .expect("emulation to start");

            let started = tokio::time::Instant::now();
            let stopped = tokio::time::timeout(FOR_GOOD, emulation.terminate()).await;
            let took = started.elapsed();
            assert!(
                recording.calls().contains(&Recorded::Terminate),
                "stopping never reached the backend's teardown: {:?}",
                recording.calls()
            );
            assert!(
                stopped.is_ok(),
                "stopping emulation still waited on its backend after {FOR_GOOD:?}"
            );
            assert!(
                took <= STOP_WITHIN,
                "stopping emulation took {took:?}, past its bound"
            );
        });
    }
}

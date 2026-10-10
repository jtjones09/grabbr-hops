//! What the app of a machine that is only controlled is told about itself,
//! read the way an app reads it: the whole daemon in this process, its
//! events folded into the model both frontends render.
//!
//! Such a machine runs emulation and nothing else, and on a Mac emulation
//! needs Accessibility. It was told only that emulation was off. And one
//! that only dials out binds no port, yet showed its configured port as if
//! it listened there.

use super::in_process::{DEADLINE, Daemon, Frontend};
use crate::test_harness::run_local;
use hops_frontend_core::{AppModel, EmulationFault, EmulationState};
use hops_ipc::FrontendRequest;
use input_emulation::recording::Recording;
use input_emulation::{Backend, InputEmulation, Permission};
use std::time::Duration;

/// A fresh model of what `app` is told when it asks for everything.
async fn synced(app: &mut Frontend) -> AppModel {
    let mut model = AppModel::default();
    model.connected = true;
    for event in app.exchange(&[FrontendRequest::Sync]).await {
        model.apply(event);
    }
    model
}

// LEDGER G2-1 | class B | 2 FrontendEvent::EmulationStatus over the real IPC socket, folded by AppModel::apply
/// The system withholds the permission emulation needs, as macOS does from
/// a Mac that has not turned hops on under Accessibility. The app is told
/// emulation failed for want of Accessibility, and the line it shows names
/// the permission and where to grant it.
#[test]
fn emulation_refused_its_permission_names_the_permission_and_the_setting() {
    run_local(async {
        let recording = Recording::new();
        recording.refuse_permission();
        let mac = Daemon::start("emu-perm", "", recording.backend()).await;
        let ipc = mac.ipc();
        let body = async {
            let mut app = ipc.connect().await;
            let deadline = tokio::time::Instant::now() + DEADLINE;
            let model = loop {
                let model = synced(&mut app).await;
                if model.emulation != EmulationState::Disabled {
                    break model;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the app was never told what became of emulation: {:?}",
                    model.emulation
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            assert_eq!(
                model.emulation,
                EmulationState::Failed(EmulationFault::Missing(vec![
                    hops_frontend_core::Permission::Accessibility
                ])),
                "emulation could not start for want of Accessibility"
            );
            let problem = model.emulation_problem().unwrap_or_default();
            assert!(
                problem.contains(input_event::settings_pane::accessibility())
                    && problem.contains("System Settings → Privacy & Security"),
                "the app must name the permission and the way to it: {problem:?}"
            );
        };
        mac.run_while(body).await;
    });
}

// LEDGER G2-2 | class B | 1 return value: InputEmulation::first_that_starts over recording backends
/// Choosing a backend moves past one the system withholds a permission
/// from, as it moves past any other, and the one it settles on keeps what
/// was withheld: a fall to `dummy` on a Mac without Accessibility names the
/// permission, and one past a backend that failed otherwise names nothing.
#[test]
fn a_fall_past_a_backend_refused_its_permission_keeps_the_permission() {
    run_local(async {
        let refused = Recording::new();
        refused.refuse_permission();
        let gone = Recording::new().backend();
        let fell = |backends: [Backend; 2]| async move {
            let emulation = InputEmulation::first_that_starts(backends)
                .await
                .expect("dummy always starts");
            (emulation.backend(), emulation.withheld_permissions())
        };
        assert_eq!(
            (
                fell([refused.backend(), Backend::Dummy]).await,
                fell([gone, Backend::Dummy]).await,
            ),
            (
                (Backend::Dummy, &[Permission::Accessibility][..]),
                (Backend::Dummy, &[][..]),
            ),
            "(past a backend refused its permission, past one that failed otherwise)"
        );
    });
}

// LEDGER L-1 | class B | 2 FrontendEvent::Listening over the real IPC socket, folded by AppModel::apply
/// A machine that only dials out binds no port, and its app says so rather
/// than showing the configured port as one it listens on. One that listens
/// shows its port.
#[test]
fn a_machine_that_only_dials_out_shows_no_port() {
    run_local(async {
        let mac = Daemon::start(
            "dial-only",
            "listen = false\n",
            input_emulation::Backend::Dummy,
        )
        .await;
        let pc = Daemon::start("listens", "", input_emulation::Backend::Dummy).await;
        let (mac_ipc, pc_ipc, pc_port) = (mac.ipc(), pc.ipc(), pc.port());
        let body = async {
            let mac_says = synced(&mut mac_ipc.connect().await).await.port_words();
            let pc_says = synced(&mut pc_ipc.connect().await).await.port_words();
            assert_eq!(
                (mac_says.as_str(), pc_says),
                ("dials out only", pc_port.to_string()),
                "(the machine that only dials out, the one that listens)"
            );
        };
        mac.run_while(pc.run_while(body)).await;
    });
}

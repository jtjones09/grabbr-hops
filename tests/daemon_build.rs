//! A daemon says which build it is before it sends any state, and the app
//! says so when that is not its own build.
//!
//! An in-place upgrade leaves the previous version's daemon running under the
//! new app: launchd keeps it, and the app attaches to whatever answers. Until
//! the daemon states its build, nothing on screen can tell.
//!
//! Runs the built binary as the daemon, with dummy capture and emulation,
//! discovery off, a free port, and every path it could touch in a scratch
//! directory. The frontends are the real IPC connector and the real
//! frontend-core client.
//!
//! Runs in its own test binary, so pointing `HOME` and the XDG directories at
//! the scratch directory cannot disturb anything else.
#![cfg(all(unix, any(feature = "tui", feature = "slint")))]

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_frontend_core::{Build, FrontendClient, Launch, ServiceBuild};
use hops_ipc::{FrontendEvent, FrontendRequest};

struct Daemon {
    child: Child,
    dir: PathBuf,
    log: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Daemon {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

fn start() -> Daemon {
    // Short, for `sun_path` (about 104 bytes on macOS).
    let dir = PathBuf::from(format!("/tmp/h-build-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment. The frontend connector finds the
    // daemon's socket and token through them.
    unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
    }
    let port = UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free port")
        .port();
    let config = config_dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n"
        ),
    )
    .expect("a config");
    let log = dir.join("daemon.log");
    let child = Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--config")
        .arg(&config)
        .arg("--cert-path")
        .arg(config_dir.join("lan-mouse.pem"))
        .arg("daemon")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &dir)
        .env("XDG_RUNTIME_DIR", &dir)
        .env("XDG_CONFIG_HOME", dir.join(".config"))
        .env("XDG_STATE_HOME", &dir)
        .env("HOPS_LOG_FILE", &log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts");
    let daemon = Daemon { child, dir, log };
    let deadline = Instant::now() + Duration::from_secs(60);
    while !daemon.log().contains("service running; stops on") {
        assert!(
            Instant::now() < deadline,
            "the daemon never reported its service loop running; log:\n{}",
            daemon.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    daemon
}

/// The build the binary names for itself: `hops <version> (<commit>)`.
fn build_of_the_binary() -> Build {
    let out = Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--version")
        .output()
        .expect("hops --version runs");
    let text = String::from_utf8_lossy(&out.stdout);
    let words: Vec<&str> = text.split_whitespace().collect();
    let [.., version, commit] = words.as_slice() else {
        panic!("`hops --version` printed {text:?}");
    };
    Build {
        version: version.to_string(),
        commit: commit.trim_matches(|c| c == '(' || c == ')').to_string(),
    }
}

/// The frontend-core client's model once the daemon has sent its state, or
/// its last model when `within` runs out.
async fn attached(client: &FrontendClient, within: Duration) -> hops_frontend_core::AppModel {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let model = client.snapshot();
        if model.connected && model.service_build != ServiceBuild::Unknown {
            return model;
        }
        if tokio::time::timeout_at(deadline, client.changed())
            .await
            .is_err()
        {
            return client.snapshot();
        }
    }
}

// LEDGER T58+T59 | class B | 2 events over real IPC from 5 the built daemon; 6 FrontendClient state
#[tokio::test(flavor = "current_thread")]
async fn the_daemon_states_its_build_first_and_the_app_names_another() {
    let daemon = start();
    let ours = build_of_the_binary();

    // T58: the raw events, as any frontend receives them.
    let (mut events, mut requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
        .await
        .expect("a frontend connects");
    requests
        .request(FrontendRequest::Sync)
        .await
        .expect("a second sync is asked for");
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Ok(Some(Ok(event))) = tokio::time::timeout_at(deadline, events.next()).await {
        let enumerate = matches!(event, FrontendEvent::Enumerate(_));
        seen.push(event);
        if enumerate
            && seen
                .iter()
                .filter(|e| matches!(e, FrontendEvent::Enumerate(_)))
                .count()
                == 2
        {
            break;
        }
    }
    let names: Vec<String> = seen
        .iter()
        .map(|e| {
            format!("{e:?}")
                .split(['(', ' ', '{'])
                .next()
                .unwrap_or("")
                .to_string()
        })
        .collect();
    assert!(
        matches!(seen.first(), Some(FrontendEvent::DaemonBuild(b)) if *b == ours),
        "the daemon's first event was not its own build, {ours}: {names:?}\nlog:\n{}",
        daemon.log()
    );
    // Every sync: a build statement before each list of clients.
    let mut stated = false;
    let mut syncs = 0;
    for event in &seen {
        match event {
            FrontendEvent::DaemonBuild(b) => {
                assert_eq!(*b, ours, "the daemon stated another build");
                stated = true;
            }
            FrontendEvent::Enumerate(_) => {
                assert!(
                    stated,
                    "a sync sent the daemon's state before its build, so the app \
                     reads it as a daemon that never says: {names:?}"
                );
                stated = false;
                syncs += 1;
            }
            _ => {}
        }
    }
    assert_eq!(syncs, 2, "two syncs were asked for: {names:?}");
    drop((events, requests));

    // T59: the app's own client, as this build and as another.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let same = FrontendClient::spawn(Launch {
                build: Some(ours.clone()),
                start_problem: Some("stale: a start that did not come up".into()),
            });
            let model = attached(&same, Duration::from_secs(10)).await;
            assert_eq!(
                (
                    model.connected,
                    model.service_problem(),
                    model.start_problem
                ),
                (true, None, None),
                "the app and the daemon are one build, and a daemon answers; the \
                 app reported {:?}",
                model.service_build
            );

            let other = Build {
                version: "0.13.0".into(),
                commit: "0000beef".into(),
            };
            let newer = FrontendClient::spawn(Launch {
                build: Some(other.clone()),
                start_problem: None,
            });
            let model = attached(&newer, Duration::from_secs(10)).await;
            let said = model.service_problem().unwrap_or_default();
            assert!(
                said.contains(&other.to_string()) && said.contains(&ours.to_string()),
                "an app of build {other} attached to a daemon of build {ours} and \
                 said {said:?}"
            );
        })
        .await;
}

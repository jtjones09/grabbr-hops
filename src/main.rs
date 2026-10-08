use hops::{
    capture_test,
    config::{self, Command, Config, ConfigError},
    daemon_start::StartReport,
    emulation_test,
    service::{Service, ServiceError},
};
use hops_cli::CliError;
use hops_ipc::{DaemonEndpoint, IpcError, IpcListenerCreationError};
use input_capture::InputCaptureError;
use input_emulation::InputEmulationError;
use std::{future::Future, io, process};
use thiserror::Error;
use tokio::task::LocalSet;

#[derive(Debug, Error)]
enum HopsError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    IpcError(#[from] IpcError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Capture(#[from] InputCaptureError),
    #[error(transparent)]
    Emulation(#[from] InputEmulationError),
    #[cfg(feature = "tui")]
    #[error(transparent)]
    Tui(#[from] hops_tui::TuiError),
    #[cfg(feature = "slint")]
    #[error(transparent)]
    Slint(#[from] hops_slint::SlintError),
    #[error(transparent)]
    Cli(#[from] CliError),
    #[error(transparent)]
    Elevated(#[from] hops::elevation::Elevated),
}

fn main() {
    // First, every command included: hops runs as the user, never elevated
    // (#109). A refused process opens no log, since an elevated process that
    // creates, opens or rotates a file where the user can write is the very
    // hazard, and reports on stderr and, where nothing keeps that on screen,
    // in a message box.
    match unless_elevated(hops::elevation::refused_here(), start) {
        Ok(()) => {}
        Err(HopsError::Elevated(e)) => process::exit(hops::elevation::refuse(&e)),
        // A `hops cli` command answers whoever ran it, a script as much as a
        // terminal, and the log reaches stderr only at a terminal.
        Err(HopsError::Cli(e)) => {
            eprintln!("{e}");
            process::exit(1);
        }
        Err(e) => {
            log::error!("{e}");
            process::exit(1);
        }
    }
}

/// `command`, unless this process is `elevated`: then nothing of hops runs,
/// not its log and not an argument parse, and the error says why and what
/// to do.
///
/// No command is exempt. `build-check` runs git in a checkout the user can
/// write, whose config can name programs for git to run, and `--help` and
/// `--version` have no use elevated that a normal shell lacks.
fn unless_elevated(
    elevated: bool,
    command: impl FnOnce() -> Result<(), HopsError>,
) -> Result<(), HopsError> {
    hops::elevation::may_run(elevated)?;
    command()
}

/// hops, once this process may run.
fn start() -> Result<(), HopsError> {
    // Logging first, before anything that can fail: a config parse error is
    // one of the things most worth having in the log.
    hops::logging::init(hops::logging::role_from_argv());
    install_panic_logger();
    dispatch()
}

/// Every command, once the log is open.
fn dispatch() -> Result<(), HopsError> {
    // Before anything that reads the config. This is the command someone runs
    // to find out why the others are failing, so it must not need them to work.
    if let Some(config::Command::BuildCheck { repo, strict }) = config::command_from_args() {
        run_build_check(repo, strict);
    }
    run()
}

/// Report whether this binary matches its source, then exit. Never returns.
fn run_build_check(repo: Option<std::path::PathBuf>, strict: bool) -> ! {
    let r = hops::build_check::check(repo);
    process::exit(hops::build_check::report(&r, strict))
}

fn run() -> Result<(), HopsError> {
    // The daemon reads the config only once it holds its IPC endpoint, so a
    // second daemon stops before touching anything the first one holds.
    if runs_the_daemon(config::command_from_args()) {
        return run_daemon();
    }
    let config = config::Config::new()?;
    match config.command() {
        Some(command) => match command {
            Command::TestEmulation(args) => run_async(emulation_test::run(config, args))?,
            Command::TestCapture(args) => run_async(capture_test::run(config, args))?,
            Command::Cli(cli_args) => run_async(hops_cli::run(cli_args))?,
            // Taken above, before the config was read. Kept so the match
            // stays exhaustive.
            Command::Daemon => run_daemon()?,
            Command::Gui { hidden } => run_gui(hidden, None)?,
            Command::Tui => run_tui(None)?,
            // Normally handled in `main` before the config is loaded; kept
            // here so the match stays exhaustive and both paths behave alike.
            Command::BuildCheck { repo, strict } => run_build_check(repo.clone(), strict),
        },
        None => {
            // The `hops` front door (any build with a front-end): make
            // sure the receiver daemon is up, then open the user's chosen
            // interface. Front-ends are attach-only — they never spawn the daemon
            // themselves. The front door starts one only when none answers; see
            // `hops::daemon_start`.
            #[cfg(any(feature = "tui", feature = "slint"))]
            {
                front_door()?;
            }
            // no front-end compiled in: just run the daemon (taken above)
            #[cfg(not(any(feature = "tui", feature = "slint")))]
            {
                run_daemon()?;
            }
        }
    }

    Ok(())
}

/// Whether this invocation runs the daemon: `hops daemon`, or `hops` in a
/// build with no frontend.
fn runs_the_daemon(command: Option<Command>) -> bool {
    match command {
        Some(Command::Daemon) => true,
        None => cfg!(not(any(feature = "tui", feature = "slint"))),
        Some(_) => false,
    }
}

/// Run the daemon (the receiver service). A redundant instance self-exits,
/// and so does one beside a daemon of an older build that listens where this
/// build's claim cannot see it (on Windows, hops 0.12 and older). An elevated
/// one never gets here ([`unless_elevated`]).
fn run_daemon() -> Result<(), HopsError> {
    if let Err(e) =
        hops::daemon_start::refuse_beside_older(DaemonEndpoint::of_older_builds().as_ref())
    {
        return daemon_ended(Err(HopsError::Service(ServiceError::IpcListen(e))));
    }
    daemon_ended(run_async(run_service()))
}

/// What the daemon's end means for how the process exits. One that found
/// another daemon of this user running says so and exits 0. Any other error
/// exits 1: that includes an endpoint something else holds (#96), and a
/// macOS permission granted while it ran (#221), whose exit is what makes
/// launchd, which restarts it only after a failure, start a fresh process
/// with the grant.
fn daemon_ended(ended: Result<(), HopsError>) -> Result<(), HopsError> {
    match ended {
        Err(HopsError::Service(ServiceError::IpcListen(
            IpcListenerCreationError::AlreadyRunning,
        ))) => {
            log::warn!(
                "a hops daemon is already running for this user; this one exits and \
                 leaves it running"
            );
            Ok(())
        }
        r => r,
    }
}

/// What a frontend is told as it opens: this build, to compare with the
/// daemon's, and what the front door did about the service, if it ran: why
/// the service did not come up, or that it restarted or left running one of
/// another build.
#[cfg(any(feature = "tui", feature = "slint"))]
fn launch(started: Option<StartReport>) -> hops_frontend_core::Launch {
    let started = started.as_ref();
    hops_frontend_core::Launch {
        build: Some(hops::config::this_build()),
        start_problem: started.and_then(StartReport::problem),
        restarted: started.and_then(StartReport::note),
        left_running: started.and_then(|started| started.left.clone()),
    }
}

/// Open the Slint GUI (attach-only). No-op with a hint if this build lacks it.
/// `hidden` starts the app in the menu bar / tray only, no window shown.
/// `started` is what the front door did about the service, if it ran.
fn run_gui(hidden: bool, started: Option<StartReport>) -> Result<(), HopsError> {
    #[cfg(feature = "slint")]
    {
        hops_slint::run(hidden, launch(started))?;
        Ok(())
    }
    #[cfg(not(feature = "slint"))]
    {
        let _ = (hidden, started);
        log::error!("this build has no GUI — rebuild with `--features slint`");
        Ok(())
    }
}

/// Make a panic diagnosable, in whichever process it happens.
///
/// The release profile is `panic = "abort"`, so a panic is the last thing the
/// process ever writes — which makes it the single most valuable line in the
/// log and the one least likely to survive. The two aborts that became #4 left exactly this in
/// gui.log:
///
/// ```text
/// thread 'main' panicked at i-slint-core-1.17.0/properties.rs:788:13:
/// Constant property being changed
/// ```
///
/// No property name, no backtrace, no frame of ours anywhere in it — the note
/// says to set `RUST_BACKTRACE`, which nobody can do for a job launchd started
/// at login. Capturing the backtrace ourselves costs nothing until something
/// panics and turns "it died again" into a stack that names the caller.
fn install_panic_logger() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // keep the standard message on stderr, then add what it leaves out
        previous(info);
        // Through `log`, not `eprintln!`. The hook was written for the GUI, and
        // on Windows the tray is started with no redirection at all — so every
        // backtrace it force-captured went to a closed handle. Routing it
        // through the logger puts it in the process's own file, which exists on
        // every platform regardless of who started it.
        log::error!(
            "panic: {info}\nbacktrace follows\n{}",
            std::backtrace::Backtrace::force_capture()
        );
    }));
}

/// Open the Ratatui TUI (attach-only). No-op with a hint if this build lacks it.
/// `started` is what the front door did about the service, if it ran.
fn run_tui(started: Option<StartReport>) -> Result<(), HopsError> {
    #[cfg(feature = "tui")]
    {
        run_async(hops_tui::run(launch(started)))?;
        Ok(())
    }
    #[cfg(not(feature = "tui"))]
    {
        let _ = started;
        log::error!("this build has no TUI — rebuild with `--features tui`");
        Ok(())
    }
}

/// `hops` with no subcommand: ensure the receiver is up, then open the user's
/// preferred front-end (or the sensible default for this environment). On the
/// very first launch, show the "choose your interface" onboarding screen first
/// and persist the pick, so every launch after that is a single, silent step.
#[cfg(any(feature = "tui", feature = "slint"))]
fn front_door() -> Result<(), HopsError> {
    use hops_frontend_core::prefs::{
        Frontend, load_frontend, onboarding_done, save_frontend, set_onboarding_done,
    };
    // What became of the start goes to the screen: a service that did not
    // come up used to leave the app at "connecting" with nothing said (#189),
    // and one of another build went on serving without a word (#222).
    let started = hops::daemon_start::ensure_running();

    let frontend = if onboarding_done() {
        load_frontend().unwrap_or_else(default_frontend)
    } else if let Some(chosen) = run_onboarding_picker() {
        save_frontend(chosen);
        set_onboarding_done();
        chosen
    } else {
        // closed/escaped without picking — don't mark onboarding done (ask
        // again next launch), just use the environment default for THIS run
        default_frontend()
    };

    match frontend {
        Frontend::Tui => run_tui(Some(started)),
        // front door = the user actively opening the app, so show the window
        Frontend::Gui => run_gui(false, Some(started)),
    }
}

/// Show the first-run interface picker in whichever medium fits the
/// environment — the same GUI-on-desktop/TUI-over-SSH question as
/// [`default_frontend`], since which picker CAN run is the same question as
/// which front-end runs by default.
#[cfg(any(feature = "tui", feature = "slint"))]
fn run_onboarding_picker() -> Option<hops_frontend_core::prefs::Frontend> {
    #[cfg(all(feature = "slint", feature = "tui"))]
    {
        let ssh =
            std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some();
        if ssh {
            hops_tui::run_onboarding().ok().flatten()
        } else {
            hops_slint::run_onboarding().ok().flatten()
        }
    }
    #[cfg(all(feature = "slint", not(feature = "tui")))]
    {
        hops_slint::run_onboarding().ok().flatten()
    }
    #[cfg(all(feature = "tui", not(feature = "slint")))]
    {
        hops_tui::run_onboarding().ok().flatten()
    }
}

/// Default front-end when the user hasn't chosen: GUI on a local desktop, TUI
/// over SSH / when only the TUI is compiled in.
#[cfg(any(feature = "tui", feature = "slint"))]
fn default_frontend() -> hops_frontend_core::prefs::Frontend {
    use hops_frontend_core::prefs::Frontend;
    let ssh = std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some();
    if !ssh && cfg!(feature = "slint") {
        Frontend::Gui
    } else if cfg!(feature = "tui") {
        Frontend::Tui
    } else {
        Frontend::Gui
    }
}

fn run_async<F, E>(f: F) -> Result<(), HopsError>
where
    F: Future<Output = Result<(), E>>,
    HopsError: From<E>,
{
    // create single threaded tokio runtime
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    // run async event loop
    Ok(runtime.block_on(LocalSet::new().run_until(f))?)
}

async fn run_service() -> Result<(), ServiceError> {
    let endpoint = DaemonEndpoint::of_this_platform().map_err(IpcListenerCreationError::from)?;
    let mut service = Service::start(&endpoint, Config::new).await?;
    // Taken once this daemon holds its own endpoint, and held until it ends.
    let _older =
        hops::daemon_start::hold_older_endpoint(DaemonEndpoint::of_older_builds().as_ref());
    service.run().await?;
    log::info!("service exited!");
    Ok(())
}

#[cfg(test)]
mod keylog_is_never_shipped {
    //! Keystroke logging must not reach a release artifact.
    //!
    //! hops needs the capability — scancode mapping is not debuggable without key
    //! identity. What it must never be is something a user ends up running by
    //! accident. Before #117 it rode along with `HOPS_LOG_LEVEL=debug`, which the
    //! Windows dev launcher had set since 2026-07-21; the resulting log was
    //! 4.4 GB of one person's typing in cleartext.
    //!
    //! The runtime gates (a duration, a cap, its own file) live in
    //! `input_event::keylog`. This guards the one property they cannot: that the
    //! code is absent from what we ship.

    const ROOT_MANIFEST: &str = include_str!("../Cargo.toml");
    const RELEASE_WF: &str = include_str!("../.github/workflows/release.yml");
    const CHECK_WF: &str = include_str!("../.github/workflows/check.yml");

    /// The `default = [ ... ]` list from the root manifest.
    fn default_features() -> &'static str {
        let start = ROOT_MANIFEST
            .find("\ndefault = [")
            .expect("a default feature list must exist");
        let rest = &ROOT_MANIFEST[start..];
        &rest[..rest.find("\n]").map(|i| i + 2).unwrap_or(rest.len())]
    }

    #[test]
    fn keylog_is_not_a_default_feature() {
        assert!(
            !default_features().contains("keylog"),
            "`keylog` must never be in `default`. A bare `cargo build` would then \
             produce a binary that can record every key the user presses."
        );
    }

    #[test]
    fn no_workflow_builds_with_keylog() {
        for (name, wf) in [("release.yml", RELEASE_WF), ("check.yml", CHECK_WF)] {
            for line in wf.lines() {
                let code = line.split('#').next().unwrap_or("");
                assert!(
                    !code.contains("keylog"),
                    "{name} names `keylog`: {}\n\
                     Nothing we build in CI — and above all nothing we release — may \
                     carry keystroke recording.",
                    line.trim()
                );
            }
        }
    }

    #[test]
    fn the_feature_exists_and_forwards() {
        // It has to be reachable deliberately, or the capability is gone rather
        // than gated — and then the next person needing it re-adds a log line.
        assert!(
            ROOT_MANIFEST.contains(r#"keylog = ["input-event/keylog"]"#),
            "the `keylog` feature must still exist and forward to input-event"
        );
    }
}

#[cfg(test)]
mod a_daemon_ended_for_a_grant_exits_unsuccessfully {
    //! launchd restarts the daemon only after it fails (#221), so the error a
    //! grant ends it with must reach `main`, which exits 1 on any error.
    use super::{HopsError, IpcListenerCreationError, ServiceError, daemon_ended};

    // LEDGER T2251 | class B | 1 return value of daemon_ended
    #[test]
    fn only_a_daemon_that_found_another_of_this_user_exits_0() {
        let granted = daemon_ended(Err(HopsError::Service(ServiceError::PermissionGranted(
            input_event::settings_pane::accessibility().into(),
        ))));
        let beside = daemon_ended(Err(HopsError::Service(ServiceError::IpcListen(
            IpcListenerCreationError::AlreadyRunning,
        ))));
        let held = daemon_ended(Err(HopsError::Service(ServiceError::IpcListen(
            IpcListenerCreationError::Held {
                endpoint: hops_ipc::DaemonEndpoint::Tcp("127.0.0.1:9".parse().expect("an address")),
                why: "a program that is not hops".into(),
                hint: String::new(),
            },
        ))));
        assert!(
            matches!(
                granted,
                Err(HopsError::Service(ServiceError::PermissionGranted(_)))
            ),
            "a daemon that ended for a grant must exit 1, or launchd leaves it down \
             until the next login: {granted:?}"
        );
        let older = daemon_ended(Err(HopsError::Service(ServiceError::IpcListen(
            IpcListenerCreationError::Older {
                endpoint: hops_ipc::DaemonEndpoint::Tcp(
                    "127.0.0.1:5252".parse().expect("an address"),
                ),
                hint: String::new(),
            },
        ))));
        assert!(
            older.is_err(),
            "a daemon that did not start beside an older build's must exit 1 with \
             the reason, not as if a daemon of this build were running: {older:?}"
        );
        assert!(beside.is_ok(), "{beside:?}");
        assert!(
            held.is_err(),
            "a daemon whose endpoint something else holds must exit 1 with the \
             reason, not as if a daemon were running: {held:?}"
        );
    }
}

#[cfg(test)]
mod an_elevated_hops_refuses_to_run {
    //! hops runs as the user and is never elevated (#109). On Windows `main`
    //! passes whether its token is elevated, before any command runs; here
    //! the seam is called with each answer, so the refusal is tested on every
    //! system. That `main` goes through it is guarded in `decision_guards`.
    use super::{HopsError, unless_elevated};
    use std::cell::Cell;

    // LEDGER T1093 | class B | 1 return value + whether the command ran
    #[test]
    fn nothing_of_hops_runs_when_elevated_and_it_exits_1() {
        let ran = Cell::new(false);
        let got = unless_elevated(true, || {
            ran.set(true);
            Ok(())
        });
        assert!(
            matches!(got, Err(HopsError::Elevated(_))) && !ran.get(),
            "an elevated process ran a hops command, or exited 0 without saying \
             why: ran {}, {got:?}",
            ran.get()
        );
        let got = unless_elevated(false, || {
            ran.set(true);
            Ok(())
        });
        assert!(
            got.is_ok() && ran.get(),
            "a process that is not elevated did not run its command"
        );
    }
}

#[cfg(all(test, any(feature = "tui", feature = "slint")))]
mod the_front_door_shows_what_became_of_its_start {
    //! A start that did not come up left the app at "connecting", with the
    //! reason in a log nobody was pointed at (#189).
    //!
    //! The text is tested where it is made (`StartReport::problem` against a
    //! real daemon that exits, in tests/failed_start.rs) and where it is shown
    //! (`AppModel::service_problem`, and the TUI's rendered header); what the
    //! front door did about a service of another build likewise
    //! (`StartReport::note` and `left`, `AppModel::launched`). What no
    //! behavioural test can reach is `front_door` itself, which opens a
    //! window or a terminal UI: that it hands the report to the frontend it
    //! opens is checked here, on its source with comments stripped.

    /// A daemon of another build that the front door left running is named
    /// before the app connects. One from before the token cannot be
    /// connected to at all, and the app sat at "connecting" with nothing
    /// said: the very thing #222 is about.
    // LEDGER T2250 | class B | 1 AppModel::service_problem over main's launch()
    #[test]
    fn a_service_left_running_is_named_before_the_app_connects() {
        use hops::daemon_start::{DaemonStart, StartReport};
        let why = "On Windows hops does not restart its service. Sign out and back in \
                   to run this version.";
        let report = StartReport {
            outcome: DaemonStart::AlreadyRunning,
            why: None,
            log_file: None,
            within: std::time::Duration::from_secs(5),
            replaced: None,
            left: Some(why.into()),
            left_build: Some("hops 0.12.0 (1111111)".into()),
        };
        let model = hops_frontend_core::AppModel::launched(super::launch(Some(report)));
        let said = model.service_problem().unwrap_or_default();
        assert!(
            !model.connected && said.contains("hops 0.12.0 (1111111)") && said.ends_with(why),
            "the app has not connected, and must already say which build still runs \
             and why: {said:?}"
        );
    }

    // LEDGER T70 | class S | source text | pair T64 (report text), T61 (model), T62 (render), T2224 (restart report), T2230 (model)
    #[test]
    fn front_door_hands_its_start_report_to_the_frontend_it_opens() {
        let src = include_str!("main.rs");
        let code: String = src
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or(src)
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let at = code
            .find("fn front_door(")
            .expect("front_door must exist; if it moved, point this check there");
        let body = &code[at..];
        let body = &body[..body.find("\n}").unwrap_or(body.len())];
        for needed in [
            "let started = hops::daemon_start::ensure_running();",
            "Frontend::Tui => run_tui(Some(started))",
            "Frontend::Gui => run_gui(false, Some(started))",
        ] {
            assert!(
                body.contains(needed),
                "front_door no longer has `{needed}`. A service that did not come \
                 up then reaches the screen as \"connecting\", with nothing said."
            );
        }
    }
}

use env_logger::Env;
use input_capture::InputCaptureError;
use input_emulation::InputEmulationError;
use lan_mouse::{
    capture_test,
    config::{self, Command, Config, ConfigError},
    emulation_test,
    service::{Service, ServiceError},
};
use lan_mouse_cli::CliError;
#[cfg(feature = "gtk")]
use lan_mouse_gtk::GtkError;
use lan_mouse_ipc::{IpcError, IpcListenerCreationError};
use std::{
    future::Future,
    io,
    process::{self, Child},
};
use thiserror::Error;
use tokio::task::LocalSet;

#[derive(Debug, Error)]
enum LanMouseError {
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
    #[cfg(feature = "gtk")]
    #[error(transparent)]
    Gtk(#[from] GtkError),
    #[cfg(feature = "tui")]
    #[error(transparent)]
    Tui(#[from] lan_mouse_tui::TuiError),
    #[cfg(feature = "slint")]
    #[error(transparent)]
    Slint(#[from] lan_mouse_slint::SlintError),
    #[error(transparent)]
    Cli(#[from] CliError),
}

fn main() {
    // init logging
    let env = Env::default().filter_or("LAN_MOUSE_LOG_LEVEL", "info");
    env_logger::init_from_env(env);

    if let Err(e) = run() {
        log::error!("{e}");
        process::exit(1);
    }
}

fn run() -> Result<(), LanMouseError> {
    let config = config::Config::new()?;
    match config.command() {
        Some(command) => match command {
            Command::TestEmulation(args) => run_async(emulation_test::run(config, args))?,
            Command::TestCapture(args) => run_async(capture_test::run(config, args))?,
            Command::Cli(cli_args) => run_async(lan_mouse_cli::run(cli_args))?,
            Command::Daemon => run_daemon(config)?,
            Command::Gui => run_gui()?,
            Command::Tui => run_tui()?,
        },
        None => {
            //  otherwise start the service as a child process and
            //  run a frontend
            #[cfg(feature = "gtk")]
            {
                let mut service = start_service()?;
                let res = lan_mouse_gtk::run(config::local_commit());
                #[cfg(unix)]
                {
                    // on unix we give the service a chance to terminate gracefully
                    let pid = service.id() as libc::pid_t;
                    unsafe {
                        libc::kill(pid, libc::SIGINT);
                    }
                    service.wait()?;
                }
                service.kill()?;
                res?;
            }
            // The `hops` front door (any build with a front-end, non-gtk): make
            // sure the receiver daemon is up, then open the user's chosen
            // interface. Front-ends are attach-only — they never spawn the daemon
            // themselves (a front-end-spawned daemon can land on the dummy backend
            // if its path lacks the Accessibility grant); `ensure_daemon_running`
            // brings up the GRANTED launchd service instead.
            #[cfg(all(not(feature = "gtk"), any(feature = "tui", feature = "slint")))]
            {
                front_door()?;
            }
            // no front-end compiled in: just run the daemon
            #[cfg(not(any(feature = "gtk", feature = "tui", feature = "slint")))]
            {
                run_daemon(config)?;
            }
        }
    }

    Ok(())
}

/// Run the daemon (the receiver service). A redundant instance self-exits.
fn run_daemon(config: config::Config) -> Result<(), LanMouseError> {
    match run_async(run_service(config)) {
        Err(LanMouseError::Service(ServiceError::IpcListen(
            IpcListenerCreationError::AlreadyRunning,
        ))) => {
            log::info!("service already running!");
            Ok(())
        }
        r => r,
    }
}

/// Open the Slint GUI (attach-only). No-op with a hint if this build lacks it.
fn run_gui() -> Result<(), LanMouseError> {
    #[cfg(feature = "slint")]
    {
        lan_mouse_slint::run()?;
        Ok(())
    }
    #[cfg(not(feature = "slint"))]
    {
        log::error!("this build has no GUI — rebuild with `--features slint`");
        Ok(())
    }
}

/// Open the Ratatui TUI (attach-only). No-op with a hint if this build lacks it.
fn run_tui() -> Result<(), LanMouseError> {
    #[cfg(feature = "tui")]
    {
        run_async(lan_mouse_tui::run())?;
        Ok(())
    }
    #[cfg(not(feature = "tui"))]
    {
        log::error!("this build has no TUI — rebuild with `--features tui`");
        Ok(())
    }
}

/// `hops` with no subcommand: ensure the receiver is up, then open the user's
/// preferred front-end (or the sensible default for this environment). On the
/// very first launch, show the "choose your interface" onboarding screen first
/// and persist the pick, so every launch after that is a single, silent step.
#[cfg(all(not(feature = "gtk"), any(feature = "tui", feature = "slint")))]
fn front_door() -> Result<(), LanMouseError> {
    use lan_mouse_frontend_core::prefs::{
        load_frontend, onboarding_done, save_frontend, set_onboarding_done, Frontend,
    };
    ensure_daemon_running();

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
        Frontend::Tui => run_tui(),
        Frontend::Gui => run_gui(),
    }
}

/// Show the first-run interface picker in whichever medium fits the
/// environment — the same GUI-on-desktop/TUI-over-SSH question as
/// [`default_frontend`], since which picker CAN run is the same question as
/// which front-end runs by default.
#[cfg(all(not(feature = "gtk"), any(feature = "tui", feature = "slint")))]
fn run_onboarding_picker() -> Option<lan_mouse_frontend_core::prefs::Frontend> {
    #[cfg(all(feature = "slint", feature = "tui"))]
    {
        let ssh = std::env::var_os("SSH_CONNECTION").is_some()
            || std::env::var_os("SSH_TTY").is_some();
        if ssh {
            lan_mouse_tui::run_onboarding().ok().flatten()
        } else {
            lan_mouse_slint::run_onboarding().ok().flatten()
        }
    }
    #[cfg(all(feature = "slint", not(feature = "tui")))]
    {
        lan_mouse_slint::run_onboarding().ok().flatten()
    }
    #[cfg(all(feature = "tui", not(feature = "slint")))]
    {
        lan_mouse_tui::run_onboarding().ok().flatten()
    }
}

/// Default front-end when the user hasn't chosen: GUI on a local desktop, TUI
/// over SSH / when only the TUI is compiled in.
#[cfg(all(not(feature = "gtk"), any(feature = "tui", feature = "slint")))]
fn default_frontend() -> lan_mouse_frontend_core::prefs::Frontend {
    use lan_mouse_frontend_core::prefs::Frontend;
    let ssh = std::env::var_os("SSH_CONNECTION").is_some()
        || std::env::var_os("SSH_TTY").is_some();
    if !ssh && cfg!(feature = "slint") {
        Frontend::Gui
    } else if cfg!(feature = "tui") {
        Frontend::Tui
    } else {
        Frontend::Gui
    }
}

/// Make sure the GRANTED receiver daemon is running, without spawning it as our
/// own child (which could land on the dummy backend). On macOS that means the
/// launchd service; elsewhere a detached background process.
#[cfg(all(not(feature = "gtk"), any(feature = "tui", feature = "slint")))]
fn ensure_daemon_running() {
    // If a receiver is already listening (e.g. the granted daemon under any
    // identity), do nothing — never start a second one, and don't (re)install a
    // LaunchAgent that would race the running one on next login.
    if daemon_socket_alive() {
        return;
    }
    #[cfg(target_os = "macos")]
    ensure_launchd_daemon();
    #[cfg(not(target_os = "macos"))]
    {
        let _ = start_detached_daemon();
    }
}

/// True if a daemon is already listening on the IPC socket.
#[cfg(all(not(feature = "gtk"), any(feature = "tui", feature = "slint")))]
fn daemon_socket_alive() -> bool {
    #[cfg(unix)]
    {
        match lan_mouse_ipc::default_socket_path() {
            Ok(path) => std::os::unix::net::UnixStream::connect(path).is_ok(),
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Bring up `com.grabbr.hops` via launchd if it isn't already loaded,
/// self-installing the LaunchAgent plist (pointed at this binary) on first run.
#[cfg(all(not(feature = "gtk"), target_os = "macos", any(feature = "tui", feature = "slint")))]
fn ensure_launchd_daemon() {
    let uid = unsafe { libc::getuid() };
    let service = format!("gui/{uid}/com.grabbr.hops");
    let loaded = process::Command::new("launchctl")
        .args(["print", &service])
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if loaded {
        return;
    }
    if let Some(plist) = install_launchd_plist_if_missing() {
        let _ = process::Command::new("launchctl")
            .args(["bootstrap", &format!("gui/{uid}"), &plist])
            .stdout(process::Stdio::null())
            .stderr(process::Stdio::null())
            .status();
    }
}

/// Write `~/Library/LaunchAgents/com.grabbr.hops.plist` (pointed at the current
/// binary) if absent; returns its path. Grant is path-bound, so the plist must
/// point at whatever `hops` binary the user actually launched.
#[cfg(all(not(feature = "gtk"), target_os = "macos", any(feature = "tui", feature = "slint")))]
fn install_launchd_plist_if_missing() -> Option<String> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from)?;
    let plist_path = home.join("Library/LaunchAgents/com.grabbr.hops.plist");
    if plist_path.exists() {
        return Some(plist_path.to_string_lossy().into_owned());
    }
    let exe = std::env::current_exe().ok()?;
    let logs = home.join("hops/logs");
    let _ = std::fs::create_dir_all(&logs);
    let log = logs.join("daemon.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.grabbr.hops</string>
    <key>ProgramArguments</key>
    <array><string>{exe}</string><string>daemon</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><false/>
    <key>ProcessType</key><string>Interactive</string>
    <key>StandardOutPath</key><string>{log}</string>
    <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        exe = exe.display(),
        log = log.display()
    );
    if let Some(dir) = plist_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&plist_path, plist).ok()?;
    Some(plist_path.to_string_lossy().into_owned())
}

fn run_async<F, E>(f: F) -> Result<(), LanMouseError>
where
    F: Future<Output = Result<(), E>>,
    LanMouseError: From<E>,
{
    // create single threaded tokio runtime
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    // run async event loop
    Ok(runtime.block_on(LocalSet::new().run_until(f))?)
}

#[cfg_attr(not(feature = "gtk"), allow(dead_code))]
fn start_service() -> Result<Child, io::Error> {
    let child = process::Command::new(std::env::current_exe()?)
        .args(std::env::args().skip(1))
        .arg("daemon")
        .spawn()?;
    Ok(child)
}

/// Start the daemon as a DETACHED background process (its own session, with
/// stdio sent to a contained log file) if one isn't already running, then return
/// without owning it. Used by the front door on non-macOS (macOS uses launchd):
/// the daemon is the persistent core engine and must survive the front-end — and
/// its terminal — going away. A redundant daemon self-exits (`AlreadyRunning`).
#[cfg(all(
    not(feature = "gtk"),
    not(target_os = "macos"),
    any(feature = "tui", feature = "slint")
))]
fn start_detached_daemon() -> Result<(), io::Error> {
    use std::process::Stdio;
    // contained daemon log (never the home root)
    let (out, err) = {
        let mut path = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        path.push("hops/logs");
        let _ = std::fs::create_dir_all(&path);
        path.push("daemon.log");
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|f| Ok((f.try_clone()?, f)))
        {
            Ok((a, b)) => (Stdio::from(a), Stdio::from(b)),
            Err(_) => (Stdio::null(), Stdio::null()),
        }
    };
    let mut cmd = process::Command::new(std::env::current_exe()?);
    cmd.args(std::env::args().skip(1))
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid() in the forked child detaches it into a new session so
        // the front-end's terminal closing (SIGHUP) can't take the daemon down.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    // we deliberately drop the Child handle — the daemon owns its own lifecycle.
    let _ = cmd.spawn()?;
    Ok(())
}

async fn run_service(config: Config) -> Result<(), ServiceError> {
    let release_bind = config.release_bind();
    let config_path = config.config_path().to_owned();
    let mut service = Service::new(config).await?;
    log::info!("using config: {config_path:?}");
    log::info!("Press {release_bind:?} to release the mouse");
    service.run().await?;
    log::info!("service exited!");
    Ok(())
}

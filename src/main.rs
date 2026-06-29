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
            Command::Daemon => {
                // if daemon is specified we run the service
                match run_async(run_service(config)) {
                    Err(LanMouseError::Service(ServiceError::IpcListen(
                        IpcListenerCreationError::AlreadyRunning,
                    ))) => log::info!("service already running!"),
                    r => r?,
                }
            }
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
            #[cfg(all(feature = "tui", not(feature = "gtk")))]
            {
                // The daemon is the persistent core engine. Start it DETACHED if
                // it isn't already running, then attach the TUI. Quitting or
                // closing the TUI detaches only — the daemon keeps running so the
                // KVM keeps working with no UI open.
                start_detached_daemon()?;
                run_async(lan_mouse_tui::run())?;
            }
            #[cfg(not(any(feature = "gtk", feature = "tui")))]
            {
                // run daemon if no frontend feature is enabled
                match run_async(run_service(config)) {
                    Err(LanMouseError::Service(ServiceError::IpcListen(
                        IpcListenerCreationError::AlreadyRunning,
                    ))) => log::info!("service already running!"),
                    r => r?,
                }
            }
        }
    }

    Ok(())
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
/// without owning it. Used by attach-and-detach front-ends (TUI/GUI): the daemon
/// is the persistent core engine and must survive the front-end — and its
/// terminal — going away. A redundant daemon self-exits (`AlreadyRunning`).
#[cfg(all(feature = "tui", not(feature = "gtk")))]
fn start_detached_daemon() -> Result<(), io::Error> {
    use std::process::Stdio;
    // contained daemon log (never the home root)
    let (out, err) = {
        let mut path = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        path.push("grabbr-hop/logs");
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

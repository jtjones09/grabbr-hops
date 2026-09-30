//! Bringing the daemon up from the front door.
//!
//! `hops` with no subcommand makes sure a daemon of its own build is running
//! before it opens a frontend. It starts one only when none answers on the IPC
//! endpoint, so opening the app never starts a second. On macOS the start goes
//! through the launchd service; on Linux and Windows it is a detached process.
//!
//! A daemon that answers is asked which build it is. One of another build, or
//! one that says none, is restarted when the hops service started it, so that
//! an app replaced in place does not go on talking to the previous release's
//! daemon (#222). A daemon of this build is never restarted, and one started
//! some other way, such as from a terminal, is left running with the reason
//! shown. See [`verdict`] for the rule, and [`stop_service_daemon`] for the
//! one place a daemon is stopped.
//!
//! A start counts only when the daemon serves frontends by the end of a
//! bounded wait: it takes the token and sends state. A daemon binds its
//! endpoint before it reads the token, the config and its keys, and one that
//! fails on any of them exits a moment later, so a process id, or something
//! answering on the endpoint, is not enough. A daemon that exits first, or has
//! not answered when the wait ends, is logged as such, with the file it logs
//! to.
//!
//! On Windows hops 0.12 and older listened on a loopback port, not this
//! build's pipe, so the front door also asks that port
//! ([`DaemonEndpoint::of_older_builds`]) and starts nothing while an older
//! hops daemon answers there; a daemon started by hand refuses the same way
//! ([`refuse_beside_older`]).
//!
//! The frontend crates attach to a daemon and spawn nothing, and `src/main.rs`
//! calls [`ensure_running`].
//!
//! The probe and the start are two steps, so two starts can still overlap: two
//! front doors opened together, or one opened while a login service is
//! bringing a daemon up. Which daemon keeps running is settled by its claim on
//! the IPC endpoint (`hops_ipc::AsyncFrontendListener::at`), which it takes
//! before it reads the config or any key; the other exits.

use hops_ipc::{
    Build, DaemonEndpoint, IpcListenerCreationError, Listener, SocketPathError, StatedBuild,
};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// What the front door did about the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonStart {
    /// A daemon already answered, so nothing was started; or one answered
    /// while the process this start brought up stopped beside it.
    AlreadyRunning,
    /// Nothing answered, and the daemon process with this id was started (or
    /// found running by launchd) and serves frontends.
    Started(u32),
    /// Nothing answered, the daemon process with this id was started (or
    /// found running by launchd), and it did not serve frontends within the
    /// wait. It may still be starting, or be stuck.
    NoAnswer(u32),
    /// Nothing answered, and the daemon process with this id was started and
    /// exited before it served frontends. No daemon is running.
    Exited(u32),
    /// Nothing answered, and no daemon process could be started.
    StartFailed,
    /// The endpoint could not be worked out, so nothing was asked or started.
    CannotProbe,
}

/// How long the front door waits for a daemon it started to serve frontends.
///
/// Long enough for a daemon to read its keys and trust store and start its
/// loop, which takes well under a second; bounded, because the app does not
/// open until the wait ends. A daemon that exits ends the wait at once.
pub const START_WAIT: Duration = Duration::from_secs(5);

/// The longest one ask may take within the wait.
const ASK_WITHIN: Duration = Duration::from_secs(1);

/// How long something on the older builds' endpoint is given to say it is a
/// hops daemon. One from before the token sends its state as soon as it
/// takes the connection.
const OLDER_ASK: Duration = Duration::from_secs(1);

/// A daemon on the older builds' endpoint, in words.
const OLDER_BUILD: &str = "hops 0.12 or older";

/// How to stop a daemon of hops 0.12 or older listening on `older`, which
/// only Windows has apart from this build's (see
/// [`DaemonEndpoint::of_older_builds`]), and keep it from starting again at
/// sign-in.
///
/// hops 0.12 started at sign-in from a scheduled task named `hops-daemon`,
/// which its task script registered elevated, or from the `hops-daemon` and
/// `hops-gui` values of the Run key, which its installer set. The old daemon
/// is found by the port it listens on: this build's program has the same
/// name. This build is registered again by its own task script, from a
/// shell that is not elevated, so it never runs elevated (service/README.md):
/// pointing the old task at it would keep the task's elevation.
///
/// The Run values are removed from a shell that is not elevated: they are in
/// the user's own hive, and an administrator shell opened with another
/// account's password reads that account's. Only the task and the daemon it
/// started elevated need an administrator.
pub fn older_stop(older: &DaemonEndpoint) -> String {
    let port = match older {
        DaemonEndpoint::Tcp(addr) => addr.port(),
        _ => OLDER_PORT,
    };
    // Each command on a line of its own, apart from the words around it, and
    // short enough not to wrap in the app.
    format!(
        "To stop it for good, first remove what its installer set to start it at \
         sign-in, from a normal PowerShell:\n\
         $run = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'\n\
         Remove-ItemProperty $run -Name hops-daemon,hops-gui\n\
         Then remove the task its task script set, which runs it elevated, and stop \
         it, from PowerShell as administrator (a normal one does if there is no task):\n\
         Unregister-ScheduledTask -TaskName hops-daemon -Confirm:$false\n\
         $old = Get-NetTCPConnection -LocalPort {port} -State Listen\n\
         Stop-Process -Id $old.OwningProcess\n\
         A line that finds nothing to remove says so. Quit the old hops in the \
         notification area too, then open hops again. To start this version at \
         sign-in, from a normal PowerShell, never an administrator one: run \
         install-hops-daemon.ps1 from service\\windows in the source code zip on the \
         release page (service/README.md); or, if 0.12 came from install.ps1 in a \
         clone of the source, update the clone and run install.ps1 again. If the old \
         one runs as another user of this computer, only that user or an administrator \
         can stop it."
    )
}

/// The port hops 0.12 and older listened on, on Windows.
pub(crate) const OLDER_PORT: u16 = 5252;

/// Why the front door started nothing beside a daemon of hops 0.12 or older,
/// and what to do.
const BESIDE_OLDER: &str = "hops did not start this version beside it: both would use this \
    machine's identity and settings, and the old one rewrites the settings file.";

/// Whether a hops daemon of an older build answers on `older`: something
/// takes a connection there and sends a hops event unasked, as a daemon from
/// before the token does. Anything else there is not hops.
fn older_daemon_at(older: &DaemonEndpoint) -> bool {
    older.answers() && older.build(None, OLDER_ASK).is_some()
}

/// Refuse to start a daemon while one of an older build answers on `older`
/// ([`DaemonEndpoint::of_older_builds`]), which this build's claim on its own
/// endpoint cannot see.
pub fn refuse_beside_older(older: Option<&DaemonEndpoint>) -> Result<(), IpcListenerCreationError> {
    match older {
        Some(older) if older_daemon_at(older) => Err(IpcListenerCreationError::Older {
            endpoint: older.clone(),
            hint: older_stop(older),
        }),
        _ => Ok(()),
    }
}

/// Take `older`, where a daemon of hops 0.12 or older listens on Windows,
/// and hold it while this daemon runs, accepting nothing there. Such a
/// daemon started after this one then finds it taken and exits, as it does
/// beside another daemon of its own build; without this it ran beside this
/// one (#222: at most one daemon). Nothing a connection there is sent, so
/// [`refuse_beside_older`] does not take this daemon for an older one.
///
/// `None` when there is nothing to hold, or it cannot be taken, as when a
/// daemon of another user of this computer holds it: a best effort that
/// never stops this daemon starting.
pub fn hold_older_endpoint(older: Option<&DaemonEndpoint>) -> Option<std::net::TcpListener> {
    let Some(DaemonEndpoint::Tcp(addr)) = older else {
        return None;
    };
    std::net::TcpListener::bind(addr)
        .inspect(|_| {
            log::info!(
                "holding {addr}, where {OLDER_BUILD} listened, so a daemon of that \
                 version started now exits"
            )
        })
        .inspect_err(|e| {
            log::info!(
                "not holding {addr}, where {OLDER_BUILD} listened: {e}. A daemon of that \
                 version started now would run beside this one"
            )
        })
        .ok()
}

/// The pause between asks.
const ASK_EVERY: Duration = Duration::from_millis(100);

/// What the front door looks at while a daemon it started comes up.
pub trait Watch {
    /// Whether a daemon serves frontends on `endpoint`, asked once and
    /// answered within `within`.
    fn serves(&mut self, endpoint: &DaemonEndpoint, within: Duration) -> bool;
    /// Whether the process with id `pid` has ended.
    fn ended(&mut self, pid: u32) -> bool;
    /// The file the daemon logs to, to name when it does not come up.
    fn log_file(&self) -> Option<PathBuf>;
}

/// This machine: the daemon's own endpoint and token, its process, and the
/// file it logs to.
pub struct ThisMachine;

impl Watch for ThisMachine {
    fn serves(&mut self, endpoint: &DaemonEndpoint, within: Duration) -> bool {
        // Read on every ask: a daemon mints the token only once it holds its
        // endpoint, which may be after the first ask.
        hops_ipc::token::read().is_ok_and(|token| endpoint.serves(&token, within))
    }

    fn ended(&mut self, pid: u32) -> bool {
        crate::pid::is_gone(pid)
    }

    fn log_file(&self) -> Option<PathBuf> {
        crate::logging::file_for("daemon")
    }
}

/// What the front door asks about a daemon that already answers.
pub trait Running {
    /// Which build the daemon on `endpoint` says it is, asked once and
    /// answered within `within`. `None` when it says nothing by then.
    fn build(&mut self, endpoint: &DaemonEndpoint, within: Duration) -> Option<StatedBuild>;
    /// Who started the daemon on `endpoint`.
    fn origin(&mut self, endpoint: &DaemonEndpoint) -> Origin;
}

impl Running for ThisMachine {
    fn build(&mut self, endpoint: &DaemonEndpoint, within: Duration) -> Option<StatedBuild> {
        // Without the token, a daemon from before it still says what it is.
        endpoint.build(hops_ipc::token::read().ok().as_deref(), within)
    }

    fn origin(&mut self, endpoint: &DaemonEndpoint) -> Origin {
        origin_for(endpoint, &std::env::current_exe().unwrap_or_default())
    }
}

/// This machine, as the copy of hops at a given path sees it: which daemon
/// counts as the service it may restart is decided against that copy
/// instead of the running program. For a test whose own program is not the
/// hops binary it starts.
pub struct AsProgram(pub PathBuf);

impl Watch for AsProgram {
    fn serves(&mut self, endpoint: &DaemonEndpoint, within: Duration) -> bool {
        ThisMachine.serves(endpoint, within)
    }

    fn ended(&mut self, pid: u32) -> bool {
        ThisMachine.ended(pid)
    }

    fn log_file(&self) -> Option<PathBuf> {
        ThisMachine.log_file()
    }
}

impl Running for AsProgram {
    fn build(&mut self, endpoint: &DaemonEndpoint, within: Duration) -> Option<StatedBuild> {
        ThisMachine.build(endpoint, within)
    }

    fn origin(&mut self, endpoint: &DaemonEndpoint) -> Origin {
        origin_for(endpoint, &self.0)
    }
}

/// Who started the daemon on `endpoint`, as the copy of hops at `exe` sees
/// it: only a daemon of the service that runs that copy is its to restart.
fn origin_for(endpoint: &DaemonEndpoint, exe: &Path) -> Origin {
    #[cfg(target_os = "macos")]
    {
        launchd_origin(
            endpoint.listener(),
            this_user(),
            installed(agent_path().and_then(|path| read_agent(&path)), exe),
            || run_launchctl(&["list"]),
        )
    }
    #[cfg(target_os = "linux")]
    {
        let listener = endpoint.listener();
        let proc = match &listener {
            Ok(listener) => PathBuf::from(format!("/proc/{}", listener.pid)),
            Err(_) => PathBuf::new(),
        };
        proc_origin(listener, this_user(), &proc, exe)
    }
    #[cfg(windows)]
    {
        let _ = (endpoint, exe);
        Origin::Other(ON_WINDOWS.to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (endpoint, exe);
        Origin::Other(not_restarted(
            "hops does not restart its service on this system",
        ))
    }
}

/// What the app says about a daemon of another build on Windows, where it
/// does not restart one: nothing there tells whether the service started the
/// daemon that holds the pipe.
#[cfg_attr(not(windows), allow(dead_code))]
const ON_WINDOWS: &str =
    "On Windows hops does not restart its service. Sign out and back in to run this version.";

/// Why a daemon of another build was left running, and what to do, from the
/// reason it was not restarted.
fn not_restarted(because: &str) -> String {
    format!("hops did not restart it, because {because}. Stop it, then open hops again.")
}

/// This process's user id.
#[cfg(unix)]
fn this_user() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Who started the daemon that answers, as far as this machine can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The hops service, whose daemon is process `pid`: on macOS the process
    /// of its launchd job; on Linux a hops daemon of this user with no
    /// terminal, as the front door and systemd start it. The app may restart
    /// it.
    Service(u32),
    /// Some other way, or it could not be told: what to show the user.
    Other(String),
}

/// What the front door does about a daemon that answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Leave it running: it is this build, or it said nothing about its build.
    Keep,
    /// Restart the service, whose daemon is process `pid`: it runs another
    /// build, or says none.
    Restart(u32),
    /// Leave it running although it runs another build, because the service
    /// did not start it. The words say why, and what to do.
    LeaveOutdated(String),
}

/// What to do about the daemon that answers, decided 2026-09-26 (#222).
///
/// A daemon of this build is kept, whoever started it, and who started it is
/// not asked. A daemon of another build, or one that states none, is
/// restarted only when the hops service started it; any other is left running
/// with the reason. One that said nothing is kept: its build is unknown, and a
/// daemon still starting says nothing either.
pub fn verdict(
    this: &Build,
    stated: Option<&StatedBuild>,
    origin: impl FnOnce() -> Origin,
) -> Verdict {
    match stated {
        None => Verdict::Keep,
        Some(StatedBuild::Is(theirs)) if theirs == this => Verdict::Keep,
        Some(_) => match origin() {
            Origin::Service(pid) => Verdict::Restart(pid),
            Origin::Other(why) => Verdict::LeaveOutdated(why),
        },
    }
}

/// What the front door asks the platform to do. One front door asks once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    /// Start the service: nothing answers.
    Start,
    /// Stop the service's daemon, process `pid`, which runs another build,
    /// and start this build in its place.
    Restart(u32),
}

/// A daemon's build in words: `hops 0.13.0 (abcd123)`, or that it says none.
fn in_words(stated: &StatedBuild) -> String {
    match stated {
        StatedBuild::Is(build) => format!("hops {build}"),
        StatedBuild::Unstated => "an older build that does not say which".to_string(),
    }
}

/// How long one ask for a daemon's build may take. A daemon of this build
/// states it at once; one from before the statement is known only when this
/// is over.
const BUILD_ASK: Duration = Duration::from_secs(1);

/// Run `start` if nothing answers at `endpoint`, and never otherwise; then wait
/// up to `within` for the daemon it started to serve frontends.
///
/// `start` returns the id of the running daemon process. `FnOnce` is part of
/// the guarantee: one call cannot request two starts.
///
/// An endpoint that cannot be worked out (no `$HOME`, no `$XDG_RUNTIME_DIR`)
/// starts nothing. A daemon started from this environment would fail on the
/// same error, and a frontend in it cannot reach a daemon either, so a start
/// could only add a process that exits. A daemon started elsewhere with its
/// own environment may well be running.
pub fn start_unless_running(
    endpoint: Result<DaemonEndpoint, SocketPathError>,
    start: impl FnOnce() -> io::Result<u32>,
    watch: &mut impl Watch,
    within: Duration,
) -> DaemonStart {
    start_unless_running_reported(endpoint, start, watch, within).outcome
}

/// What the front door did about the daemon, with what a user needs to be
/// shown when it did not come up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartReport {
    pub outcome: DaemonStart,
    /// Why nothing was started, or nothing could be asked, in words.
    pub why: Option<String>,
    /// The file the daemon logs to, where it says why it stopped.
    pub log_file: Option<PathBuf>,
    /// How long the front door waited for a daemon it started.
    pub within: Duration,
    /// The build the daemon the front door restarted ran, in words; `None`
    /// when it restarted nothing.
    pub replaced: Option<String>,
    /// Why a daemon of another build was left running, and what to do; `None`
    /// when none was.
    pub left: Option<String>,
    /// The build the daemon left running states, in words, with [`Self::left`].
    pub left_build: Option<String>,
}

/// Why the daemon of another build still runs after a restart that did not
/// stop it.
const DID_NOT_STOP: &str = "hops tried to restart it, and it did not stop. Stop it, then open \
                            hops again.";

impl StartReport {
    /// What to show the user, or `None` when a daemon is running.
    ///
    /// Without this a start that failed reached the screen as "connecting",
    /// indefinitely, with the reason in a log nobody was pointed at (#189).
    pub fn problem(&self) -> Option<String> {
        if self.outcome == DaemonStart::AlreadyRunning {
            // A daemon of another build still serves. Said here as well as
            // beside the build once connected: a daemon from before the
            // token cannot be connected to at all (#222).
            let why = self.left.as_deref()?;
            let theirs = self.left_build.as_deref().unwrap_or("another build");
            return Some(format!(
                "The hops service is running {theirs}, not this version. {why}"
            ));
        }
        let log = |lead: &str| match &self.log_file {
            // On a line of its own, so a wrapped line does not split the path.
            Some(path) => format!("{lead}:\n{}", path.display()),
            None => String::new(),
        };
        let why = self.why.as_deref().unwrap_or("no reason was given");
        match self.outcome {
            DaemonStart::AlreadyRunning | DaemonStart::Started(_) => None,
            DaemonStart::Exited(_) => Some(format!(
                "The hops service started and stopped again before it answered. {}",
                log("Its log says why")
            )),
            DaemonStart::NoAnswer(_) => Some(format!(
                "The hops service was started but did not answer within {}. It may still \
                 be starting. {}",
                seconds(self.within),
                log("If this stays, its log may say why")
            )),
            DaemonStart::StartFailed => {
                Some(format!("The hops service could not be started: {why}."))
            }
            DaemonStart::CannotProbe => Some(format!(
                "hops could not work out where its service listens ({why}), so it did \
                 not start one."
            )),
        }
        .map(|text| match &self.replaced {
            Some(old) => format!(
                "hops tried to restart its service, which was running {old}, not this \
                 version. {text}"
            ),
            None => text,
        })
        .map(|text| text.trim_end().to_string())
    }

    /// What the front door did about a daemon of another build, to tell the
    /// user once the app is open: that it restarted the service. `None` when
    /// it restarted nothing, or the restart did not come up (see
    /// [`Self::problem`]).
    pub fn note(&self) -> Option<String> {
        match (self.outcome, &self.replaced) {
            (DaemonStart::Started(_), Some(old)) => Some(format!(
                "hops restarted its service because it was running {old}, not this version."
            )),
            _ => None,
        }
    }
}

/// [`start_unless_running`], reporting why a start did not come up.
pub fn start_unless_running_reported(
    endpoint: Result<DaemonEndpoint, SocketPathError>,
    start: impl FnOnce() -> io::Result<u32>,
    watch: &mut impl Watch,
    within: Duration,
) -> StartReport {
    front_door(
        endpoint,
        None,
        |_| start(),
        watch,
        within,
        |_, _| (Verdict::Keep, None),
    )
}

/// [`start_unless_running_reported`], and when a daemon answers, restart the
/// service when that daemon is another build than `this` (#222); see
/// [`verdict`].
///
/// `launch` is asked at most once: to start the service when nothing answers,
/// or to restart it. It returns the id of the daemon process it started.
pub fn start_or_restart_reported<W: Watch + Running>(
    endpoint: Result<DaemonEndpoint, SocketPathError>,
    this: &Build,
    launch: impl FnOnce(Launch) -> io::Result<u32>,
    watch: &mut W,
    within: Duration,
) -> StartReport {
    start_or_restart_beside_older(endpoint, None, this, launch, watch, within)
}

/// [`start_or_restart_reported`], first asking `older`, where a daemon of an
/// older build listens that `endpoint` does not reach
/// ([`DaemonEndpoint::of_older_builds`]). While a hops daemon answers there
/// nothing is launched, and the report says what to do.
pub fn start_or_restart_beside_older<W: Watch + Running>(
    endpoint: Result<DaemonEndpoint, SocketPathError>,
    older: Option<DaemonEndpoint>,
    this: &Build,
    launch: impl FnOnce(Launch) -> io::Result<u32>,
    watch: &mut W,
    within: Duration,
) -> StartReport {
    front_door(endpoint, older, launch, watch, within, |endpoint, watch| {
        let stated = ask_build(endpoint, watch, within);
        let verdict = verdict(this, stated.as_ref(), || watch.origin(endpoint));
        (verdict, stated)
    })
}

/// Ask the daemon on `endpoint` which build it is until it says, it stops
/// answering, or `within` is over: one that has just bound its endpoint says
/// nothing until it has read its token and its config.
///
/// A daemon that sends state without its build is asked once more before it
/// counts as one from before the statement, since that is concluded from a
/// wait running out: a daemon of this build that was slow to handle the
/// first ask states its build on the second.
fn ask_build(
    endpoint: &DaemonEndpoint,
    watch: &mut impl Running,
    within: Duration,
) -> Option<StatedBuild> {
    let deadline = Instant::now() + within;
    let mut unstated_once = false;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match watch.build(endpoint, left.min(BUILD_ASK)) {
            Some(StatedBuild::Unstated) if !unstated_once => unstated_once = true,
            Some(stated) => return Some(stated),
            None => {}
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || !endpoint.answers() {
            return None;
        }
        std::thread::sleep(ASK_EVERY.min(left));
    }
}

/// The front door: start the service when nothing answers at `endpoint`;
/// when a daemon answers, do what `judge` decides about it. Then wait up to
/// `within` for a daemon it started to serve frontends.
fn front_door<W: Watch>(
    endpoint: Result<DaemonEndpoint, SocketPathError>,
    older: Option<DaemonEndpoint>,
    launch: impl FnOnce(Launch) -> io::Result<u32>,
    watch: &mut W,
    within: Duration,
    judge: impl FnOnce(&DaemonEndpoint, &mut W) -> (Verdict, Option<StatedBuild>),
) -> StartReport {
    let report = |outcome, why: Option<String>| StartReport {
        outcome,
        why,
        log_file: None,
        within,
        replaced: None,
        left: None,
        left_build: None,
    };
    let endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(e) => {
            log::warn!("cannot tell whether a daemon is running ({e}); not starting one");
            return report(DaemonStart::CannotProbe, Some(e.to_string()));
        }
    };
    let answers = endpoint.answers();
    // A daemon of an older build does not answer on this build's endpoint,
    // and would run on beside one started here (#222: at most one daemon).
    // Asked only while none of this build answers: one that does holds the
    // older endpoint ([`hold_older_endpoint`]), so no older daemon runs
    // beside it, and asking there would only make every open wait.
    if let Some(older) = older.filter(|older| !answers && older_daemon_at(older)) {
        log::warn!("a daemon of {OLDER_BUILD} answers on {older}; not starting one beside it");
        return StartReport {
            left: Some(format!("{BESIDE_OLDER} {}", older_stop(&older))),
            left_build: Some(OLDER_BUILD.to_string()),
            ..report(DaemonStart::AlreadyRunning, None)
        };
    }
    let (how, replaced) = if answers {
        let (verdict, stated) = judge(&endpoint, watch);
        let theirs = stated.as_ref().map(in_words).unwrap_or_default();
        match verdict {
            Verdict::Keep => {
                log::info!("a daemon answers on {endpoint}; not starting another");
                return report(DaemonStart::AlreadyRunning, None);
            }
            Verdict::LeaveOutdated(why) => {
                log::warn!(
                    "the daemon on {endpoint} runs {theirs}, not this build, and is left \
                     running: {why}"
                );
                return StartReport {
                    left: Some(why),
                    left_build: stated.as_ref().map(in_words),
                    ..report(DaemonStart::AlreadyRunning, None)
                };
            }
            Verdict::Restart(pid) => {
                log::info!(
                    "the daemon on {endpoint} (process {pid}) runs {theirs}, not this \
                     build; restarting the hops service"
                );
                (Launch::Restart(pid), Some(theirs))
            }
        }
    } else {
        log::info!("no daemon answers on {endpoint}; starting one");
        (Launch::Start, None)
    };
    let pid = match launch(how) {
        Ok(pid) => pid,
        Err(e) => {
            log::warn!("could not start the daemon: {e}");
            return StartReport {
                replaced,
                ..report(DaemonStart::StartFailed, Some(e.to_string()))
            };
        }
    };
    if how == Launch::Restart(pid) {
        // The service still runs the daemon it was to replace: a restart
        // that stopped nothing is no restart.
        log::warn!(
            "the hops service still runs process {pid}, the daemon of the other build; \
             it did not stop"
        );
        return StartReport {
            left: Some(DID_NOT_STOP.to_string()),
            left_build: replaced.clone(),
            replaced,
            ..report(DaemonStart::AlreadyRunning, None)
        };
    }
    let outcome = wait_for_daemon(&endpoint, pid, watch, within);
    let log_file = watch.log_file();
    match outcome {
        DaemonStart::Started(_) | DaemonStart::AlreadyRunning => log::info!(
            "{}",
            what_became_of(pid, outcome, &endpoint, within, log_file.as_deref())
        ),
        _ => log::warn!(
            "{}",
            what_became_of(pid, outcome, &endpoint, within, log_file.as_deref())
        ),
    }
    // A daemon still answers beside the one this restart started, which
    // stopped: the one it was to replace did not stop.
    let left = (outcome == DaemonStart::AlreadyRunning && replaced.is_some())
        .then(|| DID_NOT_STOP.to_string());
    StartReport {
        log_file,
        left_build: left.as_ref().and(replaced.clone()),
        replaced,
        left,
        ..report(outcome, None)
    }
}

/// Wait up to `within` for the daemon process `pid` to serve frontends on
/// `endpoint`. Returns [`DaemonStart::Started`], [`DaemonStart::NoAnswer`],
/// [`DaemonStart::Exited`], or [`DaemonStart::AlreadyRunning`] when another
/// daemon serves and `pid` has ended.
///
/// Each ask gets at most what is left of the wait, so the wait is over by
/// `within` whatever is on the endpoint, give or take one connection attempt
/// once `pid` has ended.
fn wait_for_daemon(
    endpoint: &DaemonEndpoint,
    pid: u32,
    watch: &mut impl Watch,
    within: Duration,
) -> DaemonStart {
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if watch.serves(endpoint, left.min(ASK_WITHIN)) {
            return if watch.ended(pid) {
                // Two starts overlapped, and this one stopped beside the other.
                DaemonStart::AlreadyRunning
            } else {
                DaemonStart::Started(pid)
            };
        }
        let ended = watch.ended(pid);
        // Nothing more will come, unless another daemon holds the endpoint and
        // is still starting: then this one stopped as already running.
        if ended && !endpoint.answers() {
            return DaemonStart::Exited(pid);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return if ended {
                DaemonStart::Exited(pid)
            } else {
                DaemonStart::NoAnswer(pid)
            };
        }
        std::thread::sleep(ASK_EVERY.min(left));
    }
}

/// The log line for what became of daemon process `pid` after a start.
fn what_became_of(
    pid: u32,
    outcome: DaemonStart,
    endpoint: &DaemonEndpoint,
    within: Duration,
    log_file: Option<&Path>,
) -> String {
    let see = match log_file {
        Some(path) => format!("; see {}", path.display()),
        None => String::new(),
    };
    match outcome {
        DaemonStart::Started(_) => {
            format!("the daemon is running as process {pid} and answers on {endpoint}")
        }
        DaemonStart::AlreadyRunning => format!(
            "process {pid} exited, and another daemon answers on {endpoint}; not starting \
             another"
        ),
        DaemonStart::Exited(_) => {
            format!("the daemon (process {pid}) exited before it answered on {endpoint}{see}")
        }
        _ => format!(
            "the daemon (process {pid}) did not answer on {endpoint} within {}{see}",
            seconds(within)
        ),
    }
}

/// `within` in words: "5 s", or "0.25 s" for less than a whole second.
fn seconds(within: Duration) -> String {
    format!("{} s", within.as_secs_f64())
}

/// [`start_unless_running`] against this platform's own endpoint, the one the
/// daemon's IPC listener binds.
pub fn ensure_running_with(
    start: impl FnOnce() -> io::Result<u32>,
    watch: &mut impl Watch,
    within: Duration,
) -> DaemonStart {
    start_unless_running(DaemonEndpoint::of_this_platform(), start, watch, within)
}

/// [`ensure_running_with`], reporting why a start did not come up.
pub fn ensure_running_reported_with(
    start: impl FnOnce() -> io::Result<u32>,
    watch: &mut impl Watch,
    within: Duration,
) -> StartReport {
    start_unless_running_reported(DaemonEndpoint::of_this_platform(), start, watch, within)
}

/// Make sure a daemon of this build is running: start one if none answers,
/// and restart the service if the one that answers is another build and the
/// service started it (#222).
///
/// A daemon of this build is left alone whoever started it. On macOS that
/// also means no LaunchAgent is installed beside it to race it at the next
/// login.
#[cfg(any(feature = "tui", feature = "slint"))]
pub fn ensure_running() -> StartReport {
    start_or_restart_beside_older(
        DaemonEndpoint::of_this_platform(),
        DaemonEndpoint::of_older_builds(),
        &crate::config::this_build(),
        launch_platform_daemon,
        &mut ThisMachine,
        START_WAIT,
    )
}

/// Start the daemon the way this platform runs it: the GRANTED launchd service
/// on macOS, never a child of ours (which could land on the dummy backend);
/// a detached background process elsewhere. A restart first stops the
/// service's daemon of the other build. Returns the daemon's process id.
#[cfg(any(feature = "tui", feature = "slint"))]
fn launch_platform_daemon(launch: Launch) -> io::Result<u32> {
    #[cfg(target_os = "macos")]
    {
        ensure_launchd_daemon(launch)
    }
    #[cfg(target_os = "linux")]
    {
        if let Launch::Restart(pid) = launch {
            let endpoint = DaemonEndpoint::of_this_platform().map_err(io::Error::other)?;
            stop_outdated_daemon(pid, &endpoint, START_WAIT)?;
        }
        start_detached_daemon()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        match launch {
            Launch::Start => start_detached_daemon(),
            // Not asked for: no daemon here counts as the service's; see
            // `ThisMachine::origin`.
            Launch::Restart(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hops does not restart its service on this system",
            )),
        }
    }
}

/// The launchd job the daemon runs as on macOS.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
const LAUNCHD_LABEL: &str = "com.grabbr.hops";

/// The app bundle's identifier, named in the plist so System Settings lists
/// the job under hops (`man launchd.plist`, AssociatedBundleIdentifiers).
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
const APP_BUNDLE_ID: &str = "com.grabbr.hops";

/// The status `launchctl kickstart` exits with for a job that is already
/// running (`EALREADY`). It prints that process's id as it does for a process
/// it started.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
const KICKSTART_ALREADY_RUNNING: i32 = 37;

/// What one `launchctl` run reported.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
#[derive(Debug)]
struct LaunchctlRun {
    /// Its exit status, `None` when a signal ended it.
    code: Option<i32>,
    /// How it exited, for a message.
    status: String,
    stdout: String,
    stderr: String,
}

#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
impl LaunchctlRun {
    /// It exited with status 0.
    fn succeeded(&self) -> bool {
        self.code == Some(0)
    }

    /// `launchctl` names what went wrong on stderr.
    fn reason(&self) -> String {
        match self.stderr.trim() {
            "" => self.status.clone(),
            said => format!("{} ({said})", self.status),
        }
    }
}

/// Bring the launchd job up, and return the id of its running process.
///
/// Runs when no daemon answers on the endpoint (see [`start_unless_running`]),
/// or, with `replacing`, to restart the job whose process `replacing` names
/// because it runs another build (#222). Only that stops a daemon that serves.
///
/// `agent` first makes the job's plist run this binary the way this build
/// runs the daemon, and says whether it had to change the file. A job that is
/// not loaded is then bootstrapped from the plist. A loaded job keeps the
/// definition it was loaded with, so one whose plist was just changed is
/// booted out and bootstrapped again: until then launchd would go on starting
/// the binary the old plist named, which after the app moves is a path that
/// is not there (#170). A plist that could not be changed leaves the job
/// loaded as it was, and the start fails naming the file.
///
/// A restart boots the loaded job out the same way, waits for its process to
/// exit, and bootstraps the plist again, which `agent` has pointed at this
/// binary. `RunAtLoad` then starts this build.
///
/// Either way the job is then kickstarted without `-k`: launchd starts a job
/// that is loaded but has no process, and leaves a running one alone. The
/// plist's `KeepAlive` restarts the daemon only after an unsuccessful exit,
/// so a daemon that quit, or exited because another held the endpoint, stays
/// loaded with no process until something starts it. Its `RunAtLoad` starts
/// the daemon as the job is bootstrapped, so the kickstart after a bootstrap
/// usually finds it running.
///
/// Succeeds only when `kickstart -p` names a process, having started it (exit
/// 0) or found it running (exit 37). `launchctl print` says whether the job is
/// loaded, by its exit status alone; its output is not read, since
/// launchctl(1) says it is not an interface.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn start_through_launchd(
    uid: u32,
    launchctl: &mut dyn FnMut(&[&str]) -> io::Result<LaunchctlRun>,
    agent: impl FnOnce() -> io::Result<AgentFile>,
    pause: &mut dyn FnMut(Duration),
    replacing: Option<Replacing<'_>>,
) -> io::Result<u32> {
    let domain = format!("gui/{uid}");
    let service = format!("{domain}/{LAUNCHD_LABEL}");
    let mut launch = |args: &[&str]| {
        launchctl(args).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("could not run `launchctl {}`: {e}", args.join(" ")),
            )
        })
    };

    let loaded = launch(&["print", &service])?.succeeded();
    let agent = agent()?;
    // The daemon to replace has already exited: another front door restarted
    // the service, and a bootout now would stop the daemon of this build it
    // started. Nothing is stopped; the kickstart names what runs.
    let mut replacing = replacing;
    let replaced_already = match replacing.as_mut() {
        Some(Replacing { pid, gone }) => gone(*pid),
        None => false,
    };
    let reload = loaded && !replaced_already && (agent.rewritten || replacing.is_some());
    if replaced_already {
        log::info!("the daemon to replace has already stopped; not stopping the job");
    }
    if reload {
        stop_service_daemon(Stop::Job {
            launch: &mut launch,
            service: &service,
        })?;
        if let Some(Replacing { pid, gone }) = replacing {
            // launchd sends the job's process SIGTERM, and the daemon lets go
            // of held keys before it exits. Until it has, it holds the
            // endpoint, and this build's daemon would stop beside it.
            let mut waited = Duration::ZERO;
            while !gone(pid) && waited < START_WAIT {
                pause(ASK_EVERY);
                waited += ASK_EVERY;
            }
        }
    }

    let mut not_loaded = String::new();
    if !loaded || reload {
        // launchd tears a booted-out job down after `bootout` returns, and a
        // bootstrap that comes too soon fails with an I/O error; so after a
        // bootout a failed bootstrap is tried again.
        let mut waits = if reload { REBOOTSTRAP_WAITS } else { &[] }.iter();
        loop {
            let bootstrap = launch(&["bootstrap", &domain, &agent.path])?;
            if bootstrap.succeeded() {
                break;
            }
            if let Some(&wait) = waits.next() {
                pause(wait);
                continue;
            }
            // Another start may have loaded the job since `print`, so this is
            // not yet a failure: the kickstart below says whether it runs.
            not_loaded = format!(
                "`launchctl bootstrap {domain} {}` failed: {}; ",
                agent.path,
                bootstrap.reason()
            );
            break;
        }
    }

    let kick = launch(&["kickstart", "-p", &service])?;
    let named_a_process = matches!(kick.code, Some(0 | KICKSTART_ALREADY_RUNNING));
    match (named_a_process, pid_in(&kick.stdout)) {
        (true, Some(pid)) => Ok(pid),
        (true, None) => Err(io::Error::other(format!(
            "{not_loaded}`launchctl kickstart -p {service}` named no running process \
             (it printed {:?})",
            kick.stdout.trim()
        ))),
        (false, _) => Err(io::Error::other(format!(
            "{not_loaded}`launchctl kickstart -p {service}` failed: {}",
            kick.reason()
        ))),
    }
}

/// The daemon a restart replaces: its process id, and whether a process id
/// has ended.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
struct Replacing<'a> {
    pid: u32,
    gone: &'a mut dyn FnMut(u32) -> bool,
}

/// How [`stop_service_daemon`] stops the service's daemon.
enum Stop<'a> {
    /// Boot launchd's job `service` out: launchd sends its process SIGTERM
    /// and unloads the job until it is bootstrapped again.
    #[cfg_attr(
        not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
        allow(dead_code)
    )]
    Job {
        launch: &'a mut dyn FnMut(&[&str]) -> io::Result<LaunchctlRun>,
        service: &'a str,
    },
    /// Send SIGTERM to the process this pidfd names, checked to be the hops
    /// daemon of this user that holds the endpoint.
    #[cfg(target_os = "linux")]
    Process(&'a std::os::fd::OwnedFd),
}

/// Stop the daemon of the hops service, so that a start can run this build
/// in its place.
///
/// The only code in the front door that stops a process; the decision guards
/// scan this file to hold it to that. It runs for two reasons: launchd's job
/// must be reloaded because its plist was rewritten while nothing answers
/// (#170), or the daemon that answers runs another build and the service
/// started it (#222; see [`verdict`]). A daemon of this build is never
/// stopped here.
#[cfg_attr(
    not(any(
        target_os = "linux",
        all(target_os = "macos", any(feature = "tui", feature = "slint"))
    )),
    allow(dead_code)
)]
fn stop_service_daemon(stop: Stop<'_>) -> io::Result<()> {
    match stop {
        Stop::Job { launch, service } => {
            let out = launch(&["bootout", service])?;
            if !out.succeeded() {
                // Whether the job is loaded is for the bootstrap after this to
                // say.
                log::debug!("`launchctl bootout {service}`: {}", out.reason());
            }
            Ok(())
        }
        #[cfg(target_os = "linux")]
        Stop::Process(pidfd) => {
            use std::os::fd::AsRawFd;
            // SAFETY: `pidfd` is open; the call takes plain values and no
            // `siginfo`, which the kernel reads as a plain kill.
            let sent = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGTERM,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if sent == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

/// How long to wait before each further bootstrap of a job just booted out.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
const REBOOTSTRAP_WAITS: &[Duration] = &[
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];

/// The job's plist as [`point_agent_at`] left it.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
#[derive(Debug)]
struct AgentFile {
    /// Where it is.
    path: String,
    /// Whether it was written or changed, so a loaded job must be reloaded.
    rewritten: bool,
}

/// The process id `launchctl kickstart -p` printed: a bare number when its
/// output is a pipe, `service spawned with pid: <n>` on a terminal.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn pid_in(stdout: &str) -> Option<u32> {
    // Take the last word that is a whole number, so a label or a `gui/<uid>`
    // domain around it is never read as the process.
    stdout
        .split_whitespace()
        .rev()
        .filter_map(|word| {
            word.trim_matches(|c: char| c.is_ascii_punctuation())
                .parse::<u32>()
                .ok()
        })
        .find(|&pid| pid > 0)
}

/// [`start_through_launchd`] with the real `launchctl`, for this user.
#[cfg(all(target_os = "macos", any(feature = "tui", feature = "slint")))]
fn ensure_launchd_daemon(launch: Launch) -> io::Result<u32> {
    let mut gone = crate::pid::is_gone;
    let replacing = match launch {
        Launch::Start => None,
        Launch::Restart(pid) => Some(Replacing {
            pid,
            gone: &mut gone,
        }),
    };
    start_through_launchd(
        this_user(),
        &mut run_launchctl,
        keep_agent_pointing_here,
        &mut std::thread::sleep,
        replacing,
    )
}

#[cfg(target_os = "macos")]
fn run_launchctl(args: &[&str]) -> io::Result<LaunchctlRun> {
    let out = std::process::Command::new("launchctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()?;
    Ok(LaunchctlRun {
        code: out.status.code(),
        status: out.status.to_string(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// [`point_agent_at`] for `~/Library/LaunchAgents/com.grabbr.hops.plist` and
/// the binary the user launched. The Accessibility grant can be bound to the
/// path, so the plist must name whatever `hops` binary the user actually ran.
#[cfg(all(target_os = "macos", any(feature = "tui", feature = "slint")))]
fn keep_agent_pointing_here() -> io::Result<AgentFile> {
    let plist = agent_path()?;
    let logs = home()?.join("hops/logs");
    let _ = std::fs::create_dir_all(&logs);
    point_agent_at(&plist, &std::env::current_exe()?, &logs.join("daemon.log"))
}

/// `$HOME`.
#[cfg(target_os = "macos")]
fn home() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "$HOME is not set"))
}

/// Where hops writes its launchd job's plist:
/// `~/Library/LaunchAgents/com.grabbr.hops.plist`.
#[cfg(target_os = "macos")]
fn agent_path() -> io::Result<PathBuf> {
    Ok(home()?.join(format!("Library/LaunchAgents/{LAUNCHD_LABEL}.plist")))
}

/// Whether hops' launchd job is running process `pid`, from what `launchctl
/// list` prints: one job a line, in three columns separated by tabs, the
/// first the job's process id or `-`, the third its label (launchctl(1)).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn job_runs(list: &str, pid: u32) -> bool {
    list.lines().any(|line| {
        let mut columns = line.splitn(3, '\t');
        let (Some(running), Some(_), Some(label)) =
            (columns.next(), columns.next(), columns.next())
        else {
            return false;
        };
        label.trim() == LAUNCHD_LABEL && running.trim().parse::<u32>().ok() == Some(pid)
    })
}

/// What hops' launchd job would run, as its plist says, beside this binary.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum Installed {
    /// There is no plist, or it could not be looked at.
    No,
    /// It runs this binary, or one that is no longer there, or it cannot be
    /// read: a restart points it at this binary.
    ThisCopy,
    /// It runs another copy of hops, which is there: a build in a checkout,
    /// say, beside the installed app.
    AnotherCopy(String),
}

/// [`Installed`], from the plist `agent` and this binary, `exe`.
///
/// A restart points the plist at the binary that restarts it, and on macOS
/// the permissions hops holds belong to the binary the plist names. So the
/// service is restarted only by the copy of hops it runs: an app replaced in
/// place, or one moved. Another copy would take the service over without
/// them.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn installed(agent: io::Result<OnDisk>, exe: &Path) -> Installed {
    let plist = match agent {
        Ok(OnDisk::Found(plist)) => plist,
        Ok(OnDisk::Unreadable(_)) => return Installed::ThisCopy,
        Ok(OnDisk::Missing) | Err(_) => return Installed::No,
    };
    let program = plist
        .get("ProgramArguments")
        .and_then(serde_json::Value::as_array)
        .and_then(|args| args.first())
        .and_then(serde_json::Value::as_str);
    match program {
        Some(other) if !names_file(other, exe) && Path::new(other).exists() => {
            Installed::AnotherCopy(other.to_string())
        }
        _ => Installed::ThisCopy,
    }
}

/// Who started the daemon `listener` names, on macOS: hops' launchd job when
/// its plist is `installed` for this copy of hops and `launchctl list` says
/// the job runs that process. The restart boots out and bootstraps that job,
/// which can stop nothing else, so any other daemon is left running with the
/// reason.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn launchd_origin(
    listener: io::Result<Listener>,
    uid: u32,
    installed: Installed,
    list: impl FnOnce() -> io::Result<LaunchctlRun>,
) -> Origin {
    let listener = match listener {
        Ok(listener) => listener,
        Err(e) => {
            return Origin::Other(not_restarted(&format!(
                "it could not tell which process serves it ({e})"
            )));
        }
    };
    if listener.uid != uid {
        return Origin::Other(not_restarted("it runs as another user"));
    }
    match installed {
        Installed::ThisCopy => {}
        Installed::No => {
            return Origin::Other(not_restarted(
                "the hops service is not installed, so it did not start it",
            ));
        }
        Installed::AnotherCopy(program) => {
            return Origin::Other(not_restarted(&format!(
                "the hops service runs another copy of hops, {program}"
            )));
        }
    }
    match list() {
        Ok(run) if run.succeeded() && job_runs(&run.stdout, listener.pid) => {
            Origin::Service(listener.pid)
        }
        Ok(run) if run.succeeded() => Origin::Other(not_restarted(
            "the hops service did not start it; it may be running in a terminal",
        )),
        Ok(run) => Origin::Other(not_restarted(&format!(
            "launchd did not say which process the hops service runs ({})",
            run.reason()
        ))),
        Err(e) => Origin::Other(not_restarted(&format!(
            "launchd could not be asked which process the hops service runs ({e})"
        ))),
    }
}

/// Whether launchd starts this process again after it exits unsuccessfully:
/// it is the process of hops' launchd job, and the job's plist restarts the
/// daemon after a failure (#221).
#[cfg(target_os = "macos")]
pub fn launchd_restarts_this_process() -> bool {
    launchd_restarts(
        agent_path().and_then(|path| read_agent(&path)),
        || run_launchctl(&["list"]),
        std::process::id(),
    )
}

/// Whether launchd starts process `pid` again after it exits unsuccessfully:
/// hops' job, whose plist is `agent`, restarts its daemon after a failure,
/// and `launchctl list`, asked only then, says the job runs `pid`. A daemon
/// run any other way that exits stays down.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn launchd_restarts(
    agent: io::Result<OnDisk>,
    list: impl FnOnce() -> io::Result<LaunchctlRun>,
    pid: u32,
) -> bool {
    matches!(agent, Ok(OnDisk::Found(plist)) if restarts_after_failure(&plist))
        && list().is_ok_and(|run| run.succeeded() && job_runs(&run.stdout, pid))
}

/// Whether a job with this plist is started again after an unsuccessful exit.
///
/// `KeepAlive` `true` restarts after any exit; a dictionary restarts after a
/// failure only when it says `SuccessfulExit` is false.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn restarts_after_failure(agent: &Plist) -> bool {
    use serde_json::Value;
    match agent.get("KeepAlive") {
        Some(Value::Bool(always)) => *always,
        Some(Value::Object(when)) => when.get("SuccessfulExit") == Some(&Value::Bool(false)),
        _ => false,
    }
}

/// A plist's top-level dictionary, as `plutil` reads it into JSON.
type Plist = serde_json::Map<String, serde_json::Value>;

/// The plist this build writes for a job that runs `exe` as the daemon.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn fresh_agent(exe: &str, log: &str) -> Plist {
    let serde_json::Value::Object(plist) = serde_json::json!({
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": [exe, "daemon"],
        "RunAtLoad": true,
        "KeepAlive": { "SuccessfulExit": false },
        "ThrottleInterval": 10,
        "ProcessType": "Interactive",
        "AssociatedBundleIdentifiers": [APP_BUNDLE_ID],
        "StandardOutPath": log,
        "StandardErrorPath": log,
    }) else {
        unreachable!("a JSON object literal")
    };
    plist
}

/// Make `agent` run `exe` as the daemon under this job's label, restarted
/// after an unsuccessful exit, touching no other key: whoever wrote the file
/// may have set its environment or its log paths. Returns what was wrong with
/// it, empty when nothing was.
///
/// The program counts as `exe` when it names the same file, so a link to the
/// binary is left alone. A path that names no file is always wrong: it is
/// what launchd is left starting after the app moves.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn repoint(agent: &mut Plist, exe: &Path, exe_text: &str) -> Vec<String> {
    use serde_json::{Value, json};
    let mut wrong = Vec::new();

    if agent.get("Label").and_then(Value::as_str) != Some(LAUNCHD_LABEL) {
        wrong.push(format!(
            "its label was {}",
            agent.get("Label").unwrap_or(&Value::Null)
        ));
        agent.insert("Label".into(), json!(LAUNCHD_LABEL));
    }

    let program: Vec<&str> = agent
        .get("ProgramArguments")
        .and_then(Value::as_array)
        .map(|args| args.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let runs_exe = matches!(program.as_slice(), [bin, "daemon"] if names_file(bin, exe));
    if !runs_exe {
        wrong.push(format!("it ran `{}`", program.join(" ")));
        agent.insert("ProgramArguments".into(), json!([exe_text, "daemon"]));
    }

    // v0.12 wrote `false`, so a daemon that crashed stayed down for the rest
    // of the session.
    if !restarts_after_failure(agent) {
        wrong.push("launchd would not restart it after a failure".into());
        agent.insert("KeepAlive".into(), json!({ "SuccessfulExit": false }));
        agent.entry("ThrottleInterval").or_insert_with(|| json!(10));
    }

    // A string or an array of strings; identifiers of other apps stay.
    let mut apps: Vec<Value> = match agent.remove("AssociatedBundleIdentifiers") {
        Some(Value::Array(apps)) => apps,
        Some(Value::String(app)) => vec![Value::String(app)],
        _ => Vec::new(),
    };
    if !apps.iter().any(|app| app.as_str() == Some(APP_BUNDLE_ID)) {
        wrong.push("it named no app".into());
        apps.push(json!(APP_BUNDLE_ID));
    }
    agent.insert("AssociatedBundleIdentifiers".into(), Value::Array(apps));
    wrong
}

/// Whether `named` names the same file as `exe`: the same path, or one that
/// resolves to it. A path that resolves to nothing names no file.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn names_file(named: &str, exe: &Path) -> bool {
    let named = Path::new(named);
    match (std::fs::canonicalize(named), std::fs::canonicalize(exe)) {
        (Ok(a), Ok(b)) => a == b,
        (Err(_), _) => false,
        (Ok(_), Err(_)) => named == exe,
    }
}

/// What is at a plist's path.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
#[derive(Debug)]
enum OnDisk {
    Missing,
    /// There, but `plutil` could not read a dictionary from it.
    Unreadable(String),
    Found(Plist),
}

/// Read the plist at `path` with `plutil`, the parser launchd's own tools
/// use, so any format and layout another writer used reads the same.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn read_agent(path: &Path) -> io::Result<OnDisk> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(OnDisk::Missing),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    let out = std::process::Command::new("plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(path)
        .stdin(std::process::Stdio::null())
        .output()?;
    if !out.status.success() {
        return Ok(OnDisk::Unreadable(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(match serde_json::from_slice(&out.stdout) {
        Ok(serde_json::Value::Object(plist)) => OnDisk::Found(plist),
        _ => OnDisk::Unreadable("it does not hold a dictionary".into()),
    })
}

/// Write `plist` to `path` as an XML plist, replacing the file in one step.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn write_agent(path: &Path, plist: &Plist) -> io::Result<()> {
    use std::io::Write;
    let fail =
        |e: io::Error| io::Error::new(e.kind(), format!("could not write {}: {e}", path.display()));
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    let staged = path.with_extension("plist.new");
    let mut plutil = std::process::Command::new("plutil")
        .args(["-convert", "xml1", "-o"])
        .arg(&staged)
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(fail)?;
    if let Some(mut stdin) = plutil.stdin.take() {
        stdin
            .write_all(
                serde_json::Value::Object(plist.clone())
                    .to_string()
                    .as_bytes(),
            )
            .map_err(fail)?;
    }
    let out = plutil.wait_with_output().map_err(fail)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&staged);
        return Err(fail(io::Error::other(format!(
            "plutil: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))));
    }
    std::fs::rename(&staged, path).map_err(fail)
}

/// Where `exe` runs from that a LaunchAgent must not name, if it does: the
/// disk image hops ships in, or the copy macOS makes to run a quarantined
/// app from (App Translocation). The image cannot be ejected while the
/// daemon runs from it, and after it is, or after the copy is cleared,
/// nothing starts at login.
///
/// The path is judged where it leads: `/Volumes` also holds a link to the
/// startup disk, and a binary reached through it is installed.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn not_installed(exe: &Path) -> Option<&'static str> {
    let resolved = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    place_of(&resolved, mounted_read_only)
}

/// [`not_installed`] for a path already resolved, with `read_only` saying
/// whether the file system holding a path is mounted read-only.
///
/// A volume under `/Volumes` counts as the disk image only when it is
/// read-only, as a mounted image is: a second disk that holds someone's
/// Applications folder is mounted there too, and an app on it is installed.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn place_of(resolved: &Path, read_only: impl Fn(&Path) -> bool) -> Option<&'static str> {
    use std::path::Component;
    let parts: Vec<Component> = resolved.components().collect();
    if matches!(parts.as_slice(), [Component::RootDir, Component::Normal(v), ..] if *v == "Volumes")
        && read_only(resolved)
    {
        return Some("a mounted disk image");
    }
    if parts
        .iter()
        .any(|c| matches!(c, Component::Normal(n) if *n == "AppTranslocation"))
    {
        return Some("a temporary copy macOS made to run it from");
    }
    None
}

/// Whether the file system holding `path` is mounted read-only. A path that
/// cannot be examined counts as read-only: the binary running is always
/// there, so this is not a case a user meets, and moving hops to
/// Applications is what the refusal asks for either way.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn mounted_read_only(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return true;
        };
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `c_path` is a NUL-terminated string that outlives the call,
        // and `stat` is only read after the call reports that it filled it.
        if unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return true;
        }
        // SAFETY: statvfs returned 0, so it wrote the whole struct.
        let stat = unsafe { stat.assume_init() };
        stat.f_flag & libc::ST_RDONLY != 0
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

/// Make the plist at `path` run `exe` as the daemon: write it when it is
/// missing or unreadable, change it when it runs another binary or would not
/// be restarted after a failure, and leave it alone otherwise.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn point_agent_at(path: &Path, exe: &Path, log: &Path) -> io::Result<AgentFile> {
    if let Some(place) = not_installed(exe) {
        log::warn!(
            "not pointing {} at {}, which is on {place}",
            path.display(),
            exe.display()
        );
        return Err(io::Error::other(format!(
            "hops is running from {place}, so it cannot be started at login from \
             there. Quit it, move hops to Applications and open it from there"
        )));
    }
    let exe_text = exe.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} cannot be written into a plist", exe.display()),
        )
    })?;
    let written = |rewritten| AgentFile {
        path: path.to_string_lossy().into_owned(),
        rewritten,
    };
    let fresh = || fresh_agent(exe_text, &log.to_string_lossy());
    let (pointed, plist) = match read_agent(path)? {
        OnDisk::Missing => {
            log::info!("writing {} to run {exe_text}", path.display());
            let plist = fresh();
            write_agent(path, &plist)?;
            (written(true), plist)
        }
        OnDisk::Unreadable(why) => {
            log::warn!(
                "{} could not be read ({why}); writing it again to run {exe_text}",
                path.display()
            );
            let plist = fresh();
            write_agent(path, &plist)?;
            (written(true), plist)
        }
        OnDisk::Found(mut plist) => {
            let wrong = repoint(&mut plist, exe, exe_text);
            if wrong.is_empty() {
                (written(false), plist)
            } else {
                let wrong = wrong.join(", and ");
                log::info!("{}: {wrong}; changing it to run {exe_text}", path.display());
                write_agent(path, &plist).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("{} is out of date ({wrong}): {e}", path.display()),
                    )
                })?;
                (written(true), plist)
            }
        }
    };
    keep_output_private(&plist);
    Ok(pointed)
}

/// Create, or narrow, the files the job's output is sent to, before launchd
/// opens them. launchd creates a missing one with its own umask, readable by
/// every account, and what lands there is what the daemon printed before its
/// logger started. Best effort: a file that cannot be opened is launchd's to
/// report, and no directory is created for one.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn keep_output_private(plist: &Plist) {
    for key in ["StandardOutPath", "StandardErrorPath"] {
        let Some(file) = plist.get(key).and_then(|v| v.as_str()) else {
            continue;
        };
        // A device or a pipe is left alone, and opening a pipe with no
        // reader would wait for one.
        if std::fs::metadata(file).is_ok_and(|m| !m.is_file()) {
            continue;
        }
        if let Err(e) = crate::logging::open_private(Path::new(file)) {
            log::warn!("the daemon's output file {file} was left as it was: {e}");
        }
    }
}

/// Start the daemon as a DETACHED background process (its own session, with
/// stdio sent to the file the daemon logs to), then return without owning it.
/// Used by the front door on non-macOS (macOS uses launchd): the daemon is the
/// persistent core engine and must survive the front-end — and its terminal —
/// going away.
#[cfg(all(not(target_os = "macos"), any(feature = "tui", feature = "slint")))]
fn start_detached_daemon() -> io::Result<u32> {
    use std::process::{self, Stdio};
    // The daemon's own log file, where it works out that file for itself:
    // `%LOCALAPPDATA%\hops\logs` on Windows, `$XDG_STATE_HOME/hops` on Linux.
    // What it writes to stdout and stderr is only what comes before its logger
    // starts, and the runtime's own message if it aborts, so the two share the
    // file the front door names when the daemon does not come up.
    let log_file = crate::logging::file_for("daemon");
    let opened = log_file
        .as_deref()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the variable its directory comes from is not set",
            )
        })
        .and_then(crate::logging::open_capped)
        .and_then(|f| Ok((f.try_clone()?, f)));
    let (out, err) = match opened {
        Ok((a, b)) => (Stdio::from(a), Stdio::from(b)),
        Err(e) => {
            // Say so. This used to fall through to /dev/null in silence,
            // for the life of the process, on the one file someone goes to
            // when something is wrong — and the thing that would have
            // carried the message is what just failed.
            log::warn!(
                "could not open the daemon's log file {} ({e}); its start-up output \
                 will not be saved. Once it is running it logs to its own file — see \
                 the Logs section of the README for where.",
                log_file
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
            (Stdio::null(), Stdio::null())
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
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Windows has no setsid(): give the daemon its own detached console and
        // process group so closing the launching terminal (or the console being
        // logged off) can't deliver CTRL_CLOSE/CTRL_BREAK and take it down —
        // without this the "detached" daemon dies with the front-end's console.
        // For login-persistent autostart prefer the Scheduled Task in
        // service/windows/; this only covers a hand-launched `hops`.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    // `spawn` returns once the program is running: on Unix a failed exec is
    // reported here, not later. The daemon owns its own lifecycle; the handle
    // goes to a thread that only reaps it when it exits, so an exit is seen as
    // one (an unreaped child still has its id on Unix) and leaves no zombie
    // for as long as the app stays open.
    let mut child = cmd.spawn()?;
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

/// Who started the daemon `listener` names, on Linux, from its entry in
/// `/proc` at `proc`, as the copy of hops at `exe` sees it.
///
/// The service is a hops daemon of this user with no controlling terminal,
/// run from `exe`: the front door starts it in a session of its own, and
/// systemd runs a unit without one. A daemon with a terminal was started
/// from it, and is left to whoever started it. One run from another copy of
/// hops belongs to that copy, as on macOS, where the service is the one whose
/// agent names this copy.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn proc_origin(listener: io::Result<Listener>, uid: u32, proc: &Path, exe: &Path) -> Origin {
    let listener = match listener {
        Ok(listener) => listener,
        Err(e) => {
            return Origin::Other(not_restarted(&format!(
                "it could not tell which process serves it ({e})"
            )));
        }
    };
    if listener.uid != uid {
        return Origin::Other(not_restarted("it runs as another user"));
    }
    // The kernel names a program whose file was replaced "<name> (deleted)",
    // which is what an update in place leaves the previous daemon running.
    let program = std::fs::read_link(proc.join("exe")).ok();
    let named_hops = program
        .as_deref()
        .and_then(Path::file_name)
        .is_some_and(|name| name.to_string_lossy().trim_end_matches(" (deleted)") == "hops");
    let args = std::fs::read(proc.join("cmdline")).unwrap_or_default();
    let as_daemon = args.split(|&b| b == 0).skip(1).any(|arg| arg == b"daemon");
    if !named_hops || !as_daemon {
        return Origin::Other(not_restarted(&format!(
            "process {} does not look like a hops daemon",
            listener.pid
        )));
    }
    if let Some(program) = program.as_deref().filter(|&p| !same_program(p, exe)) {
        return Origin::Other(not_restarted(&format!(
            "it runs another copy of hops, {}",
            deleted_trimmed(program).display()
        )));
    }
    match std::fs::read_to_string(proc.join("stat"))
        .ok()
        .as_deref()
        .and_then(terminal_of)
    {
        Some(0) => Origin::Service(listener.pid),
        Some(_) => Origin::Other(not_restarted("it was started from a terminal")),
        None => Origin::Other(not_restarted(&format!(
            "it could not tell how process {} was started",
            listener.pid
        ))),
    }
}

/// A program path as `/proc/<pid>/exe` names it, without the " (deleted)"
/// the kernel adds once the file was replaced or removed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn deleted_trimmed(program: &Path) -> PathBuf {
    let text = program.as_os_str().to_string_lossy();
    match text.strip_suffix(" (deleted)") {
        Some(trimmed) => PathBuf::from(trimmed),
        None => program.to_path_buf(),
    }
}

/// Whether the program `/proc` names is the file at `exe`: the same path,
/// including the file an update in place replaced there.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn same_program(program: &Path, exe: &Path) -> bool {
    program == exe || deleted_trimmed(program) == deleted_trimmed(exe)
}

/// The controlling terminal named in a `/proc/<pid>/stat` line: its device
/// number, 0 for none. `None` when the line does not parse.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn terminal_of(stat: &str) -> Option<i64> {
    // The program name is in parentheses and may hold spaces and parentheses
    // itself, so the fields are counted from the last `)`: state, parent,
    // process group, session, terminal.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(4)?.parse().ok()
}

/// Stop the hops daemon `pid`, which the front door found holding `endpoint`
/// with another build, and wait up to `within` for it to exit (#222).
///
/// The process is named by a pidfd, and only once that is open is it checked
/// to be the one holding the endpoint, and the service's hops daemon of this
/// user. A process id alone could by then name another process that took the
/// number over.
#[cfg(target_os = "linux")]
pub fn stop_outdated_daemon(
    pid: u32,
    endpoint: &DaemonEndpoint,
    within: Duration,
) -> io::Result<()> {
    stop_outdated_daemon_of(
        pid,
        endpoint,
        &std::env::current_exe().unwrap_or_default(),
        within,
    )
}

/// [`stop_outdated_daemon`], for the service that runs the copy of hops at
/// `exe` rather than the running program; see [`AsProgram`].
#[cfg(target_os = "linux")]
pub fn stop_outdated_daemon_of(
    pid: u32,
    endpoint: &DaemonEndpoint,
    exe: &Path,
    within: Duration,
) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let id = libc::pid_t::try_from(pid)
        .map_err(|_| io::Error::other(format!("{pid} is not a process id")))?;
    // SAFETY: the call takes plain values and returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, id, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(fd).map_err(|_| io::Error::other("the pidfd is out of range"))?;
    // SAFETY: `fd` was just opened, and nothing else owns it.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    let now = endpoint.listener()?;
    if now.pid != pid {
        return Err(io::Error::other(format!(
            "process {pid} no longer holds {endpoint}"
        )));
    }
    let proc = PathBuf::from(format!("/proc/{pid}"));
    if let Origin::Other(why) = proc_origin(Ok(now), this_user(), &proc, exe) {
        return Err(io::Error::other(why));
    }
    stop_service_daemon(Stop::Process(&pidfd))?;
    // A pidfd reads as ready once its process has exited, reaped or not.
    let mut ready = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let ms = i32::try_from(left.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: `ready` is one pollfd that outlives the call.
        match unsafe { libc::poll(&mut ready, 1, ms) } {
            1.. => return Ok(()),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "the daemon of the other build (process {pid}) did not stop within {}",
                        seconds(within)
                    ),
                ));
            }
            _ => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod a_daemon_of_hops_0_12_on_its_old_endpoint {
    //! On Windows hops 0.12 and older listened on 127.0.0.1:5252, and this
    //! build listens on a pipe, so the front door and a starting daemon saw
    //! nothing running beside a 0.12 daemon and started a second, with the
    //! same identity and config (#222: at most one daemon). These stand an
    //! older daemon up on a loopback port of their own, sending its state to
    //! whoever connects as 0.12 does, and hand that port in as the older
    //! builds' endpoint.

    use super::{
        DaemonStart, Launch, Origin, Running, Watch, refuse_beside_older,
        start_or_restart_beside_older,
    };
    use hops_ipc::{Build, DaemonEndpoint, IpcListenerCreationError, StatedBuild};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::time::Duration;

    /// Something on a loopback port that sends `hello` to every connection,
    /// then holds it until the other side hangs up.
    fn standing(hello: &'static [u8]) -> DaemonEndpoint {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let addr = listener.local_addr().expect("its address");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    let _ = stream.write_all(hello);
                    let mut sink = [0u8; 256];
                    while matches!(stream.read(&mut sink), Ok(1..)) {}
                });
            }
        });
        DaemonEndpoint::Tcp(addr)
    }

    /// A daemon of hops 0.12: its first words to any connection are its state.
    fn hops_0_12() -> DaemonEndpoint {
        standing(b"{\"Enumerate\":[]}\n{\"PortChanged\":[4242,null]}\n")
    }

    /// A loopback port nothing listens on: bound and released in one statement.
    fn nothing_listening() -> DaemonEndpoint {
        DaemonEndpoint::Tcp(
            TcpListener::bind("127.0.0.1:0")
                .and_then(|l| l.local_addr())
                .expect("a loopback port"),
        )
    }

    /// A daemon this front door starts, which serves at once.
    struct Serves;

    impl Watch for Serves {
        fn serves(&mut self, _: &DaemonEndpoint, _: Duration) -> bool {
            true
        }
        fn ended(&mut self, _: u32) -> bool {
            false
        }
        fn log_file(&self) -> Option<PathBuf> {
            None
        }
    }

    impl Running for Serves {
        fn build(&mut self, _: &DaemonEndpoint, _: Duration) -> Option<StatedBuild> {
            None
        }
        fn origin(&mut self, _: &DaemonEndpoint) -> Origin {
            Origin::Other("not asked".into())
        }
    }

    /// The front door, with nothing on this build's endpoint and `older` on
    /// the older builds'; and what it asked to launch.
    fn open_beside(older: DaemonEndpoint) -> (super::StartReport, Vec<Launch>) {
        let mut launched = Vec::new();
        let this = Build {
            version: "0.13.0".into(),
            commit: "abcdef1".into(),
        };
        let report = start_or_restart_beside_older(
            Ok(nothing_listening()),
            Some(older),
            &this,
            |launch| {
                launched.push(launch);
                Ok(4711)
            },
            &mut Serves,
            Duration::from_secs(5),
        );
        (report, launched)
    }

    // LEDGER T2260 | class B | 1 return value + launches asked for, against a stand-in 0.12 daemon on a real port
    #[test]
    fn the_front_door_starts_nothing_beside_a_0_12_daemon_and_says_how_to_stop_it() {
        let old = hops_0_12();
        let DaemonEndpoint::Tcp(addr) = &old else {
            unreachable!("a port")
        };
        let port = addr.port();
        let (report, launched) = open_beside(old);
        let said = report.problem().unwrap_or_default();
        assert_eq!(
            (report.outcome, launched),
            (DaemonStart::AlreadyRunning, vec![]),
            "a hops 0.12 daemon answers on its old endpoint, and the front door \
             started a second daemon beside it: {report:?}"
        );
        // Both ways 0.12 started at sign-in are removed, and the old daemon
        // is found by its port. The Run values from a shell that is not
        // elevated, since they are the user's own; from an administrator one
        // only what 0.12's elevated task needs, and nothing that installs.
        let lines: Vec<&str> = said.lines().collect();
        let after = |ask: &str, n: usize| {
            let at = lines.iter().position(|l| l.contains(ask))?;
            Some((at, lines.get(at + 1..at + 1 + n)?.to_vec()))
        };
        let normal = after("from a normal PowerShell:", 2);
        let admin = after("from PowerShell as administrator", 4);
        let old_daemon = format!("$old = Get-NetTCPConnection -LocalPort {port} -State Listen");
        assert_eq!(
            (
                normal.as_ref().map(|(_, cmds)| cmds.clone()),
                admin.as_ref().map(|(_, cmds)| cmds[..3].to_vec()),
                admin
                    .as_ref()
                    .map(|(_, cmds)| cmds[3].starts_with("A line")),
                normal.zip(admin).map(|((n, _), (a, _))| n < a),
            ),
            (
                Some(vec![
                    "$run = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                    "Remove-ItemProperty $run -Name hops-daemon,hops-gui",
                ]),
                Some(vec![
                    "Unregister-ScheduledTask -TaskName hops-daemon -Confirm:$false",
                    old_daemon.as_str(),
                    "Stop-Process -Id $old.OwningProcess",
                ]),
                Some(true),
                Some(true),
            ),
            "(the commands for a normal PowerShell, those for an administrator one, \
             prose after them, the normal one first) in {said:?}"
        );
        // This version is registered from a shell that is not elevated, with
        // a script a 0.12 user can find, or by the installer 0.12 came from.
        for needed in [
            "hops 0.12 or older",
            "from a normal PowerShell, never an administrator one",
            "install-hops-daemon.ps1 from service\\windows in the source code zip on the \
             release page",
            "update the clone and run install.ps1 again",
        ] {
            assert!(
                said.contains(needed),
                "the app must name the old daemon and how to stop it for good; missing \
                 {needed:?} in {said:?}"
            );
        }
        // Pointing the old task at this copy keeps the task's elevation, and
        // runs this copy elevated from wherever it was unpacked.
        assert!(
            !said.contains("Set-ScheduledTask"),
            "the steps must not run this copy from the old, elevated task: {said:?}"
        );
    }

    /// Once this daemon runs, a daemon of hops 0.12 started after it finds its
    /// endpoint taken and exits, as it does beside another of its own; and the
    /// endpoint held is not taken for a 0.12 daemon.
    // LEDGER T2279 | class B | 1 return value + a bind on a real port
    #[test]
    fn a_0_12_daemon_cannot_start_beside_this_one() {
        let older = nothing_listening();
        let DaemonEndpoint::Tcp(addr) = &older else {
            unreachable!("a port")
        };
        let held = super::hold_older_endpoint(Some(&older));
        // As hops 0.12 takes its endpoint.
        let taken = TcpListener::bind(addr).map(|_| ()).map_err(|e| e.kind());
        let (report, launched) = open_beside(older.clone());
        drop(held);
        assert_eq!(
            (taken, report.outcome, launched),
            (
                Err(std::io::ErrorKind::AddrInUse),
                DaemonStart::Started(4711),
                vec![Launch::Start]
            ),
            "(a 0.12 daemon taking its endpoint, the front door) while this daemon \
             holds that endpoint"
        );
    }

    /// While a daemon of this build answers, the front door does not ask the
    /// older endpoint: that daemon holds it, and asking would make every open
    /// wait on it.
    // LEDGER T2280 | class B | connections made to a real port
    #[test]
    fn the_older_endpoint_is_not_asked_while_this_builds_daemon_answers() {
        // Counts the connections made to it before one that says "F".
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let addr = listener.local_addr().expect("its address");
        let (fenced, before_fence) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut asked = 0;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut first = [0u8; 1];
                match stream.read(&mut first) {
                    Ok(1) if first == *b"F" => {
                        let _ = fenced.send(asked);
                        return;
                    }
                    _ => asked += 1,
                }
            }
        });
        let this = Build {
            version: "0.13.0".into(),
            commit: "abcdef1".into(),
        };
        let _ = start_or_restart_beside_older(
            Ok(standing(b"")),
            Some(DaemonEndpoint::Tcp(addr)),
            &this,
            |_| Ok(4711),
            &mut Serves,
            Duration::from_secs(5),
        );
        let mut fence = std::net::TcpStream::connect(addr).expect("the counting port");
        fence.write_all(b"F").expect("the fence");
        let asked = before_fence
            .recv_timeout(Duration::from_secs(60))
            .expect("the fence was seen");
        assert_eq!(
            asked, 0,
            "the front door asked the older endpoint while this build's daemon answered"
        );
    }

    /// Anything else on that port is not hops, and changes nothing.
    // LEDGER T2261 | class B | 1 return value + launches asked for
    #[test]
    fn something_else_on_the_old_port_does_not_stop_a_start() {
        for (what, older) in [
            ("nothing", nothing_listening()),
            ("a silent program", standing(b"")),
            ("a program that is not hops", standing(b"220 ready\r\n")),
        ] {
            let (report, launched) = open_beside(older);
            assert_eq!(
                (report.outcome, launched),
                (DaemonStart::Started(4711), vec![Launch::Start]),
                "{what} on the old port kept the front door from starting hops: {report:?}"
            );
        }
    }

    // LEDGER T2262 | class B | 1 return value, against a stand-in 0.12 daemon on a real port
    #[test]
    fn a_daemon_refuses_to_start_beside_a_0_12_daemon() {
        let old = hops_0_12();
        let refused = refuse_beside_older(Some(&old));
        assert!(
            matches!(
                &refused,
                Err(IpcListenerCreationError::Older { endpoint, hint })
                    if *endpoint == old && hint.contains("hops-daemon")
            ),
            "a daemon started beside a hops 0.12 daemon must refuse, naming its \
             sign-in task: {refused:?}"
        );
        let other = standing(b"220 ready\r\n");
        assert!(
            refuse_beside_older(Some(&other)).is_ok() && refuse_beside_older(None).is_ok(),
            "a daemon refused to start with no older hops daemon running"
        );
    }
}

#[cfg(test)]
mod waiting_for_the_daemon {
    //! A daemon binds its endpoint, then reads its token, config and keys, and
    //! exits a moment later when any of them fails. The front door must not
    //! call that a running daemon, must not wait longer than it said, and must
    //! stop waiting as soon as the process has exited. These tests give the
    //! wait a scripted daemon and never start a real one.

    use super::{DaemonStart, StartReport, Watch, start_unless_running, what_became_of};
    use hops_ipc::DaemonEndpoint;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const PID: u32 = 4711;

    /// A daemon that serves from its `serves_from`th ask on, and has ended
    /// from its `ends_at`th look at its process on.
    struct Scripted {
        serves_from: Option<usize>,
        ends_at: Option<usize>,
        asked: usize,
        looked: usize,
    }

    impl Scripted {
        fn new(serves_from: Option<usize>, ends_at: Option<usize>) -> Self {
            Self {
                serves_from,
                ends_at,
                asked: 0,
                looked: 0,
            }
        }
    }

    impl Watch for Scripted {
        fn serves(&mut self, _: &DaemonEndpoint, within: Duration) -> bool {
            self.asked += 1;
            let serves = self.serves_from.is_some_and(|n| self.asked >= n);
            if !serves {
                // An ask that gets no answer takes its time.
                std::thread::sleep(within.min(Duration::from_millis(20)));
            }
            serves
        }

        fn ended(&mut self, _: u32) -> bool {
            self.looked += 1;
            self.ends_at.is_some_and(|n| self.looked >= n)
        }

        fn log_file(&self) -> Option<PathBuf> {
            Some(PathBuf::from("logs/daemon.log"))
        }
    }

    /// A loopback port nothing listens on: bound and released in one statement.
    fn nothing_listening() -> DaemonEndpoint {
        DaemonEndpoint::Tcp(
            std::net::TcpListener::bind("127.0.0.1:0")
                .and_then(|l| l.local_addr())
                .expect("a loopback port"),
        )
    }

    /// Start against `endpoint` with `watch`, waiting at most `within`.
    fn start(
        endpoint: DaemonEndpoint,
        watch: &mut Scripted,
        within: Duration,
    ) -> (DaemonStart, Duration) {
        let began = Instant::now();
        let got = start_unless_running(Ok(endpoint), || Ok(PID), watch, within);
        (got, began.elapsed())
    }

    // LEDGER T36 | class B | 1 return value + elapsed time
    #[test]
    fn a_daemon_that_exits_before_it_serves_is_not_counted_as_started() {
        let within = Duration::from_secs(3);
        let (got, took) = start(
            nothing_listening(),
            &mut Scripted::new(None, Some(3)),
            within,
        );
        assert_eq!(
            got,
            DaemonStart::Exited(PID),
            "the daemon exited without ever serving frontends, as one that fails \
             on its lock, token or config does, and the front door reported \
             {got:?}. It used to log that the daemon was running."
        );
        assert!(
            took < within / 2,
            "the daemon had exited, and the front door still waited {took:?} of \
             its {within:?}. The app does not open until the wait ends."
        );
    }

    // LEDGER T37 | class B | 1 return value + elapsed time
    #[test]
    fn a_daemon_that_never_answers_is_reported_once_the_wait_is_over() {
        let within = Duration::from_millis(400);
        let (got, took) = start(nothing_listening(), &mut Scripted::new(None, None), within);
        assert_eq!(
            got,
            DaemonStart::NoAnswer(PID),
            "the daemon's process ran and never served frontends, and the front \
             door reported {got:?}"
        );
        assert!(
            took >= within && took < within + Duration::from_secs(2),
            "the wait was to last {within:?} and took {took:?}. A wait that ends \
             early reports a daemon that is still starting as silent; one that \
             runs on keeps the app from opening."
        );
    }

    // LEDGER T38 | class B | 1 return value
    #[test]
    fn a_daemon_that_serves_is_started_and_one_that_stopped_beside_another_is_not() {
        let within = Duration::from_secs(3);
        let (serving, _) = start(
            nothing_listening(),
            &mut Scripted::new(Some(3), None),
            within,
        );
        assert_eq!(
            serving,
            DaemonStart::Started(PID),
            "the daemon served on the third ask, and the front door reported {serving:?}"
        );

        // Another start got there first: that daemon holds the endpoint and is
        // still starting, and the process this start brought up exited as
        // already running.
        let other = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let held = DaemonEndpoint::Tcp(other.local_addr().expect("its address"));
        let mut watch = Scripted::new(Some(4), Some(1));
        let got = super::wait_for_daemon(&held, PID, &mut watch, within);
        drop(other);
        assert_eq!(
            got,
            DaemonStart::AlreadyRunning,
            "this start's process exited while another daemon held the endpoint \
             and then served. Reporting {got:?} either calls the exited process \
             the daemon, or gives up on a daemon that is running."
        );
    }

    /// A daemon on a loopback port that reads what each connection sends
    /// first, then starts a line and adds a space to it every 50 ms, never
    /// ending it, for up to 5 s or until the asker hangs up. Asked through the real
    /// [`DaemonEndpoint::serves`]; its process never ends.
    struct Trickling {
        addr: std::net::SocketAddr,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Trickling {
        const TOKEN: &'static str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        fn start() -> Self {
            use std::io::{Read, Write};
            use std::sync::atomic::Ordering;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
            let addr = listener.local_addr().expect("its address");
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stopped = stop.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(mut stream) = stream else { continue };
                    std::thread::spawn(move || {
                        let _ = stream.set_nodelay(true);
                        let _ = stream.read(&mut [0u8; Trickling::TOKEN.len() + 1]);
                        let began = Instant::now();
                        let mut sent = stream.write_all(b"{");
                        while sent.is_ok() && began.elapsed() < Duration::from_secs(5) {
                            std::thread::sleep(Duration::from_millis(50));
                            sent = stream.write_all(b" ");
                        }
                    });
                }
            });
            Self { addr, stop }
        }
    }

    impl Drop for Trickling {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            // Wake the accept loop so it sees the flag.
            let _ = std::net::TcpStream::connect(self.addr);
        }
    }

    impl Watch for Trickling {
        fn serves(&mut self, endpoint: &DaemonEndpoint, within: Duration) -> bool {
            endpoint.serves(Self::TOKEN, within)
        }

        fn ended(&mut self, _: u32) -> bool {
            false
        }

        fn log_file(&self) -> Option<PathBuf> {
            None
        }
    }

    // LEDGER T44 | class B | 1 return value + elapsed time over a real socket
    #[test]
    fn a_daemon_that_trickles_bytes_does_not_stretch_the_wait() {
        let mut daemon = Trickling::start();
        let endpoint = DaemonEndpoint::Tcp(daemon.addr);
        // Past one whole ask, so the last ask must be cut to what is left.
        let within = super::ASK_WITHIN + Duration::from_millis(200);
        let began = Instant::now();
        let got = super::wait_for_daemon(&endpoint, PID, &mut daemon, within);
        let took = began.elapsed();
        drop(daemon);
        assert_eq!(
            got,
            DaemonStart::NoAnswer(PID),
            "a daemon that never finished a line was reported as {got:?}"
        );
        assert!(
            took < within + Duration::from_millis(600),
            "the wait was to last {within:?} and took {took:?}. Something on the \
             endpoint that sends a byte now and then must not keep the app from \
             opening past the wait."
        );
    }

    /// What reaches the screen when the service did not come up (#189). It
    /// used to be "connecting", indefinitely.
    // LEDGER T63 | class B | 1 return value
    #[test]
    fn a_start_that_did_not_come_up_is_put_into_words_that_name_the_log() {
        let report = |outcome, why: Option<&str>| StartReport {
            outcome,
            why: why.map(str::to_string),
            log_file: Some(PathBuf::from("logs/daemon.log")),
            within: Duration::from_secs(5),
            replaced: None,
            left: None,
            left_build: None,
        };
        let exited = report(DaemonStart::Exited(PID), None).problem();
        let silent = report(DaemonStart::NoAnswer(PID), None).problem();
        let failed = report(
            DaemonStart::StartFailed,
            Some("`launchctl kickstart -p gui/501/com.grabbr.hops` failed"),
        )
        .problem();
        let unasked = report(DaemonStart::CannotProbe, Some("$HOME is not set")).problem();
        for (got, says) in [
            (&exited, "stopped again before it answered"),
            (&exited, "logs/daemon.log"),
            (&silent, "did not answer within 5 s"),
            (&silent, "logs/daemon.log"),
            (&failed, "could not be started: `launchctl kickstart"),
            (&unasked, "$HOME is not set"),
        ] {
            assert!(
                got.as_deref().is_some_and(|text| text.contains(says)),
                "{got:?} does not say `{says}`. A service that did not come up must \
                 be named on screen, with where to look."
            );
        }
        for running in [DaemonStart::Started(PID), DaemonStart::AlreadyRunning] {
            assert_eq!(report(running, None).problem(), None, "{running:?}");
        }
    }

    // LEDGER T39 | class B | 1 return value
    #[test]
    fn the_log_line_says_what_happened_and_where_to_look() {
        let endpoint = nothing_listening();
        let log = Path::new("logs/daemon.log");
        let silent = what_became_of(
            PID,
            DaemonStart::NoAnswer(PID),
            &endpoint,
            Duration::from_secs(5),
            Some(log),
        );
        let exited = what_became_of(
            PID,
            DaemonStart::Exited(PID),
            &endpoint,
            Duration::from_secs(5),
            Some(log),
        );
        let running = what_became_of(
            PID,
            DaemonStart::Started(PID),
            &endpoint,
            Duration::from_secs(5),
            Some(log),
        );
        for (line, says) in [
            (&silent, "did not answer"),
            (&silent, "within 5 s; see logs/daemon.log"),
            (&exited, "exited before it answered"),
            (&exited, "; see logs/daemon.log"),
            (&running, "is running as process 4711"),
        ] {
            assert!(
                line.contains(says),
                "`{line}` does not say `{says}`. A start that did not come up must \
                 say so and name the file the daemon logged its reason to."
            );
        }
        assert!(
            !silent.contains("is running") && !exited.contains("is running"),
            "a daemon that did not come up was logged as running: `{silent}`, `{exited}`"
        );
    }
}

#[cfg(test)]
mod through_launchd {
    //! On macOS the front door starts the daemon through its launchd job. A
    //! loaded job need not have a process: the plist restarts the daemon only
    //! after an unsuccessful exit, so one that quit, or exited because another
    //! held the endpoint, leaves the job loaded and idle. A job that is
    //! running, or that `RunAtLoad` started as it was bootstrapped, makes
    //! `kickstart -p` exit 37 while it prints the running process's id. These
    //! tests give the start a scripted `launchctl` and never run the real one.

    use super::{AgentFile, LaunchctlRun, start_through_launchd};
    use std::cell::RefCell;
    use std::io;
    use std::time::Duration;

    const UID: u32 = 501;
    const SERVICE: &str = "gui/501/com.grabbr.hops";

    /// A job that is loaded with no process, as `launchctl print` shows one
    /// (abridged from macOS 27): exit 0.
    fn loaded_idle() -> LaunchctlRun {
        ok(
            "gui/501/com.grabbr.hops = {\n\tactive count = 0\n\tstate = not running\n\tlast exit code = 0\n}\n",
        )
    }

    fn ok(stdout: &str) -> LaunchctlRun {
        exited(0, stdout, "")
    }

    fn failed(code: i32, stderr: &str) -> LaunchctlRun {
        exited(code, "", stderr)
    }

    /// What `kickstart -p` reports for a job that already has a process: exit
    /// 37, with that process's id printed as for one it started.
    fn already_running(pid: u32) -> LaunchctlRun {
        exited(37, &format!("{pid}\n"), "")
    }

    fn exited(code: i32, stdout: &str, stderr: &str) -> LaunchctlRun {
        LaunchctlRun {
            code: Some(code),
            status: format!("exit status: {code}"),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    const PLIST: &str = "Library/LaunchAgents/com.grabbr.hops.plist";

    /// What the plist step finds and does.
    #[derive(Clone, Copy)]
    enum Agent {
        /// It already runs this binary as this build does: left alone.
        Current,
        /// Missing, or naming another binary or the old format: written.
        Written,
        /// Out of date and could not be written.
        Unwritable,
    }

    /// Run the start against `script`, which answers each `launchctl` call by
    /// its subcommand, with a plist that is already current. Returns the
    /// result, every call made in order, and whether the plist was written.
    fn start_with(script: impl Fn(&str) -> LaunchctlRun) -> (io::Result<u32>, Vec<String>, bool) {
        let (got, calls, written, _) = start_with_agent(Agent::Current, script);
        (got, calls, written)
    }

    /// [`start_with`] with the plist step finding `agent`; also returns the
    /// pauses the start asked for.
    fn start_with_agent(
        agent: Agent,
        script: impl Fn(&str) -> LaunchctlRun,
    ) -> (io::Result<u32>, Vec<String>, bool, Vec<Duration>) {
        run_start(agent, None, script)
    }

    /// A restart of the job whose process is `old`, which has exited once
    /// `gone` has been asked `asks_until_gone` times.
    fn restart_with(
        old: u32,
        asks_until_gone: usize,
        script: impl Fn(&str) -> LaunchctlRun,
    ) -> (io::Result<u32>, Vec<String>, Vec<Duration>, Vec<u32>) {
        let asked = RefCell::new(Vec::new());
        let mut gone = |pid| {
            asked.borrow_mut().push(pid);
            asked.borrow().len() > asks_until_gone
        };
        let (got, calls, _, pauses) = run_start(
            Agent::Current,
            Some(super::Replacing {
                pid: old,
                gone: &mut gone,
            }),
            script,
        );
        (got, calls, pauses, asked.into_inner())
    }

    fn run_start(
        agent: Agent,
        replacing: Option<super::Replacing<'_>>,
        script: impl Fn(&str) -> LaunchctlRun,
    ) -> (io::Result<u32>, Vec<String>, bool, Vec<Duration>) {
        let calls = RefCell::new(Vec::new());
        let written = RefCell::new(false);
        let mut pauses = Vec::new();
        let mut launchctl = |args: &[&str]| {
            calls.borrow_mut().push(args.join(" "));
            Ok(script(args[0]))
        };
        let got = start_through_launchd(
            UID,
            &mut launchctl,
            || match agent {
                Agent::Current => Ok(AgentFile {
                    path: PLIST.into(),
                    rewritten: false,
                }),
                Agent::Written => {
                    *written.borrow_mut() = true;
                    Ok(AgentFile {
                        path: PLIST.into(),
                        rewritten: true,
                    })
                }
                Agent::Unwritable => Err(io::Error::other(format!(
                    "{PLIST} is out of date (it ran `/Applications/old/hops daemon`): \
                     permission denied"
                ))),
            },
            &mut |wait| pauses.push(wait),
            replacing,
        );
        (got, calls.into_inner(), written.into_inner(), pauses)
    }

    /// The one-daemon rule as amended on 2026-09-26 (#222): the front door
    /// never runs `kickstart -k` or `kill`, and boots the job out only to
    /// restart it, once. `bootouts` is 1 for the restart of a service running
    /// another build, and for the reload of a job whose plist was rewritten
    /// while nothing answers (#170); 0 for every other start.
    fn stops_only_to_restart(calls: &[String], bootouts: usize) {
        for call in calls {
            assert!(
                !call.contains("-k") && !call.starts_with("kill"),
                "`launchctl {call}` restarts or signals whatever daemon the job \
                 runs, and the front door stops a daemon only by booting its job \
                 out to restart it: {calls:?}"
            );
        }
        let booted_out = calls.iter().filter(|c| c.starts_with("bootout")).count();
        assert_eq!(
            booted_out, bootouts,
            "the front door booted the job out {booted_out} times, where {bootouts} \
             was allowed: {calls:?}. A bootout stops the daemon that serves input; \
             it is for restarting a service of another build, or reloading a plist \
             that was rewritten, and for nothing else."
        );
    }

    // LEDGER T12 | class B | 1 return value + 6 calls recorded by the injected runner
    #[test]
    fn a_loaded_job_with_no_process_is_started_and_counts_only_with_its_pid() {
        let (got, calls, installed) = start_with(|sub| match sub {
            "print" => loaded_idle(),
            "kickstart" => ok("4711\n"),
            other => failed(1, &format!("unexpected {other}")),
        });
        stops_only_to_restart(&calls, 0);
        assert_eq!(
            (got.as_ref().ok(), installed),
            (Some(&4711), false),
            "a loaded job was not reported by the process launchd started for it: \
             {got:?}, calls {calls:?}"
        );
        assert_eq!(
            calls,
            [
                format!("print {SERVICE}"),
                format!("kickstart -p {SERVICE}")
            ],
            "a loaded job with no process was not started through launchd. \
             The front door then reports a start while no daemon runs."
        );
    }

    // LEDGER T32 | class B | 1 return value + 6 calls recorded by the injected runner
    #[test]
    fn a_job_that_is_already_running_counts_by_the_process_launchd_names() {
        let (got, calls, installed) = start_with(|sub| match sub {
            "print" => ok("gui/501/com.grabbr.hops = {\n\tstate = running\n\tpid = 3268\n}\n"),
            "kickstart" => already_running(3268),
            other => failed(1, &format!("unexpected {other}")),
        });
        stops_only_to_restart(&calls, 0);
        assert_eq!(
            (got.as_ref().ok(), installed, calls.len()),
            (Some(&3268), false, 2),
            "launchd already runs the job and named its process (kickstart exit \
             37), and the start reported {got:?} from {calls:?}. The front door \
             logged a failed start about a daemon that was running."
        );
    }

    // LEDGER T13 | class B | 1 return value / error
    #[test]
    fn a_kickstart_that_names_no_process_is_a_failed_start() {
        let (refused, _, _) = start_with(|sub| match sub {
            "print" => loaded_idle(),
            _ => failed(
                113,
                "Could not kickstart service: 113: Could not find service",
            ),
        });
        let (silent, _, _) = start_with(|sub| match sub {
            "print" => loaded_idle(),
            _ => ok(""),
        });
        let (uid_only, _, _) = start_with(|sub| match sub {
            "print" => loaded_idle(),
            _ => ok("gui/501/com.grabbr.hops\n"),
        });
        let (running_no_pid, _, _) = start_with(|sub| match sub {
            "print" => loaded_idle(),
            _ => exited(37, "", ""),
        });
        let (failed_with_a_number, _, _) = start_with(|sub| match sub {
            "print" => loaded_idle(),
            _ => exited(5, "4711\n", "Input/output error"),
        });
        for (what, got) in [
            ("kickstart failed", &refused),
            ("kickstart printed nothing", &silent),
            ("kickstart printed only the service name", &uid_only),
            (
                "kickstart exited 37 and printed no process",
                &running_no_pid,
            ),
            (
                "kickstart failed and printed a number",
                &failed_with_a_number,
            ),
        ] {
            assert!(
                got.is_err(),
                "{what}, and the start still counted as done: {got:?}. No daemon \
                 process is known to run, and the front door would say one does."
            );
        }
        let message = refused.expect_err("checked above").to_string();
        assert!(
            message.contains("Could not find service"),
            "the failure does not carry what launchctl said: {message}"
        );
    }

    // LEDGER T14 | class B | 1 return value + 6 calls recorded by the injected runner
    #[test]
    fn a_job_that_is_not_loaded_is_bootstrapped_then_must_have_a_process() {
        // `RunAtLoad` starts the daemon as the job is bootstrapped, so the
        // kickstart finds it running.
        let (got, calls, installed, _) = start_with_agent(Agent::Written, |sub| match sub {
            "print" => failed(113, "Could not find service"),
            "bootstrap" => ok(""),
            "kickstart" => already_running(902),
            other => failed(1, &format!("unexpected {other}")),
        });
        stops_only_to_restart(&calls, 0);
        assert_eq!(
            (got.as_ref().ok(), installed, calls.len()),
            (Some(&902), true, 3),
            "not loaded: expected print, bootstrap, kickstart -p and the process \
             id, got {got:?} from {calls:?}"
        );
        assert!(
            calls[1].starts_with("bootstrap gui/501 ")
                && calls[2] == format!("kickstart -p {SERVICE}"),
            "calls {calls:?}"
        );

        // The daemon had not started yet when the kickstart came.
        let (started_by_kick, _, _) = start_with(|sub| match sub {
            "print" => failed(113, "Could not find service"),
            "bootstrap" => ok(""),
            "kickstart" => ok("904\n"),
            other => failed(1, &format!("unexpected {other}")),
        });
        assert_eq!(
            started_by_kick.as_ref().ok(),
            Some(&904),
            "{started_by_kick:?}"
        );

        // Another start loaded the job between `print` and `bootstrap`, and
        // `RunAtLoad` has it running.
        let (raced, _, _) = start_with(|sub| match sub {
            "print" => failed(113, "Could not find service"),
            "bootstrap" => failed(5, "Bootstrap failed: 5: Input/output error"),
            "kickstart" => already_running(903),
            other => failed(1, &format!("unexpected {other}")),
        });
        assert_eq!(
            raced.as_ref().ok(),
            Some(&903),
            "the job runs, loaded by another start, and this start reported \
             failure: {raced:?}"
        );

        let (neither, _, _) = start_with(|sub| match sub {
            "print" => failed(113, "Could not find service"),
            "bootstrap" => failed(5, "Bootstrap failed: 5: Input/output error"),
            _ => failed(113, "Could not find service"),
        });
        let message = neither
            .map(|pid| pid.to_string())
            .unwrap_or_else(|e| e.to_string());
        assert!(
            message.contains("Bootstrap failed") && message.contains("kickstart"),
            "a job that could neither be loaded nor started must fail and say both: \
             {message}"
        );
    }

    /// A job loaded from a plist that named a binary no longer there: the app
    /// moved, launchd was left starting a path that does not exist, and the
    /// front door used to kickstart that same definition forever (#170).
    // LEDGER T67 | class B | 1 return value + calls recorded by the injected runner
    #[test]
    fn a_loaded_job_whose_plist_was_rewritten_is_reloaded_before_it_is_started() {
        let (got, calls, written, _) = start_with_agent(Agent::Written, |sub| match sub {
            "print" => loaded_idle(),
            "bootout" | "bootstrap" => ok(""),
            "kickstart" => already_running(5150),
            other => failed(1, &format!("unexpected {other}")),
        });
        assert_eq!(
            (got.as_ref().ok(), written),
            (Some(&5150), true),
            "{got:?} from {calls:?}"
        );
        assert_eq!(
            calls,
            [
                format!("print {SERVICE}"),
                format!("bootout {SERVICE}"),
                format!("bootstrap gui/501 {PLIST}"),
                format!("kickstart -p {SERVICE}"),
            ],
            "the plist now runs this binary, but a loaded job keeps the definition \
             it was loaded with until it is booted out and bootstrapped again. \
             Without that, launchd goes on starting the path the old plist named."
        );
        stops_only_to_restart(&calls, 1);

        // Not loaded: the new plist is simply bootstrapped.
        let (got, calls, _, _) = start_with_agent(Agent::Written, |sub| match sub {
            "print" => failed(113, "Could not find service"),
            "bootstrap" => ok(""),
            "kickstart" => already_running(5151),
            other => failed(1, &format!("unexpected {other}")),
        });
        assert_eq!(got.as_ref().ok(), Some(&5151), "{got:?}");
        assert!(
            !calls.iter().any(|c| c.starts_with("bootout")),
            "a job that is not loaded has nothing to boot out: {calls:?}"
        );
    }

    /// launchd finishes tearing a booted-out job down after `bootout` returns,
    /// and a bootstrap in that window fails with an I/O error.
    // LEDGER T68 | class B | 1 return value + calls and pauses recorded
    #[test]
    fn a_bootstrap_right_after_a_bootout_is_tried_again() {
        let bootstraps = std::cell::Cell::new(0);
        let (got, calls, _, pauses) = start_with_agent(Agent::Written, |sub| match sub {
            "print" => loaded_idle(),
            "bootout" => ok(""),
            "bootstrap" => {
                bootstraps.set(bootstraps.get() + 1);
                if bootstraps.get() < 3 {
                    failed(5, "Bootstrap failed: 5: Input/output error")
                } else {
                    ok("")
                }
            }
            "kickstart" => already_running(5152),
            other => failed(1, &format!("unexpected {other}")),
        });
        assert_eq!(
            (got.as_ref().ok(), bootstraps.get(), pauses.len()),
            (Some(&5152), 3, 2),
            "two bootstraps failed while launchd was still tearing the job down, \
             and the start gave up with the job unloaded: {got:?} from {calls:?}"
        );
        assert!(
            pauses.iter().sum::<Duration>() < Duration::from_secs(5),
            "the app does not open until the start is over: {pauses:?}"
        );

        // One that never loads fails, and says so.
        let (never, _, _, pauses) = start_with_agent(Agent::Written, |sub| match sub {
            "print" => loaded_idle(),
            "bootout" => ok(""),
            "bootstrap" => failed(5, "Bootstrap failed: 5: Input/output error"),
            _ => failed(113, "Could not find service"),
        });
        let message = never
            .map(|p| p.to_string())
            .unwrap_or_else(|e| e.to_string());
        assert!(
            message.contains("Bootstrap failed") && pauses.len() == super::REBOOTSTRAP_WAITS.len(),
            "{message}, after {pauses:?}"
        );
    }

    /// A plist that could not be brought up to date must not cost the job it
    /// had: booting it out would leave nothing loaded at all.
    // LEDGER T69 | class B | 1 return value / error + calls recorded
    #[test]
    fn a_plist_that_could_not_be_rewritten_unloads_nothing_and_names_itself() {
        let (got, calls, _, _) = start_with_agent(Agent::Unwritable, |sub| match sub {
            "print" => loaded_idle(),
            _ => ok("4711\n"),
        });
        stops_only_to_restart(&calls, 0);
        assert_eq!(calls, [format!("print {SERVICE}")], "{got:?}");
        let message = got.map(|p| p.to_string()).unwrap_or_else(|e| e.to_string());
        assert!(
            message.contains(PLIST) && message.contains("/Applications/old/hops"),
            "the failure must name the plist and the binary it still runs: {message}"
        );
    }

    /// A service running another build is restarted (#222): its job is booted
    /// out, the front door waits for the old daemon to let go of the
    /// endpoint, and the plist, pointed at this binary, is bootstrapped again.
    // LEDGER T2225 | class B | 1 return value + calls, pauses and asks recorded by the injected runner
    #[test]
    fn restarting_an_outdated_service_boots_its_job_out_waits_for_it_then_starts_it_again() {
        let (got, calls, pauses, asked) = restart_with(4444, 3, |sub| match sub {
            "print" => ok("gui/501/com.grabbr.hops = {\n\tstate = running\n}\n"),
            "bootout" | "bootstrap" => ok(""),
            "kickstart" => already_running(5555),
            other => failed(1, &format!("unexpected {other}")),
        });
        stops_only_to_restart(&calls, 1);
        assert_eq!(
            calls,
            [
                format!("print {SERVICE}"),
                format!("bootout {SERVICE}"),
                format!("bootstrap gui/501 {PLIST}"),
                format!("kickstart -p {SERVICE}"),
            ],
            "{got:?}"
        );
        assert_eq!(
            (got.as_ref().ok(), asked, pauses.len()),
            (Some(&5555), vec![4444; 4], 2),
            "the restart must wait for the old daemon (4444) to exit before it \
             bootstraps the job: while it holds the endpoint, this build's daemon \
             stops beside it and the old one goes on serving"
        );
    }

    /// Two front doors can both find the old daemon and both restart the
    /// service. The second finds it gone, and must not boot out the job,
    /// which now runs the daemon of this build the first one started.
    // LEDGER T2247 | class B | 1 return value + calls recorded by the injected runner
    #[test]
    fn a_restart_that_finds_the_old_daemon_gone_stops_nothing() {
        let (got, calls, pauses, asked) = restart_with(4444, 0, |sub| match sub {
            "print" => ok("gui/501/com.grabbr.hops = {\n\tstate = running\n}\n"),
            "bootout" | "bootstrap" => ok(""),
            "kickstart" => already_running(5555),
            other => failed(1, &format!("unexpected {other}")),
        });
        stops_only_to_restart(&calls, 0);
        assert_eq!(
            (got.as_ref().ok(), calls, pauses, asked),
            (
                Some(&5555),
                vec![
                    format!("print {SERVICE}"),
                    format!("kickstart -p {SERVICE}")
                ],
                vec![],
                vec![4444]
            ),
            "the daemon being replaced had already exited: the job runs a newer one"
        );
    }

    /// The wait for the old daemon is bounded, and the job is loaded again
    /// either way: a job left booted out is no service at all.
    // LEDGER T2236 | class B | 1 return value + calls and pauses recorded
    #[test]
    fn a_daemon_that_does_not_stop_still_gets_its_job_loaded_again() {
        let (got, calls, pauses, _) = restart_with(4444, usize::MAX, |sub| match sub {
            "print" => ok(""),
            "bootout" | "bootstrap" => ok(""),
            "kickstart" => ok("5556\n"),
            other => failed(1, &format!("unexpected {other}")),
        });
        assert_eq!(got.as_ref().ok(), Some(&5556), "{calls:?}");
        assert!(
            calls.iter().any(|c| c.starts_with("bootstrap")),
            "the job was booted out and never loaded again: {calls:?}"
        );
        assert!(
            pauses.iter().sum::<Duration>() <= super::START_WAIT,
            "the app does not open until the start is over: {pauses:?}"
        );
    }

    /// `launchctl list` names the job's process in its first column; only the
    /// line with hops' label counts.
    // LEDGER T2227 | class B | 1 return value
    #[test]
    fn the_service_is_the_process_launchd_lists_for_its_label() {
        let list = "PID\tStatus\tLabel\n\
                    -\t0\tcom.apple.something\n\
                    4444\t0\tcom.grabbr.hops.gui\n\
                    5555\t0\tcom.grabbr.hops\n\
                    6666\t-15\tapplication.com.apple.Terminal.1 2\n";
        let listing = |stdout: &'static str| move || Ok(ok(stdout));
        use super::Installed::{AnotherCopy, No, ThisCopy};
        let from = |pid, uid, installed, stdout: &'static str| {
            super::launchd_origin(
                Ok(hops_ipc::Listener { pid, uid }),
                UID,
                installed,
                listing(stdout),
            )
        };
        assert_eq!(
            from(5555, UID, ThisCopy, list),
            super::Origin::Service(5555),
            "the job runs the daemon that answers"
        );
        let checkout = || AnotherCopy("/Users/me/src/hops/target/debug/hops".into());
        for (what, got) in [
            ("the tray's job runs it", from(4444, UID, ThisCopy, list)),
            ("no job runs it", from(7777, UID, ThisCopy, list)),
            (
                "the job has no process",
                from(5555, UID, ThisCopy, "-\t0\tcom.grabbr.hops\n"),
            ),
            ("no plist is installed", from(5555, UID, No, list)),
            ("another user runs it", from(5555, UID + 1, ThisCopy, list)),
            (
                "the job runs another copy of hops",
                from(5555, UID, checkout(), list),
            ),
        ] {
            assert!(
                matches!(&got, super::Origin::Other(why) if why.contains("Stop it")),
                "{what}, and it counted as the service's daemon to restart: {got:?}. \
                 A restart boots out the job: one that does not run the daemon leaves \
                 it serving, and one that runs another copy of hops hands the service \
                 to a binary without its permissions."
            );
        }
    }

    /// A restart points the plist at the binary that restarts, and on macOS
    /// hops' permissions belong to the binary the plist names: only the copy
    /// of hops the service runs restarts it. A build in a checkout beside the
    /// installed app would take the service over without them.
    // LEDGER T2246 | class B | 1 return value over real files
    #[test]
    fn only_the_copy_of_hops_the_service_runs_counts_as_this_one() {
        use super::{Installed, OnDisk, installed};
        let dir = std::env::temp_dir().join(format!("h-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let (this, other) = (dir.join("this-hops"), dir.join("other-hops"));
        std::fs::write(&this, "").expect("this binary");
        std::fs::write(&other, "").expect("another copy");
        let runs = |program: &std::path::Path| {
            let serde_json::Value::Object(plist) = serde_json::json!({
                "Label": "com.grabbr.hops",
                "ProgramArguments": [program.to_string_lossy(), "daemon"],
            }) else {
                unreachable!("a JSON object literal")
            };
            Ok(OnDisk::Found(plist))
        };
        let got = [
            installed(runs(&this), &this),
            installed(runs(&dir.join("moved-away")), &this),
            installed(Ok(OnDisk::Unreadable("garbled".into())), &this),
            installed(runs(&other), &this),
            installed(Ok(OnDisk::Missing), &this),
        ];
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            got,
            [
                Installed::ThisCopy,
                Installed::ThisCopy,
                Installed::ThisCopy,
                Installed::AnotherCopy(other.to_string_lossy().into_owned()),
                Installed::No,
            ],
            "(runs this binary, one no longer there, an unreadable plist, another \
             copy that is there, no plist)"
        );
    }

    /// The daemon exits after a grant only when launchd will start it again
    /// (#221): its job restarts after a failure and runs this very process.
    /// Exiting otherwise leaves no daemon until the next login.
    // LEDGER T2245 | class B | 1 return value + 6 whether launchctl was asked
    #[test]
    fn only_the_process_of_a_job_that_restarts_after_a_failure_exits_for_a_grant() {
        use super::{OnDisk, launchd_restarts};
        let plist = |keep_alive: serde_json::Value| {
            let serde_json::Value::Object(plist) = serde_json::json!({
                "Label": "com.grabbr.hops",
                "ProgramArguments": ["/Applications/hops.app/Contents/MacOS/hops", "daemon"],
                "KeepAlive": keep_alive,
            }) else {
                unreachable!("a JSON object literal")
            };
            Ok(OnDisk::Found(plist))
        };
        let restarts = || plist(serde_json::json!({ "SuccessfulExit": false }));
        let list = "PID\tStatus\tLabel\n5555\t0\tcom.grabbr.hops\n";
        let asked = std::cell::Cell::new(0);
        let listing = |run: LaunchctlRun| {
            let asked = &asked;
            move || {
                asked.set(asked.get() + 1);
                Ok(run)
            }
        };

        assert!(
            launchd_restarts(restarts(), listing(ok(list)), 5555),
            "the job restarts after a failure and runs this process"
        );
        for (what, got) in [
            (
                "the job runs another process: this one was started from a terminal",
                launchd_restarts(restarts(), listing(ok(list)), 7777),
            ),
            (
                "launchctl list failed",
                launchd_restarts(restarts(), listing(failed(1, "no")), 5555),
            ),
        ] {
            assert!(
                !got,
                "{what}, and the daemon would exit for a grant and stay down"
            );
        }
        let before = asked.get();
        for (what, agent) in [
            (
                "the plist never restarts it",
                plist(serde_json::json!(false)),
            ),
            (
                "the plist restarts it only after a success",
                plist(serde_json::json!({ "SuccessfulExit": true })),
            ),
            ("there is no plist", Ok(OnDisk::Missing)),
        ] {
            assert!(
                !launchd_restarts(agent, listing(ok(list)), 5555),
                "{what}, and the daemon would exit for a grant and stay down"
            );
        }
        assert_eq!(
            asked.get(),
            before,
            "launchctl is asked only when the plist restarts"
        );
    }
}

#[cfg(test)]
mod restarting_an_outdated_service {
    //! After an in-place upgrade the previous release's daemon keeps serving
    //! the new app (#222). The front door asks the daemon that answers which
    //! build it is, and restarts the service only when it is another build and
    //! the service started it. These run the front door against a real
    //! listener, with what the daemon says and who started it scripted.

    use super::{
        DaemonStart, Launch, Origin, Running, StartReport, Watch, start_or_restart_reported,
    };
    use hops_ipc::{Build, DaemonEndpoint, StatedBuild};
    use std::path::PathBuf;
    use std::time::Duration;

    const OLD: u32 = 4444;
    const NEW: u32 = 5555;

    fn build(version: &str, commit: &str) -> Build {
        Build {
            version: version.into(),
            commit: commit.into(),
        }
    }

    fn this() -> Build {
        build("0.13.0", "abcd123")
    }

    /// The daemon that answers says `stated`, one answer an ask, the last
    /// one again once they run out, and was started as `origin`; whatever
    /// the front door starts serves at once.
    struct Scripted {
        stated: Vec<Option<StatedBuild>>,
        origin: Origin,
        asked_origin: usize,
    }

    impl Watch for Scripted {
        fn serves(&mut self, _: &DaemonEndpoint, _: Duration) -> bool {
            true
        }
        fn ended(&mut self, _: u32) -> bool {
            false
        }
        fn log_file(&self) -> Option<PathBuf> {
            None
        }
    }

    impl Running for Scripted {
        fn build(&mut self, _: &DaemonEndpoint, _: Duration) -> Option<StatedBuild> {
            if self.stated.len() > 1 {
                self.stated.remove(0)
            } else {
                self.stated.first().cloned().flatten()
            }
        }
        fn origin(&mut self, _: &DaemonEndpoint) -> Origin {
            self.asked_origin += 1;
            self.origin.clone()
        }
    }

    /// Run the front door against a listener that answers, returning its
    /// report, what it asked the platform to do, and how often it asked who
    /// started the daemon.
    fn door(
        stated: Option<StatedBuild>,
        origin: Origin,
        launched: std::io::Result<u32>,
    ) -> (StartReport, Vec<Launch>, usize) {
        door_answering(vec![stated], origin, launched)
    }

    /// [`door`], with the daemon giving `stated` in turn as it is asked.
    fn door_answering(
        stated: Vec<Option<StatedBuild>>,
        origin: Origin,
        launched: std::io::Result<u32>,
    ) -> (StartReport, Vec<Launch>, usize) {
        let daemon = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let endpoint = DaemonEndpoint::Tcp(daemon.local_addr().expect("its address"));
        let mut asked = Vec::new();
        let mut watch = Scripted {
            stated,
            origin,
            asked_origin: 0,
        };
        let report = start_or_restart_reported(
            Ok(endpoint),
            &this(),
            |launch| {
                asked.push(launch);
                launched
            },
            &mut watch,
            Duration::from_secs(2),
        );
        drop(daemon);
        (report, asked, watch.asked_origin)
    }

    fn older() -> Option<StatedBuild> {
        Some(StatedBuild::Is(build("0.12.0", "1111111")))
    }

    // LEDGER T2224 | class B | 1 return value + 6 launches recorded
    #[test]
    fn an_outdated_service_is_restarted_once_and_the_app_is_told() {
        let (report, asked, _) = door(older(), Origin::Service(OLD), Ok(NEW));
        assert_eq!(
            (report.outcome, asked),
            (DaemonStart::Started(NEW), vec![Launch::Restart(OLD)]),
            "the service runs hops 0.12.0 under an app of 0.13.0. Left alone, it \
             goes on serving the new app, and none of the new build's fixes run."
        );
        let note = report.note().unwrap_or_default();
        assert!(
            note.contains("restarted its service") && note.contains("hops 0.12.0 (1111111)"),
            "the app restarted the service and must say so, and why: {note:?}"
        );

        let (unstated, asked, _) = door(Some(StatedBuild::Unstated), Origin::Service(OLD), Ok(NEW));
        assert_eq!(
            (unstated.outcome, asked),
            (DaemonStart::Started(NEW), vec![Launch::Restart(OLD)]),
            "a daemon that sends state and no build is from before the statement"
        );
        assert!(
            unstated
                .note()
                .is_some_and(|note| note.contains("does not say which")),
            "{unstated:?}"
        );
    }

    // LEDGER T2238 | class B | 1 return value + 6 launches recorded
    #[test]
    fn this_build_a_silent_daemon_and_one_the_service_did_not_start_are_left_running() {
        let (same, asked_same, origin_asks) =
            door(Some(StatedBuild::Is(this())), Origin::Service(OLD), Ok(NEW));
        let (silent, asked_silent, _) = door(None, Origin::Service(OLD), Ok(NEW));
        let why = "hops did not restart it, because it was started from a terminal. Stop it, \
                   then open hops again.";
        let (terminal, asked_terminal, _) = door(older(), Origin::Other(why.into()), Ok(NEW));
        assert_eq!(
            (
                (same.outcome, asked_same, origin_asks),
                (silent.outcome, asked_silent),
                (terminal.outcome, asked_terminal)
            ),
            (
                (DaemonStart::AlreadyRunning, vec![], 0),
                (DaemonStart::AlreadyRunning, vec![]),
                (DaemonStart::AlreadyRunning, vec![])
            ),
            "((this build, launches, origin asked), (said nothing), (another build \
             from a terminal)). A daemon of this build is never restarted by the \
             app; one that said nothing may be starting; one the service did not \
             start is not the app's to stop."
        );
        assert_eq!(
            (same.note(), same.left.as_deref(), terminal.left.as_deref()),
            (None, None, Some(why)),
            "only the daemon left running with another build carries words for it"
        );
        // Said before the app connects too: a daemon from before the token
        // cannot be connected to, and the app would wait on it in silence.
        assert_eq!(
            (same.problem(), silent.problem(), terminal.problem()),
            (
                None,
                None,
                Some(format!(
                    "The hops service is running hops 0.12.0 (1111111), not this version. \
                     {why}"
                ))
            ),
            "(this build, said nothing, left running) in words before the app connects"
        );
    }

    /// A daemon that sends state without its build is asked again before it
    /// is restarted: that it states none is concluded from a wait running
    /// out, and one of this build that was slow to answer states it next.
    // LEDGER T2248 | class B | 1 return value + 6 launches recorded
    #[test]
    fn a_daemon_that_states_no_build_is_asked_again_before_it_is_restarted() {
        let (late, asked_late, _) = door_answering(
            vec![Some(StatedBuild::Unstated), Some(StatedBuild::Is(this()))],
            Origin::Service(OLD),
            Ok(NEW),
        );
        let (never, asked_never, _) = door_answering(
            vec![Some(StatedBuild::Unstated), Some(StatedBuild::Unstated)],
            Origin::Service(OLD),
            Ok(NEW),
        );
        assert_eq!(
            ((late.outcome, asked_late), (never.outcome, asked_never)),
            (
                (DaemonStart::AlreadyRunning, vec![]),
                (DaemonStart::Started(NEW), vec![Launch::Restart(OLD)])
            ),
            "((stated this build when asked again), (stated none twice)). A daemon \
             of this build is never restarted by the app."
        );
    }

    /// A restart that hands back the daemon it was to replace stopped
    /// nothing: the old build still serves, and the app says so rather than
    /// that it restarted the service.
    // LEDGER T2249 | class B | 1 return value
    #[test]
    fn a_restart_that_leaves_the_old_daemon_running_is_not_a_restart() {
        let (report, asked, _) = door(older(), Origin::Service(OLD), Ok(OLD));
        let problem = report.problem().unwrap_or_default();
        assert_eq!(
            (report.outcome, asked, report.note()),
            (
                DaemonStart::AlreadyRunning,
                vec![Launch::Restart(OLD)],
                None
            ),
            "the service still runs process {OLD}, the old build, and the app said \
             it restarted it: {report:?}"
        );
        assert!(
            problem.contains("hops 0.12.0 (1111111)") && problem.contains("did not stop"),
            "{problem:?}"
        );
    }

    // LEDGER T2239 | class B | 1 return value
    #[test]
    fn a_restart_that_fails_says_what_it_was_restarting() {
        let (report, asked, _) = door(
            older(),
            Origin::Service(OLD),
            Err(std::io::Error::other("the daemon did not stop within 5 s")),
        );
        let problem = report.problem().unwrap_or_default();
        assert_eq!(asked, vec![Launch::Restart(OLD)]);
        assert!(
            problem.contains("tried to restart")
                && problem.contains("hops 0.12.0 (1111111)")
                && problem.contains("did not stop within 5 s"),
            "{problem:?}"
        );
        assert_eq!(report.note(), None, "{report:?}");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod stopping_an_outdated_daemon_on_linux {
    //! The restart signals only the process that holds the endpoint, and
    //! only when that is the service's hops daemon (#222). These hand it
    //! bystanders while this test holds the endpoint.

    use super::{Origin, proc_origin, stop_outdated_daemon, this_user};
    use hops_ipc::{DaemonEndpoint, Listener};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// Whether `child` is still running after `within`.
    fn still_runs(child: &mut Child, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if !matches!(child.try_wait(), Ok(None)) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }

    // LEDGER T2252 | class B | 5 processes left running + 1 return value
    #[test]
    fn a_process_that_does_not_hold_the_endpoint_is_never_signalled() {
        let dir = PathBuf::from(format!("/tmp/h-by-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("s.sock");
        // This test holds the endpoint, and is no hops daemon.
        let held = std::os::unix::net::UnixListener::bind(&path).expect("a unix listener");
        let endpoint = DaemonEndpoint::Unix(path);

        let mut plain = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .spawn()
            .expect("sleep starts");
        // One that looks like the service's daemon in every other way: a
        // program named hops, run with `daemon`, in a session of its own.
        let hops = dir.join("hops");
        std::fs::copy("/bin/sh", &hops).expect("a program named hops");
        let mut command = Command::new(&hops);
        command
            .args(["-c", "read line", "daemon"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null());
        // SAFETY: setsid is async-signal-safe and touches only the child.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut lookalike = command.spawn().expect("the lookalike starts");
        let looks = proc_origin(
            Ok(Listener {
                pid: lookalike.id(),
                uid: this_user(),
            }),
            this_user(),
            &PathBuf::from(format!("/proc/{}", lookalike.id())),
            &hops,
        );

        let within = Duration::from_secs(1);
        let refused = (
            stop_outdated_daemon(plain.id(), &endpoint, within).is_err(),
            stop_outdated_daemon(lookalike.id(), &endpoint, within).is_err(),
        );
        let alive = (
            still_runs(&mut plain, within),
            still_runs(&mut lookalike, within),
        );
        for child in [&mut plain, &mut lookalike] {
            let _ = child.kill();
            let _ = child.wait();
        }
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            looks,
            Origin::Service(lookalike.id()),
            "the lookalike must pass for the service's daemon, or this proves nothing \
             about the check that it holds the endpoint"
        );
        assert_eq!(
            (refused, alive),
            ((true, true), (true, true)),
            "((refused sleep, refused the lookalike), (sleep alive, lookalike alive)). \
             Neither holds the endpoint, so neither is the daemon to restart; the \
             front door stops nothing but that one."
        );
    }
}

#[cfg(all(test, unix))]
mod how_a_daemon_was_started_on_linux {
    //! On Linux the service the app restarts is a hops daemon of this user with
    //! no controlling terminal. These read a stand-in for its `/proc` entry.

    use super::{Origin, proc_origin, terminal_of};
    use hops_ipc::Listener;
    use std::path::{Path, PathBuf};

    const UID: u32 = 1000;
    const PID: u32 = 4242;

    struct Proc(PathBuf);

    impl Drop for Proc {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A `/proc/<pid>` stand-in: `exe` links to a file named `program`,
    /// `cmdline` holds `args`, and `stat` names terminal `tty`.
    fn proc(tag: &str, program: &str, args: &[&str], tty: i64) -> Proc {
        let dir = std::env::temp_dir().join(format!("hops-proc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).expect("a scratch directory");
        let target = dir.join("bin").join(program);
        std::fs::write(&target, "").expect("a program file");
        std::os::unix::fs::symlink(&target, dir.join("exe")).expect("the exe link");
        let mut cmdline = Vec::new();
        for arg in args {
            cmdline.extend_from_slice(arg.as_bytes());
            cmdline.push(0);
        }
        std::fs::write(dir.join("cmdline"), cmdline).expect("cmdline");
        std::fs::write(
            dir.join("stat"),
            format!("{PID} (ho ps) S 1 {PID} {PID} {tty} -1 4194560 0 0\n"),
        )
        .expect("stat");
        Proc(dir)
    }

    /// As the copy of hops at `of`'s own program sees it.
    fn origin(of: &Path, uid: u32) -> Origin {
        let program = std::fs::read_link(of.join("exe")).expect("the exe link");
        proc_origin(Ok(Listener { pid: PID, uid }), UID, of, &program)
    }

    // LEDGER T2228 | class B | 1 return value
    #[test]
    fn only_a_hops_daemon_of_this_user_with_no_terminal_is_the_service() {
        let detached = proc("detached", "hops", &["/usr/bin/hops", "daemon"], 0);
        let with_config = proc(
            "config",
            "hops",
            &["hops", "--config", "/tmp/c.toml", "daemon"],
            0,
        );
        let terminal = proc("tty", "hops", &["hops", "daemon"], 34816);
        let frontend = proc("gui", "hops", &["hops", "gui"], 0);
        let other = proc("other", "python3", &["python3", "daemon"], 0);
        assert_eq!(
            (origin(&detached.0, UID), origin(&with_config.0, UID)),
            (Origin::Service(PID), Origin::Service(PID)),
            "a hops daemon of this user with no terminal is the one the service runs"
        );
        for (what, got, says) in [
            (
                "run from a terminal",
                origin(&terminal.0, UID),
                "from a terminal",
            ),
            (
                "a frontend, not the daemon",
                origin(&frontend.0, UID),
                "hops daemon",
            ),
            ("not a hops program", origin(&other.0, UID), "hops daemon"),
            (
                "another user's",
                origin(&detached.0, UID + 1),
                "another user",
            ),
        ] {
            assert!(
                matches!(&got, Origin::Other(why) if why.contains(says)),
                "{what}: {got:?}. The front door would stop a process that is not \
                 the service's daemon."
            );
        }
    }

    /// A hops daemon of this user with no terminal, run from another copy of
    /// hops than the app's, is that copy's service, not this one's: the
    /// front door restarted it from any copy (as macOS does not).
    // LEDGER T2238 | class B | 1 return value
    #[test]
    fn a_daemon_of_another_copy_is_not_this_copys_service() {
        let theirs = proc("copy", "hops", &["/opt/hops/hops", "daemon"], 0);
        let ours = theirs.0.join("elsewhere").join("hops");
        let program = std::fs::read_link(theirs.0.join("exe")).expect("the exe link");
        let replaced = PathBuf::from(format!("{} (deleted)", program.display()));
        let other = proc_origin(Ok(Listener { pid: PID, uid: UID }), UID, &theirs.0, &ours);
        assert!(
            matches!(&other, Origin::Other(why) if why.contains("another copy")),
            "a daemon of another copy of hops was taken for this copy's service: \
             {other:?}"
        );
        assert!(
            super::same_program(&replaced, &program),
            "the daemon an update in place left running is this copy's"
        );
    }

    // LEDGER T2237 | class B | 1 return value
    #[test]
    fn the_terminal_is_read_past_a_program_name_with_parentheses() {
        assert_eq!(terminal_of("1 (a) b) S 1 1 1 34816 -1"), Some(34816));
        assert_eq!(terminal_of("1 (hops) S 1 1 1 0 -1"), Some(0));
        assert_eq!(terminal_of("garbage"), None);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod the_launch_agent_on_disk {
    //! The plist is read and written with `plutil`, and judged by what it
    //! means rather than how it is laid out, since several writers make it:
    //! v0.12's front door, this one, the installer and the dev launcher.

    use super::{LAUNCHD_LABEL, OnDisk, point_agent_at, read_agent};
    use std::path::{Path, PathBuf};

    /// The plist v0.12.0's front door wrote, verbatim but for the paths.
    fn v0_12(exe: &Path, log: &Path) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.grabbr.hops</string>
    <key>ProgramArguments</key>
    <array><string>{}</string><string>daemon</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><false/>
    <key>ProcessType</key><string>Interactive</string>
    <key>StandardOutPath</key><string>{}</string>
    <key>StandardErrorPath</key><string>{}</string>
</dict>
</plist>
"#,
            exe.display(),
            log.display(),
            log.display()
        )
    }

    /// A scratch directory holding a stand-in `hops` binary.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("hops-agent-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("new.app")).expect("a scratch directory");
            std::fs::write(dir.join("new.app/hops"), b"").expect("a stand-in binary");
            Self(dir)
        }
        fn exe(&self) -> PathBuf {
            self.0.join("new.app/hops")
        }
        fn plist(&self) -> PathBuf {
            self.0.join("com.grabbr.hops.plist")
        }
        fn log(&self) -> PathBuf {
            self.0.join("daemon.log")
        }
        fn read(&self) -> serde_json::Map<String, serde_json::Value> {
            match read_agent(&self.plist()).expect("readable") {
                OnDisk::Found(plist) => plist,
                other => panic!("the plist did not read back: {other:?}"),
            }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // LEDGER T65 | class B | 4 file on disk, read back with plutil
    #[test]
    fn a_plist_for_a_binary_that_moved_or_in_the_old_format_is_rewritten_and_a_current_one_is_not()
    {
        let dir = Scratch::new("judge");
        let exe = dir.exe();

        // Missing: written, and what is written is current.
        let first = point_agent_at(&dir.plist(), &exe, &dir.log()).expect("written");
        assert!(first.rewritten, "a missing plist was not written");
        let again = point_agent_at(&dir.plist(), &exe, &dir.log()).expect("read");
        assert!(
            !again.rewritten,
            "the plist this build writes reads as out of date: {:?}",
            dir.read()
        );

        // v0.12's plist for this very binary: the path is right, but launchd
        // never restarts a daemon that crashed.
        std::fs::write(dir.plist(), v0_12(&exe, &dir.log())).expect("a v0.12 plist");
        assert!(
            point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("rewritten")
                .rewritten,
            "a v0.12 plist, `KeepAlive` false, was left as it was"
        );
        assert_eq!(
            dir.read().get("KeepAlive"),
            Some(&serde_json::json!({ "SuccessfulExit": false })),
            "{:?}",
            dir.read()
        );

        // v0.12's plist for the app where it used to be.
        let gone = dir.0.join("old.app/hops");
        std::fs::write(dir.plist(), v0_12(&gone, &dir.log())).expect("a v0.12 plist");
        assert!(
            point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("rewritten")
                .rewritten,
            "a plist naming a binary that is no longer there was left as it was, so \
             launchd goes on starting a path that does not exist (#170)"
        );
        assert_eq!(
            dir.read().get("ProgramArguments"),
            Some(&serde_json::json!([exe.to_str().expect("utf-8"), "daemon"])),
        );
        assert_eq!(
            dir.read().get("Label").and_then(|l| l.as_str()),
            Some(LAUNCHD_LABEL)
        );
        assert!(
            !point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("read")
                .rewritten,
            "a repointed plist still reads as out of date"
        );

        // Another copy of hops that is still there: the old app was copied
        // rather than moved, and this one was launched.
        let other = dir.0.join("old.app/hops");
        std::fs::create_dir_all(dir.0.join("old.app")).expect("another app");
        std::fs::write(&other, b"").expect("another binary");
        std::fs::write(dir.plist(), v0_12(&other, &dir.log())).expect("a v0.12 plist");
        let mut plist = dir.read();
        plist.insert(
            "KeepAlive".into(),
            serde_json::json!({ "SuccessfulExit": false }),
        );
        super::write_agent(&dir.plist(), &plist).expect("written");
        assert!(
            point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("rewritten")
                .rewritten,
            "a plist naming another copy of hops was left as it was, so launchd \
             starts that copy rather than the one the user opened"
        );

        // A link to this binary names it: left alone.
        let link = dir.0.join("hops-link");
        std::os::unix::fs::symlink(&exe, &link).expect("a link");
        std::fs::write(dir.plist(), v0_12(&link, &dir.log())).expect("a plist");
        let mut plist = dir.read();
        plist.insert(
            "KeepAlive".into(),
            serde_json::json!({ "SuccessfulExit": false }),
        );
        plist.insert(
            "AssociatedBundleIdentifiers".into(),
            serde_json::json!(["com.grabbr.hops"]),
        );
        super::write_agent(&dir.plist(), &plist).expect("written");
        assert!(
            !point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("read")
                .rewritten,
            "a plist naming a link to this binary was rewritten"
        );
    }

    /// System Settings lists a legacy LaunchAgent under the app whose bundle
    /// identifier the plist names (`man launchd.plist`,
    /// AssociatedBundleIdentifiers). A plist without it is out of date, and
    /// an identifier another writer added stays.
    // LEDGER T71 | class B | 4 file on disk, read back with plutil
    #[test]
    fn the_plist_names_the_app_it_belongs_to() {
        use serde_json::json;
        let dir = Scratch::new("bundle");
        let exe = dir.exe();

        point_agent_at(&dir.plist(), &exe, &dir.log()).expect("written");
        assert_eq!(
            dir.read().get("AssociatedBundleIdentifiers"),
            Some(&json!(["com.grabbr.hops"])),
            "a new plist does not name the app it belongs to: {:?}",
            dir.read()
        );

        // Current in every other respect, but written before the key.
        let mut plist = dir.read();
        plist.remove("AssociatedBundleIdentifiers");
        super::write_agent(&dir.plist(), &plist).expect("written");
        assert!(
            point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("rewritten")
                .rewritten,
            "a plist that names no app was left as it was"
        );
        assert_eq!(
            dir.read().get("AssociatedBundleIdentifiers"),
            Some(&json!(["com.grabbr.hops"]))
        );

        // A single string naming another app: kept, and ours added.
        let mut plist = dir.read();
        plist.insert(
            "AssociatedBundleIdentifiers".into(),
            json!("org.example.other"),
        );
        super::write_agent(&dir.plist(), &plist).expect("written");
        assert!(
            point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("rewritten")
                .rewritten
        );
        assert_eq!(
            dir.read().get("AssociatedBundleIdentifiers"),
            Some(&json!(["org.example.other", "com.grabbr.hops"]))
        );
        assert!(
            !point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("read")
                .rewritten,
            "a plist naming hops among other apps reads as out of date"
        );
    }

    /// The dev launcher and the installer write their own plists, with an
    /// environment and log paths of their own. Repointing one changes only
    /// what decides which binary runs and whether it comes back.
    // LEDGER T66 | class B | 4 file on disk, read back with plutil
    #[test]
    fn repointing_keeps_what_another_writer_set() {
        let dir = Scratch::new("keep");
        let exe = dir.exe();
        std::fs::write(
            dir.plist(),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>com.grabbr.hops</string>
    <key>ProgramArguments</key><array><string>{}</string><string>daemon</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><false/>
    <key>ProcessType</key><string>Interactive</string>
    <key>EnvironmentVariables</key><dict><key>HOPS_LOG_LEVEL</key><string>info</string></dict>
    <key>StandardOutPath</key><string>/elsewhere/daemon.log</string>
    <key>StandardErrorPath</key><string>/elsewhere/daemon.log</string>
</dict></plist>
"#,
                dir.0.join("gone/hops").display()
            ),
        )
        .expect("a launcher's plist");
        assert!(
            point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("rewritten")
                .rewritten
        );
        let plist = dir.read();
        assert_eq!(
            (
                plist.get("EnvironmentVariables"),
                plist.get("StandardOutPath").and_then(|p| p.as_str()),
                plist.get("RunAtLoad"),
            ),
            (
                Some(&serde_json::json!({ "HOPS_LOG_LEVEL": "info" })),
                Some("/elsewhere/daemon.log"),
                Some(&serde_json::json!(true)),
            ),
            "repointing dropped what the plist's writer set: {plist:?}"
        );

        // And a file that is not a plist at all is replaced by a whole one.
        std::fs::write(dir.plist(), b"not a plist {").expect("junk");
        assert!(
            point_agent_at(&dir.plist(), &exe, &dir.log())
                .expect("rewritten")
                .rewritten
        );
        assert_eq!(
            dir.read().get("ProgramArguments"),
            Some(&serde_json::json!([exe.to_str().expect("utf-8"), "daemon"]))
        );
    }

    /// launchd creates the job's output file with its own umask, readable by
    /// every account, and it holds what the daemon printed before its logger
    /// started and any abort message.
    // LEDGER T67 | class B | 4 file on disk: point_agent_at, the output file's mode read back
    #[test]
    fn the_file_launchd_sends_the_daemons_output_to_is_this_users_alone() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| {
            std::fs::metadata(p)
                .expect("the output file exists")
                .permissions()
                .mode()
                & 0o777
        };
        let dir = Scratch::new("outmode");
        let exe = dir.exe();

        // A new agent: the file is there before launchd opens it.
        point_agent_at(&dir.plist(), &exe, &dir.log()).expect("written");
        assert_eq!(mode(&dir.log()), 0o600, "a new output file was left open");

        // A current agent, with the file an earlier start left readable.
        std::fs::set_permissions(dir.log(), std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let again = point_agent_at(&dir.plist(), &exe, &dir.log()).expect("read");
        assert!(!again.rewritten, "{:?}", dir.read());
        assert_eq!(
            mode(&dir.log()),
            0o600,
            "an old output file was left {:o}",
            mode(&dir.log())
        );
    }
}

#[cfg(test)]
mod a_launch_agent_is_never_pointed_at_a_disk_image {
    //! Opened from the mounted disk image, or from the copy macOS runs a
    //! quarantined app from, hops wrote its LaunchAgent to start that path at
    //! every login: the image could not be ejected while the daemon ran from
    //! it, and once it was, or the copy was cleared, nothing started at login.

    use super::point_agent_at;
    use std::path::PathBuf;

    // LEDGER T8 | class B | 1 error + 4 file on disk: point_agent_at
    #[test]
    fn a_binary_on_a_disk_image_or_a_translocated_copy_is_refused_and_nothing_is_written() {
        let dir = std::env::temp_dir().join(format!("hops-agent-dmg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let plist = dir.join("com.grabbr.hops.plist");
        let log = dir.join("daemon.log");
        let installed = b"the plist of the copy in Applications";

        for exe in [
            "/Volumes/hops/hops.app/Contents/MacOS/hops",
            "/private/var/folders/xy/abc/T/AppTranslocation/1F2E3D4C/d/hops.app/Contents/MacOS/hops",
        ] {
            let exe = PathBuf::from(exe);

            let _ = std::fs::remove_file(&plist);
            let refused = point_agent_at(&plist, &exe, &log)
                .expect_err("a LaunchAgent was pointed at a disk image");
            let why = refused.to_string();
            assert!(
                why.contains("move hops to Applications"),
                "the refusal must say what to do: {why}"
            );
            assert!(!plist.exists(), "a plist was written for {}", exe.display());

            // The agent of the copy in Applications stays as it was.
            std::fs::write(&plist, installed).expect("an installed plist");
            assert!(point_agent_at(&plist, &exe, &log).is_err());
            assert_eq!(
                std::fs::read(&plist).expect("read"),
                installed,
                "the installed agent was changed to run {}",
                exe.display()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // LEDGER T8c | class B | 1 the verdict, for a volume each way
    #[test]
    fn an_app_on_a_writable_volume_is_installed_and_one_on_a_read_only_image_is_not() {
        // Some keep Applications on a second disk, which is mounted under
        // /Volumes too; what marks the disk image hops ships in is that it
        // is mounted read-only.
        let exe =
            std::path::Path::new("/Volumes/Apps Disk/Applications/hops.app/Contents/MacOS/hops");
        assert_eq!(
            super::place_of(exe, |_| false),
            None,
            "an app on a writable volume was refused"
        );
        assert!(
            super::place_of(exe, |_| true).is_some(),
            "an app on a read-only image was accepted"
        );
    }

    // LEDGER T8d | class B | 1 the probe on real mounts
    // Unix only: elsewhere the probe answers read-only for every path, and
    // nothing outside macOS reaches it.
    #[cfg(unix)]
    #[test]
    fn the_probe_reads_a_scratch_directory_as_writable_and_the_system_volume_as_not() {
        // A scratch directory is writable, and on macOS the system volume is
        // mounted read-only, as a disk image is.
        assert!(
            !super::mounted_read_only(&std::env::temp_dir()),
            "a writable scratch directory read as read-only"
        );
        if cfg!(target_os = "macos") {
            assert!(
                super::mounted_read_only(std::path::Path::new("/usr/bin")),
                "the read-only system volume read as writable"
            );
        }
    }

    // LEDGER T8b | class B | 4 file on disk: point_agent_at through a link in /Volumes
    #[test]
    fn a_binary_reached_through_the_startup_disks_link_in_volumes_is_installed() {
        // macOS keeps a link to the startup disk in /Volumes. Without one
        // (another system) there is nothing to observe.
        let Some(link) = std::fs::read_dir("/Volumes").ok().and_then(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .find(|p| std::fs::canonicalize(p).is_ok_and(|to| to == std::path::Path::new("/")))
        }) else {
            eprintln!("no link to / in /Volumes here; nothing to check");
            return;
        };
        let dir = std::env::temp_dir().join(format!("hops-agent-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let real = dir.join("hops");
        std::fs::write(&real, b"a binary").expect("a binary");
        let through = link.join(real.strip_prefix("/").expect("an absolute path"));
        let plist = dir.join("com.grabbr.hops.plist");

        let pointed = point_agent_at(&plist, &through, &dir.join("daemon.log"));
        assert!(
            pointed.is_ok() && plist.exists(),
            "{} is on the startup disk, and was refused: {pointed:?}",
            through.display()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

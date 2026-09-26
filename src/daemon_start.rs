//! Bringing the daemon up from the front door.
//!
//! `hops` with no subcommand makes sure a daemon is running before it opens a
//! frontend. It starts one only when none answers on the IPC endpoint, so
//! opening the app never starts a second. On macOS the start goes through the
//! launchd service; on Linux and Windows it is a detached process.
//!
//! A start counts only when the daemon serves frontends by the end of a
//! bounded wait: it takes the token and sends state. A daemon binds its
//! endpoint before it reads the token, the config and its keys, and one that
//! fails on any of them exits a moment later, so a process id, or something
//! answering on the endpoint, is not enough. A daemon that exits first, or has
//! not answered when the wait ends, is logged as such, with the file it logs
//! to.
//!
//! The frontend crates attach to a daemon and spawn nothing, and `src/main.rs`
//! calls [`ensure_running`].
//!
//! The probe and the start are two steps, so two starts can still overlap: two
//! front doors opened together, or one opened while a login service is
//! bringing a daemon up. Which daemon keeps running is settled by its claim on
//! the IPC endpoint (`hops_ipc::AsyncFrontendListener::at`), which it takes
//! before it reads the config or any key; the other exits.

use hops_ipc::{DaemonEndpoint, SocketPathError};
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
}

impl StartReport {
    /// What to show the user, or `None` when a daemon is running.
    ///
    /// Without this a start that failed reached the screen as "connecting",
    /// indefinitely, with the reason in a log nobody was pointed at (#189).
    pub fn problem(&self) -> Option<String> {
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
        .map(|text| text.trim_end().to_string())
    }
}

/// [`start_unless_running`], reporting why a start did not come up.
pub fn start_unless_running_reported(
    endpoint: Result<DaemonEndpoint, SocketPathError>,
    start: impl FnOnce() -> io::Result<u32>,
    watch: &mut impl Watch,
    within: Duration,
) -> StartReport {
    let report = |outcome, why: Option<String>, log_file| StartReport {
        outcome,
        why,
        log_file,
        within,
    };
    let endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(e) => {
            log::warn!("cannot tell whether a daemon is running ({e}); not starting one");
            return report(DaemonStart::CannotProbe, Some(e.to_string()), None);
        }
    };
    if endpoint.answers() {
        log::info!("a daemon answers on {endpoint}; not starting another");
        return report(DaemonStart::AlreadyRunning, None, None);
    }
    log::info!("no daemon answers on {endpoint}; starting one");
    let pid = match start() {
        Ok(pid) => pid,
        Err(e) => {
            log::warn!("could not start the daemon: {e}");
            return report(DaemonStart::StartFailed, Some(e.to_string()), None);
        }
    };
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
    report(outcome, None, log_file)
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

/// Make sure a daemon is running, starting one only if none answers.
///
/// A daemon that answers is left alone whoever started it. On macOS that also
/// means no LaunchAgent is installed beside it to race it at the next login.
#[cfg(any(feature = "tui", feature = "slint"))]
pub fn ensure_running() -> StartReport {
    ensure_running_reported_with(start_platform_daemon, &mut ThisMachine, START_WAIT)
}

/// Start the daemon the way this platform runs it: the GRANTED launchd service
/// on macOS, never a child of ours (which could land on the dummy backend);
/// a detached background process elsewhere. Returns the daemon's process id.
#[cfg(any(feature = "tui", feature = "slint"))]
fn start_platform_daemon() -> io::Result<u32> {
    #[cfg(target_os = "macos")]
    {
        ensure_launchd_daemon()
    }
    #[cfg(not(target_os = "macos"))]
    {
        start_detached_daemon()
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
/// Runs only when no daemon answers on the endpoint (see
/// [`start_unless_running`]), so nothing it does can stop a daemon that
/// serves.
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
    let reload = loaded && agent.rewritten;
    if reload {
        // Nothing answers on the endpoint, so the job has no daemon that
        // serves. Whether this succeeds is for the bootstrap below to say.
        let out = launch(&["bootout", &service])?;
        if !out.succeeded() {
            log::debug!("`launchctl bootout {service}`: {}", out.reason());
        }
    }

    let mut not_loaded = String::new();
    if !loaded || agent.rewritten {
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
fn ensure_launchd_daemon() -> io::Result<u32> {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    start_through_launchd(
        uid,
        &mut run_launchctl,
        keep_agent_pointing_here,
        &mut std::thread::sleep,
    )
}

#[cfg(all(target_os = "macos", any(feature = "tui", feature = "slint")))]
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
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "$HOME is not set"))?;
    let plist = home.join(format!("Library/LaunchAgents/{LAUNCHD_LABEL}.plist"));
    let logs = home.join("hops/logs");
    let _ = std::fs::create_dir_all(&logs);
    point_agent_at(&plist, &std::env::current_exe()?, &logs.join("daemon.log"))
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

    // `true` restarts after any exit; a dictionary restarts after a failure
    // only when it says `SuccessfulExit` is false. v0.12 wrote `false`, so a
    // daemon that crashed stayed down for the rest of the session.
    let restarts = match agent.get("KeepAlive") {
        Some(Value::Bool(always)) => *always,
        Some(Value::Object(when)) => when.get("SuccessfulExit") == Some(&Value::Bool(false)),
        _ => false,
    };
    if !restarts {
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

/// Make the plist at `path` run `exe` as the daemon: write it when it is
/// missing or unreadable, change it when it runs another binary or would not
/// be restarted after a failure, and leave it alone otherwise.
#[cfg_attr(
    not(all(target_os = "macos", any(feature = "tui", feature = "slint"))),
    allow(dead_code)
)]
fn point_agent_at(path: &Path, exe: &Path, log: &Path) -> io::Result<AgentFile> {
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
    match read_agent(path)? {
        OnDisk::Missing => {
            log::info!("writing {} to run {exe_text}", path.display());
            write_agent(path, &fresh())?;
            Ok(written(true))
        }
        OnDisk::Unreadable(why) => {
            log::warn!(
                "{} could not be read ({why}); writing it again to run {exe_text}",
                path.display()
            );
            write_agent(path, &fresh())?;
            Ok(written(true))
        }
        OnDisk::Found(mut plist) => {
            let wrong = repoint(&mut plist, exe, exe_text);
            if wrong.is_empty() {
                return Ok(written(false));
            }
            let wrong = wrong.join(", and ");
            log::info!("{}: {wrong}; changing it to run {exe_text}", path.display());
            write_agent(path, &plist).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{} is out of date ({wrong}): {e}", path.display()),
                )
            })?;
            Ok(written(true))
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

    /// A daemon on a loopback port that takes each connection's token, then
    /// starts a line of JSON and adds a space to it every 50 ms, never ending
    /// it, for up to 5 s or until the asker hangs up. Asked through the real
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
        );
        (got, calls.into_inner(), written.into_inner(), pauses)
    }

    fn never_restarts_or_stops(calls: &[String]) {
        for call in calls {
            assert!(
                !call.contains("-k") && !call.starts_with("bootout") && !call.starts_with("kill"),
                "`launchctl {call}` can stop a running daemon, and the front door \
                 only starts one"
            );
        }
    }

    // LEDGER T12 | class B | 1 return value + 6 calls recorded by the injected runner
    #[test]
    fn a_loaded_job_with_no_process_is_started_and_counts_only_with_its_pid() {
        let (got, calls, installed) = start_with(|sub| match sub {
            "print" => loaded_idle(),
            "kickstart" => ok("4711\n"),
            other => failed(1, &format!("unexpected {other}")),
        });
        never_restarts_or_stops(&calls);
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
        never_restarts_or_stops(&calls);
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
        never_restarts_or_stops(&calls);
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
        for call in &calls {
            assert!(
                !call.contains("-k") && !call.starts_with("kill"),
                "`launchctl {call}` restarts or signals a daemon; reloading the job \
                 needs neither"
            );
        }

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
        never_restarts_or_stops(&calls);
        assert_eq!(calls, [format!("print {SERVICE}")], "{got:?}");
        let message = got.map(|p| p.to_string()).unwrap_or_else(|e| e.to_string());
        assert!(
            message.contains(PLIST) && message.contains("/Applications/old/hops"),
            "the failure must name the plist and the binary it still runs: {message}"
        );
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
}

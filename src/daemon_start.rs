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
    let endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(e) => {
            log::warn!("cannot tell whether a daemon is running ({e}); not starting one");
            return DaemonStart::CannotProbe;
        }
    };
    if endpoint.answers() {
        log::info!("a daemon answers on {endpoint}; not starting another");
        return DaemonStart::AlreadyRunning;
    }
    log::info!("no daemon answers on {endpoint}; starting one");
    let pid = match start() {
        Ok(pid) => pid,
        Err(e) => {
            log::warn!("could not start the daemon: {e}");
            return DaemonStart::StartFailed;
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
    outcome
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

/// Make sure a daemon is running, starting one only if none answers.
///
/// A daemon that answers is left alone whoever started it. On macOS that also
/// means no LaunchAgent is installed beside it to race it at the next login.
#[cfg(any(feature = "tui", feature = "slint"))]
pub fn ensure_running() -> DaemonStart {
    ensure_running_with(start_platform_daemon, &mut ThisMachine, START_WAIT)
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
/// A job that is not loaded is bootstrapped from its plist, which `install`
/// writes if it is missing. Either way the job is then kickstarted without
/// `-k`: launchd starts a job that is loaded but has no process, and leaves
/// a running one alone. The plist's `KeepAlive` restarts the daemon only after
/// an unsuccessful exit, so a daemon that quit, or exited because another held
/// the endpoint, stays loaded with no process until something starts it. Its
/// `RunAtLoad` starts the daemon as the job is bootstrapped, so the kickstart
/// after a bootstrap usually finds it running.
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
    install: impl FnOnce() -> io::Result<String>,
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

    let mut not_loaded = String::new();
    if !launch(&["print", &service])?.succeeded() {
        let plist = install()?;
        let bootstrap = launch(&["bootstrap", &domain, &plist])?;
        if !bootstrap.succeeded() {
            // Another start may have loaded the job since `print`, so this is
            // not yet a failure: the kickstart below says whether it runs.
            not_loaded = format!(
                "`launchctl bootstrap {domain} {plist}` failed: {}; ",
                bootstrap.reason()
            );
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
    start_through_launchd(uid, &mut run_launchctl, install_launchd_plist_if_missing)
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

/// Write `~/Library/LaunchAgents/com.grabbr.hops.plist` (pointed at the current
/// binary) if absent; returns its path. Grant is path-bound, so the plist must
/// point at whatever `hops` binary the user actually launched.
#[cfg(all(target_os = "macos", any(feature = "tui", feature = "slint")))]
fn install_launchd_plist_if_missing() -> io::Result<String> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "$HOME is not set"))?;
    let plist_path = home.join(format!("Library/LaunchAgents/{LAUNCHD_LABEL}.plist"));
    if plist_path.exists() {
        return Ok(plist_path.to_string_lossy().into_owned());
    }
    let exe = std::env::current_exe()?;
    let logs = home.join("hops/logs");
    let _ = std::fs::create_dir_all(&logs);
    let log = logs.join("daemon.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>{exe}</string><string>daemon</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
    <key>ThrottleInterval</key><integer>10</integer>
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
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&plist_path, plist).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("could not write {}: {e}", plist_path.display()),
        )
    })?;
    Ok(plist_path.to_string_lossy().into_owned())
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

    use super::{DaemonStart, Watch, start_unless_running, what_became_of};
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

    use super::{LaunchctlRun, start_through_launchd};
    use std::cell::RefCell;
    use std::io;

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

    /// Run the start against `script`, which answers each `launchctl` call by
    /// its subcommand. Returns the result, every call made in order, and
    /// whether the plist was installed.
    fn start_with(script: impl Fn(&str) -> LaunchctlRun) -> (io::Result<u32>, Vec<String>, bool) {
        let calls = RefCell::new(Vec::new());
        let installed = RefCell::new(false);
        let mut launchctl = |args: &[&str]| {
            calls.borrow_mut().push(args.join(" "));
            Ok(script(args[0]))
        };
        let got = start_through_launchd(UID, &mut launchctl, || {
            *installed.borrow_mut() = true;
            Ok("Library/LaunchAgents/com.grabbr.hops.plist".into())
        });
        (got, calls.into_inner(), installed.into_inner())
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
        let (got, calls, installed) = start_with(|sub| match sub {
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
}

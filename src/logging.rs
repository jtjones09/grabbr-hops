//! Logging that does not depend on how the process was started.
//!
//! # Why this exists
//!
//! Everything used to go to stderr, and whoever launched hops decided whether
//! that reached a file. Three launchers, three answers, and one of them silent:
//! the Windows tray was started with no redirection at all, so its output went
//! nowhere. A panic hook that force-captures a backtrace — added precisely
//! because "it died again" with no frame of ours was useless — wrote a full
//! stack into a void every time the tray aborted.
//!
//! So the process owns its own sink now. It opens a file itself, on every
//! platform, whatever started it. A frontend cannot be silent by omission.
//!
//! # Three things this fixes, in order of how much they cost
//!
//! **A frontend with no log.** The tray's crashes were unreadable on Windows.
//!
//! **A log that grows forever.** The dev log reached 5.2 GB. The cause was not
//! volume of real events — it was `HOPS_LOG_LEVEL=debug` applied globally, so
//! every mDNS packet was logged by a dependency. Two separate mistakes: no
//! rotation, and a level that could not be scoped. Both are fixed here — the
//! default filter targets hops' own crates and leaves dependencies at `warn`,
//! so asking for debug gives you hops' debug rather than the whole world's.
//!
//! **A log the OS cannot see.** Covered per platform below.
//!
//! # What each platform gets, and what it does not
//!
//! **Linux** needs nothing extra: under a systemd unit, stderr is captured by
//! journald already, so `journalctl --user -u hops` works today.
//!
//! **macOS** sends warnings and errors through `syslog(3)`, which modern macOS
//! forwards into the unified log — verified on 26.6.2 — so they show up in
//! Console.app and survive the process, with no new dependency and no
//! entitlement. Only warnings and errors: see `worth_telling_the_os` for the
//! measurement that decided it. Deliberately NOT `os_log` directly, whose
//! useful form is a C macro and whose FFI shape underneath redacts every
//! dynamic string unless each field is marked public — a reliable way to end up
//! with a log full of `<private>` and worse than none.
//!
//! **Windows gets the file only.** Writing to the Event Log requires a
//! registered event source, which is a registry write needing elevation at
//! install time. That is an installer decision rather than a logging one, so it
//! is deliberately left out rather than half-done. Hard crashes still reach
//! Windows Error Reporting on their own.

use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use log::{LevelFilter, Log, Metadata, Record};

/// Rotate once the file passes this, keeping one previous generation.
///
/// Eight megabytes is roughly a week of ordinary lifecycle logging and a few
/// minutes of `debug`, which is the right trade: enough to hold the run that
/// went wrong, small enough that nobody has to think about it. The failure this
/// replaces was unbounded — a single file at 5.2 GB.
const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Dependencies stay at this level unless asked for by name.
///
/// `HOPS_LOG_LEVEL=debug` used to mean *everything* debug, which is how one
/// dependency logging each mDNS packet produced a multi-gigabyte file. The
/// level now applies to hops' own crates; a dependency has to be named
/// explicitly, e.g. `HOPS_LOG_LEVEL=info,mdns_sd=debug`.
const DEPENDENCY_LEVEL: LevelFilter = LevelFilter::Warn;

/// Our own crates, so a bare level applies to them and not the world.
const OURS: &[&str] = &[
    "hops",
    "hops_ipc",
    "hops_proto",
    "hops_cli",
    "hops_tui",
    "hops_slint",
    "hops_frontend_core",
    "input_capture",
    "input_emulation",
    "input_event",
];

/// Global flags that consume the next argument.
///
/// Without these, `hops --config daemon.toml gui` reads its own config path as
/// the subcommand. Clap owns the real parse; this only has to get the role
/// right, early enough that a parse failure still reaches a log.
const TAKES_A_VALUE: &[&str] = &[
    "-c",
    "--config",
    "--capture-backend",
    "--emulation-backend",
    "--cert-path",
];

/// Which log this process writes to, read straight from argv.
///
/// The logger has to be up before `Config::new()` parses anything — a config
/// parse failure is exactly the kind of thing that should reach a log rather
/// than vanish — so the role cannot come from the parsed `Command`.
///
/// Only the three long-running roles get their own file. They are separate
/// processes with separate lifetimes, and interleaving a daemon with the tray
/// that attaches to it makes both harder to read. Everything else is a
/// short-lived command sharing one file.
pub fn role_from_argv() -> &'static str {
    role_from(std::env::args().skip(1))
}

fn role_from(args: impl Iterator<Item = String>) -> &'static str {
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if TAKES_A_VALUE.contains(&arg.as_str()) {
            args.next(); // its value, which is not a subcommand
            continue;
        }
        if arg.starts_with('-') {
            continue; // a bare switch, or `--config=path` carrying its own value
        }
        return match arg.as_str() {
            "daemon" => "daemon",
            "gui" => "gui",
            "tui" => "tui",
            _ => "cli",
        };
    }
    // No subcommand: the front door, which opens a front-end.
    if cfg!(feature = "slint") {
        "gui"
    } else {
        "tui"
    }
}

/// Where this process writes, absent an override.
///
/// Per-role rather than one shared file: the daemon and the tray are separate
/// processes with separate lifetimes, and interleaving them makes both harder
/// to read. `HOPS_LOG_FILE` overrides it entirely.
fn default_path(role: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HOPS_LOG_FILE") {
        return Some(PathBuf::from(p));
    }
    let dir = if cfg!(target_os = "macos") {
        PathBuf::from(std::env::var("HOME").ok()?)
            .join("Library")
            .join("Logs")
            .join("hops")
    } else if cfg!(windows) {
        PathBuf::from(std::env::var("LOCALAPPDATA").ok()?)
            .join("hops")
            .join("logs")
    } else {
        // $XDG_STATE_HOME is where logs belong on Linux; $HOME/.local/state is
        // its documented default.
        std::env::var("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("HOME").unwrap_or_default())
                    .join(".local")
                    .join("state")
            })
            .join("hops")
    };
    Some(dir.join(format!("{role}.log")))
}

/// Rename the current file aside once it is too big, keeping one generation.
///
/// Rotation happens on the write that crosses the line rather than on a timer,
/// so a process that logs heavily and then dies still leaves a bounded file.
fn rotate_if_needed(path: &Path, file: &mut File) -> std::io::Result<()> {
    if file.metadata().map(|m| m.len()).unwrap_or(0) < MAX_BYTES {
        return Ok(());
    }
    let previous = path.with_extension("log.1");
    let _ = fs::remove_file(&previous);
    fs::rename(path, &previous)?;
    *file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(())
}

/// Whether to write stderr as well, given whether we own a file and whether
/// stderr is a terminal.
///
/// Writing both unconditionally would leave the original defect standing. The
/// service launchers redirect stderr into a file of their own that nothing
/// rotates, so every line would land twice — once in the bounded file this
/// module keeps, once in an unbounded one. Capping the log while still feeding
/// a file that grows forever is not a fix.
///
/// So stderr is for the cases where it is the only thing that can be read: a
/// developer watching a terminal, or a process that could not open its file at
/// all. When a service redirects stderr to a log, the redirect still catches
/// what happens outside this logger — output before init, and the runtime's own
/// abort message under `panic = "abort"` — which is exactly what it is good for
/// and is bounded by how rarely those happen.
fn should_write_stderr(owns_file: bool, stderr_is_terminal: bool) -> bool {
    !owns_file || stderr_is_terminal
}

/// Open an append handle that is capped the same way this module's own log is.
///
/// For output that is redirected rather than written through the logger — the
/// stdout and stderr of a daemon started by the front door. That handle had no
/// cap at all and grew for the life of an install; one reached 4.4 GB. Rotation
/// happens here, at open, because nothing downstream of a `Stdio` handle can
/// check a size.
pub fn open_capped(path: &Path) -> std::io::Result<File> {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    rotate_if_needed(path, &mut f)?;
    Ok(f)
}

struct Sink {
    file: Option<Mutex<(PathBuf, File)>>,
    filter: env_filter::Filter,
    to_stderr: bool,
    /// Forward to the platform's own log where that is free and unredacted.
    to_os: bool,
}

impl Log for Sink {
    fn enabled(&self, m: &Metadata) -> bool {
        self.filter.enabled(m)
    }

    fn log(&self, record: &Record) {
        if !self.filter.matches(record) {
            return;
        }
        let line = format!(
            "[{} {:<5} {}] {}",
            jiff::Zoned::now().strftime("%Y-%m-%d %H:%M:%S%.3f"),
            record.level(),
            record.target(),
            record.args()
        );

        if self.to_stderr {
            eprintln!("{line}");
        }

        if let Some(lock) = self.file.as_ref() {
            if let Ok(mut guard) = lock.lock() {
                let (path, file) = &mut *guard;
                let _ = rotate_if_needed(path, file);
                let _ = writeln!(file, "{line}");
            }
        }

        if self.to_os && worth_telling_the_os(record.level()) {
            os_log(record.level(), &line);
        }
    }

    fn flush(&self) {
        if let Some(lock) = self.file.as_ref() {
            if let Ok(mut guard) = lock.lock() {
                let _ = guard.1.flush();
            }
        }
    }
}

/// Which levels are worth putting in the system-wide log.
///
/// Only what went wrong. Measured on macOS 26.6.2: the unified log records a
/// syslog message as `messageType: "Default"` *whatever* priority is passed —
/// `LOG_DEBUG`, `LOG_WARNING` and `LOG_ERR` all come back as `Default` — and
/// Default-level messages are persisted to the on-disk archive. So forwarding
/// every level would write hops' entire `debug` stream into system-wide
/// storage that hops does not own and cannot rotate. That is the 5.2 GB defect
/// again, moved into Apple's storage instead of ours.
///
/// A warning or an error is worth that cost: it survives the process, it is
/// visible in Console.app next to whatever else went wrong at that moment, and
/// there are few of them. The full record stays in hops' own file.
fn worth_telling_the_os(level: log::Level) -> bool {
    matches!(level, log::Level::Error | log::Level::Warn)
}

/// Hand the line to the platform log, where that costs nothing.
#[cfg(target_os = "macos")]
fn os_log(level: log::Level, line: &str) {
    use std::ffi::CString;
    // syslog(3) on modern macOS is forwarded into the unified log — verified on
    // 26.6.2 — so this is reachable with
    // `log show --predicate 'eventMessage CONTAINS "hops"'`, with no
    // dependency, no entitlement and no registration.
    //
    // The priority is set correctly even though macOS ignores it and stamps
    // everything `Default`; `worth_telling_the_os` is what actually keeps the
    // volume down.
    let priority = match level {
        log::Level::Error => libc::LOG_ERR,
        _ => libc::LOG_WARNING,
    };
    // A single %s with our own string: never pass the message as the format,
    // or a `%` in a peer-supplied label becomes a format directive.
    if let Ok(msg) = CString::new(line) {
        if let Ok(fmt) = CString::new("%s") {
            unsafe { libc::syslog(priority, fmt.as_ptr(), msg.as_ptr()) };
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn os_log(_level: log::Level, _line: &str) {
    // Linux: a systemd unit's stderr is captured by journald already, so the
    // eprintln above is the journal entry.
    //
    // Windows: the Event Log needs a registered event source, which is a
    // registry write requiring elevation at install time — an installer
    // decision, left out rather than half-implemented.
}

/// Build the filter so a bare level applies to hops and not to every crate.
fn build_filter(spec: &str) -> env_filter::Filter {
    let mut b = env_filter::Builder::new();
    // A spec naming targets (`info,mdns_sd=debug`) is honoured as written; a
    // bare level is expanded across our crates with dependencies held down.
    if spec.contains('=') {
        b.parse(spec);
    } else {
        b.filter(None, DEPENDENCY_LEVEL);
        let level = spec.parse().unwrap_or(LevelFilter::Info);
        for target in OURS {
            b.filter(Some(target), level);
        }
    }
    b.build()
}

/// Install the logger for `role` ("daemon", "gui", "tui", "cli").
///
/// Never fails the process: a log that cannot be opened is worth a line on
/// stderr, not a daemon that refuses to start.
pub fn init(role: &str) {
    let spec = std::env::var("HOPS_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let filter = build_filter(&spec);
    let level = filter.filter();

    let file = default_path(role).and_then(|path| {
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => Some(Mutex::new((path, f))),
            Err(e) => {
                eprintln!("hops: could not open a log file ({e}); logging to stderr only");
                None
            }
        }
    });

    let sink = Sink {
        to_stderr: should_write_stderr(file.is_some(), std::io::stderr().is_terminal()),
        file,
        filter,
        to_os: cfg!(target_os = "macos"),
    };
    if log::set_boxed_logger(Box::new(sink)).is_ok() {
        log::set_max_level(level);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_level_applies_to_hops_and_leaves_dependencies_quiet() {
        let f = build_filter("debug");
        assert!(
            f.enabled(
                &Metadata::builder()
                    .level(log::Level::Debug)
                    .target("hops")
                    .build()
            ),
            "a bare level must apply to hops' own crates"
        );
        assert!(
            !f.enabled(
                &Metadata::builder()
                    .level(log::Level::Debug)
                    .target("mdns_sd")
                    .build()
            ),
            "a bare level must NOT turn on debug for every dependency. It did, \
             and one dependency logging each mDNS packet produced a 5.2 GB file."
        );
    }

    #[test]
    fn a_dependency_can_still_be_turned_up_by_name() {
        let f = build_filter("info,mdns_sd=debug");
        assert!(
            f.enabled(
                &Metadata::builder()
                    .level(log::Level::Debug)
                    .target("mdns_sd")
                    .build()
            ),
            "naming a target explicitly must still work — that is how a protocol \
             problem gets diagnosed"
        );
    }

    #[test]
    fn a_redirected_handle_is_capped_at_open() {
        // The daemon's stdout/stderr are a `Stdio` handle: nothing downstream
        // can check a size, so the only moment a cap can be applied is here.
        // Uncapped, this handle grew for the life of an install — one reached
        // 4.4 GB.
        let dir = std::env::temp_dir().join(format!("hops-capped-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("daemon.log");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("log.1"));

        fs::write(&path, vec![b'x'; (MAX_BYTES + 1) as usize]).expect("fill");
        let f = open_capped(&path).expect("open");
        drop(f);

        assert!(
            fs::metadata(&path).expect("stat").len() < MAX_BYTES,
            "an oversized handle must be rotated at open — after this point the \
             writer is a redirected file descriptor and no size check is possible"
        );
        assert!(
            path.with_extension("log.1").exists(),
            "and what was there is kept as one generation, not discarded"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_rotates_rather_than_growing_without_bound() {
        let dir = std::env::temp_dir().join(format!("hops-log-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("rot.log");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("log.1"));

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open");
        f.write_all(&vec![b'x'; (MAX_BYTES + 1) as usize])
            .expect("fill");
        rotate_if_needed(&path, &mut f).expect("rotate");

        assert!(
            path.with_extension("log.1").exists(),
            "the oversized file must be kept as one previous generation"
        );
        assert!(
            fs::metadata(&path).expect("stat").len() < MAX_BYTES,
            "the live file must start fresh after rotating, or the cap does \
             nothing and the log grows forever — which is how one reached 5.2 GB"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    fn role(argv: &[&str]) -> &'static str {
        role_from(argv.iter().map(|s| s.to_string()))
    }

    #[test]
    fn the_role_comes_from_the_subcommand_not_from_a_flags_value() {
        assert_eq!(role(&["daemon"]), "daemon");
        assert_eq!(role(&["gui", "--hidden"]), "gui");
        assert_eq!(role(&["tui"]), "tui");
        assert_eq!(role(&["cli", "list"]), "cli");
        assert_eq!(
            role(&["--config", "daemon", "gui"]),
            "gui",
            "a flag's value is a path, not a subcommand — reading it as one \
             sends the tray's log to the daemon's file"
        );
        assert_eq!(role(&["--cert-path", "tui", "daemon"]), "daemon");
        assert_eq!(
            role(&["--config=daemon.toml", "gui"]),
            "gui",
            "`--flag=value` carries its value inline; skipping the next \
             argument as well would swallow the subcommand"
        );
    }

    #[test]
    fn only_warnings_and_errors_reach_the_system_wide_log() {
        assert!(worth_telling_the_os(log::Level::Error));
        assert!(worth_telling_the_os(log::Level::Warn));
        for quiet in [log::Level::Info, log::Level::Debug, log::Level::Trace] {
            assert!(
                !worth_telling_the_os(quiet),
                "{quiet} must not reach the system log. macOS records a \
                 forwarded syslog message as Default whatever priority is \
                 passed (measured on 26.6.2), and Default is persisted to the \
                 on-disk archive — so forwarding everything writes hops' whole \
                 debug stream into storage hops neither owns nor rotates."
            );
        }
    }

    #[test]
    fn a_redirected_stderr_does_not_get_a_second_unbounded_copy() {
        assert!(
            !should_write_stderr(true, false),
            "under a service launcher stderr is redirected into a file nothing \
             rotates. Writing there as well as to the rotated file means every \
             line lands twice, once somewhere unbounded — which leaves the \
             defect this module exists to fix standing."
        );
        assert!(
            should_write_stderr(true, true),
            "a developer watching a terminal must still see output"
        );
        assert!(
            should_write_stderr(false, false),
            "with no file open, stderr is the only sink there is — a process \
             that cannot open its log must not fall silent"
        );
    }

    #[test]
    fn each_role_gets_its_own_file_so_two_processes_do_not_interleave() {
        // Overrides are absolute, so clear it for this check.
        std::env::remove_var("HOPS_LOG_FILE");
        let d = default_path("daemon").expect("a path");
        let g = default_path("gui").expect("a path");
        assert_ne!(
            d, g,
            "the daemon and the tray are separate processes with separate \
             lifetimes; one file makes both harder to read"
        );
        assert!(d.to_string_lossy().contains("daemon"));
    }
}

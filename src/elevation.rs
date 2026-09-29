//! hops runs as the user and is never elevated (#109).
//!
//! An administrator process started from a folder the user can write hands
//! administrator to anything that can replace the file, whichever hops
//! command it runs, and hops reads its enter hook from a config file the
//! user can write. So on Windows every hops command refuses to run in an
//! elevated process: `main` asks [`may_run`] before it opens its log or
//! parses a single argument, and a refused process touches no file. The
//! enter hook is also refused in any elevated process (`crate::enter_hook`).
//!
//! The decisions take their inputs as values, so they are tested on every
//! system; [`this_process_is_elevated`], [`this_stderr`] and
//! [`alone_on_its_console`] are the only parts that ask the OS.

use std::fmt;
use std::io::Write;

/// What hops says when it finds itself elevated, and how to put it right.
pub const RUNS_AS_THE_USER: &str = "hops is running elevated, as an administrator, and it \
     runs only as the user, never elevated: an administrator process started from a folder \
     the user can write hands administrator to anything that can replace the file. Start \
     hops from a normal PowerShell, or open it without \"Run as administrator\". If it \
     started at sign-in from the task hops 0.12 registered, remove that task as \
     service/README.md says under \"Upgrading from hops 0.12 or older\". If User Account \
     Control is turned off for your account, everything you start is elevated and hops \
     cannot run for it: use a standard account, or turn User Account Control on.";

/// Why hops did not run: this process is elevated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elevated;

impl fmt::Display for Elevated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(RUNS_AS_THE_USER)
    }
}

impl std::error::Error for Elevated {}

/// Whether hops may run in a process that is `elevated`. Anything it
/// started would be elevated too.
pub fn may_run(elevated: bool) -> Result<(), Elevated> {
    if elevated { Err(Elevated) } else { Ok(()) }
}

/// A debug build made for GitHub's Windows runners, which run every job as
/// an administrator with User Account Control off, so that the tests which
/// start hops can run there. Only the `elevated_ci_runner` feature turns it
/// on, only in a build with debug assertions, and a release build with the
/// feature does not compile. No release feature set names it
/// (`decision_guards`), and the same runner tests the refusal in a build
/// without it.
pub const ELEVATED_CI_RUNNER: bool = cfg!(all(feature = "elevated_ci_runner", debug_assertions));

#[cfg(all(feature = "elevated_ci_runner", not(debug_assertions)))]
compile_error!(
    "`elevated_ci_runner` lets hops run elevated, for Windows CI's test builds only; \
     a release build must never have it"
);

/// Whether this process is elevated in the sense hops refuses: on Windows,
/// an elevated token. Elsewhere hops runs as whoever starts it, so this is
/// `false` without asking.
pub fn refused_here() -> bool {
    cfg!(windows) && !ELEVATED_CI_RUNNER && this_process_is_elevated()
}

/// Where this process's stderr goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stderr {
    /// A console, which stays on screen only while a process shares it.
    Terminal,
    /// A file or a pipe: whoever redirected it keeps what is written.
    Redirected,
    /// No handle at all: what is written is lost.
    Nowhere,
}

/// How an elevated hops ends: its exit code, the text, and whether a
/// message box shows it as well as stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub exit_code: i32,
    pub text: String,
    pub message_box: bool,
}

/// How `refused` is reported. It always goes to stderr and the exit code is
/// always 1. On Windows it also goes in a message box whenever nothing
/// would keep stderr on screen: a console this process has to itself, as
/// from a double-click, "Run as administrator" or the tray's hidden
/// launcher, closes when it exits, and a stderr with no handle goes
/// nowhere. One redirected is kept by whoever redirected it, and a box
/// there would wait for a click nobody sees.
pub fn refusal(
    refused: &Elevated,
    on_windows: bool,
    stderr: Stderr,
    alone_on_its_console: bool,
) -> Refusal {
    let lost = match stderr {
        Stderr::Terminal => alone_on_its_console,
        Stderr::Redirected => false,
        Stderr::Nowhere => true,
    };
    Refusal {
        exit_code: 1,
        text: refused.to_string(),
        message_box: on_windows && lost,
    }
}

/// Write `refusal` to `stderr`, and to `show_box` when it asks for a box;
/// then the exit code it asks for.
pub fn tell(refusal: &Refusal, stderr: &mut impl Write, show_box: impl FnOnce(&str)) -> i32 {
    let _ = writeln!(stderr, "{}", refusal.text);
    let _ = stderr.flush();
    if refusal.message_box {
        show_box(&refusal.text);
    }
    refusal.exit_code
}

/// Report `refused` where it is seen, from this process, and return the code
/// to exit with. Creates, opens and changes no file.
pub fn refuse(refused: &Elevated) -> i32 {
    let refusal = refusal(
        refused,
        cfg!(windows),
        this_stderr(),
        alone_on_its_console(),
    );
    tell(&refusal, &mut std::io::stderr(), message_box)
}

/// Where this process's stderr goes.
pub fn this_stderr() -> Stderr {
    use std::io::IsTerminal;
    let stderr = std::io::stderr();
    if stderr.is_terminal() {
        return Stderr::Terminal;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let handle = stderr.as_raw_handle();
        // GetStdHandle's two answers for a process given no stderr.
        if handle.is_null() || handle as isize == -1 {
            return Stderr::Nowhere;
        }
    }
    Stderr::Redirected
}

/// Whether no other process shares this process's console, or it has none:
/// then no shell is left to show what it wrote once it exits.
#[cfg(windows)]
pub fn alone_on_its_console() -> bool {
    use windows::Win32::System::Console::GetConsoleProcessList;
    let mut ids = [0u32; 2];
    // SAFETY: the call writes at most `ids.len()` ids into `ids`, and
    // returns how many processes share the console, 0 when there is none.
    let sharing = unsafe { GetConsoleProcessList(&mut ids) };
    sharing <= 1
}

/// Elsewhere a terminal outlives the process that writes to it.
#[cfg(not(windows))]
pub fn alone_on_its_console() -> bool {
    false
}

/// A message box with `text`, on Windows; elsewhere there is none to show.
fn message_box(text: &str) {
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        use windows::core::HSTRING;
        // SAFETY: both strings outlive the call, and no owner window is named.
        let _ = unsafe {
            MessageBoxW(
                None,
                &HSTRING::from(text),
                &HSTRING::from("hops"),
                MB_OK | MB_ICONERROR,
            )
        };
    }
    #[cfg(not(windows))]
    let _ = text;
}

/// Whether this process runs with more privilege than the user who started
/// it: as root, or set-uid to another user.
///
/// A process whose ids cannot differ from its user's cannot be elevated, so
/// there is nothing here that can fail.
#[cfg(unix)]
pub fn this_process_is_elevated() -> bool {
    // SAFETY: both calls only read this process's credentials.
    let (effective, real) = unsafe { (libc::geteuid(), libc::getuid()) };
    effective == 0 || effective != real
}

/// Whether this process's token is elevated: started from an administrator
/// shell, or by a scheduled task with the highest run level.
///
/// When the token cannot be read the answer is yes, so hops does not run
/// with privilege nobody checked.
#[cfg(windows)]
pub fn this_process_is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle GetCurrentProcess returns needs no closing,
    // and `token` is written only when the call succeeds.
    if let Err(e) = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } {
        log::warn!("could not open this process's token ({e}); treating it as elevated");
        return true;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut written = 0u32;
    // SAFETY: `elevation` is a TOKEN_ELEVATION and the length passed is its size.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut written,
        )
    };
    // SAFETY: `token` was opened above and is closed once.
    let _ = unsafe { CloseHandle(token) };
    match read {
        Ok(()) => elevation.TokenIsElevated != 0,
        Err(e) => {
            log::warn!(
                "could not read whether this process is elevated ({e}); treating it \
                 as elevated"
            );
            true
        }
    }
}

/// Whether this process is elevated, as the operating system's own tools
/// report it.
#[cfg(test)]
pub(crate) fn elevated_by_the_os() -> bool {
    #[cfg(unix)]
    {
        let id = |flags: &[&str]| {
            let out = std::process::Command::new("id")
                .args(flags)
                .output()
                .expect("id runs");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let (effective, real) = (id(&["-u"]), id(&["-r", "-u"]));
        effective == "0" || effective != real
    }
    #[cfg(windows)]
    {
        // High and System mandatory levels: an elevated token has one.
        let out = std::process::Command::new("whoami")
            .arg("/groups")
            .output()
            .expect("whoami runs");
        let groups = String::from_utf8_lossy(&out.stdout);
        groups.contains("S-1-16-12288") || groups.contains("S-1-16-16384")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // LEDGER T66 | class B | 1 return value / error
    #[test]
    fn this_process_is_elevated_agrees_with_the_os() {
        assert_eq!(
            this_process_is_elevated(),
            elevated_by_the_os(),
            "hops and the operating system disagree about whether this process is \
             elevated. Wrong one way, an elevated hops runs its daemon and enter \
             hook; wrong the other, neither runs for anyone."
        );
    }

    /// Set by the Windows CI step that runs these tests elevated in a build
    /// without `elevated_ci_runner`, so that a runner which stopped being
    /// elevated fails the step instead of proving nothing. Tests read it;
    /// hops never does.
    const RUNNER_IS_ELEVATED: &str = "HOPS_TEST_RUNNER_IS_ELEVATED";

    // LEDGER T1095 | class B | 1 return value: refused_here
    #[test]
    fn hops_refuses_exactly_an_elevated_windows_process() {
        if std::env::var_os(RUNNER_IS_ELEVATED).is_some() {
            assert!(
                cfg!(windows) && elevated_by_the_os() && !ELEVATED_CI_RUNNER,
                "{RUNNER_IS_ELEVATED} says this run tests the refusal on an elevated \
                 Windows runner, in a build without `elevated_ci_runner`, and it is \
                 not one: windows {}, elevated {}, test build {}",
                cfg!(windows),
                elevated_by_the_os(),
                ELEVATED_CI_RUNNER
            );
        }
        assert_eq!(
            refused_here(),
            cfg!(windows) && !ELEVATED_CI_RUNNER && elevated_by_the_os(),
            "hops would refuse to run where it may, or run elevated on Windows"
        );
    }

    // LEDGER T1096 | class B | 1 return value: refusal, over every input
    #[test]
    fn a_refusal_exits_1_and_shows_a_box_where_nothing_keeps_stderr() {
        for on_windows in [false, true] {
            for stderr in [Stderr::Terminal, Stderr::Redirected, Stderr::Nowhere] {
                for alone in [false, true] {
                    let got = refusal(&Elevated, on_windows, stderr, alone);
                    let lost = match stderr {
                        Stderr::Terminal => alone,
                        Stderr::Redirected => false,
                        Stderr::Nowhere => true,
                    };
                    assert_eq!(
                        got,
                        Refusal {
                            exit_code: 1,
                            text: RUNS_AS_THE_USER.to_string(),
                            message_box: on_windows && lost,
                        },
                        "windows {on_windows}, stderr {stderr:?}, alone on its console \
                         {alone}. A refusal exits 1 with the fix; on Windows it is also \
                         in a box when its console closes with it or stderr goes \
                         nowhere, and never where a box would wait on a script"
                    );
                }
            }
        }
        // The cases that were silent: a double-click, "Run as administrator"
        // and the tray's hidden launcher each give hops a console of its own.
        assert!(
            refusal(&Elevated, true, Stderr::Terminal, true).message_box,
            "an elevated hops with a console of its own ends without a word on \
             screen: the console closes with it"
        );
    }

    // LEDGER T1097 | class B | 1 bytes written + whether a box was asked for + code
    #[test]
    fn a_refusal_is_written_to_stderr_and_to_a_box_when_it_asks() {
        for message_box in [false, true] {
            let refusal = Refusal {
                exit_code: 1,
                text: RUNS_AS_THE_USER.to_string(),
                message_box,
            };
            let mut stderr = Vec::new();
            let mut boxed = None;
            let code = tell(&refusal, &mut stderr, |text| boxed = Some(text.to_string()));
            let written = String::from_utf8_lossy(&stderr);
            assert!(
                code == 1
                    && written.trim_end() == RUNS_AS_THE_USER
                    && boxed.as_deref() == message_box.then_some(RUNS_AS_THE_USER),
                "a refusal must exit 1, always write its text to stderr, and show \
                 it in a box exactly when asked: code {code}, stderr {written:?}, \
                 box {boxed:?}"
            );
        }
    }

    // LEDGER T1091 | class B | 1 return value / error: may_run
    #[test]
    fn hops_runs_only_in_a_process_that_is_not_elevated() {
        assert_eq!(
            (may_run(true), may_run(false)),
            (Err(Elevated), Ok(())),
            "hops runs as the user and is never elevated (#109)"
        );
        let said = Elevated.to_string();
        for needed in [
            "never elevated",
            "normal PowerShell",
            "hops 0.12",
            "service/README.md",
            "User Account Control is turned off",
            "use a standard account, or turn User Account Control on",
        ] {
            assert!(
                said.contains(needed),
                "the refusal does not say `{needed}`, so it does not say what \
                 to do: {said}"
            );
        }
    }
}

//! hops runs as the user and is never elevated (#109).
//!
//! An administrator process started from a folder the user can write hands
//! administrator to anything that can replace the file, whichever hops
//! command it runs, and hops reads its enter hook from a config file the
//! user can write. So on Windows every hops command refuses to run in an
//! elevated process: `main` asks [`may_run`] before it parses a single
//! argument. The enter hook is also refused in any elevated process
//! (`crate::enter_hook`).
//!
//! The decision takes `elevated` as a value, so it is tested on every
//! system; [`this_process_is_elevated`] is the only part that asks the OS.

use std::fmt;

/// What hops says when it finds itself elevated, and how to put it right.
pub const RUNS_AS_THE_USER: &str = "hops is running elevated, as an administrator, and it \
     runs only as the user, never elevated: an administrator process started from a folder \
     the user can write hands administrator to anything that can replace the file. Start \
     hops from a normal PowerShell, or open it without \"Run as administrator\". If it \
     started at sign-in from the task hops 0.12 registered, remove that task as \
     service/README.md says under \"Upgrading from hops 0.12 or older\".";

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

/// Whether this process is elevated in the sense hops refuses: on Windows,
/// an elevated token. Elsewhere hops runs as whoever starts it, so this is
/// `false` without asking.
pub fn refused_here() -> bool {
    cfg!(windows) && this_process_is_elevated()
}

/// Show `refused` where it is seen. At a terminal the log has already put it
/// on stderr; with none, as for the tray or a task at sign-in, it goes in a
/// message box on Windows, so hops never ends without a word.
pub fn tell(refused: &Elevated) {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        return;
    }
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        use windows::core::HSTRING;
        // SAFETY: both strings outlive the call, and no owner window is named.
        let _ = unsafe {
            MessageBoxW(
                None,
                &HSTRING::from(refused.to_string()),
                &HSTRING::from("hops"),
                MB_OK | MB_ICONERROR,
            )
        };
    }
    #[cfg(not(windows))]
    eprintln!("{refused}");
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

    // LEDGER T1095 | class B | 1 return value: refused_here
    #[test]
    fn hops_refuses_exactly_an_elevated_windows_process() {
        assert_eq!(
            refused_here(),
            cfg!(windows) && elevated_by_the_os(),
            "hops would refuse to run where it may, or run elevated on Windows"
        );
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
        ] {
            assert!(
                said.contains(needed),
                "the refusal does not say `{needed}`, so it does not say what \
                 to do: {said}"
            );
        }
    }
}

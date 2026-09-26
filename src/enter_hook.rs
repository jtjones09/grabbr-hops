//! The enter hook: a command from `config.toml` that runs each time the
//! pointer crosses onto a device.
//!
//! # It runs as the user, and never with more (#109)
//!
//! The daemon runs as the user on every platform, and nothing in this
//! repository installs it elevated. If it is elevated anyway, started from an
//! administrator shell on Windows or as root or set-uid on Unix, the hook is
//! refused rather than run. Its command comes from a file the user can write,
//! so running it elevated would let any process of that user run a program
//! with privilege the user does not have.
//!
//! # It is a program and its arguments, not a shell command (#108)
//!
//! Pipes, `;`, `&&`, globs and variables are not interpreted. A hook that
//! needs them names a shell itself, as in `sh -c '...'`.
//!
//! * On Unix the line is split into words the way a POSIX shell splits them,
//!   so quotes and backslashes group and escape as they would there.
//! * On Windows the first word, in double quotes if it holds a space, is the
//!   program, and the rest of the line is handed to it unchanged: Windows
//!   programs split their own command lines.
//!
//! This module only says what to run. The process is started in
//! `Service::spawn_hook_command`, the one place the guard for #56 watches.

use std::fmt;

/// Why the enter hook was not run.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// This process runs with more privilege than the user's.
    Elevated,
    /// The hook names no program.
    Empty,
    /// A quote in the hook is not closed.
    Unbalanced,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Elevated => {
                "hops is running as an administrator or root, and the enter hook \
                 runs only with the user's own privilege"
            }
            Self::Empty => "it names no program",
            Self::Unbalanced => "a quote in it is not closed",
        })
    }
}

/// What an enter hook runs: a program, and what it is given.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Invocation {
    pub(crate) program: String,
    /// The arguments, one word each.
    #[cfg(unix)]
    pub(crate) args: Vec<String>,
    /// The rest of the line, to hand to the program unchanged.
    #[cfg(windows)]
    pub(crate) rest: String,
}

/// What the enter hook `line` runs in this process, or why it may not run.
pub(crate) fn invocation(line: &str) -> Result<Invocation, Refused> {
    invocation_as(line, this_process_is_elevated())
}

/// [`invocation`], for a process that is `elevated` or not.
fn invocation_as(line: &str, elevated: bool) -> Result<Invocation, Refused> {
    if elevated {
        return Err(Refused::Elevated);
    }
    #[cfg(unix)]
    {
        let mut words = shlex::split(line).ok_or(Refused::Unbalanced)?;
        if words.is_empty() {
            return Err(Refused::Empty);
        }
        let program = words.remove(0);
        Ok(Invocation {
            program,
            args: words,
        })
    }
    #[cfg(windows)]
    {
        let (program, rest) = split_program(line)?;
        Ok(Invocation {
            program: program.to_string(),
            rest: rest.to_string(),
        })
    }
}

/// The program a Windows command line names, and the rest of the line.
///
/// The program is read as Windows reads it: up to the closing quote when the
/// line starts with one, and otherwise up to the first space or tab. Nothing
/// else is interpreted.
#[cfg(any(windows, test))]
fn split_program(line: &str) -> Result<(&str, &str), Refused> {
    const BLANK: [char; 2] = [' ', '\t'];
    let line = line.trim_start_matches(BLANK);
    let (program, rest) = match line.strip_prefix('"') {
        Some(quoted) => {
            let end = quoted.find('"').ok_or(Refused::Unbalanced)?;
            (&quoted[..end], &quoted[end + 1..])
        }
        None => line.split_at(line.find(BLANK).unwrap_or(line.len())),
    };
    if program.is_empty() {
        return Err(Refused::Empty);
    }
    Ok((program, rest.trim_start_matches(BLANK)))
}

/// Whether this process runs with more privilege than the user who started
/// it: as root, or set-uid to another user.
///
/// A process whose ids cannot differ from its user's cannot be elevated, so
/// there is nothing here that can fail.
#[cfg(unix)]
pub(crate) fn this_process_is_elevated() -> bool {
    // SAFETY: both calls only read this process's credentials.
    let (effective, real) = unsafe { (libc::geteuid(), libc::getuid()) };
    effective == 0 || effective != real
}

/// Whether this process's token is elevated: started from an administrator
/// shell, or by a scheduled task with the highest run level.
///
/// When the token cannot be read the answer is yes, so the hook is refused
/// rather than run with privilege nobody checked.
#[cfg(windows)]
pub(crate) fn this_process_is_elevated() -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether this process is elevated, as the operating system's own tools
    /// report it.
    fn elevated_by_the_os() -> bool {
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

    // LEDGER T65 | class B | 1 return value / error
    #[test]
    fn an_elevated_process_runs_no_hook() {
        let hook = "hops-hook-that-must-not-run --now";
        assert_eq!(
            invocation_as(hook, true),
            Err(Refused::Elevated),
            "an elevated hops would run its enter hook. The hook comes from a file \
             the user can write, so any process of that user could run a program as \
             an administrator or root."
        );
        assert!(
            invocation_as(hook, false).is_ok(),
            "a hook was refused in a process that is not elevated"
        );
    }

    // LEDGER T66 | class B | 1 return value / error
    #[test]
    fn this_process_is_elevated_agrees_with_the_os() {
        assert_eq!(
            this_process_is_elevated(),
            elevated_by_the_os(),
            "hops and the operating system disagree about whether this process is \
             elevated. Wrong one way, an elevated hops runs the enter hook; wrong \
             the other, the hook never runs for anyone."
        );
    }

    // LEDGER T67 | class B | 1 return value / error
    #[test]
    fn the_hook_this_process_would_run_is_refused_exactly_when_it_is_elevated() {
        let elevated = elevated_by_the_os();
        let got = invocation("hops-hook-that-must-not-run --now");
        assert_eq!(
            got.as_ref().err(),
            elevated.then_some(&Refused::Elevated),
            "this process is {}elevated, and the enter hook was {}",
            if elevated { "" } else { "not " },
            if got.is_ok() { "allowed" } else { "refused" }
        );
    }

    // LEDGER T68 | class B | 1 return value / error
    #[test]
    fn a_windows_hook_names_its_program_and_hands_on_the_rest_unchanged() {
        let cases = [
            (
                r#""C:\Program Files\tool\hook.exe" --a "b c""#,
                Ok((r"C:\Program Files\tool\hook.exe", r#"--a "b c""#)),
            ),
            (
                r"C:\tools\hook.exe  arg\with\slashes",
                Ok((r"C:\tools\hook.exe", r"arg\with\slashes")),
            ),
            ("  hook.exe", Ok(("hook.exe", ""))),
            (
                r#""C:\Program Files\hook.exe --a"#,
                Err(Refused::Unbalanced),
            ),
            ("   ", Err(Refused::Empty)),
            (r#""" --a"#, Err(Refused::Empty)),
        ];
        for (line, expected) in cases {
            assert_eq!(split_program(line), expected, "for the hook {line:?}");
        }
    }
}

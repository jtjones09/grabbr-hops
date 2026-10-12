//! The console Windows gives hops when it is opened from Explorer (#247).
//!
//! hops.exe is one console program for the GUI, the terminal UI, the CLI and
//! the daemon, so Windows gives it a console of its own whenever it starts
//! outside one: opened from Explorer, the Start menu or a shortcut, a
//! terminal window stood beside the app for as long as it ran, and closing
//! it ended hops. Before the GUI opens, hops lets go of a console no other
//! process shares. One shared with the shell it was started from stays, so
//! what it prints still reaches that shell, and the terminal UI and the CLI
//! always keep theirs.
//!
//! [`releases_console`] takes its inputs as values, so it is tested on every
//! system; [`release_if_alone`] is the only part that asks the OS.

/// What this process is about to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runs {
    /// The window: it needs no console.
    Gui,
    /// The terminal UI, which draws in the console.
    Tui,
    /// A command that prints its answer to the console.
    Cli,
}

/// Whether a process about to run `runs` lets go of its console, when
/// `sharing` processes are attached to that console, this one included, and
/// 0 when it has none.
///
/// Only the GUI does, and only from a console it has to itself: the one
/// Windows made for it, which nothing else would ever write to. A console
/// shared with a shell belongs to the shell.
pub fn releases_console(runs: Runs, sharing: u32) -> bool {
    runs == Runs::Gui && sharing == 1
}

/// Let go of this process's console when it is about to run `runs` and no
/// other process shares that console, so the window it opens is the only one
/// on screen. Returns whether it did. Elsewhere than Windows a terminal is
/// never created for a process, so this does nothing.
///
/// Its standard handles that were the console are set to none, so a later
/// write to stdout or stderr, such as a log line, is dropped rather than
/// sent to a console this process no longer has. Rust's standard library
/// treats a missing handle as a write that succeeded.
pub fn release_if_alone(runs: Runs) -> bool {
    #[cfg(windows)]
    {
        release_on_windows(runs)
    }
    #[cfg(not(windows))]
    {
        let _ = runs;
        false
    }
}

#[cfg(windows)]
fn release_on_windows(runs: Runs) -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::{
        CONSOLE_MODE, FreeConsole, GetConsoleMode, GetConsoleProcessList, GetStdHandle,
        STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
    };

    let mut ids = [0u32; 2];
    // SAFETY: the call writes at most `ids.len()` ids into `ids`, and returns
    // how many processes share the console, 0 when there is none.
    let sharing = unsafe { GetConsoleProcessList(&mut ids) };
    if !releases_console(runs, sharing) {
        return false;
    }
    // Which standard handles are the console, asked while it is still
    // attached. One redirected to a file or a pipe is left as it is.
    let on_the_console: Vec<_> = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
        .into_iter()
        .filter(|&which| {
            // SAFETY: both calls only read; `mode` outlives the second.
            unsafe { GetStdHandle(which) }.is_ok_and(|handle| {
                let mut mode = CONSOLE_MODE::default();
                unsafe { GetConsoleMode(handle, &mut mode) }.is_ok()
            })
        })
        .collect();
    // SAFETY: detaches this process from its console; nothing of hops holds
    // a console handle past this point but the standard ones reset below.
    if let Err(e) = unsafe { FreeConsole() } {
        log::warn!("could not close the terminal window opened with hops ({e})");
        return false;
    }
    for which in on_the_console {
        // SAFETY: a null handle is what GetStdHandle returns for a process
        // given no such handle.
        let _ = unsafe { SetStdHandle(which, HANDLE::default()) };
    }
    log::info!("let go of the console Windows opened with hops; the log continues in this file");
    true
}

#[cfg(test)]
mod a_gui_opened_alone_closes_its_terminal {
    use super::{Runs, releases_console};

    // LEDGER T2470 | class B | 1 return value of releases_console
    #[test]
    fn only_the_gui_lets_go_and_only_of_a_console_it_has_to_itself() {
        assert!(
            releases_console(Runs::Gui, 1),
            "the GUI opened from Explorer keeps the terminal window Windows made for \
             it, and closing that window ends hops (#247)"
        );
        for (runs, sharing) in [
            (Runs::Gui, 0),
            (Runs::Gui, 2),
            (Runs::Gui, 5),
            (Runs::Tui, 0),
            (Runs::Tui, 1),
            (Runs::Tui, 2),
            (Runs::Cli, 0),
            (Runs::Cli, 1),
            (Runs::Cli, 2),
        ] {
            assert!(
                !releases_console(runs, sharing),
                "{runs:?} on a console {sharing} processes share lets go of it: a \
                 shell started from loses what hops prints, and the terminal UI or a \
                 command has nowhere to draw or answer"
            );
        }
    }
}

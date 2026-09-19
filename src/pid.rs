//! Whether a process is gone, by its id.

/// Whether no process with id `pid` is running. `false` when one is, when the
/// answer is unknown, and for an id that cannot name a process.
///
/// On Unix a process that has exited but has not been reaped by its parent
/// still counts as running. On Windows a process that has exited counts as
/// gone even while a handle keeps its id.
pub(crate) fn is_gone(pid: u32) -> bool {
    if pid == 0 {
        // Not a process of anyone's: a process group on Unix, the idle
        // process on Windows.
        return false;
    }
    #[cfg(unix)]
    {
        // `kill` treats negative ids as process groups too.
        let Ok(id) = libc::pid_t::try_from(pid) else {
            return false;
        };
        // SAFETY: signal 0 sends nothing; it only checks that `id` exists.
        let sent = unsafe { libc::kill(id, 0) };
        sent == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, STILL_ACTIVE};
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: OpenProcess takes plain values and returns an owned handle,
        // which is closed below.
        match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            // No process has this id. Any other refusal, such as access
            // denied for another user's process, leaves the answer unknown.
            Err(e) => e.code() == ERROR_INVALID_PARAMETER.to_hresult(),
            Ok(handle) => {
                let mut code = 0u32;
                // SAFETY: `handle` is open and `code` outlives the call.
                let read = unsafe { GetExitCodeProcess(handle, &mut code) };
                // SAFETY: `handle` is open and closed once, here.
                let _ = unsafe { CloseHandle(handle) };
                read.is_ok() && code != STILL_ACTIVE.0 as u32
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(test)]
pub(crate) mod processes {
    //! Process ids for tests: one that is running, and one that is gone.

    use std::process::{Child, Command, Stdio};

    /// A process that runs until its stdin closes.
    pub(crate) fn waiting() -> Child {
        // Both read their input to the end before exiting.
        #[cfg(unix)]
        let program = "cat";
        #[cfg(windows)]
        let program = "sort";
        Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("a process that waits on its input")
    }

    /// End `child` and reap it.
    pub(crate) fn finish(mut child: Child) {
        drop(child.stdin.take());
        let _ = child.wait();
    }

    /// The id of a process that has exited and been reaped.
    pub(crate) fn gone() -> u32 {
        let child = waiting();
        let pid = child.id();
        finish(child);
        pid
    }
}

#[cfg(test)]
mod tests {
    use super::{is_gone, processes};

    // LEDGER T31 | class B | 1 return value for real processes
    #[test]
    fn only_a_process_that_has_ended_is_gone() {
        let running = processes::waiting();
        let live = running.id();
        let was_live = is_gone(live);
        processes::finish(running);
        let gone = processes::gone();
        assert_eq!(
            (
                was_live,
                is_gone(gone),
                is_gone(std::process::id()),
                is_gone(0)
            ),
            (false, true, false, false),
            "(running child, reaped child, this process, id 0). A process that is \
             running must never count as gone: what is left behind in its name \
             would be removed while it still writes it."
        );
    }
}

//! Where hops writes its logs, on each platform.
//!
//! One definition, for every file hops logs to: the daemon's and the
//! frontends' logs (`src/logging.rs`) and the keystroke log ([`crate::keylog`]).
//! It lives here because this is the lowest crate both reach. A per-OS policy
//! copied into each place that needs it drifts: the keystroke log once wrote
//! to `~/hops/logs` on every platform while the rest of hops logged to the
//! platform's own log directory.

use std::path::PathBuf;

/// The directory hops writes its logs to:
///
/// - macOS: `~/Library/Logs/hops`
/// - Windows: `%LOCALAPPDATA%\hops\logs`
/// - Linux and the rest: `$XDG_STATE_HOME/hops`, or `~/.local/state/hops`
///   when `XDG_STATE_HOME` is not set
///
/// `None` when the variable the directory comes from is not set. Nothing is
/// created; the caller creates the directory when it writes there.
pub fn log_dir() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).map(PathBuf::from);
    if cfg!(target_os = "macos") {
        Some(var("HOME")?.join("Library").join("Logs").join("hops"))
    } else if cfg!(windows) {
        Some(var("LOCALAPPDATA")?.join("hops").join("logs"))
    } else {
        // $XDG_STATE_HOME is where logs belong on Linux; $HOME/.local/state is
        // its documented default.
        let state = match var("XDG_STATE_HOME") {
            Some(state) => state,
            None => var("HOME")?.join(".local").join("state"),
        };
        Some(state.join("hops"))
    }
}

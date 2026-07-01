//! UI-local preferences shared across front-ends (never sent over IPC).
//!
//! These live next to the config (`~/.config/lan-mouse/`) and record the user's
//! choices the daemon doesn't care about — which front-end to open, and whether
//! first-run onboarding has completed. The `hops` launcher reads these to decide
//! what to show; the GUI/TUI write them (onboarding, Settings, switch-on-the-fly).

use std::path::PathBuf;

/// Which front-end the user prefers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frontend {
    Gui,
    Tui,
}

impl Frontend {
    pub fn as_str(self) -> &'static str {
        match self {
            Frontend::Gui => "gui",
            Frontend::Tui => "tui",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "gui" => Some(Frontend::Gui),
            "tui" => Some(Frontend::Tui),
            _ => None,
        }
    }
}

fn pref_path(name: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut p = PathBuf::from(home);
    p.push(".config/lan-mouse");
    p.push(name);
    Some(p)
}

fn write_pref(name: &str, value: &str) {
    if let Some(p) = pref_path(name) {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(p, value);
    }
}

fn read_pref(name: &str) -> Option<String> {
    let s = std::fs::read_to_string(pref_path(name)?).ok()?;
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The persisted front-end choice, if the user has made one.
pub fn load_frontend() -> Option<Frontend> {
    read_pref("frontend").as_deref().and_then(Frontend::parse)
}

/// Persist the front-end choice (best-effort).
pub fn save_frontend(frontend: Frontend) {
    write_pref("frontend", frontend.as_str());
}

/// Whether first-run onboarding has been completed.
pub fn onboarding_done() -> bool {
    read_pref("onboarded").as_deref() == Some("1")
}

/// Mark first-run onboarding complete (best-effort).
pub fn set_onboarding_done() {
    write_pref("onboarded", "1");
}

/// Persist `target` as the preferred front-end, then EXEC-REPLACE this process
/// with `hops <target>` — the current process image becomes the other front-end
/// in place (same PID; a controlling terminal, if any, carries straight over to
/// the TUI), so switching is instant with no separate process to spawn or clean
/// up. Only ever returns on FAILURE: a successful `exec` never returns, so the
/// caller should surface the error rather than assume anything continued.
///
/// If the caller is a TUI holding the terminal in raw mode, it must restore the
/// terminal (e.g. `ratatui::restore()`) BEFORE calling this — exec doesn't run
/// any of the old process's cleanup code, so a still-raw terminal would carry
/// over broken into whatever comes next.
#[cfg(unix)]
pub fn switch_to(target: Frontend) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    save_frontend(target);
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return e,
    };
    std::process::Command::new(exe).arg(target.as_str()).exec()
}

#[cfg(not(unix))]
pub fn switch_to(target: Frontend) -> std::io::Error {
    save_frontend(target);
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "switching interfaces on the fly isn't supported on this platform — restart manually",
    )
}

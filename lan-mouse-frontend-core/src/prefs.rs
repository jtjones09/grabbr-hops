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

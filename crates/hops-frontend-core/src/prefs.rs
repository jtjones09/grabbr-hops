//! UI-local preferences shared across front-ends (never sent over IPC).
//!
//! These live next to the config (`~/.config/lan-mouse/`) and record the user's
//! choices the daemon doesn't care about — which front-end to open, and whether
//! first-run onboarding has completed. The `hops` launcher reads these to decide
//! what to show; the GUI/TUI write them (onboarding, Settings, switch-on-the-fly).

use std::{ffi::OsString, path::PathBuf};

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

/// Whether this platform can switch between the two front-ends in place.
/// Only a Unix `exec` replaces the process; elsewhere [`switch_to`] saves the
/// choice and fails, so no front-end offers the switch there (#173).
pub const CAN_SWITCH: bool = cfg!(unix);

/// The directory UI preferences live in, beside `config.toml`, or `None`
/// when the environment names none.
///
/// On Windows it is under `LOCALAPPDATA`, else `USERPROFILE`, as the config
/// is. Preferences were built from `HOME` alone, which a Start-menu launch
/// does not set there, so nothing was saved: not the front-end, not the
/// theme, not that onboarding was done (#173).
pub fn ui_dir() -> Option<PathBuf> {
    ui_dir_with(cfg!(windows), |name| std::env::var_os(name))
}

/// The directory the state directory sits in: `LOCALAPPDATA` (else
/// `USERPROFILE/.config`) on Windows, `HOME/.config` elsewhere.
pub fn config_base() -> Option<PathBuf> {
    config_base_with(cfg!(windows), |name| std::env::var_os(name))
}

/// [`ui_dir`] for Windows or not, reading the environment through `var`.
fn ui_dir_with(windows: bool, var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    Some(config_base_with(windows, var)?.join("lan-mouse"))
}

fn config_base_with(windows: bool, var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let set = |name: &str| var(name).filter(|v| !v.is_empty());
    if windows {
        return match set("LOCALAPPDATA") {
            Some(app_data) => Some(PathBuf::from(app_data)),
            None => Some(PathBuf::from(set("USERPROFILE")?).join(".config")),
        };
    }
    Some(PathBuf::from(set("HOME")?).join(".config"))
}

fn pref_path(name: &str) -> Option<PathBuf> {
    Some(ui_dir()?.join(name))
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

#[cfg(test)]
mod where_preferences_live {
    //! UI preferences resolve on Windows without `HOME` (#173).
    use super::ui_dir_with;
    use std::{ffi::OsString, path::PathBuf};

    fn env<'a>(vars: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    // LEDGER T528 | class B | 1 return value: prefs::ui_dir_with
    #[test]
    fn windows_preferences_sit_beside_the_config_without_home() {
        assert_eq!(
            ui_dir_with(true, env(&[("LOCALAPPDATA", "C:/Users/u/AppData/Local")])),
            Some(PathBuf::from("C:/Users/u/AppData/Local").join("lan-mouse")),
            "with HOME unset, as from the Start menu, preferences had nowhere to go"
        );
        assert_eq!(
            ui_dir_with(true, env(&[("USERPROFILE", "C:/Users/u")])),
            Some(
                PathBuf::from("C:/Users/u")
                    .join(".config")
                    .join("lan-mouse")
            ),
        );
        assert_eq!(
            ui_dir_with(
                true,
                env(&[("HOME", "/h"), ("LOCALAPPDATA", "C:/Users/u/AppData/Local")])
            ),
            Some(PathBuf::from("C:/Users/u/AppData/Local").join("lan-mouse")),
            "a HOME set by a Unix-style shell moved the preferences away from the config"
        );
        assert_eq!(ui_dir_with(true, env(&[("LOCALAPPDATA", "")])), None);
    }

    // LEDGER T529 | class B | 1 return value: prefs::ui_dir_with
    #[test]
    fn elsewhere_preferences_stay_under_home() {
        assert_eq!(
            ui_dir_with(false, env(&[("HOME", "/home/u")])),
            Some(PathBuf::from("/home/u/.config/lan-mouse"))
        );
        assert_eq!(ui_dir_with(false, env(&[("LOCALAPPDATA", "C:/x")])), None);
    }
}

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

/// Where UI preferences were kept on Windows before they moved beside the
/// config: under `HOME`, which only a Unix-style shell sets there. `None`
/// where nothing moved.
fn legacy_ui_dir_with(windows: bool, var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    if !windows {
        return None;
    }
    let home = var("HOME").filter(|v| !v.is_empty())?;
    let old = PathBuf::from(home).join(".config").join("lan-mouse");
    (ui_dir_with(windows, var).as_ref() != Some(&old)).then_some(old)
}

/// The UI preference `name` to read: where it is kept now, else where it
/// was kept before the move, so a user who ran hops from such a shell does
/// not see onboarding again or lose a theme (#173). Written only to the
/// current place, which then wins.
pub(crate) fn readable(name: &str) -> Option<PathBuf> {
    let windows = cfg!(windows);
    let var = |name: &str| std::env::var_os(name);
    readable_in(
        ui_dir_with(windows, var),
        legacy_ui_dir_with(windows, var),
        name,
    )
}

/// [`readable`] given the current and the previous directory.
fn readable_in(current: Option<PathBuf>, legacy: Option<PathBuf>, name: &str) -> Option<PathBuf> {
    let current = current.map(|d| d.join(name));
    if current.as_ref().is_some_and(|p| p.exists()) {
        return current;
    }
    legacy
        .map(|d| d.join(name))
        .filter(|p| p.exists())
        .or(current)
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
    let s = std::fs::read_to_string(readable(name)?).ok()?;
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
    use super::{legacy_ui_dir_with, readable_in, ui_dir_with};
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

    // LEDGER T534 | class B | 1 return value: prefs::legacy_ui_dir_with
    #[test]
    fn the_old_windows_place_is_known_only_where_preferences_moved() {
        assert_eq!(
            legacy_ui_dir_with(
                true,
                env(&[
                    ("HOME", "C:/h"),
                    ("LOCALAPPDATA", "C:/Users/u/AppData/Local")
                ])
            ),
            Some(PathBuf::from("C:/h").join(".config").join("lan-mouse")),
            "preferences kept under HOME by an earlier build were not looked for"
        );
        assert_eq!(
            legacy_ui_dir_with(true, env(&[("HOME", "C:/u"), ("USERPROFILE", "C:/u")])),
            None,
            "the place preferences are kept now was taken for an old one"
        );
        assert_eq!(
            legacy_ui_dir_with(true, env(&[("LOCALAPPDATA", "C:/x")])),
            None
        );
        assert_eq!(legacy_ui_dir_with(false, env(&[("HOME", "/home/u")])), None);
    }

    // LEDGER T535 | class B | 1 return value + 4 file on disk: prefs::readable_in over a temp dir
    #[test]
    fn a_preference_only_the_old_place_has_is_still_read() {
        let root = std::env::temp_dir().join(format!(
            "hops-prefs-readable-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let (now, old) = (root.join("now"), root.join("old"));
        std::fs::create_dir_all(&now).expect("temp dir");
        std::fs::create_dir_all(&old).expect("temp dir");
        std::fs::write(old.join("onboarded"), "1").expect("write");

        let read = |name: &str| readable_in(Some(now.clone()), Some(old.clone()), name);
        assert_eq!(
            read("onboarded"),
            Some(old.join("onboarded")),
            "a preference only the old place has was ignored: onboarding \
             again, and the theme lost"
        );
        std::fs::write(now.join("onboarded"), "1").expect("write");
        assert_eq!(
            read("onboarded"),
            Some(now.join("onboarded")),
            "the old place outranked what was written since"
        );
        assert_eq!(
            read("tui-theme"),
            Some(now.join("tui-theme")),
            "a preference neither place has must name the current place"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

//! Keystroke logging: opt-in, time-boxed, and in its own file.
//!
//! hops needs this. Scancode mapping is not debuggable without key identity —
//! the Linux↔Windows table has measured wrong entries, and Caps Lock repeat and
//! modifier coherence both required seeing exactly which key arrived.
//!
//! What it must never be is a side effect of turning up the log level. Before
//! this existed, `HOPS_LOG_LEVEL=debug` — set to look at a handshake, a dial, a
//! config reload — wrote every key pressed on the machine to the ordinary daemon
//! log in cleartext. The dev launcher on the Windows box had it on since
//! 2026-07-21; the resulting file was **4.4 GB** and contained readable
//! sentences. Nobody choosing `debug` for a connection problem consented to that
//! (issue #117).
//!
//! It also sat badly beside #48, where the installer instruction that granted
//! users system-wide keylogging was removed on the grounds that hops does not
//! need that capability.
//!
//! Three properties, all structural:
//!
//! 1. **Compiled out by default.** Without the `keylog` cargo feature — absent
//!    from every release feature set — the recording code is not in the binary.
//! 2. **Time-boxed, never unlimited.** `HOPS_LOG_KEYS` takes a duration, not a
//!    boolean. There is no "on until you remember to turn it off", which is the
//!    state the 4.4 GB file represents.
//! 3. **Its own file.** Keystrokes never enter the general log, so a daemon log
//!    stays shareable. You cannot hand anyone a debug log today without handing
//!    them your typing.

use std::time::Duration;

/// Longest a single arming may last. Beyond this, re-arm deliberately.
pub const MAX_DURATION: Duration = Duration::from_secs(60 * 60);

/// Parse a duration like `30s`, `10m`, `1h`. Bare digits are seconds.
///
/// Returns `None` for anything unparseable — including `1`, `true`, `yes` and
/// the empty string, all of which a boolean-shaped flag would have accepted.
/// That is deliberate: `HOPS_LOG_KEYS=1` reads like "on" and must not silently
/// mean "on for one second" either.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (digits, mult) = match s.as_bytes()[s.len() - 1] {
        b's' => (&s[..s.len() - 1], 1),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        b'0'..=b'9' => (s, 1),
        _ => return None,
    };
    let n: u64 = digits.parse().ok()?;
    if n == 0 {
        return None;
    }
    Some(Duration::from_secs(n.saturating_mul(mult)).min(MAX_DURATION))
}

#[cfg(feature = "keylog")]
mod armed {
    use super::{MAX_DURATION, parse_duration};
    use std::cell::RefCell;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    thread_local! {
        static SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
        static CHECKED: RefCell<bool> = const { RefCell::new(false) };
    }

    struct Sink {
        file: File,
        until: Instant,
        path: PathBuf,
        expired: bool,
    }

    fn log_path() -> PathBuf {
        let mut p = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        p.push("hops/logs");
        let _ = std::fs::create_dir_all(&p);
        p.push("keystrokes.log");
        p
    }

    #[cfg(unix)]
    fn create_private(path: &std::path::Path) -> std::io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
    }

    #[cfg(not(unix))]
    fn create_private(path: &std::path::Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    }

    fn arm() -> Option<Sink> {
        let raw = std::env::var("HOPS_LOG_KEYS").ok()?;
        let Some(d) = parse_duration(&raw) else {
            log::warn!(
                "HOPS_LOG_KEYS={raw:?} is not a duration — keystroke logging stays OFF. \
                 Use 30s, 10m or 1h (max {MAX_DURATION:?}). It is deliberately not a \
                 boolean: there is no unlimited mode."
            );
            return None;
        };
        let path = log_path();
        let file = match create_private(&path) {
            Ok(f) => f,
            Err(e) => {
                log::error!("keystroke logging requested but {path:?} could not be opened: {e}");
                return None;
            }
        };
        log::warn!(
            "KEYSTROKE LOGGING IS ON for {d:?}. Every key pressed on this machine is \
             being written in cleartext to {path:?}. It stops by itself when the time \
             is up. Delete that file when you are done with it."
        );
        Some(Sink {
            file,
            until: Instant::now() + d,
            path,
            expired: false,
        })
    }

    /// Record one key event, if armed and not yet expired.
    pub fn key(key: u32, state: u8, scancode: &str) {
        SINK.with(|s| {
            let mut s = s.borrow_mut();
            let first = CHECKED.with(|c| {
                let mut c = c.borrow_mut();
                let first = !*c;
                *c = true;
                first
            });
            if first {
                *s = arm();
            }
            let Some(sink) = s.as_mut() else { return };
            if sink.expired {
                return;
            }
            if Instant::now() >= sink.until {
                sink.expired = true;
                let _ = writeln!(sink.file, "--- keystroke logging expired ---");
                log::warn!(
                    "keystroke logging has expired and stopped. {:?} is closed; \
                     re-arm HOPS_LOG_KEYS and restart to record again.",
                    sink.path
                );
                return;
            }
            let _ = writeln!(sink.file, "key={key} state={state} scancode={scancode}");
        });
    }

    /// Whether recording is currently armed. Exposed for tests and diagnostics.
    pub fn is_armed() -> bool {
        SINK.with(|s| s.borrow().as_ref().is_some_and(|k| !k.expired))
    }

    #[allow(dead_code)]
    fn _assert_bounded(d: Duration) -> bool {
        d <= MAX_DURATION
    }
}

#[cfg(not(feature = "keylog"))]
mod armed {
    /// Compiled out. Without the `keylog` feature there is no recording code in
    /// the binary at all, which is the point — a shipped hops cannot do this.
    pub fn key(_key: u32, _state: u8, _scancode: &str) {}
    pub fn is_armed() -> bool {
        false
    }
}

pub use armed::{is_armed, key};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("10m"), Some(Duration::from_secs(600)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("45"), Some(Duration::from_secs(45)));
    }

    #[test]
    fn there_is_no_unlimited_mode() {
        // The cap is the whole point: "on until you remember" is the state that
        // produced a 4.4 GB file of one person's typing.
        assert_eq!(parse_duration("99h"), Some(MAX_DURATION));
        assert_eq!(parse_duration("100000000s"), Some(MAX_DURATION));
    }

    #[test]
    fn boolean_shaped_values_are_refused_not_guessed() {
        // `HOPS_LOG_KEYS=1` reads as "on". It must not quietly mean "on for one
        // second" either — an ambiguous arming of a keylogger is worse than none.
        for v in [
            "", "  ", "true", "yes", "on", "0", "0s", "forever", "-5", "abc",
        ] {
            assert_eq!(parse_duration(v), None, "{v:?} must not arm anything");
        }
    }

    /// Through the REAL arming path, not just the parser: junk in the
    /// environment must leave recording off. Without this, `parse_duration`
    /// could be perfect and `arm()` could still fall back to a default — which
    /// is exactly the mutation that slipped past the parser tests.
    #[cfg(feature = "keylog")]
    #[test]
    fn junk_in_the_environment_does_not_arm_recording() {
        unsafe { std::env::set_var("HOPS_LOG_KEYS", "true") };
        key(30, 1, "KeyA");
        assert!(
            !is_armed(),
            "a value that is not a duration must leave recording OFF — never fall \
             back to some default window"
        );
        unsafe { std::env::remove_var("HOPS_LOG_KEYS") };
    }

    #[cfg(not(feature = "keylog"))]
    #[test]
    fn without_the_feature_nothing_can_be_armed() {
        unsafe { std::env::set_var("HOPS_LOG_KEYS", "10m") };
        key(30, 1, "KeyA");
        assert!(
            !is_armed(),
            "a build without the `keylog` feature must not record, whatever the \
             environment says — the code is not supposed to be in the binary"
        );
        unsafe { std::env::remove_var("HOPS_LOG_KEYS") };
    }
}

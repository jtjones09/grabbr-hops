//! The name System Settings gives the list that lets hops control this Mac.
//!
//! Under Privacy & Security that list is "Accessibility" up to macOS 26 and
//! "Device Control and Data Access" from macOS 27; Input Monitoring kept its
//! name. Telling someone on macOS 27 to look for "Accessibility" names a
//! list they cannot find. Every user-visible mention of it goes through
//! [`accessibility`], here because this is the lowest crate everything that
//! names it reaches: capture, emulation, the IPC types the frontends
//! display, and the daemon. Internal names (the `Accessibility` permission
//! variants, the `Privacy_Accessibility` link) are unchanged.

use std::sync::OnceLock;

/// The list's name up to macOS 26.
pub const ACCESSIBILITY: &str = "Accessibility";

/// The list's name from macOS 27.
pub const DEVICE_CONTROL: &str = "Device Control and Data Access";

/// The list's name on macOS `major`.
pub fn pane_name_for(major: u32) -> &'static str {
    if major >= 27 {
        DEVICE_CONTROL
    } else {
        ACCESSIBILITY
    }
}

/// The major version in a macOS product version: 27 in "27.2", 15 in
/// "15.7.1". `None` for anything else.
pub fn major_of(version: &str) -> Option<u32> {
    version.trim().split('.').next()?.parse().ok()
}

/// The list's name on the Mac this runs on, worked out once per process.
/// "Accessibility" off macOS, where it is never shown, and when the version
/// cannot be read.
pub fn accessibility() -> &'static str {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(major) = ASSUMED.with(std::cell::Cell::get) {
        return pane_name_for(major);
    }
    static NAME: OnceLock<&'static str> = OnceLock::new();
    NAME.get_or_init(|| pane_name_for(running_major().unwrap_or(0)))
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static ASSUMED: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// Make [`accessibility`] answer, on this thread, as on macOS `major`, or
/// as on the running Mac again with `None`. For tests, so a test of what a
/// message says on macOS 27 and on 26 runs the same on any host. Per thread,
/// since tests run in parallel. Only with the `test-support` feature, which
/// crates enable for their tests alone, so no shipped build has it.
#[cfg(any(test, feature = "test-support"))]
pub fn assume_major(major: Option<u32>) {
    ASSUMED.with(|assumed| assumed.set(major));
}

/// The running macOS's major version, from `kern.osproductversion`.
#[cfg(target_os = "macos")]
fn running_major() -> Option<u32> {
    let name = c"kern.osproductversion";
    let mut buf = [0u8; 32];
    let mut len = buf.len();
    // SAFETY: `name` is NUL-terminated, `buf` holds `len` bytes, and no new
    // value is passed.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let version = std::str::from_utf8(&buf[..len.min(buf.len())]).ok()?;
    major_of(version.trim_end_matches('\0'))
}

#[cfg(not(target_os = "macos"))]
fn running_major() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // LEDGER T4 | class B | 1 return value: pane_name_for
    #[test]
    fn macos_27_renamed_the_list() {
        assert_eq!(
            [15, 26, 27, 28].map(pane_name_for),
            [ACCESSIBILITY, ACCESSIBILITY, DEVICE_CONTROL, DEVICE_CONTROL]
        );
    }

    // LEDGER T5 | class B | 1 return value: major_of
    #[test]
    fn the_major_version_is_read_from_the_product_version() {
        assert_eq!(
            ["27.2", "15.7.1", "26", " 28.0\n", "", "x.1"].map(major_of),
            [Some(27), Some(15), Some(26), Some(28), None, None]
        );
    }

    // LEDGER T8 | class B | 1 return value: accessibility, with assume_major
    #[test]
    fn an_assumed_version_names_the_list_on_this_thread() {
        assume_major(Some(27));
        assert_eq!(accessibility(), DEVICE_CONTROL);
        assume_major(Some(26));
        assert_eq!(accessibility(), ACCESSIBILITY);
        assume_major(None);
    }

    /// The name on this Mac is the one for the version `sw_vers` reports,
    /// read independently of the sysctl the function uses.
    // LEDGER T6 | class B | 1 return value: accessibility, against sw_vers
    #[cfg(target_os = "macos")]
    #[test]
    fn the_name_on_this_mac_is_the_one_for_its_version() {
        let out = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .expect("sw_vers");
        let version = String::from_utf8_lossy(&out.stdout);
        let major = major_of(&version).expect("a macOS version");
        assert_eq!(accessibility(), pane_name_for(major), "macOS {version}");
    }
}

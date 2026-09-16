//! What to tell the user about a file the daemon needs and cannot use.
//!
//! The common cause on macOS and Linux is a file or directory another user
//! owns, left behind after hops ran as that user, for example under `sudo`.
//! The error then says which one it is, whose it is and what to do, instead of
//! only "Permission denied".

use std::io;
use std::path::{Path, PathBuf};

/// A file or directory that belongs to a user other than the one hops runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Foreign {
    /// What belongs to the other user: the file, or the directory it would
    /// have been created in.
    pub(crate) path: PathBuf,
    /// Its owner's uid.
    pub(crate) owner: u32,
    /// The uid hops runs as.
    pub(crate) me: u32,
}

/// What to say about `foreign`.
///
/// Says to give it back rather than remove it: it may be the whole config
/// directory, devices and keys included.
pub(crate) fn another_users(foreign: &Foreign) -> String {
    let Foreign { path, owner, me } = foreign;
    format!(
        "{} belongs to uid {owner}, not to this user (uid {me}), which happens \
         after hops has run as that user, for example under sudo. Give it back \
         to this user (`sudo chown {me} {}`), then start hops again.",
        path.display(),
        path.display()
    )
}

/// [`another_users`] when `foreign` names something another user owns, as
/// [`foreign_owner`] returns it; `otherwise` when it does not.
pub(crate) fn hint(foreign: Option<Foreign>, otherwise: &str) -> String {
    match foreign {
        Some(foreign) => another_users(&foreign),
        None => otherwise.to_string(),
    }
}

/// What at `path` belongs to another user, if that is why it could not be
/// used.
///
/// `error` is how opening or creating `path` failed. When nothing is at
/// `path` and permission was refused, the directory it would be created in is
/// what stopped it, so that directory is checked instead.
#[cfg(unix)]
pub(crate) fn foreign_owner(path: &Path, error: &io::Error) -> Option<Foreign> {
    use std::os::unix::fs::MetadataExt;
    let (path, owner) = match std::fs::symlink_metadata(path) {
        Ok(meta) => (path.to_path_buf(), meta.uid()),
        Err(_) if error.kind() == io::ErrorKind::PermissionDenied => {
            let dir = path
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            (dir.to_path_buf(), std::fs::metadata(dir).ok()?.uid())
        }
        Err(_) => return None,
    };
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    (owner != me).then_some(Foreign { path, owner, me })
}

/// Windows files have no single owning uid to compare, so no hint is given.
#[cfg(not(unix))]
pub(crate) fn foreign_owner(_path: &Path, _error: &io::Error) -> Option<Foreign> {
    None
}

#[cfg(test)]
mod tests {
    use super::{Foreign, another_users, hint};
    use std::path::PathBuf;

    // LEDGER T26 | class B | 1 return value
    #[test]
    fn something_another_user_owns_is_described_with_both_users_and_what_to_do() {
        let foreign = Foreign {
            path: PathBuf::from("/home/me/.config/lan-mouse"),
            owner: 0,
            me: 501,
        };
        let said = another_users(&foreign);
        for part in [
            "/home/me/.config/lan-mouse belongs to uid 0",
            "(uid 501)",
            "`sudo chown 501 /home/me/.config/lan-mouse`",
        ] {
            assert!(
                said.contains(part),
                "the hint for something another user owns must name it, both \
                 users and how to give it back; `{part}` is missing: {said}"
            );
        }
        assert_eq!(
            (hint(Some(foreign), "generic"), hint(None, "generic")),
            (said, "generic".to_string()),
            "the hint must be the other-user text only when another user owns it"
        );
    }
}

#[cfg(all(test, unix))]
mod lookup {
    use super::{Foreign, foreign_owner};
    use std::io;
    use std::path::{Path, PathBuf};

    fn refused() -> io::Error {
        io::Error::from(io::ErrorKind::PermissionDenied)
    }

    // LEDGER T16 | class B | 1 return value
    #[test]
    fn a_file_another_user_owns_is_reported_with_both_users() {
        // `/` belongs to root on macOS and Linux. Run as root, it is not foreign.
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        let foreign = |path: &str| {
            (me != 0).then(|| Foreign {
                path: PathBuf::from(path),
                owner: 0,
                me,
            })
        };
        assert_eq!(
            foreign_owner(Path::new("/"), &io::Error::other("any failure")),
            foreign("/"),
            "a file owned by another user must be recognised as theirs, so the \
             error can say to give it back"
        );
        // Nothing there, and creating it was refused: the directory decided.
        let absent = Path::new("/hops-no-such-file-for-this-test");
        assert_eq!(
            (
                foreign_owner(absent, &refused()),
                foreign_owner(absent, &io::Error::from(io::ErrorKind::StorageFull)),
            ),
            (foreign("/"), None),
            "a file that could not be created in another user's directory must be \
             reported as that directory, and only when permission was refused"
        );
        let mine = std::env::temp_dir().join(format!("hops-owner-mine-{}", std::process::id()));
        std::fs::write(&mine, b"").expect("a file of this user's");
        let got = foreign_owner(&mine, &refused());
        let _ = std::fs::remove_file(&mine);
        assert_eq!(got, None, "a file this user owns was reported as another's");
    }
}

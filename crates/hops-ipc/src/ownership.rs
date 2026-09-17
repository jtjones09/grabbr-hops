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
    /// A symbolic link `path` is reached through, if there is one: `path`
    /// itself or a directory above it.
    pub(crate) through: Option<Link>,
}

/// A symbolic link, and the target it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    /// Where the link is.
    pub(crate) at: PathBuf,
    /// What it names, as the link holds it.
    pub(crate) to: PathBuf,
}

/// What to say about `foreign`.
///
/// Says to give it back rather than remove it: it may be the whole config
/// directory, devices and keys included. When it is reached through a link,
/// no chown is suggested: `chown` follows the link, so it would change what
/// the link names, and any process of this user can make such a link.
pub(crate) fn another_users(foreign: &Foreign) -> String {
    let Foreign {
        path,
        owner,
        me,
        through,
    } = foreign;
    match through {
        None => format!(
            "{} belongs to uid {owner}, not to this user (uid {me}), which happens \
             after hops has run as that user, for example under sudo. Give it back \
             to this user (`sudo chown {me} {}`), then start hops again.",
            path.display(),
            path.display()
        ),
        Some(Link { at, to }) => format!(
            "{} belongs to uid {owner}, not to this user (uid {me}), and {} is a \
             symbolic link to {}. A chown would follow the link, so check that the \
             link belongs there, then start hops again.",
            path.display(),
            at.display(),
            to.display()
        ),
    }
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
    (owner != me).then(|| Foreign {
        through: link_on_the_way(&path),
        path,
        owner,
        me,
    })
}

/// The symbolic link nearest `path` among `path` and the directories above
/// it, if there is one.
///
/// A link at any of them decides what a chown of `path` changes: `chown`
/// follows a link at `path`, and the path to it resolves through the others.
#[cfg(unix)]
fn link_on_the_way(path: &Path) -> Option<Link> {
    path.ancestors()
        .filter(|at| !at.as_os_str().is_empty())
        // `read_link` succeeds only on a symbolic link.
        .find_map(|at| {
            Some(Link {
                at: at.to_path_buf(),
                to: std::fs::read_link(at).ok()?,
            })
        })
}

/// Windows files have no single owning uid to compare, so no hint is given.
#[cfg(not(unix))]
pub(crate) fn foreign_owner(_path: &Path, _error: &io::Error) -> Option<Foreign> {
    None
}

#[cfg(test)]
mod tests {
    use super::{Foreign, Link, another_users, hint};
    use std::path::PathBuf;

    // LEDGER T26 | class B | 1 return value
    #[test]
    fn something_another_user_owns_is_described_with_both_users_and_what_to_do() {
        let foreign = Foreign {
            path: PathBuf::from("/home/me/.config/lan-mouse"),
            owner: 0,
            me: 501,
            through: None,
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
            (
                hint(Some(foreign.clone()), "generic"),
                hint(None, "generic")
            ),
            (said, "generic".to_string()),
            "the hint must be the other-user text only when another user owns it"
        );

        let linked = another_users(&Foreign {
            through: Some(Link {
                at: PathBuf::from("/home/me/.config"),
                to: PathBuf::from("/Library"),
            }),
            ..foreign
        });
        assert_eq!(
            (
                linked.contains(
                    "/home/me/.config/lan-mouse belongs to uid 0, not to this user \
                     (uid 501), and /home/me/.config is a symbolic link to /Library."
                ),
                linked.contains("chown 501"),
            ),
            (true, false),
            "(names the link and its target, advises a chown) for something \
             reached through a link. `chown` follows the link, so the advice \
             would give this user whatever directory the link names. Got: {linked}"
        );
    }
}

#[cfg(all(test, unix))]
mod lookup {
    use super::{Foreign, Link, foreign_owner};
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
                through: None,
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

        // Reached through a link: a link to `/` stands in for one to any
        // directory root owns. `/usr` is root's on macOS and Linux.
        let up = std::env::temp_dir().join(format!("hops-owner-up-{}", std::process::id()));
        let _ = std::fs::remove_file(&up);
        std::os::unix::fs::symlink("/", &up).expect("a link to /");
        let through_up = |path: PathBuf| {
            (me != 0).then(|| Foreign {
                path,
                owner: 0,
                me,
                through: Some(Link {
                    at: up.clone(),
                    to: PathBuf::from("/"),
                }),
            })
        };
        let got = (
            foreign_owner(&up.join("usr"), &io::Error::other("any failure")),
            foreign_owner(&up.join("hops-no-such-file-for-this-test"), &refused()),
        );
        let _ = std::fs::remove_file(&up);
        assert_eq!(
            got,
            (through_up(up.join("usr")), through_up(up.clone())),
            "(a file reached through a link above it, a directory that is a \
             link). Each must carry the link and its target, so the hint names \
             the link instead of advising a chown that would follow it."
        );
    }
}

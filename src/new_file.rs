//! Creating a file whole, and only where there is none.
//!
//! The identity key, the trust authority key and the default config are each
//! created once, by whichever process gets there first, and read by others.
//! Two promises hold for all three:
//!
//! * **No partial file.** A reader finds nothing at the path, or all of it.
//!   The contents are written to a private temporary file beside the path and
//!   synced before anything appears at the path itself.
//! * **Never over an existing file.** If another process created the file
//!   first, this one fails with `AlreadyExists` and leaves that file alone. A
//!   daemon may already hold it in memory.
//!
//! The finished file is hard-linked into place, which fails rather than
//! replace a file. Some filesystems have no hard links: FAT and exFAT (USB
//! drives), and some FUSE and network mounts. There the file is renamed into
//! place under an exclusive lock on a sibling lock file, after checking that
//! nothing is at the path. Every creator here takes that lock on that path,
//! and so does a save that renames a file over it
//! (`config::write_atomically`), so the check and the rename are one step
//! for them.
//!
//! A process that ends between writing its temporary file and removing it
//! leaves `.<name>.<pid>.<n>.tmp` behind, holding a whole private key when
//! the file is a key. [`remove_abandoned_temporaries`] removes those once
//! their process is gone.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Who may do what with the created file, on Unix. Windows files keep the ACL
/// of their directory.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Access {
    /// `0400`: a key, never rewritten in place.
    OwnerRead,
    /// `0600`: a file the daemon rewrites later.
    OwnerReadWrite,
}

/// Put `contents` at `path`, whole, and only if nothing is there yet.
///
/// Fails with `AlreadyExists` when a file is already at `path`, leaving it
/// untouched. Creates the parent directory if it is missing. Every error
/// names `path`.
pub(crate) fn create_whole(path: &Path, contents: &[u8], access: Access) -> io::Result<()> {
    create_whole_with(
        path,
        contents,
        access,
        |from, to| fs::hard_link(from, to),
        || {},
    )
}

/// [`create_whole`], with the hard link supplied, so a test can take it away,
/// and a step between the check and the rename where there are no hard links,
/// so a test can put another writer there.
fn create_whole_with(
    path: &Path,
    contents: &[u8],
    access: Access,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
    before_rename: impl FnOnce(),
) -> io::Result<()> {
    place(path, contents, access, link, before_rename).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("could not create {}: {e}", path.display()),
        )
    })
}

fn place(
    path: &Path,
    contents: &[u8],
    access: Access,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
    before_rename: impl FnOnce(),
) -> io::Result<()> {
    let dir = directory_of(path);
    fs::create_dir_all(dir)?;
    let tmp = sibling(path, &format!("{}.tmp", unique()));

    let placed = write_private(&tmp, contents, access).and_then(|()| match link(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) if !hard_links_unsupported(&e) => Err(e),
        Err(link_error) => {
            log::debug!(
                "no hard link for {} ({link_error}); renaming it into place under a lock",
                path.display()
            );
            rename_into_place_under_lock(&tmp, path, before_rename)
        }
    });
    let _ = fs::remove_file(&tmp);
    #[cfg(unix)]
    if placed.is_ok() {
        // So the new directory entry survives a crash, as the contents do.
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    placed
}

/// The directory `path` is in, `.` for a bare file name.
fn directory_of(path: &Path) -> &Path {
    path.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Remove the temporary files creators of `path` left behind, when the
/// process that wrote each one is gone.
///
/// Only names this module writes are touched, `.<name>.<pid>.<n>.tmp` for
/// exactly `path`'s name, and only regular files, not links. A temporary whose
/// process is running, this one included, or may be, is left alone, since it
/// may still be writing it. Best effort: a failure is logged and changes
/// nothing else.
pub(crate) fn remove_abandoned_temporaries(path: &Path) {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let Ok(entries) = fs::read_dir(directory_of(path)) else {
        return;
    };
    let prefix = format!(".{name}.");
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .and_then(|n| temporary_writer(n, &prefix))
        else {
            continue;
        };
        if !entry.file_type().is_ok_and(|t| t.is_file()) || !crate::pid::is_gone(pid) {
            continue;
        }
        match fs::remove_file(entry.path()) {
            Ok(()) => log::info!(
                "removed {}, left behind by process {pid}, which is gone",
                entry.path().display()
            ),
            Err(e) => log::warn!("could not remove {}: {e}", entry.path().display()),
        }
    }
}

/// The process id in `file_name` when it is a temporary this module writes
/// for the file whose sibling names start with `prefix`.
///
/// Both numbers must be written as [`unique`] writes them: decimal digits
/// with no leading zero, a process id that fits a `u32` and a counter that
/// fits a `u64`.
fn temporary_writer(file_name: &str, prefix: &str) -> Option<u32> {
    let middle = file_name.strip_prefix(prefix)?.strip_suffix(".tmp")?;
    let (pid, n) = middle.split_once('.')?;
    let as_written = |s: &str| {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
    };
    if !as_written(pid) || !as_written(n) || n.parse::<u64>().is_err() {
        return None;
    }
    pid.parse().ok()
}

/// Take an exclusive lock on `.<name>.lock` beside `path`, waiting for it.
///
/// Held by everything that renames a file to `path`: a creator without hard
/// links, for its check and its rename, and a save, for its write and its
/// rename. The lock goes with the process that holds it. The lock file stays:
/// removing it would let a later process lock a new file while an earlier one
/// still holds the old.
///
/// A link at the lock path is not followed, and the lock is then refused: a
/// daemon run as root would otherwise create or lock whatever file a process
/// of this user linked there.
pub(crate) fn lock_sibling(path: &Path) -> io::Result<fs::File> {
    let lock_path = sibling(path, "lock");
    let mut opts = fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = opts.open(&lock_path)?;
    lock.lock()?;
    Ok(lock)
}

/// Whether a failed hard link says the filesystem has none, as opposed to a
/// file being in the way or the directory being unwritable.
///
/// Only these fall back. Every process creating the same file sees the same
/// answer from the same filesystem, so none of them links while another
/// renames. Matched by the OS's own code, since Rust gives some of them no
/// `ErrorKind`: `ENOTSUP`, which macOS returns for exFAT, is `Uncategorized`.
fn hard_links_unsupported(e: &io::Error) -> bool {
    // ENOTSUP from macOS exFAT and msdos, ENOSYS from FUSE, EPERM from Linux vfat.
    #[cfg(unix)]
    let no_links = [libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOSYS, libc::EPERM];
    // ERROR_INVALID_FUNCTION from FAT and exFAT, ERROR_NOT_SUPPORTED from a share.
    #[cfg(windows)]
    let no_links = [1, 50];
    #[cfg(not(any(unix, windows)))]
    let no_links: [i32; 0] = [];
    e.raw_os_error()
        .is_some_and(|code| no_links.contains(&code))
}

/// Rename `tmp` to `path` unless something is at `path`, holding the
/// [`lock_sibling`] lock for the check and the rename.
fn rename_into_place_under_lock(
    tmp: &Path,
    path: &Path,
    before_rename: impl FnOnce(),
) -> io::Result<()> {
    // Blocks for as long as another creator or a save holds it, and no longer.
    let _lock = lock_sibling(path)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    before_rename();
    fs::rename(tmp, path)
}

/// Create `path` private to its owner, write `contents`, sync, and set its
/// final mode, before any other name for it exists.
fn write_private(path: &Path, contents: &[u8], access: Access) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    #[cfg(unix)]
    if let Access::OwnerRead = access {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o400))?;
    }
    #[cfg(not(unix))]
    let _ = access; /* FIXME windows permissions */
    Ok(())
}

/// `.<name>.<suffix>` in the same directory as `path`.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.{suffix}"))
}

/// A name no other process or thread is using for a temporary file.
fn unique() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod where_hard_links_are_missing {
    //! FAT, exFAT and some FUSE and network mounts have no hard links. The
    //! identity key, the authority key and the default config must still be
    //! created there, and still never half-written or over a file another
    //! process created. These tests take the hard link away.

    use super::{Access, create_whole_with};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hops-new-file-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    /// What the OS says when a filesystem has no hard links: ENOTSUP from
    /// exFAT on macOS, ERROR_INVALID_FUNCTION from FAT on Windows.
    fn no_hard_links(_: &Path, _: &Path) -> io::Result<()> {
        #[cfg(unix)]
        let code = libc::ENOTSUP;
        #[cfg(windows)]
        let code = 1;
        Err(io::Error::from_raw_os_error(code))
    }

    /// Everything in `dir` but the lock file, which stays by design.
    fn leftovers(dir: &Path, keep: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("the scratch directory")
            .map(|e| e.expect("an entry").path())
            .filter(|p| p != keep && !p.to_string_lossy().ends_with(".lock"))
            .map(|p| p.display().to_string())
            .collect()
    }

    // LEDGER T20 | class B | 4 file on disk + 1 return value
    #[test]
    fn without_hard_links_the_file_is_still_created_whole() {
        let dir = scratch("created");
        let path = dir.join("lan-mouse.pem");

        let got = create_whole_with(
            &path,
            b"whole contents",
            Access::OwnerRead,
            no_hard_links,
            || {},
        );
        let on_disk = std::fs::read(&path);
        let left = leftovers(&dir, &path);

        // A link that fails for another reason is an error, not a reason to
        // fall back: the directory may be unwritable, or the disk full.
        let other = dir.join("other.pem");
        let refused = create_whole_with(
            &other,
            b"x",
            Access::OwnerRead,
            |_, _| Err(io::Error::new(io::ErrorKind::StorageFull, "no space left")),
            || {},
        );
        let other_exists = other.exists();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            got.is_ok(),
            "on a filesystem without hard links the file could not be created: {got:?}. \
             A first run with its identity on a USB drive would never start."
        );
        assert_eq!(
            on_disk.as_deref().ok(),
            Some(&b"whole contents"[..]),
            "the created file does not hold what was written"
        );
        assert!(
            left.is_empty(),
            "temporary files were left behind: {left:?}"
        );
        let message = refused
            .as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert_eq!(
            (refused.map_err(|e| e.kind()), other_exists),
            (Err(io::ErrorKind::StorageFull), false),
            "a link that failed for a reason other than missing hard links was \
             not reported as that failure"
        );
        assert!(
            message.contains(&other.display().to_string()),
            "the error does not name the file it could not create: {message}. \
             With the identity key given by --cert-path, the log said only \
             \"no space left\"."
        );
    }

    // LEDGER T21 | class B | 4 file on disk + 1 return value
    #[test]
    fn without_hard_links_a_file_already_there_is_never_replaced() {
        const ROUNDS: usize = 20;
        const WRITERS: usize = 8;
        let dir = scratch("race");
        let path = dir.join("config.toml");

        std::fs::write(&path, b"written by the daemon").expect("seed");
        let later = create_whole_with(
            &path,
            b"default",
            Access::OwnerReadWrite,
            no_hard_links,
            || {},
        );
        let kept = std::fs::read_to_string(&path).expect("the file");
        assert_eq!(
            (later.map_err(|e| e.kind()), kept.as_str()),
            (Err(io::ErrorKind::AlreadyExists), "written by the daemon"),
            "creating a file where one already exists replaced it"
        );

        for round in 0..ROUNDS {
            let _ = std::fs::remove_file(&path);
            let start = Arc::new(Barrier::new(WRITERS));
            let got: Vec<(usize, io::Result<()>)> = (0..WRITERS)
                .map(|n| {
                    let (start, path) = (start.clone(), path.clone());
                    std::thread::spawn(move || {
                        start.wait();
                        let contents = format!("writer {n}");
                        let got = create_whole_with(
                            &path,
                            contents.as_bytes(),
                            Access::OwnerRead,
                            no_hard_links,
                            || {},
                        );
                        (n, got)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().expect("a writer thread"))
                .collect();
            let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
            let left = leftovers(&dir, &path);
            let winners: Vec<usize> = got
                .iter()
                .filter(|(_, r)| r.is_ok())
                .map(|(n, _)| *n)
                .collect();
            let others_refused = got.iter().all(|(_, r)| match r {
                Ok(()) => true,
                Err(e) => e.kind() == io::ErrorKind::AlreadyExists,
            });
            if winners.len() != 1 || !others_refused || !left.is_empty() {
                let _ = std::fs::remove_dir_all(&dir);
            }
            assert!(
                winners.len() == 1 && others_refused,
                "round {round}: {} creators reported creating the file ({got:?}). \
                 Without hard links, a creator replaced a file another had just \
                 created: a daemon holding that identity would present one that \
                 is no longer on disk.",
                winners.len()
            );
            assert_eq!(
                on_disk,
                format!("writer {}", winners[0]),
                "round {round}: the file on disk is not the one its creator wrote"
            );
            assert!(left.is_empty(), "round {round}: left behind {left:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // LEDGER T29 | class B | 4 file on disk
    #[test]
    fn without_hard_links_a_config_saved_while_a_default_is_created_is_kept() {
        let dir = scratch("save");
        let path = dir.join("config.toml");

        // The save starts after this creator found no config, and before it
        // renames the default into place.
        let (saved_tx, saved) = mpsc::channel();
        let mut saver = None;
        let created = create_whole_with(
            &path,
            b"default",
            Access::OwnerReadWrite,
            no_hard_links,
            || {
                let path = path.clone();
                saver = Some(std::thread::spawn(move || {
                    let got = crate::config::write_atomically(&path, b"saved by the daemon");
                    let _ = saved_tx.send(());
                    got
                }));
                // Give the save the time it needs to finish, if nothing holds
                // it back.
                let _ = saved.recv_timeout(Duration::from_secs(1));
            },
        );
        let save = saver
            .expect("the step before the rename ran")
            .join()
            .expect("the saving thread");
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            (created.is_ok(), save.is_ok(), on_disk.as_str()),
            (true, true, "saved by the daemon"),
            "(default created, config saved, config on disk). Without hard links, \
             a default config renamed into place after a save replaced what the \
             save wrote: the devices and settings in it were lost."
        );
    }
}

#[cfg(all(test, unix))]
mod the_lock_is_not_taken_through_a_link {
    // LEDGER T53 | class B | 1 return value / error + 4 file on disk
    #[test]
    fn a_link_in_the_lock_files_place_is_refused_and_not_followed() {
        let dir = std::env::temp_dir().join(format!("hops-lock-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("config.toml");
        let nowhere = dir.join("named-by-the-link");
        std::os::unix::fs::symlink(&nowhere, super::sibling(&path, "lock"))
            .expect("a link where the lock goes");

        let locked = super::lock_sibling(&path).is_ok();
        let created = std::fs::symlink_metadata(&nowhere).is_ok();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            (locked, created),
            (false, false),
            "(locked, created the file the link names). Any process of this \
             user can put a link where the lock goes, and a daemon run as root \
             that follows it creates a file wherever the link says."
        );
    }
}

#[cfg(test)]
mod abandoned_temporaries {
    //! A process that ends between writing a temporary file and removing it
    //! leaves a whole private key beside the identity or the authority key.

    use super::remove_abandoned_temporaries;
    use crate::pid::processes;
    use std::collections::BTreeSet;

    // LEDGER T34 | class B | 4 file on disk
    #[test]
    fn temporaries_of_a_process_that_is_gone_are_removed_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("hops-abandoned-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("lan-mouse.pem");

        let gone = processes::gone();
        let running = processes::waiting();
        let live = running.id();
        let me = std::process::id();
        let abandoned = format!(".lan-mouse.pem.{gone}.0.tmp");
        let kept = [
            format!(".lan-mouse.pem.{live}.0.tmp"),
            format!(".lan-mouse.pem.{me}.3.tmp"),
            format!(".lan-mouse.pem.{gone}.0.tmp.bak"),
            format!(".lan-mouse.pem.{gone}.tmp"),
            format!(".lan-mouse.pem.x{gone}.0.tmp"),
            format!(".lan-mouse.pem.{gone}.0.1.tmp"),
            // A counter no `u64` holds is not one this module wrote.
            format!(".lan-mouse.pem.{gone}.99999999999999999999999.tmp"),
            // Nor are numbers with a leading zero, which name the same
            // process and counter.
            format!(".lan-mouse.pem.0{gone}.0.tmp"),
            format!(".lan-mouse.pem.{gone}.00.tmp"),
            format!(".lan-mouse.pem.{gone}.07.tmp"),
            format!("lan-mouse.pem.{gone}.0.tmp"),
            format!(".other.pem.{gone}.0.tmp"),
            ".lan-mouse.pem.lock".to_string(),
        ];
        for name in kept.iter().chain([&abandoned]) {
            std::fs::write(dir.join(name), b"-----BEGIN PRIVATE KEY-----").expect("a file");
        }
        // A directory with the right name is not a file this module wrote.
        let not_a_file = format!(".lan-mouse.pem.{gone}.1.tmp");
        std::fs::create_dir(dir.join(&not_a_file)).expect("a directory");
        // Nor is a link, whatever it points at.
        #[cfg(unix)]
        let a_link = {
            let name = format!(".lan-mouse.pem.{gone}.2.tmp");
            std::os::unix::fs::symlink(dir.join(&kept[0]), dir.join(&name)).expect("a link");
            name
        };

        remove_abandoned_temporaries(&path);
        let left: BTreeSet<String> = std::fs::read_dir(&dir)
            .expect("the scratch directory")
            .map(|e| {
                e.expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        processes::finish(running);
        let _ = std::fs::remove_dir_all(&dir);

        #[allow(unused_mut)] // only Unix adds the link
        let mut expected: BTreeSet<String> = kept.iter().cloned().chain([not_a_file]).collect();
        #[cfg(unix)]
        expected.insert(a_link);
        assert_eq!(
            left, expected,
            "only `.<name>.<pid>.<n>.tmp` files of a process that is gone may be \
             removed. A key left by a crashed first run stays beside the identity \
             for good otherwise, and removing anything else can take a file a \
             running process is writing."
        );
    }

    // LEDGER T35 | class B | 4 file on disk + 1 return value
    #[test]
    fn the_identity_the_authority_key_and_the_config_clear_what_was_left_beside_them() {
        let dir = std::env::temp_dir().join(format!("hops-left-beside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let gone = processes::gone();
        let identity = dir.join("lan-mouse.pem");
        let authority = dir.join(crate::authority::AUTHORITY_KEY_FILE_NAME);
        let config = dir.join("config.toml");
        for path in [&identity, &authority, &config] {
            let name = path.file_name().expect("a name").to_string_lossy();
            std::fs::write(
                dir.join(format!(".{name}.{gone}.0.tmp")),
                b"-----BEGIN PRIVATE KEY-----",
            )
            .expect("a temporary left behind");
        }

        let loaded = (
            crate::crypto::load_or_generate_key_and_cert(&identity).is_ok(),
            crate::authority::SoftwareAuthority::load_or_generate(&authority).is_ok(),
            crate::config::ensure_config_file(&config).is_ok(),
        );
        let left: BTreeSet<String> = std::fs::read_dir(&dir)
            .expect("the scratch directory")
            .map(|e| {
                e.expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            (loaded, left),
            ((true, true, true), BTreeSet::new()),
            "((identity, authority key, config) loaded, temporaries left). What a \
             process that ended part-way through creating one of them left beside \
             it must be gone once it is loaded again. A temporary beside a key is \
             a copy of a private key."
        );
    }
}

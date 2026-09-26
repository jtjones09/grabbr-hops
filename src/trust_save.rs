//! Getting the trust store to disk, and saying so when it does not get there.
//!
//! A failed save used to be one error line. The change stayed in effect in
//! memory, so nothing looked wrong until the next start rebuilt trust from the
//! last file that did reach disk: a removed device was trusted again, a new
//! pairing was gone, and nothing had appeared on screen at any point.
//!
//! Now a change that did not reach disk is kept as waiting and retried on the
//! daemon's minute sweep until it does, whether or not the clock floor moved:
//! a system clock set behind the floor never moves it, so a retry tied to the
//! floor would never come. The user is told when it fails and when it lands.

use crate::trust::TrustStore;
use crate::trust_file::{TrustFile, records_of};

/// Why the store in memory is not the store on disk.
struct Unsaved {
    error: String,
    /// The trust changes waiting, each as the user would name it. Empty when
    /// only an advance of the clock floor is waiting, which is not worth
    /// interrupting the user for.
    changes: Vec<String>,
}

pub(crate) struct TrustSaver {
    file: TrustFile,
    /// The clock floor last written, so a quiet daemon does not rewrite a
    /// sealed file every sweep for nothing.
    saved_floor: u64,
    unsaved: Option<Unsaved>,
}

impl TrustSaver {
    pub(crate) fn new(file: TrustFile) -> Self {
        Self {
            file,
            saved_floor: 0,
            unsaved: None,
        }
    }

    /// Save after trust changed; `what` names the change for the user, as in
    /// `removing "desk mac"`. Returns what to tell the user, if anything.
    #[must_use = "the notice is how the user learns trust did not reach disk"]
    pub(crate) fn save_change(&mut self, store: &TrustStore, what: String) -> Option<String> {
        match self.save(store, Some(what)) {
            Ok(saved) => saved.map(|changes| saved_notice(&changes)),
            Err(()) => self.pending_notice(),
        }
    }

    /// The minute sweep's save: while anything is waiting, or when the clock
    /// floor has moved. Returns what to tell the user, if anything.
    #[must_use = "the notice is how the user learns trust did not reach disk"]
    pub(crate) fn sweep(&mut self, store: &TrustStore) -> Option<String> {
        if self.unsaved.is_none() && store.clock().floor() <= self.saved_floor {
            return None;
        }
        // A retry that fails again says nothing: the user was told when the
        // change failed, and a notice every minute would bury everything else.
        self.save(store, None)
            .ok()
            .flatten()
            .map(|changes| saved_notice(&changes))
    }

    /// What a frontend attaching now must be shown, while a change waits.
    #[must_use = "the notice is how the user learns trust did not reach disk"]
    pub(crate) fn pending_notice(&self) -> Option<String> {
        self.unsaved
            .as_ref()
            .filter(|u| !u.changes.is_empty())
            .map(|u| unsaved_notice(&u.changes, &u.error))
    }

    /// Write every record. `Ok(Some(changes))` when that carried changes an
    /// earlier save failed to write. Any successful save clears what was
    /// waiting, a floor-only save included, because it writes the whole
    /// store, not a difference.
    fn save(
        &mut self,
        store: &TrustStore,
        what: Option<String>,
    ) -> Result<Option<Vec<String>>, ()> {
        let floor = store.clock().floor();
        match self.file.save(&records_of(store)) {
            Ok(()) => {
                self.saved_floor = self.saved_floor.max(floor);
                let recovered = self
                    .unsaved
                    .take()
                    .map(|u| u.changes)
                    .filter(|c| !c.is_empty());
                if recovered.is_some() {
                    log::info!(
                        "the trust store is saved; the changes that failed to save are on disk now"
                    );
                }
                Ok(recovered)
            }
            Err(e) => {
                let error = e.to_string();
                log::error!(
                    "failed to write the trust store: {error}. The change is in effect \
                     but not on disk; retrying every minute"
                );
                let mut changes = self.unsaved.take().map(|u| u.changes).unwrap_or_default();
                changes.extend(what);
                self.unsaved = Some(Unsaved { error, changes });
                Err(())
            }
        }
    }
}

fn unsaved_notice(changes: &[String], error: &str) -> String {
    format!(
        "Could not save a change to trusted devices: {} ({error}). It is in \
         effect now, but if hops restarts before it is saved, it is undone. hops \
         tries to save it again every minute.",
        changes.join(", ")
    )
}

fn saved_notice(changes: &[String]) -> String {
    format!(
        "Saved the change to trusted devices that could not be saved earlier: {}.",
        changes.join(", ")
    )
}

#[cfg(test)]
mod tests {
    //! A real store file in a scratch directory. A save is made to fail the
    //! way a full or read-only disk makes it fail: the write of the file's
    //! temporary sibling is refused, and the last good file stays in place.

    use super::*;
    use crate::authority::{AUTHORITY_KEY_FILE_NAME, SoftwareAuthority};
    use crate::trust::Caps;
    use crate::trust_file::{Loaded, TRUST_FILE_NAME};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const OURS: &str = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:\
10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
    const PEER: &str = "1e:19:1b:c4:a8:40:f5:26:37:39:9d:c7:c7:75:fe:17:\
4f:03:d5:a9:76:49:cd:b1:12:d1:2f:6c:1f:d2:22:c5";
    const OTHER: &str = "2e:19:1b:c4:a8:40:f5:26:37:39:9d:c7:c7:75:fe:17:\
4f:03:d5:a9:76:49:cd:b1:12:d1:2f:6c:1f:d2:22:c5";
    /// A clock floor that never moves in these tests: nothing observes time.
    const FLOOR: u64 = 1_788_579_979;

    struct Disk {
        dir: PathBuf,
    }

    impl Disk {
        fn new(name: &str) -> Disk {
            let dir =
                std::env::temp_dir().join(format!("hops-trustsave-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            Disk { dir }
        }

        fn open(&self) -> (TrustFile, Loaded) {
            let authority = Arc::new(
                SoftwareAuthority::load_or_generate(&self.dir.join(AUTHORITY_KEY_FILE_NAME))
                    .expect("authority"),
            );
            TrustFile::open(&self.dir, authority).expect("open")
        }

        /// Where a save writes before it renames into place.
        fn staging(&self) -> PathBuf {
            Path::new(&self.dir.join(TRUST_FILE_NAME)).with_extension("toml.tmp")
        }

        /// Refuse every save from now on, leaving the last good file alone.
        fn refuse_writes(&self) {
            std::fs::create_dir_all(self.staging().join("in-the-way")).expect("block");
        }

        fn accept_writes(&self) {
            std::fs::remove_dir_all(self.staging()).expect("unblock");
        }

        /// What a daemon starting now would load: the fingerprints on disk
        /// and the serial of the file.
        fn on_restart(&self) -> (Vec<String>, u64) {
            match self.open().1 {
                Loaded::Present { leases, serial, .. } => {
                    (leases.into_iter().map(|l| l.fingerprint).collect(), serial)
                }
                Loaded::Absent => (vec![], 0),
            }
        }
    }

    impl Drop for Disk {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A saver the way a daemon that has run for a while holds it: its store
    /// saved, and a sweep since, so the floor at [`FLOOR`] is on disk.
    fn saved(disk: &Disk) -> (TrustSaver, TrustStore) {
        let store = TrustStore::new(OURS, FLOOR).expect("store");
        let mut saver = TrustSaver::new(disk.open().0);
        assert_eq!(
            saver.save_change(&store, "setting up".into()),
            None,
            "the first save must work"
        );
        assert_eq!(saver.sweep(&store), None, "the first sweep must work");
        (saver, store)
    }

    // LEDGER TSAVE-1 | class B | 4 file on disk: TrustSaver::sweep, then TrustFile::open
    /// The clock floor is held still, as it is whenever the system clock is
    /// behind it. A sweep that saves only when the floor moves would never
    /// write the change, and a restart would undo it.
    #[test]
    fn a_change_that_failed_to_save_is_written_by_the_next_sweep_though_the_floor_is_still() {
        let disk = Disk::new("retry");
        let (mut saver, mut store) = saved(&disk);

        disk.refuse_writes();
        store.issue(PEER, "peer", Caps::INBOUND).expect("issue");
        let _ = saver.save_change(&store, "trusting \"peer\"".into());
        assert!(
            !disk.on_restart().0.contains(&PEER.to_owned()),
            "the save was meant to fail, so the test is not testing a failure"
        );

        disk.accept_writes();
        assert_eq!(
            store.clock().floor(),
            FLOOR,
            "the floor must not have moved"
        );
        let _ = saver.sweep(&store);
        assert!(
            disk.on_restart().0.contains(&PEER.to_owned()),
            "the disk accepts writes again, a sweep has run, and the pairing \
             is still not on disk: a restart would forget it"
        );
    }

    // LEDGER TSAVE-2 | class B | 1 return value: TrustSaver::save_change, sweep, pending_notice
    #[test]
    fn the_user_is_told_which_change_was_not_saved_and_when_it_is() {
        let disk = Disk::new("notice");
        let (mut saver, mut store) = saved(&disk);

        disk.refuse_writes();
        store.revoke(PEER);
        let told = saver
            .save_change(&store, "removing \"desk mac\"".into())
            .expect("a change that did not reach disk must be reported to the user");
        assert!(
            told.contains("Could not save")
                && told.contains("removing \"desk mac\"")
                && told.contains("every minute"),
            "the notice must name the change, say it is not saved, and that it \
             is retried: {told:?}"
        );
        assert_eq!(
            saver.sweep(&store),
            None,
            "a sweep that fails again must not repeat the notice every minute"
        );
        assert!(
            saver
                .pending_notice()
                .is_some_and(|n| n.contains("removing \"desk mac\"")),
            "a frontend that attaches while the change is unsaved must be told which"
        );
        store.issue(OTHER, "laptop", Caps::INBOUND).expect("issue");
        let told = saver
            .save_change(&store, "trusting \"laptop\"".into())
            .expect("a further change that also fails must be reported");
        assert!(
            told.contains("removing \"desk mac\"") && told.contains("trusting \"laptop\""),
            "both changes are waiting, and the notice must name both: {told:?}"
        );

        disk.accept_writes();
        let told = saver
            .sweep(&store)
            .expect("the user was told the change was not saved, and must be told it is now");
        assert!(
            told.contains("Saved") && told.contains("removing \"desk mac\""),
            "{told:?}"
        );
        assert_eq!(saver.pending_notice(), None, "nothing is waiting any more");
    }

    // LEDGER TSAVE-3 | class B | 4 file on disk: TrustSaver::sweep, then TrustFile::open
    #[test]
    fn a_sweep_writes_only_when_something_is_waiting_or_the_floor_moved() {
        let disk = Disk::new("quiet");
        let (mut saver, store) = saved(&disk);
        let (_, serial) = disk.on_restart();

        assert_eq!(saver.sweep(&store), None);
        assert_eq!(
            disk.on_restart().1,
            serial,
            "a quiet sweep rewrote the sealed file: nothing changed and the floor did not move"
        );

        store.clock().observe(FLOOR + 60);
        assert_eq!(saver.sweep(&store), None);
        assert!(
            disk.on_restart().1 > serial,
            "the floor moved and the sweep did not write it: a restart would \
             start from an older floor"
        );
    }
}

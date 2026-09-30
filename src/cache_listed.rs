//! A removal made in the `[authorized_fingerprints]` cache is honoured.
//!
//! The daemon writes that table in `config.toml` as a cache of the trust
//! store and never reads it as a grant. Older builds (0.12 and before) read
//! it as their allowlist and remove a device by deleting its line, and so
//! does a person editing the file. Once the store existed, such a removal
//! was undone: the device the line named was trusted again at the next start.
//!
//! So a device the store trusts to drive this machine, which the cache has
//! listed and no longer lists, was removed there, and the daemon forgets it.
//! A line the cache gains grants nothing: only the store grants.
//!
//! "Has listed" is kept in [`FILE_NAME`] beside the config: the devices the
//! last save wrote to the cache, or at a start the ones the file listed that
//! the store trusts. Without it a device paired but not yet written to the
//! cache, as when the write failed or a build before this one never wrote
//! it, would read as removed; and so would one whose right to drive this
//! machine was taken away, written out, and given back before the next save.
//! The file can only ever make the daemon forget a device, never trust one.
//!
//! A removal is final, so it is acted on only once the file has settled: a
//! second read [`SETTLE`] after the one that found it must agree
//! ([`confirmed`]). A file read while a save is still writing it, as an
//! older build writes in place, can lack lines it is about to gain.
//!
//! While the trust store holds a change that has not reached disk, what is
//! recorded only grows ([`Listed::record_keeping`]): a device forgotten in
//! memory is still on disk, and must still read as removed at the next start.
//!
//! A machine an older build listed there, which the store holds to be paired
//! again and grants nothing (#231), is removed the same way while the file
//! still lists it. The daemon's own next save drops such a line, and stops
//! recording it ([`Listed::unrecord`]).

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long after a read that finds a device removed the file is read again
/// to confirm it.
pub const SETTLE: Duration = Duration::from_secs(1);

/// The file, beside `config.toml`, naming each device the cache has listed.
pub const FILE_NAME: &str = "authorized_fingerprints.listed";

/// The devices the `[authorized_fingerprints]` cache has listed.
#[derive(Debug)]
pub struct Listed {
    path: PathBuf,
    fingerprints: BTreeSet<String>,
}

/// A fingerprint as the store keys it.
pub fn canonical(fp: &str) -> String {
    hops_ipc::identity::canonical_fingerprint(fp).unwrap_or_else(|| fp.trim().to_lowercase())
}

impl Listed {
    /// What the file in `config_dir` says; nothing when it is absent or
    /// cannot be read, which forgets nothing.
    pub fn read(config_dir: &Path) -> Self {
        let path = config_dir.join(FILE_NAME);
        let fingerprints = match std::fs::read_to_string(&path) {
            Ok(text) => text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(canonical)
                .collect(),
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    log::warn!("could not read {}: {e}", path.display());
                }
                BTreeSet::new()
            }
        };
        Self { path, fingerprints }
    }

    /// The devices removed from the cache: in `granted`, what the store
    /// would write there now, listed before, and not in `file`, what the
    /// file lists now. Nothing when the file has no such table, as a file
    /// replaced wholesale has not; that is not a removal of one device.
    pub fn removed(
        &self,
        granted: &HashMap<String, String>,
        file: Option<&HashMap<String, String>>,
    ) -> Vec<String> {
        let Some(file) = file else {
            return Vec::new();
        };
        let in_file: BTreeSet<String> = file.keys().map(|fp| canonical(fp)).collect();
        let mut gone: Vec<String> = granted
            .keys()
            .map(|fp| canonical(fp))
            .filter(|fp| self.fingerprints.contains(fp) && !in_file.contains(fp))
            .collect();
        gone.sort();
        gone
    }

    /// Record that the cache lists `listed` and nothing else, or, when
    /// `keep` is set, keep what is recorded already as well: while the trust store on disk may still trust a device
    /// forgotten in memory, that device must stay recorded, or at the next
    /// start the file's lack of it no longer reads as a removal. Saves when
    /// that changes what is recorded.
    pub fn record_keeping(
        &mut self,
        listed: impl IntoIterator<Item = String>,
        keep: bool,
    ) -> io::Result<()> {
        let mut next: BTreeSet<String> = listed.into_iter().map(|fp| canonical(&fp)).collect();
        if keep {
            next.extend(self.fingerprints.iter().cloned());
        }
        self.save(next)
    }

    /// Stop recording each of `fingerprints`, whose lines a save by this
    /// daemon dropped from the file: its lack of them is not a removal.
    pub fn unrecord(&mut self, fingerprints: impl IntoIterator<Item = String>) -> io::Result<()> {
        let dropped: BTreeSet<String> = fingerprints.into_iter().map(|fp| canonical(&fp)).collect();
        let next = self.fingerprints.difference(&dropped).cloned().collect();
        self.save(next)
    }

    /// Record `next`, saving it when that changes what is recorded.
    fn save(&mut self, next: BTreeSet<String>) -> io::Result<()> {
        if next == self.fingerprints {
            return Ok(());
        }
        let mut text = String::new();
        for fp in &next {
            text.push_str(fp);
            text.push('\n');
        }
        crate::config::write_atomically(&self.path, text.as_bytes())?;
        self.fingerprints = next;
        Ok(())
    }
}

/// Of `removed`, found by one read of the file, those a second read, `again`,
/// taken once the file has settled, does not list either. Nothing when the
/// second read has no table or could not be made: two reads that do not
/// agree remove nothing.
pub fn confirmed(removed: Vec<String>, again: Option<&HashMap<String, String>>) -> Vec<String> {
    let Some(again) = again else {
        return Vec::new();
    };
    let listed: BTreeSet<String> = again.keys().map(|fp| canonical(fp)).collect();
    removed
        .into_iter()
        .filter(|fp| !listed.contains(&canonical(fp)))
        .collect()
}

/// A device forgotten because the cache no longer lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forgotten {
    /// How a notice names it.
    pub name: String,
    /// It held no pairing here, only a listing to be paired again, left by
    /// an older build's list (#231).
    pub to_pair_again: bool,
}

/// What the app is told of `forgotten`, the devices forgotten because the
/// cache no longer lists them. A pairing removed is told as one; a machine
/// only listed to be paired again had no pairing to remove (#231).
pub fn notice(forgotten: &[Forgotten]) -> String {
    let names = |to_pair_again: bool| -> Vec<&str> {
        forgotten
            .iter()
            .filter(|f| f.to_pair_again == to_pair_again)
            .map(|f| f.name.as_str())
            .collect()
    };
    let mut told = Vec::new();
    match names(false).as_slice() {
        [] => {}
        [one] => told.push(format!(
            "{one} was removed from the trusted devices in config.toml, by hand or by an \
             older version of hops, so its pairing is removed here too."
        )),
        many => told.push(format!(
            "{} were removed from the trusted devices in config.toml, by hand or by an \
             older version of hops, so their pairings are removed here too.",
            many.join(", ")
        )),
    }
    match names(true).as_slice() {
        [] => {}
        [one] => told.push(format!(
            "{one} was removed from the list an older version of hops wrote in \
             config.toml, by hand or by that version, so it is no longer shown here as \
             one to pair again."
        )),
        many => told.push(format!(
            "{} were removed from the list an older version of hops wrote in \
             config.toml, by hand or by that version, so they are no longer shown here \
             as ones to pair again.",
            many.join(", ")
        )),
    }
    told.push(if forgotten.len() == 1 {
        "To use it again, pair the two machines again.".to_string()
    } else {
        "To use one again, pair the two machines again.".to_string()
    });
    told.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESK: &str = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:\
11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";
    const LAPTOP: &str = "aa:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:\
11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";

    fn table(fps: &[&str]) -> HashMap<String, String> {
        fps.iter().map(|fp| (fp.to_string(), "x".into())).collect()
    }

    // LEDGER T2263 | class B | 1 return value of Listed::removed
    #[test]
    fn only_a_device_listed_before_and_gone_now_was_removed() {
        let dir = std::env::temp_dir().join(format!("hops-listed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let mut listed = Listed::read(&dir);
        let granted = table(&[DESK, LAPTOP]);
        let never = listed.removed(&granted, Some(&table(&[DESK])));
        listed
            .record_keeping([DESK.to_uppercase(), LAPTOP.to_string()], false)
            .expect("recorded");
        let listed = Listed::read(&dir);
        let gone = listed.removed(&granted, Some(&table(&[DESK])));
        let no_table = listed.removed(&granted, None);
        let added = listed.removed(&table(&[DESK]), Some(&table(&[DESK, LAPTOP])));
        // The laptop's right to drive this machine is taken away and saved,
        // then given back by a pairing, which does not save the cache.
        let mut listed = listed;
        listed
            .record_keeping([DESK.to_string()], false)
            .expect("recorded");
        let regained = Listed::read(&dir).removed(&granted, Some(&table(&[DESK])));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            (never, gone, no_table, added, regained),
            (vec![], vec![LAPTOP.to_string()], vec![], vec![], vec![]),
            "(never listed, listed then deleted, no table, a line added, dropped \
             from the cache by a save and granted again since)"
        );
    }

    // LEDGER T2270 | class B | 1 return value of confirmed
    #[test]
    fn a_removal_stands_only_when_a_second_read_agrees() {
        let found = || vec![LAPTOP.to_string()];
        let back = confirmed(found(), Some(&table(&[DESK, &LAPTOP.to_uppercase()])));
        let unreadable = confirmed(found(), None);
        let agreed = confirmed(found(), Some(&table(&[DESK])));
        assert_eq!(
            (back, unreadable, agreed),
            (vec![], vec![], vec![LAPTOP.to_string()]),
            "(the second read lists it again, the second read failed, the second \
             read agrees it is gone)"
        );
    }

    // LEDGER T2271 | class B | 4 file content on disk via Listed::read
    #[test]
    fn what_is_recorded_only_grows_while_asked_to_keep_it() {
        let dir = std::env::temp_dir().join(format!("hops-listed-keep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let granted = table(&[DESK, LAPTOP]);
        let mut listed = Listed::read(&dir);
        listed
            .record_keeping([DESK.to_string(), LAPTOP.to_string()], false)
            .expect("recorded");
        listed
            .record_keeping([DESK.to_string()], true)
            .expect("recorded");
        let kept = Listed::read(&dir).removed(&granted, Some(&table(&[DESK])));
        listed
            .record_keeping([DESK.to_string()], false)
            .expect("recorded");
        let replaced = Listed::read(&dir).removed(&granted, Some(&table(&[DESK])));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            (kept, replaced),
            (vec![LAPTOP.to_string()], vec![]),
            "(the laptop, recorded while kept, reads as removed; once replaced it \
             does not)"
        );
    }
}

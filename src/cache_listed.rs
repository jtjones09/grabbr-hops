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

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};

/// The file, beside `config.toml`, naming each device the cache has listed.
pub const FILE_NAME: &str = "authorized_fingerprints.listed";

/// The devices the `[authorized_fingerprints]` cache has listed.
#[derive(Debug)]
pub struct Listed {
    path: PathBuf,
    fingerprints: BTreeSet<String>,
}

/// A fingerprint as the store keys it.
fn canonical(fp: &str) -> String {
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

    /// Record that the cache lists `listed` and nothing else. Saves when
    /// that changes what is recorded.
    pub fn record(&mut self, listed: impl IntoIterator<Item = String>) -> io::Result<()> {
        let next: BTreeSet<String> = listed.into_iter().map(|fp| canonical(&fp)).collect();
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

/// What the app is told of devices forgotten because the cache no longer
/// lists them, named as `names`.
pub fn notice(names: &[String]) -> String {
    let (who, its) = match names {
        [one] => (format!("{one} was"), "its pairing is"),
        _ => (format!("{} were", names.join(", ")), "their pairings are"),
    };
    format!(
        "{who} removed from the trusted devices in config.toml, by hand or by an older \
         version of hops, so {its} removed here too. To use it again, pair the two \
         machines again."
    )
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
            .record([DESK.to_uppercase(), LAPTOP.to_string()])
            .expect("recorded");
        let listed = Listed::read(&dir);
        let gone = listed.removed(&granted, Some(&table(&[DESK])));
        let no_table = listed.removed(&granted, None);
        let added = listed.removed(&table(&[DESK]), Some(&table(&[DESK, LAPTOP])));
        // The laptop's right to drive this machine is taken away and saved,
        // then given back by a pairing, which does not save the cache.
        let mut listed = listed;
        listed.record([DESK.to_string()]).expect("recorded");
        let regained = Listed::read(&dir).removed(&granted, Some(&table(&[DESK])));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            (never, gone, no_table, added, regained),
            (vec![], vec![LAPTOP.to_string()], vec![], vec![], vec![]),
            "(never listed, listed then deleted, no table, a line added, dropped \
             from the cache by a save and granted again since)"
        );
    }
}

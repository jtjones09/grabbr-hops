//! Saving the config without losing what hops did not change (#7).
//!
//! The daemon holds the config in memory, and a save used to write that
//! memory over the file. Everything else in the file went with it: an edit
//! made by hand that the daemon had not read back yet (on Windows, where the
//! watcher does not report edits (#5), every such edit), keys this build does
//! not know, and every comment.
//!
//! A save now reads the file first and changes in it only what the daemon
//! changed since it last read or wrote it:
//!
//! * `[authorized_fingerprints]` and `[revoked_fingerprints]` are a cache of
//!   the trust store, which the daemon owns outright. Rewritten when they
//!   differ from it, left as they are, comments included, when they do not.
//! * `[[clients]]`: the entries the daemon created or removed, and in an entry
//!   it changed, the fields it changed. Every other field, key and comment in
//!   the entry is kept, and so is every other entry.
//! * Everything else is the file's.
//!
//! A save never writes a hook the file does not hold: `enter_hook` is set by
//! editing the file, and only there (#56). It is never written into an entry
//! the file has, and an entry written again from memory carries it only if
//! the entry it replaces held it. (With no file on disk at all, memory is
//! written whole.)
//!
//! A file whose devices a save cannot edit without losing some of them is
//! left as it is, and the save fails.

use std::collections::HashMap;

use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, Value};

use super::{ConfigClient, ConfigToml, TomlClient};

#[derive(Debug, thiserror::Error)]
pub(super) enum MergeError {
    #[error("it does not parse: {0}")]
    Syntax(#[from] toml_edit::TomlError),
    #[error("it does not parse: {0}")]
    Content(#[from] toml_edit::de::Error),
    #[error("the config in memory could not be written out: {0}")]
    Render(#[from] toml_edit::ser::Error),
    #[error(
        "its devices are not written as [[clients]] tables, and a save cannot \
         change them without losing some; write each device as a [[clients]] table"
    )]
    Shape,
}

/// The text to save: `disk` with the daemon's changes since `base` applied.
///
/// `base` is the `[[clients]]` list as the daemon last read it from or wrote
/// it to the file, and `ours` the config it holds now. A `disk` that does not
/// parse is an error, and nothing is to be written: whatever broke it is
/// someone's edit in progress.
pub(super) fn merge(
    disk: &str,
    base: &[ConfigClient],
    ours: &ConfigToml,
) -> Result<String, MergeError> {
    let mut doc: DocumentMut = disk.parse()?;
    let theirs: ConfigToml = toml_edit::de::from_document(doc.clone())?;
    // The daemon's own rendering, which new items are taken from.
    let fresh: DocumentMut = toml_edit::ser::to_string_pretty(ours)?.parse()?;

    if !same_map(
        &theirs.authorized_fingerprints,
        &ours.authorized_fingerprints,
    ) {
        replace(&mut doc, &fresh, "authorized_fingerprints");
    }
    if !same_map(&theirs.revoked_fingerprints, &ours.revoked_fingerprints) {
        replace(&mut doc, &fresh, "revoked_fingerprints");
    }

    let fresh_entries: Vec<Table> = fresh
        .get("clients")
        .and_then(Item::as_array_of_tables)
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default();
    merge_clients(
        &mut doc,
        base,
        &entries(&ours.clients),
        &entries(&theirs.clients),
        &fresh_entries,
    )?;
    Ok(doc.to_string())
}

fn entries(clients: &Option<Vec<TomlClient>>) -> Vec<ConfigClient> {
    clients
        .iter()
        .flatten()
        .cloned()
        .map(ConfigClient::from)
        .collect()
}

fn same_map<V: PartialEq>(a: &Option<HashMap<String, V>>, b: &Option<HashMap<String, V>>) -> bool {
    let empty = HashMap::new();
    a.as_ref().unwrap_or(&empty) == b.as_ref().unwrap_or(&empty)
}

/// Apply to the file's `[[clients]]` what the daemon did to its list since
/// `base`. `fresh[i]` is `ours[i]` as the daemon renders it.
fn merge_clients(
    doc: &mut DocumentMut,
    base: &[ConfigClient],
    ours: &[ConfigClient],
    theirs: &[ConfigClient],
    fresh: &[Table],
) -> Result<(), MergeError> {
    let kept = pair(base, ours, Against::Memory);
    let on_disk = pair(base, theirs, Against::File);
    let mut claimed = vec![false; ours.len()];
    let mut edits = vec![];
    let mut removed = vec![];
    for (b, o) in kept.iter().enumerate() {
        match (o, on_disk[b]) {
            (Some(o), t) => {
                claimed[*o] = true;
                if base[b] != ours[*o] {
                    // An entry gone from the file was removed there: leave it gone.
                    if let Some(t) = t {
                        edits.push((t, *o, b));
                    }
                }
            }
            (None, Some(t)) => removed.push(t),
            (None, None) => {}
        }
    }
    let created: Vec<usize> = (0..ours.len()).filter(|&o| !claimed[o]).collect();
    if edits.is_empty() && removed.is_empty() && created.is_empty() {
        return Ok(());
    }
    // Every index below is one into `theirs`, read from this array.
    let (file, above) = clients_of(doc)?;
    for (t, o, b) in edits {
        if let (Some(entry), Some(new)) = (file.get_mut(t), fresh.get(o)) {
            change_fields(entry, &base[b], &ours[o], new);
        }
    }
    // The hooks of the entries this save removes: the only ones an entry it
    // writes may carry. A device not recognised is removed and written again.
    let mut hooks: Vec<&String> = removed
        .iter()
        .filter_map(|&t| theirs.get(t)?.enter_hook.as_ref())
        .collect();
    removed.sort_unstable();
    for t in removed.into_iter().rev() {
        if t < file.len() {
            file.remove(t);
        }
    }
    for o in created {
        if let Some(Item::Table(mut new)) = fresh.get(o).map(|t| detached(&Item::Table(t.clone())))
        {
            let held = ours[o]
                .enter_hook
                .as_ref()
                .and_then(|h| hooks.iter().position(|k| *k == h));
            match held {
                Some(i) => {
                    hooks.swap_remove(i);
                }
                None => {
                    new.remove("enter_hook");
                }
            }
            file.push(new);
        }
    }
    // A list written inline had the comment above it on its key, which is
    // gone: it goes above the first entry. With none left, it goes with them.
    if let (Some(above), Some(first)) = (above, file.get_mut(0)) {
        let own = first
            .decor()
            .prefix()
            .and_then(|p| p.as_str())
            .unwrap_or("");
        let prefix = format!("{above}{own}");
        first.decor_mut().set_prefix(prefix);
    }
    Ok(())
}

/// The file's `[[clients]]`, made one if it is missing or written inline,
/// and the comment above a list that was written inline.
///
/// Refused when that would lose entries: a device can also be written as an
/// array of its fields in order, which has no table to edit.
fn clients_of(doc: &mut DocumentMut) -> Result<(&mut ArrayOfTables, Option<String>), MergeError> {
    let table = doc.as_table_mut();
    let inline = table
        .get("clients")
        .is_some_and(|item| !item.is_array_of_tables());
    let mut above = None;
    if inline {
        above = comment_above(table, "clients");
        // `clients = [ { .. } ]`, or `clients = []`
        let item = table.remove("clients").unwrap_or_default();
        let entries = match item.into_array_of_tables() {
            Ok(entries) => entries,
            Err(Item::Value(Value::Array(a))) if a.is_empty() => ArrayOfTables::new(),
            Err(_) => return Err(MergeError::Shape),
        };
        table.insert("clients", Item::ArrayOfTables(entries));
    }
    let file = table
        .entry("clients")
        .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or(MergeError::Shape)?;
    Ok((file, above))
}

/// The comment on the lines above `key` in `table`, which toml_edit keeps
/// on the key and drops with it.
fn comment_above(table: &Table, key: &str) -> Option<String> {
    let prefix = table.key(key)?.leaf_decor().prefix()?.as_str()?;
    prefix.contains('#').then(|| prefix.to_string())
}

/// Write into `entry` the fields the daemon changed between `base` and
/// `ours`, as `fresh` renders them, and nothing else.
fn change_fields(entry: &mut Table, base: &ConfigClient, ours: &ConfigClient, fresh: &Table) {
    // Every field named, so a field added to `ConfigClient` does not compile
    // until it is placed here.
    let ConfigClient {
        ips,
        hostname,
        port,
        pos,
        active,
        // the file's alone (#56)
        enter_hook: _,
        fingerprint,
    } = base;
    let changed = [
        ("hostname", *hostname != ours.hostname),
        ("ips", *ips != ours.ips),
        ("port", *port != ours.port),
        ("position", *pos != ours.pos),
        ("activate_on_startup", *active != ours.active),
        ("fingerprint", *fingerprint != ours.fingerprint),
    ];
    for (key, _) in changed.iter().filter(|(_, changed)| *changed) {
        match fresh.get(key) {
            // the default, which the daemon writes by leaving the key out
            None => {
                entry.remove(key);
            }
            Some(new) => {
                let mut new = new.clone();
                // keep a comment written after the old value
                if let (Some(old), Some(value)) =
                    (entry.get(key).and_then(Item::as_value), new.as_value_mut())
                {
                    *value.decor_mut() = old.decor().clone();
                }
                // In place: `insert` over a key clears the key's decor, which
                // holds a comment written on the line above it.
                match entry.get_mut(key) {
                    Some(slot) => *slot = new,
                    None => {
                        entry.insert(key, new);
                    }
                }
            }
        }
    }
}

/// Put the daemon's rendering of `key` in place of the file's.
fn replace(doc: &mut DocumentMut, fresh: &DocumentMut, key: &str) {
    let Some(new) = fresh.get(key) else {
        doc.remove(key);
        return;
    };
    let mut new = detached(new);
    if let Item::Table(table) = &mut new {
        match doc.get(key) {
            // where the old table was, with the comment above it
            Some(Item::Table(old)) => {
                if let Some(at) = old.position() {
                    place(table, at);
                }
                *table.decor_mut() = old.decor().clone();
            }
            // written inline, with the comment above it on its key
            Some(_) => {
                if let Some(above) = comment_above(doc.as_table(), key) {
                    table.decor_mut().set_prefix(above);
                }
            }
            None => {}
        }
    }
    doc.insert(key, new);
}

/// `item` with no table in it tied to a place in the document it came from.
fn detached(item: &Item) -> Item {
    match item {
        Item::Table(t) => {
            let mut out = Table::new();
            out.set_implicit(t.is_implicit());
            for (k, v) in t.iter() {
                out.insert(k, detached(v));
            }
            Item::Table(out)
        }
        Item::ArrayOfTables(a) => {
            let mut out = ArrayOfTables::new();
            for t in a.iter() {
                if let Item::Table(t) = detached(&Item::Table(t.clone())) {
                    out.push(t);
                }
            }
            Item::ArrayOfTables(out)
        }
        other => other.clone(),
    }
}

/// Render `table` and every table in it at document position `at`.
fn place(table: &mut Table, at: usize) {
    table.set_position(at);
    for (_, v) in table.iter_mut() {
        if let Item::Table(t) = v {
            place(t, at);
        }
    }
}

/// Whose list [`pair`] matches the daemon's last read or write against.
#[derive(Clone, Copy, PartialEq)]
enum Against {
    Memory,
    File,
}

/// For each entry of `left`, the entry of `right` that is the same device.
///
/// The file carries no id per entry, so a device is recognised by what it
/// holds: an unchanged entry by being equal, a changed one by its pin, its
/// hostname or its addresses, in that order. Two entries pinned to different
/// machines are never the same device.
///
/// Against memory, the one entry left on each side after that is the same
/// device if they differ in a single field, which is what one change by the
/// daemon does: a rename of a device known by nothing else. A pin on the
/// left missing on the right is not counted: memory forgets a pin with every
/// new name or address, until the next handshake learns it.
///
/// Against the file, nothing left over is paired: an entry changed by hand
/// past recognition cannot be told from a device removed and another added,
/// and a change to one device, its pin above all, must never land on
/// another's entry. Anything left over is a device removed on one side and
/// another added on the other, so no field of one lands on the other.
fn pair(left: &[ConfigClient], right: &[ConfigClient], against: Against) -> Vec<Option<usize>> {
    fn apart(a: &ConfigClient, b: &ConfigClient) -> bool {
        matches!((&a.fingerprint, &b.fingerprint), (Some(x), Some(y)) if x != y)
    }
    fn differences(a: &ConfigClient, b: &ConfigClient) -> usize {
        // Every field named, as in `change_fields`.
        let ConfigClient {
            ips,
            hostname,
            port,
            pos,
            active,
            enter_hook,
            fingerprint,
        } = a;
        [
            *hostname != b.hostname,
            *ips != b.ips,
            *port != b.port,
            *pos != b.pos,
            *active != b.active,
            *enter_hook != b.enter_hook,
            b.fingerprint.is_some() && *fingerprint != b.fingerprint,
        ]
        .into_iter()
        .filter(|&d| d)
        .count()
    }
    let tests: [fn(&ConfigClient, &ConfigClient) -> bool; 4] = [
        |a, b| a == b,
        |a, b| a.fingerprint.is_some() && a.fingerprint == b.fingerprint,
        |a, b| a.hostname.is_some() && a.hostname == b.hostname && !apart(a, b),
        |a, b| !a.ips.is_empty() && a.ips == b.ips && a.port == b.port && !apart(a, b),
    ];
    let mut out = vec![None; left.len()];
    let mut taken = vec![false; right.len()];
    for same in tests {
        for (l, a) in left.iter().enumerate() {
            if out[l].is_some() {
                continue;
            }
            if let Some(r) = (0..right.len()).find(|&r| !taken[r] && same(a, &right[r])) {
                out[l] = Some(r);
                taken[r] = true;
            }
        }
    }
    if against == Against::File {
        return out;
    }
    let left_over: Vec<usize> = (0..left.len()).filter(|&l| out[l].is_none()).collect();
    let right_over: Vec<usize> = (0..right.len()).filter(|&r| !taken[r]).collect();
    if let ([l], [r]) = (left_over.as_slice(), right_over.as_slice()) {
        if differences(&left[*l], &right[*r]) == 1 && !apart(&left[*l], &right[*r]) {
            out[*l] = Some(*r);
        }
    }
    out
}

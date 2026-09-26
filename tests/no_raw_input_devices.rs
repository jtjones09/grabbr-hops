//! hops reads no raw input device, and nothing it ships tells anyone to open
//! one or to join the group that can (#75).
//!
//! On Linux `/dev/input/event*` is `root:input 0660`, so membership of `input`
//! is read access to every keyboard on the machine for anything running as
//! that account, granted once and in practice never revoked. Capture here goes
//! through the portal (xdg-desktop-portal InputCapture / libei), which asks
//! and can be withdrawn, and emulation goes through the display server. The
//! project once told users to join the group anyway, for a capability no code
//! used.
//!
//! The guard before this one was two greps in check.yml. One read the
//! installer, later a list of file extensions that left out `.rs`, so the
//! instruction could ship inside the binary; the other read two of the crates.
//! Each was scoped to where a defect had been found rather than to the
//! property. This one reads every tracked file outside a `tests` directory,
//! so a file added later is covered without editing it, and skips none for
//! its encoding: only an image or a font is not read, and a file it cannot
//! decode fails it.
//!
//! A source scan on purpose: the property is text that ships or instructs, and
//! there is no runtime behaviour to observe. It does not scan itself, because
//! `tests` directories do not ship and are skipped.
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Text that names a raw input device, or the call that grabs one.
const RAW_DEVICE: &[&str] = &[
    "/dev/input",
    "/dev/uinput",
    "/dev/hidraw",
    "eviocgrab",
    "evdev::",
];

/// Words that put an account or a service in a group, or load a kernel module:
/// the commands, a systemd unit's `SupplementaryGroups=`, a NixOS user's
/// `extraGroups`, and a container's `--group-add`.
const GRANTS: &[&str] = &[
    "usermod",
    "gpasswd",
    "adduser",
    "addgroup",
    "useradd",
    "modprobe",
    "supplementarygroups",
    "extragroups",
    "--group-add",
];

/// The groups, and the module, that open raw input devices to an account.
const INPUT_GROUPS: &[&str] = &["input", "uinput"];

/// Lines that name a raw input device or the input group only to say hops
/// does not use either, each as (path, the line with surrounding whitespace
/// removed). Matched exactly, so rewording one brings it back here to be read
/// again.
const STATES_THE_PROHIBITION: &[(&str, &str)] = &[
    (
        ".github/workflows/check.yml",
        "# themselves to the input group, granting system-wide keylogging, on a",
    ),
    (".github/workflows/check.yml", "name: no /dev/input access"),
    (
        "AGENTS.md",
        "- **No raw input devices.** hops must not open `/dev/input` or `/dev/uinput`, and the",
    ),
    (
        "AGENTS.md",
        "installer must never tell users to join the `input` group — that grants system-wide",
    ),
    (
        "AGENTS.md",
        "keylogging for a capability hops does not have. Enforced by the `no /dev/input access` CI",
    ),
    (
        "AGENTS.md",
        "`no /dev/input access` guard. `release.yml` runs on `v*` tags and by hand (a run by hand",
    ),
    (
        "install.sh",
        "# Deliberately NO \"add yourself to the input group\" instruction here.",
    ),
    (
        "install.sh",
        "# /dev/input/event* is root:input 0660, so that group grants read access to",
    ),
    (
        "install.sh",
        "# and no hops code opens /dev/input or /dev/uinput. Enforced by CI, see",
    ),
    (
        "service/hops-headless.service",
        "# There is no /dev/uinput backend in this codebase, so on a box with no display",
    ),
    (
        "service/hops-headless.service",
        "# Do NOT add yourself to the `input` group for this. Earlier revisions of this",
    ),
    (
        "service/hops-headless.service",
        "# file said to; it grants read access to every /dev/input/event* — system-wide",
    ),
];

/// Why `line` would grant or use raw input access, or `None`.
fn offence(line: &str) -> Option<&'static str> {
    let l = line.to_ascii_lowercase();
    if RAW_DEVICE.iter().any(|n| l.contains(n)) {
        return Some("names a raw input device");
    }
    // `-` is part of a word, so `input-capture` is not the group `input`.
    let words: Vec<&str> = l
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .filter(|w| !w.is_empty())
        .collect();
    let group = |w: &&str| INPUT_GROUPS.contains(w);
    // `usermod -aGinput`: a short option with its group glued on.
    let glued = |w: &&str| {
        w.starts_with('-')
            && !w.starts_with("--")
            && w.split_once('g')
                .is_some_and(|(_, g)| INPUT_GROUPS.contains(&g))
    };
    if words.iter().any(|w| GRANTS.contains(w)) && words.iter().any(|w| group(w) || glued(w)) {
        return Some("adds an account to an input group or loads uinput");
    }
    // Prose: "join the `input` group", "the group input".
    if words.windows(2).any(|p| {
        (group(&p[0]) && matches!(p[1], "group" | "groups")) || (p[0] == "group" && group(&p[1]))
    }) {
        return Some("names the input group");
    }
    // systemd `Group=input`, udev `GROUP="input"`.
    let squashed: String = l
        .chars()
        .filter(|c| !(c.is_whitespace() || matches!(c, '"' | '\'' | '`')))
        .collect();
    if squashed.contains("group=input") || squashed.contains("group=uinput") {
        return Some("runs something as an input group");
    }
    if (l.contains("kernel==") || l.contains("subsystem==")) && l.contains("input") {
        return Some("is a udev rule on input devices");
    }
    None
}

/// Every tracked file, relative to the top of the checkout, `/`-separated.
fn tracked() -> Vec<String> {
    let mut git = Command::new("git");
    // A hook, or a caller in another repository, can point git at a different
    // repository or index through the environment.
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy().into_owned();
        if key.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("GIT_")) {
            git.env_remove(key);
        }
    }
    let out = git
        .args(["-c", "safe.directory=*", "-C"])
        .arg(repo())
        .args(["ls-files", "-z"])
        .output()
        .expect("this guard lists the files it reads with `git ls-files`; git must run");
    assert!(
        out.status.success(),
        "git ls-files failed, so nothing was checked: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("tracked paths are UTF-8")
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Extensions of the tracked files that are not text. A file with a NUL byte
/// and any other extension fails the guard instead of being skipped.
const BINARY: &[&str] = &["png", "ttf", "otf", "ico", "icns", "jpg", "jpeg"];

/// The text of `bytes`, the contents of the tracked file `rel`, decoded the way
/// an editor or a shell would read it; `Ok(None)` for an image or a font.
///
/// A file is never skipped for its encoding: UTF-16 with a byte-order mark is
/// what Windows PowerShell's `>` writes, and a stray Latin-1 byte does not
/// stop a shell running the rest of a script, so both are read. A NUL byte in
/// a file that is not a known binary is an error, not a reason to look away.
fn text_of(rel: &str, bytes: &[u8]) -> Result<Option<String>, &'static str> {
    let utf16 = |bytes: &[u8], unit: fn([u8; 2]) -> u16| -> String {
        char::decode_utf16(bytes.as_chunks::<2>().0.iter().map(|&p| unit(p)))
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    };
    let text = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        utf16(rest, u16::from_le_bytes)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        utf16(rest, u16::from_be_bytes)
    } else {
        let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        String::from_utf8_lossy(rest).into_owned()
    };
    if !text.contains('\0') {
        return Ok(Some(text));
    }
    let ext = Path::new(rel).extension().and_then(|e| e.to_str());
    if ext.is_some_and(|e| BINARY.contains(&e.to_ascii_lowercase().as_str())) {
        return Ok(None);
    }
    Err(
        "has a NUL byte and no UTF-16 byte-order mark, so it cannot be read as text; \
         if it is binary, add its extension to BINARY",
    )
}

/// The characters that carry a command on to the next line in `rel`: a
/// shell's `\` anywhere, PowerShell's backtick and cmd's `^`.
fn continuations(rel: &str) -> &'static [char] {
    let ext = Path::new(rel).extension().and_then(|e| e.to_str());
    match ext.map(str::to_ascii_lowercase).as_deref() {
        Some("ps1" | "psm1" | "psd1") => &['\\', '`'],
        Some("cmd" | "bat") => &['\\', '^'],
        _ => &['\\'],
    }
}

/// Every offending line in `text`, the contents of `rel`, as (line number,
/// trimmed line, why). A line continued onto the next is read joined to it,
/// so a command cannot be split to get past the scan.
fn offences(rel: &str, text: &str) -> Vec<(usize, String, &'static str)> {
    let more = continuations(rel);
    let mut found = Vec::new();
    let mut joined = String::new();
    let mut first = 0;
    for (i, line) in text.lines().enumerate() {
        if joined.is_empty() {
            first = i + 1;
        }
        let line = line.trim_end();
        match line.strip_suffix(more) {
            Some(head) => {
                joined.push_str(head);
                joined.push(' ');
            }
            None => {
                joined.push_str(line);
                if let Some(why) = offence(&joined) {
                    found.push((first, joined.trim().to_owned(), why));
                }
                joined.clear();
            }
        }
    }
    if let Some(why) = offence(&joined) {
        found.push((first, joined.trim().to_owned(), why));
    }
    found
}

/// What reading one tracked file found.
#[derive(Default)]
struct Scan {
    /// Read as text, rather than skipped as an image or a font.
    read: bool,
    /// Each offending line that is not allowed, or why the file is unreadable.
    found: Vec<String>,
    /// Each line STATES_THE_PROHIBITION allowed.
    allowed: Vec<String>,
}

/// Reads the tracked file `rel`, whose contents are `bytes`.
fn scan(rel: &str, bytes: &[u8]) -> Scan {
    let mut got = Scan::default();
    let text = match text_of(rel, bytes) {
        Ok(Some(text)) => text,
        Ok(None) => return got,
        Err(why) => {
            got.found.push(format!("{rel}: {why}"));
            return got;
        }
    };
    got.read = true;
    for (n, line, why) in offences(rel, &text) {
        if STATES_THE_PROHIBITION.contains(&(rel, line.as_str())) {
            got.allowed.push(line);
        } else {
            got.found.push(format!("{rel}:{n}: {why}: {line}"));
        }
    }
    got
}

// LEDGER T13 | class S | every tracked file's text | pair NONE (shipped text)
#[test]
fn nothing_shipped_opens_a_raw_input_device_or_tells_anyone_to() {
    let files = tracked();
    for must in [
        "install.sh",
        "README.md",
        "service/README.md",
        "service/hops-headless.service",
        "src/main.rs",
        ".github/workflows/check.yml",
    ] {
        assert!(
            files.iter().any(|f| f == must),
            "{must} is not in the tracked files, so this guard is not reading the checkout"
        );
    }

    let mut read = 0;
    let mut found = Vec::new();
    let mut allowed = Vec::new();
    for rel in &files {
        if rel.split('/').any(|part| part == "tests") {
            continue;
        }
        let bytes = match std::fs::read(repo().join(rel)) {
            Ok(bytes) => bytes,
            // Deleted in the work tree and not yet staged.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                found.push(format!("{rel}: could not be read: {e}"));
                continue;
            }
        };
        let got = scan(rel, &bytes);
        read += usize::from(got.read);
        found.extend(got.found);
        allowed.extend(got.allowed.into_iter().map(|line| (rel.clone(), line)));
    }
    assert!(read > 100, "read only {read} files");
    assert!(
        found.is_empty(),
        "hops must not read raw input devices, and nothing it ships may tell anyone to \
         open one or join the group that can: that is read access to every keyboard on \
         the machine, for a capability hops does not have. A line that only states the \
         prohibition goes in STATES_THE_PROHIBITION. A deliberate, privileged backend \
         changes this test and the security model in the same PR.\n{}",
        found.join("\n")
    );
    for (rel, line) in STATES_THE_PROHIBITION {
        assert!(
            allowed.iter().any(|(r, l)| r == rel && l == line),
            "STATES_THE_PROHIBITION allows a line {rel} no longer has: {line}"
        );
    }
}

// LEDGER T14 | class S | the scan T13 relies on, over inline text | pair T13
#[test]
fn the_scan_recognises_each_way_of_granting_raw_input() {
    for line in [
        "sudo usermod -aG input \"$USER\"",
        "sudo usermod -a -G input $USER",
        "usermod --append --groups input me",
        "sudo gpasswd -a $USER input",
        "sudo adduser $USER input",
        "sudo useradd -G uinput hops",
        "sudo modprobe uinput",
        "KERNEL==\"uinput\", MODE=\"0660\", GROUP=\"input\"",
        "SUBSYSTEM==\"input\", MODE=\"0666\"",
        "sudo chmod 0666 /dev/uinput",
        "let f = File::open(\"/dev/input/event0\")?;",
        "ioctl(fd, EVIOCGRAB, 1);",
        "use evdev::Device;",
        "SupplementaryGroups=input",
        "Group=input",
        "users.users.me.extraGroups = [ \"wheel\" \"input\" ];",
        "docker run --group-add input hops",
        "sudo usermod -aGinput \"$USER\"",
        "sudo useradd -Guinput hops",
        "First add your account to the `input` group and log in again.",
        "open(\"/dev/hidraw0\")",
    ] {
        assert!(offence(line).is_some(), "not caught: {line}");
    }
    // A command continued onto the next line is read as one, and reported at
    // the line it starts on.
    for (rel, text) in [
        (
            "scripts/setup.sh",
            "echo ok\nsudo usermod -aG \\\n  input \"$USER\"\n",
        ),
        (
            "scripts/setup.ps1",
            "echo ok\r\n# usermod -aG `\r\n#   input me\r\n",
        ),
        (
            "scripts/setup.cmd",
            "echo ok\r\nrem usermod -aG ^\r\nrem   input me\r\n",
        ),
    ] {
        let found = offences(rel, text);
        assert!(
            matches!(found.as_slice(), [(2, ..)]),
            "a continued line in {rel} was not caught at line 2: {found:?}"
        );
    }
    for line in [
        "input-capture reads events from the portal",
        "Caps / Num / Scroll Lock (evdev codes)",
        "the user adds a device in the input settings",
    ] {
        assert_eq!(offence(line), None, "caught, but grants nothing: {line}");
    }
}

// LEDGER T16 | class S | how T13 decodes a file, over inline bytes | pair T13
#[test]
fn the_scan_reads_every_encoding_a_tracked_file_can_have() {
    let plant = "# Linux peers: sudo usermod -aG input $USER";
    let utf16 = |bom: [u8; 2], unit: fn(u16) -> [u8; 2]| -> Vec<u8> {
        let units: Vec<u16> = format!("{plant}\r\n").encode_utf16().collect();
        bom.into_iter()
            .chain(units.into_iter().flat_map(unit))
            .collect()
    };
    let latin1 = [b"Caf\xe9\n".as_slice(), plant.as_bytes()].concat();
    let utf8_bom = [b"\xEF\xBB\xBF".as_slice(), plant.as_bytes()].concat();
    let ps1 = "service/windows/hops-ctl.ps1";
    for (what, rel, bytes) in [
        ("a Latin-1 byte", "service/README.md", latin1),
        ("UTF-16LE", ps1, utf16([0xFF, 0xFE], u16::to_le_bytes)),
        ("UTF-16BE", ps1, utf16([0xFE, 0xFF], u16::to_be_bytes)),
        ("a UTF-8 byte-order mark", "scripts/setup.sh", utf8_bom),
    ] {
        let got = scan(rel, &bytes);
        assert!(
            got.found.iter().any(|f| f.ends_with(plant)),
            "{what}: the planted line in {rel} was not caught: {:?}",
            got.found
        );
    }

    // UTF-16 with no byte-order mark, or a NUL in any file that is not an
    // image or a font, fails the guard rather than being skipped.
    let bare: Vec<u8> = plant.encode_utf16().flat_map(u16::to_le_bytes).collect();
    for (what, rel, bytes) in [
        ("UTF-16 with no mark", ps1, bare.as_slice()),
        ("a NUL in Markdown", "README.md", b"# hops\0\n".as_slice()),
        (
            "a NUL under an image's name",
            "docs/x.png.md",
            b"\x89PNG\0".as_slice(),
        ),
    ] {
        let got = scan(rel, bytes);
        assert!(
            !got.found.is_empty(),
            "{what}: {rel} was skipped, not reported"
        );
    }
    let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
    for rel in ["screenshots/hops-gui.png", "fonts/x.TTF"] {
        let got = scan(rel, png);
        assert!(
            !got.read && got.found.is_empty(),
            "{rel} is binary and is skipped"
        );
    }
}

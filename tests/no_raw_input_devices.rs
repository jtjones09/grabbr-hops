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
//! so a file added later is covered without editing it.
//!
//! A source scan on purpose: the property is text that ships or instructs, and
//! there is no runtime behaviour to observe. It does not scan itself, because
//! `tests` directories do not ship and are skipped.
use std::path::PathBuf;
use std::process::Command;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Text that names a raw input device, or the call that grabs one.
const RAW_DEVICE: &[&str] = &["/dev/input", "/dev/uinput", "eviocgrab", "evdev::"];

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
    if words.iter().any(|w| GRANTS.contains(w)) && words.iter().any(group) {
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

/// Every offending line in `text`, as (line number, trimmed line, why).
fn offences(text: &str) -> Vec<(usize, &str, &'static str)> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| offence(line).map(|why| (i + 1, line.trim(), why)))
        .collect()
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
        let Ok(bytes) = std::fs::read(repo().join(rel)) else {
            continue; // deleted in the work tree and not yet staged
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue; // an image or another binary
        };
        read += 1;
        for (n, line, why) in offences(&text) {
            if STATES_THE_PROHIBITION.contains(&(rel.as_str(), line)) {
                allowed.push((rel.clone(), line.to_owned()));
            } else {
                found.push(format!("{rel}:{n}: {why}: {line}"));
            }
        }
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
        "First add your account to the `input` group and log in again.",
    ] {
        assert!(offence(line).is_some(), "not caught: {line}");
    }
    for line in [
        "input-capture reads events from the portal",
        "Caps / Num / Scroll Lock (evdev codes)",
        "the user adds a device in the input settings",
    ] {
        assert_eq!(offence(line), None, "caught, but grants nothing: {line}");
    }
}

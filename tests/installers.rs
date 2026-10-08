//! The shell scripts that build, sign and install hops, run for real against
//! stand-ins for the tools they drive.
//!
//! Each script runs with a PATH that holds only the stand-ins and a few named
//! system tools, so a tool this file forgot to stand in for is "command not
//! found" rather than the real `launchctl`, `codesign` or `security` of the
//! machine running the tests.
#![cfg(unix)]

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A directory of its own, removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("hops-installers-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The system tools a script may reach, by name, as links in one directory.
fn system_tools(dir: &Path, names: &[&str]) {
    std::fs::create_dir_all(dir).unwrap();
    for name in names {
        let found = ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(name))
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("no {name} in /usr/bin or /bin"));
        symlink(found, dir.join(name)).unwrap();
    }
}

/// A stand-in named `name` in `dir`, running `body` under bash.
fn stand_in(dir: &Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A stand-in that appends its name and arguments, one per `[..]`, to `log`.
fn recorder(dir: &Path, name: &str, log: &Path, then: &str) {
    stand_in(
        dir,
        name,
        &format!(
            "{{ printf '%s' {name}; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; echo; }} >> '{}'\n{then}",
            log.display()
        ),
    );
}

/// Run `script` with only `fakes` and `tools` on PATH.
fn run(script: &Path, args: &[&str], fakes: &Path, tools: &Path, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("/bin/bash");
    cmd.arg(script)
        .args(args)
        .env_clear()
        .env("PATH", format!("{}:{}", fakes.display(), tools.display()));
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("bash runs")
}

fn text(out: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `security find-identity -v -p codesigning` as it prints `identities`
/// (hash, name).
fn find_identity(identities: &[(&str, &str)]) -> String {
    let mut lines: Vec<String> = identities
        .iter()
        .enumerate()
        .map(|(i, (hash, name))| format!("  {}) {hash} \"{name}\"", i + 1))
        .collect();
    lines.push(format!("     {} valid identities found", identities.len()));
    lines.join("\n")
}

const HASH_OTHER_DEV_ID: &str = "1111111111111111111111111111111111111111";
const HASH_APPLE_DEV: &str = "2222222222222222222222222222222222222222";
const OTHER_DEV_ID: &str = "Developer ID Application: Example Maker (EXAMPLE123)";
const APPLE_DEV: &str = "Apple Development: Example Maker (EXAMPLE456)";
const HASH_PROJECT_ID: &str = "3333333333333333333333333333333333333333";
/// The identity the project's releases, and so its users' grants, are bound to.
const PROJECT_ID: &str = "Developer ID Application: Hotash Studios LLC (9V42Q953X9)";

/// What `codesign` was asked to do, one line per call.
fn codesign_calls(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("codesign "))
        .map(str::to_owned)
        .collect()
}

/// Build a bundle with scripts/macos-app-bundle.sh `--sign`, the keychain
/// holding `identities`.
fn bundle(tag: &str, identities: &[(&str, &str)], env: &[(&str, &str)]) -> (Output, Vec<String>) {
    let s = Scratch::new(tag);
    let fakes = s.path().join("fakes");
    let tools = s.path().join("tools");
    let log = s.path().join("calls.log");
    system_tools(
        &tools,
        &["bash", "rm", "mkdir", "cp", "chmod", "cat", "awk", "grep"],
    );
    recorder(&fakes, "codesign", &log, "exit 0");
    recorder(&fakes, "plutil", &log, "exit 0");
    stand_in(
        &fakes,
        "security",
        &format!("cat <<'IDS'\n{}\nIDS", find_identity(identities)),
    );
    let bin = s.path().join("hops");
    std::fs::write(&bin, b"a binary").unwrap();
    let app = s.path().join("hops.app");
    let out = run(
        &repo().join("scripts/macos-app-bundle.sh"),
        &[
            bin.to_str().unwrap(),
            "1.2.3",
            app.to_str().unwrap(),
            "",
            "--sign",
        ],
        &fakes,
        &tools,
        env,
    );
    (out, codesign_calls(&log))
}

// LEDGER T6 | class B | 5 process: scripts/macos-app-bundle.sh --sign, its codesign call
#[test]
fn a_local_bundle_is_signed_with_the_identity_the_keychain_holds_under_the_hops_identifier() {
    // Another maker's Developer ID: the bundle is signed with it. Signing with
    // a hard-coded identity it does not hold fails the build.
    let (out, calls) = bundle(
        "devid",
        &[
            (HASH_APPLE_DEV, APPLE_DEV),
            (HASH_OTHER_DEV_ID, OTHER_DEV_ID),
        ],
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(calls.len(), 1, "one signing, of the bundle: {calls:?}");
    assert!(
        calls[0].contains("[--identifier] [com.grabbr.hops]")
            && calls[0].contains(&format!("[--sign] [{HASH_OTHER_DEV_ID}]")),
        "the bundle must be signed with the Developer ID the keychain holds and \
         the hops identifier, which the macOS grants are bound to: {calls:?}"
    );
    // Whichever certificate is chosen puts its maker's name on the app.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(OTHER_DEV_ID),
        "the identity chosen must be named: {stderr}"
    );

    // The project's own Developer ID, listed after another: the project's.
    // The grants already given are bound to it.
    let (out, calls) = bundle(
        "project",
        &[
            (HASH_OTHER_DEV_ID, OTHER_DEV_ID),
            (HASH_PROJECT_ID, PROJECT_ID),
        ],
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        calls.len() == 1 && calls[0].contains(&format!("[--sign] [{HASH_PROJECT_ID}]")),
        "the project's Developer ID must win over any other the keychain \
         holds: {calls:?}"
    );

    // Only a development certificate: still a stable identity.
    let (out, calls) = bundle("appledev", &[(HASH_APPLE_DEV, APPLE_DEV)], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        calls.len() == 1
            && calls[0].contains("[--identifier] [com.grabbr.hops]")
            && calls[0].contains(&format!("[--sign] [{HASH_APPLE_DEV}]")),
        "{calls:?}"
    );

    // Named in the environment: that one, whatever else the keychain holds.
    let (out, calls) = bundle(
        "named",
        &[(HASH_OTHER_DEV_ID, OTHER_DEV_ID)],
        &[("DEVELOPER_ID", APPLE_DEV)],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        calls.len() == 1 && calls[0].contains(&format!("[--sign] [{APPLE_DEV}]")),
        "{calls:?}"
    );

    // None at all: sealed ad hoc, under the same identifier, and said so.
    let (out, calls) = bundle("adhoc", &[], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        calls.len() == 1
            && calls[0].contains("[--identifier] [com.grabbr.hops]")
            && calls[0].contains("[--sign] [-]"),
        "{calls:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("every rebuild"),
        "an ad hoc signature must say the grants end with every rebuild: {stderr}"
    );
}

/// Run scripts/sign-macos.sh with Gatekeeper answering `app` for the app and
/// `dmg` for the disk image, each (exit status, output).
fn sign(tag: &str, app: (i32, &str), dmg: (i32, &str)) -> (Output, bool) {
    let s = Scratch::new(tag);
    let fakes = s.path().join("fakes");
    let tools = s.path().join("tools");
    let log = s.path().join("calls.log");
    let out_dir = s.path().join("out");
    std::fs::create_dir_all(out_dir.join("hops.app/Contents/MacOS")).unwrap();
    std::fs::write(out_dir.join("hops.app/Contents/MacOS/hops"), b"a binary").unwrap();
    system_tools(
        &tools,
        &[
            "bash", "dirname", "mktemp", "rm", "cp", "ln", "mkdir", "touch",
        ],
    );
    for name in ["codesign", "xcrun", "xattr"] {
        recorder(&fakes, name, &log, "exit 0");
    }
    // `ditto <src> <dst>` copies; `ditto -c -k ... <zip>` archives.
    recorder(
        &fakes,
        "ditto",
        &log,
        "if [ \"$1\" = -c ]; then touch \"${@: -1}\"; else cp -R \"$1\" \"$2\"; fi",
    );
    recorder(&fakes, "hdiutil", &log, "touch \"${@: -1}\"");
    recorder(
        &fakes,
        "spctl",
        &log,
        &format!(
            "case \"$*\" in *execute*) echo '{}'; exit {} ;; *) echo '{}'; exit {} ;; esac",
            app.1, app.0, dmg.1, dmg.0
        ),
    );
    let out = run(
        &repo().join("scripts/sign-macos.sh"),
        &[out_dir.to_str().unwrap()],
        &fakes,
        &tools,
        &[
            ("DEVELOPER_ID", OTHER_DEV_ID),
            ("NOTARY_PROFILE", "a-profile"),
            ("TMPDIR", s.path().to_str().unwrap()),
        ],
    );
    let published = out_dir.join("hops-macos.dmg").exists();
    (out, published)
}

const ACCEPTED: &str = "accepted source=Notarized Developer ID";
const REJECTED: &str = "rejected source=Unnotarized Developer ID";

// LEDGER T5 | class B | 5 process exit code + 4 files published: scripts/sign-macos.sh
#[test]
fn signing_fails_and_publishes_nothing_when_gatekeeper_rejects_what_it_signed() {
    let (out, published) = sign("accepted", (0, ACCEPTED), (0, ACCEPTED));
    assert!(
        out.status.success() && published,
        "with both accepted the script must finish and publish the dmg:\n{}",
        text(&out)
    );

    for (tag, app, dmg) in [
        ("app-rejected", (3, REJECTED), (0, ACCEPTED)),
        ("dmg-rejected", (0, ACCEPTED), (3, REJECTED)),
    ] {
        let (out, published) = sign(tag, app, dmg);
        assert!(
            !out.status.success(),
            "{tag}: Gatekeeper rejected what was signed, and the script succeeded:\n{}",
            text(&out)
        );
        assert!(!published, "{tag}: a dmg Gatekeeper rejected was published");
    }
}

/// The features in the release workflow's build for `os`.
#[cfg(target_os = "linux")]
fn release_features(os: &str) -> BTreeSet<String> {
    let release = std::fs::read_to_string(repo().join(".github/workflows/release.yml")).unwrap();
    let line = release
        .lines()
        .find(|l| l.contains(&format!("os: {os}")) && l.contains("features:"))
        .unwrap_or_else(|| panic!("release.yml has no build for {os}"));
    let rest = &line[line.find("features:").unwrap()..];
    let open = rest.find('"').unwrap() + 1;
    let close = open + rest[open..].find('"').unwrap();
    rest[open..close]
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// The features `cargo build` was given in a recorded call.
#[cfg(target_os = "linux")]
fn features_of(call: &str) -> BTreeSet<String> {
    let at = call
        .find("[--features] [")
        .unwrap_or_else(|| panic!("no --features in {call}"));
    let rest = &call[at + "[--features] [".len()..];
    rest[..rest.find(']').unwrap()]
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// Run the installer in a copy of the checkout, on a system that `uname`
/// calls `system`, with `identities` in the keychain.
///
/// Linux only: the macOS arm is run with every macOS tool stood in for, so
/// nothing of the machine running the tests can be reached; on a Mac, a
/// stand-in this test forgot would find the real one only by PATH, and the
/// PATH here holds none. The check is kept off macOS all the same, so the
/// installer never runs on a machine it could install onto.
#[cfg(target_os = "linux")]
fn install(tag: &str, system: &str, identities: &[(&str, &str)]) -> (Output, String, Scratch) {
    install_in("checkout", tag, system, identities)
}

/// [`install`], from a checkout in a directory named `checkout`.
#[cfg(target_os = "linux")]
fn install_in(
    checkout: &str,
    tag: &str,
    system: &str,
    identities: &[(&str, &str)],
) -> (Output, String, Scratch) {
    install_with(checkout, tag, system, identities, "26")
}

/// [`install_in`], on a macOS whose major version `sw_vers` reports as
/// `macos_major`.
#[cfg(target_os = "linux")]
fn install_with(
    checkout: &str,
    tag: &str,
    system: &str,
    identities: &[(&str, &str)],
    macos_major: &str,
) -> (Output, String, Scratch) {
    let s = Scratch::new(tag);
    let fakes = s.path().join("fakes");
    let tools = s.path().join("tools");
    let log = s.path().join("calls.log");
    let checkout = s.path().join(checkout);
    let home = s.path().join("home");
    std::fs::create_dir_all(checkout.join("scripts")).unwrap();
    std::fs::create_dir_all(checkout.join("resources")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    for file in [
        "install.sh",
        "Cargo.toml",
        "scripts/macos-app-bundle.sh",
        DESKTOP_ENTRY,
    ] {
        std::fs::copy(repo().join(file), checkout.join(file)).unwrap();
    }
    system_tools(
        &tools,
        &[
            "bash", "dirname", "grep", "sed", "mkdir", "cat", "rm", "cp", "chmod", "id", "awk",
        ],
    );
    stand_in(&fakes, "uname", &format!("echo {system}"));
    stand_in(
        &fakes,
        "sw_vers",
        &format!("[ \"$1\" = -productMajorVersion ] && echo {macos_major}"),
    );
    recorder(
        &fakes,
        "cargo",
        &log,
        "mkdir -p target/release && echo 'a binary' > target/release/hops",
    );
    for name in ["launchctl", "open", "systemctl", "codesign", "plutil"] {
        recorder(&fakes, name, &log, "exit 0");
    }
    stand_in(
        &fakes,
        "security",
        &format!("cat <<'IDS'\n{}\nIDS", find_identity(identities)),
    );
    let out = run(
        &checkout.join("install.sh"),
        &[],
        &fakes,
        &tools,
        &[("HOME", home.to_str().unwrap())],
    );
    let calls = std::fs::read_to_string(&log).unwrap_or_default();
    (out, calls, s)
}

/// The desktop entry the portal reads to name hops, as the checkout holds it.
#[cfg(target_os = "linux")]
const DESKTOP_ENTRY: &str = "resources/com.grabbr.hops.desktop";

/// The program a desktop entry's `Exec` value runs, read the way the Desktop
/// Entry spec says and GLib does: the string escapes of the value first,
/// then `%%` as a literal `%`, then the first argument, in which a quoted
/// `\`, `"`, `` ` `` and `$` each take a backslash. None if GLib would not
/// read it as one program.
#[cfg(target_os = "linux")]
fn exec_program(value: &str) -> Option<String> {
    let mut unescaped = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            unescaped.push(c);
            continue;
        }
        unescaped.push(match chars.next()? {
            's' => ' ',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            _ => return None,
        });
    }
    let mut expanded = String::new();
    let mut chars = unescaped.chars();
    while let Some(c) = chars.next() {
        if c == '%' && chars.next()? != '%' {
            return None;
        }
        expanded.push(c);
    }
    let mut chars = expanded.chars();
    if chars.next()? != '"' {
        let word = expanded.split(' ').next()?;
        let plain = !word.contains(['"', '\'', '\\', '`', '$']);
        return plain.then(|| word.to_owned());
    }
    let mut program = String::new();
    loop {
        match chars.next()? {
            '"' => break,
            '`' | '$' => return None,
            '\\' => match chars.next()? {
                c @ ('"' | '`' | '$' | '\\') => program.push(c),
                _ => return None,
            },
            c => program.push(c),
        }
    }
    matches!(chars.next(), None | Some(' ')).then_some(program)
}

// LEDGER T8 | class B | 4 files written: install.sh's desktop entry, and the binary its Exec names
/// The portal names the caller after the desktop entry whose id it registered
/// as, and only when that entry's Exec is a program it can find. The daemon
/// runs from a systemd unit, whose PATH need not hold the checkout, so the
/// entry must name the binary this install built, whatever the checkout's
/// path holds: GLib drops an entry whose Exec it cannot parse, silently.
#[cfg(target_os = "linux")]
#[test]
fn the_linux_installer_installs_the_desktop_entry_the_portal_names_hops_by() {
    for checkout in ["checkout", r#"a "quoted" `odd` $HOME \ 100% checkout"#] {
        let (out, calls, s) = install_in(checkout, "linux-desktop", "Linux", &[]);
        assert!(out.status.success(), "{}\n{calls}", text(&out));
        let installed = s
            .path()
            .join("home/.local/share/applications")
            .join(format!("{}.desktop", input_event::APP_ID));
        let entry = std::fs::read_to_string(&installed).unwrap_or_else(|e| {
            panic!(
                "the installer left no {}: {e}. Without it the portal cannot name \
                 hops, and the consent prompt asks for an unnamed application",
                installed.display()
            )
        });
        let bin = s.path().join(checkout).join("target/release/hops");
        let exec: Vec<&str> = entry.lines().filter(|l| l.starts_with("Exec=")).collect();
        assert_eq!(exec.len(), 1, "one Exec: {exec:?}");
        assert_eq!(
            exec_program(&exec[0]["Exec=".len()..]),
            Some(bin.to_str().unwrap().to_owned()),
            "the installed entry must run the binary this install built: {}",
            exec[0]
        );
        assert!(bin.is_file(), "{} is not there", bin.display());
        let shipped = std::fs::read_to_string(repo().join(DESKTOP_ENTRY)).unwrap();
        let rest = |t: &str| -> Vec<String> {
            t.lines()
                .filter(|l| !l.starts_with("Exec="))
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(rest(&entry), rest(&shipped), "only Exec may differ");
    }
}

// LEDGER T9 | class B | 1 return value: exec_program, the reading T8 relies on
/// The reading of Exec agrees with the spec's own examples.
#[cfg(target_os = "linux")]
#[test]
fn exec_is_read_as_the_desktop_entry_spec_reads_it() {
    assert_eq!(exec_program("hops"), Some("hops".into()));
    assert_eq!(exec_program(r#""/a b/hops""#), Some("/a b/hops".into()));
    // The spec: four backslashes for one, `\\$` for a dollar sign.
    assert_eq!(exec_program(r#""/a\\\\b""#), Some(r"/a\b".into()));
    assert_eq!(exec_program(r#""/a\\$b""#), Some("/a$b".into()));
    assert_eq!(exec_program(r#""/a\\"b""#), Some(r#"/a"b"#.into()));
    assert_eq!(exec_program(r#""/100%%""#), Some("/100%".into()));
    // Unescaped, GLib cannot read them as the path.
    assert_eq!(exec_program(r#""/a$b""#), None);
    assert_eq!(exec_program(r#""/100%""#), None);
    assert_eq!(exec_program(r#""/a\"b""#), None);
    assert_eq!(exec_program(r#""/a"b""#), None);
}

// LEDGER T2 | class B | 5 process: install.sh, the cargo, codesign and launchctl calls it makes
#[cfg(target_os = "linux")]
#[test]
fn the_installer_builds_and_signs_what_the_release_ships() {
    // Linux: the input backends are cargo features, so a build without the
    // release's set can neither capture nor inject.
    let (out, calls, _s) = install("linux", "Linux", &[]);
    assert!(out.status.success(), "{}\n{calls}", text(&out));
    let builds: Vec<&str> = calls.lines().filter(|l| l.starts_with("cargo ")).collect();
    assert_eq!(builds.len(), 1, "{calls}");
    assert_eq!(
        features_of(builds[0]),
        release_features("ubuntu-latest"),
        "the installer's Linux build is not the Linux release's"
    );
    assert!(calls.contains("systemctl [--user] [enable]"), "{calls}");

    // macOS, with a Developer ID in the keychain: the app is signed with it,
    // under the identifier the Accessibility grant is bound to. An ad hoc
    // signature is a new identity with every rebuild.
    let (out, calls, s) = install("macos", "Darwin", &[(HASH_OTHER_DEV_ID, OTHER_DEV_ID)]);
    assert!(out.status.success(), "{}\n{calls}", text(&out));
    let builds: Vec<&str> = calls.lines().filter(|l| l.starts_with("cargo ")).collect();
    assert_eq!(builds.len(), 1, "{calls}");
    assert_eq!(
        features_of(builds[0]),
        release_features("macos-latest"),
        "the installer's macOS build is not the macOS release's"
    );
    let signs: Vec<&str> = calls
        .lines()
        .filter(|l| l.starts_with("codesign "))
        .collect();
    assert!(
        !signs.is_empty()
            && signs
                .iter()
                .all(|c| c.contains("[--identifier] [com.grabbr.hops]")
                    && c.contains(&format!("[--sign] [{HASH_OTHER_DEV_ID}]"))),
        "with a Developer ID at hand, every signing must use it and the hops \
         identifier: {signs:?}"
    );
    assert!(calls.contains("launchctl [bootstrap]"), "{calls}");

    // launchd creates each job's output file with its own umask; the
    // installer creates them first, readable by this user alone, in the
    // directory hops itself logs to on macOS, and sends each job's output
    // there.
    let home = s.path().join("home");
    let logs = home.join("Library/Logs/hops");
    for (label, log) in [
        ("com.grabbr.hops", "daemon.log"),
        ("com.grabbr.hops.gui", "gui.log"),
    ] {
        let path = logs.join(log);
        let mode = std::fs::metadata(&path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or_else(|e| panic!("the installer left no {}: {e}", path.display()));
        assert_eq!(mode, 0o600, "the installer left {log} {mode:o}");
        let plist =
            std::fs::read_to_string(home.join(format!("Library/LaunchAgents/{label}.plist")))
                .unwrap_or_else(|e| panic!("the installer wrote no {label} plist: {e}"));
        for key in ["StandardOutPath", "StandardErrorPath"] {
            assert!(
                plist.contains(&format!(
                    "<key>{key}</key><string>{}</string>",
                    path.display()
                )),
                "{label} does not send its {key} to {}: {plist}",
                path.display()
            );
        }
    }
    assert!(
        !home.join("hops").exists(),
        "the installer created ~/hops, which hops no longer writes to"
    );
}

/// The installer names the System Settings list that lets hops move the
/// pointer as the Mac it runs on names it: macOS 27 renamed Accessibility.
// LEDGER T7 | class B | 5 process stdout: the installer, with sw_vers stood in
#[cfg(target_os = "linux")]
#[test]
fn the_installer_names_the_list_as_this_macos_does() {
    for (major, pane, not) in [
        ("26", "Accessibility ", "Device Control"),
        ("27", "Device Control and Data Access", "Accessibility "),
    ] {
        let (out, _calls, _s) =
            install_with("checkout", &format!("macos-{major}"), "Darwin", &[], major);
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{}", text(&out));
        let line = said
            .lines()
            .find(|l| l.contains("to move the cursor"))
            .unwrap_or_else(|| panic!("macOS {major}: no line names the list:\n{said}"));
        assert!(
            line.contains(pane) && !line.contains(not),
            "macOS {major} must be told to look under {pane:?}: {line:?}"
        );
    }
}

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
    let s = Scratch::new(tag);
    let fakes = s.path().join("fakes");
    let tools = s.path().join("tools");
    let log = s.path().join("calls.log");
    let checkout = s.path().join("checkout");
    let home = s.path().join("home");
    std::fs::create_dir_all(checkout.join("scripts")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    for file in ["install.sh", "Cargo.toml", "scripts/macos-app-bundle.sh"] {
        std::fs::copy(repo().join(file), checkout.join(file)).unwrap();
    }
    system_tools(
        &tools,
        &[
            "bash", "dirname", "grep", "sed", "mkdir", "cat", "rm", "cp", "chmod", "id", "awk",
        ],
    );
    stand_in(&fakes, "uname", &format!("echo {system}"));
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
    let (out, calls, _s) = install("macos", "Darwin", &[(HASH_OTHER_DEV_ID, OTHER_DEV_ID)]);
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
}

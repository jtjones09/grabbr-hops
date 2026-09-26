//! The release pipeline, checked from the two ends that can run off GitHub.
//!
//! The gates are shell, and each is run here with the inputs a real run would
//! give it: the step text is taken from the parsed workflow and handed to bash,
//! so what runs is what GitHub runs. What only GitHub interprets — which job a
//! secret reaches, which job may write, what an action reference resolves to —
//! is read from the parsed workflows instead. Those properties have no local
//! behaviour; a dispatch run on GitHub is their proof.
use std::collections::BTreeSet;
use std::path::PathBuf;

use yaml_rust2::{Yaml, YamlLoader};

const RELEASE: &str = ".github/workflows/release.yml";
/// The one job that signs, and so the one job any secret may reach.
const SIGN: &str = "sign-macos";
/// The one job that publishes, and so the one job that may write.
const PUBLISH: &str = "publish";
/// The artifact the signing job receives: the unsigned universal binary.
const UNSIGNED: &str = "hops-macos-universal";
const DMG: &str = "hops-macos-universal.dmg";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn parse(rel: &str) -> Yaml {
    let mut docs = YamlLoader::load_from_str(&read(rel))
        .unwrap_or_else(|e| panic!("{rel} is not valid YAML: {e}"));
    assert_eq!(docs.len(), 1, "{rel}: expected one YAML document");
    docs.remove(0)
}

/// Every workflow, as (path, text, parsed).
fn workflows() -> Vec<(String, String, Yaml)> {
    let dir = repo().join(".github/workflows");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect(".github/workflows") {
        let path = entry.expect("dir entry").path();
        let ext = path.extension().and_then(|e| e.to_str());
        if matches!(ext, Some("yml" | "yaml")) {
            let rel = format!(
                ".github/workflows/{}",
                path.file_name().unwrap().to_string_lossy()
            );
            out.push((rel.clone(), read(&rel), parse(&rel)));
        }
    }
    assert!(out.len() >= 2, "found only {} workflows", out.len());
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn jobs(wf: &Yaml) -> Vec<(String, &Yaml)> {
    wf["jobs"]
        .as_hash()
        .expect("a workflow has jobs")
        .iter()
        .map(|(k, v)| (k.as_str().expect("job id").to_owned(), v))
        .collect()
}

fn steps(job: &Yaml) -> &[Yaml] {
    job["steps"].as_vec().map(Vec::as_slice).unwrap_or(&[])
}

/// The text inside every `${{ }}` in `s`. An expression left open runs to the
/// end of the string.
fn expressions(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find("${{") {
        let inner = &rest[i + 3..];
        let end = inner.find("}}").unwrap_or(inner.len());
        out.push(&inner[..end]);
        rest = &inner[end..];
    }
    out
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Every use of the `secrets` context in `y`: the name, upper-cased as GitHub
/// matches it, for `secrets.NAME` and `secrets['NAME']`, and `*` for any use
/// that can reach every secret: `toJSON(secrets)`, a computed index, or a
/// `secrets:` key, which hands secrets to a called workflow (`inherit`).
fn secret_refs(y: &Yaml) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    walk_secret_refs(y, &mut refs);
    refs
}

fn walk_secret_refs(y: &Yaml, refs: &mut BTreeSet<String>) {
    match y {
        Yaml::String(s) => {
            for e in expressions(s) {
                for (i, _) in e.match_indices("secrets") {
                    let after = &e[i + "secrets".len()..];
                    if e[..i].chars().next_back().is_some_and(is_ident)
                        || after.chars().next().is_some_and(is_ident)
                    {
                        continue;
                    }
                    let after = after.trim_start();
                    let name = if let Some(r) = after.strip_prefix('.') {
                        r.trim_start()
                            .chars()
                            .take_while(|c| is_ident(*c))
                            .collect()
                    } else if let Some(r) = after.strip_prefix('[') {
                        r.trim_start()
                            .strip_prefix('\'')
                            .and_then(|r| r.split_once('\''))
                            .filter(|(_, tail)| tail.trim_start().starts_with(']'))
                            .map(|(n, _)| n.to_owned())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    refs.insert(if name.is_empty() {
                        "*".to_owned()
                    } else {
                        name.to_ascii_uppercase()
                    });
                }
            }
        }
        Yaml::Array(a) => a.iter().for_each(|v| walk_secret_refs(v, refs)),
        Yaml::Hash(h) => h.iter().for_each(|(k, v)| {
            if k.as_str() == Some("secrets") {
                refs.insert("*".to_owned());
            }
            walk_secret_refs(k, refs);
            walk_secret_refs(v, refs);
        }),
        _ => {}
    }
}

fn mentions_secret(y: &Yaml) -> bool {
    !secret_refs(y).is_empty()
}

fn uses(step: &Yaml) -> &str {
    step["uses"].as_str().unwrap_or("")
}

fn step_named<'a>(job: &'a Yaml, job_id: &str, name: &str) -> &'a Yaml {
    steps(job)
        .iter()
        .find(|s| s["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("job {job_id} has no step named {name:?}"))
}

// ---------------------------------------------------------------------------
// Behaviour: the gates' shell, run with the inputs a run would give it. Unix
// only: these steps run on Linux and macOS runners, under bash.
// ---------------------------------------------------------------------------
#[cfg(unix)]
mod gates {
    use super::*;
    use std::path::Path;

    /// The shell a step runs. Expressions reach a script only through `env:`, so
    /// the text run here is exactly the text GitHub runs.
    fn step_script(job: &str, step: &str) -> String {
        let wf = parse(RELEASE);
        let job_yaml = &wf["jobs"][job];
        assert!(!job_yaml.is_badvalue(), "release.yml has no job {job}");
        let run = step_named(job_yaml, job, step)["run"]
            .as_str()
            .unwrap_or_else(|| panic!("{job}/{step:?} runs no shell"))
            .to_owned();
        assert!(
            !run.contains("${{"),
            "{job}/{step:?} interpolates an expression into its shell; pass it through env: \
         so the script is fixed text"
        );
        run
    }

    /// A directory removed when the test ends.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("hops-release-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    struct Ran {
        ok: bool,
        text: String,
    }

    /// Run `script` the way a step with no `shell:` runs on a Linux or macOS
    /// runner (`bash -e {0}`), in `cwd`, with only `env` and PATH set.
    fn bash(script: &str, file_dir: &Path, cwd: &Path, env: &[(&str, &str)]) -> Ran {
        let file = file_dir.join("step.sh");
        std::fs::write(&file, script).expect("write step");
        let out = std::process::Command::new("bash")
            .args(["--noprofile", "--norc", "-e"])
            .arg(&file)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(env.iter().copied())
            .output()
            .expect("bash runs");
        Ran {
            ok: out.status.success(),
            text: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }

    // LEDGER T1 | class B | 5 process exit code: release.yml version-matches-tag step
    #[test]
    fn a_branch_build_passes_the_version_gate_and_a_wrong_tag_does_not() {
        let script = step_script("version-matches-tag", "a tag must equal the crate version");
        let s = scratch("version");
        let version = env!("CARGO_PKG_VERSION");
        let run = |r: &str| bash(&script, &s.0, &repo(), &[("GITHUB_REF", r)]);

        let branch = run("refs/heads/main");
        assert!(
            branch.ok,
            "a dispatch from a branch publishes nothing and must still build, but the \
         version gate failed it:\n{}",
            branch.text
        );

        let tag = format!("refs/tags/v{version}");
        let matching = run(&tag);
        assert!(matching.ok, "{tag} matches the crate:\n{}", matching.text);

        let wrong = run("refs/tags/v0.0.0-not-this-crate");
        assert!(
            !wrong.ok,
            "a tag that disagrees with the crate version was accepted:\n{}",
            wrong.text
        );
    }

    // LEDGER T2 | class B | 5 process exit code: release.yml sign-macos presence step
    #[test]
    fn signing_without_every_secret_fails() {
        const STEP: &str = "every signing secret is set";
        let script = step_script(SIGN, STEP);
        let wf = parse(RELEASE);
        let names: Vec<String> = step_named(&wf["jobs"][SIGN], SIGN, STEP)["env"]
            .as_hash()
            .expect("the presence check receives each secret's presence through env:")
            .keys()
            .map(|k| k.as_str().expect("env name").to_owned())
            .collect();
        assert!(names.len() >= 6, "only {names:?} are checked");
        let s = scratch("secrets");

        let all: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "true")).collect();
        let set = bash(&script, &s.0, &s.0, &all);
        assert!(
            set.ok,
            "every secret set, yet the check failed:\n{}",
            set.text
        );

        for missing in &names {
            let env: Vec<(&str, &str)> = names
                .iter()
                .map(|n| (n.as_str(), if n == missing { "false" } else { "true" }))
                .collect();
            let ran = bash(&script, &s.0, &s.0, &env);
            assert!(
                !ran.ok,
                "{missing} is not set and the signing job carried on; a run without it \
             produces no signed dmg:\n{}",
                ran.text
            );
            assert!(
                ran.text.contains(missing.as_str()),
                "the failure does not name {missing}:\n{}",
                ran.text
            );
        }
    }

    // LEDGER T3 | class B | 5 process exit code: release.yml publish asset step
    #[test]
    fn a_release_is_published_with_every_asset_or_not_at_all() {
        let script = step_script(PUBLISH, "the release is exactly its four assets");
        const ASSETS: [&str; 4] = [
            DMG,
            "hops-macos-universal.tar.gz",
            "hops-windows-x86_64.zip",
            "hops-linux-x86_64.tar.gz",
        ];
        let s = scratch("assets");
        let stage = |present: &[&str], empty: &[&str], extra: &[&str]| {
            let dir = s.0.join("artifacts");
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            for f in present.iter().chain(extra) {
                std::fs::write(dir.join(f), b"bytes").unwrap();
            }
            for f in empty {
                std::fs::write(dir.join(f), b"").unwrap();
            }
            bash(&script, &s.0, &s.0, &[])
        };

        let complete = stage(&ASSETS, &[], &[]);
        assert!(complete.ok, "all four assets present:\n{}", complete.text);

        let no_dmg = stage(&ASSETS[1..], &[], &[]);
        assert!(
            !no_dmg.ok,
            "a release with no dmg would have been published:\n{}",
            no_dmg.text
        );
        assert!(
            no_dmg.text.contains(DMG),
            "the failure does not name the dmg:\n{}",
            no_dmg.text
        );

        let empty_dmg = stage(&ASSETS[1..], &[DMG], &[]);
        assert!(!empty_dmg.ok, "an empty dmg passed:\n{}", empty_dmg.text);

        // The unsigned dmg, and names that are part of a listed name: matching
        // a whole line, not a substring, is what refuses the last two.
        for name in ["hops-macos-unsigned.dmg", "hops", "hops-macos-universal"] {
            let extra = stage(&ASSETS, &[], &[name]);
            assert!(
                !extra.ok,
                "{name}, which nobody listed, would have been published:\n{}",
                extra.text
            );
        }
    }

    /// Stand-ins for the macOS tools the verify script calls, each answering the
    /// way the real one was measured to: `spctl` and `stapler` on a notarized app
    /// and on an unsigned dmg, `codesign -dv` on a bundle signed by
    /// scripts/sign-macos.sh's commands, and `codesign --verify --strict` on a
    /// bundle whose sealed resources were changed after signing.
    struct Tools {
        spctl_dmg: (i32, &'static str),
        spctl_app: (i32, &'static str),
        stapler_dmg: i32,
        stapler_app: i32,
        /// Exit status of `codesign --verify --strict` on the app.
        verify_app: i32,
        identifier: &'static str,
    }

    const NOTARIZED: (i32, &str) = (
        0,
        "accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Example (EXAMPLE123)",
    );
    /// What `spctl --assess` answers for anything once assessments are disabled.
    const ASSESSMENTS_OFF: (i32, &str) = (0, "accepted\noverride=security disabled");
    const REJECTED: (i32, &str) = (3, "rejected\nsource=no usable signature");
    const SIGNED_ONLY: (i32, &str) = (
        0,
        "accepted\nsource=Developer ID\norigin=Developer ID Application: Example (EXAMPLE123)",
    );

    impl Tools {
        fn release() -> Self {
            Tools {
                spctl_dmg: NOTARIZED,
                spctl_app: NOTARIZED,
                stapler_dmg: 0,
                stapler_app: 0,
                verify_app: 0,
                identifier: "com.grabbr.hops",
            }
        }

        fn install(&self, bin: &Path) {
            use std::os::unix::fs::PermissionsExt;
            let write = |name: &str, body: String| {
                let p = bin.join(name);
                std::fs::write(&p, format!("#!/usr/bin/env bash\n{body}")).unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            };
            write(
                "spctl",
                format!(
                    r#"for a; do target="$a"; done
case "$target" in
  *.dmg) printf '%s: %s\n' "$target" "$(printf '{}')" >&2; exit {} ;;
  *) printf '%s: %s\n' "$target" "$(printf '{}')" >&2; exit {} ;;
esac
"#,
                    self.spctl_dmg.1.replace('\n', "\\n"),
                    self.spctl_dmg.0,
                    self.spctl_app.1.replace('\n', "\\n"),
                    self.spctl_app.0
                ),
            );
            write(
                "xcrun",
                format!(
                    r#"[ "$1 $2" = "stapler validate" ] || exit 64
echo "Processing: $3"
case "$3" in
  *.dmg) code={} ;;
  *) code={} ;;
esac
[ "$code" = 0 ] && echo "The validate action worked!" || echo "$(basename "$3") does not have a ticket stapled to it."
exit "$code"
"#,
                    self.stapler_dmg, self.stapler_app
                ),
            );
            write(
                "codesign",
                format!(
                    r#"for a; do target="$a"; done
case "$1" in
  -dv|--display) printf 'Executable=%s/Contents/MacOS/hops\nIdentifier={}\nFormat=app bundle with Mach-O universal (x86_64 arm64)\n' "$target" >&2 ;;
  --verify)
    [ "$2" = --strict ] || exit 64
    [ {verify} = 0 ] || {{ printf '%s: a sealed resource is missing or invalid\n' "$target" >&2; exit {verify}; }} ;;
  *) exit 64 ;;
esac
"#,
                    self.identifier,
                    verify = self.verify_app
                ),
            );
            write(
                "hdiutil",
                r#"case "$1" in
  attach)
    while [ $# -gt 0 ]; do [ "$1" = -mountpoint ] && mnt="$2"; shift; done
    mkdir -p "$mnt/hops.app/Contents/MacOS" ;;
  detach) for a; do mnt="$a"; done; rm -rf "$mnt/hops.app" ;;
  *) exit 64 ;;
esac
"#
                .to_owned(),
            );
        }
    }

    fn verify(tools: &Tools, dmg_bytes: Option<&[u8]>) -> Ran {
        let s = scratch("verify");
        let bin = s.0.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        tools.install(&bin);
        let dmg = s.0.join(DMG);
        if let Some(b) = dmg_bytes {
            std::fs::write(&dmg, b).unwrap();
        }
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = std::process::Command::new("bash")
            .arg(repo().join("scripts/verify-macos-release.sh"))
            .arg(&dmg)
            .current_dir(&s.0)
            .env_clear()
            .env("PATH", path)
            .env("TMPDIR", &s.0)
            .output()
            .expect("bash runs");
        Ran {
            ok: out.status.success(),
            text: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }

    // LEDGER T4 | class B | 5 process exit code: scripts/verify-macos-release.sh
    #[test]
    fn only_a_notarized_stapled_dmg_passes_verification() {
        let image: &[u8] = b"not empty";
        let empty: &[u8] = b"";
        let good = verify(&Tools::release(), Some(image));
        assert!(
            good.ok,
            "a notarized, stapled release failed:\n{}",
            good.text
        );

        let cases: [(&str, Tools, Option<&[u8]>); 10] = [
            ("there is no dmg", Tools::release(), None),
            ("the dmg is empty", Tools::release(), Some(empty)),
            (
                "Gatekeeper rejects the dmg",
                Tools {
                    spctl_dmg: REJECTED,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "assessments are disabled, so the dmg's `accepted` proves nothing",
                Tools {
                    spctl_dmg: ASSESSMENTS_OFF,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "the dmg is signed but not notarized",
                Tools {
                    spctl_dmg: SIGNED_ONLY,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "no ticket is stapled to the dmg",
                Tools {
                    stapler_dmg: 65,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "assessments are disabled, so the app's `accepted` proves nothing",
                Tools {
                    spctl_app: ASSESSMENTS_OFF,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "no ticket is stapled to the app",
                Tools {
                    stapler_app: 65,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "the app's signature does not verify under --strict",
                Tools {
                    verify_app: 1,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "the app is signed under another identifier, which voids the Accessibility grant",
                Tools {
                    identifier: "hops",
                    ..Tools::release()
                },
                Some(image),
            ),
        ];
        for (why, tools, bytes) in cases {
            let ran = verify(&tools, bytes);
            assert!(!ran.ok, "verification passed although {why}:\n{}", ran.text);
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration only GitHub interprets, read from the parsed workflows.
// ---------------------------------------------------------------------------

// LEDGER T5 | class S | parsed workflow YAML
#[test]
fn only_the_environment_scoped_signing_job_can_read_a_secret() {
    for (rel, _, wf) in workflows() {
        assert!(
            !mentions_secret(&wf["env"]),
            "{rel}: a workflow-level env hands a secret to every step of every job"
        );
        for (id, job) in jobs(&wf) {
            assert!(
                !mentions_secret(&job["env"]),
                "{rel}: job {id} puts a secret in its job-level env, where every step \
                 — and every build script cargo runs — can read it"
            );
            if !mentions_secret(job) {
                continue;
            }
            assert!(
                rel == RELEASE && id == SIGN,
                "{rel}: job {id} references {:?}; only {SIGN} in {RELEASE} may",
                secret_refs(job)
            );
            assert!(
                job["environment"].as_str().is_some_and(|e| !e.is_empty()),
                "{rel}: {id} reads secrets but names no environment to scope them"
            );
        }
    }

    // The presence check sees whether each secret is set, never its value,
    // and covers every secret the job uses.
    let wf = parse(RELEASE);
    let sign = &wf["jobs"][SIGN];
    let check = step_named(sign, SIGN, "every signing secret is set")["env"]
        .as_hash()
        .expect("presence check env");
    let mut checked = BTreeSet::new();
    for (k, v) in check {
        let (k, v) = (k.as_str().unwrap(), v.as_str().unwrap_or(""));
        assert_eq!(
            v.split_whitespace().collect::<String>(),
            format!("${{{{secrets.{k}!=''}}}}"),
            "the presence check must receive `secrets.{k} != ''`, not the secret"
        );
        checked.insert(k.to_owned());
    }
    assert_eq!(
        secret_refs(sign),
        checked,
        "every secret {SIGN} uses is checked for presence before it is used"
    );
}

// LEDGER T6 | class S | parsed workflow YAML
#[test]
fn the_signing_job_builds_nothing_and_skips_nothing() {
    let wf = parse(RELEASE);
    let sign = &wf["jobs"][SIGN];
    assert!(!sign.is_badvalue(), "release.yml has no {SIGN} job");
    for step in steps(sign) {
        let name = step["name"].as_str().unwrap_or(uses(step));
        let run = step["run"].as_str().unwrap_or("");
        assert!(
            !run.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .any(|w| w == "cargo"),
            "{SIGN} step {name:?} runs cargo in the job that holds the signing secrets"
        );
        assert!(
            !uses(step).contains("rust-toolchain") && !uses(step).contains("rust-cache"),
            "{SIGN} step {name:?} sets up Rust in the job that holds the signing secrets"
        );
        assert!(
            step["if"].is_badvalue(),
            "{SIGN} step {name:?} is conditional; a skipped signing step is a release \
             with no dmg"
        );
        if uses(step).starts_with("actions/download-artifact@") {
            assert_eq!(
                step["with"]["name"].as_str(),
                Some(UNSIGNED),
                "{SIGN} receives the unsigned binary and nothing else"
            );
        }
    }
    assert_eq!(
        sign["needs"].as_str(),
        Some("build"),
        "{SIGN} signs what build produced"
    );
}

/// `permissions` that grant nothing beyond read.
fn read_only(p: &Yaml) -> bool {
    match p {
        Yaml::Hash(h) => h
            .values()
            .all(|v| matches!(v.as_str(), Some("read" | "none"))),
        _ => false,
    }
}

// LEDGER T7 | class S | parsed workflow YAML
#[test]
fn only_the_publish_job_may_write() {
    for (rel, _, wf) in workflows() {
        assert!(
            read_only(&wf["permissions"]),
            "{rel}: the workflow must set `permissions:` to read-only; without it every \
             job gets the repository default, which may be write"
        );
        for (id, job) in jobs(&wf) {
            let p = &job["permissions"];
            if p.is_badvalue() || read_only(p) {
                continue;
            }
            assert!(
                rel == RELEASE && id == PUBLISH,
                "{rel}: job {id} may write; only {PUBLISH} in {RELEASE} may"
            );
        }
    }
    let wf = parse(RELEASE);
    let publish = &wf["jobs"][PUBLISH]["permissions"];
    let grants: Vec<(String, String)> = publish
        .as_hash()
        .expect("publish sets its own permissions")
        .iter()
        .map(|(k, v)| (k.as_str().unwrap().into(), v.as_str().unwrap_or("").into()))
        .collect();
    assert_eq!(
        grants,
        vec![("contents".to_owned(), "write".to_owned())],
        "publish writes release assets and nothing else"
    );
}

fn is_commit(r: &str) -> bool {
    r.len() == 40
        && r.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// The one reference still allowed to name a branch: the toolchain action at
/// exactly the compiler rust-toolchain.toml pins. `chore::toolchain_pin` in
/// src/lib.rs reads the version from this ref, so pinning it to a commit
/// changes that guard, and that is a separate decision. Nothing else is exempt.
fn toolchain_branch(uses: &str) -> bool {
    let channel = read("rust-toolchain.toml")
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .find_map(|l| {
            let v = l.trim().strip_prefix("channel")?.trim().strip_prefix('=')?;
            Some(v.trim().trim_matches('"').to_owned())
        })
        .expect("rust-toolchain.toml sets channel");
    uses == format!("dtolnay/rust-toolchain@{channel}")
}

// LEDGER T8 | class S | raw workflow text + parsed workflow YAML
#[test]
fn every_action_is_pinned_to_a_commit() {
    for (rel, text, wf) in workflows() {
        let mut parsed = Vec::new();
        for (id, job) in jobs(&wf) {
            if let Some(u) = job["uses"].as_str() {
                parsed.push((id.clone(), u.to_owned()));
            }
            for step in steps(job) {
                if let Some(u) = step["uses"].as_str() {
                    parsed.push((id.clone(), u.to_owned()));
                }
            }
        }
        for (id, u) in &parsed {
            if u.starts_with("./") || toolchain_branch(u) {
                continue;
            }
            let (_, r) = u
                .rsplit_once('@')
                .unwrap_or_else(|| panic!("{rel}: {id} uses {u} with no ref"));
            assert!(
                is_commit(r),
                "{rel}: {id} uses {u}; a tag or branch can be moved to other code \
                 after review, a commit cannot"
            );
        }

        // Comments are not in the parsed tree, so the tag each commit stands for
        // is read from the line itself.
        let mut lines = 0;
        for line in text.lines() {
            let t = line.trim_start();
            let t = t.strip_prefix("- ").unwrap_or(t).trim_start();
            let Some(v) = t.strip_prefix("uses:") else {
                continue;
            };
            lines += 1;
            let (value, comment) = v.split_once('#').unwrap_or((v, ""));
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
            if value.starts_with("./") || toolchain_branch(value) {
                continue;
            }
            assert!(
                !comment.trim().is_empty(),
                "{rel}: `{}` names no tag in a trailing comment; a bare commit cannot \
                 be reviewed or updated",
                line.trim()
            );
            assert!(
                value.rsplit_once('@').is_some_and(|(_, r)| is_commit(r)),
                "{rel}: `{}` is not pinned to a commit",
                line.trim()
            );
        }
        assert_eq!(
            lines,
            parsed.len(),
            "{rel}: some `uses:` is not on a line of its own, so its tag comment went unchecked"
        );
    }
}

// LEDGER T9 | class S | parsed workflow YAML
#[test]
fn no_checkout_keeps_its_credentials() {
    let mut seen = 0;
    for (rel, _, wf) in workflows() {
        for (id, job) in jobs(&wf) {
            for step in steps(job) {
                if !uses(step).starts_with("actions/checkout@") {
                    continue;
                }
                seen += 1;
                assert_eq!(
                    step["with"]["persist-credentials"].as_bool(),
                    Some(false),
                    "{rel}: a checkout in {id} leaves the job token in .git/config, where \
                     every later step, build scripts included, can read it"
                );
            }
        }
    }
    assert!(
        seen > 0,
        "no checkout found; the scan is not reading the workflows"
    );
}

// LEDGER T10 | class S | parsed workflow YAML | pair T1
#[test]
fn a_dispatch_builds_and_signs_and_only_a_tag_push_publishes() {
    let wf = parse(RELEASE);
    assert!(
        !wf["on"]["workflow_dispatch"].is_badvalue(),
        "release.yml can no longer be run by hand"
    );
    // A job whose `if` is false is skipped, and so is every job that needs it.
    // Only publish may be skipped, so a dispatch runs everything else.
    for (id, job) in jobs(&wf) {
        if id != PUBLISH {
            assert!(
                job["if"].is_badvalue(),
                "job {id} has an `if`; on a dispatch it and everything after it is skipped"
            );
        }
    }
    let publish = &wf["jobs"][PUBLISH];
    assert_eq!(
        publish["if"].as_str(),
        Some("github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"),
        "only a pushed version tag publishes; a dispatch never does"
    );
    let needs: BTreeSet<&str> = publish["needs"]
        .as_vec()
        .expect("publish needs a list")
        .iter()
        .filter_map(Yaml::as_str)
        .collect();
    for job in ["version-matches-tag", "build", SIGN] {
        assert!(
            needs.contains(job),
            "publish does not need {job}; a release could go out without it"
        );
    }
}

// LEDGER T11 | class S | parsed workflow YAML | pair T4
#[test]
fn the_signing_job_uploads_only_a_verified_dmg() {
    let wf = parse(RELEASE);
    let sign = steps(&wf["jobs"][SIGN]);
    let pos = |what: &str, f: &dyn Fn(&Yaml) -> bool| {
        sign.iter()
            .position(f)
            .unwrap_or_else(|| panic!("{SIGN} has no step that {what}"))
    };
    let verified = pos("runs the verify script on the dmg", &|s| {
        s["run"].as_str().is_some_and(|r| {
            r.lines()
                .any(|l| l.trim() == format!("scripts/verify-macos-release.sh {DMG}"))
        })
    });
    let uploaded = pos("uploads the dmg", &|s| {
        uses(s).starts_with("actions/upload-artifact@") && s["with"]["path"].as_str() == Some(DMG)
    });
    assert!(
        verified < uploaded,
        "{SIGN} uploads the dmg before verifying it"
    );
    assert_eq!(
        sign[uploaded]["with"]["if-no-files-found"].as_str(),
        Some("error"),
        "a missing dmg must fail the upload, not warn"
    );
}

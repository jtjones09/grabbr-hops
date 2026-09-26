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

const BUILD: &str = "build";
/// The job that checksums and attests every asset, and so the one job that
/// may mint an OIDC token.
const ATTEST: &str = "attest";
/// The artifact attest uploads and publish releases: every asset, attested.
const RELEASE_ARTIFACT: &str = "release";
const SUMS: &str = "SHA256SUMS";
const LICENSE: &str = "LICENSE";
const NOTICES: &str = "THIRD-PARTY-NOTICES.txt";
/// The section `cargo auditable` embeds a binary's dependency list in. Its
/// name is in the binary on every platform hops ships: ELF, Mach-O and PE.
const AUDIT_SECTION: &str = ".dep-v0";

/// Each archive, the binary in it, and every target that binary is compiled
/// for. Each target has its own SBOM: the two macOS slices resolve different
/// dependencies.
const ARCHIVES: [(&str, &str, &[&str]); 3] = [
    (
        "hops-linux-x86_64.tar.gz",
        "hops",
        &["x86_64-unknown-linux-gnu"],
    ),
    (
        "hops-macos-universal.tar.gz",
        "hops",
        &["aarch64-apple-darwin", "x86_64-apple-darwin"],
    ),
    (
        "hops-windows-x86_64.zip",
        "hops.exe",
        &["x86_64-pc-windows-msvc"],
    ),
];
const APPLE_TARGETS: [&str; 2] = ["aarch64-apple-darwin", "x86_64-apple-darwin"];

// Step names, as the workflow spells them.
const TOOLS_STEP: &str = "Install the release tools";
const NOTICES_STEP: &str = "Licence notices and SBOMs";
const PACKAGE_UNIX: &str = "Package (Linux, macOS)";
const PACKAGE_WINDOWS: &str = "Package (Windows)";
const UNPACK_STEP: &str = "Unpack the unsigned build";
const ARCHIVE_GATE: &str = "every archive carries its licence, notices, SBOMs and audit data";
const SUMS_STEP: &str = "SHA256SUMS";
const PUBLISH_GATE: &str = "the release is exactly its assets, each as SHA256SUMS describes it";
const NOTES_STEP: &str = "the release notes name every ignored advisory";
const NOTES_CHECK: &str = "the release notes are present";

/// The SBOM of one target, as the release names it.
fn sbom(target: &str) -> String {
    format!("hops-{target}.cdx.json")
}

/// Every asset a release publishes besides SHA256SUMS.
fn assets() -> Vec<String> {
    let mut out = vec![DMG.to_owned()];
    for (archive, _, targets) in ARCHIVES {
        out.push(archive.to_owned());
        out.extend(targets.iter().map(|t| sbom(t)));
    }
    out.sort();
    out
}

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
                // Context names are case-insensitive: `Secrets.X` reads the
                // same secret as `secrets.X`. ASCII lowercasing keeps offsets.
                let lower = e.to_ascii_lowercase();
                for (i, _) in lower.match_indices("secrets") {
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

fn step_position(job: &Yaml, job_id: &str, name: &str) -> usize {
    steps(job)
        .iter()
        .position(|s| s["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("job {job_id} has no step named {name:?}"))
}

/// The commands a step runs: one a line, with a line ending in `\` joined to
/// the next, each split into words.
fn commands(step: &Yaml) -> Vec<Vec<String>> {
    step["run"]
        .as_str()
        .unwrap_or("")
        .replace("\\\n", " ")
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .map(|l| l.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
        .filter(|words| !words.is_empty())
        .collect()
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

    /// Where a step runs: its `working-directory` under `root`, or `root`.
    fn step_dir(root: &Path, job: &str, step: &str) -> PathBuf {
        let wf = parse(RELEASE);
        match step_named(&wf["jobs"][job], job, step)["working-directory"].as_str() {
            Some(d) => root.join(d),
            None => root.to_path_buf(),
        }
    }

    fn reset(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
    }

    /// Install `body` as an executable named `name` in `dir`.
    fn tool(dir: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/usr/bin/env bash\n{body}")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// `dir` ahead of the test's own PATH.
    fn path_with(dir: &Path) -> String {
        format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        )
    }

    /// Stage every release asset, each with its own bytes, in `dir`, and run
    /// the attest job's SHA256SUMS step over them.
    fn stage_release(s: &Path, dir: &Path, skip: &[&str], empty: &[&str], extra: &[&str]) {
        reset(dir);
        for f in assets()
            .iter()
            .map(String::as_str)
            .chain(extra.iter().copied())
        {
            if skip.contains(&f) {
                continue;
            }
            let bytes = if empty.contains(&f) {
                Vec::new()
            } else {
                format!("the bytes of {f}\n").into_bytes()
            };
            std::fs::write(dir.join(f), bytes).unwrap();
        }
        let tmp = s.join("runner-temp");
        reset(&tmp);
        let sums = bash(
            &step_script(ATTEST, SUMS_STEP),
            s,
            &step_dir(s, ATTEST, SUMS_STEP),
            &[("RUNNER_TEMP", tmp.to_str().unwrap())],
        );
        assert!(sums.ok, "the checksum step failed:\n{}", sums.text);
    }

    // LEDGER T3 | class B | 5 process exit code: release.yml publish asset step
    #[test]
    fn a_release_is_published_with_every_asset_or_not_at_all() {
        let script = step_script(PUBLISH, PUBLISH_GATE);
        let s = scratch("assets");
        let dir = step_dir(&s.0, PUBLISH, PUBLISH_GATE);
        assert_eq!(
            dir,
            step_dir(&s.0, ATTEST, SUMS_STEP),
            "publish checks the directory the checksums were written for"
        );
        let gate = || bash(&script, &s.0, &dir, &[]);

        stage_release(&s.0, &dir, &[], &[], &[]);
        let complete = gate();
        assert!(complete.ok, "every asset present:\n{}", complete.text);

        stage_release(&s.0, &dir, &[DMG], &[], &[]);
        let no_dmg = gate();
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

        stage_release(&s.0, &dir, &[], &[DMG], &[]);
        let empty_dmg = gate();
        assert!(!empty_dmg.ok, "an empty dmg passed:\n{}", empty_dmg.text);

        for (_, _, targets) in ARCHIVES {
            for t in targets {
                let name = sbom(t);
                stage_release(&s.0, &dir, &[&name], &[], &[]);
                let ran = gate();
                assert!(
                    !ran.ok && ran.text.contains(&name),
                    "a release without {name} would have been published:\n{}",
                    ran.text
                );
            }
        }

        stage_release(&s.0, &dir, &[], &[], &[]);
        std::fs::remove_file(dir.join(SUMS)).unwrap();
        let no_sums = gate();
        assert!(
            !no_sums.ok,
            "a release without SHA256SUMS would have been published:\n{}",
            no_sums.text
        );

        // An asset changed after it was checksummed and attested.
        stage_release(&s.0, &dir, &[], &[], &[]);
        let tampered = dir.join(ARCHIVES[0].0);
        let mut bytes = std::fs::read(&tampered).unwrap();
        bytes.push(b'!');
        std::fs::write(&tampered, bytes).unwrap();
        let changed = gate();
        assert!(
            !changed.ok,
            "an asset that no longer matches SHA256SUMS would have been published:\n{}",
            changed.text
        );

        // SHA256SUMS that leaves an asset out.
        stage_release(&s.0, &dir, &[], &[], &[]);
        let sums = std::fs::read_to_string(dir.join(SUMS)).unwrap();
        let fewer: String = sums
            .lines()
            .filter(|l| !l.ends_with(ARCHIVES[0].0))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(fewer, sums, "the test did not remove a line");
        std::fs::write(dir.join(SUMS), fewer).unwrap();
        let unlisted = gate();
        assert!(
            !unlisted.ok && unlisted.text.contains(ARCHIVES[0].0),
            "an asset SHA256SUMS does not name would have been published:\n{}",
            unlisted.text
        );

        // The unsigned dmg, names that are part of a listed name (matching a
        // whole line, not a substring, refuses those), and a dotfile, which
        // `*` alone does not list.
        for name in [
            "hops-macos-unsigned.dmg",
            "hops",
            "hops-macos-universal",
            ".hidden-asset",
        ] {
            stage_release(&s.0, &dir, &[], &[], &[name]);
            let extra = gate();
            assert!(
                !extra.ok,
                "{name}, which nobody listed, would have been published:\n{}",
                extra.text
            );
        }
    }

    // LEDGER T2241 | class B | 5 process exit code + file contents: release.yml attest SHA256SUMS step
    #[test]
    fn the_checksums_name_every_asset_but_themselves() {
        use sha2::{Digest, Sha256};
        let s = scratch("sums");
        let dir = step_dir(&s.0, ATTEST, SUMS_STEP);
        stage_release(&s.0, &dir, &[], &[], &[]);
        let sums = std::fs::read_to_string(dir.join(SUMS)).expect("SHA256SUMS was written");
        let mut named = Vec::new();
        for line in sums.lines() {
            let (hash, name) = line
                .split_once("  ")
                .unwrap_or_else(|| panic!("not a sha256sum line: {line:?}"));
            let bytes = std::fs::read(dir.join(name)).unwrap();
            assert_eq!(
                hash,
                format!("{:x}", Sha256::digest(&bytes)),
                "SHA256SUMS gives {name} a hash that is not its SHA-256"
            );
            named.push(name.to_owned());
        }
        named.sort();
        assert_eq!(
            named,
            assets(),
            "SHA256SUMS must name every other asset once, and not itself"
        );
    }

    fn app_docs() -> Vec<String> {
        let mut docs = vec![LICENSE.to_owned(), NOTICES.to_owned()];
        docs.extend(APPLE_TARGETS.iter().map(|t| sbom(t)));
        docs
    }

    // LEDGER T2242 | class B | 5 process exit code + files written: release.yml build notices step, stub cargo
    #[test]
    fn every_build_writes_notices_and_an_sbom_for_each_target_it_compiles() {
        let script = step_script(BUILD, NOTICES_STEP);
        let wf = parse(RELEASE);
        let job = &wf["jobs"][BUILD];
        for (var, key) in [
            ("FEATURES", "features"),
            ("TARGETS", "targets"),
            ("NAME", "name"),
        ] {
            assert_eq!(
                job["env"][var]
                    .as_str()
                    .map(|v| v.split_whitespace().collect::<String>()),
                Some(format!("${{{{matrix.{key}}}}}")),
                "the build job's {var} is not its matrix {key}, so the notices and SBOMs \
                 could describe another build"
            );
        }
        let entries = job["strategy"]["matrix"]["include"]
            .as_vec()
            .expect("build has a matrix");
        assert_eq!(entries.len(), ARCHIVES.len(), "one build per archive");

        let s = scratch("notices");
        let stubs = s.0.join("stubs");
        // cargo, answering the way cargo-about and cargo-cyclonedx write
        // their output: `-o FILE`, and `--override-filename NAME` → NAME.json.
        tool(
            &stubs,
            "cargo",
            r#"for a; do printf '[%s]' "$a"; done >> "$CARGO_LOG"; echo >> "$CARGO_LOG"
out=; name=
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output-file) out="$2"; shift ;;
    --override-filename) name="$2"; shift ;;
  esac
  shift
done
[ -z "$out" ] || printf 'notices\n' > "$out"
[ -z "$name" ] || printf '{"bomFormat": "CycloneDX"}\n' > "$name.json"
"#,
        );
        for entry in entries {
            let name = entry["name"].as_str().expect("matrix name");
            let features = entry["features"].as_str().expect("matrix features");
            let targets: Vec<&str> = entry["targets"]
                .as_str()
                .unwrap_or_else(|| panic!("build {name} lists no targets"))
                .split_whitespace()
                .collect();
            let (_, _, want) = ARCHIVES
                .iter()
                .find(|(a, _, _)| a.starts_with(&format!("hops-{name}.")))
                .unwrap_or_else(|| panic!("build {name} makes no release archive"));
            assert_eq!(&targets, want, "build {name} compiles other targets");

            let cwd = s.0.join(format!("checkout-{name}"));
            reset(&cwd);
            std::fs::copy(repo().join(LICENSE), cwd.join(LICENSE)).unwrap();
            let log = s.0.join(format!("cargo-{name}.log"));
            let ran = bash(
                &script,
                &s.0,
                &cwd,
                &[
                    ("PATH", &path_with(&stubs)),
                    ("CARGO_LOG", log.to_str().unwrap()),
                    ("FEATURES", features),
                    ("TARGETS", &targets.join(" ")),
                    ("NAME", name),
                ],
            );
            assert!(ran.ok, "{name}: the notices step failed:\n{}", ran.text);
            let dist = cwd.join("dist");
            assert_eq!(
                std::fs::read(dist.join(LICENSE)).ok(),
                std::fs::read(repo().join(LICENSE)).ok(),
                "{name}: dist/{LICENSE} is not the repository's licence"
            );
            assert!(
                dist.join(NOTICES).is_file(),
                "{name}: no dist/{NOTICES}; the archive would ship without notices"
            );
            for t in &targets {
                for place in [dist.join(sbom(t)), cwd.join(sbom(t))] {
                    assert!(
                        place.is_file(),
                        "{name}: no SBOM for {t} at {}",
                        place.display()
                    );
                }
            }

            let calls = std::fs::read_to_string(&log).unwrap_or_default();
            let calls: Vec<&str> = calls.lines().collect();
            let selects = |c: &str, t: &str| {
                c.contains("[--no-default-features]")
                    && c.contains(&format!("[--features][{features}]"))
                    && c.contains(&format!("[--target][{t}]"))
            };
            let fetch = calls.iter().position(|c| *c == "[fetch][--locked]");
            let about = calls.iter().position(|c| {
                c.starts_with("[about][generate]")
                    && c.contains("[--frozen]")
                    && c.contains("[--fail]")
                    && targets.iter().all(|t| selects(c, t))
            });
            assert!(
                fetch.is_some() && about.is_some() && fetch < about,
                "{name}: the notices are not generated, offline and failing on an unknown \
                 licence, for the features and every target of this build:\n{calls:#?}"
            );
            for t in &targets {
                assert!(
                    calls
                        .iter()
                        .any(|c| c.starts_with("[cyclonedx]") && selects(c, t)),
                    "{name}: no SBOM is generated for {t} with this build's features:\n{calls:#?}"
                );
            }
        }
    }

    // LEDGER T2243 | class B | 5 process exit code + archive listing: release.yml unix packaging step
    #[test]
    fn a_unix_archive_holds_everything_the_build_wrote() {
        let script = step_script(BUILD, PACKAGE_UNIX);
        let s = scratch("package-unix");
        for (archive, bin, targets) in ARCHIVES.iter().filter(|a| a.0.ends_with(".tar.gz")) {
            let name = archive
                .strip_prefix("hops-")
                .and_then(|n| n.strip_suffix(".tar.gz"))
                .unwrap();
            let cwd = s.0.join(name);
            let dist = cwd.join("dist");
            reset(&dist);
            let mut want = vec![bin.to_string(), LICENSE.to_owned(), NOTICES.to_owned()];
            want.extend(targets.iter().map(|t| sbom(t)));
            for f in &want {
                std::fs::write(dist.join(f), f.as_bytes()).unwrap();
            }
            let ran = bash(&script, &s.0, &cwd, &[("NAME", name)]);
            assert!(ran.ok, "{archive}: packaging failed:\n{}", ran.text);
            let out = std::process::Command::new("tar")
                .arg("-tzf")
                .arg(cwd.join(archive))
                .output()
                .expect("tar runs");
            assert!(out.status.success(), "{archive} was not written");
            let mut got: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::to_owned)
                .collect();
            got.sort();
            want.sort();
            assert_eq!(
                got, want,
                "{archive} must hold the binary, {LICENSE}, {NOTICES} and the SBOM of \
                 every target, at its top level"
            );
        }
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// An archive's members, as (name, bytes).
    type Members = Vec<(String, Vec<u8>)>;

    /// A zip of stored (uncompressed) entries, as `unzip` reads one.
    fn zip(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let (mut out, mut central) = (Vec::new(), Vec::new());
        for (name, data) in entries {
            let offset = out.len() as u32;
            let (crc, size, len) = (crc32(data), data.len() as u32, name.len() as u16);
            out.extend(0x0403_4b50u32.to_le_bytes());
            for v in [20u16, 0, 0, 0, 0x21] {
                out.extend(v.to_le_bytes());
            }
            for v in [crc, size, size] {
                out.extend(v.to_le_bytes());
            }
            out.extend(len.to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(name.as_bytes());
            out.extend(data);
            central.extend(0x0201_4b50u32.to_le_bytes());
            for v in [20u16, 20, 0, 0, 0, 0x21] {
                central.extend(v.to_le_bytes());
            }
            for v in [crc, size, size] {
                central.extend(v.to_le_bytes());
            }
            for v in [len, 0, 0, 0, 0] {
                central.extend(v.to_le_bytes());
            }
            central.extend(0u32.to_le_bytes());
            central.extend(offset.to_le_bytes());
            central.extend(name.as_bytes());
        }
        let (at, size, count) = (out.len() as u32, central.len() as u32, entries.len() as u16);
        out.extend(central);
        out.extend(0x0605_4b50u32.to_le_bytes());
        for v in [0u16, 0, count, count] {
            out.extend(v.to_le_bytes());
        }
        out.extend(size.to_le_bytes());
        out.extend(at.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    /// Write `archive` into `dir` holding `members`.
    fn write_archive(s: &Path, dir: &Path, archive: &str, members: &[(String, Vec<u8>)]) {
        if archive.ends_with(".zip") {
            std::fs::write(dir.join(archive), zip(members)).unwrap();
            return;
        }
        let stage = s.join("stage");
        reset(&stage);
        for (name, data) in members {
            std::fs::write(stage.join(name), data).unwrap();
        }
        let ok = std::process::Command::new("tar")
            .arg("-C")
            .arg(&stage)
            .arg("-czf")
            .arg(dir.join(archive))
            .args(members.iter().map(|(n, _)| n))
            .status()
            .expect("tar runs")
            .success();
        assert!(ok, "could not write {archive}");
    }

    /// What a release archive holds: the binary, carrying cargo auditable's
    /// section, the licence, the notices and an SBOM per target.
    fn members(bin: &str, targets: &[&str]) -> Members {
        let mut m = vec![
            (
                bin.to_owned(),
                format!("\x7fELF code {AUDIT_SECTION} code").into_bytes(),
            ),
            (LICENSE.to_owned(), b"GNU GENERAL PUBLIC LICENSE\n".to_vec()),
            (NOTICES.to_owned(), b"THIRD-PARTY NOTICES\n".to_vec()),
        ];
        for t in targets {
            m.push((
                sbom(t),
                b"{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.5\"\n}\n".to_vec(),
            ));
        }
        m
    }

    // LEDGER T2244 | class B | 5 process exit code: release.yml attest archive gate
    #[test]
    fn every_archive_carries_its_licence_notices_sboms_and_audit_data() {
        let script = step_script(ATTEST, ARCHIVE_GATE);
        let s = scratch("archive-gate");
        let dir = step_dir(&s.0, ATTEST, ARCHIVE_GATE);
        assert_eq!(
            dir,
            step_dir(&s.0, ATTEST, SUMS_STEP),
            "the archives checked are the ones checksummed"
        );
        // Every archive complete, except that `change` is applied to `archive`.
        let run = |archive: &str, change: &dyn Fn(&mut Members)| {
            reset(&dir);
            for (a, bin, targets) in ARCHIVES {
                let mut m = members(bin, targets);
                if a == archive {
                    change(&mut m);
                }
                write_archive(&s.0, &dir, a, &m);
            }
            bash(&script, &s.0, &dir, &[])
        };

        let complete = run("", &|_| {});
        assert!(complete.ok, "every archive complete:\n{}", complete.text);

        for (archive, bin, targets) in ARCHIVES {
            let mut required = vec![bin.to_owned(), LICENSE.to_owned(), NOTICES.to_owned()];
            required.extend(targets.iter().map(|t| sbom(t)));
            for missing in &required {
                let ran = run(archive, &|m| m.retain(|(n, _)| n != missing));
                assert!(
                    !ran.ok && ran.text.contains(archive) && ran.text.contains(missing.as_str()),
                    "{archive} without {missing} passed, or the failure does not name both:\n{}",
                    ran.text
                );
            }
            for empty in [LICENSE, NOTICES] {
                let ran = run(archive, &|m| {
                    m.iter_mut()
                        .filter(|(n, _)| n == empty)
                        .for_each(|(_, d)| d.clear())
                });
                assert!(
                    !ran.ok,
                    "{archive} with an empty {empty} passed:\n{}",
                    ran.text
                );
            }
            let unaudited = run(archive, &|m| m[0].1 = b"\x7fELF code".to_vec());
            assert!(
                !unaudited.ok && unaudited.text.contains("cargo auditable"),
                "{archive}: a binary with no embedded dependency list passed:\n{}",
                unaudited.text
            );
            let not_cdx = run(archive, &|m| {
                m.iter_mut()
                    .filter(|(n, _)| n.ends_with(".cdx.json"))
                    .for_each(|(_, d)| *d = b"{}\n".to_vec())
            });
            assert!(
                !not_cdx.ok,
                "{archive}: an SBOM that is not CycloneDX passed:\n{}",
                not_cdx.text
            );
        }
    }

    // LEDGER T2245 | class B | 5 process exit code + files unpacked: release.yml sign-macos unpack step
    #[test]
    fn the_signing_job_unpacks_the_notices_with_the_binary() {
        let script = step_script(SIGN, UNPACK_STEP);
        let s = scratch("unpack");
        let (_, bin, targets) = ARCHIVES[1];
        let tmp = s.0.join("runner-temp");
        let run = |change: &dyn Fn(&Path)| {
            reset(&tmp);
            let stage = s.0.join("stage");
            reset(&stage);
            let m = members(bin, targets);
            for (name, data) in &m {
                std::fs::write(stage.join(name), data).unwrap();
            }
            change(&stage);
            let names: Vec<String> = std::fs::read_dir(&stage)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            std::fs::create_dir_all(tmp.join("unsigned")).unwrap();
            let ok = std::process::Command::new("tar")
                .arg("-C")
                .arg(&stage)
                .arg("-czf")
                .arg(tmp.join("unsigned").join(format!("{UNSIGNED}.tar.gz")))
                .args(&names)
                .status()
                .unwrap()
                .success();
            assert!(ok, "could not write the unsigned archive");
            bash(
                &script,
                &s.0,
                &s.0,
                &[("RUNNER_TEMP", tmp.to_str().unwrap())],
            )
        };

        let complete = run(&|_| {});
        assert!(
            complete.ok,
            "a complete build failed to unpack:\n{}",
            complete.text
        );
        for f in std::iter::once(bin.to_owned()).chain(app_docs()) {
            assert!(
                tmp.join("bin").join(&f).is_file(),
                "{f} was not unpacked beside the binary, so the app would not carry it"
            );
        }

        for missing in app_docs() {
            let ran = run(&|d| std::fs::remove_file(d.join(&missing)).unwrap());
            assert!(
                !ran.ok && ran.text.contains(&missing),
                "a build without {missing} was unpacked for signing:\n{}",
                ran.text
            );
        }
        let empty = run(&|d| std::fs::write(d.join(NOTICES), b"").unwrap());
        assert!(
            !empty.ok,
            "empty notices were unpacked for signing:\n{}",
            empty.text
        );
        for linked in [bin, LICENSE] {
            let ran = run(&|d| {
                std::fs::remove_file(d.join(linked)).unwrap();
                std::os::unix::fs::symlink("/etc/hosts", d.join(linked)).unwrap();
            });
            assert!(
                !ran.ok,
                "{linked} as a symlink was unpacked for signing:\n{}",
                ran.text
            );
        }
    }

    // LEDGER T2246 | class B | 5 process exit code + files written: scripts/package-macos.sh
    #[test]
    fn packaging_puts_the_licence_notices_and_sboms_in_the_app() {
        let s = scratch("package-macos");
        let stubs = s.0.join("stubs");
        tool(&stubs, "plutil", "exit 0\n");
        // `hdiutil create` stands in as a copy of the folder it images.
        tool(
            &stubs,
            "hdiutil",
            r#"[ "$1" = create ] || exit 64
for a; do out="$a"; done
while [ $# -gt 0 ]; do [ "$1" = -srcfolder ] && src="$2"; shift; done
cp -R "$src" "$out"
"#,
        );
        let build = s.0.join("build");
        reset(&build);
        let (_, bin, targets) = ARCHIVES[1];
        let m = members(bin, targets);
        for (name, data) in &m {
            std::fs::write(build.join(name), data).unwrap();
        }
        let out_dir = s.0.join("out");
        let out = std::process::Command::new("bash")
            .arg(repo().join("scripts/package-macos.sh"))
            .arg(build.join(bin))
            .arg(&out_dir)
            .arg("0.0.0")
            .current_dir(&s.0)
            .env_clear()
            .env("PATH", path_with(&stubs))
            .env("TMPDIR", &s.0)
            .output()
            .expect("bash runs");
        assert!(
            out.status.success(),
            "package-macos.sh failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        for app in [
            out_dir.join("hops.app"),
            out_dir.join("hops-macos.dmg/hops.app"),
        ] {
            for (name, data) in m.iter().skip(1) {
                let placed = app.join("Contents/Resources").join(name);
                assert_eq!(
                    std::fs::read(&placed).ok().as_ref(),
                    Some(data),
                    "{} does not hold the {name} built beside the binary",
                    placed.display()
                );
            }
        }
    }

    // LEDGER T2247 | class B | 5 process exit code + file contents: release.yml advisories notes step
    #[test]
    fn the_release_notes_name_every_ignored_advisory_with_its_reason() {
        let script = step_script("advisories", NOTES_STEP);
        let s = scratch("notes");
        let notes = |deny: &str| {
            std::fs::write(s.0.join("deny.toml"), deny).unwrap();
            let _ = std::fs::remove_file(s.0.join("release-notes.md"));
            let ran = bash(
                &script,
                &s.0,
                &s.0,
                &[("GITHUB_REPOSITORY", "example/hops")],
            );
            let text = std::fs::read_to_string(s.0.join("release-notes.md")).unwrap_or_default();
            (ran, text)
        };

        let deny = read("deny.toml");
        let doc: toml_edit::DocumentMut = deny.parse().expect("deny.toml parses");
        let ignored = doc["advisories"]["ignore"]
            .as_array()
            .expect("deny.toml ignores advisories as an array");
        assert!(!ignored.is_empty(), "the real deny.toml ignores nothing");
        let (ran, text) = notes(&deny);
        assert!(ran.ok, "notes from deny.toml failed:\n{}", ran.text);
        for entry in ignored.iter() {
            let t = entry.as_inline_table().expect("an ignore entry is a table");
            let id = t.get("id").and_then(|v| v.as_str()).expect("id");
            let reason = t
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("deny.toml ignores {id} with no reason"));
            assert!(
                text.lines().any(|l| l.contains(id) && l.contains(reason)),
                "the release notes do not give {id} with its reason {reason:?}:\n{text}"
            );
        }
        assert!(
            text.contains("gh attestation verify") && text.contains("example/hops"),
            "the notes do not say how to verify a download:\n{text}"
        );

        let no_reason =
            "[advisories]\nignore = [\n    { id = \"RUSTSEC-2000-0001\" },\n]\n".to_owned();
        let bare = "[advisories]\nignore = [\n    \"RUSTSEC-2000-0001\",\n]\n".to_owned();
        let inline = "[advisories]\nignore = [\"RUSTSEC-2000-0001\"]\n".to_owned();
        for (why, deny) in [
            ("an entry with no reason", no_reason),
            ("a bare advisory id", bare),
            ("the list on one line", inline),
        ] {
            let (ran, _) = notes(&deny);
            assert!(
                !ran.ok && ran.text.contains("RUSTSEC-2000-0001"),
                "{why} was accepted, so an ignore could reach a release unexplained:\n{}",
                ran.text
            );
        }

        let (ran, text) = notes("[advisories]\nyanked = \"deny\"\n");
        assert!(
            ran.ok,
            "a deny.toml that ignores nothing failed:\n{}",
            ran.text
        );
        assert!(
            text.contains("None"),
            "the notes do not say that nothing is ignored:\n{text}"
        );

        // The notes reach the release, and a release without them is refused.
        let wf = parse(RELEASE);
        let advisories = steps(&wf["jobs"]["advisories"]);
        let written = step_position(&wf["jobs"]["advisories"], "advisories", NOTES_STEP);
        assert!(
            advisories[written + 1..].iter().any(|st| {
                uses(st).starts_with("actions/upload-artifact@")
                    && st["with"]["name"].as_str() == Some("release-notes")
                    && st["with"]["path"].as_str() == Some("release-notes.md")
                    && st["with"]["if-no-files-found"].as_str() == Some("error")
            }),
            "advisories does not upload the notes it writes"
        );
        let publish = &wf["jobs"][PUBLISH];
        assert!(
            steps(publish).iter().any(|st| {
                uses(st).starts_with("actions/download-artifact@")
                    && st["with"]["name"].as_str() == Some("release-notes")
                    && st["with"]["path"].as_str() == Some("notes")
            }),
            "publish does not download the notes"
        );
        let release = steps(publish)
            .iter()
            .find(|st| uses(st).starts_with("softprops/action-gh-release@"))
            .expect("publish creates the release");
        assert_eq!(
            release["with"]["body_path"].as_str(),
            Some("notes/release-notes.md"),
            "the release body is not the notes"
        );
        let check = step_script(PUBLISH, NOTES_CHECK);
        reset(&s.0.join("notes"));
        let absent = bash(&check, &s.0, &s.0, &[]);
        assert!(
            !absent.ok,
            "a release with no notes would have been published; the release action \
             falls back to an empty body when body_path cannot be read:\n{}",
            absent.text
        );
        std::fs::write(s.0.join("notes/release-notes.md"), text).unwrap();
        let present = bash(&check, &s.0, &s.0, &[]);
        assert!(present.ok, "notes present, yet refused:\n{}", present.text);
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
        /// A file under hops.app/Contents that the mounted image leaves out.
        omit: Option<String>,
        /// Whether the binary in the app carries cargo auditable's section.
        audited: bool,
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
                omit: None,
                audited: true,
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
            // The mounted app: a binary, with or without cargo auditable's
            // section, and what every artifact carries in Resources.
            let mut files = vec![(
                "MacOS/hops".to_owned(),
                if self.audited {
                    format!("code {AUDIT_SECTION} code")
                } else {
                    "code".to_owned()
                },
            )];
            files.extend(
                app_docs()
                    .into_iter()
                    .map(|d| (format!("Resources/{d}"), d)),
            );
            let populate: String = files
                .iter()
                .filter(|(f, _)| self.omit.as_deref() != Some(f.as_str()))
                .map(|(f, body)| {
                    format!("    printf '%s\\n' '{body}' > \"$mnt/hops.app/Contents/{f}\"\n")
                })
                .collect();
            write(
                "hdiutil",
                format!(
                    r#"case "$1" in
  attach)
    while [ $# -gt 0 ]; do [ "$1" = -mountpoint ] && mnt="$2"; shift; done
    mkdir -p "$mnt/hops.app/Contents/MacOS" "$mnt/hops.app/Contents/Resources"
{populate}    ;;
  detach) for a; do mnt="$a"; done; rm -rf "$mnt/hops.app" ;;
  *) exit 64 ;;
esac
"#
                ),
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

        let mut cases: Vec<(String, Tools, Option<&[u8]>)> = vec![
            ("there is no dmg".into(), Tools::release(), None),
            ("the dmg is empty".into(), Tools::release(), Some(empty)),
            (
                "Gatekeeper rejects the dmg".into(),
                Tools {
                    spctl_dmg: REJECTED,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "assessments are disabled, so the dmg's `accepted` proves nothing".into(),
                Tools {
                    spctl_dmg: ASSESSMENTS_OFF,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "the dmg is signed but not notarized".into(),
                Tools {
                    spctl_dmg: SIGNED_ONLY,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "no ticket is stapled to the dmg".into(),
                Tools {
                    stapler_dmg: 65,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "assessments are disabled, so the app's `accepted` proves nothing".into(),
                Tools {
                    spctl_app: ASSESSMENTS_OFF,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "no ticket is stapled to the app".into(),
                Tools {
                    stapler_app: 65,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "the app's signature does not verify under --strict".into(),
                Tools {
                    verify_app: 1,
                    ..Tools::release()
                },
                Some(image),
            ),
            (
                "the app is signed under another identifier, which voids the Accessibility grant"
                    .into(),
                Tools {
                    identifier: "hops",
                    ..Tools::release()
                },
                Some(image),
            ),
        ];
        for doc in app_docs() {
            cases.push((
                format!("the app carries no {doc}"),
                Tools {
                    omit: Some(format!("Resources/{doc}")),
                    ..Tools::release()
                },
                Some(image),
            ));
        }
        cases.push((
            "the app's binary carries no dependency list from cargo auditable".into(),
            Tools {
                audited: false,
                ..Tools::release()
            },
            Some(image),
        ));
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

// LEDGER T5a | class S | the scan T5 relies on, over inline YAML
#[test]
fn the_secret_scan_reads_the_context_name_in_any_case() {
    let scan = |expr: &str| {
        let doc = format!("env:\n  P: \"${{{{ {expr} }}}}\"\n");
        secret_refs(&YamlLoader::load_from_str(&doc).unwrap()[0])
    };
    let one = |n: &str| BTreeSet::from([n.to_owned()]);
    for expr in [
        "secrets.MACOS_CERT_P12",
        "Secrets.MACOS_CERT_P12",
        "SECRETS.macos_cert_p12",
        "sEcReTs['MACOS_CERT_P12']",
    ] {
        assert_eq!(scan(expr), one("MACOS_CERT_P12"), "{expr} was not seen");
    }
    assert_eq!(
        scan("toJSON(Secrets)"),
        one("*"),
        "toJSON(Secrets) was not seen"
    );
    assert!(scan("github.MySecrets").is_empty(), "a longer name matched");
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

/// A job's `permissions`, as sorted (scope, access) pairs.
fn grants(job: &Yaml, id: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = job["permissions"]
        .as_hash()
        .unwrap_or_else(|| panic!("{id} sets no permissions of its own"))
        .iter()
        .map(|(k, v)| (k.as_str().unwrap().into(), v.as_str().unwrap_or("").into()))
        .collect();
    out.sort();
    out
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
                rel == RELEASE && (id == PUBLISH || id == ATTEST),
                "{rel}: job {id} may write; only {PUBLISH} and {ATTEST} in {RELEASE} may"
            );
        }
    }
    let wf = parse(RELEASE);
    let pair = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    assert_eq!(
        grants(&wf["jobs"][PUBLISH], PUBLISH),
        vec![pair("contents", "write")],
        "publish writes release assets and nothing else"
    );
    // An OIDC token to sign with and the attestations store to write to; not
    // the repository, since this job has no reason to read or change it.
    assert_eq!(
        grants(&wf["jobs"][ATTEST], ATTEST),
        vec![pair("attestations", "write"), pair("id-token", "write")],
        "attest signs and stores attestations and does nothing else"
    );
}

fn is_commit(r: &str) -> bool {
    r.len() == 40
        && r.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
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
            if u.starts_with("./") {
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
            if value.starts_with("./") {
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
    for job in ["version-matches-tag", "advisories", BUILD, SIGN, ATTEST] {
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
// LEDGER T2248 | class S | parsed workflow YAML | pair T2243, T2244 (the PowerShell step has no local runner)
#[test]
fn every_build_uploads_an_archive_of_everything_it_wrote_and_its_sboms() {
    let wf = parse(RELEASE);
    let build = &wf["jobs"][BUILD];
    let windows = step_named(build, BUILD, PACKAGE_WINDOWS);
    assert_eq!(windows["if"].as_str(), Some("runner.os == 'Windows'"));
    assert!(
        commands(windows).iter().any(|c| {
            c.first().map(String::as_str) == Some("Compress-Archive")
                && c.windows(2).any(|w| w == ["-Path", "dist\\*"])
                && c.windows(2)
                    .any(|w| w == ["-DestinationPath", "\"hops-$env:NAME.zip\""])
        }),
        "{PACKAGE_WINDOWS} does not zip the whole of dist, where the binary, {LICENSE}, \
         {NOTICES} and the SBOM were written"
    );
    let unix = step_named(build, BUILD, PACKAGE_UNIX);
    assert_eq!(unix["if"].as_str(), Some("runner.os != 'Windows'"));

    let notices = step_position(build, BUILD, NOTICES_STEP);
    let upload = steps(build)
        .iter()
        .position(|s| uses(s).starts_with("actions/upload-artifact@"))
        .expect("build uploads what it made");
    for packaging in [PACKAGE_UNIX, PACKAGE_WINDOWS] {
        let at = step_position(build, BUILD, packaging);
        assert!(
            notices < at && at < upload,
            "{packaging} must run after {NOTICES_STEP} and before the upload"
        );
    }
    let paths: BTreeSet<&str> = steps(build)[upload]["with"]["path"]
        .as_str()
        .unwrap_or("")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        paths,
        BTreeSet::from(["hops-${{ matrix.name }}.*", "hops-*.cdx.json"]),
        "build uploads its archive and its SBOMs, each a release asset"
    );
    assert_eq!(
        steps(build)[upload]["with"]["if-no-files-found"].as_str(),
        Some("error")
    );
}

// LEDGER T2249 | class S | parsed workflow YAML | pair T2244 (the audit data in the artifact)
#[test]
fn every_release_binary_is_built_with_cargo_auditable() {
    let wf = parse(RELEASE);
    let build = &wf["jobs"][BUILD];
    let mut built = BTreeSet::new();
    for step in steps(build) {
        let name = step["name"].as_str().unwrap_or(uses(step));
        for c in commands(step) {
            assert!(
                !c.windows(2).any(|w| w == ["cargo", "build"]),
                "{name} runs `cargo build`; a release binary is built with `cargo auditable \
                 build`, which embeds the list of crates it was built from"
            );
            if c.windows(3).any(|w| w == ["cargo", "auditable", "build"]) {
                for flag in ["--locked", "--release", "--target"] {
                    assert!(c.iter().any(|w| w == flag), "{name}: {c:?} lacks {flag}");
                }
                built.insert(name.to_owned());
            }
        }
    }
    assert_eq!(
        built,
        BTreeSet::from([
            "Build (Linux)".to_owned(),
            "Build (Windows)".to_owned(),
            "Build (macOS universal)".to_owned(),
        ]),
        "every platform's build step must run `cargo auditable build`"
    );
}

// LEDGER T22410 | class S | parsed workflow YAML | pair NONE (what `cargo install` fetches runs only on GitHub)
#[test]
fn the_release_tools_are_pinned_and_built_from_their_lockfiles() {
    let wf = parse(RELEASE);
    let build = &wf["jobs"][BUILD];
    let install = step_named(build, BUILD, TOOLS_STEP);
    assert!(install["if"].is_badvalue(), "{TOOLS_STEP} is conditional");
    let mut installed = BTreeSet::new();
    for c in commands(install) {
        assert_eq!(
            c.get(..2),
            Some(&["cargo".to_owned(), "install".to_owned()][..]),
            "{TOOLS_STEP} runs {c:?}; it installs the tools and does nothing else"
        );
        assert!(
            c.iter().any(|w| w == "--locked"),
            "{c:?} resolves the tool's dependencies afresh instead of from its own lockfile"
        );
        let spec = c.last().unwrap();
        let (krate, version) = spec
            .split_once('@')
            .unwrap_or_else(|| panic!("{c:?} installs whatever version is newest"));
        assert!(
            version.split('.').count() == 3 && version.split('.').all(|p| p.parse::<u32>().is_ok()),
            "{spec} is not an exact version"
        );
        installed.insert(krate.to_owned());
    }
    assert_eq!(
        installed,
        BTreeSet::from([
            "cargo-about".to_owned(),
            "cargo-auditable".to_owned(),
            "cargo-cyclonedx".to_owned(),
        ])
    );
    let at = step_position(build, BUILD, TOOLS_STEP);
    for later in [
        "Build (macOS universal)",
        "Build (Windows)",
        "Build (Linux)",
        NOTICES_STEP,
    ] {
        assert!(
            at < step_position(build, BUILD, later),
            "{later} runs before the tools it needs are installed"
        );
    }
}

// LEDGER T22411 | class S | parsed workflow YAML | pair T3, T2241, T2244 (attestation is minted only on GitHub)
#[test]
fn every_asset_is_attested_by_a_job_that_can_do_nothing_else() {
    let wf = parse(RELEASE);
    let attest = &wf["jobs"][ATTEST];
    assert!(!attest.is_badvalue(), "release.yml has no {ATTEST} job");
    let needs: BTreeSet<&str> = attest["needs"]
        .as_vec()
        .expect("attest needs a list")
        .iter()
        .filter_map(Yaml::as_str)
        .collect();
    assert_eq!(
        needs,
        BTreeSet::from([BUILD, SIGN]),
        "attest covers what build and {SIGN} produced"
    );
    for step in steps(attest) {
        let name = step["name"].as_str().unwrap_or(uses(step));
        assert!(
            !uses(step).starts_with("actions/checkout@"),
            "{ATTEST} checks out the repository; a job that can mint a signing token \
             runs no code from it"
        );
        assert!(
            step["if"].is_badvalue(),
            "{ATTEST} step {name:?} is conditional"
        );
        // `cargo` in command position: first on a line, or after an operator.
        let runs_cargo = commands(step).iter().any(|c| {
            c.iter().enumerate().any(|(i, w)| {
                w == "cargo"
                    && (i == 0
                        || ["&&", "||", "|", ";", "then", "do", "else"]
                            .contains(&c[i - 1].as_str()))
            })
        });
        assert!(!runs_cargo, "{ATTEST} step {name:?} runs cargo");
    }

    let all = steps(attest);
    let pos = |what: &str, f: &dyn Fn(&Yaml) -> bool| {
        all.iter()
            .position(f)
            .unwrap_or_else(|| panic!("{ATTEST} has no step that {what}"))
    };
    let dir = step_named(attest, ATTEST, SUMS_STEP)["working-directory"]
        .as_str()
        .expect("the checksums are written in the release directory")
        .to_owned();
    let downloaded = pos("downloads every build's assets", &|s| {
        uses(s).starts_with("actions/download-artifact@")
            && s["with"]["pattern"].as_str() == Some("hops-*")
            && s["with"]["merge-multiple"].as_bool() == Some(true)
            && s["with"]["path"].as_str() == Some(dir.as_str())
    });
    let checked = step_position(attest, ATTEST, ARCHIVE_GATE);
    let summed = step_position(attest, ATTEST, SUMS_STEP);
    let attested = pos("attests build provenance", &|s| {
        uses(s).starts_with("actions/attest-build-provenance@")
    });
    let uploaded = pos("uploads the attested release", &|s| {
        uses(s).starts_with("actions/upload-artifact@")
            && s["with"]["name"].as_str() == Some(RELEASE_ARTIFACT)
    });
    assert!(
        downloaded < checked && checked < summed && summed < attested && attested < uploaded,
        "{ATTEST} must download, check the archives, write SHA256SUMS, attest, then upload"
    );
    assert_eq!(
        all[attested]["with"]["subject-path"].as_str(),
        Some(format!("{dir}/*").as_str()),
        "the attestation must cover every asset in {dir}, SHA256SUMS included"
    );
    assert_eq!(
        all[uploaded]["with"]["path"].as_str(),
        Some(format!("{dir}/").as_str()),
        "{ATTEST} uploads exactly what it attested"
    );
    assert_eq!(
        all[uploaded]["with"]["if-no-files-found"].as_str(),
        Some("error")
    );

    // What publish releases is that artifact and nothing else.
    let publish = &wf["jobs"][PUBLISH];
    let downloads: Vec<&Yaml> = steps(publish)
        .iter()
        .filter(|s| uses(s).starts_with("actions/download-artifact@"))
        .collect();
    let release: Vec<&&Yaml> = downloads
        .iter()
        .filter(|s| s["with"]["path"].as_str() == Some(dir.as_str()))
        .collect();
    assert!(
        release.len() == 1
            && release[0]["with"]["name"].as_str() == Some(RELEASE_ARTIFACT)
            && release[0]["with"]["pattern"].is_badvalue(),
        "publish must download {dir} as the one `{RELEASE_ARTIFACT}` artifact {ATTEST} \
         uploaded, so nothing unattested is published"
    );
    let gh = steps(publish)
        .iter()
        .find(|s| uses(s).starts_with("softprops/action-gh-release@"))
        .expect("publish creates the release");
    assert_eq!(
        gh["with"]["files"].as_str(),
        Some(format!("{dir}/*").as_str())
    );
    assert!(
        step_position(publish, PUBLISH, PUBLISH_GATE)
            < steps(publish)
                .iter()
                .position(|s| uses(s).starts_with("softprops/action-gh-release@"))
                .unwrap(),
        "publish checks the assets before it releases them"
    );
}

// ---------------------------------------------------------------------------
// check.yml: the workspace tests run on Linux as well as macOS (#228). A
// Linux-only deadlock failed only the Ubuntu release job, twice, while the
// workspace tests, which ran on macOS alone, were green.
// ---------------------------------------------------------------------------

const CHECK: &str = ".github/workflows/check.yml";
const WORKSPACE_TESTS: &str = "workspace-tests";

/// The runner labels a job runs on: its `runs-on`, or, when that is
/// `${{ matrix.os }}`, every `os` the matrix lists or includes.
fn runners(job_id: &str, job: &Yaml) -> BTreeSet<String> {
    let runs_on = job["runs-on"]
        .as_str()
        .unwrap_or_else(|| panic!("{job_id}: runs-on is not a single label"));
    if !runs_on.contains("${{") {
        return BTreeSet::from([runs_on.to_owned()]);
    }
    let expr: String = runs_on.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(
        expr, "${{matrix.os}}",
        "{job_id}: runs-on is an expression this test cannot resolve"
    );
    let matrix = &job["strategy"]["matrix"];
    assert!(
        matrix["exclude"].is_badvalue(),
        "{job_id}: a matrix `exclude` can drop a runner without the list showing it; \
         list the runners instead"
    );
    let listed = matrix["os"].as_vec().map(Vec::as_slice).unwrap_or(&[]);
    let included = matrix["include"].as_vec().map(Vec::as_slice).unwrap_or(&[]);
    listed
        .iter()
        .chain(included.iter().map(|entry| &entry["os"]))
        .filter_map(|os| os.as_str().map(str::to_owned))
        .collect()
}

/// Whether a job or step is marked so that its failure fails nothing.
fn may_fail(y: &Yaml) -> bool {
    !matches!(
        y["continue-on-error"],
        Yaml::BadValue | Yaml::Boolean(false)
    )
}

// LEDGER T12 | class S | parsed workflow YAML | pair NONE (CI configuration)
#[test]
fn the_workspace_tests_run_on_linux_and_on_macos() {
    let wf = parse(CHECK);
    let job = &wf["jobs"][WORKSPACE_TESTS];
    assert!(!job.is_badvalue(), "check.yml has no {WORKSPACE_TESTS} job");
    let on = runners(WORKSPACE_TESTS, job);
    for os in ["ubuntu-latest", "macos-latest"] {
        assert!(
            on.contains(os),
            "{WORKSPACE_TESTS} runs on {on:?}, not {os}. Every crate's tests must run on \
             Linux and macOS; a platform with no workspace run lets a defect that only \
             exists there merge green"
        );
    }
    assert!(
        job["if"].is_badvalue() && !may_fail(job),
        "{WORKSPACE_TESTS} is conditional or allowed to fail"
    );

    let wanted = ["--locked", "--workspace", "--all-targets"];
    let mut found = 0;
    for step in steps(job) {
        let name = step["name"].as_str().unwrap_or("cargo test");
        // One command a line, and a line ending in `\` goes on to the next.
        let run = step["run"].as_str().unwrap_or("").replace("\\\n", " ");
        for command in run.lines() {
            let tokens: Vec<&str> = command.split_whitespace().collect();
            let Some(at) = tokens.windows(2).position(|w| w == ["cargo", "test"]) else {
                continue;
            };
            let args = &tokens[at + 2..];
            if !wanted.iter().all(|w| args.contains(w)) {
                continue;
            }
            assert!(
                step["if"].is_badvalue() && !may_fail(step),
                "{WORKSPACE_TESTS}/{name:?} is conditional or allowed to fail, so some runner \
                 can skip the workspace tests"
            );
            // Exactly these: anything more is a package, a target, a test name
            // filter or `-- --skip`, which runs fewer tests, or shell that
            // hides a failure.
            let mut sorted = args.to_vec();
            sorted.sort_unstable();
            let mut want = wanted.to_vec();
            want.sort_unstable();
            assert!(
                sorted == want,
                "{WORKSPACE_TESTS}/{name:?} runs `cargo test {}`; it must pass exactly `{}`, \
                 since anything more runs fewer tests than the workspace or hides a failure",
                args.join(" "),
                wanted.join(" ")
            );
            found += 1;
        }
    }
    assert_eq!(
        found,
        1,
        "{WORKSPACE_TESTS} must run `cargo test {}` once, in one step",
        wanted.join(" ")
    );
}

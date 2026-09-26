pub mod authority;
pub mod build_check;
mod capture;
pub mod capture_test;
pub mod client;
mod clipboard;
pub mod config;
mod connect;
mod crypto;
pub mod daemon_start;
pub mod discovery;
mod dns;
mod emulation;
pub mod emulation_test;
pub(crate) mod enter_hook;
mod git_env;
mod hop_log;
mod listen;
pub mod logging;
pub mod match_code;
mod new_file;
mod permission_watch;
mod pid;
mod prompt_gate;
pub mod service;
mod transport;
pub mod trust;
pub mod trust_file;
mod trust_save;

/// Guards for decisions already made — and, three times now, rebuilt anyway.
/// See the module docs for the bar each guard is held to.
#[cfg(test)]
mod decision_guards;

/// Two machines in one test process: a real listener and a real dialer on
/// loopback, with recording emulation and scripted capture.
#[cfg(test)]
mod test_harness;

#[cfg(test)]
mod toolchain_pin {
    //! `rust-toolchain.toml` and the workflows must name the same compiler, and
    //! the action that installs it must be a commit, not a ref that can move.
    //!
    //! The pin exists because CI ran `@stable` (unpinned) with
    //! `RUSTFLAGS: -D warnings`, so a Rust release could redden `main` with no
    //! repo change — and did move underneath a run on 2026-09-01
    //! (`stable-aarch64-apple-darwin updated ... from rustc 1.97.1`).
    //!
    //! A pin in two places that can disagree is worse than no pin, because it
    //! reads as pinned while the workflow silently installs something else. So
    //! bumping the version means changing every site in the same commit, and
    //! this fails until they agree.
    //!
    //! The version used to be the action's ref, `dtolnay/rust-toolchain@1.98.0`.
    //! That ref is a branch of the action's repository, so the code it runs could
    //! change after review, in the release job as much as anywhere. The ref is
    //! now a commit and the version is the action's `toolchain` input (#177).
    use yaml_rust2::{Yaml, YamlLoader};

    const ACTION: &str = "dtolnay/rust-toolchain@";

    fn pinned_channel() -> String {
        const TOML: &str = include_str!("../rust-toolchain.toml");
        TOML.lines()
            .map(|l| l.split('#').next().unwrap_or("")) // drop comments
            .find_map(|l| l.trim().strip_prefix("channel").map(str::to_string))
            .and_then(|l| {
                l.split('=')
                    .nth(1)
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
            .expect("rust-toolchain.toml must set channel = \"<version>\"")
    }

    fn is_commit(r: &str) -> bool {
        r.len() == 40
            && r.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// Every workflow in the repository, as (file name, parsed), so a workflow
    /// added later is covered without editing this list.
    fn workflows() -> Vec<(String, Yaml)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).expect(".github/workflows") {
            let path = entry.expect("dir entry").path();
            if !matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            ) {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path).expect("workflow is readable");
            let mut docs = YamlLoader::load_from_str(&text)
                .unwrap_or_else(|e| panic!("{name} is not valid YAML: {e}"));
            out.push((name, docs.remove(0)));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    // LEDGER T15 | class S | parsed workflow YAML | pair NONE (CI configuration)
    #[test]
    fn every_workflow_installs_the_pinned_toolchain_from_a_commit() {
        let want = pinned_channel();
        assert!(
            want.chars().next().is_some_and(|c| c.is_ascii_digit()),
            "the pin must be an explicit version, not a moving channel like \
             {want:?} — a moving channel is what this guard exists to prevent"
        );
        let found = workflows();
        for required in ["check.yml", "release.yml"] {
            assert!(
                found.iter().any(|(name, _)| name == required),
                "{required} is gone — this guard is testing less than it claims"
            );
        }
        for (name, wf) in found {
            let jobs = wf["jobs"].as_hash().expect("a workflow has jobs");
            let installs: Vec<(String, &Yaml)> = jobs
                .iter()
                .flat_map(|(id, job)| {
                    let id = id.as_str().unwrap_or("?").to_owned();
                    job["steps"]
                        .as_vec()
                        .map(Vec::as_slice)
                        .unwrap_or(&[])
                        .iter()
                        .filter(|s| s["uses"].as_str().is_some_and(|u| u.starts_with(ACTION)))
                        .map(move |s| (id.clone(), s))
                })
                .collect();
            if matches!(name.as_str(), "check.yml" | "release.yml") {
                assert!(
                    !installs.is_empty(),
                    "{name} no longer installs a toolchain — this guard is testing nothing"
                );
            }
            for (job, step) in installs {
                let uses = step["uses"].as_str().unwrap_or("");
                let r = &uses[ACTION.len()..];
                assert!(
                    is_commit(r),
                    "{name}: job {job} uses {uses}. A branch or tag of the action can be \
                     moved to other code after review; pin a 40-character commit and \
                     name the version with `toolchain:`"
                );
                let got = step["with"]["toolchain"].as_str();
                assert_eq!(
                    got,
                    Some(want.as_str()),
                    "{name}: job {job} installs toolchain {got:?} but rust-toolchain.toml \
                     pins {want:?}. Bump both in the same commit; a pin that disagrees \
                     with the workflow reads as pinned while building with something else."
                );
            }
        }
    }
}

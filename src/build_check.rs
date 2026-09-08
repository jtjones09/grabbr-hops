//! Is the binary you are about to run the one you think you built?
//!
//! # Why this exists
//!
//! A launcher can start a stale binary, and nothing says so. That has now cost
//! real time twice, in both directions:
//!
//! - A test session was spent on a crash in a build that predated the fix for
//!   it. The launcher relaunched an executable from the day before, because on
//!   that platform the launcher did not build — while the one on another
//!   platform did. It looked exactly like a deployment.
//! - A validated change sat unpromoted for three weeks while the everyday
//!   binary kept running the old behaviour, and it was noticed only by feel.
//!
//! Both are the same missing step: nothing compares what is about to run
//! against what the source says it should be.
//!
//! # Why this is Rust and not three shell scripts
//!
//! Because three shell scripts is what caused it. The same policy was written
//! once in bash, once in VBS/cmd, and not at all for Linux, so the platforms
//! drifted apart silently and the difference only surfaced as a wasted test
//! cycle. This is written once and runs identically everywhere; the launchers
//! call it and hold no policy of their own.
//!
//! The check is self-diagnosing, which is what makes it safe: a stale binary
//! running this code reports its own staleness, because the commit it compares
//! against `HEAD` is the one baked into *it* at compile time by `build.rs`.
//!
//! # What it checks, and why both halves are needed
//!
//! **The commit** catches a binary built from a different revision — a missing
//! rebuild after a pull or a branch switch.
//!
//! **The timestamps** catch what the commit cannot. `build.rs` bakes in the
//! commit, so a binary built before an uncommitted edit still reports a commit
//! equal to `HEAD` while missing the edit entirely. That is the ordinary
//! day-to-day case: change a file, forget to rebuild, test the old code. Only
//! comparing the binary's mtime against the newest tracked source file finds
//! it.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// The check passed, or was not asked to enforce anything.
pub const EXIT_OK: i32 = 0;
/// `--strict`, and the binary does not match the source.
///
/// Deliberately not 1. Every other failure in this process also exits 1 —
/// `main` maps any error to `process::exit(1)` — so a launcher reading 1 as
/// "stale" also reads "your config file is unparseable" as "stale", and tells
/// you to rebuild for a problem no rebuild can fix. Staleness needs a code
/// nothing else uses.
pub const EXIT_STALE: i32 = 2;
/// `--strict`, and the comparison could not be made at all.
///
/// Separate from stale because the remedy is different — a repo path or a
/// missing `git`, not a rebuild — and separate from success because a gate that
/// verified nothing must never report that it verified something.
pub const EXIT_CANNOT_VERIFY: i32 = 3;

/// What a build check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No git checkout to compare against — a released install, not a dev tree.
    NotACheckout,
    /// The binary matches the source.
    Current,
    /// Built from a different revision.
    WrongCommit { built: String, head: String },
    /// The right revision, but source has been edited since the binary was
    /// linked.
    SourceNewer { newest: String },
}

impl Verdict {
    /// Whether this should stop a dev launcher.
    ///
    /// `NotACheckout` is deliberately not stale: an installed copy has no
    /// source to be behind, and refusing to launch there would be nonsense.
    pub fn is_stale(&self) -> bool {
        matches!(
            self,
            Verdict::WrongCommit { .. } | Verdict::SourceNewer { .. }
        )
    }
}

/// Decide, given facts someone else gathered.
///
/// Split out from the gathering so the rules can be tested without a git
/// repository, a build, or a filesystem.
///
/// Order matters: a wrong commit is reported ahead of a stale timestamp because
/// it is the more fundamental mistake and its fix (rebuild) is the same. Saying
/// "source is newer" to someone who is actually on the wrong branch would send
/// them looking at the wrong thing.
pub fn judge(
    built_commit: &str,
    head: Option<&str>,
    binary_mtime: Option<SystemTime>,
    newest_source: Option<(String, SystemTime)>,
) -> Verdict {
    let Some(head) = head else {
        return Verdict::NotACheckout;
    };
    // `build.rs` falls back to this outside a checkout; it can never match a
    // real revision, and reporting it as a mismatch would be noise.
    if built_commit == "unknown" {
        return Verdict::NotACheckout;
    }
    if built_commit != head {
        return Verdict::WrongCommit {
            built: built_commit.to_string(),
            head: head.to_string(),
        };
    }
    if let (Some(bin), Some((path, src))) = (binary_mtime, newest_source) {
        if src > bin {
            return Verdict::SourceNewer { newest: path };
        }
    }
    Verdict::Current
}

/// `git -C <repo> <args...>`, trimmed, or `None` if git or the repo is absent.
fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The most recently modified tracked source file, if any.
///
/// Tracked files only, via `git ls-files`: a target directory holds build
/// output newer than any source, and untracked scratch files are not what the
/// binary was built from. Restricted to inputs that actually change the
/// binary — walking every tracked file would let a README edit read as a stale
/// build.
fn newest_source(repo: &Path) -> Option<(String, SystemTime)> {
    let listing = git(repo, &["ls-files"])?;
    listing
        .lines()
        .filter(|f| {
            f.ends_with(".rs")
                || f.ends_with(".toml")
                || f.ends_with(".slint")
                || f.ends_with(".lock")
        })
        .filter(|f| !is_separate_target(f))
        .filter_map(|f| {
            let mtime = std::fs::metadata(repo.join(f)).ok()?.modified().ok()?;
            Some((f.to_string(), mtime))
        })
        .max_by_key(|(_, t)| *t)
}

/// Whether this path builds into its own cargo target rather than the binary.
///
/// Integration tests, benches and examples are separate targets: editing one
/// cannot change `hops`, so counting them makes the binary look stale when it
/// is not. That is not merely noisy — a spurious stale verdict blocks a
/// promotion that should have gone ahead, and adding a test is a normal thing
/// to do between validating a build and promoting it.
fn is_separate_target(path: &str) -> bool {
    path.split('/')
        .any(|c| matches!(c, "tests" | "benches" | "examples"))
}

/// Everything the report needs, gathered from the running binary and the repo.
pub struct Report {
    pub verdict: Verdict,
    pub built_commit: String,
    pub head: Option<String>,
    pub dirty: bool,
    /// Commits on the repo's default branch that this build does not have.
    pub behind: Option<usize>,
    pub binary: PathBuf,
}

/// Locate the repo to compare against.
///
/// Explicit argument first, then `HOPS_REPO`, then the working directory — so a
/// launcher can be explicit while a developer standing in the repo needs no
/// arguments.
fn resolve_repo(explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .or_else(|| std::env::var_os("HOPS_REPO").map(PathBuf::from))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Compare the running binary against a source tree.
pub fn check(repo: Option<PathBuf>) -> Report {
    let repo = resolve_repo(repo);
    let built_commit = env!("HOPS_SHORT_COMMIT").to_string();
    let head = git(&repo, &["rev-parse", "--short=8", "HEAD"]);
    let dirty = git(&repo, &["status", "--porcelain"]).is_some();
    let binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("hops"));
    let binary_mtime = std::fs::metadata(&binary)
        .ok()
        .and_then(|m| m.modified().ok());

    // How far behind the integration branch this build is. Only meaningful for
    // a promoted binary, which is deliberately not HEAD; `origin/main` rather
    // than `main` because a local main can itself be weeks stale.
    let behind = git(
        &repo,
        &[
            "rev-list",
            "--count",
            &format!("{built_commit}..origin/main"),
        ],
    )
    .and_then(|s| s.parse().ok());

    let verdict = judge(
        &built_commit,
        head.as_deref(),
        binary_mtime,
        newest_source(&repo),
    );

    Report {
        verdict,
        built_commit,
        head,
        dirty,
        behind,
        binary,
    }
}

/// Print the report and return the process exit code.
///
/// `strict` is for dev launchers, where a stale binary means the test that
/// follows would measure the wrong code. A daily launcher passes `false`: its
/// binary is a deliberately-promoted older build, so being behind `HEAD` is
/// expected and must never block a launch — it only needs saying out loud,
/// because an everyday binary once ran three weeks behind unnoticed.
pub fn report(r: &Report, strict: bool) -> i32 {
    match &r.verdict {
        Verdict::NotACheckout => {
            println!(
                "hops {} — no source tree to compare against",
                r.built_commit
            );
            if strict {
                // Someone asked for this to be verified and it could not be.
                // Returning 0 here would be a gate that passes having checked
                // nothing — which reads as proof and is worse than no gate.
                println!("  CANNOT VERIFY: no git checkout at the path given");
                println!("  the binary may or may not match; nothing was compared");
                EXIT_CANNOT_VERIFY
            } else {
                EXIT_OK
            }
        }
        Verdict::Current => {
            let dirty = if r.dirty {
                ", tree has uncommitted changes"
            } else {
                ""
            };
            println!("hops {} — up to date{dirty}", r.built_commit);
            0
        }
        Verdict::WrongCommit { built, head } => {
            println!("STALE: this binary is {built}, the source is {head}");
            println!("  {}", r.binary.display());
            if let Some(n) = r.behind {
                if n > 0 {
                    println!("  {n} commit(s) behind origin/main");
                }
            }
            if strict {
                println!("  rebuild before testing, or you will be testing the old code");
                EXIT_STALE
            } else {
                EXIT_OK
            }
        }
        Verdict::SourceNewer { newest } => {
            println!("STALE: {newest} was edited after this binary was built");
            println!("  {}", r.binary.display());
            if strict {
                println!("  rebuild before testing, or you will be testing the old code");
                EXIT_STALE
            } else {
                EXIT_OK
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn rep(verdict: Verdict) -> Report {
        Report {
            verdict,
            built_commit: "abc12345".into(),
            head: Some("abc12345".into()),
            dirty: false,
            behind: None,
            binary: PathBuf::from("/tmp/hops"),
        }
    }

    #[test]
    fn stale_uses_a_code_no_other_failure_uses() {
        assert_ne!(
            EXIT_STALE, 1,
            "every other failure in this process exits 1 — `main` maps any error \
             to exit(1) — so if stale were also 1, a launcher would report \
             \"stale, rebuild\" for an unparseable config file, which no rebuild fixes"
        );
        assert_ne!(EXIT_CANNOT_VERIFY, 1);
        assert_ne!(EXIT_STALE, EXIT_CANNOT_VERIFY);
        assert_ne!(EXIT_STALE, EXIT_OK);
    }

    #[test]
    fn a_gate_that_compared_nothing_does_not_report_success() {
        assert_eq!(
            report(&rep(Verdict::NotACheckout), true),
            EXIT_CANNOT_VERIFY,
            "under --strict, being unable to find a checkout means nothing was \
             compared. Returning success there is a gate that passes having \
             verified nothing, which reads as proof and is worse than no gate."
        );
    }

    #[test]
    fn a_daily_launcher_is_never_blocked() {
        for v in [
            Verdict::NotACheckout,
            Verdict::Current,
            Verdict::WrongCommit {
                built: "a".into(),
                head: "b".into(),
            },
            Verdict::SourceNewer {
                newest: "src/x.rs".into(),
            },
        ] {
            assert_eq!(
                report(&rep(v.clone()), false),
                EXIT_OK,
                "without --strict nothing may block a launch: a promoted daily \
                 build is deliberately behind HEAD, and refusing to start it \
                 would break the everyday driver. {v:?} blocked it."
            );
        }
    }

    #[test]
    fn a_separate_cargo_target_does_not_make_the_binary_look_stale() {
        for p in [
            "tests/logging_sink.rs",
            "crates/hops-ipc/tests/auth_roundtrip.rs",
            "crates/hops-slint/examples/render_png.rs",
            "benches/x.rs",
        ] {
            assert!(
                is_separate_target(p),
                "{p} builds its own target and cannot change the hops binary; \
                 counting it makes a current binary look stale and blocks a \
                 promotion that should have gone ahead"
            );
        }
        for p in [
            "src/service.rs",
            "crates/hops-ipc/src/lib.rs",
            "Cargo.lock",
            "build.rs",
        ] {
            assert!(!is_separate_target(p), "{p} does link into the binary");
        }
    }

    #[test]
    fn a_matching_commit_with_an_older_source_tree_is_current() {
        assert_eq!(
            judge(
                "abc12345",
                Some("abc12345"),
                Some(t(100)),
                Some(("src/x.rs".into(), t(50)))
            ),
            Verdict::Current
        );
    }

    #[test]
    fn a_different_commit_is_stale() {
        let v = judge("abc12345", Some("def67890"), Some(t(100)), None);
        assert_eq!(
            v,
            Verdict::WrongCommit {
                built: "abc12345".into(),
                head: "def67890".into()
            }
        );
        assert!(
            v.is_stale(),
            "a binary from another revision must stop a dev launcher"
        );
    }

    #[test]
    fn an_edit_after_the_build_is_stale_even_when_the_commit_matches() {
        let v = judge(
            "abc12345",
            Some("abc12345"),
            Some(t(100)),
            Some(("src/service.rs".into(), t(200))),
        );
        assert_eq!(
            v,
            Verdict::SourceNewer {
                newest: "src/service.rs".into()
            },
            "the commit is baked in at build time, so an uncommitted edit leaves \
             it equal to HEAD while the binary misses the edit entirely. That is \
             the ordinary case — edit, forget to rebuild, test the old code — and \
             only the timestamps catch it."
        );
        assert!(v.is_stale());
    }

    #[test]
    fn a_release_install_outside_a_checkout_is_not_stale() {
        assert_eq!(
            judge("abc12345", None, Some(t(100)), None),
            Verdict::NotACheckout
        );
        assert_eq!(
            judge("unknown", Some("abc12345"), Some(t(100)), None),
            Verdict::NotACheckout,
            "`build.rs` writes \"unknown\" outside a checkout; reporting that as \
             a mismatch would make every released install look broken"
        );
        assert!(
            !judge("abc12345", None, None, None).is_stale(),
            "an installed copy has no source to be behind — refusing to launch \
             it would be nonsense"
        );
    }

    #[test]
    fn the_wrong_revision_is_reported_before_a_stale_timestamp() {
        // Both are true here; only one gets reported.
        let v = judge(
            "abc12345",
            Some("def67890"),
            Some(t(100)),
            Some(("src/x.rs".into(), t(200))),
        );
        assert!(
            matches!(v, Verdict::WrongCommit { .. }),
            "being on another revision is the more fundamental mistake; leading \
             with \"source is newer\" sends someone looking at the wrong thing"
        );
    }
}

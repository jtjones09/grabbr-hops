//! The dev launchers bring their checkout up to date before building
//! (`hops_update_checkout` in `service/{macos,linux}/.hops-paths`).
//!
//! Each case runs the real shell function against a scratch clone of a scratch
//! remote, with git's configuration and environment isolated from this
//! machine's. Unix only: the Windows launcher is batch and is not run here.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A directory removed when the test ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("hops-launch-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    Scratch(dir)
}

/// git with nothing inherited: no GIT_ variables, no user or system config.
fn git(home: &Path, dir: &Path, args: &[&str]) -> Output {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn head(home: &Path, dir: &Path) -> String {
    String::from_utf8(git(home, dir, &["rev-parse", "HEAD"]).stdout)
        .expect("utf8")
        .trim()
        .to_string()
}

/// A remote with one commit, a clone that tracks it, and a second clone to
/// push new commits from.
struct Repos {
    _dir: Scratch,
    home: PathBuf,
    clone: PathBuf,
    other: PathBuf,
}

fn repos(name: &str) -> Repos {
    let dir = scratch(name);
    let home = dir.0.join("home");
    let remote = dir.0.join("remote.git");
    let clone = dir.0.join("clone");
    let other = dir.0.join("other");
    std::fs::create_dir_all(&home).expect("home");
    // An identity, so a plain merge would succeed and only the launcher's
    // fast-forward-only rule can refuse a diverged checkout.
    std::fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = t\n\temail = t@example.invalid\n[commit]\n\tgpgsign = false\n",
    )
    .expect("gitconfig");
    git(
        &home,
        &dir.0,
        &["init", "-q", "--bare", remote.to_str().expect("path")],
    );
    git(
        &home,
        &dir.0,
        &[
            "clone",
            "-q",
            remote.to_str().expect("path"),
            other.to_str().expect("path"),
        ],
    );
    std::fs::write(other.join("a.txt"), "one\n").expect("write");
    git(&home, &other, &["add", "a.txt"]);
    git(&home, &other, &["commit", "-q", "-m", "one"]);
    git(&home, &other, &["push", "-q", "origin", "HEAD:main"]);
    git(
        &home,
        &dir.0,
        &[
            "clone",
            "-q",
            remote.to_str().expect("path"),
            clone.to_str().expect("path"),
        ],
    );
    Repos {
        _dir: dir,
        home,
        clone,
        other,
    }
}

impl Repos {
    fn commit_on(&self, dir: &Path, text: &str) {
        std::fs::write(dir.join("a.txt"), text).expect("write");
        git(&self.home, dir, &["commit", "-q", "-am", text]);
    }

    fn push_new_commit(&self) {
        self.commit_on(&self.other, "two\n");
        git(
            &self.home,
            &self.other,
            &["push", "-q", "origin", "HEAD:main"],
        );
    }

    /// Run `hops_update_checkout` from `helpers` against the clone.
    fn update(&self, helpers: &Path, extra: &[(&str, &str)]) -> (bool, String) {
        let mut cmd = Command::new("bash");
        cmd.arg("-c")
            .arg(". \"$1\" && hops_update_checkout")
            .arg("_")
            .arg(helpers)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOPS_REPO", &self.clone);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("bash runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }
}

fn helper_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    vec![
        root.join("service/macos/.hops-paths"),
        root.join("service/linux/.hops-paths"),
    ]
}

// LEDGER T1 | class B | 5 exit code + stdout + 4 repository state: hops_update_checkout
#[test]
fn a_clean_checkout_behind_its_remote_is_fast_forwarded() {
    for helpers in helper_files() {
        let r = repos("behind");
        r.push_new_commit();
        let (ok, said) = r.update(&helpers, &[]);
        assert!(ok, "{}: {said}", helpers.display());
        assert_eq!(
            head(&r.home, &r.clone),
            head(&r.home, &r.other),
            "{}: the checkout was not brought up to date: {said}",
            helpers.display()
        );
        assert!(
            said.contains("building main at"),
            "{}: {said}",
            helpers.display()
        );
    }
}

// LEDGER T2 | class B | 5 exit code + stdout + 4 repository state: hops_update_checkout
#[test]
fn uncommitted_changes_are_built_as_they_are() {
    for helpers in helper_files() {
        let r = repos("dirty");
        r.push_new_commit();
        let before = head(&r.home, &r.clone);
        std::fs::write(r.clone.join("a.txt"), "local edit\n").expect("write");
        let (ok, said) = r.update(&helpers, &[]);
        assert!(ok, "{}: {said}", helpers.display());
        assert_eq!(
            head(&r.home, &r.clone),
            before,
            "{}: pulled over local edits",
            helpers.display()
        );
        assert!(
            said.contains("uncommitted changes"),
            "{}: {said}",
            helpers.display()
        );
    }
}

// LEDGER T3 | class B | 5 exit code + stdout + 4 repository state: hops_update_checkout
#[test]
fn a_checkout_that_has_diverged_stops_the_build() {
    for helpers in helper_files() {
        let r = repos("diverged");
        r.push_new_commit();
        // A local commit that touches a different file, so a plain merge
        // would succeed: only a fast-forward-only update refuses this.
        std::fs::write(r.clone.join("b.txt"), "local\n").expect("write");
        git(&r.home, &r.clone, &["add", "b.txt"]);
        git(&r.home, &r.clone, &["commit", "-q", "-m", "local"]);
        let before = head(&r.home, &r.clone);
        let (ok, said) = r.update(&helpers, &[]);
        assert!(
            !ok,
            "{}: a diverged checkout must stop the launcher: {said}",
            helpers.display()
        );
        assert_eq!(
            head(&r.home, &r.clone),
            before,
            "{}: the checkout changed",
            helpers.display()
        );
        assert!(said.contains("diverged"), "{}: {said}", helpers.display());
    }
}

// LEDGER T4 | class B | 5 exit code + stdout + 4 repository state: hops_update_checkout
#[test]
fn a_branch_with_no_remote_and_hops_no_pull_are_built_as_they_are() {
    for helpers in helper_files() {
        let r = repos("local");
        git(&r.home, &r.clone, &["switch", "-q", "-c", "just-here"]);
        let (ok, said) = r.update(&helpers, &[]);
        assert!(
            ok && said.contains("tracks no remote branch"),
            "{}: {said}",
            helpers.display()
        );

        let r = repos("nopull");
        r.push_new_commit();
        let before = head(&r.home, &r.clone);
        let (ok, said) = r.update(&helpers, &[("HOPS_NO_PULL", "1")]);
        assert!(
            ok && said.contains("HOPS_NO_PULL"),
            "{}: {said}",
            helpers.display()
        );
        assert_eq!(
            head(&r.home, &r.clone),
            before,
            "{}: HOPS_NO_PULL still pulled",
            helpers.display()
        );
    }
}

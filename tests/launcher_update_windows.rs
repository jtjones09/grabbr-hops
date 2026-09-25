//! The Windows dev launcher brings its checkout up to date before building
//! (`service/windows/grabbr-hop-update.cmd`, called by `grabbr-hop-dev.cmd`).
//!
//! Each case runs the real batch script through `cmd.exe` against a scratch
//! clone of a scratch remote, the same four cases `launcher_update.rs` runs
//! against the shell version. Windows only.
#![cfg(windows)]

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
        .env("USERPROFILE", home)
        .envs(windows_env())
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

/// What `cmd.exe` and git need from the environment that `env_clear` removes.
fn windows_env() -> Vec<(String, String)> {
    [
        "SystemRoot",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
    ]
    .into_iter()
    .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
    .collect()
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

    /// Run the update script against the clone.
    fn update(&self, extra: &[(&str, &str)]) -> (bool, String) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("service")
            .join("windows")
            .join("grabbr-hop-update.cmd");
        let mut cmd = Command::new("cmd");
        cmd.arg("/d")
            .arg("/c")
            .arg(&script)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(windows_env())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOPS_REPO", &self.clone);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("cmd runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }
}

#[test]
fn a_clean_checkout_behind_its_remote_is_fast_forwarded() {
    let r = repos("behind");
    r.push_new_commit();
    let (ok, said) = r.update(&[]);
    assert!(ok, "{said}");
    assert_eq!(
        head(&r.home, &r.clone),
        head(&r.home, &r.other),
        "the checkout was not brought up to date: {said}"
    );
    assert!(said.to_lowercase().contains("building main at"), "{said}");
}

#[test]
fn uncommitted_changes_are_built_as_they_are() {
    let r = repos("dirty");
    r.push_new_commit();
    let before = head(&r.home, &r.clone);
    std::fs::write(r.clone.join("a.txt"), "local edit\n").expect("write");
    let (ok, said) = r.update(&[]);
    assert!(ok, "{said}");
    assert_eq!(head(&r.home, &r.clone), before, "pulled over local edits");
    assert!(said.contains("uncommitted changes"), "{said}");
}

#[test]
fn a_checkout_that_has_diverged_stops_the_build() {
    let r = repos("diverged");
    r.push_new_commit();
    // A local commit that touches a different file, so a plain merge would
    // succeed: only a fast-forward-only update refuses this.
    std::fs::write(r.clone.join("b.txt"), "local\n").expect("write");
    git(&r.home, &r.clone, &["add", "b.txt"]);
    git(&r.home, &r.clone, &["commit", "-q", "-m", "local"]);
    let before = head(&r.home, &r.clone);
    let (ok, said) = r.update(&[]);
    assert!(!ok, "a diverged checkout must stop the launcher: {said}");
    assert_eq!(head(&r.home, &r.clone), before, "the checkout changed");
    assert!(said.contains("diverged"), "{said}");
}

#[test]
fn a_branch_with_no_remote_and_hops_no_pull_are_built_as_they_are() {
    let r = repos("local");
    git(&r.home, &r.clone, &["switch", "-q", "-c", "just-here"]);
    let (ok, said) = r.update(&[]);
    assert!(ok && said.contains("tracks no remote branch"), "{said}");

    let r = repos("nopull");
    r.push_new_commit();
    let before = head(&r.home, &r.clone);
    let (ok, said) = r.update(&[("HOPS_NO_PULL", "1")]);
    assert!(ok && said.contains("HOPS_NO_PULL"), "{said}");
    assert_eq!(head(&r.home, &r.clone), before, "HOPS_NO_PULL still pulled");
}

//! `build-check` must answer when the config file does not.
//!
//! It is the command someone runs to find out why the others are failing, so it
//! cannot need them to work. It used to: `Config::new()` loaded and validated
//! the config file before any subcommand was dispatched, so one bad line there
//! made the check exit 1 having never run — printing nothing at all. Exit 1 is
//! also what `--strict` used to return for a stale binary, so every launcher
//! read a corrupt config as "stale" and told the user to rebuild, which no
//! rebuild could fix.
//!
//! Only an end-to-end test sees this: the defect was the ORDER of two calls in
//! `main`, and every unit test of the check itself passed throughout.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

fn hops() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hops"))
}

#[test]
fn a_broken_config_file_does_not_stop_the_diagnostic() {
    let dir = std::env::temp_dir().join(format!("hops-bc-{}", std::process::id()));
    let cfg = dir.join("lan-mouse");
    std::fs::create_dir_all(&cfg).expect("mkdir");
    // The exact shape the config module documents as having happened: a value
    // of the wrong type, which fails deserialization rather than parsing.
    std::fs::write(cfg.join("config.toml"), "port = \"not-a-number\"\n").expect("write");

    let out = hops()
        .args([
            "build-check",
            "--repo",
            env!("CARGO_MANIFEST_DIR"),
            "--strict",
        ])
        .env("XDG_CONFIG_HOME", &dir)
        .output()
        .expect("run");

    let code = out.status.code();
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_ne!(
        code,
        Some(1),
        "exit 1 is this process's generic failure. Returning it here means a \
         launcher cannot tell an unparseable config from a stale binary, and \
         tells the user to rebuild for a problem no rebuild fixes. stdout was: \
         {stdout:?}"
    );
    assert!(
        stdout.contains("hops") || stdout.contains("STALE"),
        "the check must actually run and say something; it printed nothing, \
         which is what it did when the config was loaded first. stdout: {stdout:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_path_with_no_checkout_cannot_pass_a_strict_gate() {
    let empty = std::env::temp_dir().join(format!("hops-bc-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).expect("mkdir");

    let strict = hops()
        .args(["build-check", "--repo"])
        .arg(&empty)
        .arg("--strict")
        .output()
        .expect("run");
    assert_ne!(
        strict.status.code(),
        Some(0),
        "a --strict gate that found no checkout compared nothing. Reporting \
         success there is a gate that passes having verified nothing, which \
         reads as proof and is worse than having no gate at all."
    );

    let lenient = hops()
        .args(["build-check", "--repo"])
        .arg(&empty)
        .output()
        .expect("run");
    assert_eq!(
        lenient.status.code(),
        Some(0),
        "without --strict nothing may block a launch — a daily binary on a \
         machine with no source tree must still start"
    );

    let _ = std::fs::remove_dir_all(&empty);
}

/// Variables that move where git reads `HEAD` from, given as `files://<dir>`:
/// `GIT_REFERENCE_BACKEND` from git 2.54, and its newer name
/// `GIT_REF_STORAGE_FORMAT`. An older git ignores both.
const REF_BACKEND_VARS: &[&str] = &["GIT_REFERENCE_BACKEND", "GIT_REF_STORAGE_FORMAT"];

/// The value of `var` that points git at the repository in `git_dir`.
fn pointing_at(var: &str, git_dir: &Path) -> OsString {
    if REF_BACKEND_VARS.contains(&var) {
        format!("files://{}", git_dir.display()).into()
    } else {
        git_dir.into()
    }
}

/// Whether git reads `name` as one of its own variables on some platform:
/// `GIT_` in any case, since Windows looks names up regardless of case.
fn is_git_variable(name: &str) -> bool {
    name.get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("GIT_"))
}

/// Remove every git variable this test process inherited from `cmd`, so a test
/// run from inside a hook neither writes into the repository being committed
/// nor hands the hook's repository to the command under test.
fn without_git_variables(cmd: &mut Command) -> &mut Command {
    for (name, _) in std::env::vars_os() {
        if is_git_variable(&name.to_string_lossy()) {
            cmd.env_remove(name);
        }
    }
    cmd
}

/// A directory that is removed when the test ends, pass or fail.
struct Scratch(PathBuf);

impl Scratch {
    fn new(base: &Path, name: &str) -> Self {
        let dir = base.join(format!("hops-bc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `git -C <dir>` with no inherited git variable.
fn setup_git(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    without_git_variables(&mut cmd).arg("-C").arg(dir);
    cmd
}

fn stdout_of(cmd: &mut Command) -> String {
    let out = cmd.output().expect("these tests need git on PATH");
    assert!(
        out.status.success(),
        "git setup step failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf-8")
        .trim()
        .to_string()
}

/// A new repository at `dir` whose HEAD is one empty commit, returned in the
/// short form the check prints. Plumbing only, so no hook, signing key or user
/// identity from the machine's git config takes part.
fn repo_with_one_commit(dir: &Path, message: &str) -> String {
    std::fs::create_dir_all(dir).expect("mkdir");
    stdout_of(setup_git(dir).args(["init", "-q"]));
    let tree = stdout_of(setup_git(dir).arg("write-tree"));
    let commit = stdout_of(setup_git(dir).args([
        "-c",
        "user.name=hops test",
        "-c",
        "user.email=hops-test@example.invalid",
        "commit-tree",
        "--no-gpg-sign",
        &tree,
        "-m",
        message,
    ]));
    stdout_of(setup_git(dir).args(["update-ref", "HEAD", &commit]));
    stdout_of(setup_git(dir).args(["rev-parse", "--short=8", "HEAD"]))
}

/// The commit `build.rs` baked into the hops under test, read from the report
/// for a directory that holds no checkout, or `None` if it baked none.
fn baked_commit(no_checkout: &Path) -> Option<String> {
    let out = without_git_variables(&mut hops())
        .args(["build-check", "--repo"])
        .arg(no_checkout)
        .output()
        .expect("run");
    let report = String::from_utf8_lossy(&out.stdout);
    let commit = report
        .strip_prefix("hops ")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no commit in the report: {report:?}"));
    (commit != "unknown").then(|| commit.to_string())
}

/// A launcher started from inside git (a hook, or a shell that exported it)
/// carries `GIT_DIR`, and `git -C <repo>` obeys it over `<repo>`. The check then
/// compared that other repository: it named the wrong commit for a checkout,
/// and could pass a strict gate for a path that holds none. The ref backend
/// variables do the same for `HEAD` on a git new enough to read them; an older
/// git ignores them, and that part of the comparison holds whatever the check
/// does.
// LEDGER T12 | class B | 5 process exit code + stdout
#[test]
fn an_inherited_repository_does_not_stand_in_for_the_named_checkout() {
    let scratch = Scratch::new(&std::env::temp_dir(), "gitdir");
    let named = scratch.0.join("named");
    let other = scratch.0.join("other");
    let empty = scratch.0.join("empty");
    let named_head = repo_with_one_commit(&named, "named");
    let other_head = repo_with_one_commit(&other, "other");
    std::fs::create_dir_all(&empty).expect("mkdir");
    assert_ne!(named_head, other_head);

    if baked_commit(&empty).is_none() {
        eprintln!(
            "nothing compared: this hops was built without a commit baked in, so \
             it reports no checkout whichever repository it reads"
        );
        return;
    }

    let strict_check = |path: &Path, inherited: Option<&str>| {
        let mut cmd = hops();
        without_git_variables(&mut cmd);
        if let Some(var) = inherited {
            cmd.env(var, pointing_at(var, &other.join(".git")));
        }
        let out = cmd
            .args(["build-check", "--repo"])
            .arg(path)
            .arg("--strict")
            .output()
            .expect("run");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };

    let (_, report) = strict_check(&named, None);
    assert!(
        report.contains(&named_head),
        "the check did not compare the named checkout at all, so agreement \
         below would prove nothing. stdout: {report:?}"
    );

    // The checkout whose HEAD differs goes first: its exit code is 2 whichever
    // repository is compared, so only the commit in the report tells them apart.
    for &var in ["GIT_DIR"].iter().chain(REF_BACKEND_VARS) {
        for path in [&named, &empty] {
            assert_eq!(
                strict_check(path, Some(var)),
                strict_check(path, None),
                "--repo {} was judged by the repository an inherited {var} \
                 named, not by what is at that path",
                path.display()
            );
        }
    }
}

/// The compiler for this build: `rustc` beside the `cargo` running it, or the
/// one on PATH.
fn rustc() -> PathBuf {
    let beside_cargo =
        Path::new(env!("CARGO")).with_file_name(format!("rustc{}", std::env::consts::EXE_SUFFIX));
    if beside_cargo.is_file() {
        beside_cargo
    } else {
        PathBuf::from("rustc")
    }
}

/// The edition this package is built with, read from its manifest.
fn package_edition(manifest_dir: &Path) -> String {
    let manifest =
        std::fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("read Cargo.toml");
    let manifest: toml_edit::DocumentMut = manifest.parse().expect("parse Cargo.toml");
    manifest["package"]["edition"]
        .as_str()
        .unwrap_or("2015")
        .to_string()
}

/// `build.rs` asks git for the commit to bake in. A build started from inside
/// git, such as a hook in another repository, inherits `GIT_DIR`. When that
/// reached git, the binary carried the other repository's commit, every strict
/// check reported it stale, and rebuilding kept it.
///
/// The build of this suite inherits no such variable, so its own binary agrees
/// with the checkout either way. This compiles the checkout's `build.rs` and
/// runs it the way cargo does, with each variable set, for a repository of its
/// own; that happens in every run, a source archive included.
// LEDGER T15 | class B | 5 process stdout: the commit build.rs prints for cargo
#[test]
fn the_build_script_bakes_its_own_checkout_whatever_git_variables_it_inherits() {
    let scratch = Scratch::new(Path::new(env!("CARGO_TARGET_TMPDIR")), "build-script");
    let named = scratch.0.join("named");
    let other = scratch.0.join("other");
    let named_head = repo_with_one_commit(&named, "named");
    let other_head = repo_with_one_commit(&other, "other");
    assert_ne!(named_head, other_head);

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = scratch.0.join(format!(
        "build-script-build{}",
        std::env::consts::EXE_SUFFIX
    ));
    let compiled = without_git_variables(&mut Command::new(rustc()))
        .current_dir(manifest_dir)
        .args(["--edition", &package_edition(manifest_dir)])
        .args(["--crate-name", "build_script_build", "--crate-type", "bin"])
        .arg("-o")
        .arg(&script)
        .arg(manifest_dir.join("build.rs"))
        .output()
        .expect("run rustc");
    assert!(
        compiled.status.success(),
        "build.rs did not compile on its own: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    // Cargo runs a build script from the package directory and names that
    // directory in CARGO_MANIFEST_DIR.
    let baked = |inherited: Option<&str>| {
        let mut cmd = Command::new(&script);
        without_git_variables(&mut cmd)
            .current_dir(&named)
            .env("CARGO_MANIFEST_DIR", &named);
        if let Some(var) = inherited {
            cmd.env(var, pointing_at(var, &other.join(".git")));
        }
        let out = cmd.output().expect("run the build script");
        assert!(
            out.status.success(),
            "the build script failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("cargo::rustc-env=HOPS_SHORT_COMMIT="))
            .map(str::to_string)
    };

    assert_eq!(
        baked(None).as_deref(),
        Some(named_head.as_str()),
        "with no git variable set the build script did not bake the HEAD of \
         its own directory, so the runs below would compare nothing"
    );
    for &var in ["GIT_DIR"].iter().chain(REF_BACKEND_VARS) {
        assert_eq!(
            baked(Some(var)).as_deref(),
            Some(named_head.as_str()),
            "built under an inherited {var}, the binary carries the commit of \
             the repository that variable names, so every strict build-check \
             reports it stale and no rebuild changes that"
        );
    }
}

/// A caller can fence git in with `GIT_CEILING_DIRECTORIES`, so that a path
/// holding no checkout is not judged by a checkout above it. Removing every git
/// variable removed that fence too: the check then gave a verdict about the
/// enclosing checkout instead of saying that nothing was compared.
// LEDGER T17 | class B | 5 process exit code + stdout
#[test]
fn a_ceiling_the_caller_set_still_stops_the_search_for_a_checkout() {
    let empty = Scratch::new(&std::env::temp_dir(), "ceiling-empty");
    if baked_commit(&empty.0).is_none() {
        eprintln!(
            "nothing compared: this hops was built without a commit baked in, so \
             it reports no checkout wherever git stops"
        );
        return;
    }

    let scratch = Scratch::new(Path::new(env!("CARGO_TARGET_TMPDIR")), "ceiling");
    let enclosing = scratch.0.join("enclosing");
    let enclosing_head = repo_with_one_commit(&enclosing, "enclosing");
    let below = enclosing.join("no-checkout-here");
    std::fs::create_dir_all(&below).expect("mkdir");

    let strict_check = |ceiling: Option<&Path>| {
        let mut cmd = hops();
        without_git_variables(&mut cmd);
        if let Some(dir) = ceiling {
            cmd.env("GIT_CEILING_DIRECTORIES", dir);
        }
        let out = cmd
            .args(["build-check", "--repo"])
            .arg(&below)
            .arg("--strict")
            .output()
            .expect("run");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };

    let (_, report) = strict_check(None);
    assert!(
        report.contains(&enclosing_head),
        "with no ceiling the check did not reach the enclosing checkout, so a \
         ceiling would have nothing to stop. stdout: {report:?}"
    );

    let (code, report) = strict_check(Some(&enclosing));
    assert_eq!(
        code,
        Some(3),
        "GIT_CEILING_DIRECTORIES fenced off the enclosing checkout, yet the \
         check judged --repo by it rather than reporting that nothing was \
         compared. stdout: {report:?}"
    );
}

/// `git status` refreshes the index when a file's timestamp no longer matches
/// the one recorded, and writes it back under the index lock. A commit started
/// at that moment fails on the lock. The check only reads, so it must leave the
/// index as it found it.
// LEDGER T16 | class B | 4 file on disk: the checkout's index after the check
#[test]
fn the_check_does_not_rewrite_the_index_of_the_checkout_it_reads() {
    let scratch = Scratch::new(&std::env::temp_dir(), "index");
    let repo = scratch.0.join("repo");
    repo_with_one_commit(&repo, "index");
    let file = repo.join("a.rs");
    // No line ending, so no end-of-line conversion takes part.
    std::fs::write(&file, "x").expect("write");
    stdout_of(setup_git(&repo).args(["add", "a.rs"]));
    let long_ago =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    std::fs::File::options()
        .write(true)
        .open(&file)
        .and_then(|f| f.set_modified(long_ago))
        .expect("set the file's timestamp");
    let index = repo.join(".git").join("index");
    let before = std::fs::read(&index).expect("read the index");

    let out = without_git_variables(&mut hops())
        .args(["build-check", "--repo"])
        .arg(&repo)
        .arg("--strict")
        .output()
        .expect("run");
    assert_eq!(
        std::fs::read(&index).expect("read the index"),
        before,
        "build-check rewrote the index of the checkout it only reads, taking \
         the lock a commit needs. stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    stdout_of(setup_git(&repo).args(["status", "--porcelain"]));
    assert_ne!(
        std::fs::read(&index).expect("read the index"),
        before,
        "a plain git status left this index unchanged too, so the comparison \
         above observed nothing"
    );
}

/// Marks the start of one call in the fake git's log.
#[cfg(unix)]
const CALL_MARK: &str = "@@hops-test-git-call@@";

#[cfg(unix)]
fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

/// One git call the check made: its arguments and every variable it received.
#[cfg(unix)]
struct GitCall {
    args: String,
    env: Vec<String>,
}

/// Run `build-check --strict` on a checkout, with `set` added to the
/// environment and each value that names a repository pointing at another one,
/// through a git on PATH that logs each call's environment before running the
/// real one.
#[cfg(unix)]
fn git_calls_with(name: &str, set: &[&str]) -> Vec<GitCall> {
    use std::os::unix::fs::PermissionsExt;

    // The fake git has to be executable, and a cargo target directory is.
    let scratch = Scratch::new(Path::new(env!("CARGO_TARGET_TMPDIR")), name);
    let named = scratch.0.join("named");
    let other = scratch.0.join("other");
    repo_with_one_commit(&named, "named");
    repo_with_one_commit(&other, "other");

    let path = std::env::var_os("PATH").unwrap_or_default();
    let real_git = std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|git| git.is_file())
        .expect("these tests need git on PATH");
    let log = scratch.0.join("calls.log");
    let script = format!(
        "#!/bin/sh\n\
         {{ echo '{CALL_MARK}' \"$*\"; env; }} >> {log}\n\
         exec {real_git} \"$@\"\n",
        log = sh_quote(&log),
        real_git = sh_quote(&real_git),
    );
    let bin = scratch.0.join("bin");
    std::fs::create_dir_all(&bin).expect("mkdir");
    let fake_git = bin.join("git");
    std::fs::write(&fake_git, script).expect("write the fake git");
    std::fs::set_permissions(&fake_git, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let mut cmd = hops();
    let search = std::iter::once(bin).chain(std::env::split_paths(&path));
    cmd.env("PATH", std::env::join_paths(search).expect("PATH"));
    for var in set {
        cmd.env(var, pointing_at(var, &other.join(".git")));
    }
    let out = cmd
        .args(["build-check", "--repo"])
        .arg(&named)
        .arg("--strict")
        .output()
        .expect("run");

    let mut calls: Vec<GitCall> = Vec::new();
    for line in std::fs::read_to_string(&log).unwrap_or_default().lines() {
        if let Some(args) = line.strip_prefix(CALL_MARK) {
            calls.push(GitCall {
                args: args.trim().to_string(),
                env: Vec::new(),
            });
        } else if let (Some((var, _)), Some(call)) = (line.split_once('='), calls.last_mut()) {
            call.env.push(var.to_string());
        }
    }
    assert!(
        calls
            .iter()
            .any(|call| call.args.ends_with("rev-parse --short=8 HEAD")),
        "build-check did not run git through the logging git, so nothing was \
         observed. calls: {:?}; stdout: {}",
        calls.iter().map(|call| &call.args).collect::<Vec<_>>(),
        String::from_utf8_lossy(&out.stdout)
    );
    calls
}

/// `git -C` obeys an inherited `GIT_DIR` over the path, and git keeps adding
/// variables that do the same: the ref backend ones, which
/// `git rev-parse --local-env-vars` does not list, and whatever comes next. So
/// no variable git would read as its own may reach a call the check makes, a
/// name no git knows yet and one in another case included. The one exception
/// is `GIT_CEILING_DIRECTORIES`, which can only stop git finding a repository
/// (see the ceiling test).
#[cfg(unix)]
// LEDGER T13 | class B | 5 process started: environment of each git build-check runs
#[test]
fn no_git_variable_reaches_the_checks_git_calls() {
    let mut set = vec![
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_HOPS_FUTURE_VAR",
        "Git_Hops_Mixed_Case_Var",
    ];
    set.extend(REF_BACKEND_VARS);
    let leaked: Vec<_> = git_calls_with("env-git", &set)
        .into_iter()
        .map(|call| {
            let received: Vec<_> = call
                .env
                .into_iter()
                .filter(|var| {
                    is_git_variable(var) && !var.eq_ignore_ascii_case("GIT_CEILING_DIRECTORIES")
                })
                .collect();
            (call.args, received)
        })
        .filter(|(_, received)| !received.is_empty())
        .collect();
    assert!(
        leaked.is_empty(),
        "these git calls received git variables, any of which may choose a \
         repository other than --repo: {leaked:?}"
    );
}

/// Only git's own variables are taken away: the rest of the environment, such
/// as the home directory git finds its config through, still reaches git, and
/// a name that merely contains `GIT_` is not one of git's.
#[cfg(unix)]
// LEDGER T14 | class B | 5 process started: environment of each git build-check runs
#[test]
fn variables_that_are_not_gits_still_reach_git() {
    const KEPT: &str = "HOPS_GIT_TEST_NOT_A_GIT_VARIABLE";
    let missing: Vec<_> = git_calls_with("env-kept", &[KEPT])
        .into_iter()
        .filter(|call| !call.env.iter().any(|var| var == KEPT))
        .map(|call| call.args)
        .collect();
    assert!(
        missing.is_empty(),
        "{KEPT} is not a git variable, yet these git calls did not receive it: \
         {missing:?}"
    );
}

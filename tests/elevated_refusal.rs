//! hops runs as the user and is never elevated (#109): an elevated hops on
//! Windows exits 1, says why on stderr, and creates, opens and changes no
//! file, not even its log, since an elevated process doing that where the
//! user can write is the hazard itself.
//!
//! GitHub's Windows runners run every job as an administrator with User
//! Account Control off, so there this runs the real refusal: check.yml runs
//! it in a build without `elevated_ci_runner` and sets
//! `HOPS_TEST_RUNNER_IS_ELEVATED`, which fails the test if the runner is
//! not elevated and it would prove nothing. Anywhere hops may run, the same
//! command runs and exits 0.

use std::process::{Command, Stdio};

/// Whether this process is elevated, as `whoami` reports it: an elevated
/// token has the High or System mandatory level.
#[cfg(windows)]
fn elevated_by_the_os() -> bool {
    let out = Command::new("whoami")
        .arg("/groups")
        .output()
        .expect("whoami runs");
    let groups = String::from_utf8_lossy(&out.stdout);
    groups.contains("S-1-16-12288") || groups.contains("S-1-16-16384")
}

/// hops refuses only on Windows.
#[cfg(not(windows))]
fn elevated_by_the_os() -> bool {
    false
}

// LEDGER T1098 | class B | 5 process exit code + stderr + files on disk
#[test]
fn an_elevated_hops_exits_1_says_why_and_touches_no_file() {
    let refuses = cfg!(windows) && !cfg!(feature = "elevated_ci_runner") && elevated_by_the_os();
    if std::env::var_os("HOPS_TEST_RUNNER_IS_ELEVATED").is_some() {
        assert!(
            refuses,
            "HOPS_TEST_RUNNER_IS_ELEVATED says this run tests the refusal on an \
             elevated Windows runner, in a build without `elevated_ci_runner`, and \
             it is not one: windows {}, elevated {}",
            cfg!(windows),
            elevated_by_the_os()
        );
    }

    let dir = std::env::temp_dir().join(format!("hops-elevated-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let mut hops = Command::new(env!("CARGO_BIN_EXE_hops"));
    hops.arg("--version")
        .env("HOPS_LOG_FILE", dir.join("hops.log"))
        .stdin(Stdio::null());
    for var in [
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
    ] {
        hops.env(var, &dir);
    }
    let out = hops.output().expect("the hops binary starts");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let left: Vec<String> = std::fs::read_dir(&dir)
        .expect("the scratch directory")
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    let _ = std::fs::remove_dir_all(&dir);

    if refuses {
        assert!(
            out.status.code() == Some(1)
                && stderr.contains(hops::elevation::RUNS_AS_THE_USER)
                && stdout.is_empty()
                && left.is_empty(),
            "an elevated hops must exit 1 with the fix on stderr, run nothing and \
             create no file: exit {:?}, stdout {stdout:?}, stderr {stderr:?}, \
             files {left:?}",
            out.status.code()
        );
    } else {
        assert!(
            out.status.success() && stdout.contains(env!("CARGO_PKG_VERSION")),
            "hops refused to run, or failed, where it may run: exit {:?}, stdout \
             {stdout:?}, stderr {stderr:?}",
            out.status.code()
        );
    }
}

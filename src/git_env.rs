//! `git` pointed at a path, and at nothing its environment names instead.
//!
//! `build.rs` bakes the commit into the binary and `build_check` compares
//! against it, so both must read the checkout they are given. A build script
//! cannot use this crate's modules, so `build.rs` compiles this file in with
//! `#[path]`: one copy, one rule.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

/// The one git variable passed on.
///
/// `GIT_CEILING_DIRECTORIES` names directories git must not climb into while
/// it looks for a repository above the path. It can stop git finding a
/// repository, never make it find another one, and git ignores it when the
/// path itself holds one. Removing it let a path with no checkout be judged by
/// an enclosing checkout the caller had fenced off.
pub(crate) const KEPT_GIT_VARIABLE: &str = "GIT_CEILING_DIRECTORIES";

/// `git -C <repo>`, with every inherited variable whose name starts with
/// `GIT_` removed, except [`KEPT_GIT_VARIABLE`].
///
/// `git -C` obeys an inherited `GIT_DIR` over the path, and a hook exports
/// one. It is not the only such variable, and git keeps adding them:
/// `GIT_REFERENCE_BACKEND` (git 2.54) and its newer name
/// `GIT_REF_STORAGE_FORMAT` move where `HEAD` is read from, and
/// `git rev-parse --local-env-vars` lists neither. A list of names to remove
/// misses the next one, so only a name known to be safe is kept. git finds the
/// repository from the path, its helper programs from where it is installed,
/// and its config in the default files. That config cannot move the
/// repository either: git reads where refs and objects live only from the
/// repository's own config file (`read_repository_format` in git's `setup.c`).
///
/// Config given through the environment (`GIT_CONFIG_COUNT` and the like) is
/// removed with the rest, `safe.directory` included. A checkout that needs it
/// is then refused by git, and the check reports that nothing was compared.
pub(crate) fn git_at(repo: &Path) -> Command {
    let mut cmd = Command::new("git");
    for (name, _) in std::env::vars_os() {
        if is_git_variable(&name) && !is_kept(&name) {
            cmd.env_remove(name);
        }
    }
    cmd.arg("-C").arg(repo);
    cmd
}

/// `GIT_` in any case: git on Windows looks variables up with
/// `GetEnvironmentVariableW`, which ignores case, so it reads `Git_Dir` as
/// `GIT_DIR`.
fn is_git_variable(name: &OsStr) -> bool {
    name.to_string_lossy()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("GIT_"))
}

/// In any case, for the same reason: on Windows every spelling is the one
/// variable.
fn is_kept(name: &OsStr) -> bool {
    name.to_string_lossy()
        .eq_ignore_ascii_case(KEPT_GIT_VARIABLE)
}

use std::path::PathBuf;

#[path = "src/git_env.rs"]
mod git_env;

fn main() {
    // Embed the short git commit (sent in the peer "hello" as a build id). We read
    // it with the `git` CLI on purpose, NOT a libgit2 binding: pulling in
    // git2/libgit2-sys compiles libgit2's bundled C sources — including a file
    // literally named `credential.c` — which trips endpoint-security (EDR)
    // heuristics on managed machines. The CLI needs no C compilation. Falls back
    // to "unknown" outside a git checkout (e.g. a release tarball).
    //
    // Asked of this package's directory with no inherited GIT_ variable, the
    // same way `build-check` asks (src/git_env.rs). A build started from inside
    // git, such as a hook in another repository, would otherwise bake that
    // repository's commit, and later builds would keep it.
    //
    // Only when this directory is the top of its checkout. git searches upward,
    // so source unpacked inside some other repository (a packaging recipe's, or
    // a home directory kept in git) would otherwise bake that repository's
    // commit as this build's id.
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    let commit = git_env::work_tree(&manifest_dir)
        .filter(|(_, is_top)| *is_top)
        .and_then(|_| {
            git_env::git_at(&manifest_dir)
                .args(["rev-parse", "--short=8", "HEAD"])
                .output()
                .ok()
        })
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo::rustc-env=HOPS_SHORT_COMMIT={commit}");

    // Rebuild when the commit changes. Watching .git/HEAD alone is NOT enough:
    // on a branch, HEAD holds "ref: refs/heads/<branch>" and only changes when
    // you SWITCH branches — committing updates the ref file it points at. So a
    // series of commits on one branch kept baking in the hash from whenever
    // build.rs last ran, and `hops --version` reported a stale commit. That is
    // load-bearing: it is how a deployed binary is matched to its source.
    println!("cargo::rerun-if-changed=.git/HEAD");
    if let Ok(head) = std::fs::read_to_string(".git/HEAD") {
        if let Some(git_ref) = head.strip_prefix("ref:").map(str::trim) {
            println!("cargo::rerun-if-changed=.git/{git_ref}");
        }
    }
    // refs can live packed rather than as loose files
    println!("cargo::rerun-if-changed=.git/packed-refs");
    // No commit read: git missing, or refusing the checkout (safe.directory).
    // Installing git or trusting the checkout changes none of the files above,
    // so a checkout that has them all kept "unknown" baked in, and rebuilding
    // did not help. Cargo reruns a script that watches a missing path on every
    // build, recompiling this package, so the script reruns until git reads a
    // commit. A source archive, with no .git/HEAD, already reruns that way.
    if commit == "unknown" {
        println!("cargo::rerun-if-changed=.git/hops-build-read-no-commit");
    }

    let unix = target_is("unix");
    let macos = target_os() == "macos";

    let layer_shell_capture = cfg!(feature = "layer_shell_capture");
    let libei_capture = cfg!(feature = "libei_capture");
    let x11_capture = cfg!(feature = "x11_capture");

    let libei_emulation = cfg!(feature = "libei_emulation");
    let x11_emulation = cfg!(feature = "x11_emulation");
    let wlroots_emulation = cfg!(feature = "wlroots_emulation");
    let rdp_emulation = cfg!(feature = "rdp_emulation");

    let layer_shell_capture = unix && !macos && layer_shell_capture;
    let libei_capture = unix && !macos && libei_capture;
    let x11_capture = unix && !macos && x11_capture;

    let libei_emulation = unix && !macos && libei_emulation;
    let rdp_emulation = unix && !macos && rdp_emulation;
    let wlroots_emulation = unix && !macos && wlroots_emulation;
    let x11_emulation = unix && !macos && x11_emulation;

    println!("cargo::rustc-check-cfg=cfg(layer_shell_capture)");
    println!("cargo::rustc-check-cfg=cfg(libei_capture)");
    println!("cargo::rustc-check-cfg=cfg(x11_capture)");

    println!("cargo::rustc-check-cfg=cfg(libei_emulation)");
    println!("cargo::rustc-check-cfg=cfg(rdp_emulation)");
    println!("cargo::rustc-check-cfg=cfg(wlroots_emulation)");
    println!("cargo::rustc-check-cfg=cfg(x11_emulation)");

    if layer_shell_capture {
        println!("cargo::rustc-cfg=layer_shell_capture");
    }
    if libei_capture {
        println!("cargo::rustc-cfg=libei_capture");
    }
    if x11_capture {
        println!("cargo::rustc-cfg=x11_capture");
    }

    if libei_emulation {
        println!("cargo::rustc-cfg=libei_emulation");
    }
    if rdp_emulation {
        println!("cargo::rustc-cfg=rdp_emulation");
    }
    if wlroots_emulation {
        println!("cargo::rustc-cfg=wlroots_emulation");
    }
    if x11_emulation {
        println!("cargo::rustc-cfg=x11_emulation");
    }
}

// See crates/input-capture/build.rs for why these read the environment rather
// than `cfg!`: a build script runs on the HOST, so host predicates silently
// mis-configure every cross-compile (#44).
fn target_is(family: &str) -> bool {
    std::env::var("CARGO_CFG_TARGET_FAMILY")
        .unwrap_or_default()
        .split(',')
        .any(|f| f == family)
}

fn target_os() -> String {
    std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default()
}

use std::process::Command;

fn main() {
    // Embed the short git commit (sent in the peer "hello" as a build id). We read
    // it with the `git` CLI on purpose, NOT a libgit2 binding: pulling in
    // git2/libgit2-sys compiles libgit2's bundled C sources — including a file
    // literally named `credential.c` — which trips endpoint-security (EDR)
    // heuristics on managed machines. The CLI needs no C compilation. Falls back
    // to "unknown" outside a git checkout (e.g. a release tarball).
    let commit = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo::rustc-env=HOPS_SHORT_COMMIT={commit}");
    println!("cargo::rerun-if-changed=.git/HEAD");

    let unix = cfg!(unix);
    let macos = cfg!(target_os = "macos");

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

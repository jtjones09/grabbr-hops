// Build scripts run on the HOST, so `cfg!(unix)` / `cfg!(target_os = ...)` here
// describe the machine doing the building — NOT the machine being built for.
// Reading them meant every cross-compile silently disabled every Unix backend
// and still reported success: `cargo check --target x86_64-unknown-linux-gnu`
// from a Mac decided `macos=true` and switched off libei, layer_shell and x11.
// That makes "let me verify the Linux build locally" a false green (#44).
//
// `CARGO_CFG_TARGET_OS` / `CARGO_CFG_TARGET_FAMILY` are set by cargo from the
// TARGET and are the correct source. `cfg!(feature = ...)` IS correct in a build
// script — features are passed through — so only the platform predicates change.
fn target_is(family: &str) -> bool {
    std::env::var("CARGO_CFG_TARGET_FAMILY")
        .unwrap_or_default()
        .split(',')
        .any(|f| f == family)
}

fn target_os() -> String {
    std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default()
}

fn main() {
    let unix = target_is("unix");
    let layer_shell = cfg!(feature = "layer_shell");
    let libei = cfg!(feature = "libei");
    let x11 = cfg!(feature = "x11");
    let macos = target_os() == "macos";

    let libei = unix && !macos && libei;
    let layer_shell = unix && !macos && layer_shell;
    let x11 = unix && !macos && x11;

    println!("cargo::rustc-check-cfg=cfg(layer_shell)");
    println!("cargo::rustc-check-cfg=cfg(libei)");
    println!("cargo::rustc-check-cfg=cfg(x11)");

    if layer_shell {
        println!("cargo::rustc-cfg=layer_shell");
    }
    if libei {
        println!("cargo::rustc-cfg=libei");
    }
    if x11 {
        println!("cargo::rustc-cfg=x11");
    }
}

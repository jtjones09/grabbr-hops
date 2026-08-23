// Repro for #4: does HopsTray::hide() abort on a const-folded property?

fn main() {
    let tray = hops_slint::HopsTray::new().expect("tray");
    eprintln!("REPRO: tray created");
    tray.show().expect("show");
    eprintln!("REPRO: show() OK (visible was already true, so set() is a no-op)");
    eprintln!("REPRO: calling hide() ...");
    let _ = tray.hide();
    eprintln!("REPRO: hide() RETURNED — no panic");
}

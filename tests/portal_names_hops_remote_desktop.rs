//! Remote-desktop emulation registers hops with the desktop portal before it
//! asks the portal for anything, so the consent prompt can say who is asking
//! (#113).
#![cfg(all(unix, not(target_os = "macos"), feature = "rdp_emulation"))]

mod portal;

// LEDGER T12 | class B | 2 D-Bus calls: remote-desktop emulation's, in order, to a stand-in portal
#[tokio::test]
async fn remote_desktop_emulation_registers_hops_before_its_first_portal_call() {
    let stand_in = portal::start("remote-desktop");
    portal::registers_before_the_first_portal_call(
        &stand_in,
        "remote-desktop emulation",
        input_emulation::InputEmulation::new(Some(input_emulation::Backend::Xdp)),
    )
    .await;
}

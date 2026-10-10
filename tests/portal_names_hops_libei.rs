//! libei emulation registers hops with the desktop portal before it asks the
//! portal for anything, so the consent prompt can say who is asking (#113).
#![cfg(all(unix, not(target_os = "macos"), feature = "libei_emulation"))]

mod portal;

// LEDGER T11 | class B | 2 D-Bus calls: libei emulation's, in order, to a stand-in portal
#[tokio::test]
async fn libei_emulation_registers_hops_before_its_first_portal_call() {
    let stand_in = portal::start("libei");
    portal::registers_before_the_first_portal_call(
        &stand_in,
        "libei emulation",
        input_emulation::InputEmulation::new(Some(input_emulation::Backend::Libei)),
    )
    .await;
}

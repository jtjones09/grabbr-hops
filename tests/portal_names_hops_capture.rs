//! Input capture registers hops with the desktop portal before it asks the
//! portal for anything, so the consent prompt can say who is asking (#113).
#![cfg(all(unix, not(target_os = "macos"), feature = "libei_capture"))]

mod portal;

// LEDGER T10 | class B | 2 D-Bus calls: input capture's, in order, to a stand-in portal
#[tokio::test]
async fn input_capture_registers_hops_before_its_first_portal_call() {
    let stand_in = portal::start("capture");
    portal::registers_before_the_first_portal_call(
        &stand_in,
        "input capture",
        input_capture::InputCapture::new(Some(input_capture::Backend::InputCapturePortal)),
    )
    .await;
}

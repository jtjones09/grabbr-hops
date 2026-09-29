//! The macOS power assertion that keeps a Mac another machine controls from
//! idle-sleeping. A Mac asleep suspends hops and is unreachable over the
//! network until something wakes it by hand, as a lid-lift does.
//!
//! This module only takes and releases the assertion. When one is wanted is
//! decided by the daemon: only while a paired device that may control this
//! Mac is switched on.

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};

/// The name the assertion is listed under, as `pmset -g assertions` shows it.
pub const ASSERTION_NAME: &str = "hops KVM receiver active";

/// Which assertion to take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertionKind {
    /// `PreventUserIdleSystemSleep`: the system stays awake and reachable
    /// while the display is free to blank; remote input wakes the display.
    System,
    /// `PreventUserIdleDisplaySleep`: the display stays on too.
    Display,
}

impl AssertionKind {
    /// The IOKit assertion type.
    pub fn type_name(self) -> &'static str {
        match self {
            AssertionKind::System => "PreventUserIdleSystemSleep",
            AssertionKind::Display => "PreventUserIdleDisplaySleep",
        }
    }
}

/// An `IOPMAssertion` this process holds, released when dropped.
#[derive(Debug)]
pub struct PowerAssertion {
    id: u32,
}

impl PowerAssertion {
    /// Take an assertion of `kind`, named [`ASSERTION_NAME`]. The error is
    /// the `IOReturn` the system refused it with.
    pub fn take(kind: AssertionKind) -> Result<Self, i32> {
        let kind = CFString::new(kind.type_name());
        let name = CFString::new(ASSERTION_NAME);
        let mut id: u32 = 0;
        const LEVEL_ON: u32 = 255; // kIOPMAssertionLevelOn
        // SAFETY: the CFStrings outlive the synchronous call; `id` is a valid
        // out-pointer.
        let result = unsafe {
            IOPMAssertionCreateWithName(
                kind.as_concrete_TypeRef(),
                LEVEL_ON,
                name.as_concrete_TypeRef(),
                &mut id,
            )
        };
        if result == 0 {
            Ok(Self { id })
        } else {
            Err(result)
        }
    }
}

impl Drop for PowerAssertion {
    fn drop(&mut self) {
        // SAFETY: `id` came from a successful create and is released once.
        unsafe { IOPMAssertionRelease(self.id) };
    }
}

/// The assertions this process holds, as `(type, name)` pairs: what
/// `pmset -g assertions` lists for it. Empty when the list cannot be read.
pub fn held_by_this_process() -> Vec<(String, String)> {
    let mut by_pid: CFDictionaryRef = std::ptr::null();
    // SAFETY: `by_pid` is a valid out-pointer; on success it holds a
    // dictionary this code owns (the create rule).
    if unsafe { IOPMCopyAssertionsByProcess(&mut by_pid) } != 0 || by_pid.is_null() {
        return vec![];
    }
    let by_pid: CFDictionary<CFNumber, CFArray<CFDictionary<CFString, CFType>>> =
        unsafe { CFDictionary::wrap_under_create_rule(by_pid) };
    let pid = CFNumber::from(std::process::id() as i32);
    let Some(ours) = by_pid.find(&pid) else {
        return vec![];
    };
    let field = |a: &CFDictionary<CFString, CFType>, key: &str| {
        a.find(CFString::new(key))
            .and_then(|v| v.downcast::<CFString>())
            .map(|s| s.to_string())
            .unwrap_or_default()
    };
    ours.iter()
        .map(|a| (field(&a, "AssertType"), field(&a, "AssertName")))
        .collect()
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOPMAssertionCreateWithName(
        assertion_type: CFStringRef,
        level: u32,
        name: CFStringRef,
        assertion_id: *mut u32,
    ) -> i32;
    fn IOPMAssertionRelease(assertion_id: u32) -> i32;
    fn IOPMCopyAssertionsByProcess(assertions_by_pid: *mut CFDictionaryRef) -> i32;
}

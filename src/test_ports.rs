//! Ports for the daemons tests start, from where the system never hands
//! one out by itself.
//!
//! A port found by binding port 0 and letting it go comes from the system's
//! ephemeral range, which is also where every dial in a parallel test run is
//! given its local port: a dial can take it before the daemon binds it, and
//! the daemon exits with the address in use. These ports come from below the
//! default ephemeral ranges (Linux 32768-60999, macOS and Windows
//! 49152-65535, and on Linux the range the system is set to), from a start
//! that differs per process, and each is checked free by a bind first.
//! Another process can still bind one before the daemon does, so what starts
//! a daemon on one starts it again on another when that happens.
//!
//! Shared by the crate's own tests and, through a `#[path]` module in
//! `tests/common`, by the tests that run the built binary.

use std::net::{Ipv4Addr, UdpSocket};
use std::ops::Range;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

/// Where ports are picked from: above the ports services register, and below
/// the lowest default ephemeral range.
pub const BAND: Range<u16> = 20000..32768;

/// A port in [`BAND`] that nothing on loopback holds, and that no other call
/// in this process has been given.
pub fn pick() -> u16 {
    let span = usize::from(BAND.end - BAND.start);
    first_free(std::iter::repeat_with(next_in_band).take(span)).unwrap_or_else(|| {
        panic!(
            "no port in {BAND:?} is free on loopback outside the ephemeral range {:?}",
            configured_ephemeral()
        )
    })
}

/// The first of `candidates` outside the system's ephemeral range that a
/// bind on loopback shows free.
pub fn first_free(candidates: impl IntoIterator<Item = u16>) -> Option<u16> {
    candidates
        .into_iter()
        .find(|&port| !ephemeral(port) && UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok())
}

/// Whether the system can hand `port` out to a socket bound to port 0.
pub fn ephemeral(port: u16) -> bool {
    configured_ephemeral().is_some_and(|range| range.contains(&port))
}

/// The ports after the last one handed out, from a start drawn once per
/// process so two test binaries running at once do not walk the same ports.
fn next_in_band() -> u16 {
    static NEXT: OnceLock<AtomicU32> = OnceLock::new();
    let span = u32::from(BAND.end - BAND.start);
    let next = NEXT.get_or_init(|| {
        use std::hash::BuildHasher;
        let seed = std::collections::hash_map::RandomState::new().hash_one(std::process::id());
        AtomicU32::new((seed % u64::from(span)) as u32)
    });
    let offset = next.fetch_add(1, Ordering::Relaxed) % span;
    BAND.start + offset as u16
}

/// The ephemeral range the system is set to, where it can be read: Linux
/// can be set to one that reaches into [`BAND`].
fn configured_ephemeral() -> Option<Range<u16>> {
    static RANGE: OnceLock<Option<Range<u16>>> = OnceLock::new();
    RANGE
        .get_or_init(|| {
            let text = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
            let mut bounds = text.split_whitespace().map(str::parse::<u16>);
            let (low, high) = (bounds.next()?.ok()?, bounds.next()?.ok()?);
            Some(low..high.saturating_add(1))
        })
        .clone()
}

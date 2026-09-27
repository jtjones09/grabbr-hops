//! Ports for the daemons tests start, from where the system never hands
//! one out by itself.
//!
//! A port found by binding port 0 and letting it go comes from the system's
//! ephemeral range, which is also where every dial in a parallel test run is
//! given its local port: a dial can take it before the daemon binds it, and
//! the daemon exits with the address in use. These ports come from below the
//! default ephemeral ranges (Linux 32768-60999, macOS and Windows
//! 49152-65535), from a start that differs per process, and each is checked
//! free by a bind on every address first. Another process can still bind one
//! before the daemon does, so what starts a daemon on one starts it again on
//! another when that happens.
//!
//! Linux can be set to an ephemeral range that reaches into [`BAND`]; its
//! ports are then left out, and where the range covers all of it, ports are
//! picked outside the range above 1023 instead. Only where the range covers
//! every one of those (`1024 65535`) are ports picked from the band anyway:
//! a dial can then take one, and the daemon is started again on another.
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

/// The ports picks are drawn from.
#[derive(Debug, PartialEq, Eq)]
pub struct Pool {
    /// Its ports, in ascending ranges.
    pub ranges: Vec<Range<u32>>,
    /// Whether the system can give none of them to a socket bound to port 0.
    #[allow(dead_code)] // read by tests/port_band.rs
    pub clear_of_dials: bool,
}

impl Pool {
    fn len(&self) -> u32 {
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }

    /// Whether `port` is one of its ports.
    #[allow(dead_code)] // read by tests/port_band.rs
    pub fn contains(&self, port: u16) -> bool {
        self.ranges.iter().any(|r| r.contains(&u32::from(port)))
    }

    /// Its `n`th port, counting on from the first; `n` below [`Pool::len`].
    fn nth(&self, mut n: u32) -> u16 {
        for range in &self.ranges {
            let len = range.end - range.start;
            if n < len {
                return u16::try_from(range.start + n).expect("a pool holds ports");
            }
            n -= len;
        }
        unreachable!("an index within the pool")
    }
}

/// The pool for a system whose ephemeral range is `ephemeral` (end
/// exclusive), or that has none that can be read.
pub fn pool_for(ephemeral: Option<Range<u32>>) -> Pool {
    let band = u32::from(BAND.start)..u32::from(BAND.end);
    let Some(ephemeral) = ephemeral else {
        return Pool {
            ranges: vec![band],
            clear_of_dials: true,
        };
    };
    let outside = |within: Range<u32>| -> Vec<Range<u32>> {
        [
            within.start..within.end.min(ephemeral.start),
            within.start.max(ephemeral.end)..within.end,
        ]
        .into_iter()
        .filter(|r| !r.is_empty())
        .collect()
    };
    for within in [band.clone(), 1024..65536] {
        let ranges = outside(within);
        if !ranges.is_empty() {
            return Pool {
                ranges,
                clear_of_dials: true,
            };
        }
    }
    Pool {
        ranges: vec![band],
        clear_of_dials: false,
    }
}

/// The pool on this system.
pub fn pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(|| pool_for(configured_ephemeral()))
}

/// A port from [`pool`] that nothing on this machine holds, and that no
/// other call in this process has been given.
pub fn pick() -> u16 {
    let pool = pool();
    let len = pool.len();
    first_free(std::iter::repeat_with(|| pool.nth(next_offset(len))).take(len as usize))
        .unwrap_or_else(|| panic!("no port in {:?} is free", pool.ranges))
}

/// The first of `candidates` that a bind on every address shows free, as the
/// daemon binds its port.
pub fn first_free(candidates: impl IntoIterator<Item = u16>) -> Option<u16> {
    candidates
        .into_iter()
        .find(|&port| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok())
}

/// The offset after the last one handed out, below `len`, from a start drawn
/// once per process so two test binaries running at once do not walk the
/// same ports.
fn next_offset(len: u32) -> u32 {
    static NEXT: OnceLock<AtomicU32> = OnceLock::new();
    let next = NEXT.get_or_init(|| {
        use std::hash::BuildHasher;
        let seed = std::collections::hash_map::RandomState::new().hash_one(std::process::id());
        AtomicU32::new((seed % u64::from(len)) as u32)
    });
    next.fetch_add(1, Ordering::Relaxed) % len
}

/// The ephemeral range the system is set to (end exclusive), where it can be
/// read.
fn configured_ephemeral() -> Option<Range<u32>> {
    let text = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
    let mut bounds = text.split_whitespace().map(str::parse::<u32>);
    let (low, high) = (bounds.next()?.ok()?, bounds.next()?.ok()?);
    Some(low..high.saturating_add(1))
}

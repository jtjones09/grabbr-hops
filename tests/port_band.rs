//! The ports daemon tests start daemons on are ones no dial is given, and
//! each is free when it is handed out (#229).
//!
//! A dial binds port 0, and the system gives it a port from its ephemeral
//! range. A daemon started on a port from that range can find it taken by a
//! dial elsewhere in a parallel test run, and exit.

#[path = "../src/test_ports.rs"]
mod ports;

use std::net::{Ipv4Addr, UdpSocket};

// LEDGER T229c | class B | 1 the ports the system gives 512 sockets bound to port 0
#[test]
fn no_socket_bound_to_port_zero_is_given_a_port_from_the_pool() {
    let dials: Vec<UdpSocket> = (0..512)
        .map(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a dial's socket"))
        .collect();
    let given: Vec<u16> = dials
        .iter()
        .map(|s| s.local_addr().expect("its address").port())
        .collect();
    let pool = ports::pool();
    let in_pool: Vec<u16> = given
        .iter()
        .copied()
        .filter(|&p| pool.contains(p))
        .collect();
    assert!(
        in_pool.is_empty(),
        "the system gave {} of {} sockets bound to port 0 ports daemons are started on \
         ({pool:?}), such as {:?}",
        in_pool.len(),
        given.len(),
        &in_pool[..in_pool.len().min(8)]
    );
}

// LEDGER T229d | class B | 1 the ports picked, and whether each binds on every address
#[test]
fn picked_ports_are_in_the_pool_distinct_and_free() {
    let picked: Vec<u16> = (0..64).map(|_| ports::pick()).collect();
    let mut distinct = picked.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let misplaced: Vec<u16> = picked
        .iter()
        .copied()
        .filter(|&p| !ports::pool().contains(p))
        .collect();
    let unbindable: Vec<u16> = picked
        .iter()
        .copied()
        .filter(|&p| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, p)).is_err())
        .collect();
    assert_eq!(
        (distinct.len(), misplaced, unbindable),
        (picked.len(), vec![], vec![]),
        "picked {picked:?}"
    );
}

// LEDGER T229e | class B | 1 the port chosen while a socket on a local address holds the first candidate
#[test]
fn a_port_another_socket_holds_on_any_local_address_is_passed_over() {
    // 127.0.0.2 can be bound on Linux, where all of 127/8 is loopback; the
    // daemon listens on every address, so a holder there takes its port too.
    let holders = [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)];
    let mut checked = Vec::new();
    for address in holders {
        let held = ports::pick();
        let Ok(_holder) = UdpSocket::bind((address, held)) else {
            continue;
        };
        let next = ports::pick();
        checked.push((address, ports::first_free([held, next]) == Some(next)));
    }
    assert!(
        checked.iter().any(|&(a, _)| a == Ipv4Addr::LOCALHOST) && checked.iter().all(|&(_, p)| p),
        "a held port was not passed over: {checked:?}"
    );
}

// LEDGER T229f | class B | 1 the pool for each ephemeral range a system can be set to
#[test]
#[allow(clippy::single_range_in_vec_init)] // a pool of one range of ports
fn the_pool_leaves_out_every_port_the_ephemeral_range_holds() {
    let band = 20000..32768;
    let cases = [
        (None, vec![band.clone()], true),
        (Some(32768..61000), vec![band.clone()], true),
        (Some(49152..65536), vec![band.clone()], true),
        (Some(25000..61000), vec![20000..25000], true),
        (Some(22000..24000), vec![20000..22000, 24000..32768], true),
        (Some(15000..40001), vec![1024..15000, 40001..65536], true),
        (Some(1024..40001), vec![40001..65536], true),
        (Some(1024..65536), vec![band.clone()], false),
    ];
    let wrong: Vec<_> = cases
        .into_iter()
        .filter_map(|(ephemeral, ranges, clear_of_dials)| {
            let want = ports::Pool {
                ranges,
                clear_of_dials,
            };
            let got = ports::pool_for(ephemeral.clone());
            (got != want).then_some((ephemeral, got, want))
        })
        .collect();
    assert!(wrong.is_empty(), "(ephemeral, got, want): {wrong:#?}");
}

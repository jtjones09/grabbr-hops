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
fn no_socket_bound_to_port_zero_is_given_a_port_from_the_band() {
    let dials: Vec<UdpSocket> = (0..512)
        .map(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a dial's socket"))
        .collect();
    let given: Vec<u16> = dials
        .iter()
        .map(|s| s.local_addr().expect("its address").port())
        .collect();
    let in_band: Vec<u16> = given
        .iter()
        .copied()
        .filter(|p| ports::BAND.contains(p))
        .collect();
    assert!(
        in_band.is_empty(),
        "the system gave {} of {} sockets bound to port 0 ports daemons are started on, \
         such as {:?}",
        in_band.len(),
        given.len(),
        &in_band[..in_band.len().min(8)]
    );
}

// LEDGER T229d | class B | 1 the ports picked, and whether each binds
#[test]
fn picked_ports_are_in_the_band_outside_the_ephemeral_range_distinct_and_free() {
    let picked: Vec<u16> = (0..64).map(|_| ports::pick()).collect();
    let mut distinct = picked.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let misplaced: Vec<u16> = picked
        .iter()
        .copied()
        .filter(|p| !ports::BAND.contains(p) || ports::ephemeral(*p))
        .collect();
    let unbindable: Vec<u16> = picked
        .iter()
        .copied()
        .filter(|&p| UdpSocket::bind((Ipv4Addr::LOCALHOST, p)).is_err())
        .collect();
    assert_eq!(
        (distinct.len(), misplaced, unbindable),
        (picked.len(), vec![], vec![]),
        "picked {picked:?}"
    );
}

// LEDGER T229e | class B | 1 the port chosen while another socket holds the first candidate
#[test]
fn a_port_another_socket_holds_is_passed_over() {
    let held = ports::pick();
    let _holder = UdpSocket::bind((Ipv4Addr::LOCALHOST, held)).expect("the port is held");
    let next = ports::pick();
    assert_eq!(ports::first_free([held, next]), Some(next));
}

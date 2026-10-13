//! A daemon whose port another socket binds between the port being picked
//! and the daemon binding it is started again on another port, instead of
//! its test waiting out a deadline for a daemon that has exited (#229).
//!
//! Runs the built binary through the start every daemon test uses, with the
//! first port it is offered held by another socket.
#![cfg(unix)]

mod common;

use std::cell::RefCell;
use std::net::{Ipv4Addr, UdpSocket};

// LEDGER T229b | class B | 5 process: the built daemon running, the ports it was offered, the port its listener holds
#[test]
fn a_daemon_whose_port_was_taken_first_starts_on_another() {
    let taken = common::ports::pick();
    let _holder = UdpSocket::bind((Ipv4Addr::LOCALHOST, taken)).expect("the port is held");
    let offered = RefCell::new(Vec::new());
    let (mut daemon, port) = common::start_on(
        || {
            let port = if offered.borrow().is_empty() {
                taken
            } else {
                common::ports::pick()
            };
            offered.borrow_mut().push(port);
            port
        },
        "h-taken",
        "",
    );
    let listener_holds_it = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_err();
    let still_running = daemon.is_running();
    assert_eq!(
        (offered.into_inner(), listener_holds_it, still_running),
        (vec![taken, port], true, true),
        "the daemon was not started again on a second port when its first was taken; log:\n{}",
        daemon.log()
    );
}

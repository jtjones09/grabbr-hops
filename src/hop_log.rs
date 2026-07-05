//! Composable, platform-agnostic logging for the connection / screen-crossing
//! lifecycle.
//!
//! Every hops instance — on whatever platform it's installed — drives its
//! crossings through this same shared service layer, so logging these transitions
//! in ONE place yields identical, quiet, **once-per-transition** logs everywhere.
//! The noisy per-wire-event diagnostics (the sender re-sending `Enter` until the
//! `Ack`, the receiver's edge-barrier probes) are NOT lifecycle events — they stay
//! at `trace`.
//!
//! Composable surface: to add a lifecycle event, add a variant + its line here;
//! callers just write `Lifecycle::Foo { .. }.log()`. Format and level live in one
//! place, so the log reads the same on macOS, Windows, and Linux.

use lan_mouse_ipc::Position;
use std::net::SocketAddr;

/// A connection / screen-crossing transition worth exactly one info line.
pub(crate) enum Lifecycle<'a> {
    /// A peer finished the handshake and connected.
    Connected {
        addr: SocketAddr,
        fingerprint: &'a str,
    },
    /// A peer's connection ended (closed, lost, or timed out).
    Disconnected { addr: SocketAddr },
    /// The cursor crossed ONTO this device — we begin emulating the peer's input.
    Entered { addr: SocketAddr, pos: Position },
    /// The cursor crossed OFF this device, back toward the peer.
    Left { addr: SocketAddr },
}

impl Lifecycle<'_> {
    /// Emit this transition as a single, consistent `info` line.
    pub(crate) fn log(&self) {
        match self {
            Lifecycle::Connected { addr, fingerprint } => {
                log::info!("peer connected: {addr} [{fingerprint}]")
            }
            Lifecycle::Disconnected { addr } => log::info!("peer disconnected: {addr}"),
            Lifecycle::Entered { addr, pos } => {
                log::info!("cursor entered this device from {addr} ({pos:?})")
            }
            Lifecycle::Left { addr } => log::info!("cursor left this device, back to {addr}"),
        }
    }
}

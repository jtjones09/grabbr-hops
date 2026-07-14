use input_event::{Event as InputEvent, KeyboardEvent, PointerEvent};
use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};
use paste::paste;
use std::{
    fmt::{Debug, Display, Formatter},
    mem::size_of,
};
use thiserror::Error;

/// defines the maximum size an encoded event can take up
/// this is currently the pointer motion event
/// type: u8, time: u32, dx: f64, dy: f64
pub const MAX_EVENT_SIZE: usize = size_of::<u8>() + size_of::<u32>() + 2 * size_of::<f64>();

/// Registry of capability bits advertised in the [`ProtoEvent::Capability`]
/// handshake. Each bit means "I understand and will honor this optional
/// feature." A peer ORs together the bits it actually implements; the other
/// end gates optional emissions on the bits it observes. Absence of a
/// `Capability` event (an older peer that predates it) reads as "no bits set",
/// so every gate degrades to the pre-capability behavior.
///
/// These bits are a permanent wire contract: only ever APPEND new bits, and
/// only ever advertise a bit once the feature behind it is actually
/// implemented (advertising a feature you don't handle would invite the peer
/// to emit events you silently drop).
pub mod caps {
    /// Peer understands `PointerMotionAbsolute` — Stage 2 absolute-position
    /// motion (cumulative displacement from the entry anchor). Not yet wired.
    pub const ABSOLUTE_MOTION: u32 = 1 << 0;
    /// Peer understands the Trueloop cursor-report return channel — Stage 3
    /// closed-loop servo (receiver reports the real post-injection position
    /// back to the sender). Not yet wired.
    pub const TRUELOOP_REPORT: u32 = 1 << 1;
}

/// error type for protocol violations
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// event type does not exist
    #[error("invalid event id: `{0}`")]
    InvalidEventId(#[from] TryFromPrimitiveError<EventType>),
    /// position type does not exist
    #[error("invalid event id: `{0}`")]
    InvalidPosition(#[from] TryFromPrimitiveError<Position>),
}

/// Position of a client
#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum Position {
    Left,
    Right,
    Top,
    Bottom,
}

impl Display for Position {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pos = match self {
            Position::Left => "left",
            Position::Right => "right",
            Position::Top => "top",
            Position::Bottom => "bottom",
        };
        write!(f, "{pos}")
    }
}

/// main lan-mouse protocol event type
#[derive(Clone, Copy, Debug)]
pub enum ProtoEvent {
    /// notify a client that the cursor entered its region at the given position
    /// [`ProtoEvent::Ack`] with the same serial is used for synchronization between devices
    Enter(Position),
    /// notify a client that the cursor left its region
    /// [`ProtoEvent::Ack`] with the same serial is used for synchronization between devices
    Leave(u32),
    /// acknowledge of an [`ProtoEvent::Enter`] or [`ProtoEvent::Leave`] event
    Ack(u32),
    /// Input event
    Input(InputEvent),
    /// Ping event for tracking unresponsive clients.
    /// A client has to respond with [`ProtoEvent::Pong`].
    Ping,
    /// Response to [`ProtoEvent::Ping`], true if emulation is enabled / available
    Pong(bool),
    /// Build identification for the sending peer. Sent by the
    /// connect side once after the connection authenticates, and
    /// echoed back by the listen side in reply, so each end can
    /// display the peer's build hash and warn (soft) on mismatch.
    /// `commit` is the 8-byte ASCII short commit hash from
    /// `shadow_rs`'s `SHORT_COMMIT`. Old peers that don't
    /// recognize the event type silently skip it per the
    /// forward-compat handling in the receive loop.
    Hello { commit: [u8; 8] },
    /// Capability negotiation. Emitted UNCONDITIONALLY by both ends
    /// right after the [`ProtoEvent::Hello`] exchange, carrying the
    /// [`caps`] bits this build supports. Each end records the peer's
    /// bits and gates optional emissions on them. An older peer that
    /// predates this event simply never sends one (the receive loop
    /// skips the unknown type on the far side), which reads as "no
    /// capabilities" and degrades every gate to the pre-capability
    /// behavior — the same forward-compat contract as `Hello`.
    Capability { flags: u32 },
    /// Absolute-position pointer motion (Stage 2). Carries the cumulative
    /// displacement (`vx`, `vy`) from the entry anchor rather than a
    /// per-event delta, a sequence number `seq` for closed-loop
    /// reconciliation (Stage 3 Trueloop servo), and a timestamp `ts`.
    /// Uses f32 (not f64) so the event is 17 bytes — within
    /// [`MAX_EVENT_SIZE`], so old peers skip it rather than tear down.
    /// Gated behind [`caps::ABSOLUTE_MOTION`]; not yet emitted or consumed
    /// (the wire type and its codec, landed ahead of the sender/receiver
    /// wiring — provisional until the Stage 2/3 reconstruction is built).
    PointerMotionAbsolute { seq: u32, ts: u32, vx: f32, vy: f32 },
}

impl Display for ProtoEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoEvent::Enter(s) => write!(f, "Enter({s})"),
            ProtoEvent::Leave(s) => write!(f, "Leave({s})"),
            ProtoEvent::Ack(s) => write!(f, "Ack({s})"),
            ProtoEvent::Input(e) => write!(f, "{e}"),
            ProtoEvent::Ping => write!(f, "ping"),
            ProtoEvent::Pong(alive) => {
                write!(
                    f,
                    "pong: {}",
                    if *alive { "alive" } else { "not available" }
                )
            }
            ProtoEvent::Hello { commit } => {
                let s = std::str::from_utf8(commit).unwrap_or("????????");
                write!(f, "Hello({s})")
            }
            ProtoEvent::Capability { flags } => write!(f, "Capability(0x{flags:08x})"),
            ProtoEvent::PointerMotionAbsolute { seq, ts, vx, vy } => {
                write!(f, "MotionAbs(seq={seq} ts={ts} vx={vx:.1} vy={vy:.1})")
            }
        }
    }
}

#[derive(TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum EventType {
    PointerMotion,
    PointerButton,
    PointerAxis,
    PointerAxisValue120,
    KeyboardKey,
    KeyboardModifiers,
    Ping,
    Pong,
    Enter,
    Leave,
    Ack,
    Hello,
    Capability,
    PointerMotionAbsolute,
}

impl ProtoEvent {
    fn event_type(&self) -> EventType {
        match self {
            ProtoEvent::Input(e) => match e {
                InputEvent::Pointer(p) => match p {
                    PointerEvent::Motion { .. } => EventType::PointerMotion,
                    PointerEvent::Button { .. } => EventType::PointerButton,
                    PointerEvent::Axis { .. } => EventType::PointerAxis,
                    PointerEvent::AxisDiscrete120 { .. } => EventType::PointerAxisValue120,
                },
                InputEvent::Keyboard(k) => match k {
                    KeyboardEvent::Key { .. } => EventType::KeyboardKey,
                    KeyboardEvent::Modifiers { .. } => EventType::KeyboardModifiers,
                },
            },
            ProtoEvent::Ping => EventType::Ping,
            ProtoEvent::Pong(_) => EventType::Pong,
            ProtoEvent::Enter(_) => EventType::Enter,
            ProtoEvent::Leave(_) => EventType::Leave,
            ProtoEvent::Ack(_) => EventType::Ack,
            ProtoEvent::Hello { .. } => EventType::Hello,
            ProtoEvent::Capability { .. } => EventType::Capability,
            ProtoEvent::PointerMotionAbsolute { .. } => EventType::PointerMotionAbsolute,
        }
    }
}

impl TryFrom<[u8; MAX_EVENT_SIZE]> for ProtoEvent {
    type Error = ProtocolError;

    fn try_from(buf: [u8; MAX_EVENT_SIZE]) -> Result<Self, Self::Error> {
        let mut buf = &buf[..];
        let event_type = decode_u8(&mut buf)?;
        match EventType::try_from(event_type)? {
            EventType::PointerMotion => {
                Ok(Self::Input(InputEvent::Pointer(PointerEvent::Motion {
                    time: decode_u32(&mut buf)?,
                    dx: decode_f64(&mut buf)?,
                    dy: decode_f64(&mut buf)?,
                })))
            }
            EventType::PointerButton => {
                Ok(Self::Input(InputEvent::Pointer(PointerEvent::Button {
                    time: decode_u32(&mut buf)?,
                    button: decode_u32(&mut buf)?,
                    state: decode_u32(&mut buf)?,
                })))
            }
            EventType::PointerAxis => Ok(Self::Input(InputEvent::Pointer(PointerEvent::Axis {
                time: decode_u32(&mut buf)?,
                axis: decode_u8(&mut buf)?,
                value: decode_f64(&mut buf)?,
            }))),
            EventType::PointerAxisValue120 => Ok(Self::Input(InputEvent::Pointer(
                PointerEvent::AxisDiscrete120 {
                    axis: decode_u8(&mut buf)?,
                    value: decode_i32(&mut buf)?,
                },
            ))),
            EventType::KeyboardKey => Ok(Self::Input(InputEvent::Keyboard(KeyboardEvent::Key {
                time: decode_u32(&mut buf)?,
                key: decode_u32(&mut buf)?,
                state: decode_u8(&mut buf)?,
            }))),
            EventType::KeyboardModifiers => Ok(Self::Input(InputEvent::Keyboard(
                KeyboardEvent::Modifiers {
                    depressed: decode_u32(&mut buf)?,
                    latched: decode_u32(&mut buf)?,
                    locked: decode_u32(&mut buf)?,
                    group: decode_u32(&mut buf)?,
                },
            ))),
            EventType::Ping => Ok(Self::Ping),
            EventType::Pong => Ok(Self::Pong(decode_u8(&mut buf)? != 0)),
            EventType::Enter => Ok(Self::Enter(decode_u8(&mut buf)?.try_into()?)),
            EventType::Leave => Ok(Self::Leave(decode_u32(&mut buf)?)),
            EventType::Ack => Ok(Self::Ack(decode_u32(&mut buf)?)),
            EventType::Hello => {
                let mut commit = [0u8; 8];
                for b in commit.iter_mut() {
                    *b = decode_u8(&mut buf)?;
                }
                Ok(Self::Hello { commit })
            }
            EventType::Capability => Ok(Self::Capability {
                flags: decode_u32(&mut buf)?,
            }),
            EventType::PointerMotionAbsolute => Ok(Self::PointerMotionAbsolute {
                seq: decode_u32(&mut buf)?,
                ts: decode_u32(&mut buf)?,
                vx: decode_f32(&mut buf)?,
                vy: decode_f32(&mut buf)?,
            }),
        }
    }
}

impl From<ProtoEvent> for ([u8; MAX_EVENT_SIZE], usize) {
    fn from(event: ProtoEvent) -> Self {
        let mut buf = [0u8; MAX_EVENT_SIZE];
        let mut len = 0usize;
        {
            let mut buf = &mut buf[..];
            let buf = &mut buf;
            let len = &mut len;
            encode_u8(buf, len, event.event_type() as u8);
            match event {
                ProtoEvent::Input(event) => match event {
                    InputEvent::Pointer(p) => match p {
                        PointerEvent::Motion { time, dx, dy } => {
                            encode_u32(buf, len, time);
                            encode_f64(buf, len, dx);
                            encode_f64(buf, len, dy);
                        }
                        PointerEvent::Button {
                            time,
                            button,
                            state,
                        } => {
                            encode_u32(buf, len, time);
                            encode_u32(buf, len, button);
                            encode_u32(buf, len, state);
                        }
                        PointerEvent::Axis { time, axis, value } => {
                            encode_u32(buf, len, time);
                            encode_u8(buf, len, axis);
                            encode_f64(buf, len, value);
                        }
                        PointerEvent::AxisDiscrete120 { axis, value } => {
                            encode_u8(buf, len, axis);
                            encode_i32(buf, len, value);
                        }
                    },
                    InputEvent::Keyboard(k) => match k {
                        KeyboardEvent::Key { time, key, state } => {
                            encode_u32(buf, len, time);
                            encode_u32(buf, len, key);
                            encode_u8(buf, len, state);
                        }
                        KeyboardEvent::Modifiers {
                            depressed,
                            latched,
                            locked,
                            group,
                        } => {
                            encode_u32(buf, len, depressed);
                            encode_u32(buf, len, latched);
                            encode_u32(buf, len, locked);
                            encode_u32(buf, len, group);
                        }
                    },
                },
                ProtoEvent::Ping => {}
                ProtoEvent::Pong(alive) => encode_u8(buf, len, alive as u8),
                ProtoEvent::Enter(pos) => encode_u8(buf, len, pos as u8),
                ProtoEvent::Leave(serial) => encode_u32(buf, len, serial),
                ProtoEvent::Ack(serial) => encode_u32(buf, len, serial),
                ProtoEvent::Hello { commit } => {
                    for b in commit.iter() {
                        encode_u8(buf, len, *b);
                    }
                }
                ProtoEvent::Capability { flags } => encode_u32(buf, len, flags),
                ProtoEvent::PointerMotionAbsolute { seq, ts, vx, vy } => {
                    encode_u32(buf, len, seq);
                    encode_u32(buf, len, ts);
                    encode_f32(buf, len, vx);
                    encode_f32(buf, len, vy);
                }
            }
        }
        (buf, len)
    }
}

macro_rules! decode_impl {
    ($t:ty) => {
        paste! {
            fn [<decode_ $t>](data: &mut &[u8]) -> Result<$t, ProtocolError> {
                let (int_bytes, rest) = data.split_at(size_of::<$t>());
                *data = rest;
                Ok($t::from_be_bytes(int_bytes.try_into().unwrap()))
            }
        }
    };
}

decode_impl!(u8);
decode_impl!(u32);
decode_impl!(i32);

// f64 gets a hand-written decoder (not via decode_impl): a non-finite value
// (NaN/Inf) from a malformed/hostile peer would poison a cursor coordinate or
// scroll delta, so coerce non-finite to 0.0 (a harmless no-op).
fn decode_f64(data: &mut &[u8]) -> Result<f64, ProtocolError> {
    let (bytes, rest) = data.split_at(size_of::<f64>());
    *data = rest;
    let v = f64::from_be_bytes(bytes.try_into().unwrap());
    Ok(if v.is_finite() { v } else { 0.0 })
}

// f32 companion to `decode_f64`, with the same non-finite coercion: a
// NaN/Inf from a malformed/hostile peer would poison a cursor coordinate.
// Used by PointerMotionAbsolute, whose f32 fields (not f64) keep the event
// within MAX_EVENT_SIZE.
fn decode_f32(data: &mut &[u8]) -> Result<f32, ProtocolError> {
    let (bytes, rest) = data.split_at(size_of::<f32>());
    *data = rest;
    let v = f32::from_be_bytes(bytes.try_into().unwrap());
    Ok(if v.is_finite() { v } else { 0.0 })
}

macro_rules! encode_impl {
    ($t:ty) => {
        paste! {
            fn [<encode_ $t>](buf: &mut &mut [u8], amt: &mut usize, n: $t) {
                let src = n.to_be_bytes();
                let data = std::mem::take(buf);
                let (int_bytes, rest) = data.split_at_mut(size_of::<$t>());
                int_bytes.copy_from_slice(&src);
                *amt += size_of::<$t>();
                *buf = rest
            }
        }
    };
}

encode_impl!(u8);
encode_impl!(u32);
encode_impl!(i32);
encode_impl!(f64);
encode_impl!(f32);

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode then decode; returns the decoded event and the on-wire byte length.
    fn roundtrip(ev: ProtoEvent) -> (ProtoEvent, usize) {
        let (buf, len): ([u8; MAX_EVENT_SIZE], usize) = ev.into();
        let decoded = ProtoEvent::try_from(buf).expect("decode failed");
        (decoded, len)
    }

    #[test]
    fn capability_roundtrips() {
        for flags in [0u32, 1, 0b1011, caps::ABSOLUTE_MOTION, 0xDEAD_BEEF, u32::MAX] {
            let (decoded, len) = roundtrip(ProtoEvent::Capability { flags });
            assert!(
                matches!(decoded, ProtoEvent::Capability { flags: f } if f == flags),
                "capability flags did not survive round-trip: {flags:#x}",
            );
            // 1 type byte + u32 = 5 bytes; must stay well under MAX_EVENT_SIZE
            // so old peers never trip their `len > MAX_EVENT_SIZE` teardown.
            assert_eq!(len, 5, "Capability must be exactly 5 bytes on the wire");
            assert!(len <= MAX_EVENT_SIZE);
        }
    }

    /// The u8 wire tags are a permanent contract. New event types may only be
    /// APPENDED (next higher discriminant); reordering or inserting silently
    /// misdecodes every event between mismatched peers. This test freezes the
    /// mapping so any such change fails loudly instead of shipping.
    #[test]
    fn event_type_discriminants_are_append_only() {
        assert_eq!(EventType::PointerMotion as u8, 0);
        assert_eq!(EventType::PointerButton as u8, 1);
        assert_eq!(EventType::PointerAxis as u8, 2);
        assert_eq!(EventType::PointerAxisValue120 as u8, 3);
        assert_eq!(EventType::KeyboardKey as u8, 4);
        assert_eq!(EventType::KeyboardModifiers as u8, 5);
        assert_eq!(EventType::Ping as u8, 6);
        assert_eq!(EventType::Pong as u8, 7);
        assert_eq!(EventType::Enter as u8, 8);
        assert_eq!(EventType::Leave as u8, 9);
        assert_eq!(EventType::Ack as u8, 10);
        assert_eq!(EventType::Hello as u8, 11);
        assert_eq!(EventType::Capability as u8, 12);
        assert_eq!(EventType::PointerMotionAbsolute as u8, 13);
    }

    /// An old peer receiving a future event type must get a clean error (which
    /// the read loop turns into skip-and-continue), never a panic.
    #[test]
    fn unknown_event_type_is_rejected_cleanly() {
        // 14 is the first tag past the last valid discriminant (13 =
        // PointerMotionAbsolute); everything here must decode to Err.
        for tag in [14u8, 42, 200, 255] {
            let mut buf = [0u8; MAX_EVENT_SIZE];
            buf[0] = tag;
            assert!(
                ProtoEvent::try_from(buf).is_err(),
                "unknown event tag {tag} should decode to Err, not a value",
            );
        }
    }

    #[test]
    fn pointer_motion_absolute_roundtrips() {
        for (seq, ts, vx, vy) in [
            (0u32, 0u32, 0.0f32, 0.0f32),
            (1, 2, 3.5, -4.25),
            (u32::MAX, 12345, 1920.0, -1080.5),
            (7, 8, f32::MIN, f32::MAX),
        ] {
            let (decoded, len) = roundtrip(ProtoEvent::PointerMotionAbsolute { seq, ts, vx, vy });
            match decoded {
                ProtoEvent::PointerMotionAbsolute {
                    seq: s,
                    ts: t,
                    vx: x,
                    vy: y,
                } => {
                    assert_eq!((s, t), (seq, ts));
                    assert_eq!((x, y), (vx, vy), "f32 fields must round-trip bit-exact");
                }
                other => panic!("decoded wrong variant: {other}"),
            }
            // u8 + u32 + u32 + f32 + f32 = 17 bytes, <= MAX_EVENT_SIZE (21)
            assert_eq!(len, 17, "MotionAbs must be 17 bytes on the wire");
            assert!(len <= MAX_EVENT_SIZE);
        }
    }

    /// A hostile/garbage NaN or Inf coordinate must be coerced to 0.0 on decode
    /// (the decode_f32 guard), never poison a cursor position.
    #[test]
    fn motion_absolute_coerces_non_finite() {
        // Hand-build a MotionAbs frame with NaN in vx and +Inf in vy.
        let mut buf = [0u8; MAX_EVENT_SIZE];
        let mut w = &mut buf[..];
        let w = &mut w;
        let mut len = 0usize;
        encode_u8(w, &mut len, EventType::PointerMotionAbsolute as u8);
        encode_u32(w, &mut len, 1); // seq
        encode_u32(w, &mut len, 2); // ts
        encode_f32(w, &mut len, f32::NAN);
        encode_f32(w, &mut len, f32::INFINITY);
        let decoded = ProtoEvent::try_from(buf).expect("decode");
        match decoded {
            ProtoEvent::PointerMotionAbsolute { vx, vy, .. } => {
                assert_eq!(vx, 0.0, "NaN must coerce to 0.0");
                assert_eq!(vy, 0.0, "Inf must coerce to 0.0");
            }
            other => panic!("wrong variant: {other}"),
        }
    }

    /// A representative spread of control events survives round-trip and keeps
    /// its Display form (guards the encode/decode and Display arms together).
    #[test]
    fn representative_events_roundtrip() {
        for ev in [
            ProtoEvent::Ping,
            ProtoEvent::Pong(true),
            ProtoEvent::Ack(42),
            ProtoEvent::Leave(7),
            ProtoEvent::Enter(Position::Right),
            ProtoEvent::Hello { commit: *b"abc12345" },
            ProtoEvent::Capability {
                flags: caps::ABSOLUTE_MOTION | caps::TRUELOOP_REPORT,
            },
        ] {
            let (decoded, _) = roundtrip(ev);
            assert_eq!(format!("{decoded}"), format!("{ev}"));
        }
    }
}

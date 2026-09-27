//! Where one device's connection stands: the one state the device dot and
//! its status words are drawn from (#148).
//!
//! The dot used to be recomputed in each frontend from five loosely related
//! booleans with different owners and lifetimes (`online`, `alive`,
//! `active`, `active_addr`, and a refusal predicate over them). Each wrong
//! colour was a different predicate wrong in a different direction (#92,
//! #135, #144, #148), and the two frontends could disagree with each other.
//!
//! Here the facts are gathered once, into [`Facts`], and mapped to one
//! [`Connection`] by a single `match` with no catch-all arm, so the compiler
//! checks that every combination of facts has exactly one state. Frontends
//! render [`Connection::tone`] and [`Connection::words`] and nothing else.

/// One device's connection, as the dot and the status words show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Connection {
    /// No hops service answers this app, so nothing on the row is live: it
    /// is what was last known (#34).
    ServiceGone,
    /// This machine removed the device; it cannot come back as itself.
    Removed,
    /// A pairing waits for the person here to compare its number (#167).
    ComparingNumber,
    /// This machine approved a pairing and waits for the other machine to
    /// approve it, or to confirm the number (#167).
    AwaitingOtherMachine,
    /// This machine sends to the device over a live link, and the device
    /// says it is not injecting input, so everything sent is refused. Never
    /// masked by an inbound connection (#92), and never said of a device
    /// with no link (#144).
    NotAcceptingInput,
    /// A live link: this machine's link to the device is up and it takes
    /// input, or the device is connected in.
    Connected,
    /// Switched off here, and not connected in.
    Off,
    /// Switched on, but no pairing lets this machine drive it.
    NotPaired,
    /// Switched on and paired, and the last crossing to it found no link,
    /// with none up since.
    Unreachable,
    /// Paired, and no link either way, with nothing wrong known: this
    /// machine dials it when the pointer crosses to it, or waits for it to
    /// connect in.
    NotConnected,
}

/// The colour family a state is drawn in. Each frontend maps it onto its
/// theme; the choice is made here, once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tone {
    /// Working now.
    Good,
    /// Needs attention, or is on its way.
    Warn,
    /// Broken: input will not get through.
    Bad,
    /// Nothing live, and nothing wrong.
    Quiet,
}

impl Connection {
    /// Every state, for frontends and tests that show or check them all.
    pub const ALL: [Connection; 10] = [
        Connection::ServiceGone,
        Connection::Removed,
        Connection::ComparingNumber,
        Connection::AwaitingOtherMachine,
        Connection::NotAcceptingInput,
        Connection::Connected,
        Connection::Off,
        Connection::NotPaired,
        Connection::Unreachable,
        Connection::NotConnected,
    ];

    /// The one state these facts are in.
    pub fn of(f: Facts) -> Connection {
        use Connection as C;
        use Link::{Down, Up};
        use Number::{Answered, NotYet, OnScreen};
        use SendFacet::{Off, On};
        use Standing::{NotPaired, Paired, Pairing, Removed};
        // No `_ =>` arm: a new fact, or a new value of one, does not compile
        // until it is given a state.
        match (f.service, f.standing, f.send, f.inbound) {
            (false, _, _, _) => C::ServiceGone,
            (true, Removed, _, _) => C::Removed,
            // Before any arm that can go green, and whatever the inbound
            // direction says: that is a fact about the other direction (#92).
            (true, NotPaired | Paired | Pairing(_), On(Up { accepting: false }), _) => {
                C::NotAcceptingInput
            }
            (true, NotPaired | Paired | Pairing(_), On(Up { accepting: true }), _) => C::Connected,
            (
                true,
                NotPaired | Paired | Pairing(_),
                SendFacet::None | Off | On(Down { .. }),
                true,
            ) => C::Connected,
            (true, Pairing(OnScreen), SendFacet::None | Off | On(Down { .. }), false) => {
                C::ComparingNumber
            }
            (true, Pairing(NotYet | Answered), SendFacet::None | Off | On(Down { .. }), false) => {
                C::AwaitingOtherMachine
            }
            (true, NotPaired | Paired, Off, false) => C::Off,
            (true, NotPaired, On(Down { .. }), false) => C::NotPaired,
            (true, Paired, On(Down { unanswered: true }), false) => C::Unreachable,
            (true, Paired, On(Down { unanswered: false }), false) => C::NotConnected,
            (true, NotPaired | Paired, SendFacet::None, false) => C::NotConnected,
        }
    }

    /// The colour family of the dot.
    pub fn tone(self) -> Tone {
        match self {
            Connection::Connected => Tone::Good,
            Connection::NotAcceptingInput | Connection::Removed => Tone::Bad,
            Connection::ComparingNumber
            | Connection::AwaitingOtherMachine
            | Connection::NotPaired
            | Connection::Unreachable => Tone::Warn,
            Connection::ServiceGone | Connection::Off | Connection::NotConnected => Tone::Quiet,
        }
    }

    /// What the row says. Distinct for every state, so two states with one
    /// colour still read apart.
    pub fn words(self) -> &'static str {
        match self {
            Connection::ServiceGone => "service not answering",
            Connection::Removed => "removed",
            Connection::ComparingNumber => "compare the number",
            Connection::AwaitingOtherMachine => "waiting for its approval",
            Connection::NotAcceptingInput => "not accepting input",
            Connection::Connected => "connected",
            Connection::Off => "off",
            Connection::NotPaired => "not paired",
            Connection::Unreachable => "unreachable",
            Connection::NotConnected => "not connected",
        }
    }
}

/// Everything the state is derived from, for one device. Gathered in one
/// place, [`crate::AppModel::devices`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Facts {
    /// A hops service answers this app.
    pub service: bool,
    /// Where the pairing with the device stands.
    pub standing: Standing,
    /// Whether this machine sends to the device, and how that link is.
    pub send: SendFacet,
    /// The device is connected in to this machine.
    pub inbound: bool,
}

/// Where the pairing with a device stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Standing {
    /// This machine removed it.
    Removed,
    /// Approved here, not yet confirmed on both machines (#167).
    Pairing(Number),
    /// A confirmed pairing, in either direction.
    Paired,
    /// No pairing: never identified, or no grant either way.
    NotPaired,
}

/// Where the number of a pairing stands, on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Number {
    /// No number shown here yet.
    NotYet,
    /// A number to compare is on screen here.
    OnScreen,
    /// The person here answered it.
    Answered,
}

/// This machine's sending side of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendFacet {
    /// This machine does not dial it.
    None,
    /// Dialled, and switched off: a device that is off holds no link (#218).
    Off,
    /// Dialled, and switched on.
    On(Link),
}

/// The link of a switched-on device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Link {
    /// No link. `unanswered`: the last crossing to it found none, and none
    /// came up since.
    Down { unanswered: bool },
    /// A link is up. `accepting`: the device says it injects input.
    Up { accepting: bool },
}

#[cfg(test)]
mod tests {
    //! The mapping is checked over every combination of facts, not over
    //! examples: each rule below is a property that must hold for all of
    //! them.
    use super::*;

    fn every() -> Vec<Facts> {
        let standings = [
            Standing::Removed,
            Standing::Pairing(Number::NotYet),
            Standing::Pairing(Number::OnScreen),
            Standing::Pairing(Number::Answered),
            Standing::Paired,
            Standing::NotPaired,
        ];
        let sends = [
            SendFacet::None,
            SendFacet::Off,
            SendFacet::On(Link::Down { unanswered: false }),
            SendFacet::On(Link::Down { unanswered: true }),
            SendFacet::On(Link::Up { accepting: false }),
            SendFacet::On(Link::Up { accepting: true }),
        ];
        let mut all = Vec::new();
        for service in [false, true] {
            for standing in standings {
                for send in sends {
                    for inbound in [false, true] {
                        all.push(Facts {
                            service,
                            standing,
                            send,
                            inbound,
                        });
                    }
                }
            }
        }
        all
    }

    fn link_up(f: &Facts) -> bool {
        matches!(f.send, SendFacet::On(Link::Up { .. }))
    }

    // LEDGER T148-1 | class B | 1 return value: Connection::of over every Facts
    #[test]
    fn every_combination_of_facts_keeps_every_rule() {
        let all = every();
        assert_eq!(all.len(), 2 * 6 * 6 * 2, "the enumeration missed a value");
        for f in all {
            let c = Connection::of(f);
            let why = format!("{f:?} is {c:?}");
            // Nothing reads live without a service (#34).
            assert_eq!(!f.service, c == Connection::ServiceGone, "service: {why}");
            if !f.service {
                continue;
            }
            assert_eq!(
                f.standing == Standing::Removed,
                c == Connection::Removed,
                "removed: {why}"
            );
            if f.standing == Standing::Removed {
                continue;
            }
            // A link that is up and refused reads refused, whatever the
            // inbound direction says (#92) ...
            if f.send == SendFacet::On(Link::Up { accepting: false }) {
                assert_eq!(c, Connection::NotAcceptingInput, "masked: {why}");
            }
            // ... and nothing without a link up reads refused (#144).
            if c == Connection::NotAcceptingInput {
                assert!(link_up(&f), "refusing without a link: {why}");
            }
            // Green only with a live link, one way or the other (#34, #156).
            assert_eq!(
                c == Connection::Connected,
                f.send == SendFacet::On(Link::Up { accepting: true })
                    || (f.inbound && !link_up(&f)),
                "connected: {why}"
            );
            // With no link either way, the pairing speaks first, then the
            // switch, then the dial.
            if !f.inbound && !link_up(&f) {
                let expected = match (f.standing, f.send) {
                    (Standing::Pairing(Number::OnScreen), _) => Connection::ComparingNumber,
                    (Standing::Pairing(_), _) => Connection::AwaitingOtherMachine,
                    (_, SendFacet::Off) => Connection::Off,
                    (Standing::NotPaired, SendFacet::On(_)) => Connection::NotPaired,
                    (_, SendFacet::On(Link::Down { unanswered: true })) => Connection::Unreachable,
                    _ => Connection::NotConnected,
                };
                assert_eq!(c, expected, "{f:?}");
            }
        }
    }

    // LEDGER T148-2 | class B | 1 return value: Connection::of, tone, words
    #[test]
    fn every_state_is_reached_and_reads_apart() {
        let reached: std::collections::HashSet<Connection> =
            every().into_iter().map(Connection::of).collect();
        for c in Connection::ALL {
            assert!(reached.contains(&c), "no facts lead to {c:?}");
        }
        assert_eq!(reached.len(), Connection::ALL.len(), "ALL misses a state");
        let words: std::collections::HashSet<&str> =
            Connection::ALL.iter().map(|c| c.words()).collect();
        assert_eq!(
            words.len(),
            Connection::ALL.len(),
            "two states say the same words"
        );
    }
}

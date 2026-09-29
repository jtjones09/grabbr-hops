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
    /// The device's machine refused this one's dial as a machine it holds no
    /// pairing with: it removed this machine (#184). This machine still
    /// holds its side until someone removes it here, so the card says so.
    /// Nothing sent to it gets through, whatever its link or the switch here
    /// says, so it outranks every state but [`Connection::ServiceGone`].
    NoLongerTrusts,
    /// Paired with a version of hops before the trust store, and not since:
    /// it grants nothing either way until it is paired again, with the
    /// direction chosen (#231). Nothing here or there changes that, so it
    /// outranks every state but [`Connection::ServiceGone`] and
    /// [`Connection::NoLongerTrusts`].
    PairAgain,
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
    /// input; or the device is connected in, and nothing is known about
    /// this machine's own direction that outranks it (see [`Connection::of`]).
    Connected,
    /// Switched off here, whether or not the device is connected in.
    Off,
    /// Switched on, with no pairing in either direction: nothing this
    /// machine holds lets it drive the device or be driven by it.
    NotPaired,
    /// Switched on and paired, and the last crossing to it found no link,
    /// with none of this machine's own up since. A link the device opened
    /// in does not clear it: that is the other direction.
    Unreachable,
    /// Paired, and the device's machine dials this one to be controlled from
    /// here (#15): this machine never dials it, and waits for it to connect.
    /// Also a pairing this machine controls and holds no device for, which
    /// gets one when it dials in.
    AwaitingItsDial,
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
    pub const ALL: [Connection; 12] = [
        Connection::ServiceGone,
        Connection::PairAgain,
        Connection::NoLongerTrusts,
        Connection::ComparingNumber,
        Connection::AwaitingOtherMachine,
        Connection::NotAcceptingInput,
        Connection::Connected,
        Connection::Off,
        Connection::NotPaired,
        Connection::Unreachable,
        Connection::AwaitingItsDial,
        Connection::NotConnected,
    ];

    /// The one state these facts are in.
    pub fn of(f: Facts) -> Connection {
        use Connection as C;
        use Link::{Down, Up};
        use Number::{Answered, NotYet, OnScreen};
        use SendFacet::{Off, On};
        use Standing::{NotPaired, PairAgain, Paired, Pairing};
        // No `_ =>` arm: a new fact, or a new value of one, does not compile
        // until it is given a state.
        //
        // The order, top first: the other machine refusing this one; then
        // this machine's own link, when it is up; then a pairing in progress;
        // then the switch here; then a crossing that found no link; only then
        // the inbound link. What the other machine does in its direction
        // never hides a fact about this one (#92).
        match (
            f.service,
            f.removed_by_peer,
            f.standing,
            f.send,
            f.inbound,
            f.dials_us,
        ) {
            (false, _, _, _, _, _) => C::ServiceGone,
            // That machine refuses this one outright: no link, switch or
            // pairing here changes that, and the card must say what does.
            (true, true, _, _, _, _) => C::NoLongerTrusts,
            // Nothing is granted either way until it is paired again, so
            // nothing about a link says more (#231).
            (true, false, PairAgain, _, _, _) => C::PairAgain,
            (true, false, _, On(Up { accepting: false }), _, _) => C::NotAcceptingInput,
            // The number of a pairing in progress is on its own card; the dot
            // says whether input gets through the link that is up.
            (true, false, _, On(Up { accepting: true }), _, _) => C::Connected,
            (true, false, Pairing(OnScreen), SendFacet::None | Off | On(Down { .. }), _, _) => {
                C::ComparingNumber
            }
            (
                true,
                false,
                Pairing(NotYet | Answered),
                SendFacet::None | Off | On(Down { .. }),
                _,
                _,
            ) => C::AwaitingOtherMachine,
            // A device switched off here stays connected in when its own
            // pairing lets it drive this machine; the switch is still said.
            (true, false, NotPaired | Paired, Off, _, _) => C::Off,
            // A device whose machine dials this one is waited for, not
            // unreachable: this machine never dials it (#15).
            (true, false, Paired, On(Down { unanswered: true }), _, true) => C::AwaitingItsDial,
            // So is a dial that failed while the other machine's link in is
            // up: one direction can be blocked while the other gets through.
            (true, false, Paired, On(Down { unanswered: true }), _, false) => C::Unreachable,
            (true, false, NotPaired, SendFacet::None | On(Down { .. }), true, _) => C::Connected,
            (true, false, Paired, SendFacet::None | On(Down { unanswered: false }), true, _) => {
                C::Connected
            }
            (true, false, NotPaired, On(Down { .. }), false, _) => C::NotPaired,
            (true, false, Paired, On(Down { unanswered: false }), false, true) => {
                C::AwaitingItsDial
            }
            (true, false, Paired, On(Down { unanswered: false }), false, false) => C::NotConnected,
            // A pairing this machine controls and holds no device for: the
            // device appears when that machine dials in (#15).
            (true, false, Paired, SendFacet::None, false, true) => C::AwaitingItsDial,
            (true, false, NotPaired | Paired, SendFacet::None, false, _) => C::NotConnected,
        }
    }

    /// The colour family of the dot.
    pub fn tone(self) -> Tone {
        match self {
            Connection::Connected => Tone::Good,
            Connection::NotAcceptingInput | Connection::NoLongerTrusts => Tone::Bad,
            Connection::ComparingNumber
            | Connection::AwaitingOtherMachine
            | Connection::PairAgain
            | Connection::NotPaired
            | Connection::Unreachable => Tone::Warn,
            Connection::ServiceGone
            | Connection::Off
            | Connection::AwaitingItsDial
            | Connection::NotConnected => Tone::Quiet,
        }
    }

    /// What the row says. Distinct for every state, so two states with one
    /// colour still read apart.
    pub fn words(self) -> &'static str {
        match self {
            Connection::ServiceGone => "service not answering",
            // Short enough to fit beside a send row's controls in the
            // window at its default width; the daemon's notice says the rest.
            Connection::NoLongerTrusts => "it removed this machine",
            // The daemon's notice and the row's buttons say the rest.
            Connection::PairAgain => "paired with an older version: add it again",
            Connection::ComparingNumber => "compare the number",
            Connection::AwaitingOtherMachine => "waiting for its approval",
            Connection::NotAcceptingInput => "not accepting input",
            Connection::Connected => "connected",
            Connection::Off => "off",
            Connection::NotPaired => "not paired",
            Connection::Unreachable => "unreachable",
            Connection::AwaitingItsDial => "waiting for it to dial",
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
    /// The device's machine refused this one as a machine it holds no
    /// pairing with, and no link to it has come up since (#184).
    pub removed_by_peer: bool,
    /// The device's machine dials this one to be controlled from here, so
    /// this machine waits for it rather than dialling it (#15).
    pub dials_us: bool,
}

/// Where the pairing with a device stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Standing {
    /// Approved here, not yet confirmed on both machines (#167).
    Pairing(Number),
    /// A confirmed pairing, in either direction.
    Paired,
    /// No pairing: never identified, or no grant either way.
    NotPaired,
    /// Paired with a version of hops before the trust store, and granting
    /// nothing until it is paired again (#231).
    PairAgain,
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
            Standing::Pairing(Number::NotYet),
            Standing::Pairing(Number::OnScreen),
            Standing::Pairing(Number::Answered),
            Standing::Paired,
            Standing::NotPaired,
            Standing::PairAgain,
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
                        for removed_by_peer in [false, true] {
                            for dials_us in [false, true] {
                                all.push(Facts {
                                    service,
                                    standing,
                                    send,
                                    inbound,
                                    removed_by_peer,
                                    dials_us,
                                });
                            }
                        }
                    }
                }
            }
        }
        all
    }

    fn link_up(f: &Facts) -> bool {
        matches!(f.send, SendFacet::On(Link::Up { .. }))
    }

    // LEDGER T148-1 | class B | 1 return value: Connection::of over every Facts (T12: extended with dials_us, #15)
    #[test]
    fn every_combination_of_facts_keeps_every_rule() {
        let all = every();
        assert_eq!(
            all.len(),
            2 * 6 * 6 * 2 * 2 * 2,
            "the enumeration missed a value"
        );
        for f in all {
            let c = Connection::of(f);
            let why = format!("{f:?} is {c:?}");
            // Nothing reads live without a service (#34).
            assert_eq!(!f.service, c == Connection::ServiceGone, "service: {why}");
            if !f.service {
                continue;
            }
            // The other machine refusing this one is said whatever else
            // holds, and only then (#184): a link that is up, refused or
            // not, the switch here and a pairing in progress never hide it,
            // since that machine refuses everything this one sends.
            assert_eq!(
                f.removed_by_peer,
                c == Connection::NoLongerTrusts,
                "no longer trusts: {why}"
            );
            if f.removed_by_peer {
                continue;
            }
            // A machine to pair again says so whatever else holds, and only
            // it does (#231): it grants nothing either way until then.
            assert_eq!(
                f.standing == Standing::PairAgain,
                c == Connection::PairAgain,
                "pair again: {why}"
            );
            if c == Connection::PairAgain {
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
            // The switch here, and a crossing that found no link, are facts
            // about this direction: the other machine's link in hides
            // neither of them.
            let paired_or_not = matches!(f.standing, Standing::Paired | Standing::NotPaired);
            if paired_or_not && f.send == SendFacet::Off {
                assert_eq!(c, Connection::Off, "the switch is masked: {why}");
            }
            // For a device whose machine dials this one, the crossing found
            // it not yet connected, which is what its state already says.
            if f.standing == Standing::Paired
                && f.send == SendFacet::On(Link::Down { unanswered: true })
            {
                let expected = if f.dials_us {
                    Connection::AwaitingItsDial
                } else {
                    Connection::Unreachable
                };
                assert_eq!(c, expected, "the failed dial is masked: {why}");
            }
            // Waiting for it to connect is said only of a paired device
            // that dials this machine, with this machine's link to it down
            // (#15): never of one this machine dials, and never over a
            // link that is up.
            if c == Connection::AwaitingItsDial {
                assert!(
                    f.dials_us && f.standing == Standing::Paired && !link_up(&f),
                    "waiting for a device that does not dial in: {why}"
                );
            }
            // Green only with a live link, one way or the other (#34, #156).
            if c == Connection::Connected {
                assert!(
                    f.send == SendFacet::On(Link::Up { accepting: true }) || f.inbound,
                    "connected with no link: {why}"
                );
            }
            // Without this machine's link up: the pairing speaks first, then
            // the switch, then the dial that failed, then the link in, then
            // the dial.
            if !link_up(&f) {
                let expected = match (f.standing, f.send, f.inbound) {
                    (Standing::Pairing(Number::OnScreen), _, _) => Connection::ComparingNumber,
                    (Standing::Pairing(_), _, _) => Connection::AwaitingOtherMachine,
                    (_, SendFacet::Off, _) => Connection::Off,
                    // A device that dials this machine is waited for,
                    // not unreachable: this machine never dials it (#15).
                    (_, SendFacet::On(Link::Down { unanswered: true }), _)
                        if f.standing == Standing::Paired && f.dials_us =>
                    {
                        Connection::AwaitingItsDial
                    }
                    (_, SendFacet::On(Link::Down { unanswered: true }), _)
                        if f.standing == Standing::Paired =>
                    {
                        Connection::Unreachable
                    }
                    (_, _, true) => Connection::Connected,
                    (Standing::NotPaired, SendFacet::On(_), _) => Connection::NotPaired,
                    (Standing::Paired, SendFacet::On(Link::Down { .. }), false) if f.dials_us => {
                        Connection::AwaitingItsDial
                    }
                    // A pairing this machine controls with no device here
                    // yet: its device appears when it dials in.
                    (Standing::Paired, SendFacet::None, false) if f.dials_us => {
                        Connection::AwaitingItsDial
                    }
                    _ => Connection::NotConnected,
                };
                assert_eq!(c, expected, "{f:?}");
            } else if f.send == SendFacet::On(Link::Up { accepting: true }) {
                assert_eq!(c, Connection::Connected, "{f:?}");
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

//! The pairing prompts raised and not yet answered (#114, #107).
//!
//! The table is private to this module. A prompt is held, taken for a grant
//! or listed for a frontend only through a method that first forgets every
//! prompt whose pairing window has closed, so the grant door has no way to
//! read one past its window.

use crate::prompt_gate::PromptGate;
use hops_ipc::AttemptOrigin;
use std::{collections::HashMap, net::SocketAddr, time::Instant};

/// A prompt raised and not yet answered.
#[derive(Debug, Clone, Copy)]
pub(super) struct PendingAttempt {
    pub(super) origin: AttemptOrigin,
    pub(super) addr: Option<SocketAddr>,
    admitted: Instant,
}

/// How many unanswered prompts are remembered at once.
///
/// Anyone on the network can add one by dialling with a certificate we do not
/// recognise while add device is open. Well past any real fleet, small enough
/// that a flood costs nothing.
const MAX_PENDING_ATTEMPTS: usize = 32;

/// The prompt each fingerprint is waiting on: its provenance, where it came
/// from, and when it was admitted.
///
/// A grant has to be shaped by HOW the peer arrived: an unsolicited knock
/// asks "may this machine drive mine", our own dial asks "may I drive that
/// machine". Also what a frontend that attaches later is shown (#114).
///
/// Bounded, because anyone on the network can cause an entry. A prompt may
/// be approved only while the window that admitted it is still open. Once it
/// closes nothing may grant from it, even after add device is opened again,
/// so a program holding the IPC token cannot keep a prompt from one window
/// and approve it in another (#107).
#[derive(Debug, Default)]
pub(super) struct PendingAttempts {
    held: HashMap<String, PendingAttempt>,
}

impl PendingAttempts {
    /// Hold the prompt `fingerprint` was just shown, admitted at `now`.
    pub(super) fn hold(
        &mut self,
        gate: &PromptGate,
        fingerprint: String,
        origin: AttemptOrigin,
        addr: Option<SocketAddr>,
        now: Instant,
    ) {
        self.expire(gate, now);
        if self.held.len() >= MAX_PENDING_ATTEMPTS {
            self.held.clear();
        }
        self.held.insert(
            fingerprint,
            PendingAttempt {
                origin,
                addr,
                admitted: now,
            },
        );
    }

    /// The held prompt from `fingerprint`, taken for a grant: its
    /// provenance and where it came from, or `None` when there is none or
    /// its window has closed.
    pub(super) fn take(
        &mut self,
        gate: &PromptGate,
        fingerprint: &str,
        now: Instant,
    ) -> Option<PendingAttempt> {
        self.expire(gate, now);
        self.held.remove(fingerprint)
    }

    /// The held prompts a frontend attaching at `now` is shown, less any
    /// from a device `removed` names.
    pub(super) fn replay(
        &mut self,
        gate: &PromptGate,
        removed: impl Fn(&str) -> bool,
        now: Instant,
    ) -> Vec<(String, PendingAttempt)> {
        self.expire(gate, now);
        attempts_to_replay(&self.held, gate, removed, now)
    }

    /// Forget every prompt whose pairing window has closed since it was
    /// raised.
    fn expire(&mut self, gate: &PromptGate, now: Instant) {
        self.held
            .retain(|_, a| gate.open_throughout(a.admitted, now));
    }
}

/// The held prompts a frontend attaching at `now` is shown (#114): those the
/// gate would still allow on screen, less any from a removed device.
fn attempts_to_replay(
    pending: &HashMap<String, PendingAttempt>,
    gate: &PromptGate,
    removed: impl Fn(&str) -> bool,
    now: Instant,
) -> Vec<(String, PendingAttempt)> {
    pending
        .iter()
        .filter(|(fp, a)| gate.replayable(a.admitted, now) && !removed(fp))
        .map(|(fp, a)| (fp.clone(), *a))
        .collect()
}

#[cfg(test)]
mod replay_on_attach {
    //! A frontend that attaches late is shown the prompts it missed, but only
    //! those the pairing window still allows (#114, #195).
    use super::{PendingAttempt, attempts_to_replay};
    use crate::prompt_gate::PromptGate;
    use hops_ipc::AttemptOrigin;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    const S: Duration = Duration::from_secs(1);

    fn held(admitted: Instant) -> PendingAttempt {
        PendingAttempt {
            origin: AttemptOrigin::Inbound,
            addr: None,
            admitted,
        }
    }

    fn replayed(
        pending: &HashMap<String, PendingAttempt>,
        gate: &PromptGate,
        removed: &str,
        now: Instant,
    ) -> Vec<String> {
        let mut fps: Vec<String> = attempts_to_replay(pending, gate, |fp| fp == removed, now)
            .into_iter()
            .map(|(fp, _)| fp)
            .collect();
        fps.sort();
        fps
    }

    // LEDGER T13 | class B | 1 return value: attempts_to_replay
    #[test]
    fn only_prompts_the_window_still_allows_are_replayed() {
        let t0 = Instant::now();
        let mut gate = PromptGate::new();
        gate.open(t0);
        let pending = HashMap::from([
            ("aa".to_string(), held(t0 + S)),
            ("dd".to_string(), held(t0 + S)),
        ]);
        assert_eq!(
            replayed(&pending, &gate, "dd", t0 + 30 * S),
            vec!["aa".to_string()],
            "half a minute into the window, the live request must be replayed and \
             the removed device's must not"
        );
        assert_eq!(
            replayed(&pending, &gate, "dd", t0 + PromptGate::WINDOW + 5 * S),
            Vec::<String>::new(),
            "a request was replayed after the pairing window closed"
        );
        gate.open(t0 + 130 * S);
        let pending = HashMap::from([
            ("xx".to_string(), held(t0 + 100 * S)),
            ("yy".to_string(), held(t0 + 131 * S)),
        ]);
        assert_eq!(
            replayed(&pending, &gate, "dd", t0 + 135 * S),
            vec!["yy".to_string()],
            "add device reopened for one machine replayed another machine's \
             request from the window before"
        );
    }
}

#[cfg(test)]
mod a_prompt_expires_with_its_pairing_window {
    //! A held prompt can be approved only while the pairing window that
    //! admitted it is still open (#107). It used to be forgotten only on a
    //! grant or when the table overflowed, so a prompt from one window could
    //! be approved in the next.
    use super::{PendingAttempt, PendingAttempts};
    use crate::prompt_gate::PromptGate;
    use crate::service::{GrantRefused, grant_for_attempt};
    use crate::trust::TrustStore;
    use hops_ipc::AttemptOrigin;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    const S: Duration = Duration::from_secs(1);

    fn fp(tag: u8) -> String {
        (0u8..32)
            .map(|i| format!("{:02x}", tag.wrapping_add(i)))
            .collect::<Vec<_>>()
            .join(":")
    }

    fn held(admitted: Instant) -> PendingAttempts {
        let held = HashMap::from([
            (
                fp(0xa0),
                PendingAttempt {
                    origin: AttemptOrigin::Inbound,
                    addr: None,
                    admitted,
                },
            ),
            (
                fp(0xb0),
                PendingAttempt {
                    origin: AttemptOrigin::OutboundDial,
                    addr: None,
                    admitted,
                },
            ),
        ]);
        PendingAttempts { held }
    }

    // LEDGER EN-2 | class B | 2 return value + 1 struct state: PendingAttempts::take, grant_for_attempt, the held prompts
    #[test]
    fn a_prompt_cannot_be_approved_once_its_pairing_window_has_closed() {
        let t0 = Instant::now();
        let mut gate = PromptGate::new();
        gate.open(t0);
        let knocked = t0 + S;

        let mut pending = held(knocked);
        gate.open(t0 + 60 * S);
        assert_eq!(
            pending
                .take(&gate, &fp(0xa0), t0 + 100 * S)
                .map(|a| a.origin),
            Some(AttemptOrigin::Inbound),
            "add device opened again while its window was still open ended a \
             prompt that was on screen"
        );

        let closed = t0 + 60 * S + PromptGate::WINDOW;
        let mut pending = held(knocked);
        assert_eq!(
            pending.take(&gate, &fp(0xa0), closed).map(|a| a.origin),
            None,
            "a prompt could still be approved after its pairing window closed"
        );
        assert!(
            pending.held.is_empty(),
            "a prompt from a closed pairing window was kept: {:?}",
            pending.held.keys().collect::<Vec<_>>()
        );

        let mut pending = held(knocked);
        gate.open(closed + 10 * S);
        let origin = pending
            .take(&gate, &fp(0xb0), closed + 11 * S)
            .map(|a| a.origin);
        let mut store = TrustStore::new(&fp(0x01), 0).expect("our fingerprint");
        assert_eq!(
            grant_for_attempt(
                &mut store,
                &fp(0xb0),
                "a stranger",
                origin,
                hops_ipc::Controller::ThatMachine,
                false
            ),
            Err(GrantRefused::NoAttempt),
            "a prompt from a pairing window that had closed was approved after add \
             device was opened again. The window is what makes a prompt answerable: \
             a prompt kept past it can be approved at any later moment by anything \
             that can send the approval."
        );
        assert!(
            !store.is_known(&fp(0xb0)),
            "the approval of an expired prompt left a record"
        );
    }
}

//! How long capture and emulation that the system ended wait before they
//! start again on their own (#240, #258).

use std::time::Duration;

/// How long capture or emulation that the system interrupted waits before
/// it starts again on its own the first time. Each interruption soon after a
/// restart doubles the wait, up to [`RESTART_AFTER_AT_MOST`]; but after
/// secure input took the pointer back, capture's wait is always this, so it
/// is never off for long after an unlock.
pub(crate) const RESTART_AFTER: Duration = Duration::from_secs(1);

/// The longest wait before an interrupted capture or emulation starts again.
pub(crate) const RESTART_AFTER_AT_MOST: Duration = Duration::from_secs(60);

/// A capture or emulation that ran this long before it was interrupted
/// starts the waits over from [`RESTART_AFTER`].
pub(crate) const RAN_LONG_ENOUGH: Duration = Duration::from_secs(60);

/// The wait before an interrupted capture or emulation starts again:
/// `restart_after` the first time, or after one that ran
/// [`RAN_LONG_ENOUGH`]; double the previous wait otherwise, up to
/// [`RESTART_AFTER_AT_MOST`].
pub(crate) fn restart_wait(
    previous: Option<Duration>,
    ran: Duration,
    restart_after: Duration,
) -> Duration {
    match previous {
        Some(previous) if ran < RAN_LONG_ENOUGH => (previous * 2).min(RESTART_AFTER_AT_MOST),
        _ => restart_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // LEDGER | behaviour | 1 return value: restart_wait over a run of interruptions
    /// While the cause keeps recurring, such as a screen that stays locked,
    /// each wait doubles up to a minute; a run that lasted starts over.
    #[test]
    fn the_wait_doubles_while_it_keeps_failing_and_starts_over_after_a_long_run() {
        let short = Duration::from_millis(10);
        let mut waits = vec![];
        let mut previous = None;
        for _ in 0..9 {
            let wait = restart_wait(previous, short, RESTART_AFTER);
            waits.push(wait.as_secs());
            previous = Some(wait);
        }
        assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(
            restart_wait(previous, RAN_LONG_ENOUGH, RESTART_AFTER),
            RESTART_AFTER
        );
    }
}

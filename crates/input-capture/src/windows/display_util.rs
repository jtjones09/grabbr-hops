#[cfg(windows)]
use windows::Win32::Foundation::RECT;

/// Win32's `RECT`, so this geometry is tested on every OS.
#[cfg(not(windows))]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy)]
pub(crate) struct RECT {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

use crate::Position;

fn is_within_dp_region(point: (i32, i32), display: &RECT) -> bool {
    [
        Position::Left,
        Position::Right,
        Position::Top,
        Position::Bottom,
    ]
    .iter()
    .all(|&pos| is_within_dp_boundary(point, display, pos))
}

fn is_within_dp_boundary(point: (i32, i32), display: &RECT, pos: Position) -> bool {
    let (x, y) = point;
    match pos {
        Position::Left => display.left <= x,
        Position::Right => display.right > x,
        Position::Top => display.top <= y,
        Position::Bottom => display.bottom > y,
    }
}

/// returns whether the given position is within the display bounds with respect to the given
/// barrier position
///
/// # Arguments
///
/// * `x`:
/// * `y`:
/// * `displays`:
/// * `pos`:
///
/// returns: bool
///
fn in_bounds(point: (i32, i32), displays: &[RECT], pos: Position) -> bool {
    displays
        .iter()
        .any(|d| is_within_dp_boundary(point, d, pos))
}

fn in_display_region(point: (i32, i32), displays: &[RECT]) -> bool {
    displays.iter().any(|d| is_within_dp_region(point, d))
}

fn moved_across_boundary(
    prev_pos: (i32, i32),
    curr_pos: (i32, i32),
    displays: &[RECT],
    pos: Position,
) -> bool {
    /* was within bounds, but is not anymore */
    in_display_region(prev_pos, displays) && !in_bounds(curr_pos, displays, pos)
}

pub(crate) fn entered_barrier(
    prev_pos: (i32, i32),
    curr_pos: (i32, i32),
    displays: &[RECT],
) -> Option<Position> {
    [
        Position::Left,
        Position::Right,
        Position::Top,
        Position::Bottom,
    ]
    .into_iter()
    .find(|&pos| moved_across_boundary(prev_pos, curr_pos, displays, pos))
}

/// Clamps `point` to the display that contains `prev_point`, inclusive: where
/// the OS leaves the cursor when a move leaves that display.
///
/// Runs inside the mouse hook, so it cannot panic: `None` when no display
/// contains `prev_point`. A display that contains a point is at least one
/// pixel wide and high, so its bounds are ordered.
pub(crate) fn clamp_to_display_bounds(
    display_regions: &[RECT],
    prev_point: (i32, i32),
    point: (i32, i32),
) -> Option<(i32, i32)> {
    let display = display_regions
        .iter()
        .find(|&d| is_within_dp_region(prev_point, d))?;
    let (x, y) = point;
    let (min_x, max_x) = (display.left, display.right - 1);
    let (min_y, max_y) = (display.top, display.bottom - 1);
    Some((x.max(min_x).min(max_x), y.max(min_y).min(max_y)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESK: RECT = RECT {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1080,
    };

    #[test]
    fn a_move_past_the_right_edge_enters_the_right_barrier_at_the_last_pixel() {
        let displays = [DESK];
        assert_eq!(entered_barrier((1900, 500), (1905, 500), &displays), None);
        let entered = entered_barrier((1919, 500), (1925, 500), &displays);
        assert!(matches!(entered, Some(Position::Right)));
        assert_eq!(
            clamp_to_display_bounds(&displays, (1919, 500), (1925, 500)),
            Some((1919, 500))
        );
        assert_eq!(
            clamp_to_display_bounds(&displays, (3, 2), (-4, -9)),
            Some((0, 0))
        );
    }

    #[test]
    fn a_crossing_with_no_source_display_does_not_panic() {
        assert_eq!(clamp_to_display_bounds(&[], (10, 10), (-5, 10)), None);
        assert_eq!(
            clamp_to_display_bounds(&[DESK], (5000, 10), (5005, 10)),
            None
        );
        let empty = RECT {
            left: 100,
            top: 100,
            right: 100,
            bottom: 100,
        };
        assert_eq!(
            clamp_to_display_bounds(&[empty], (100, 100), (99, 100)),
            None
        );
    }
}

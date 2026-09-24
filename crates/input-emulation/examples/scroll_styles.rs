//! Post one scroll, in a style you choose, into whatever is focused.
//!
//! macOS decides how a scroll behaves from the fields on the event, not from
//! the hardware. A wheel notch and a trackpad swipe reach an app as different
//! kinds of thing: the trackpad's is continuous and carries a phase (began,
//! changed, ended) and a momentum tail, and surfaces that treat scrolling as a
//! gesture — iPhone Mirroring, some paging views — act on the phased kind and
//! barely move for the other.
//!
//! hops posts the unphased kind today (`macos.rs`, the `Axis` and
//! `AxisDiscrete120` arms), so this runs the alternatives side by side to find
//! out which one a given app wants, before changing what hops sends.
//!
//! Nothing here is used by the daemon; it is a measuring tool.
//!
//! ```text
//! cargo run -p input-emulation --example scroll_styles -- --mode line
//! cargo run -p input-emulation --example scroll_styles -- --mode phased
//! cargo run -p input-emulation --example scroll_styles -- --mode momentum --up
//! ```
//!
//! Focus the app you are testing during the countdown. If nothing moves at all,
//! the terminal running this needs Accessibility in System Settings → Privacy
//! & Security.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("scroll_styles is macOS only: it measures how macOS reads a scroll event.");
}

#[cfg(target_os = "macos")]
fn main() {
    use core_graphics::event::{
        CGEvent, CGEventTapLocation, CGEventType, CGMouseButton, CGScrollEventUnit, ScrollEventUnit,
    };
    use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
    use std::thread::sleep;
    use std::time::Duration;

    // From CGEventTypes.h. `CGEventField` is a plain u32, so the fields macOS
    // uses for gesture scrolling can be set by number.
    const FIXED_PT_DELTA_AXIS_1: u32 = 93;
    const POINT_DELTA_AXIS_1: u32 = 96;
    const SCROLL_PHASE: u32 = 99;
    const MOMENTUM_PHASE: u32 = 123;
    const IS_CONTINUOUS: u32 = 88;

    const DELTA_AXIS_1: u32 = 11;

    // CGScrollPhase, which is what field 99 takes. These are NOT the NSEventPhase
    // numbers an application sees: there, Changed is 4 and Ended is 8. Writing
    // NSEventPhase into field 99 sends Ended where Changed was meant and
    // Cancelled where Ended was meant, which looks like a working gesture in the
    // source and measures as nonsense.
    const PHASE_BEGAN: i64 = 1;
    const PHASE_CHANGED: i64 = 2;
    const PHASE_ENDED: i64 = 4;
    // CGMomentumScrollPhase, field 123. Ordinal, not a bitmask like the above.
    const MOMENTUM_BEGIN: i64 = 1;
    const MOMENTUM_CONTINUE: i64 = 2;
    const MOMENTUM_END: i64 = 3;

    let mut mode = String::from("phased");
    let mut pixels = 400i32;
    let mut lines = 3i32;
    let mut steps = 20i32;
    let mut gap_ms = 8u64;
    let mut after = 3u64;
    let mut repeat = 1u32;
    let mut sign = -1i32; // down, as a finger moving up the screen scrolls

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let next = |i: usize| -> String {
            args.get(i + 1)
                .cloned()
                .unwrap_or_else(|| panic!("{} needs a value", args[i]))
        };
        match args[i].as_str() {
            "--mode" => {
                mode = next(i);
                i += 1;
            }
            "--pixels" => {
                pixels = next(i).parse().expect("--pixels takes a number");
                i += 1;
            }
            "--lines" => {
                lines = next(i).parse().expect("--lines takes a number");
                i += 1;
            }
            "--steps" => {
                steps = next(i).parse().expect("--steps takes a number");
                i += 1;
            }
            "--gap-ms" => {
                gap_ms = next(i).parse().expect("--gap-ms takes a number");
                i += 1;
            }
            "--after" => {
                after = next(i).parse().expect("--after takes seconds");
                i += 1;
            }
            "--repeat" => {
                repeat = next(i).parse().expect("--repeat takes a number");
                i += 1;
            }
            "--up" => sign = 1,
            "--down" => sign = -1,
            "--help" | "-h" => {
                println!(
                    "usage: scroll_styles [--mode fields|line|pixel|phased|momentum|drag|hold-pan] \
                     [--pixels N] \
                     [--lines N] [--steps N] [--gap-ms N] [--repeat N] [--after SECONDS] \
                     [--up|--down]\n\n\
                     fields   print which fields macOS fills in itself; posts nothing\n\
                     line     one LINE-unit event, what hops sends for one wheel notch today\n\
                     pixel    one PIXEL-unit event, unphased, what hops sends for precise scrolling\n\
                     phased   continuous, began -> changed -> ended, what a trackpad swipe looks like\n\
                     momentum phased, then the inertia tail a trackpad leaves behind\n\
                     drag     press the left button, move while held, release: what a mouse drag is\n\
                     hold-pan press the left button and send phased scrolling while it is held:\n\
                              what hops would do to make click-and-hold feel like a finger"
                );
                return;
            }
            other => panic!("unknown argument {other}; try --help"),
        }
        i += 1;
    }
    assert!(steps > 0, "--steps must be at least 1");

    // The same state the daemon uses, so the probe measures what hops would
    // send rather than something a receiving app may treat differently.
    let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
        .expect("an event source; the terminal may need Accessibility");

    if mode == "fields" {
        // Which fields macOS fills in on its own, for each unit. Nothing is
        // posted, so this is safe to run with anything focused.
        for (name, unit) in [
            ("PIXEL", ScrollEventUnit::PIXEL),
            ("LINE", ScrollEventUnit::LINE),
        ] {
            let event = CGEvent::new_scroll_event(source.clone(), unit, 1, 10 * sign, 0, 0)
                .expect("scroll event");
            println!("{name} unit, delta {}:", 10 * sign);
            for (label, field) in [
                ("DeltaAxis1 (11)", DELTA_AXIS_1),
                ("FixedPtDeltaAxis1 (93)", FIXED_PT_DELTA_AXIS_1),
                ("PointDeltaAxis1 (96)", POINT_DELTA_AXIS_1),
                ("IsContinuous (88)", IS_CONTINUOUS),
                ("ScrollPhase (99)", SCROLL_PHASE),
                ("MomentumPhase (123)", MOMENTUM_PHASE),
            ] {
                println!(
                    "  {label:<24} {} ({})",
                    event.get_integer_value_field(field),
                    event.get_double_value_field(field)
                );
            }
        }
        return;
    }

    // One event, with whatever fields the style calls for.
    let post = |delta: i32, phase: Option<i64>, momentum: Option<i64>, unit: CGScrollEventUnit| {
        let event =
            CGEvent::new_scroll_event(source.clone(), unit, 1, delta, 0, 0).expect("scroll event");
        // A trackpad reports the same movement three ways and apps read
        // different ones: lines, points, and a fixed-point line value. Creating
        // the event with a PIXEL delta fills in all three, and sets the
        // continuous flag too, so the only thing a gesture still needs is the
        // phase. Run `--mode fields` to see that for yourself; do not write
        // those deltas by hand, because macOS recomputes them from each other
        // and the order it does that in is not documented.
        if let Some(phase) = phase {
            event.set_integer_value_field(SCROLL_PHASE, phase);
        }
        if let Some(momentum) = momentum {
            event.set_integer_value_field(MOMENTUM_PHASE, momentum);
        }
        event.post(CGEventTapLocation::HID);
    };

    let per_step = (pixels / steps).max(1) * sign;
    println!(
        "scroll_styles: mode {mode}, {} ",
        match mode.as_str() {
            "line" => format!("{} lines", lines * sign),
            "pixel" => format!("{} pixels in one event", pixels * sign),
            _ => format!(
                "{} pixels over {steps} steps of {per_step}, {gap_ms} ms apart",
                pixels * sign
            ),
        }
    );
    println!("  focus the app you are testing now");
    for left in (1..=after).rev() {
        println!("  {left}...");
        sleep(Duration::from_secs(1));
    }

    for round in 1..=repeat {
        match mode.as_str() {
            "line" => post(lines * sign, None, None, ScrollEventUnit::LINE),
            "pixel" => post(pixels * sign, None, None, ScrollEventUnit::PIXEL),
            "phased" | "momentum" => {
                for step in 0..steps {
                    let phase = if step == 0 {
                        PHASE_BEGAN
                    } else {
                        PHASE_CHANGED
                    };
                    post(per_step, Some(phase), None, ScrollEventUnit::PIXEL);
                    sleep(Duration::from_millis(gap_ms));
                }
                // The end of a gesture carries no movement: it says the fingers
                // left the trackpad.
                post(0, Some(PHASE_ENDED), None, ScrollEventUnit::PIXEL);
                if mode == "momentum" {
                    let mut decay = per_step;
                    let mut first = true;
                    while decay.abs() > 1 {
                        let momentum = if first {
                            MOMENTUM_BEGIN
                        } else {
                            MOMENTUM_CONTINUE
                        };
                        post(decay, None, Some(momentum), ScrollEventUnit::PIXEL);
                        first = false;
                        decay = decay * 3 / 4;
                        sleep(Duration::from_millis(gap_ms));
                    }
                    post(0, None, Some(MOMENTUM_END), ScrollEventUnit::PIXEL);
                }
            }
            "drag" | "hold-pan" => {
                // Where the pointer already is: this drags from there, as a
                // hand would, rather than teleporting first.
                let at = CGEvent::new(source.clone())
                    .expect("an event to read the pointer from")
                    .location();
                let press = CGEvent::new_mouse_event(
                    source.clone(),
                    CGEventType::LeftMouseDown,
                    at,
                    CGMouseButton::Left,
                )
                .expect("left down");
                press.post(CGEventTapLocation::HID);
                sleep(Duration::from_millis(30));

                for step in 0..steps {
                    if mode == "drag" {
                        // A mouse drag: the pointer moves while the button is
                        // held, which is exactly what hops sends today.
                        let mut to = at;
                        to.y += (per_step * (step + 1)) as f64;
                        let moved = CGEvent::new_mouse_event(
                            source.clone(),
                            CGEventType::LeftMouseDragged,
                            to,
                            CGMouseButton::Left,
                        )
                        .expect("left drag");
                        moved.post(CGEventTapLocation::HID);
                    } else {
                        // Held button, but the movement goes out as gesture
                        // scrolling: the shape of the change being considered.
                        let phase = if step == 0 {
                            PHASE_BEGAN
                        } else {
                            PHASE_CHANGED
                        };
                        post(per_step, Some(phase), None, ScrollEventUnit::PIXEL);
                    }
                    sleep(Duration::from_millis(gap_ms));
                }
                if mode == "hold-pan" {
                    post(0, Some(PHASE_ENDED), None, ScrollEventUnit::PIXEL);
                }

                let mut up_at = at;
                up_at.y += (per_step * steps) as f64;
                let release = CGEvent::new_mouse_event(
                    source.clone(),
                    CGEventType::LeftMouseUp,
                    if mode == "drag" { up_at } else { at },
                    CGMouseButton::Left,
                )
                .expect("left up");
                release.post(CGEventTapLocation::HID);
            }
            other => panic!("unknown mode {other}; try --help"),
        }
        if repeat > 1 {
            println!("  posted {round} of {repeat}");
            sleep(Duration::from_millis(400));
        }
    }
    println!("  done. If nothing moved at all, grant Accessibility to this terminal.");
}

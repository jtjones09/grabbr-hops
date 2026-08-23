// Diagnostic probe for issue #30 — what size does the window actually OPEN at?
//
// The app has three show paths and they do not agree: two call a helper that
// re-asserts the size, one calls `show()` bare. This reproduces each in
// isolation and prints the resulting window size, because reading the code is
// exactly how this bug survived two previous "fixes".
use slint::ComponentHandle;
slint::include_modules!();

const W: f32 = 560.0;
const H: f32 = 690.0;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "set-size".into());

    let ui = AppWindow::new().unwrap();
    // every mode except `natural` mirrors lib.rs:307 — set at creation
    if mode != "natural" {
        ui.window().set_size(slint::LogicalSize::new(W, H));
    }

    match mode.as_str() {
        // startup, not hidden: show_app_window() -> set_size + show
        "set-size" => {
            ui.window().set_size(slint::LogicalSize::new(W, H));
            ui.show().unwrap();
        }
        // no set_size anywhere: pure content size
        "natural" => ui.show().unwrap(),
        // launchd `--hidden`: created, never shown, later surfaced by the
        // second-launch path at lib.rs:558 which calls show() BARE
        "hidden-then-bare-show" => {
            std::thread::sleep(std::time::Duration::from_millis(300));
            ui.show().unwrap();
        }
        // shown from the tray, closed, then surfaced again by the bare path
        "show-hide-bare-show" => {
            ui.window().set_size(slint::LogicalSize::new(W, H));
            ui.show().unwrap();
            ui.hide().unwrap();
            ui.show().unwrap();
        }
        other => panic!("unknown mode {other}"),
    }

    println!("[{mode}] immediately after show: {:?}", ui.window().size());

    let weak = ui.as_weak();
    let t = slint::Timer::default();
    let mut n = 0;
    let m = mode.clone();
    t.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(400),
        move || {
            let ui = weak.upgrade().unwrap();
            n += 1;
            let s = ui.window().size();
            let sf = ui.window().scale_factor();
            println!(
                "[{m}] tick {n}: logical {}x{} (sf {sf})",
                s.width as f32 / sf,
                s.height as f32 / sf
            );
            if n >= 3 {
                slint::quit_event_loop().unwrap();
            }
        },
    );
    slint::run_event_loop().unwrap();
}

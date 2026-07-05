// Headless self-review render: builds AppWindow with mock data and writes a PNG
// using the pure software renderer — no window, no GPU, no macOS TCC permission.
// This is how the GUI's design gets reviewed without a display.
//
//   cargo run -p lan-mouse-slint --example render_png -- /path/to/out.png [w] [h] [theme_index] [mode]
//   mode: normal (default) | settings | add-device | edit-device | delete-confirm | layout-canvas
//
// Requires the crate's slint dep to carry feature "software-renderer-systemfonts"
// (see Cargo.toml) — without it, AppWindow::new() panics when the embedded
// Space Grotesk / Space Mono TTFs try to register with the software renderer.

use std::rc::Rc;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter, WindowEvent};
use slint::{ComponentHandle, ModelRc, PhysicalSize, VecModel};

// Reuse the lib crate's Slint-generated types (AppWindow, DeviceRow, TrustedRow,
// Theme, theme_colors) instead of calling `include_modules!()` again here — a
// second invocation would compile the SAME .slint source into a SECOND, nominally
// distinct set of Rust types, incompatible with the lib's (e.g. two different
// `ThemeColors` structs), even though they look identical.
use lan_mouse_slint::{theme_colors, AppWindow, CanvasBox, DeviceRow, Theme, TrustedRow};

/// Headless platform: every window is a MinimalSoftwareWindow (CPU renderer, no OS window).
struct HeadlessPlatform {
    window: Rc<MinimalSoftwareWindow>,
}

impl Platform for HeadlessPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.window.clone())
    }
    // run_event_loop() / duration_since_start() keep their defaults; we never run a loop.
}

fn render_appwindow_to_png(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1) Install the headless platform BEFORE creating any component.
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(HeadlessPlatform {
        window: window.clone(),
    }))
    .expect("set_platform must run exactly once, before AppWindow::new()");

    // 2) Build the component. Runs the generated register_font_from_memory(...) for the
    //    embedded TTFs — needs the software-renderer-systemfonts feature.
    let ui = AppWindow::new()?;

    // 2b) Theme.palettes is populated by Rust at runtime (not hardcoded in
    //     .slint) — the real app does this in lib.rs::run(); without it here the
    //     preview would render every color as the struct default (transparent).
    let themes = lan_mouse_frontend_core::theme::all_themes();
    ui.global::<Theme>().set_palettes(ModelRc::new(VecModel::from(
        themes.iter().map(theme_colors).collect::<Vec<_>>(),
    )));
    // 4th arg picks which theme to render (index into all_themes(): built-ins
    // then any user themes) — handy for reviewing every palette, not just index 0.
    let theme_idx: i32 = std::env::args().nth(4).and_then(|s| s.parse().ok()).unwrap_or(0);
    ui.global::<Theme>().set_index(theme_idx);

    // 3) Representative mock data so every region is exercised in one shot.
    ui.set_connected(true);
    ui.set_capture("enabled".into());
    ui.set_emulation("enabled".into());
    ui.set_port("4242".into());
    ui.set_fingerprint("73:90:2a:3c:9d:e5:18:52:7c:aa:c3:de:de:04:cd:ec".into());
    ui.set_pairing_fp("a4:f0:9c:2e:11:bd:77:0c:35:9a".into()); // shows the pairing card

    ui.set_devices(ModelRc::new(VecModel::from(vec![
        DeviceRow {
            handle: "1".into(),
            name: "studio-pc".into(),
            addr: "10.110.20.42:4242".into(),
            pos: "left".into(),
            active: true,
            alive: true,
        },
        DeviceRow {
            handle: "2".into(),
            name: "media-rig".into(),
            addr: "unresolved".into(),
            pos: "top".into(),
            active: false,
            alive: false,
        },
    ])));

    ui.set_trusted(ModelRc::new(VecModel::from(vec![
        TrustedRow {
            name: "windows-pc".into(),
            fp: "1e:19:1b:c4…".into(),
            fp_full: "1e:19:1b:c4:a8:44".into(),
            online: true,
        },
        TrustedRow {
            name: "laptop-air".into(),
            fp: "b7:2a:55:e1…".into(),
            fp_full: "b7:2a:55:e1:90:33".into(),
            online: false,
        },
    ])));

    match std::env::args().nth(5).as_deref() {
        Some("settings") => ui.set_show_settings(true),
        Some("add-device") => ui.set_show_add_device(true),
        Some("edit-device") => ui.set_editing_device("1".into()), // matches the mock studio-pc handle
        Some("delete-confirm") => ui.set_confirm_delete_handle("1".into()),
        Some("layout-canvas") => {
            ui.set_canvas_boxes(ModelRc::new(VecModel::from(vec![
                CanvasBox { handle: "1".into(), name: "studio-pc".into(), x: 20.0, y: 108.0 },
                CanvasBox { handle: "2".into(), name: "media-rig".into(), x: 192.0, y: 16.0 },
            ])));
            ui.set_show_layout_canvas(true);
        }
        _ => {}
    }

    // 4) Fixed HiDPI size. No Window::set_scale_factor in 1.14 — dispatch a WindowEvent
    //    BEFORE set_size (which takes PHYSICAL px; MinimalSoftwareWindow does not auto-size).
    let scale = 2.0_f32;
    // review height (taller than the app's default so the whole layout incl. footer
    // is visible in one shot); override with args: -- out.png [w] [h]
    let w: f32 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(560.0);
    let h: f32 = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(760.0);
    window
        .window()
        .dispatch_event(WindowEvent::ScaleFactorChanged {
            scale_factor: scale,
        });
    window.set_size(PhysicalSize::new((w * scale) as u32, (h * scale) as u32));

    // 5) Realize + settle bindings, then snapshot.
    ui.show()?;
    slint::platform::update_timers_and_animations();

    // 6) take_snapshot() re-renders one frame into RGBA8, but the software renderer copies
    //    RGB only and leaves ALPHA = 0 — force opaque or the PNG reads as blank.
    let buf = ui.window().take_snapshot()?;
    let (w, h) = (buf.width(), buf.height());
    let mut bytes = buf.as_bytes().to_vec();
    for px in bytes.chunks_exact_mut(4) {
        px[3] = 255;
    }
    image::RgbaImage::from_raw(w, h, bytes)
        .ok_or("buffer size mismatch for RgbaImage")?
        .save(path)?;

    ui.hide().ok();
    println!("wrote {path} ({w}x{h})");
    Ok(())
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "appwindow.png".into());
    render_appwindow_to_png(&path).expect("render failed");
}

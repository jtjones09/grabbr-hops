// Headless self-review render of the first-run onboarding screen. Same mechanism
// as render_png.rs (see that file for the detailed walkthrough of each step) —
// separate example because the mock data shape is entirely different (no
// devices/trusted list, just the theme palette).
//
//   cargo run -p lan-mouse-slint --example render_onboarding -- /path/to/out.png [w] [h] [theme_index]

use std::rc::Rc;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter, WindowEvent};
use slint::{ComponentHandle, ModelRc, PhysicalSize, VecModel};

use hops_slint::{theme_colors, OnboardingWindow, Theme};

struct HeadlessPlatform {
    window: Rc<MinimalSoftwareWindow>,
}

impl Platform for HeadlessPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.window.clone())
    }
}

fn render(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(HeadlessPlatform {
        window: window.clone(),
    }))
    .expect("set_platform must run exactly once, before OnboardingWindow::new()");

    let ui = OnboardingWindow::new()?;

    let themes = hops_frontend_core::theme::all_themes();
    ui.global::<Theme>().set_palettes(ModelRc::new(VecModel::from(
        themes.iter().map(theme_colors).collect::<Vec<_>>(),
    )));
    let theme_idx: i32 = std::env::args().nth(4).and_then(|s| s.parse().ok()).unwrap_or(0);
    ui.global::<Theme>().set_index(theme_idx);

    let scale = 2.0_f32;
    let w: f32 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(580.0);
    let h: f32 = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(420.0);
    window
        .window()
        .dispatch_event(WindowEvent::ScaleFactorChanged {
            scale_factor: scale,
        });
    window.set_size(PhysicalSize::new((w * scale) as u32, (h * scale) as u32));

    ui.show()?;
    slint::platform::update_timers_and_animations();

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
        .unwrap_or_else(|| "onboarding.png".into());
    render(&path).expect("render failed");
}

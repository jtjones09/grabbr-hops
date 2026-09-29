// Headless self-review render: builds AppWindow with mock data and writes a PNG
// using the pure software renderer — no window, no GPU, no macOS TCC permission.
// This is how the GUI's design gets reviewed without a display.
//
//   cargo run -p lan-mouse-slint --example render_png -- /path/to/out.png [w] [h] [theme_index] [mode]
//   mode: normal (default) | settings | add-device | edit-device | delete-confirm | removed-delete-confirm | revoke-confirm | layout-canvas
//         | layout-canvas
//
// Requires the crate's slint dep to carry feature "software-renderer-systemfonts"
// (see Cargo.toml) — without it, AppWindow::new() panics when the embedded
// Space Grotesk / Space Mono TTFs try to register with the software renderer.

use std::rc::Rc;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter, WindowEvent};
use slint::{ComponentHandle, Model, ModelRc, PhysicalSize, VecModel};

// Reuse the lib crate's Slint-generated types (AppWindow, DeviceRow, Theme,
// theme_colors) instead of calling `include_modules!()` again here — a second
// invocation would compile the SAME .slint source into a SECOND, nominally
// distinct set of Rust types, incompatible with the lib's (e.g. two different
// `ThemeColors` structs), even though they look identical.
use hops_frontend_core::Connection;
use hops_slint::{AppWindow, CanvasBox, DeviceRow, DiscoveredRow, DotTone, Theme, theme_colors};

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
    let themes = hops_frontend_core::theme::all_themes();
    ui.global::<Theme>()
        .set_palettes(ModelRc::new(VecModel::from(
            themes.iter().map(theme_colors).collect::<Vec<_>>(),
        )));
    // 4th arg picks which theme to render (index into all_themes(): built-ins
    // then any user themes) — handy for reviewing every palette, not just index 0.
    let theme_idx: i32 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    ui.global::<Theme>().set_index(theme_idx);

    // 3) Representative mock data so every region is exercised in one shot.
    // PREVIEW_SERVICE_PROBLEM=<text> shows the service banner; with
    // PREVIEW_DISCONNECTED set, as the app shows it before a daemon answers.
    ui.set_connected(std::env::var_os("PREVIEW_DISCONNECTED").is_none());
    if let Ok(problem) = std::env::var("PREVIEW_SERVICE_PROBLEM") {
        ui.set_service_problem(problem.into());
    }
    ui.set_capture("enabled".into());
    // PREVIEW_CAPTURE_PROBLEM=<text> shows a capture that failed, with the
    // settings button a Mac offers for a missing permission.
    if let Ok(problem) = std::env::var("PREVIEW_CAPTURE_PROBLEM") {
        ui.set_capture("failed".into());
        ui.set_capture_problem(problem.into());
        ui.set_capture_settings(true);
    }
    ui.set_emulation("enabled".into());
    ui.set_port("4722".into());
    // PREVIEW_CONTROLLED_MAC=1 shows a Mac that is only controlled: it only
    // dials out, and macOS has not granted hops Accessibility, so emulation
    // cannot run.
    if std::env::var_os("PREVIEW_CONTROLLED_MAC").is_some() {
        ui.set_emulation("failed".into());
        ui.set_emulation_problem(
            "Input emulation cannot run: macOS does not grant hops Accessibility, which \
             this Mac needs to be controlled from other machines. Turn hops on under \
             System Settings → Privacy & Security → Accessibility."
                .into(),
        );
        ui.set_emulation_settings(true);
        ui.set_dials_out_only(true);
    }
    ui.set_fingerprint("73:90:2a:3c:9d:e5:18:52:7c:aa:c3:de:de:04:cd:ec".into());
    let first_run = std::env::var_os("PREVIEW_FIRST_RUN").is_some();
    ui.set_discovery_active(std::env::var("PREVIEW_DISCOVERY").as_deref() != Ok("off"));
    // "off" implies an empty list, as the daemon sends: it stops publishing
    // peers when discovery is not running. A harness that shows rows while
    // inactive would exercise a state the product cannot produce.
    let nothing_found = matches!(
        std::env::var("PREVIEW_DISCOVERY").as_deref(),
        Ok("empty") | Ok("off") | Ok("quiet")
    );
    // PREVIEW_DISCOVERY=quiet: looking, and nobody has answered for a while.
    if std::env::var("PREVIEW_DISCOVERY").as_deref() == Ok("quiet") {
        ui.set_discovery_empty(
            "No other machine has answered. If one on this network runs hops, check that \
             hops is on under System Settings → Privacy & Security → Local Network."
                .into(),
        );
    }
    ui.set_discovered(ModelRc::new(VecModel::from(if nothing_found {
        vec![]
    } else {
        vec![
            DiscoveredRow {
                label: "linux-box".into(),
                fingerprint: "9c:2e:11".into(),
                addr_summary: "192.0.2.51 +2 more".into(),
                ips: "192.0.2.51,198.51.100.51,203.0.113.9".into(),
                port: "4722".into(),
            },
            DiscoveredRow {
                label: "lab-mbp-m4-max".into(),
                fingerprint: "".into(),
                addr_summary: "192.0.2.99".into(),
                ips: "192.0.2.99".into(),
                port: "4722".into(),
            },
        ]
    })));
    ui.set_pairing_fp("a4:f0:9c:2e:11:bd:77:0c:35:9a".into()); // shows the pairing card
    // flip to true to review the "we dialled this device" wording (#61)
    ui.set_pairing_from_our_dial(std::env::var_os("PREVIEW_OUR_DIAL").is_some());
    if std::env::var_os("PREVIEW_OUR_DIAL").is_some() {
        ui.set_pairing_addr("192.0.2.7:4722".into());
        // The words the poll loop sets, for the device this machine dialled
        // (#93); PREVIEW_OUR_DIAL=unknown for a dial that matches no device.
        let dialled = match std::env::var("PREVIEW_OUR_DIAL").as_deref() {
            Ok("unknown") => vec![],
            _ => vec!["desk mac (desk-mac.local:4722)".to_string()],
        };
        ui.set_pairing_dialled(hops_frontend_core::our_dial_words(&dialled).into());
    }
    // PREVIEW_KNOCK_ADDR=1: an inbound request with the address it came from
    // (#83), and a name typed into the card (#168).
    if std::env::var_os("PREVIEW_KNOCK_ADDR").is_some() {
        ui.set_pairing_addr("192.0.2.7:51234".into());
        ui.set_pairing_name("laptop".into());
    }
    // PREVIEW_CONTROLLER=0|1|2 answers "which machine is in control?" on the
    // card (#220); unset, nothing is chosen. PREVIEW_CLIPBOARD=1 switches the
    // clipboard on (#182).
    if let Some(i) = std::env::var("PREVIEW_CONTROLLER")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
    {
        ui.set_pairing_controller(i);
    }
    ui.set_pairing_clipboard(std::env::var_os("PREVIEW_CLIPBOARD").is_some());
    // the notice banner — the daemon's only "that didn't work" channel
    ui.set_notice(
        "Nothing was trusted: this machine is being controlled remotely, so it \
         refused to grant trust. Move the pointer back to the machine controlling \
         it, then try again with this machine's own keyboard and mouse."
            .into(),
    );
    ui.set_notice_seq(1);
    // PREVIEW_NOTICE="..." shows another notice, such as the front door's
    // restart of a service running another build (#222).
    if let Ok(notice) = std::env::var("PREVIEW_NOTICE") {
        ui.set_notice(notice.into());
    }
    // PREVIEW_INFO="..." shows the neutral info bar, e.g. the restart note.
    if let Ok(info) = std::env::var("PREVIEW_INFO") {
        ui.set_info(info.into());
    }

    // Exercise all four merged-card states in one shot.
    ui.set_devices(ModelRc::new(VecModel::from(vec![
        // #92: connected IN (online) but its emulation is OFF, so everything we
        // send is refused. This used to render green because `online || alive`.
        DeviceRow {
            handle: "1".into(),
            name: "studio-pc".into(),
            addr: "192.0.2.42:4722".into(),
            pos: "left".into(),
            active: true,
            tone: DotTone::Bad,
            status: "not accepting input".into(),
            has_send: true,
            fingerprint: "1e:19:1b".into(),
            fp_full: "1e:19:1b:c4:a8:44".into(),
            pin: "1e:19:1b:c4:a8:44".into(),
            trusted: true,
            clipboard: "shared both ways".into(),
            clipboard_on: true,
            pair_again: false,
        },
        // send-only, never connected (provisional — no fingerprint learned yet)
        DeviceRow {
            handle: "2".into(),
            name: "media-rig".into(),
            addr: "unresolved".into(),
            pos: "top".into(),
            active: false,
            tone: DotTone::Quiet,
            status: "off".into(),
            has_send: true,
            fingerprint: "".into(),
            fp_full: "".into(),
            pin: "".into(),
            trusted: false,
            clipboard: "".into(),
            clipboard_on: false,
            pair_again: false,
        },
        // receive-only trusted peer, connected in
        DeviceRow {
            handle: "".into(),
            name: "windows-pc".into(),
            addr: "".into(),
            pos: "".into(),
            active: false,
            tone: DotTone::Good,
            status: "connected".into(),
            has_send: false,
            fingerprint: "b7:2a:55".into(),
            fp_full: "b7:2a:55:e1:90:33".into(),
            pin: "b7:2a:55:e1:90:33".into(),
            trusted: true,
            clipboard: "arrives here from this device".into(),
            clipboard_on: true,
            pair_again: false,
        },
        // receive-only trusted peer, offline
        DeviceRow {
            handle: "".into(),
            name: "laptop-air".into(),
            addr: "".into(),
            pos: "".into(),
            active: false,
            tone: DotTone::Quiet,
            status: "not connected".into(),
            has_send: false,
            fingerprint: "c3:de:04".into(),
            fp_full: "c3:de:04:aa:11:22".into(),
            pin: "c3:de:04:aa:11:22".into(),
            trusted: true,
            clipboard: "off".into(),
            clipboard_on: false,
            pair_again: false,
        },
        // a machine this one controls that dials in to be controlled (#15),
        // with its link down: this machine waits for it
        DeviceRow {
            handle: "5".into(),
            name: "work-laptop".into(),
            addr: "dials in".into(),
            pos: "bottom".into(),
            active: true,
            tone: DotTone::Quiet,
            status: Connection::AwaitingItsDial.words().into(),
            has_send: true,
            fingerprint: "5d:81:e2".into(),
            fp_full: "5d:81:e2:07:bb:19".into(),
            pin: "5d:81:e2:07:bb:19".into(),
            trusted: true,
            clipboard: "goes from here to this device".into(),
            clipboard_on: true,
            pair_again: false,
        },
        // a pairing this machine only controls, with no device for it yet:
        // listed, and removable, before that machine first dials in
        DeviceRow {
            handle: "".into(),
            name: "desk mac".into(),
            addr: "".into(),
            pos: "".into(),
            active: false,
            tone: DotTone::Quiet,
            status: Connection::AwaitingItsDial.words().into(),
            has_send: false,
            fingerprint: "2d:18:1a".into(),
            fp_full: "2d:18:1a:c4:a8:40".into(),
            pin: "".into(),
            trusted: true,
            clipboard: "goes from here to this device".into(),
            clipboard_on: true,
            pair_again: false,
        },
        // the machine this one dials removed this one (#184): the card says
        // so and keeps its delete button, rather than vanishing
        DeviceRow {
            handle: "4".into(),
            name: "old-thinkpad".into(),
            addr: "192.0.2.61:4722".into(),
            pos: "top".into(),
            active: true,
            tone: DotTone::Bad,
            status: Connection::NoLongerTrusts.words().into(),
            has_send: true,
            fingerprint: "9f:04:7c".into(),
            fp_full: "9f:04:7c:12:aa:03".into(),
            pin: "9f:04:7c:12:aa:03".into(),
            trusted: true,
            clipboard: "".into(),
            clipboard_on: false,
            pair_again: false,
        },
        // paired with an older version and not since (#231): it grants
        // nothing, and the card offers to add it again or remove it
        DeviceRow {
            handle: "".into(),
            name: "iridium".into(),
            addr: "".into(),
            pos: "".into(),
            active: false,
            tone: hops_slint::dot_tone(Connection::PairAgain.tone()),
            status: Connection::PairAgain.words().into(),
            has_send: false,
            fingerprint: "bc:05:ab".into(),
            fp_full: "bc:05:ab:7a:a4:de".into(),
            pin: "".into(),
            trusted: false,
            clipboard: "".into(),
            clipboard_on: false,
            pair_again: true,
        },
    ])));

    // PREVIEW_NO_SWITCH=1 shows Settings as a Windows build has it, with no
    // in-place switch to the terminal interface (#173).
    ui.set_can_switch_interface(std::env::var_os("PREVIEW_NO_SWITCH").is_none());

    // PREVIEW_DISCONNECTED=1 shows what the app keeps once the daemon has gone:
    // the rows as last known, with every live fact cleared the way
    // hops_frontend_core clears it, and the notice a click then gets (#34).
    if std::env::var_os("PREVIEW_DISCONNECTED").is_some() {
        ui.set_capture("disabled".into());
        ui.set_emulation("disabled".into());
        ui.set_pairing_fp("".into());
        ui.set_notice(hops_frontend_core::NOT_CONNECTED.into());
        let rows: Vec<DeviceRow> = ui
            .get_devices()
            .iter()
            .map(|d| DeviceRow {
                tone: hops_slint::dot_tone(Connection::ServiceGone.tone()),
                status: Connection::ServiceGone.words().into(),
                ..d
            })
            .collect();
        ui.set_devices(ModelRc::new(VecModel::from(rows)));
    }

    // PREVIEW_STATES=1 lists one device in each connection state, drawn with
    // the window's own tone and words for it, to check each reads apart (#148).
    if std::env::var_os("PREVIEW_STATES").is_some() {
        let template = ui.get_devices().row_data(0).expect("a seeded row");
        let rows: Vec<DeviceRow> = Connection::ALL
            .iter()
            .enumerate()
            .map(|(i, c)| DeviceRow {
                handle: (i + 1).to_string().into(),
                name: format!("{c:?}").to_lowercase().into(),
                active: !matches!(c, Connection::Off),
                tone: hops_slint::dot_tone(c.tone()),
                status: c.words().into(),
                trusted: true,
                has_send: true,
                ..template.clone()
            })
            .collect();
        ui.set_devices(ModelRc::new(VecModel::from(rows)));
        ui.set_notice("".into());
        ui.set_pairing_fp("".into());
    }

    // PREVIEW_FIRST_RUN=1 shows the case discovery exists FOR: a fresh install
    // with nothing configured, where "on your network" is the whole screen.
    // Applied after the seeded state above so it actually wins.
    if first_run {
        ui.set_devices(ModelRc::new(VecModel::from(Vec::<DeviceRow>::new())));
        ui.set_notice("".into());
        ui.set_pairing_fp("".into());
    }

    // PREVIEW_PAIRING_SECONDS=102 shows the pairing window counting down (#195).
    if let Some(seconds) = std::env::var("PREVIEW_PAIRING_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        ui.set_pairing_seconds(seconds);
    }

    // PREVIEW_CHECK=show|show-answered|pick|pick-answered shows the number
    // card (#11, #167): the adding machine's number and confirm, or the three
    // numbers the machine being added picks from, before and after answering.
    if let Ok(check) = std::env::var("PREVIEW_CHECK") {
        ui.set_pairing_fp("".into());
        ui.set_notice("".into());
        ui.set_check_fp("a4:f0:9c:2e:11:bd:77:0c:35:9a".into());
        ui.set_check_from("a4:f0:9c at 192.0.2.7:4722".into());
        ui.set_check_show(check.starts_with("show"));
        ui.set_check_number("042 917".into());
        ui.set_check_choices(ModelRc::new(VecModel::from(vec![
            slint::SharedString::from("318 204"),
            "042 917".into(),
            "775 061".into(),
        ])));
        ui.set_check_answered(check.ends_with("answered"));
    }

    match std::env::args().nth(5).as_deref() {
        Some("settings") => ui.set_show_settings(true),
        Some("add-device") => ui.set_show_add_device(true),
        // matches the mock studio-pc handle: paired, so its address carries its pin
        Some("edit-device") => {
            ui.set_editing_device("1".into());
            ui.set_editing_pin("1e:19:1b:c4:a8:44".into());
            ui.set_editing_send(true);
        }
        Some("clipboard-confirm") => {
            ui.set_editing_device("1".into());
            ui.set_editing_pin("1e:19:1b:c4:a8:44".into());
            ui.set_editing_send(true);
            ui.set_confirm_clipboard_off(true);
        }
        // laptop-air: a receive-only row, keyed by fingerprint, clipboard off
        Some("edit-clipboard-off") => ui.set_editing_device("c3:de:04:aa:11:22".into()),
        // the question left open while the clipboard went off from another
        // app: the row must say off, not ask
        Some("clipboard-confirm-after-off") => {
            ui.set_editing_device("c3:de:04:aa:11:22".into());
            ui.set_confirm_clipboard_off(true);
        }
        // media-rig: never connected, so no pairing and no clipboard to show
        Some("edit-unpaired") => {
            ui.set_editing_device("2".into());
            ui.set_editing_send(true);
        }
        Some("delete-confirm") => ui.set_confirm_delete_handle("1".into()),
        // the device whose machine removed this one, asked about deleting it
        Some("removed-delete-confirm") => ui.set_confirm_delete_handle("4".into()),
        // b7:2a:55 is the mock windows-pc — a trusted, receive-capable peer
        Some("revoke-confirm") => ui.set_confirm_revoke_fp("b7:2a:55:e1:90:33".into()),
        // The arrange overlay is a hardcoded 560x420 centred by
        // (parent.width - 560)/2. Render it at the window's MINIMUM: before the
        // ScrollView floor the window could open 381px wide, making that offset
        // -89 and hanging the overlay off all four edges.
        Some("layout-canvas") => {
            ui.set_canvas_boxes(ModelRc::new(VecModel::from(vec![
                CanvasBox {
                    handle: "1".into(),
                    name: "studio-pc".into(),
                    x: 20.0,
                    y: 108.0,
                },
                CanvasBox {
                    handle: "2".into(),
                    name: "media-rig".into(),
                    x: 192.0,
                    y: 16.0,
                },
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
    let w: f32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(560.0);
    let h: f32 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(760.0);
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
    for px in bytes.as_chunks_mut::<4>().0 {
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

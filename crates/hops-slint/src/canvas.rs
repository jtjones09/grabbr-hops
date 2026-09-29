//! The arrange canvas (#174): where a device is dropped sets the edge of
//! this machine its pointer crosses at, and each device is drawn at a clean
//! spot on its edge's side, so the picture and the crossing always agree.
//!
//! Every length here is in the canvas's logical px and matches `CanvasSize`
//! in ui/layout_canvas.slint: a 480x280 canvas, 96x64 boxes, this machine's
//! box in the middle.

use std::{cell::RefCell, rc::Rc};

use hops_frontend_core::{AppModel, ClientHandle, FrontendRequest, Position};
use hops_ipc::Geometry;
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::{AppWindow, CanvasBox};

const CANVAS_W: f32 = 480.0;
const CANVAS_H: f32 = 280.0;
const BOX_W: f32 = 96.0;
const BOX_H: f32 = 64.0;
/// This machine's box: the top-left corner of the middle of the canvas.
const HOME: (f32, f32) = ((CANVAS_W - BOX_W) / 2.0, (CANVAS_H - BOX_H) / 2.0);
/// How far a box sits from the canvas's border on its side.
const MARGIN: f32 = 16.0;
/// How far a box's top-left corner can be from this machine's, across and
/// down: a box anywhere on the canvas is within these.
const REACH: (f32, f32) = (HOME.0, HOME.1);
/// Offsets along a side, one per box drawn there. Only one device per edge
/// is switched on; the others there are switched off and drawn beside it,
/// clear of it, and still reached through that side's edge by
/// [`drop_edge`].
const ALONG_LEFT_RIGHT: [f32; 3] = [0.0, -72.0, 72.0];
const ALONG_TOP_BOTTOM: [f32; 3] = [0.0, -104.0, 104.0];

/// The edge of this machine a box dropped with its top-left corner at
/// `(x, y)` is reached through. The canvas's two diagonals, which cross at
/// this machine's box, cut it into four zones, one per edge: the drop takes
/// the edge of the zone it lies in. That is the dominant axis of the box's
/// offset from this machine's box, each axis measured against how far the
/// canvas lets a box go that way. A drop exactly on a diagonal counts as
/// horizontal, for the left and right edges most setups use. A box dropped
/// squarely on this machine's has no side.
pub(crate) fn drop_edge(x: f32, y: f32) -> Option<Position> {
    let (dx, dy) = (x - HOME.0, y - HOME.1);
    if !dx.is_finite() || !dy.is_finite() || (dx == 0.0 && dy == 0.0) {
        return None;
    }
    // |dx| / REACH.0 >= |dy| / REACH.1, without dividing
    Some(if dx.abs() * REACH.1 >= dy.abs() * REACH.0 {
        if dx < 0.0 {
            Position::Left
        } else {
            Position::Right
        }
    } else if dy < 0.0 {
        Position::Top
    } else {
        Position::Bottom
    })
}

/// Where the canvas draws the `k`th box on the `pos` side: the first
/// centred on that side of this machine, the rest beside it.
pub(crate) fn edge_spot(pos: Position, k: usize) -> (f32, f32) {
    let lr = ALONG_LEFT_RIGHT[k % ALONG_LEFT_RIGHT.len()];
    let tb = ALONG_TOP_BOTTOM[k % ALONG_TOP_BOTTOM.len()];
    match pos {
        Position::Left => (MARGIN, HOME.1 + lr),
        Position::Right => (CANVAS_W - BOX_W - MARGIN, HOME.1 + lr),
        Position::Top => (HOME.0 + tb, MARGIN),
        Position::Bottom => (HOME.0 + tb, CANVAS_H - BOX_H - MARGIN),
    }
}

/// The boxes the canvas draws for `m`'s devices, with `moved` (a device
/// and the edge it was just dropped on) drawn there already. Per side, the
/// switched-on device takes the middle spot; the switched-off ones are
/// drawn before it, so it is on top where they overlap.
pub(crate) fn canvas_boxes(
    m: &AppModel,
    moved: Option<(ClientHandle, Position)>,
) -> Vec<CanvasBox> {
    let mut devices: Vec<(ClientHandle, String, Position, bool)> = m
        .clients
        .iter()
        .map(|(&h, (cfg, state))| {
            let pos = match moved {
                Some((m, to)) if m == h => to,
                _ => cfg.pos,
            };
            let name = cfg
                .label
                .clone()
                .or_else(|| cfg.hostname.clone())
                .unwrap_or_else(|| "unnamed".into());
            (h, name, pos, state.active)
        })
        .collect();
    // switched on first, then by handle: the order spots are handed out in
    devices.sort_by_key(|&(h, _, _, active)| (!active, h));
    let mut taken = [0usize; 4];
    let mut boxes: Vec<(bool, CanvasBox)> = devices
        .into_iter()
        .map(|(h, name, pos, active)| {
            let side = match pos {
                Position::Left => 0,
                Position::Right => 1,
                Position::Top => 2,
                Position::Bottom => 3,
            };
            let (x, y) = edge_spot(pos, taken[side]);
            taken[side] += 1;
            let b = CanvasBox {
                handle: h.to_string().into(),
                name: name.into(),
                x,
                y,
                active,
            };
            (active, b)
        })
        .collect();
    // drawn in order: switched off first, so the switched-on one is on top
    boxes.sort_by_key(|(active, b)| (*active, b.handle.parse::<u64>().unwrap_or(0)));
    boxes.into_iter().map(|(_, b)| b).collect()
}

/// What dropping device `handle`'s box with its top-left corner at `(x, y)`
/// asks the daemon for: the edge the drop lies on, if that changed, and the
/// clean spot on that side as its saved geometry. Nothing for a drop
/// squarely on this machine, or for a device the model does not hold.
pub(crate) fn drop_requests(
    m: &AppModel,
    handle: ClientHandle,
    x: f32,
    y: f32,
) -> Vec<FrontendRequest> {
    let (Some((cfg, _)), Some(edge)) = (m.clients.get(&handle), drop_edge(x, y)) else {
        return Vec::new();
    };
    let (sx, sy) = edge_spot(edge, 0);
    let spot = Geometry {
        x: sx as i32,
        y: sy as i32,
        width: BOX_W as u32,
        height: BOX_H as u32,
    };
    let mut out = Vec::new();
    if cfg.pos != edge {
        out.push(FrontendRequest::UpdatePosition(handle, edge));
    }
    if cfg.geometry != Some(spot) {
        out.push(FrontendRequest::UpdateGeometry(handle, Some(spot)));
    }
    out
}

/// The paired machines this one may control that have no device here, so
/// no edge to set: hops has no address to reach them at until one connects.
/// Their names, for the line saying why they are not on the canvas.
pub(crate) fn unplaced(m: &AppModel) -> String {
    let names: Vec<String> = m
        .devices()
        .into_iter()
        .filter(|d| d.send.is_none() && d.controls && !d.pair_again)
        .map(|d| d.label)
        .collect();
    names.join(", ")
}

/// This machine's box: its name, without the `.local` mDNS suffix, and
/// what kind of machine it is.
pub(crate) fn this_machine(hostname: Option<&str>, os: &str) -> (String, &'static str) {
    let name = hostname
        .map(|h| h.trim().trim_end_matches(".local").to_owned())
        .unwrap_or_default();
    let kind = match os {
        "macos" => "this Mac",
        "windows" => "this PC",
        _ => "this computer",
    };
    (name, kind)
}

/// Keeps the open canvas drawn from the model: redrawn when a device is
/// added, removed, renamed, switched, or moves edge, and only then, since a
/// redraw ends a drag in progress.
#[derive(Default)]
pub(crate) struct Canvas {
    drawn_from: Option<(Vec<CanvasBox>, String)>,
}

impl Canvas {
    pub(crate) fn open(&mut self, ui: &AppWindow, m: &AppModel) {
        self.drawn_from = None;
        ui.set_show_layout_canvas(true);
        self.tick(ui, m);
    }

    /// Redraw the canvas if it is open and what it draws changed.
    pub(crate) fn tick(&mut self, ui: &AppWindow, m: &AppModel) {
        if !ui.get_show_layout_canvas() {
            self.drawn_from = None;
            return;
        }
        let now = (canvas_boxes(m, None), unplaced(m));
        if self.drawn_from.as_ref() != Some(&now) {
            ui.set_canvas_boxes(ModelRc::new(VecModel::from(now.0.clone())));
            ui.set_canvas_unplaced(now.1.clone().into());
            self.drawn_from = Some(now);
        }
    }

    /// A box was dropped: snap it to its spot on the edge it now uses at
    /// once, and return what to ask the daemon for. The rest of the canvas
    /// follows when the daemon's answer changes the model.
    pub(crate) fn dropped(
        &mut self,
        ui: &AppWindow,
        m: &AppModel,
        handle: ClientHandle,
        x: f32,
        y: f32,
    ) -> Vec<FrontendRequest> {
        let requests = drop_requests(m, handle, x, y);
        let moved = requests.iter().find_map(|r| match r {
            FrontendRequest::UpdatePosition(h, to) => Some((*h, *to)),
            _ => None,
        });
        ui.set_canvas_boxes(ModelRc::new(VecModel::from(canvas_boxes(m, moved))));
        requests
    }
}

/// Wire the canvas's callbacks: `snapshot` reads the model, `send` sends a
/// request to the daemon. The poll loop calls `tick` on what this returns.
pub(crate) fn wire(
    ui: &AppWindow,
    snapshot: impl Fn() -> AppModel + Clone + 'static,
    send: impl Fn(FrontendRequest) + 'static,
) -> Rc<RefCell<Canvas>> {
    let canvas = Rc::new(RefCell::new(Canvas::default()));
    {
        let (weak, canvas, snapshot) = (ui.as_weak(), canvas.clone(), snapshot.clone());
        ui.on_open_layout_canvas(move || {
            if let Some(ui) = weak.upgrade() {
                canvas.borrow_mut().open(&ui, &snapshot());
            }
        });
    }
    {
        let (weak, canvas) = (ui.as_weak(), canvas.clone());
        ui.on_device_dropped(move |handle, x, y| {
            let (Some(ui), Ok(h)) = (weak.upgrade(), handle.as_str().parse::<ClientHandle>())
            else {
                return;
            };
            let requests = canvas.borrow_mut().dropped(&ui, &snapshot(), h, x, y);
            for request in requests {
                send(request);
            }
        });
    }
    canvas
}

#[cfg(test)]
mod tests {
    use super::*;
    use hops_frontend_core::{ClientConfig, ClientState, FrontendEvent, PeerTrust};
    use slint::Model;
    use std::cell::RefCell;

    fn device(name: &str, pos: Position, active: bool) -> (ClientConfig, ClientState) {
        (
            ClientConfig {
                hostname: Some(name.into()),
                pos,
                ..Default::default()
            },
            ClientState {
                active,
                ..Default::default()
            },
        )
    }

    /// The desk pc on the left and the media rig on the right, both on.
    fn two_devices() -> AppModel {
        let mut m = AppModel::default();
        for (h, (c, s)) in [
            (0, device("desk-pc", Position::Left, true)),
            (1, device("media-rig", Position::Right, true)),
        ] {
            m.apply(FrontendEvent::Created(h, c, s));
        }
        m
    }

    /// Each box the window holds: handle, x, y.
    fn drawn(ui: &AppWindow) -> Vec<(String, f32, f32)> {
        ui.get_canvas_boxes()
            .iter()
            .map(|b| (b.handle.to_string(), b.x, b.y))
            .collect()
    }

    // LEDGER T174f | class B | 1 return value: drop_edge, edge_spot
    #[test]
    fn a_drop_takes_the_edge_of_the_zone_it_lies_in() {
        use Position::*;
        let cases: &[((f32, f32), Option<Position>, &str)] = &[
            ((16.0, 108.0), Some(Left), "beside, on the left"),
            ((368.0, 108.0), Some(Right), "beside, on the right"),
            ((192.0, 16.0), Some(Top), "above"),
            ((192.0, 200.0), Some(Bottom), "below"),
            ((300.0, 0.0), Some(Top), "above, a little right"),
            ((380.0, 30.0), Some(Right), "right, a little up"),
            // exactly on a diagonal: horizontal
            ((0.0, 0.0), Some(Left), "the top-left corner"),
            ((384.0, 0.0), Some(Right), "the top-right corner"),
            ((0.0, 216.0), Some(Left), "the bottom-left corner"),
            ((384.0, 216.0), Some(Right), "the bottom-right corner"),
            ((96.0, 54.0), Some(Left), "halfway to the top-left corner"),
            // one step off the diagonal, toward the top
            ((97.0, 53.0), Some(Top), "just above the top-left diagonal"),
            ((192.0, 108.0), None, "squarely on this machine"),
            ((f32::NAN, 10.0), None, "not a number"),
            ((f32::INFINITY, 10.0), None, "not finite"),
        ];
        for &((x, y), edge, what) in cases {
            assert_eq!(drop_edge(x, y), edge, "{what} ({x}, {y})");
        }
    }

    // LEDGER T174f2 | class B | 1 return value: edge_spot through drop_edge
    /// Every spot a device is drawn at is reached through its own edge and
    /// lies on the canvas, and the spots on one side keep clear of each
    /// other: the picture never shows a place the crossing does not honour.
    #[test]
    fn every_spot_drawn_is_on_its_own_edge() {
        for pos in [
            Position::Left,
            Position::Right,
            Position::Top,
            Position::Bottom,
        ] {
            for k in 0..6 {
                let (x, y) = edge_spot(pos, k);
                assert_eq!(drop_edge(x, y), Some(pos), "spot {k} on the {pos} side");
                assert!(
                    (0.0..=CANVAS_W - BOX_W).contains(&x) && (0.0..=CANVAS_H - BOX_H).contains(&y),
                    "spot {k} on the {pos} side, ({x}, {y}), is off the canvas"
                );
            }
            let spots: Vec<_> = (0..3).map(|k| edge_spot(pos, k)).collect();
            for (i, a) in spots.iter().enumerate() {
                for b in &spots[i + 1..] {
                    let apart = (a.0 - b.0).abs() >= BOX_W || (a.1 - b.1).abs() >= BOX_H;
                    assert!(apart, "two boxes on the {pos} side overlap: {a:?} {b:?}");
                }
            }
        }
    }

    // LEDGER T174g | class B | 1 return value: drop_requests
    #[test]
    fn a_drop_asks_for_the_edge_it_lies_on_and_the_spot_there() {
        let m = two_devices();
        let right_spot = Geometry {
            x: 368,
            y: 108,
            width: 96,
            height: 64,
        };
        let left_spot = Geometry {
            x: 16,
            y: 108,
            width: 96,
            height: 64,
        };
        assert_eq!(
            drop_requests(&m, 0, 360.0, 150.0),
            [
                FrontendRequest::UpdatePosition(0, Position::Right),
                FrontendRequest::UpdateGeometry(0, Some(right_spot)),
            ],
            "the desk pc dropped on the right"
        );
        assert_eq!(
            drop_requests(&m, 0, 40.0, 60.0),
            [FrontendRequest::UpdateGeometry(0, Some(left_spot))],
            "the desk pc dropped higher on its own side keeps its edge"
        );
        assert_eq!(
            drop_requests(&m, 0, 192.0, 108.0),
            [],
            "dropped on this machine"
        );
        assert_eq!(
            drop_requests(&m, 7, 360.0, 150.0),
            [],
            "a device not in the model"
        );
    }

    /// What the wired canvas sent the daemon.
    type Sent = Rc<RefCell<Vec<FrontendRequest>>>;

    /// A window with the canvas wired to `model`, recording what it sends.
    fn wired(model: Rc<RefCell<AppModel>>) -> (AppWindow, Rc<RefCell<Canvas>>, Sent) {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("window");
        ui.window().set_size(slint::LogicalSize::new(560.0, 760.0));
        ui.show().expect("the window shows");
        let sent = Rc::new(RefCell::new(Vec::new()));
        let canvas = wire(
            &ui,
            {
                let model = model.clone();
                move || model.borrow().clone()
            },
            {
                let sent = sent.clone();
                move |r| sent.borrow_mut().push(r)
            },
        );
        (ui, canvas, sent)
    }

    // LEDGER T174h | class B | 3 widget tree: a drag dispatched to AppWindow's canvas, the requests its callback sends, canvas-boxes
    /// The desk pc's box is dragged from the left of this machine to the
    /// right: the window asks for the right edge and draws the box at its
    /// spot there at once.
    #[test]
    fn dragging_a_box_across_moves_its_device_to_that_edge() {
        let model = Rc::new(RefCell::new(two_devices()));
        let (ui, canvas, sent) = wired(model.clone());
        ui.invoke_open_layout_canvas();
        assert!(ui.get_show_layout_canvas(), "the canvas did not open");
        let desk = i_slint_backend_testing::ElementHandle::find_by_accessible_label(&ui, "desk-pc")
            .next()
            .expect("the desk pc's box");
        let (at, size) = (desk.absolute_position(), desk.size());
        // its centre, moved from the left spot to the right one
        let to =
            slint::LogicalPosition::new(at.x + size.width / 2.0 + 352.0, at.y + size.height / 2.0);
        desk.mock_drag(to, slint::platform::PointerEventButton::Left);

        assert!(
            sent.borrow()
                .contains(&FrontendRequest::UpdatePosition(0, Position::Right)),
            "the drag did not ask for the right edge: {:?}",
            sent.borrow()
        );
        let desk_now = drawn(&ui).into_iter().find(|b| b.0 == "0");
        assert_eq!(
            desk_now,
            Some(("0".into(), 368.0, 108.0)),
            "the desk pc is not drawn at its spot on the right"
        );
        // Until the daemon answers, the poll must not draw it back.
        canvas.borrow_mut().tick(&ui, &model.borrow());
        assert_eq!(
            drawn(&ui).into_iter().find(|b| b.0 == "0").map(|b| b.1),
            Some(368.0),
            "a poll before the daemon answered drew the box back where it was"
        );
    }

    // LEDGER T174i | class B | 3 widget tree: canvas-boxes after Canvas::tick over AppModel::apply
    /// While the canvas is open, a device that moves edge (as the one on
    /// the far edge does when another takes its edge) is redrawn there, and
    /// one added is drawn; a poll that changes nothing redraws nothing.
    #[test]
    fn the_open_canvas_follows_the_devices() {
        let model = Rc::new(RefCell::new(two_devices()));
        let (ui, canvas, _sent) = wired(model.clone());
        ui.invoke_open_layout_canvas();
        assert_eq!(
            drawn(&ui),
            [("0".into(), 16.0, 108.0), ("1".into(), 368.0, 108.0)]
        );

        {
            let mut m = model.borrow_mut();
            let (c, s) = device("desk-pc", Position::Right, true);
            m.apply(FrontendEvent::State(0, c, s));
            let (c, s) = device("media-rig", Position::Left, true);
            m.apply(FrontendEvent::State(1, c, s));
            let (c, s) = device("lab-linux", Position::Top, true);
            m.apply(FrontendEvent::Created(2, c, s));
        }
        canvas.borrow_mut().tick(&ui, &model.borrow());
        assert_eq!(
            drawn(&ui),
            [
                ("0".into(), 368.0, 108.0),
                ("1".into(), 16.0, 108.0),
                ("2".into(), 192.0, 16.0),
            ],
            "the open canvas did not follow the devices"
        );

        // A redraw ends a drag in progress, so an unchanged model draws nothing.
        ui.set_canvas_boxes(ModelRc::new(VecModel::from(Vec::<CanvasBox>::new())));
        canvas.borrow_mut().tick(&ui, &model.borrow());
        assert!(
            drawn(&ui).is_empty(),
            "a poll that changed nothing redrew the canvas"
        );
    }

    // LEDGER T174j | class B | 1 return value + 3 widget tree: unplaced, canvas-unplaced after open
    /// A paired machine this one may control, with no device here, has no
    /// edge to set: it is named under the canvas, not drawn on it.
    #[test]
    fn a_paired_machine_with_no_device_is_named_not_drawn() {
        let mut m = two_devices();
        let trust = [(
            "c3:5e:aa:10:44:9b:21:07".to_string(),
            PeerTrust {
                label: "office laptop".into(),
                we_may_drive: true,
                ..Default::default()
            },
        )];
        m.apply(FrontendEvent::TrustUpdated(trust.into_iter().collect()));
        let (ui, _canvas, _sent) = wired(Rc::new(RefCell::new(m)));
        ui.invoke_open_layout_canvas();
        assert_eq!(
            (ui.get_canvas_unplaced().to_string(), drawn(&ui).len()),
            ("office laptop".to_string(), 2),
            "(named under the canvas, boxes drawn)"
        );
    }

    // LEDGER T174k | class B | 1 return value: this_machine
    #[test]
    fn this_machine_is_named_for_what_it_is() {
        assert_eq!(
            this_machine(Some("desk-mac.local"), "macos"),
            ("desk-mac".to_string(), "this Mac")
        );
        assert_eq!(
            this_machine(Some("studio-pc"), "windows"),
            ("studio-pc".to_string(), "this PC")
        );
        assert_eq!(
            this_machine(None, "linux"),
            (String::new(), "this computer")
        );
    }
}

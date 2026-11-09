//! Host contracts for Win16 region and clip calls.
//!
//! Windows 3.1 stores an empty region when a rectangle's horizontal edges are
//! reversed. Win32 normalizes that span, so these tests call the host adapter
//! rather than the raw Win32 constructors.

use runtime::{
    Win16DrawingOperation, Win16DrawingPoint, Win16DrawingRect, Win16DrawingResult,
    Win16GdiObjectOperation, Win16HostDc, Win16HostGdiObject,
};
use windows_sys::Win32::Graphics::Gdi::{
    ALTERNATE, COMPLEXREGION, NULLREGION, RGN_AND, RGN_COPY, RGN_ERROR, SIMPLEREGION, WINDING,
};

use super::guest_text::GuestTextCodec;
use super::win16_drawing;
use super::win16_gdi::Win16Dcs;
use super::win16_gdi_object_factories;
use super::win16_gdi_objects::Win16Objects;
use super::win16_images::Win16Images;

struct Fixture {
    dcs: Win16Dcs,
    images: Win16Images,
    objects: Win16Objects,
}

impl Fixture {
    fn new() -> Self {
        let codec = GuestTextCodec::new(1252).expect("code page 1252");
        let images = Win16Images::new(GuestTextCodec::new(1252).expect("code page 1252"));
        Self {
            dcs: Win16Dcs::with_text_codec(codec),
            images,
            objects: Win16Objects::new(),
        }
    }

    fn create(&mut self, operation: Win16GdiObjectOperation) -> Option<Win16HostGdiObject> {
        win16_gdi_object_factories::create(&mut self.objects, &self.dcs, operation)
            .expect("region factory")
    }

    fn draw(&mut self, operation: Win16DrawingOperation) -> Win16DrawingResult {
        win16_drawing::execute(&self.dcs, &mut self.objects, &self.images, operation)
            .expect("region drawing")
    }
}

fn edges(left: i32, top: i32, right: i32, bottom: i32) -> Win16DrawingRect {
    Win16DrawingRect {
        left,
        top,
        right,
        bottom,
    }
}

fn point(x: i32, y: i32) -> Win16DrawingPoint {
    Win16DrawingPoint { x, y }
}

fn rect_op(left: i32, top: i32, right: i32, bottom: i32) -> Win16GdiObjectOperation {
    Win16GdiObjectOperation::CreateRectRgn {
        rect: edges(left, top, right, bottom),
    }
}

fn flag(result: Win16DrawingResult) -> bool {
    match result {
        Win16DrawingResult::Bool(value) => value,
        other => panic!("expected a BOOL result, got {other:?}"),
    }
}

fn kind(result: Win16DrawingResult) -> i32 {
    match result {
        Win16DrawingResult::RegionComplexity(value) => value,
        other => panic!("expected a region complexity, got {other:?}"),
    }
}

fn boxed(result: Win16DrawingResult) -> (i32, Win16DrawingRect) {
    match result {
        Win16DrawingResult::Rect { complexity, rect } => (complexity, rect),
        other => panic!("expected a region box, got {other:?}"),
    }
}

fn region_box(fix: &mut Fixture, region: Win16HostGdiObject) -> (i32, Win16DrawingRect) {
    boxed(fix.draw(Win16DrawingOperation::GetRgnBox { region }))
}

fn inside(fix: &mut Fixture, region: Win16HostGdiObject, x: i32, y: i32) -> bool {
    flag(fix.draw(Win16DrawingOperation::PtInRegion { region, x, y }))
}

#[test]
fn rectangular_regions_keep_reversed_horizontal_edges_empty() {
    let mut fix = Fixture::new();
    let reversed = fix
        .create(rect_op(20, 10, 10, 20))
        .expect("reversed region");
    assert_eq!(
        region_box(&mut fix, reversed),
        (NULLREGION, edges(0, 0, 0, 0))
    );
    assert!(!inside(&mut fix, reversed, 15, 15));

    let flat = fix.create(rect_op(5, 1, 5, 9)).expect("flat region");
    assert_eq!(region_box(&mut fix, flat), (NULLREGION, edges(0, 0, 0, 0)));
    assert!(flag(fix.draw(Win16DrawingOperation::EqualRgn {
        region1: reversed,
        region2: flat,
    })));

    let indirect = fix
        .create(Win16GdiObjectOperation::CreateRectRgnIndirect {
            rect: Some(edges(8, 3, 2, 12)),
        })
        .expect("indirect reversed region");
    assert_eq!(
        region_box(&mut fix, indirect),
        (NULLREGION, edges(0, 0, 0, 0))
    );
    assert!(
        fix.create(Win16GdiObjectOperation::CreateRectRgnIndirect { rect: None })
            .is_none()
    );

    let ordered = fix.create(rect_op(10, 10, 20, 20)).expect("ordered region");
    assert_eq!(
        region_box(&mut fix, ordered),
        (SIMPLEREGION, edges(10, 10, 20, 20))
    );
    assert!(inside(&mut fix, ordered, 10, 10));
    assert!(inside(&mut fix, ordered, 19, 19));
    assert!(!inside(&mut fix, ordered, 20, 10));
    assert!(!inside(&mut fix, ordered, 10, 20));

    let vertical = fix
        .create(rect_op(10, 20, 20, 10))
        .expect("vertical region");
    assert_eq!(
        region_box(&mut fix, vertical),
        (SIMPLEREGION, edges(10, 10, 20, 20))
    );
    assert!(inside(&mut fix, vertical, 15, 15));
    assert!(flag(fix.draw(Win16DrawingOperation::EqualRgn {
        region1: ordered,
        region2: vertical,
    })));
}

#[test]
fn set_rect_rgn_empties_a_reversed_horizontal_span() {
    let mut fix = Fixture::new();
    let region = fix.create(rect_op(0, 0, 12, 9)).expect("region");
    assert!(flag(fix.draw(Win16DrawingOperation::SetRectRgn {
        region,
        rect: edges(30, 4, 10, 18),
    })));
    assert_eq!(
        region_box(&mut fix, region),
        (NULLREGION, edges(0, 0, 0, 0))
    );
    assert!(!inside(&mut fix, region, 20, 10));

    assert!(flag(fix.draw(Win16DrawingOperation::SetRectRgn {
        region,
        rect: edges(1, 8, 9, 2),
    })));
    assert_eq!(
        region_box(&mut fix, region),
        (SIMPLEREGION, edges(1, 2, 9, 8))
    );
    assert!(inside(&mut fix, region, 1, 2));
    assert!(!inside(&mut fix, region, 9, 2));

    let pen = fix
        .create(Win16GdiObjectOperation::CreatePen {
            style: 0,
            width: 1,
            color: 0,
        })
        .expect("pen");
    assert!(!flag(fix.draw(Win16DrawingOperation::SetRectRgn {
        region: pen,
        rect: edges(0, 0, 4, 4),
    })));
    assert!(!inside(&mut fix, pen, 1, 1));
}

#[test]
fn round_rect_with_a_zero_axis_uses_the_rectangular_rule() {
    let mut fix = Fixture::new();
    let rectangle = fix.create(rect_op(0, 0, 30, 20)).expect("rectangle");
    let rounded = fix
        .create(Win16GdiObjectOperation::CreateRoundRectRgn {
            rect: edges(0, 0, 30, 20),
            ellipse_width: 0,
            ellipse_height: 8,
        })
        .expect("zero-width round rect");
    assert!(flag(fix.draw(Win16DrawingOperation::EqualRgn {
        region1: rectangle,
        region2: rounded,
    })));

    let negative_height = fix
        .create(Win16GdiObjectOperation::CreateRoundRectRgn {
            rect: edges(0, 0, 30, 20),
            ellipse_width: 0,
            ellipse_height: -4,
        })
        .expect("zero-width negative-height round rect");
    assert!(flag(fix.draw(Win16DrawingOperation::EqualRgn {
        region1: rectangle,
        region2: negative_height,
    })));

    let reversed = fix
        .create(Win16GdiObjectOperation::CreateRoundRectRgn {
            rect: edges(30, 0, 0, 20),
            ellipse_width: 6,
            ellipse_height: 0,
        })
        .expect("reversed round rect");
    assert_eq!(
        region_box(&mut fix, reversed),
        (NULLREGION, edges(0, 0, 0, 0))
    );

    let curved = fix
        .create(Win16GdiObjectOperation::CreateRoundRectRgn {
            rect: edges(0, 0, 30, 20),
            ellipse_width: 8,
            ellipse_height: 8,
        })
        .expect("round rect");
    assert!(inside(&mut fix, curved, 15, 10));
    assert!(!inside(&mut fix, curved, 100, 100));
    let negative = fix
        .create(Win16GdiObjectOperation::CreateRoundRectRgn {
            rect: edges(0, 0, 30, 20),
            ellipse_width: -8,
            ellipse_height: -6,
        })
        .expect("negative corner axes");
    assert!(inside(&mut fix, negative, 15, 10));
}

#[test]
fn elliptic_and_polygon_regions_use_native_fill_rules() {
    let mut fix = Fixture::new();
    let ellipse = fix
        .create(Win16GdiObjectOperation::CreateEllipticRgn {
            rect: edges(0, 0, 20, 16),
        })
        .expect("ellipse");
    assert!(inside(&mut fix, ellipse, 10, 8));
    assert!(!inside(&mut fix, ellipse, 0, 0));
    assert!(
        fix.create(Win16GdiObjectOperation::CreateEllipticRgnIndirect { rect: None })
            .is_none()
    );

    let points = vec![point(0, 0), point(12, 0), point(0, 12)];
    let polygon = fix
        .create(Win16GdiObjectOperation::CreatePolygonRgn {
            points: points.clone(),
            count: 3,
            fill_mode: ALTERNATE as i16,
        })
        .expect("polygon");
    assert!(inside(&mut fix, polygon, 1, 1));
    assert!(!inside(&mut fix, polygon, 11, 11));
    let winding = fix
        .create(Win16GdiObjectOperation::CreatePolygonRgn {
            points,
            count: 3,
            fill_mode: WINDING as i16,
        })
        .expect("winding polygon");
    assert!(inside(&mut fix, winding, 1, 1));
    assert!(
        fix.create(Win16GdiObjectOperation::CreatePolygonRgn {
            points: vec![point(0, 0)],
            count: 1,
            fill_mode: ALTERNATE as i16,
        })
        .is_none()
    );
    assert!(
        fix.create(Win16GdiObjectOperation::CreatePolygonRgn {
            points: vec![point(0, 0), point(4, 0), point(0, 4)],
            count: 3,
            fill_mode: 0,
        })
        .is_none()
    );
}

#[test]
fn combine_offset_and_compare_regions() {
    let mut fix = Fixture::new();
    let left = fix.create(rect_op(0, 0, 10, 10)).expect("left");
    let right = fix.create(rect_op(6, 4, 14, 12)).expect("right");
    let destination = fix.create(rect_op(1, 1, 2, 2)).expect("destination");
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::CombineRgn {
            destination,
            source1: left,
            source2: Some(right),
            mode: RGN_AND,
        })),
        SIMPLEREGION
    );
    assert_eq!(
        region_box(&mut fix, destination),
        (SIMPLEREGION, edges(6, 4, 10, 10))
    );

    let source = fix.create(rect_op(2, 3, 8, 9)).expect("source");
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::CombineRgn {
            destination,
            source1: source,
            source2: None,
            mode: RGN_COPY,
        })),
        SIMPLEREGION
    );
    assert!(flag(fix.draw(Win16DrawingOperation::EqualRgn {
        region1: destination,
        region2: source,
    })));
    assert!(!flag(fix.draw(Win16DrawingOperation::EqualRgn {
        region1: destination,
        region2: left,
    })));

    let before = region_box(&mut fix, destination);
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::CombineRgn {
            destination,
            source1: left,
            source2: Some(right),
            mode: 0,
        })),
        RGN_ERROR
    );
    assert_eq!(region_box(&mut fix, destination), before);

    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::OffsetRgn {
            region: source,
            x: -4,
            y: 5
        })),
        SIMPLEREGION
    );
    assert_eq!(
        region_box(&mut fix, source),
        (SIMPLEREGION, edges(-2, 8, 4, 14))
    );

    let pen = fix
        .create(Win16GdiObjectOperation::CreatePen {
            style: 0,
            width: 1,
            color: 0,
        })
        .expect("pen");
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::CombineRgn {
            destination,
            source1: left,
            source2: Some(pen),
            mode: RGN_AND,
        })),
        RGN_ERROR
    );
    assert_eq!(region_box(&mut fix, destination), before);
    assert!(!flag(fix.draw(Win16DrawingOperation::EqualRgn {
        region1: pen,
        region2: left,
    })));
}

#[test]
fn clip_queries_follow_the_selected_region() {
    let mut fix = Fixture::new();
    let dc = fix
        .dcs
        .create_compatible(None)
        .expect("display DC")
        .expect("memory DC");
    let bitmap = fix
        .create(Win16GdiObjectOperation::CreateCompatibleBitmap {
            dc,
            width: 40,
            height: 30,
        })
        .expect("surface");
    {
        let lease = fix.dcs.lease_dc(dc).expect("lease").expect("live DC");
        assert!(
            fix.objects
                .select(lease.native(), bitmap, None)
                .expect("select")
                .is_some()
        );
    }
    assert_eq!(
        boxed(fix.draw(Win16DrawingOperation::GetClipBox { dc })),
        (SIMPLEREGION, edges(0, 0, 40, 30))
    );

    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::IntersectClipRect {
            dc,
            rect: edges(8, 7, 22, 19),
        })),
        SIMPLEREGION
    );
    assert_eq!(
        boxed(fix.draw(Win16DrawingOperation::GetClipBox { dc })),
        (SIMPLEREGION, edges(8, 7, 22, 19))
    );
    assert!(flag(fix.draw(Win16DrawingOperation::PtVisible {
        dc,
        x: 8,
        y: 7
    })));
    assert!(flag(fix.draw(Win16DrawingOperation::PtVisible {
        dc,
        x: 21,
        y: 18
    })));
    assert!(!flag(fix.draw(Win16DrawingOperation::PtVisible {
        dc,
        x: 22,
        y: 7
    })));
    assert!(!flag(fix.draw(Win16DrawingOperation::PtVisible {
        dc,
        x: 8,
        y: 19
    })));
    assert!(flag(fix.draw(Win16DrawingOperation::RectVisible {
        dc,
        rect: edges(21, 18, 30, 30),
    })));
    assert!(!flag(fix.draw(Win16DrawingOperation::RectVisible {
        dc,
        rect: edges(22, 0, 30, 10),
    })));
    assert!(!flag(fix.draw(Win16DrawingOperation::RectVisible {
        dc,
        rect: edges(0, 0, 8, 7),
    })));

    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::OffsetClipRgn { dc, x: 3, y: -2 })),
        SIMPLEREGION
    );
    assert_eq!(
        boxed(fix.draw(Win16DrawingOperation::GetClipBox { dc })),
        (SIMPLEREGION, edges(11, 5, 25, 17))
    );

    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::SelectClipRgn { dc, region: None })),
        SIMPLEREGION
    );
    assert_eq!(
        boxed(fix.draw(Win16DrawingOperation::GetClipBox { dc })),
        (SIMPLEREGION, edges(0, 0, 40, 30))
    );
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::ExcludeClipRect {
            dc,
            rect: edges(10, 0, 20, 30),
        })),
        COMPLEXREGION
    );
    assert!(flag(fix.draw(Win16DrawingOperation::PtVisible {
        dc,
        x: 5,
        y: 15
    })));
    assert!(!flag(fix.draw(Win16DrawingOperation::PtVisible {
        dc,
        x: 15,
        y: 15
    })));
    assert!(flag(fix.draw(Win16DrawingOperation::PtVisible {
        dc,
        x: 25,
        y: 15
    })));
    assert_eq!(
        boxed(fix.draw(Win16DrawingOperation::GetClipBox { dc })),
        (COMPLEXREGION, edges(0, 0, 40, 30))
    );

    let clip = fix.create(rect_op(4, 5, 16, 18)).expect("clip");
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::SelectClipRgn {
            dc,
            region: Some(clip)
        })),
        SIMPLEREGION
    );
    assert_eq!(
        boxed(fix.draw(Win16DrawingOperation::GetClipBox { dc })),
        (SIMPLEREGION, edges(4, 5, 16, 18))
    );
    assert!(flag(fix.draw(Win16DrawingOperation::RectInRegion {
        region: clip,
        rect: edges(15, 17, 16, 18),
    })));
    assert!(!flag(fix.draw(Win16DrawingOperation::RectInRegion {
        region: clip,
        rect: edges(16, 5, 20, 10),
    })));

    let empty = fix.create(rect_op(4, 4, 4, 9)).expect("empty clip");
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::SelectClipRgn {
            dc,
            region: Some(empty)
        })),
        NULLREGION
    );
    let pen = fix
        .create(Win16GdiObjectOperation::CreatePen {
            style: 0,
            width: 1,
            color: 0,
        })
        .expect("pen");
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::SelectClipRgn {
            dc,
            region: Some(pen)
        })),
        RGN_ERROR
    );
    assert_eq!(
        boxed(fix.draw(Win16DrawingOperation::GetClipBox { dc })),
        (NULLREGION, edges(0, 0, 0, 0))
    );

    let missing = Win16HostDc(0x1111_2222_3333);
    assert_eq!(
        boxed(fix.draw(Win16DrawingOperation::GetClipBox { dc: missing })),
        (0, edges(0, 0, 0, 0))
    );
    assert!(!flag(fix.draw(Win16DrawingOperation::PtVisible {
        dc: missing,
        x: 0,
        y: 0
    })));
    assert!(!flag(fix.draw(Win16DrawingOperation::RectVisible {
        dc: missing,
        rect: edges(0, 0, 1, 1),
    })));
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::ExcludeClipRect {
            dc: missing,
            rect: edges(0, 0, 1, 1),
        })),
        0
    );
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::IntersectClipRect {
            dc: missing,
            rect: edges(0, 0, 1, 1),
        })),
        0
    );
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::OffsetClipRgn {
            dc: missing,
            x: 1,
            y: 1
        })),
        RGN_ERROR
    );
    assert_eq!(
        kind(fix.draw(Win16DrawingOperation::SelectClipRgn {
            dc: missing,
            region: None
        })),
        RGN_ERROR
    );
}

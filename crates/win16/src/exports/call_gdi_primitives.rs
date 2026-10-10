//! Stack decoders for GDI primitive, region, path, and state APIs.

use super::super::request::Win16ApiRequest;
use super::{Win16ExportId, dword_argument, gdi_calls, word_argument};
use crate::window_geometry::Rect16;
use crate::{Point16, SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

const MAX_POLYGON_POINT_ITEMS: usize = 65_535;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::GdiGetNearestColor => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetNearestColor {
                dc: word_argument(arguments, 0)?, color: dword_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiGetBkColor => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetBkColor {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetBkMode => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetBkMode {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetMapMode => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetMapMode {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetPolyFillMode => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetPolyFillMode {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetRop2 => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetRop2 {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetTextColor => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetTextColor {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetArcDirection => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetArcDirection {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetBrushOrg => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetBrushOrg {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetBrushOrgEx => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetBrushOrgEx {
                dc: word_argument(arguments, 0)?,
                output: dword_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiGetDcOrg => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetDcOrg {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiSetPolyFillMode => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetPolyFillMode {
                dc: word_argument(arguments, 0)?,
                mode: word_argument(arguments, 1)? as i16,
            })
        }
        Win16ExportId::GdiSetArcDirection => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetArcDirection {
                dc: word_argument(arguments, 0)?,
                direction: word_argument(arguments, 1)? as i16,
            })
        }
        Win16ExportId::GdiSetBrushOrg => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetBrushOrg {
                dc: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiArc | Win16ExportId::GdiPie | Win16ExportId::GdiChord => {
            let dc = word_argument(arguments, 0)?;
            let left = word_argument(arguments, 1)? as i16;
            let top = word_argument(arguments, 2)? as i16;
            let right = word_argument(arguments, 3)? as i16;
            let bottom = word_argument(arguments, 4)? as i16;
            let start_x = word_argument(arguments, 5)? as i16;
            let start_y = word_argument(arguments, 6)? as i16;
            let end_x = word_argument(arguments, 7)? as i16;
            let end_y = word_argument(arguments, 8)? as i16;
            match export {
                Win16ExportId::GdiArc => {
                    Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::Arc {
                        dc,
                        left,
                        top,
                        right,
                        bottom,
                        start_x,
                        start_y,
                        end_x,
                        end_y,
                    })
                }
                Win16ExportId::GdiPie => {
                    Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::Pie {
                        dc,
                        left,
                        top,
                        right,
                        bottom,
                        start_x,
                        start_y,
                        end_x,
                        end_y,
                    })
                }
                _ => Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::Chord {
                    dc,
                    left,
                    top,
                    right,
                    bottom,
                    start_x,
                    start_y,
                    end_x,
                    end_y,
                }),
            }
        }
        Win16ExportId::GdiEllipse => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::Ellipse {
                dc: word_argument(arguments, 0)?,
                rect: rect_from_words(arguments, 1)?,
            })
        }
        Win16ExportId::GdiRoundRect => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::RoundRect {
                dc: word_argument(arguments, 0)?,
                rect: rect_from_words(arguments, 1)?,
                ellipse_width: word_argument(arguments, 5)? as i16,
                ellipse_height: word_argument(arguments, 6)? as i16,
            })
        }
        Win16ExportId::GdiFloodFill | Win16ExportId::GdiExtFloodFill => {
            let dc = word_argument(arguments, 0)?;
            let x = word_argument(arguments, 1)? as i16;
            let y = word_argument(arguments, 2)? as i16;
            let color = dword_argument(arguments, 3)?;
            if export == Win16ExportId::GdiFloodFill {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::FloodFill {
                    dc,
                    x,
                    y,
                    color,
                })
            } else {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::ExtFloodFill {
                    dc,
                    x,
                    y,
                    color,
                    fill_type: word_argument(arguments, 4)?,
                })
            }
        }
        Win16ExportId::GdiOffsetClipRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::OffsetClipRgn {
                dc: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiPolygon => {
            let count = word_argument(arguments, 2)? as i16;
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::Polygon {
                dc: word_argument(arguments, 0)?,
                count,
                points: super::gdi_drawing_calls::read_points(
                    dword_argument(arguments, 1)?,
                    count,
                    selectors,
                    memory,
                )?,
            })
        }
        Win16ExportId::GdiFillRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::FillRgn {
                dc: word_argument(arguments, 0)?,
                region: word_argument(arguments, 1)?,
                brush: word_argument(arguments, 2)?,
            })
        }
        Win16ExportId::GdiFrameRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::FrameRgn {
                dc: word_argument(arguments, 0)?,
                region: word_argument(arguments, 1)?,
                brush: word_argument(arguments, 2)?,
                width: word_argument(arguments, 3)? as i16,
                height: word_argument(arguments, 4)? as i16,
            })
        }
        Win16ExportId::GdiInvertRgn | Win16ExportId::GdiPaintRgn => {
            let dc = word_argument(arguments, 0)?;
            let region = word_argument(arguments, 1)?;
            if export == Win16ExportId::GdiInvertRgn {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::InvertRgn { dc, region })
            } else {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::PaintRgn { dc, region })
            }
        }
        Win16ExportId::GdiSelectClipRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SelectClipRgn {
                dc: word_argument(arguments, 0)?,
                region: word_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiCombineRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::CombineRgn {
                destination: word_argument(arguments, 0)?,
                source1: word_argument(arguments, 1)?,
                source2: word_argument(arguments, 2)?,
                mode: word_argument(arguments, 3)? as i16,
            })
        }
        Win16ExportId::GdiEqualRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::EqualRgn {
                first: word_argument(arguments, 0)?,
                second: word_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiOffsetRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::OffsetRgn {
                region: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiPtVisible => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::PtVisible {
                dc: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiGetRgnBox => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetRgnBox {
                region: word_argument(arguments, 0)?,
                output: dword_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiPtInRegion => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::PtInRegion {
                region: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiSetRectRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetRectRgn {
                region: word_argument(arguments, 0)?,
                left: word_argument(arguments, 1)? as i16,
                top: word_argument(arguments, 2)? as i16,
                right: word_argument(arguments, 3)? as i16,
                bottom: word_argument(arguments, 4)? as i16,
            })
        }
        Win16ExportId::GdiGetClipRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetClipRgn {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiRectInRegion | Win16ExportId::GdiRectInRegionEhh => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::RectInRegion {
                region: word_argument(arguments, 0)?,
                rect: super::gdi_drawing_calls::read_optional_rect(
                    dword_argument(arguments, 1)?,
                    selectors,
                    memory,
                )?,
            })
        }
        Win16ExportId::GdiPolyBezier | Win16ExportId::GdiPolyBezierTo => {
            let count = word_argument(arguments, 2)? as i16;
            let valid = count > 0
                && if export == Win16ExportId::GdiPolyBezier {
                    count >= 4 && (count - 1) % 3 == 0
                } else {
                    count >= 3 && count % 3 == 0
                };
            let points = if valid {
                super::gdi_drawing_calls::read_points(
                    dword_argument(arguments, 1)?,
                    count,
                    selectors,
                    memory,
                )?
            } else {
                Vec::new()
            };
            if export == Win16ExportId::GdiPolyBezier {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::PolyBezier {
                    dc: word_argument(arguments, 0)?,
                    count,
                    points,
                    valid,
                })
            } else {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::PolyBezierTo {
                    dc: word_argument(arguments, 0)?,
                    count,
                    points,
                    valid,
                })
            }
        }
        Win16ExportId::GdiPolyPolygon => decode_poly_polygon(arguments, selectors, memory)?,
        Win16ExportId::GdiAbortPath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::AbortPath {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiBeginPath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::BeginPath {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiCloseFigure => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::CloseFigure {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiEndPath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::EndPath {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiFillPath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::FillPath {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiFlattenPath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::FlattenPath {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiPathToRegion => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::PathToRegion {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiStrokeAndFillPath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::StrokeAndFillPath {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiStrokePath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::StrokePath {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiWidenPath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::WidenPath {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetPath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetPath {
                dc: word_argument(arguments, 0)?,
                output_points: dword_argument(arguments, 1)?,
                output_types: dword_argument(arguments, 2)?,
                count: word_argument(arguments, 3)? as i16,
            })
        }
        Win16ExportId::GdiSelectClipPath => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SelectClipPath {
                dc: word_argument(arguments, 0)?,
                mode: word_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiExtSelectClipRgn => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::ExtSelectClipRgn {
                dc: word_argument(arguments, 0)?,
                region: word_argument(arguments, 1)?,
                mode: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiCreateEllipticRgn | Win16ExportId::GdiCreateRectRgn => {
            let left = word_argument(arguments, 0)? as i16;
            let top = word_argument(arguments, 1)? as i16;
            let right = word_argument(arguments, 2)? as i16;
            let bottom = word_argument(arguments, 3)? as i16;
            if export == Win16ExportId::GdiCreateEllipticRgn {
                Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateEllipticRgn {
                    left,
                    top,
                    right,
                    bottom,
                })
            } else {
                Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateRectRgn {
                    left,
                    top,
                    right,
                    bottom,
                })
            }
        }
        Win16ExportId::GdiCreateEllipticRgnIndirect | Win16ExportId::GdiCreateRectRgnIndirect => {
            let rect = super::gdi_drawing_calls::read_optional_rect(
                dword_argument(arguments, 0)?,
                selectors,
                memory,
            )?;
            if export == Win16ExportId::GdiCreateEllipticRgnIndirect {
                Win16ApiRequest::GdiObjects(
                    super::Win16GdiObjectsRequest::CreateEllipticRgnIndirect { rect },
                )
            } else {
                Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateRectRgnIndirect {
                    rect,
                })
            }
        }
        Win16ExportId::GdiCreatePolygonRgn => {
            let count = word_argument(arguments, 1)? as i16;
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreatePolygonRgn {
                points: super::gdi_drawing_calls::read_points(
                    dword_argument(arguments, 0)?,
                    count,
                    selectors,
                    memory,
                )?,
                count,
                fill_mode: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiCreateRoundRectRgn => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateRoundRectRgn {
                left: word_argument(arguments, 0)? as i16,
                top: word_argument(arguments, 1)? as i16,
                right: word_argument(arguments, 2)? as i16,
                bottom: word_argument(arguments, 3)? as i16,
                ellipse_width: word_argument(arguments, 4)? as i16,
                ellipse_height: word_argument(arguments, 5)? as i16,
            })
        }
        Win16ExportId::GdiCreatePolyPolygonRgn => {
            decode_create_poly_polygon_rgn(arguments, selectors, memory)?
        }
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

fn decode_poly_polygon(
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let polygon_count = word_argument(arguments, 3)?;
    let (point_counts, total, valid) = read_polygon_counts(
        dword_argument(arguments, 2)?,
        polygon_count,
        selectors,
        memory,
    )?;
    let points = if valid {
        read_points_exact(dword_argument(arguments, 1)?, total, selectors, memory)?
    } else {
        Vec::new()
    };
    Ok(Win16ApiRequest::GdiDrawing(
        super::Win16GdiDrawingRequest::PolyPolygon {
            dc: word_argument(arguments, 0)?,
            polygon_count,
            point_counts,
            points,
            valid,
        },
    ))
}

fn decode_create_poly_polygon_rgn(
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let polygon_count = word_argument(arguments, 2)? as i16;
    if polygon_count <= 0 {
        return Ok(Win16ApiRequest::GdiObjects(
            super::Win16GdiObjectsRequest::CreatePolyPolygonRgn {
                points: Vec::new(),
                polygon_counts: Vec::new(),
                polygon_count,
                fill_mode: word_argument(arguments, 3)? as i16,
                valid: false,
            },
        ));
    }
    let (polygon_counts, total, valid) = read_polygon_counts(
        dword_argument(arguments, 1)?,
        polygon_count as u16,
        selectors,
        memory,
    )?;
    let points = if valid {
        read_points_exact(dword_argument(arguments, 0)?, total, selectors, memory)?
    } else {
        Vec::new()
    };
    Ok(Win16ApiRequest::GdiObjects(
        super::Win16GdiObjectsRequest::CreatePolyPolygonRgn {
            points,
            polygon_counts,
            polygon_count,
            fill_mode: word_argument(arguments, 3)? as i16,
            valid,
        },
    ))
}

fn read_polygon_counts(
    far: u32,
    polygon_count: u16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<(Vec<i16>, usize, bool), Win16Error> {
    if polygon_count == 0 {
        return Ok((Vec::new(), 0, false));
    }
    let counts = super::gdi_drawing_calls::read_i16_values(
        far,
        usize::from(polygon_count),
        selectors,
        memory,
    )?;
    let mut total = 0usize;
    for count in &counts {
        if *count <= 0 {
            return Ok((Vec::new(), 0, false));
        }
        total = match total.checked_add(*count as usize) {
            Some(value) if value <= MAX_POLYGON_POINT_ITEMS => value,
            _ => return Ok((Vec::new(), 0, false)),
        };
    }
    Ok((counts, total, true))
}

fn read_points_exact(
    far: u32,
    count: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<Point16>, Win16Error> {
    let bytes = read_point_bytes(far, count, selectors, memory)?;
    let mut points = Vec::new();
    points
        .try_reserve_exact(count)
        .map_err(|_| Win16Error::OutOfMemory)?;
    for p in bytes.chunks_exact(4) {
        points.push(Point16 {
            x: i16::from_le_bytes([p[0], p[1]]),
            y: i16::from_le_bytes([p[2], p[3]]),
        });
    }
    Ok(points)
}

fn read_point_bytes(
    far: u32,
    count: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let length = count.checked_mul(4).ok_or(Win16Error::InvalidRange)?;
    gdi_calls::read_exact_bytes(far, length, selectors, memory)
}

fn rect_from_words(arguments: &[Win16Argument], start: usize) -> Result<Rect16, Win16Error> {
    Ok(Rect16 {
        left: word_argument(arguments, start)? as i16,
        top: word_argument(arguments, start + 1)? as i16,
        right: word_argument(arguments, start + 2)? as i16,
        bottom: word_argument(arguments, start + 3)? as i16,
    })
}

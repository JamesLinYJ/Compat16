//! Stack decoder for GDI drawing and coordinate-state APIs.

use super::super::request::Win16ApiRequest;
use super::{Win16ExportId, dword_argument, gdi_calls, word_argument};
use crate::gdi_abi::{ETO_PDY, ETO_RECT_FLAGS};
use crate::window_geometry::Rect16;
use crate::{Point16, SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request =
        match export {
            Win16ExportId::GdiSetStretchBltMode => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetStretchBltMode {
                    dc: word_argument(arguments, 0)?,
                    mode: word_argument(arguments, 1)? as i16,
                })
            }
            Win16ExportId::GdiGetStretchBltMode => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetStretchBltMode {
                    dc: word_argument(arguments, 0)?,
                })
            }
            Win16ExportId::GdiSetWindowExt => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetWindowExt {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                })
            }
            Win16ExportId::GdiSetWindowOrg => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetWindowOrg {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                })
            }
            Win16ExportId::GdiSetViewportOrg => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetViewportOrg {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                })
            }
            Win16ExportId::GdiSetViewportExt => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetViewportExt {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                })
            }
            Win16ExportId::GdiOffsetWindowOrg => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::OffsetWindowOrg {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                })
            }
            Win16ExportId::GdiOffsetViewportOrg => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::OffsetViewportOrg {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                })
            }
            Win16ExportId::GdiScaleWindowExt => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::ScaleWindowExt {
                    dc: word_argument(arguments, 0)?,
                    x_numerator: word_argument(arguments, 1)? as i16,
                    x_denominator: word_argument(arguments, 2)? as i16,
                    y_numerator: word_argument(arguments, 3)? as i16,
                    y_denominator: word_argument(arguments, 4)? as i16,
                })
            }
            Win16ExportId::GdiScaleViewportExt => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::ScaleViewportExt {
                    dc: word_argument(arguments, 0)?,
                    x_numerator: word_argument(arguments, 1)? as i16,
                    x_denominator: word_argument(arguments, 2)? as i16,
                    y_numerator: word_argument(arguments, 3)? as i16,
                    y_denominator: word_argument(arguments, 4)? as i16,
                })
            }
            Win16ExportId::GdiExcludeClipRect | Win16ExportId::GdiIntersectClipRect => {
                let dc = word_argument(arguments, 0)?;
                let left = word_argument(arguments, 1)? as i16;
                let top = word_argument(arguments, 2)? as i16;
                let right = word_argument(arguments, 3)? as i16;
                let bottom = word_argument(arguments, 4)? as i16;
                if export == Win16ExportId::GdiExcludeClipRect {
                    Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::ExcludeClipRect {
                        dc,
                        left,
                        top,
                        right,
                        bottom,
                    })
                } else {
                    Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::IntersectClipRect {
                        dc,
                        left,
                        top,
                        right,
                        bottom,
                    })
                }
            }
            Win16ExportId::GdiPatBlt => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::PatBlt {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                    width: word_argument(arguments, 3)? as i16,
                    height: word_argument(arguments, 4)? as i16,
                    rop: dword_argument(arguments, 5)?,
                })
            }
            Win16ExportId::GdiSaveDc => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SaveDC {
                    dc: word_argument(arguments, 0)?,
                })
            }
            Win16ExportId::GdiSetPixel => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetPixel {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                    color: dword_argument(arguments, 3)?,
                })
            }
            Win16ExportId::GdiStretchBlt => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::StretchBlt {
                    destination: word_argument(arguments, 0)?,
                    destination_x: word_argument(arguments, 1)? as i16,
                    destination_y: word_argument(arguments, 2)? as i16,
                    width: word_argument(arguments, 3)? as i16,
                    height: word_argument(arguments, 4)? as i16,
                    source: word_argument(arguments, 5)?,
                    source_x: word_argument(arguments, 6)? as i16,
                    source_y: word_argument(arguments, 7)? as i16,
                    source_width: word_argument(arguments, 8)? as i16,
                    source_height: word_argument(arguments, 9)? as i16,
                    rop: dword_argument(arguments, 10)?,
                })
            }
            Win16ExportId::GdiPolyline => {
                let count = word_argument(arguments, 2)? as i16;
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::Polyline {
                    dc: word_argument(arguments, 0)?,
                    count,
                    points: read_points(dword_argument(arguments, 1)?, count, selectors, memory)?,
                })
            }
            Win16ExportId::GdiRestoreDc => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::RestoreDC {
                    dc: word_argument(arguments, 0)?,
                    saved: word_argument(arguments, 1)? as i16,
                })
            }
            Win16ExportId::GdiDptoLp | Win16ExportId::GdiLptoDp => {
                let dc = word_argument(arguments, 0)?;
                let count = word_argument(arguments, 2)? as i16;
                let points = read_points(dword_argument(arguments, 1)?, count, selectors, memory)?;
                let output = dword_argument(arguments, 1)?;
                if export == Win16ExportId::GdiDptoLp {
                    Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::DPtoLP {
                        dc,
                        count,
                        points,
                        output,
                    })
                } else {
                    Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::LPtoDP {
                        dc,
                        count,
                        points,
                        output,
                    })
                }
            }
            Win16ExportId::GdiGetClipBox => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetClipBox {
                    dc: word_argument(arguments, 0)?,
                    output: dword_argument(arguments, 1)?,
                })
            }
            Win16ExportId::GdiGetPixel => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetPixel {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                })
            }
            Win16ExportId::GdiRectVisibleOld | Win16ExportId::GdiRectVisible => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::RectVisible {
                    dc: word_argument(arguments, 0)?,
                    rect: read_optional_rect(dword_argument(arguments, 1)?, selectors, memory)?,
                })
            }
            Win16ExportId::GdiGetTextCharacterExtra => {
                Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetTextCharacterExtra {
                    dc: word_argument(arguments, 0)?,
                })
            }
            Win16ExportId::GdiSetTextCharacterExtra => {
                Win16ApiRequest::GdiText(super::Win16GdiTextRequest::SetTextCharacterExtra {
                    dc: word_argument(arguments, 0)?,
                    extra: word_argument(arguments, 1)? as i16,
                })
            }
            Win16ExportId::GdiSetTextJustification => {
                Win16ApiRequest::GdiText(super::Win16GdiTextRequest::SetTextJustification {
                    dc: word_argument(arguments, 0)?,
                    extra: word_argument(arguments, 1)? as i16,
                    breaks: word_argument(arguments, 2)? as i16,
                })
            }
            Win16ExportId::GdiGetTextAlign => {
                Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetTextAlign {
                    dc: word_argument(arguments, 0)?,
                })
            }
            Win16ExportId::GdiSetTextAlign => {
                Win16ApiRequest::GdiText(super::Win16GdiTextRequest::SetTextAlign {
                    dc: word_argument(arguments, 0)?,
                    alignment: word_argument(arguments, 1)?,
                })
            }
            Win16ExportId::GdiExtTextOut => {
                let count = word_argument(arguments, 6)?;
                let options = word_argument(arguments, 3)?;
                let rect_far = dword_argument(arguments, 4)?;
                let spacing_far = dword_argument(arguments, 7)?;
                let rect = if options & ETO_RECT_FLAGS != 0 {
                    read_optional_rect(rect_far, selectors, memory)?
                } else {
                    None
                };
                let text = if count == 0 {
                    Vec::new()
                } else {
                    gdi_calls::read_exact_bytes(
                        dword_argument(arguments, 5)?,
                        usize::from(count),
                        selectors,
                        memory,
                    )?
                };
                let spacing = if count == 0 || spacing_far == 0 {
                    None
                } else {
                    let values_per_character = if options & ETO_PDY != 0 { 2 } else { 1 };
                    Some(read_i16_values(
                        spacing_far,
                        usize::from(count)
                            .checked_mul(values_per_character)
                            .ok_or(Win16Error::InvalidRange)?,
                        selectors,
                        memory,
                    )?)
                };
                Win16ApiRequest::GdiText(super::Win16GdiTextRequest::ExtTextOut {
                    dc: word_argument(arguments, 0)?,
                    x: word_argument(arguments, 1)? as i16,
                    y: word_argument(arguments, 2)? as i16,
                    options,
                    rect,
                    text,
                    count,
                    spacing,
                })
            }
            Win16ExportId::GdiGetCurrentPositionEx
            | Win16ExportId::GdiGetViewportOrgEx
            | Win16ExportId::GdiGetViewportExtEx
            | Win16ExportId::GdiGetWindowExtEx
            | Win16ExportId::GdiGetWindowOrgEx => {
                let dc = word_argument(arguments, 0)?;
                let output = dword_argument(arguments, 1)?;
                match export {
                    Win16ExportId::GdiGetCurrentPositionEx => Win16ApiRequest::GdiDrawing(
                        super::Win16GdiDrawingRequest::GetCurrentPositionEx { dc, output },
                    ),
                    Win16ExportId::GdiGetViewportOrgEx => Win16ApiRequest::GdiDrawing(
                        super::Win16GdiDrawingRequest::GetViewportOrgEx { dc, output },
                    ),
                    Win16ExportId::GdiGetViewportExtEx => Win16ApiRequest::GdiDrawing(
                        super::Win16GdiDrawingRequest::GetViewportExtEx { dc, output },
                    ),
                    Win16ExportId::GdiGetWindowExtEx => {
                        Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetWindowExtEx {
                            dc,
                            output,
                        })
                    }
                    _ => {
                        Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetWindowOrgEx {
                            dc,
                            output,
                        })
                    }
                }
            }
            Win16ExportId::GdiGetCurrentPosition => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetCurrentPosition {
                    dc: word_argument(arguments, 0)?,
                })
            }
            Win16ExportId::GdiGetViewportExt => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetViewportExt {
                    dc: word_argument(arguments, 0)?,
                })
            }
            Win16ExportId::GdiGetViewportOrg => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetViewportOrg {
                    dc: word_argument(arguments, 0)?,
                })
            }
            Win16ExportId::GdiGetWindowExt => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetWindowExt {
                    dc: word_argument(arguments, 0)?,
                })
            }
            Win16ExportId::GdiGetWindowOrg => {
                Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::GetWindowOrg {
                    dc: word_argument(arguments, 0)?,
                })
            }
            Win16ExportId::GdiSetViewportExtEx
            | Win16ExportId::GdiSetViewportOrgEx
            | Win16ExportId::GdiSetWindowExtEx
            | Win16ExportId::GdiSetWindowOrgEx
            | Win16ExportId::GdiMoveToEx => {
                let dc = word_argument(arguments, 0)?;
                let x = word_argument(arguments, 1)? as i16;
                let y = word_argument(arguments, 2)? as i16;
                let output = dword_argument(arguments, 3)?;
                match export {
                    Win16ExportId::GdiSetViewportExtEx => Win16ApiRequest::GdiDrawing(
                        super::Win16GdiDrawingRequest::SetViewportExtEx { dc, x, y, output },
                    ),
                    Win16ExportId::GdiSetViewportOrgEx => Win16ApiRequest::GdiDrawing(
                        super::Win16GdiDrawingRequest::SetViewportOrgEx { dc, x, y, output },
                    ),
                    Win16ExportId::GdiSetWindowExtEx => {
                        Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetWindowExtEx {
                            dc,
                            x,
                            y,
                            output,
                        })
                    }
                    Win16ExportId::GdiSetWindowOrgEx => {
                        Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetWindowOrgEx {
                            dc,
                            x,
                            y,
                            output,
                        })
                    }
                    _ => Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::MoveToEx {
                        dc,
                        x,
                        y,
                        output,
                    }),
                }
            }
            Win16ExportId::GdiOffsetViewportOrgEx | Win16ExportId::GdiOffsetWindowOrgEx => {
                let dc = word_argument(arguments, 0)?;
                let x = word_argument(arguments, 1)? as i16;
                let y = word_argument(arguments, 2)? as i16;
                let output = dword_argument(arguments, 3)?;
                if export == Win16ExportId::GdiOffsetViewportOrgEx {
                    Win16ApiRequest::GdiDrawing(
                        super::Win16GdiDrawingRequest::OffsetViewportOrgEx { dc, x, y, output },
                    )
                } else {
                    Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::OffsetWindowOrgEx {
                        dc,
                        x,
                        y,
                        output,
                    })
                }
            }
            Win16ExportId::GdiScaleViewportExtEx | Win16ExportId::GdiScaleWindowExtEx => {
                let dc = word_argument(arguments, 0)?;
                let x_numerator = word_argument(arguments, 1)? as i16;
                let x_denominator = word_argument(arguments, 2)? as i16;
                let y_numerator = word_argument(arguments, 3)? as i16;
                let y_denominator = word_argument(arguments, 4)? as i16;
                let output = dword_argument(arguments, 5)?;
                if export == Win16ExportId::GdiScaleViewportExtEx {
                    Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::ScaleViewportExtEx {
                        dc,
                        x_numerator,
                        x_denominator,
                        y_numerator,
                        y_denominator,
                        output,
                    })
                } else {
                    Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::ScaleWindowExtEx {
                        dc,
                        x_numerator,
                        x_denominator,
                        y_numerator,
                        y_denominator,
                        output,
                    })
                }
            }
            Win16ExportId::GdiGetTextExtentPoint => {
                let count = word_argument(arguments, 2)? as i16;
                let text = if count > 0 {
                    gdi_calls::read_exact_bytes(
                        dword_argument(arguments, 1)?,
                        usize::try_from(count).map_err(|_| Win16Error::InvalidRange)?,
                        selectors,
                        memory,
                    )?
                } else {
                    Vec::new()
                };
                Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetTextExtentPoint {
                    dc: word_argument(arguments, 0)?,
                    text,
                    count,
                    output: dword_argument(arguments, 3)?,
                })
            }
            _ => return Err(Win16Error::InvalidRange),
        };
    Ok(request)
}

pub(super) fn read_points(
    far: u32,
    count: i16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<Point16>, Win16Error> {
    if count <= 0 {
        return Ok(Vec::new());
    }
    let point_count = usize::try_from(count).map_err(|_| Win16Error::InvalidRange)?;
    let byte_count = point_count.checked_mul(4).ok_or(Win16Error::InvalidRange)?;
    let bytes = gdi_calls::read_exact_bytes(far, byte_count, selectors, memory)?;
    let mut points = Vec::new();
    points
        .try_reserve_exact(point_count)
        .map_err(|_| Win16Error::OutOfMemory)?;
    for pair in bytes.chunks_exact(4) {
        points.push(Point16 {
            x: i16::from_le_bytes([pair[0], pair[1]]),
            y: i16::from_le_bytes([pair[2], pair[3]]),
        });
    }
    Ok(points)
}

pub(super) fn read_i16_values(
    far: u32,
    count: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<i16>, Win16Error> {
    let byte_count = count.checked_mul(2).ok_or(Win16Error::InvalidRange)?;
    let bytes = gdi_calls::read_exact_bytes(far, byte_count, selectors, memory)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| Win16Error::OutOfMemory)?;
    for pair in bytes.chunks_exact(2) {
        values.push(i16::from_le_bytes([pair[0], pair[1]]));
    }
    Ok(values)
}

pub(super) fn read_optional_rect(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Rect16>, Win16Error> {
    if far == 0 {
        return Ok(None);
    }
    let bytes = gdi_calls::read_exact_bytes(far, Rect16::SIZE, selectors, memory)?;
    let bytes: [u8; Rect16::SIZE] = bytes.try_into().map_err(|_| Win16Error::InvalidRange)?;
    Ok(Some(Rect16::decode(&bytes)))
}

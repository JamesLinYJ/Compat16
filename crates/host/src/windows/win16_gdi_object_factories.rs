//! Native Win16 GDI factories for pens, fonts, brushes, bitmaps, and regions.
//!
//! Guest layouts are converted by runtime into pointer-free host requests.
//! Every successful native object is adopted by the existing `Win16Objects`
//! table so selection, deletion, and shutdown share one identity/owner map.

use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DrawingPoint, Win16DrawingRect,
    Win16GdiObjectOperation as Operation, Win16HostGdiObject,
};
use windows_sys::Win32::Foundation::{POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    BITMAP, BITMAPINFO, BITMAPINFOHEADER, BS_DIBPATTERN, BS_PATTERN, CreateBitmap,
    CreateBitmapIndirect, CreateBrushIndirect, CreateCompatibleBitmap, CreateDIBPatternBrushPt,
    CreateDIBitmap, CreateEllipticRgn, CreateEllipticRgnIndirect, CreateFontIndirectW, CreateFontW,
    CreatePen, CreatePenIndirect, CreatePolyPolygonRgn, CreatePolygonRgn, CreateRectRgn,
    CreateRectRgnIndirect, CreateRoundRectRgn, HGDIOBJ, LOGBRUSH, LOGFONTW, LOGPEN, LoadBitmapW,
};

use super::win16_gdi::Win16Dcs;
use super::win16_gdi::fonts::{create_face_name_wide, create_logfont_face_wide};
use super::win16_gdi_objects::Win16Objects;

/// Native-region factory inputs after the runtime has checked/copied every
/// Win16 pointer and widened the guest coordinates.
pub(super) enum Win16RegionCreate<'a> {
    Ellipse(Win16DrawingRect),
    EllipseIndirect(Option<Win16DrawingRect>),
    Polygon {
        points: &'a [Win16DrawingPoint],
        count: i16,
        fill_mode: i16,
    },
    Rectangle(Win16DrawingRect),
    RectangleIndirect(Option<Win16DrawingRect>),
    RoundRectangle {
        rect: Win16DrawingRect,
        ellipse_width: i16,
        ellipse_height: i16,
    },
    PolyPolygon {
        points: &'a [Win16DrawingPoint],
        polygon_counts: &'a [i16],
        polygon_count: i16,
        fill_mode: i16,
        valid: bool,
    },
}

/// Runs a native GDI factory and registers the owned HGDIOBJ in the common
/// host object table. Invalid guest values and native GDI failures remain a
/// normal `None` result; table exhaustion is a host resource error.
pub(super) fn create(
    objects: &mut Win16Objects,
    dcs: &Win16Dcs,
    operation: Operation,
) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
    match operation {
        Operation::LoadSystemBitmap { resource_id } => {
            let resource_id = super::win16_gdi_oem_bitmaps::native_resource_id(resource_id);
            // MAKEINTRESOURCE encodes a numeric resource, not a guest pointer.
            // LoadBitmap returns an owned object requiring DeleteObject:
            // https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-loadbitmapw
            // SAFETY: `LoadBitmapW` receives a host pointer formed in this function. The pointer is non-null when dereferenced, stays live for this synchronous call, and is not a guest address.
            let bitmap =
                unsafe { LoadBitmapW(ptr::null_mut(), usize::from(resource_id) as *const u16) };
            adopt(objects, bitmap.cast())
        }
        Operation::CreatePen {
            style,
            width,
            color,
        } => {
            // SAFETY: Arguments are scalars. GDI owns the returned pen after
            // the common object table adopts it.
            let pen = unsafe { CreatePen(i32::from(style), i32::from(width), color) };
            adopt(objects, pen.cast())
        }
        Operation::CreatePenIndirect { logpen } => {
            let native = LOGPEN {
                lopnStyle: u32::from(logpen.style),
                lopnWidth: windows_sys::Win32::Foundation::POINT {
                    x: i32::from(logpen.width_x),
                    y: i32::from(logpen.width_y),
                },
                lopnColor: logpen.color,
            };
            // SAFETY: `native` is a complete host LOGPEN and remains live for
            // the synchronous GDI call.
            let pen = unsafe { CreatePenIndirect(&native) };
            adopt(objects, pen.cast())
        }
        Operation::CreateFont {
            height,
            width,
            escapement,
            orientation,
            weight,
            italic,
            underline,
            strikeout,
            char_set,
            out_precision,
            clip_precision,
            quality,
            pitch_and_family,
            face_name,
        } => {
            let face_name = match face_name.as_deref() {
                Some(bytes) => match create_face_name_wide(dcs.text_codec(), bytes)? {
                    Some(face_name) => Some(face_name),
                    None => return Ok(None),
                },
                None => None,
            };
            let face_pointer = face_name
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr());
            // SAFETY: The optional UTF-16 string is retained through this
            // synchronous native call; all other arguments are scalar values.
            let font = unsafe {
                CreateFontW(
                    i32::from(height),
                    i32::from(width),
                    i32::from(escapement),
                    i32::from(orientation),
                    i32::from(weight),
                    u32::from(italic as u8),
                    u32::from(underline as u8),
                    u32::from(strikeout as u8),
                    u32::from(char_set as u8),
                    u32::from(out_precision as u8),
                    u32::from(clip_precision as u8),
                    u32::from(quality as u8),
                    u32::from(pitch_and_family as u8),
                    face_pointer,
                )
            };
            adopt(objects, font.cast())
        }
        Operation::CreateFontIndirect { logfont } => {
            let Some(face_name) = create_logfont_face_wide(dcs.text_codec(), &logfont.face_name)?
            else {
                return Ok(None);
            };
            let mut native = LOGFONTW::default();
            native.lfHeight = i32::from(logfont.height);
            native.lfWidth = i32::from(logfont.width);
            native.lfEscapement = i32::from(logfont.escapement);
            native.lfOrientation = i32::from(logfont.orientation);
            native.lfWeight = i32::from(logfont.weight);
            native.lfItalic = logfont.italic;
            native.lfUnderline = logfont.underline;
            native.lfStrikeOut = logfont.strikeout;
            native.lfCharSet = logfont.char_set;
            native.lfOutPrecision = logfont.out_precision;
            native.lfClipPrecision = logfont.clip_precision;
            native.lfQuality = logfont.quality;
            native.lfPitchAndFamily = logfont.pitch_and_family;
            native.lfFaceName = face_name;
            // SAFETY: `native` is a complete host LOGFONTW retained through
            // the synchronous native call.
            let font = unsafe { CreateFontIndirectW(&native) };
            adopt(objects, font.cast())
        }
        Operation::CreateBitmap {
            width,
            height,
            planes,
            bits_per_pixel,
            bits,
        } => {
            let bits_pointer = bits
                .as_ref()
                .map_or(ptr::null(), |bytes| bytes.as_ptr().cast());
            // SAFETY: Runtime owns and sized the optional pixel buffer for
            // the documented word-aligned bitmap input; GDI copies it during
            // this synchronous call.
            let bitmap = unsafe {
                CreateBitmap(
                    i32::from(width),
                    i32::from(height),
                    u32::from(planes),
                    u32::from(bits_per_pixel),
                    bits_pointer,
                )
            };
            adopt(objects, bitmap.cast())
        }
        Operation::CreateBitmapIndirect { bitmap, bits } => {
            let bits_pointer = bits
                .as_ref()
                .map_or(ptr::null_mut(), |bytes| bytes.as_ptr().cast_mut().cast());
            let native = BITMAP {
                bmType: i32::from(bitmap.kind),
                bmWidth: i32::from(bitmap.width),
                bmHeight: i32::from(bitmap.height),
                bmWidthBytes: i32::from(bitmap.width_bytes),
                bmPlanes: u16::from(bitmap.planes),
                bmBitsPixel: u16::from(bitmap.bits_per_pixel),
                bmBits: bits_pointer,
            };
            // SAFETY: `native` is a complete host BITMAP. Its optional bits
            // point into the owned copy retained until CreateBitmapIndirect
            // returns; no guest FAR address crosses the host boundary.
            let handle = unsafe { CreateBitmapIndirect(&native) };
            adopt(objects, handle.cast())
        }
        Operation::CreateBrushIndirect {
            logbrush,
            pattern_bitmap,
            dib_pattern,
        } => {
            let style = u32::from(logbrush.style);
            let hatch = if style == BS_PATTERN {
                let Some(token) = pattern_bitmap else {
                    return Ok(None);
                };
                let Some(bitmap) = objects.native_bitmap(token) else {
                    return Ok(None);
                };
                bitmap as usize
            } else if style == BS_DIBPATTERN {
                let Some(dib) = dib_pattern.as_ref() else {
                    return Ok(None);
                };
                let usage = u32::from(logbrush.color as u16);
                let Some(native_dib) = aligned_dib_words(&dib.info, &dib.bits)? else {
                    return Ok(None);
                };
                // SAFETY: Runtime validated the complete packed DIB. This
                // aligned owned buffer remains live for the synchronous
                // call, which copies the brush pattern before returning.
                let brush = unsafe { CreateDIBPatternBrushPt(native_dib.as_ptr().cast(), usage) };
                return adopt(objects, brush.cast());
            } else {
                logbrush.hatch as isize as usize
            };
            let native = LOGBRUSH {
                lbStyle: style,
                lbColor: logbrush.color,
                lbHatch: hatch,
            };
            // SAFETY: `native` has the host LOGBRUSH layout; any hatch bitmap
            // was resolved through the shared object table above.
            let brush = unsafe { CreateBrushIndirect(&native) };
            adopt(objects, brush.cast())
        }
        Operation::CreateCompatibleBitmap { dc, width, height } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(None);
            };
            // SAFETY: The HDC lease remains live through the native call;
            // GDI receives scalar dimensions and owns the returned bitmap.
            let bitmap = unsafe {
                CreateCompatibleBitmap(dc_use.native(), i32::from(width), i32::from(height))
            };
            drop(dc_use);
            adopt(objects, bitmap.cast())
        }
        Operation::CreateDibitmap {
            dc,
            header,
            init_flags,
            bits,
            info,
            color_usage,
        } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(None);
            };
            let header = aligned_optional_bytes(header.as_deref())?;
            let bits = aligned_optional_bytes(bits.as_deref())?;
            let info = aligned_optional_bytes(info.as_deref())?;
            let header_pointer = header.as_ref().map_or(ptr::null(), |bytes| {
                bytes.as_ptr().cast::<BITMAPINFOHEADER>()
            });
            let bits_pointer = bits
                .as_ref()
                .map_or(ptr::null(), |bytes| bytes.as_ptr().cast());
            let info_pointer = info
                .as_ref()
                .map_or(ptr::null(), |bytes| bytes.as_ptr().cast::<BITMAPINFO>());
            // SAFETY: The HDC lease remains live through the native call. Each
            // non-null pointer refers to an owned, DWORD-aligned snapshot;
            // nullness mirrors the original Win16 pointers.
            let bitmap = unsafe {
                CreateDIBitmap(
                    dc_use.native(),
                    header_pointer,
                    init_flags,
                    bits_pointer,
                    info_pointer,
                    color_usage,
                )
            };
            drop(dc_use);
            adopt(objects, bitmap.cast())
        }
        Operation::CreateEllipticRgn { rect } => {
            create_region(objects, Win16RegionCreate::Ellipse(rect))
        }
        Operation::CreateEllipticRgnIndirect { rect } => {
            create_region(objects, Win16RegionCreate::EllipseIndirect(rect))
        }
        Operation::CreatePolygonRgn {
            points,
            count,
            fill_mode,
        } => create_region(
            objects,
            Win16RegionCreate::Polygon {
                points: &points,
                count,
                fill_mode,
            },
        ),
        Operation::CreateRectRgn { rect } => {
            create_region(objects, Win16RegionCreate::Rectangle(rect))
        }
        Operation::CreateRectRgnIndirect { rect } => {
            create_region(objects, Win16RegionCreate::RectangleIndirect(rect))
        }
        Operation::CreateRoundRectRgn {
            rect,
            ellipse_width,
            ellipse_height,
        } => create_region(
            objects,
            Win16RegionCreate::RoundRectangle {
                rect,
                ellipse_width,
                ellipse_height,
            },
        ),
        Operation::CreatePolyPolygonRgn {
            points,
            polygon_counts,
            polygon_count,
            fill_mode,
            valid,
        } => create_region(
            objects,
            Win16RegionCreate::PolyPolygon {
                points: &points,
                polygon_counts: &polygon_counts,
                polygon_count,
                fill_mode,
                valid,
            },
        ),
    }
}

fn adopt(
    objects: &mut Win16Objects,
    native: HGDIOBJ,
) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
    objects.adopt_owned(native)
}

/// Executes one of the Win16 region constructors and transfers the native
/// region into the shared GDI object table.
pub(super) fn create_region(
    objects: &mut Win16Objects,
    shape: Win16RegionCreate<'_>,
) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
    let native = match shape {
        // SAFETY: `CreateEllipticRgn` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        Win16RegionCreate::Ellipse(rect) => unsafe {
            CreateEllipticRgn(rect.left, rect.top, rect.right, rect.bottom)
        },
        Win16RegionCreate::EllipseIndirect(rect) => {
            let Some(rect) = rect else {
                return Ok(None);
            };
            let native_rect = native_rect(rect);
            // SAFETY: `native_rect` is a complete host RECT retained through
            // the synchronous call.
            unsafe { CreateEllipticRgnIndirect(&native_rect) }
        }
        Win16RegionCreate::Polygon {
            points,
            count,
            fill_mode,
        } => {
            let Ok(expected_count) = usize::try_from(count) else {
                return Ok(None);
            };
            if points.len() != expected_count {
                return Ok(None);
            }
            let native_points = native_points(points)?;
            let sentinel = POINT { x: 0, y: 0 };
            let points_pointer: *const POINT = if native_points.is_empty() {
                &sentinel
            } else {
                native_points.as_ptr()
            };
            // SAFETY: `CreatePolygonRgn` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            unsafe { CreatePolygonRgn(points_pointer, i32::from(count), i32::from(fill_mode)) }
        }
        // SAFETY: CreateRectRgn takes integer bounds and returns a region this process must delete.
        Win16RegionCreate::Rectangle(rect) => unsafe {
            CreateRectRgn(rect.left, rect.top, rect.right, rect.bottom)
        },
        Win16RegionCreate::RectangleIndirect(rect) => {
            let Some(rect) = rect else {
                return Ok(None);
            };
            let native_rect = native_rect(rect);
            // SAFETY: `native_rect` is a complete host RECT retained through
            // the synchronous call.
            unsafe { CreateRectRgnIndirect(&native_rect) }
        }
        Win16RegionCreate::RoundRectangle {
            rect,
            ellipse_width,
            ellipse_height,
        } => unsafe {
            CreateRoundRectRgn(
                rect.left,
                rect.top,
                rect.right,
                rect.bottom,
                i32::from(ellipse_width),
                i32::from(ellipse_height),
            )
        },
        Win16RegionCreate::PolyPolygon {
            points,
            polygon_counts,
            polygon_count,
            fill_mode,
            valid,
        } => {
            if !valid {
                return Ok(None);
            }
            let Ok(expected_polygon_count) = usize::try_from(polygon_count) else {
                return Ok(None);
            };
            if polygon_counts.len() != expected_polygon_count {
                return Ok(None);
            }
            let Some(expected_points) = polygon_counts.iter().try_fold(0_usize, |total, count| {
                usize::try_from(*count)
                    .ok()
                    .and_then(|count| total.checked_add(count))
            }) else {
                return Ok(None);
            };
            if points.len() != expected_points {
                return Ok(None);
            }
            let native_points = native_points(points)?;
            let mut native_counts = Vec::new();
            native_counts
                .try_reserve_exact(polygon_counts.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "allocate native Win16 polygon-count array",
                        error,
                    )
                })?;
            native_counts.extend(polygon_counts.iter().copied().map(i32::from));
            let point_sentinel = POINT { x: 0, y: 0 };
            let count_sentinel = 0_i32;
            let points_pointer: *const POINT = if native_points.is_empty() {
                &point_sentinel
            } else {
                native_points.as_ptr()
            };
            let counts_pointer: *const i32 = if native_counts.is_empty() {
                &count_sentinel
            } else {
                native_counts.as_ptr()
            };
            // SAFETY: `CreatePolyPolygonRgn` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            unsafe {
                CreatePolyPolygonRgn(
                    points_pointer,
                    counts_pointer,
                    i32::from(polygon_count),
                    i32::from(fill_mode),
                )
            }
        }
    };
    adopt(objects, native.cast())
}

fn native_rect(rect: Win16DrawingRect) -> RECT {
    RECT {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn native_points(points: &[Win16DrawingPoint]) -> Result<Vec<POINT>, RuntimeError> {
    let mut result = Vec::new();
    result.try_reserve_exact(points.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate native Win16 region points",
            error,
        )
    })?;
    result.extend(points.iter().map(|point| POINT {
        x: point.x,
        y: point.y,
    }));
    Ok(result)
}

/// Gives native GDI a DWORD-aligned packed-DIB base address. `Vec<u32>` also
/// preserves byte order on Windows; the final partial word is zero-padded,
/// outside the parser-validated minimum DIB extent.
fn aligned_dib_words(info: &[u8], bits: &[u8]) -> Result<Option<Vec<u32>>, RuntimeError> {
    let byte_len = info.len().checked_add(bits.len()).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 packed DIB length overflowed",
        )
    })?;
    if byte_len == 0 {
        return Ok(None);
    }
    let padded_len = byte_len.checked_add(3).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 packed DIB aligned length overflowed",
        )
    })?;
    let word_count = padded_len / 4;
    let mut words = Vec::new();
    words.try_reserve_exact(word_count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate aligned native Win16 packed DIB",
            error,
        )
    })?;
    for start in (0..padded_len).step_by(4) {
        let mut word = [0_u8; 4];
        for (index, destination) in word.iter_mut().enumerate() {
            let offset = start + index;
            if offset < info.len() {
                *destination = info[offset];
            } else if offset < byte_len {
                *destination = bits[offset - info.len()];
            }
        }
        words.push(u32::from_ne_bytes(word));
    }
    Ok(Some(words))
}

/// Copies an optional guest DIB buffer to DWORD-aligned owned storage. Empty
/// but present buffers get a one-word sentinel to preserve non-nullness.
fn aligned_optional_bytes(bytes: Option<&[u8]>) -> Result<Option<Vec<u32>>, RuntimeError> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let padded_len = bytes.len().checked_add(3).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 DIB aligned length overflowed",
        )
    })?;
    let word_count = (padded_len / 4).max(1);
    let mut words = Vec::new();
    words.try_reserve_exact(word_count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate aligned native Win16 DIB buffer",
            error,
        )
    })?;
    for chunk in bytes.chunks(4) {
        let mut word = [0_u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        words.push(u32::from_ne_bytes(word));
    }
    if words.is_empty() {
        words.push(0);
    }
    Ok(Some(words))
}

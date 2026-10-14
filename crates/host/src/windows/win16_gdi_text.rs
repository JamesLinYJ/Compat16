//! Guest-ANSI text conversion for native Unicode GDI calls.

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DrawingRect, Win16DrawingResult, Win16HostDc,
};
use windows_sys::Win32::Foundation::{RECT, SIZE};
use windows_sys::Win32::Graphics::Gdi::{
    DT_MODIFYSTRING, DrawTextW, ETO_GLYPH_INDEX, ETO_PDY, ExtTextOutW, GetTextExtentPoint32W,
    GetTabbedTextExtentW, TabbedTextOutW, TextOutW,
};

use super::super::guest_text::{GuestTextBuffer, GuestTextSpan};
use super::super::win16_gdi::Win16Dcs;

/// Convert a counted guest byte string using the encoding captured by its DC
/// table. Conversion uses the selected Windows code page instead of the
/// process ACP, retaining Windows' legacy replacement behavior.
fn guest_text(dcs: &Win16Dcs, bytes: &[u8]) -> Result<GuestTextBuffer, RuntimeError> {
    let codec = dcs.text_codec();
    let mut wide = GuestTextBuffer::acquire();
    codec
        .to_wide_into(bytes, &mut wide)
        .map_err(|error| error.with_context("decode Win16 GDI guest text"))?;
    Ok(wide)
}

fn text_pointer(wide: &[u16], empty: &[u16; 1]) -> *const u16 {
    if wide.is_empty() {
        empty.as_ptr()
    } else {
        wide.as_ptr()
    }
}

pub(super) fn text_out(
    dcs: &Win16Dcs,
    dc: Win16HostDc,
    x: i32,
    y: i32,
    bytes: &[u8],
) -> Result<bool, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(false);
    };
    let wide = guest_text(dcs, bytes)?;
    let Ok(count) = i32::try_from(wide.len()) else {
        return Ok(false);
    };
    let empty = [0_u16; 1];
    let pointer = text_pointer(&wide, &empty);
    // SAFETY: The HDC lease and owned UTF-16 text remain live until TextOutW returns.
    Ok(unsafe { TextOutW(dc_use.native(), x, y, pointer, count) } != 0)
}

pub(super) fn text_extent(
    dcs: &Win16Dcs,
    dc: Win16HostDc,
    bytes: &[u8],
) -> Result<Option<(bool, SIZE)>, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(None);
    };
    let wide = guest_text(dcs, bytes)?;
    let Ok(count) = i32::try_from(wide.len()) else {
        return Ok(Some((false, SIZE { cx: 0, cy: 0 })));
    };
    let empty = [0_u16; 1];
    let pointer = text_pointer(&wide, &empty);
    let mut size = SIZE { cx: 0, cy: 0 };
    // SAFETY: The HDC lease, owned text, and writable SIZE remain live through the call.
    let success = unsafe { GetTextExtentPoint32W(dc_use.native(), pointer, count, &mut size) } != 0;
    Ok(Some((success, size)))
}

pub(super) fn tabbed_text(
    dcs: &Win16Dcs,
    dc: Win16HostDc,
    bytes: &[u8],
    tab_stops: &[i32],
    output: Option<(i32, i32, i32)>,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::PackedTextExtent(0));
    };
    // Win16 counts guest bytes; the W APIs count UTF-16 units. Tabs remain
    // logical positions and must not be scaled by the text's byte length.
    let wide = guest_text(dcs, bytes)?;
    let (Ok(count), Ok(tab_count)) = (i32::try_from(wide.len()), i32::try_from(tab_stops.len())) else {
        return Ok(Win16DrawingResult::PackedTextExtent(0));
    };
    let empty = [0_u16; 1];
    let pointer = text_pointer(&wide, &empty);
    let stops = if tab_stops.is_empty() { std::ptr::null() } else { tab_stops.as_ptr() };
    // SAFETY: The HDC lease, owned converted text and widened tab array stay
    // live for this synchronous call. No guest address reaches native USER.
    let extent = unsafe {
        match output {
            Some((x, y, origin)) => TabbedTextOutW(
                dc_use.native(), x, y, pointer, count, tab_count, stops, origin,
            ) as u32,
            None => GetTabbedTextExtentW(dc_use.native(), pointer, count, tab_count, stops),
        }
    };
    // LONG and DWORD expose identical packed width/height bits in Win16.
    Ok(Win16DrawingResult::PackedTextExtent(extent))
}

pub(super) fn ext_text_out(
    dcs: &Win16Dcs,
    dc: Win16HostDc,
    x: i32,
    y: i32,
    options: u32,
    rect: Option<Win16DrawingRect>,
    bytes: &[u8],
    spacing: Option<&[i32]>,
) -> Result<bool, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(false);
    };

    // Win16's counted text is a byte string, while ETO_GLYPH_INDEX expects a
    // native array of WORD glyph IDs. Decoding those bytes into text would
    // fabricate glyph identifiers, so the caller reports a recoverable false.
    if options & ETO_GLYPH_INDEX != 0 {
        return Ok(false);
    }

    let mut wide = GuestTextBuffer::acquire();
    let native_spacing = match spacing {
        Some(values) => {
            let codec = dcs.text_codec();
            let spans = match codec.to_wide_with_ranges_into(bytes, &mut wide) {
                Ok(converted) => converted,
                // The runtime host reports a mapping gap and returns ordinary
                // failure; propagate the typed cause without converting twice.
                Err(error) => return Err(error.with_context("map Win16 ExtTextOut spacing text")),
            };
            let Some(converted) =
                convert_spacing(&spans, bytes, &wide, values, options & ETO_PDY != 0)?
            else {
                return Ok(false);
            };
            Some(converted)
        }
        None => {
            dcs.text_codec().to_wide_into(bytes, &mut wide)
                .map_err(|error| error.with_context("decode Win16 GDI guest text"))?;
            None
        }
    };
    let Ok(count) = u32::try_from(wide.len()) else {
        return Ok(false);
    };
    let native_rect = rect.map(|r| RECT {
        left: r.left,
        top: r.top,
        right: r.right,
        bottom: r.bottom,
    });
    let rect_pointer = native_rect
        .as_ref()
        .map_or(std::ptr::null(), |rect| rect as *const RECT);
    let empty = [0_u16; 1];
    let pointer = text_pointer(&wide, &empty);
    let spacing_pointer = native_spacing
        .as_ref()
        .filter(|values| !values.is_empty())
        .map_or(std::ptr::null(), |values| values.as_ptr());
    // SAFETY: The HDC lease, UTF-16 string, optional copied RECT, and remapped
    // spacing array are owned and remain live for the synchronous GDI call.
    Ok(unsafe {
        ExtTextOutW(
            dc_use.native(),
            x,
            y,
            options,
            rect_pointer,
            pointer,
            count,
            spacing_pointer,
        ) != 0
    })
}

/// Convert guest byte displacements to one displacement per UTF-16 code unit.
/// `GuestTextCodec` supplies exact guest-byte/UTF-16 ranges, which Windows' W
/// APIs no longer retain. This combines source-byte advances for a DBCS
/// character and keeps one total advance across any surrogate pair.
fn convert_spacing(
    spans: &[GuestTextSpan],
    bytes: &[u8],
    wide: &[u16],
    guest_spacing: &[i32],
    pdy: bool,
) -> Result<Option<Vec<i32>>, RuntimeError> {
    let values_per_byte = if pdy { 2 } else { 1 };
    let Some(expected) = bytes.len().checked_mul(values_per_byte) else {
        return Ok(None);
    };
    if guest_spacing.len() != expected {
        return Ok(None);
    }
    let values_per_wide_unit = if pdy { 2 } else { 1 };
    let Some(output_len) = wide.len().checked_mul(values_per_wide_unit) else {
        return Ok(None);
    };
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 ExtTextOut spacing",
            error,
        )
    })?;

    let mut wide_offset = 0_usize;
    let mut byte_offset = 0_usize;
    for span in spans {
        let byte_range = span.guest_bytes.clone();
        let unit_range = span.utf16_units.clone();
        if byte_range.start != byte_offset
            || unit_range.start != wide_offset
            || byte_range.end > bytes.len()
            || unit_range.end > wide.len()
            || byte_range.start >= byte_range.end
            || unit_range.start >= unit_range.end
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 guest text codec returned noncontiguous GDI character spans",
            ));
        }

        let mut x_advance = 0_i32;
        let mut y_advance = 0_i32;
        for byte_index in byte_range.clone() {
            let Some(base) = byte_index.checked_mul(values_per_byte) else {
                return Ok(None);
            };
            x_advance = x_advance.checked_add(guest_spacing[base]).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "Win16 ExtTextOut x displacement overflow",
                )
            })?;
            if pdy {
                y_advance = y_advance
                    .checked_add(guest_spacing[base + 1])
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InvalidInput,
                            "Win16 ExtTextOut y displacement overflow",
                        )
                    })?;
            }
        }

        for unit_index in 0..unit_range.len() {
            if pdy {
                output.push(if unit_index == 0 { x_advance } else { 0 });
                output.push(if unit_index == 0 { y_advance } else { 0 });
            } else {
                output.push(if unit_index == 0 { x_advance } else { 0 });
            }
        }
        byte_offset = byte_range.end;
        wide_offset = unit_range.end;
    }

    if byte_offset != bytes.len() || wide_offset != wide.len() || output.len() != output_len {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 ExtTextOut spacing does not cover converted text",
        ));
    }
    Ok(Some(output))
}

pub(super) fn draw_text(
    dcs: &Win16Dcs,
    dc: Win16HostDc,
    bytes: Vec<u8>,
    count: i32,
    rect: Option<Win16DrawingRect>,
    flags: u32,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::DrawText { height: 0, rect });
    };
    let Some(mut native_rect) = rect.map(native_rect) else {
        return Ok(Win16DrawingResult::DrawText {
            height: 0,
            rect: None,
        });
    };
    if count < -1 || (count >= 0 && bytes.len() != count as usize) {
        return Ok(Win16DrawingResult::DrawText { height: 0, rect });
    }
    // DT_MODIFYSTRING is a Win32 extension absent from the Win16 UINT format
    // word and from the host result/copy-back contract. Do not let native GDI
    // rewrite text whose guest-byte storage budget cannot be represented here.
    if flags & DT_MODIFYSTRING != 0 {
        return Ok(Win16DrawingResult::DrawText { height: 0, rect });
    }

    let mut wide = GuestTextBuffer::acquire();
    let native_count = if count == -1 {
        dcs.text_codec().to_wide_z_into(&bytes, &mut wide)
            .map_err(|error| error.with_context("decode Win16 GDI guest text"))?;
        -1
    } else {
        dcs.text_codec().to_wide_into(&bytes, &mut wide)
            .map_err(|error| error.with_context("decode Win16 GDI guest text"))?;
        let Ok(count) = i32::try_from(wide.len()) else {
            return Ok(Win16DrawingResult::DrawText { height: 0, rect });
        };
        count
    };
    let empty = [0_u16; 1];
    let pointer = text_pointer(&wide, &empty);
    // SAFETY: The HDC lease, owned UTF-16 buffer, and copied RECT remain live
    // through the synchronous DrawTextW call; counts retain guest semantics.
    let height = unsafe {
        DrawTextW(
            dc_use.native(),
            pointer,
            native_count,
            &mut native_rect,
            flags,
        )
    };
    Ok(Win16DrawingResult::DrawText {
        height,
        rect: Some(host_rect(native_rect)),
    })
}

fn native_rect(rect: Win16DrawingRect) -> RECT {
    RECT {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn host_rect(rect: RECT) -> Win16DrawingRect {
    Win16DrawingRect {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

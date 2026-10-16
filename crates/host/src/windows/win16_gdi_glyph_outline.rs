//! Selected-font glyph queries using owned buffers and Unicode GDI calls.

use super::super::win16_gdi::Win16Dcs;
use super::allocate_zeroed_bytes;
use runtime::{
    DiagnosticKind, RuntimeError, Win16GdiServicesResult as ResultValue, Win16HostDc,
    Win16HostGlyphMetrics,
};
use windows_sys::Win32::Globalization::{
    CHARSETINFO, CP_SYMBOL, GetTextCharsetInfo, IsDBCSLeadByteEx, MB_ERR_INVALID_CHARS,
    MultiByteToWideChar, TCI_SRCCHARSET, TranslateCharsetInfo,
};
use windows_sys::Win32::Graphics::Gdi::{
    DEFAULT_CHARSET, FIXED, GDI_ERROR, GLYPHMETRICS, GetGlyphOutlineW, HDC, MAT2,
};

pub(super) fn execute(
    dcs: &Win16Dcs,
    dc: Win16HostDc,
    character: u16,
    format: u16,
    matrix: [u32; 4],
    byte_count: u32,
    copy_buffer: bool,
) -> Result<ResultValue, RuntimeError> {
    let failure = || ResultValue::GlyphOutline {
        result: GDI_ERROR as u32,
        metrics: None,
        bytes: Vec::new(),
    };
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(failure());
    };
    let character = if format & 0x0080 != 0 {
        character // GGO_GLYPH_INDEX is an index, never an encoded character.
    } else {
        let Some(character) =
            glyph_character(dc_use.native(), dcs.text_codec().code_page(), character)
        else {
            return Ok(failure());
        };
        character
    };
    let fixed = |bits: u32| FIXED {
        fract: bits as u16,
        value: (bits >> 16) as i16,
    };
    let matrix = MAT2 {
        eM11: fixed(matrix[0]),
        eM12: fixed(matrix[1]),
        eM21: fixed(matrix[2]),
        eM22: fixed(matrix[3]),
    };
    let copy_buffer = copy_buffer && byte_count != 0 && format & !0x0180 != 0;
    let mut metrics = GLYPHMETRICS::default();
    // SAFETY: The HDC lease, aligned matrix and writable metrics remain live.
    // Query actual output size before allocating: a large caller capacity must
    // neither impose an arbitrary 64 KiB limit nor force that much allocation.
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getglyphoutlinew
    let needed = unsafe {
        GetGlyphOutlineW(
            dc_use.native(),
            u32::from(character),
            u32::from(format),
            &mut metrics,
            0,
            std::ptr::null_mut(),
            &matrix,
        )
    };
    if needed == GDI_ERROR as u32 || (copy_buffer && needed > byte_count) {
        return Ok(failure());
    }
    let (result, bytes) = if copy_buffer && needed != 0 {
        let Some(mut bytes) = allocate_zeroed_bytes(needed as usize) else {
            return Ok(failure());
        };
        // SAFETY: The owned allocation covers exactly the size passed to GDI.
        // The same HDC lease and bit-exact matrix cover both calls.
        let result = unsafe {
            GetGlyphOutlineW(
                dc_use.native(),
                u32::from(character),
                u32::from(format),
                &mut metrics,
                needed,
                bytes.as_mut_ptr().cast(),
                &matrix,
            )
        };
        if result == GDI_ERROR as u32 {
            return Ok(failure());
        }
        if result as usize > bytes.len() {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "GetGlyphOutlineW returned more bytes than its supplied buffer",
            ));
        }
        bytes.truncate(result as usize);
        (result, bytes)
    } else {
        (needed, Vec::new())
    };
    // BITMAP rows and TTPOLYGONHEADER/TTPOLYCURVE/POINTFX records have the
    // same fixed-width, pointer-free little-endian format in SDK 3.1 and Win32.
    // Return their bytes unchanged; only GLYPHMETRICS needs Win16 narrowing.
    Ok(ResultValue::GlyphOutline {
        result,
        metrics: Some(Win16HostGlyphMetrics {
            black_box_x: metrics.gmBlackBoxX,
            black_box_y: metrics.gmBlackBoxY,
            origin_x: metrics.gmptGlyphOrigin.x,
            origin_y: metrics.gmptGlyphOrigin.y,
            cell_inc_x: metrics.gmCellIncX,
            cell_inc_y: metrics.gmCellIncY,
        }),
        bytes,
    })
}

fn glyph_character(dc: HDC, guest_code_page: u32, code: u16) -> Option<u16> {
    // Numeric DBCS codes use lead << 8 | trail. Select the realized font's
    // character set as GDI's ANSI interface does; unresolved/default charsets
    // use the explicit guest page instead of the host process/thread ACP.
    // SAFETY: The caller holds the HDC lease; the signature output is optional.
    let charset = unsafe { GetTextCharsetInfo(dc, std::ptr::null_mut(), 0) };
    let mut info = CHARSETINFO::default();
    let code_page = if (0..=255).contains(&charset)
        && charset != i32::from(DEFAULT_CHARSET)
        // TCI_SRCCHARSET takes a numeric charset in lpSrc, not an address.
        // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-translatecharsetinfo
        && unsafe {
            TranslateCharsetInfo(charset as usize as *mut u32, &mut info, TCI_SRCCHARSET)
        } != 0
        && info.ciACP > 3
    // Exclude symbolic ACP/OEM/Mac/thread page selectors.
    {
        info.ciACP
    } else {
        guest_code_page
    };
    let encoded = code.to_be_bytes();
    let bytes = if unsafe { IsDBCSLeadByteEx(code_page, encoded[0]) } != 0 {
        &encoded[..]
    } else {
        &encoded[1..]
    };
    let mut wide = [0_u16; 2];
    // CP_SYMBOL requires zero flags. Other legacy pages reject malformed
    // numeric input rather than manufacturing a replacement glyph.
    let flags = if code_page == CP_SYMBOL {
        0
    } else {
        MB_ERR_INVALID_CHARS
    };
    // SAFETY: Fixed arrays hold the complete one/two-byte code and both
    // possible UTF-16 units; neither conversion retains their pointers.
    let count = unsafe {
        MultiByteToWideChar(
            code_page,
            flags,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            wide.len() as i32,
        )
    };
    (count == 1).then_some(wide[0])
}

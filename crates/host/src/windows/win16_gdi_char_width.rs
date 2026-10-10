//! GetCharWidth's selected-font query, with explicit guest character decoding.

use runtime::{RuntimeError, Win16GdiServicesResult as ResultValue, Win16HostDc};
use windows_sys::Win32::Graphics::Gdi::GetCharWidthW;
use windows_sys::Win32::Globalization::{
    IsDBCSLeadByteEx, MB_ERR_INVALID_CHARS, MultiByteToWideChar,
};

use super::super::{guest_text::GuestTextCodec, win16_gdi::Win16Dcs};
use super::allocate_defaulted;

pub(super) fn execute(
    dcs: &Win16Dcs,
    dc: Win16HostDc,
    first: u16,
    last: u16,
) -> Result<ResultValue, RuntimeError> {
    let failure = || ResultValue::CharWidths { success: false, entries: Vec::new() };
    // A Win16 int FAR* can contain at most 32768 results. Check independently
    // at the host boundary, before either conversion or output allocation.
    if first > last || usize::from(last - first) + 1 > 0x8000 {
        return Ok(failure());
    }
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(failure());
    };
    let Some(characters) = guest_character_range(dcs.text_codec(), first, last) else {
        return Ok(failure());
    };
    let Some(mut widths) = allocate_defaulted::<i32>(characters.len()) else {
        return Ok(failure());
    };
    // Microsoft SDK 3.0, Reference Volume 1, GetCharWidth: current font,
    // inclusive character range, logical widths, default-character fallback.
    // https://www.pcjs.org/documents/books/mspl13/win/w3sdkr1/
    // Microsoft explicitly retains GetCharWidthW for 16-bit compatibility:
    // https://learn.microsoft.com/windows/win32/api/wingdi/nf-wingdi-getcharwidthw
    // Do not substitute GetCharWidth32W or an ABC sum. Leave font selection,
    // mapping-mode metrics and missing-glyph fallback with this pinned HDC.
    // The current docs and historical Microsoft KB Q94646 disagree about
    // TrueType support; forward the actual native result without a type gate.
    let success = query_runs(&characters, &mut widths, |first, last, output| {
        // SAFETY: The lease pins the native HDC throughout all runs. Each
        // run maps to exactly output.len() consecutive UTF-16 code units;
        // the writable host slice has one native INT for every code unit.
        unsafe { GetCharWidthW(dc_use.native(), u32::from(first), u32::from(last), output.as_mut_ptr()) != 0 }
    });
    Ok(if success {
        ResultValue::CharWidths { success: true, entries: widths }
    } else {
        failure()
    })
}

fn guest_character_range(codec: GuestTextCodec, first: u16, last: u16) -> Option<Vec<u16>> {
    let count = usize::from(last.checked_sub(first)?) + 1;
    if count > 0x8000 {
        return None;
    }
    let mut wide = Vec::new();
    wide.try_reserve_exact(count).ok()?;
    for code in first..=last {
        let encoded = code.to_be_bytes();
        let bytes = if code <= u16::from(u8::MAX) { &encoded[1..] } else { &encoded[..] };
        // Microsoft KB244046 specifies numeric DBCS character codes as
        // (lead << 8) | trail for GetCharWidth and related Win32 APIs:
        // https://ftp.zx.net.nz/pub/archive/ftp.microsoft.com/MISC/KB/en-us/244/046.HTM
        // This explicit boundary convention is not a claim that every
        // localized Win16 implementation used the same packing. A historical
        // DBCS workload remains needed to establish that compatibility.
        // Never reinterpret the guest word as UTF-16 or use the host ACP.
        // Numeric codes must describe one complete guest character. The
        // general text codec permits Windows replacement decoding on legacy
        // pages; that must not turn a malformed numeric code into a glyph.
        // IsDBCSLeadByteEx is false for SBCS bytes such as CP1252's 0x81.
        // SAFETY: The codec owns a validated numeric code page, and the
        // native queries only read this local one- or two-byte input.
        let is_lead = unsafe { IsDBCSLeadByteEx(codec.code_page(), bytes[0]) != 0 };
        if is_lead != (bytes.len() == 2) {
            return None;
        }
        let mut character = [0_u16; 2];
        // SAFETY: The fixed native output covers both possible UTF-16 units.
        // Reject invalid encodings and unsupported strict-conversion pages;
        // do not infer a default-glyph contract for malformed guest codes.
        let converted = unsafe {
            MultiByteToWideChar(codec.code_page(), MB_ERR_INVALID_CHARS,
                bytes.as_ptr(), bytes.len() as i32, character.as_mut_ptr(), 2)
        };
        if converted != 1 {
            return None;
        }
        wide.push(character[0]);
    }
    Some(wide)
}

fn query_runs(
    characters: &[u16],
    output: &mut [i32],
    mut query: impl FnMut(u16, u16, &mut [i32]) -> bool,
) -> bool {
    if characters.is_empty() || characters.len() != output.len() {
        return false;
    }
    let mut start = 0;
    while start < characters.len() {
        let mut end = start;
        // Consecutive guest codes need not be consecutive Unicode codes.
        // Group only proven adjacent mappings, preserving guest output order.
        while end + 1 < characters.len()
            && characters[end].checked_add(1) == Some(characters[end + 1])
        {
            end += 1;
        }
        if !query(characters[start], characters[end], &mut output[start..=end]) {
            return false;
        }
        start = end + 1;
    }
    true
}

#[cfg(test)]
#[path = "win16_gdi_char_width_tests.rs"]
mod tests;

//! Win16 StretchDIBits translation over checked, owned DIB input.

use guest_core::memory::Memory;

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16DrawingOperation as Operation, Win16DrawingResult as HostResult,
    Win16HostDib,
};

pub(super) fn stretch_dibits(
    state: &Win16State,
    memory: &Memory,
    host: &mut impl RuntimeHost,
    guest_dc: u16,
    destination_x: i16,
    destination_y: i16,
    destination_width: i16,
    destination_height: i16,
    source_x: i16,
    source_y: i16,
    source_width: i16,
    source_height: i16,
    info_far: u32,
    bits_far: u32,
    usage: u16,
    rop: u32,
) -> Result<u32, RuntimeError> {
    // An unknown DC, a missing DIB, or an unusable color table is an ordinary
    // failure. GDI_ERROR (-1) is only the native result when a driver cannot
    // handle a JPEG or PNG image, and guest_stretch_lines keeps that pattern.
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-stretchdibits
    let Some(dc) = state.guest_gdi.dc(guest_dc) else {
        return Ok(0);
    };
    let Some(info) = state.copy_dib_info(memory, info_far, usage)? else {
        return Ok(0);
    };
    let Some(bits) = state.copy_dib_bits(memory, bits_far, info.layout.bits_bytes)? else {
        return Ok(0);
    };
    let dib = Win16HostDib { info: info.bytes, bits };

    match host.win16_gdi(Operation::StretchDibits {
        dc,
        destination_x: i32::from(destination_x),
        destination_y: i32::from(destination_y),
        destination_width: i32::from(destination_width),
        destination_height: i32::from(destination_height),
        source_x: i32::from(source_x),
        source_y: i32::from(source_y),
        source_width: i32::from(source_width),
        source_height: i32::from(source_height),
        dib,
        usage: u32::from(usage),
        rop,
    })? {
        HostResult::Dibits(lines) => Ok(guest_stretch_lines(lines)),
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 host drawing returned the wrong result for StretchDIBits",
        )),
    }
}

/// Win16 `StretchDIBits` returns a signed int. Mirrored copies and
/// `GDI_ERROR` (-1) fit in that int and keep their bit pattern. A host count
/// outside the int, such as 32768 scan lines, is failure (0).
/// <https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-stretchdibits>
fn guest_stretch_lines(lines: i32) -> u32 {
    match i16::try_from(lines) {
        Ok(lines) => u32::from(lines as u16),
        Err(_) => 0,
    }
}

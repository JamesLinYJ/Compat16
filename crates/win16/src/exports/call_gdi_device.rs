//! Standalone decoder for the GDI bitmap/DIB/palette and print-device services.
//!
//! The common export catalog and call dispatcher own registration. This
//! decoder accepts a catalog module/ordinal and checked scalar slots, so it
//! does not duplicate export identities or guess unknown stack layouts.

use guest_core::GuestMemory;

use crate::{SelectorTable, Win16Argument, Win16Error};
use super::super::request::gdi_device::{
    DibColorTableKind, DibRgbQuad16, DocInfo16, GdiDeviceRequest as Request, PaletteEntry16,
    PaletteTransferKind, PrintOperation,
};

pub fn decode(
    module: &[u8],
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    if module.eq_ignore_ascii_case(b"GDI") {
        return decode_gdi(ordinal, arguments, selectors, memory);
    }
    if module.eq_ignore_ascii_case(b"WING") {
        return decode_wing(ordinal, arguments, selectors, memory);
    }
    Ok(None)
}

fn decode_gdi(
    ordinal: u16,
    a: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    let request = match ordinal {
        38 => Request::Escape {
            dc: word(a, 0)?, escape: word(a, 1)? as i16, input_size: word(a, 2)? as i16,
            input: dword(a, 3)?, output: dword(a, 4)?,
        },
        74 => Request::GetBitmapBits {
            bitmap: word(a, 0)?, byte_count: dword(a, 1)? as i32, output: dword(a, 2)?,
        },
        106 => {
            let byte_count = dword(a, 1)? as i32;
            let bytes = if byte_count > 0 {
                read_far(dword(a, 2)?, byte_count as usize, selectors, memory)?
            } else {
                Vec::new()
            };
            Request::SetBitmapBits { bitmap: word(a, 0)?, byte_count, bytes }
        }
        156 => Request::CreateDiscardableBitmap {
            dc: word(a, 0)?, width: word(a, 1)? as i16, height: word(a, 2)? as i16,
        },
        360 => {
            let (version, entries) = read_log_palette(dword(a, 0)?, selectors, memory)?;
            Request::CreatePalette { version, entries }
        }
        361 => Request::SelectPalette {
            dc: word(a, 0)?, palette: word(a, 1)?, force_background: word(a, 2)? != 0,
        },
        362 => Request::RealizePalette { dc: word(a, 0)? },
        363 | 364 | 367 => {
            let kind = match ordinal {
                363 => PaletteTransferKind::Get,
                364 => PaletteTransferKind::Set,
                _ => PaletteTransferKind::Animate,
            };
            let count = word(a, 2)?;
            let pointer = dword(a, 3)?;
            let entries = if kind == PaletteTransferKind::Get {
                None
            } else {
                Some(read_palette_entries(pointer, count, selectors, memory)?)
            };
            Request::PaletteEntries {
                kind, palette: word(a, 0)?, start: word(a, 1)?, count, entries,
                output: if kind == PaletteTransferKind::Get { pointer } else { 0 },
            }
        }
        365 => Request::RealizeDefaultPalette { dc: word(a, 0)? },
        366 => Request::UpdateColors { dc: word(a, 0)? },
        368 => Request::ResizePalette { palette: word(a, 0)?, count: word(a, 1)? },
        370 => Request::GetNearestPaletteIndex { palette: word(a, 0)?, color: dword(a, 1)? },
        373 => Request::SetSystemPaletteUse { dc: word(a, 0)?, use_mode: word(a, 1)? },
        374 => Request::GetSystemPaletteUse { dc: word(a, 0)? },
        375 => Request::GetSystemPaletteEntries {
            dc: word(a, 0)?, start: word(a, 1)?, count: word(a, 2)?, output: dword(a, 3)?,
        },
        376 => Request::ResetDc { dc: word(a, 0)?, devmode: dword(a, 1)? },
        377 => Request::StartDoc {
            dc: word(a, 0)?, doc_info: read_doc_info(dword(a, 1)?, selectors, memory)?,
        },
        378 => Request::Print { operation: PrintOperation::EndDocument, dc: word(a, 0)? },
        379 => Request::Print { operation: PrintOperation::StartPage, dc: word(a, 0)? },
        380 => Request::Print { operation: PrintOperation::EndPage, dc: word(a, 0)? },
        381 => Request::SetAbortProc { dc: word(a, 0)?, callback: dword(a, 1)? },
        382 => Request::Print { operation: PrintOperation::AbortDocument, dc: word(a, 0)? },
        439 => Request::StretchDibits {
            dc: word(a, 0)?, destination_x: word(a, 1)? as i16,
            destination_y: word(a, 2)? as i16, destination_width: word(a, 3)? as i16,
            destination_height: word(a, 4)? as i16, source_x: word(a, 5)? as i16,
            source_y: word(a, 6)? as i16, source_width: word(a, 7)? as i16,
            source_height: word(a, 8)? as i16, bits: dword(a, 9)?, info: dword(a, 10)?,
            usage: word(a, 11)?, rop: dword(a, 12)?,
        },
        440 | 441 => {
            let dc = word(a, 0)?;
            let bitmap = word(a, 1)?;
            let start_scan = word(a, 2)?;
            let scan_lines = word(a, 3)?;
            let bits = dword(a, 4)?;
            let info = dword(a, 5)?;
            let color_usage = word(a, 6)?;
            if ordinal == 440 {
                Request::SetDibits { bitmap, dc, start_scan, scan_lines, bits, info, color_usage }
            } else {
                Request::GetDibits { bitmap, dc, start_scan, scan_lines, bits, info, color_usage }
            }
        }
        442 => Request::CreateDibitmap {
            dc: word(a, 0)?, header: dword(a, 1)?, init_flags: dword(a, 2)?,
            bits: dword(a, 3)?, info: dword(a, 4)?, color_usage: word(a, 5)?,
        },
        443 => Request::SetDibitsToDevice {
            dc: word(a, 0)?, destination_x: word(a, 1)? as i16,
            destination_y: word(a, 2)? as i16, width: word(a, 3)? as i16,
            height: word(a, 4)? as i16, source_x: word(a, 5)? as i16,
            source_y: word(a, 6)? as i16, start_scan: word(a, 7)?,
            scan_lines: word(a, 8)?, bits: dword(a, 9)?, info: dword(a, 10)?,
            color_usage: word(a, 11)?,
        },
        529 => Request::CreateHalftonePalette { dc: word(a, 0)? },
        162 => Request::GetBitmapDimension { bitmap: word(a, 0)? },
        163 => Request::SetBitmapDimension {
            bitmap: word(a, 0)?, width: word(a, 1)? as i16, height: word(a, 2)? as i16,
        },
        468 => Request::GetBitmapDimensionEx { bitmap: word(a, 0)?, output: dword(a, 1)? },
        478 => Request::SetBitmapDimensionEx {
            bitmap: word(a, 0)?, width: word(a, 1)? as i16, height: word(a, 2)? as i16,
            output: dword(a, 3)?,
        },
        602 | 603 => decode_dib_color_table(a, ordinal == 602, selectors, memory)?,
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn decode_wing(
    ordinal: u16,
    a: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    let request = match ordinal {
        1001 if a.is_empty() => Request::WinGCreateDc,
        1002 => Request::WinGRecommendDibFormat { info: dword(a, 0)? },
        1003 => Request::WinGCreateBitmap {
            dc: word(a, 0)?, info: dword(a, 1)?, bits_output: dword(a, 2)?,
        },
        1004 => Request::WinGGetDibPointer { bitmap: word(a, 0)?, info: dword(a, 1)? },
        1005 | 1006 => decode_dib_color_table(a, ordinal == 1006, selectors, memory)?,
        1007 if a.is_empty() => Request::WinGCreateHalfTonePalette,
        1008 => Request::WinGCreateHalfToneBrush {
            dc: word(a, 0)?, color: dword(a, 1)?, dither_type: word(a, 2)?,
        },
        1009 => Request::WinGStretchBlt {
            destination: word(a, 0)?, destination_x: word(a, 1)? as i16,
            destination_y: word(a, 2)? as i16, destination_width: word(a, 3)? as i16,
            destination_height: word(a, 4)? as i16, source: word(a, 5)?,
            source_x: word(a, 6)? as i16, source_y: word(a, 7)? as i16,
            source_width: word(a, 8)? as i16, source_height: word(a, 9)? as i16,
        },
        1010 => Request::WinGBitBlt {
            destination: word(a, 0)?, destination_x: word(a, 1)? as i16,
            destination_y: word(a, 2)? as i16, width: word(a, 3)? as i16,
            height: word(a, 4)? as i16, source: word(a, 5)?,
            source_x: word(a, 6)? as i16, source_y: word(a, 7)? as i16,
        },
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn decode_dib_color_table(
    a: &[Win16Argument],
    set: bool,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Request, Win16Error> {
    let kind = if set { DibColorTableKind::Set } else { DibColorTableKind::Get };
    let count = word(a, 2)?;
    let pointer = dword(a, 3)?;
    let entries = if set {
        Some(read_dib_rgbquads(pointer, count, selectors, memory)?)
    } else { None };
    Ok(Request::DibColorTable {
        kind, dc: word(a, 0)?, start: word(a, 1)?, count, entries,
        output: if set { 0 } else { pointer },
    })
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn read_log_palette(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<(u16, Vec<PaletteEntry16>), Win16Error> {
    let header = read_far(far, 4, selectors, memory)?;
    let version = u16::from_le_bytes([header[0], header[1]]);
    let count = u16::from_le_bytes([header[2], header[3]]);
    Ok((version, read_palette_entries_at(far, 4, count, selectors, memory)?))
}

fn read_doc_info(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<DocInfo16>, Win16Error> {
    if far == 0 { return Ok(None); }
    // Windows 3.1 DOCINFO is a 16-bit size followed by two 16:16 FAR strings.
    // Its documented Win16 extent is 10 bytes; Win32-only fields are absent.
    const DOCINFO16_SIZE: usize = 10;
    let bytes = read_far(far, DOCINFO16_SIZE, selectors, memory)?;
    let size = u16::from_le_bytes([bytes[0], bytes[1]]);
    if usize::from(size) != DOCINFO16_SIZE { return Ok(None); }
    let document_name = read_optional_string(read_u32(&bytes, 2)?, selectors, memory)?;
    let output = read_optional_string(read_u32(&bytes, 6)?, selectors, memory)?;
    Ok(Some(DocInfo16 { document_name, output }))
}

fn read_optional_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, Win16Error> {
    if far == 0 { return Ok(None); }
    crate::strings::read_ansi_z(selectors, memory, far, crate::exports::MAX_WIN16_STRING_BYTES)
        .map(Some)
}

fn read_palette_entries(
    far: u32,
    count: u16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<PaletteEntry16>, Win16Error> {
    read_palette_entries_at(far, 0, count, selectors, memory)
}

fn read_palette_entries_at(
    far: u32,
    byte_offset: u32,
    count: u16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<PaletteEntry16>, Win16Error> {
    let length = usize::from(count).checked_mul(4).ok_or(Win16Error::InvalidRange)?;
    if length == 0 { return Ok(Vec::new()); }
    let pointer = selectors.pointer_from_far(far)?;
    let pointer = selectors.add_bytes(pointer, byte_offset)?;
    let bytes = read_pointer(pointer, length, selectors, memory)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(usize::from(count)).map_err(|_| Win16Error::OutOfMemory)?;
    for entry in bytes.chunks_exact(4) {
        entries.push(PaletteEntry16 {
            red: entry[0], green: entry[1], blue: entry[2], flags: entry[3],
        });
    }
    Ok(entries)
}

fn read_dib_rgbquads(
    far: u32,
    count: u16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<DibRgbQuad16>, Win16Error> {
    let length = usize::from(count).checked_mul(4).ok_or(Win16Error::InvalidRange)?;
    if length == 0 { return Ok(Vec::new()); }
    let bytes = read_far(far, length, selectors, memory)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(usize::from(count)).map_err(|_| Win16Error::OutOfMemory)?;
    for entry in bytes.chunks_exact(4) {
        entries.push(DibRgbQuad16 {
            blue: entry[0], green: entry[1], red: entry[2], reserved: entry[3],
        });
    }
    Ok(entries)
}

fn read_far(
    far: u32,
    count: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    read_pointer(selectors.pointer_from_far(far)?, count, selectors, memory)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Win16Error> {
    let word = bytes.get(offset..offset + 4).ok_or(Win16Error::InvalidRange)?;
    Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

fn read_pointer(
    mut pointer: crate::SegmentedPointer,
    count: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(count).map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(count, 0);
    let mut offset = 0usize;
    while offset < count {
        let descriptor = selectors.describe(pointer.selector())?;
        let segment_bytes = descriptor.limit.checked_sub(u32::from(pointer.offset()))
            .and_then(|remaining| remaining.checked_add(1))
            .and_then(|remaining| usize::try_from(remaining).ok())
            .ok_or(Win16Error::InvalidRange)?;
        let chunk = (count - offset).min(segment_bytes);
        if chunk == 0 { return Err(Win16Error::InvalidRange); }
        let end = offset.checked_add(chunk).ok_or(Win16Error::InvalidRange)?;
        selectors.read(memory, pointer, &mut bytes[offset..end])?;
        offset = end;
        if offset < count {
            pointer = selectors.add_bytes(
                pointer,
                u32::try_from(chunk).map_err(|_| Win16Error::InvalidRange)?,
            )?;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "call_escape_tests.rs"]
mod escape_tests;

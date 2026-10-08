//! Windows GDI adapter for Win16 palettes, bitmap metrics, and print calls.
//!
//! Every native handle is resolved from the existing shared tables. Guest
//! pointers are absent; variable-sized data is owned by the runtime request.

use std::{mem::size_of, ptr};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DibColorTableKind,
    Win16GdiDeviceOperation as Operation, Win16GdiDeviceResult as ResultValue,
    Win16HostGdiObject, Win16PaletteTransferKind,
};
use windows_sys::Win32::Foundation::SIZE;
use windows_sys::Win32::Graphics::Gdi::{
    AnimatePalette, CreateDiscardableBitmap, CreateHalftonePalette, CreatePalette,
    GetBitmapDimensionEx, GetDIBColorTable, GetNearestPaletteIndex,
    GetPaletteEntries, GetDC, GetSystemPaletteEntries, GetSystemPaletteUse, RealizePalette,
    ReleaseDC, ResizePalette,
    SelectPalette, SetBitmapDimensionEx, SetDIBColorTable, SetPaletteEntries,
    SetStretchBltMode, SetSystemPaletteUse, StretchBlt, UpdateColors, COLORONCOLOR,
    LOGPALETTE, SRCCOPY,
    PALETTEENTRY, RGBQUAD,
};
use windows_sys::Win32::Storage::Xps::{
    AbortDoc, EndDoc, EndPage, StartDocW, StartPage, DOCINFOW,
};

use super::guest_text::GuestTextCodec;
use super::{win16_gdi::Win16Dcs, win16_gdi_objects::Win16Objects};

pub(super) fn execute(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    operation: Operation,
) -> Result<ResultValue, RuntimeError> {
    use Operation as Op;
    use ResultValue as Value;

    match operation {
        Op::GetObject { object } => objects.query_object(object, dcs.text_codec()).map(Value::ObjectInfo),
        Op::UnrealizeObject { object } => Ok(Value::Bool(objects.unrealize(object))),
        Op::RecommendWinGDibFormat | Op::CreateWinGDibSection { .. } => {
            Err(RuntimeError::new(
                Kind::InternalInvariant,
                "WinG bitmap operation bypassed its DIB backend",
            ))
        }
        Op::CreatePalette { version, entries } => {
            if version != 0x0300 || entries.len() > usize::from(u16::MAX) {
                return Ok(Value::Object(None));
            }
            let Some(native) = create_palette_native(version, &entries)? else {
                return Ok(Value::Object(None));
            };
            objects.adopt_owned(native.cast()).map(Value::Object)
        }
        Op::CreateDiscardableBitmap { dc, width, height } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(Value::Object(None)); };
            // Preserve the Win16 export's discardable-bitmap operation. Its
            // native HBITMAP is adopted into the shared GDI object registry.
            // SAFETY: The HDC lease remains live through the native call, and
            // width/height are scalar dimensions copied from the guest frame.
            let bitmap = unsafe {
                CreateDiscardableBitmap(dc_use.native(), i32::from(width), i32::from(height))
            };
            objects.adopt_owned(bitmap.cast()).map(Value::Object)
        }
        Op::CreateHalftonePalette { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(Value::Object(None)); };
            // SAFETY: The DC is a live retained HDC. The returned palette is
            // newly owned and adopted into the common GDI object table.
            let palette = unsafe { CreateHalftonePalette(dc_use.native()) };
            objects.adopt_owned(palette.cast()).map(Value::Object)
        }
        Op::CreateWinGHalftonePalette => {
            // WinG's no-argument export creates a palette from the display
            // DC. The temporary USER DC is released on both success and
            // palette-creation failure paths.
            let screen_dc = unsafe { GetDC(std::ptr::null_mut()) };
            if screen_dc.is_null() { return Ok(Value::Object(None)); }
            let palette = unsafe { CreateHalftonePalette(screen_dc) };
            unsafe { ReleaseDC(std::ptr::null_mut(), screen_dc); }
            objects.adopt_owned(palette.cast()).map(Value::Object)
        }
        Op::CreateWinGHalftoneBrush { dc, color, pattern } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(Value::Object(None)); };
            super::win16_wing_brush::create(objects, dc_use.native(), color, pattern)
                .map(Value::Object)
        }
        Op::WinGStretchBlt {
            destination,
            destination_x,
            destination_y,
            destination_width,
            destination_height,
            source,
            source_x,
            source_y,
            source_width,
            source_height,
        } => {
            let Some(destination_use) = dcs.lease_dc(destination)? else {
                return Ok(Value::Bool(false));
            };
            let Some(source_use) = dcs.lease_dc(source)? else {
                return Ok(Value::Bool(false));
            };

            // WinG's STRETCH_DELETESCANS is numeric mode 3, the Windows
            // COLORONCOLOR mode. Keep both HDC leases through mode restore.
            // SAFETY: The destination HDC is leased and mode is the documented
            // WinG/Windows mode value; the previous mode is returned on success.
            let previous_mode = unsafe {
                SetStretchBltMode(destination_use.native(), COLORONCOLOR)
            };
            if previous_mode == 0 {
                return Ok(Value::Bool(false));
            }

            // SAFETY: Both HDCs remain leased; dimensions/coordinates are sign
            // extended from Win16 int values and SRCCOPY is a scalar ROP.
            let drawn = unsafe {
                StretchBlt(
                    destination_use.native(),
                    i32::from(destination_x),
                    i32::from(destination_y),
                    i32::from(destination_width),
                    i32::from(destination_height),
                    source_use.native(),
                    i32::from(source_x),
                    i32::from(source_y),
                    i32::from(source_width),
                    i32::from(source_height),
                    SRCCOPY,
                ) != 0
            };
            // Always restore after a draw attempt, including StretchBlt failure.
            // SAFETY: The destination remains leased and previous_mode came
            // directly from the successful SetStretchBltMode call above.
            let restored = unsafe {
                SetStretchBltMode(destination_use.native(), previous_mode) != 0
            };
            Ok(Value::Bool(drawn && restored))
        }
        Op::SelectPalette { dc, palette, force_background } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(Value::Object(None)); };
            let Some(palette) = objects.native_palette(palette) else {
                return Ok(Value::Object(None));
            };
            // SAFETY: Both handles are retained and type checked; GDI owns the
            // selection behavior and returns the previously selected palette.
            let previous = unsafe {
                SelectPalette(dc_use.native(), palette, if force_background { 1 } else { 0 })
            };
            if previous.is_null() { return Ok(Value::Object(None)); }
            objects.intern_borrowed(previous.cast()).map(|token| Value::Object(Some(token)))
        }
        Op::RealizePalette { dc } | Op::RealizeDefaultPalette { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(Value::Count(0)); };
            // SAFETY: The DC is retained for this synchronous native call.
            Ok(Value::Count(unsafe { RealizePalette(dc_use.native()) } as i32))
        }
        Op::UpdateColors { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(Value::Bool(false)); };
            // SAFETY: The DC is retained for this synchronous native call.
            Ok(Value::Bool(unsafe { UpdateColors(dc_use.native()) } != 0))
        }
        Op::PaletteEntries { kind, palette, start, count, entries } => {
            let Some(native) = objects.native_palette(palette) else {
                return match kind {
                    Win16PaletteTransferKind::Get => Ok(Value::PaletteEntries {
                        count: 0, entries: Vec::new(),
                    }),
                    _ => Ok(Value::Count(0)),
                };
            };
            match kind {
                Win16PaletteTransferKind::Get => {
                    let mut native_entries = native_palette_entries(usize::from(count))?;
                    // SAFETY: `native_entries` owns `count` writable entries
                    // and the palette token resolves to a retained HPALETTE.
                    let copied = unsafe {
                        GetPaletteEntries(native, u32::from(start), u32::from(count),
                            native_entries.as_mut_ptr())
                    };
                    Ok(Value::PaletteEntries {
                        count: copied as i32,
                        entries: palette_entries_to_bytes(native_entries)?,
                    })
                }
                Win16PaletteTransferKind::Set | Win16PaletteTransferKind::Animate => {
                    let Some(entries) = entries else { return Ok(Value::Count(0)); };
                    if entries.len() != usize::from(count) { return Ok(Value::Count(0)); }
                    let mut native_entries = bytes_to_palette_entries(entries)?;
                    let result = if kind == Win16PaletteTransferKind::Set {
                        // SAFETY: The owned entry array remains live through
                        // the synchronous SetPaletteEntries call.
                        (unsafe { SetPaletteEntries(native, u32::from(start), u32::from(count),
                            native_entries.as_mut_ptr()) }) as i32
                    } else {
                        // SAFETY: The owned entry array remains live through
                        // the synchronous AnimatePalette call.
                        unsafe { AnimatePalette(native, u32::from(start), u32::from(count),
                            native_entries.as_mut_ptr()) }
                    };
                    Ok(Value::Count(result))
                }
            }
        }
        Op::ResizePalette { palette, count } => {
            let Some(native) = objects.native_palette(palette) else { return Ok(Value::Bool(false)); };
            // SAFETY: The palette token resolves to a retained HPALETTE.
            Ok(Value::Bool(unsafe { ResizePalette(native, u32::from(count)) } != 0))
        }
        Op::GetNearestPaletteIndex { palette, color } => {
            let Some(native) = objects.native_palette(palette) else { return Ok(Value::Count(-1)); };
            // SAFETY: The palette token resolves to a retained HPALETTE.
            Ok(Value::Count(unsafe { GetNearestPaletteIndex(native, color) } as i32))
        }
        Op::SetSystemPaletteUse { dc, use_mode } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(Value::Count(0)); };
            // SAFETY: The DC is retained and `use_mode` is a scalar guest value.
            Ok(Value::Count(unsafe {
                SetSystemPaletteUse(dc_use.native(), u32::from(use_mode))
            } as i32))
        }
        Op::GetSystemPaletteUse { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(Value::Count(0)); };
            // SAFETY: The DC is retained for this synchronous native call.
            Ok(Value::Count(unsafe { GetSystemPaletteUse(dc_use.native()) } as i32))
        }
        Op::GetSystemPaletteEntries { dc, start, count } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::PaletteEntries { count: 0, entries: Vec::new() });
            };
            let mut entries = native_palette_entries(usize::from(count))?;
            // SAFETY: `entries` is writable for the requested number of rows.
            let copied = unsafe { GetSystemPaletteEntries(dc_use.native(), u32::from(start),
                u32::from(count), entries.as_mut_ptr()) };
            Ok(Value::PaletteEntries {
                count: copied as i32,
                entries: palette_entries_to_bytes(entries)?,
            })
        }
        Op::DibColorTable { kind, dc, start, count, entries } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return match kind {
                    Win16DibColorTableKind::Get => Ok(Value::PaletteEntries {
                        count: 0, entries: Vec::new(),
                    }),
                    Win16DibColorTableKind::Set => Ok(Value::Count(0)),
                };
            };
            match kind {
                Win16DibColorTableKind::Get => {
                    let mut colors = native_rgb_quads(usize::from(count))?;
                    // SAFETY: `colors` is writable for the requested number of
                    // RGBQUAD rows and `dc` is a retained HDC.
                    let copied = unsafe { GetDIBColorTable(dc_use.native(), u32::from(start),
                        u32::from(count), colors.as_mut_ptr()) };
                    Ok(Value::PaletteEntries {
                        count: copied as i32,
                        entries: rgbquads_to_bytes(colors)?,
                    })
                }
                Win16DibColorTableKind::Set => {
                    let Some(entries) = entries else { return Ok(Value::Count(0)); };
                    if entries.len() != usize::from(count) { return Ok(Value::Count(0)); }
                    let mut colors = bytes_to_rgbquads(entries)?;
                    // SAFETY: The owned RGBQUAD array remains live through the
                    // synchronous SetDIBColorTable call.
                    Ok(Value::Count(unsafe { SetDIBColorTable(dc_use.native(), u32::from(start),
                        u32::from(count), colors.as_mut_ptr()) } as i32))
                }
            }
        }
        Op::GetBitmapDimension { bitmap } => Ok(bitmap_dimension(objects, bitmap, None)),
        Op::SetBitmapDimension { bitmap, width, height } =>
            Ok(bitmap_dimension(objects, bitmap, Some((i32::from(width), i32::from(height))))),
        Op::ResetDc { dc, devmode } => Ok(Value::Dc(dcs.reset(dc, devmode.as_ref())?)),
        Op::StartDoc { dc, document_name, output } =>
            start_doc(dcs, dc, document_name.as_deref(), output.as_deref()),
        Op::Print { operation, dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(Value::Count(-1)); };
            let result = match operation {
                runtime::Win16PrintOperation::EndDocument => unsafe { EndDoc(dc_use.native()) },
                runtime::Win16PrintOperation::StartPage => unsafe { StartPage(dc_use.native()) },
                runtime::Win16PrintOperation::EndPage => unsafe { EndPage(dc_use.native()) },
                runtime::Win16PrintOperation::AbortDocument => unsafe { AbortDoc(dc_use.native()) },
            };
            Ok(Value::Count(result as i32))
        }
    }
}

fn create_palette_native(
    version: u16,
    entries: &[[u8; 4]],
) -> Result<Option<windows_sys::Win32::Graphics::Gdi::HPALETTE>, RuntimeError> {
    let bytes = entries.len().checked_mul(4).and_then(|size| size.checked_add(4))
        .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
            "Win16 LOGPALETTE allocation size overflowed"))?;
    let word_count = bytes.checked_add(3).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "Win16 LOGPALETTE alignment overflowed"))? / 4;
    let mut words = Vec::new();
    words.try_reserve_exact(word_count).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate aligned Win16 LOGPALETTE", error))?;
    words.push(u32::from(version) | ((entries.len() as u32) << 16));
    for entry in entries { words.push(u32::from_ne_bytes(*entry)); }
    while words.len() < word_count { words.push(0); }
    // SAFETY: The aligned owned words contain the exact LOGPALETTE prefix and
    // entries; CreatePalette reads the variable-sized structure synchronously.
    let palette = unsafe { CreatePalette(words.as_ptr().cast::<LOGPALETTE>()) };
    Ok((!palette.is_null()).then_some(palette))
}

fn bitmap_dimension(
    objects: &Win16Objects,
    bitmap: Win16HostGdiObject,
    new_size: Option<(i32, i32)>,
) -> ResultValue {
    let Some(bitmap) = objects.native_bitmap(bitmap) else {
        return ResultValue::Point { success: false, x: 0, y: 0 };
    };
    let mut size = SIZE { cx: 0, cy: 0 };
    // SAFETY: `bitmap` is retained as an HBITMAP and `size` is writable for
    // this synchronous native call.
    let succeeded = unsafe {
        if let Some((width, height)) = new_size {
            SetBitmapDimensionEx(bitmap, width, height, &mut size)
        } else {
            GetBitmapDimensionEx(bitmap, &mut size)
        }
    } != 0;
    ResultValue::Point { success: succeeded, x: size.cx, y: size.cy }
}

fn start_doc(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    name: Option<&[u8]>,
    output: Option<&[u8]>,
) -> Result<ResultValue, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(ResultValue::Count(-1)); };
    let codec = dcs.text_codec();
    let name = start_doc_string(codec, name, "document name")?;
    let output = start_doc_string(codec, output, "output path")?;
    let info = DOCINFOW {
        cbSize: i32::try_from(size_of::<DOCINFOW>()).map_err(|error| RuntimeError::with_source(
            Kind::InternalInvariant, "native DOCINFOW size exceeds its size field", error))?,
        lpszDocName: name.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
        lpszOutput: output.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
        lpszDatatype: ptr::null(),
        fwType: 0,
    };
    // SAFETY: The HDC lease and `info` plus all C strings remain live
    // through the synchronous native StartDocW call.
    Ok(ResultValue::Count(unsafe { StartDocW(dc_use.native(), &info) }))
}

fn start_doc_string(
    codec: GuestTextCodec,
    bytes: Option<&[u8]>,
    field: &'static str,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let Some(bytes) = bytes else { return Ok(None); };
    if bytes.contains(&0) {
        return Err(RuntimeError::new(Kind::InvalidInput,
            format!("Win16 StartDoc {field} contains an embedded NUL")));
    }
    codec.to_wide_z(bytes).map(Some)
}

fn native_palette_entries(count: usize) -> Result<Vec<PALETTEENTRY>, RuntimeError> {
    let mut entries = Vec::new();
    entries.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate native Win16 palette entries", error))?;
    entries.resize(count, PALETTEENTRY::default());
    Ok(entries)
}

fn native_rgb_quads(count: usize) -> Result<Vec<RGBQUAD>, RuntimeError> {
    let mut entries = Vec::new();
    entries.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate native Win16 DIB color table", error))?;
    entries.resize(count, RGBQUAD::default());
    Ok(entries)
}

fn bytes_to_palette_entries(bytes: Vec<[u8; 4]>) -> Result<Vec<PALETTEENTRY>, RuntimeError> {
    let mut entries = Vec::new();
    entries.try_reserve_exact(bytes.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate native Win16 palette input", error))?;
    entries.extend(bytes.into_iter().map(|entry| PALETTEENTRY {
        peRed: entry[0], peGreen: entry[1], peBlue: entry[2], peFlags: entry[3],
    }));
    Ok(entries)
}

fn palette_entries_to_bytes(entries: Vec<PALETTEENTRY>) -> Result<Vec<[u8; 4]>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(entries.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate Win16 palette output", error))?;
    bytes.extend(entries.into_iter().map(|entry|
        [entry.peRed, entry.peGreen, entry.peBlue, entry.peFlags]));
    Ok(bytes)
}

fn bytes_to_rgbquads(bytes: Vec<[u8; 4]>) -> Result<Vec<RGBQUAD>, RuntimeError> {
    let mut colors = Vec::new();
    colors.try_reserve_exact(bytes.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate native Win16 DIB color-table input", error))?;
    colors.extend(bytes.into_iter().map(|entry| RGBQUAD {
        rgbBlue: entry[2], rgbGreen: entry[1], rgbRed: entry[0], rgbReserved: entry[3],
    }));
    Ok(colors)
}

fn rgbquads_to_bytes(colors: Vec<RGBQUAD>) -> Result<Vec<[u8; 4]>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(colors.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate Win16 DIB color-table output", error))?;
    bytes.extend(colors.into_iter().map(|color|
        [color.rgbRed, color.rgbGreen, color.rgbBlue, color.rgbReserved]));
    Ok(bytes)
}

//! Native Windows GDI operations for Win16 DC state and object queries.

#[path = "win16_gdi_char_width.rs"]
mod char_width;
#[path = "win16_gdi_glyph_outline.rs"]
mod glyph_outline;

use std::ffi::c_void;
use std::ptr;

use runtime::{
    RuntimeError, Win16GdiObjectInfo, Win16GdiServicesOperation as Operation,
    Win16GdiServicesResult as ResultValue, Win16HostAbcWidth, Win16HostGdiIdentity,
    Win16HostKerningPair, Win16HostRasterizerCaps,
};
use windows_sys::Win32::Foundation::{RECT, SIZE};
use windows_sys::Win32::Graphics::Gdi::{
    ABC, AddFontResourceW, CreateScalableFontResourceW, GDI_ERROR, GetAspectRatioFilterEx,
    GetBoundsRect, GetCharABCWidthsW, GetFontData, GetKerningPairsW, GetObjectType,
    GetRasterizerCaps, KERNINGPAIR, OBJ_METADC, RASTERIZER_STATUS, RemoveFontResourceW,
    SetBoundsRect, SetMapperFlags,
};

use super::{win16_gdi::Win16Dcs, win16_gdi_objects::Win16Objects};
use crate::filesystem::Filesystem;

pub(super) fn execute(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    filesystem: &mut Filesystem,
    operation: Operation,
) -> Result<ResultValue, RuntimeError> {
    use Operation as Op;
    use ResultValue as Value;

    match operation {
        Op::GetGlyphOutline { dc, character, format, matrix, byte_count, copy_buffer } =>
            glyph_outline::execute(dcs, dc, character, format, matrix, byte_count, copy_buffer),
        Op::SetBoundsRect { dc, rect, flags } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::Dword(0));
            };
            let native_rect = rect.map(to_native_rect);
            // SAFETY: The HDC is pinned by `dc_use`; the optional RECT is an
            // aligned native stack value built from copied signed Win16 fields.
            let previous = unsafe {
                SetBoundsRect(
                    dc_use.native(),
                    native_rect
                        .as_ref()
                        .map_or(std::ptr::null(), |rect| rect as *const RECT),
                    flags,
                )
            };
            Ok(Value::Dword(previous))
        }
        Op::GetBoundsRect { dc, flags } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::BoundsRect {
                    flags: 0,
                    rect: zero_rect(),
                });
            };
            let mut native_rect = RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            // SAFETY: The HDC is pinned and `native_rect` is an aligned,
            // writable host RECT for the synchronous native call.
            let result = unsafe { GetBoundsRect(dc_use.native(), &mut native_rect, flags) };
            Ok(Value::BoundsRect {
                flags: result,
                rect: from_native_rect(native_rect),
            })
        }
        Op::SetMapperFlags { dc, flags } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::Dword(u32::MAX));
            };
            // SAFETY: The HDC is pinned for the native call and flags are a
            // scalar copied from the Win16 stack.
            Ok(Value::Dword(unsafe {
                SetMapperFlags(dc_use.native(), flags)
            }))
        }
        Op::GetAspectRatioFilter { dc } | Op::GetAspectRatioFilterEx { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::AspectRatio {
                    success: false,
                    width: 0,
                    height: 0,
                });
            };
            let mut native_size = SIZE { cx: 0, cy: 0 };
            // SAFETY: The HDC is pinned and `native_size` is a writable host
            // SIZE; the runtime performs any Win16 packing or narrowing.
            let success = unsafe { GetAspectRatioFilterEx(dc_use.native(), &mut native_size) != 0 };
            Ok(Value::AspectRatio {
                success,
                width: native_size.cx,
                height: native_size.cy,
            })
        }
        Op::AddFontResource { guest_path } => {
            let Some(path) = font_resource_path(filesystem, &guest_path, false) else {
                return Ok(Value::FontResourceCount(0));
            };
            // The Windows 3.1 SDK declares an ANSI DOS path. Resolve its
            // bytes through the active DOS filesystem mapping, including a
            // native-volume mount, then use W so the host ACP cannot
            // reinterpret the guest code page.
            // SAFETY: `path` is an owned, NUL-terminated UTF-16 path produced
            // from the filesystem's resolved native path.
            Ok(Value::FontResourceCount(unsafe {
                AddFontResourceW(path.as_ptr())
            }))
        }
        Op::RemoveFontResource { guest_path } => {
            let Some(path) = font_resource_path(filesystem, &guest_path, false) else {
                return Ok(Value::Bool(false));
            };
            // SAFETY: `path` is an owned, NUL-terminated UTF-16 path produced
            // from the filesystem's resolved native path.
            Ok(Value::Bool(unsafe {
                RemoveFontResourceW(path.as_ptr()) != 0
            }))
        }
        Op::CreateScalableFontResource {
            hidden,
            resource_file,
            font_file,
            current_path,
        } => create_scalable_font_resource(
            filesystem,
            hidden,
            &resource_file,
            &font_file,
            current_path.as_deref(),
        ),
        Op::GetCharWidth { dc, first, last } => char_width::execute(dcs, dc, first, last),
        Op::GetCharAbcWidths { dc, first, last } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::AbcWidths {
                    success: false,
                    entries: Vec::new(),
                });
            };
            let Some(wide_chars) = guest_character_range(dcs.text_codec(), first, last) else {
                return Ok(Value::AbcWidths {
                    success: false,
                    entries: Vec::new(),
                });
            };
            let Some(mut native_entries) = allocate_defaulted::<ABC>(wide_chars.len()) else {
                return Ok(Value::AbcWidths {
                    success: false,
                    entries: Vec::new(),
                });
            };
            // The Windows 3.1 SDK defines ABC as three 16-bit fields. The
            // XP NTVDM wgdi31.c thunk allocates one native ABC per inclusive
            // guest character and copies results only on success. W calls
            // are grouped only where the fixed guest codec maps consecutive
            // guest characters to a consecutive UTF-16 range.
            if !get_abc_widths_for_guest_chars(dc_use.native(), &wide_chars, &mut native_entries) {
                return Ok(Value::AbcWidths {
                    success: false,
                    entries: Vec::new(),
                });
            }
            Ok(Value::AbcWidths {
                success: true,
                entries: native_entries
                    .into_iter()
                    .map(|entry| Win16HostAbcWidth {
                        abc_a: entry.abcA,
                        abc_b: entry.abcB,
                        abc_c: entry.abcC,
                    })
                    .collect(),
            })
        }
        Op::GetFontData {
            dc,
            table,
            offset,
            byte_count,
            copy_buffer,
        } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::FontData {
                    result: GDI_ERROR as u32,
                    bytes: Vec::new(),
                });
            };
            // SDK 3.1 Programmer's Reference, Volume 2 (GetFontData) specifies
            // zero when dwOffset is at or beyond a valid table's size. The
            // native W API reports GDI_ERROR for that case, so query the size
            // on this same pinned HDC before making the data call. An unknown
            // table or other native query error remains GDI_ERROR.
            let table_size = unsafe { GetFontData(dc_use.native(), table, 0, ptr::null_mut(), 0) };
            if table_size == GDI_ERROR as u32 {
                return Ok(Value::FontData {
                    result: GDI_ERROR as u32,
                    bytes: Vec::new(),
                });
            }
            if offset >= table_size {
                return Ok(Value::FontData {
                    result: 0,
                    bytes: Vec::new(),
                });
            }
            let mut bytes = if copy_buffer && byte_count != 0 {
                let Some(bytes) = allocate_zeroed_bytes(byte_count as usize) else {
                    return Ok(Value::FontData {
                        result: GDI_ERROR as u32,
                        bytes: Vec::new(),
                    });
                };
                bytes
            } else {
                Vec::new()
            };
            let buffer = if bytes.is_empty() {
                ptr::null_mut()
            } else {
                bytes.as_mut_ptr().cast::<c_void>()
            };
            // SAFETY: the HDC remains pinned, and `buffer` is either null or
            // points into an owned buffer of exactly `byte_count` bytes.
            let result = unsafe { GetFontData(dc_use.native(), table, offset, buffer, byte_count) };
            if result == GDI_ERROR as u32 {
                bytes.clear();
            } else if !bytes.is_empty() {
                bytes.truncate(bytes.len().min(result as usize));
            }
            Ok(Value::FontData { result, bytes })
        }
        Op::GetRasterizerCaps { byte_count } => {
            let mut native = RASTERIZER_STATUS::default();
            // Windows 3.1 WINDOWS.H defines three 16-bit `int` members;
            // XP's thunk writes all three fields after the API call. The
            // Win32 binding retains those fields as i16, so no host layout
            // bytes cross the boundary.
            // SAFETY: `native` is initialized and writable for this call.
            let success =
                unsafe { GetRasterizerCaps(&mut native, i32::from(byte_count) as u32) != 0 };
            Ok(Value::RasterizerCaps {
                success,
                caps: Win16HostRasterizerCaps {
                    size: native.nSize,
                    flags: native.wFlags,
                    language_id: native.nLanguageID,
                },
            })
        }
        Op::GetKerningPairs { dc, pair_count } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::KerningPairs {
                    count: 0,
                    entries: Vec::new(),
                });
            };
            // SDK 3.1 Volume 2 defines NULL lpkrnpair as a total-count query;
            // XP NTVDM passes the supplied count and pointer to GetKerningPairs
            // then narrows each returned pair to the 16-bit guest layout. W
            // results need a guest-codepage projection, so fetch the complete
            // native table before filtering; this makes query and copy counts
            // agree even when unrepresentable pairs occur before later valid
            // pairs in the native list.
            // SAFETY: `dc_use` pins the HDC; a null output pointer requests the
            // documented native count and does not write through the pointer.
            let native_count = unsafe { GetKerningPairsW(dc_use.native(), 0, ptr::null_mut()) };
            let Ok(native_capacity) = usize::try_from(native_count) else {
                return Ok(Value::KerningPairs {
                    count: 0,
                    entries: Vec::new(),
                });
            };
            let Some(mut native_entries) = allocate_defaulted::<KERNINGPAIR>(native_capacity)
            else {
                return Ok(Value::KerningPairs {
                    count: 0,
                    entries: Vec::new(),
                });
            };
            if native_count != 0 {
                // The Windows 3.1 KERNINGPAIR is 6 bytes; XP's wgdi31.c
                // converts both WORD characters and narrows the amount to
                // INT16. The HDC stays pinned and this owned array has room
                // for every pair reported by the count query.
                let fetched = unsafe {
                    GetKerningPairsW(dc_use.native(), native_count, native_entries.as_mut_ptr())
                };
                native_entries.truncate((fetched as usize).min(native_entries.len()));
            } else {
                return Ok(Value::KerningPairs {
                    count: 0,
                    entries: Vec::new(),
                });
            }

            let codec = dcs.text_codec();
            let mut guest_entries = Vec::new();
            let requested = pair_count as usize;
            let guest_capacity = if pair_count == 0 {
                0
            } else {
                native_entries.len().min(requested)
            };
            if guest_entries.try_reserve_exact(guest_capacity).is_err() {
                return Ok(Value::KerningPairs {
                    count: 0,
                    entries: Vec::new(),
                });
            }
            let mut filtered_count = 0u32;
            for entry in native_entries {
                let (Some(first), Some(second)) = (
                    guest_character_from_wide(codec, entry.wFirst),
                    guest_character_from_wide(codec, entry.wSecond),
                ) else {
                    continue;
                };
                filtered_count += 1;
                if pair_count != 0 && guest_entries.len() < requested {
                    guest_entries.push(Win16HostKerningPair {
                        first,
                        second,
                        amount: entry.iKernAmount,
                    });
                }
            }
            Ok(Value::KerningPairs {
                // NULL-output queries return the filtered total. Copy calls
                // return only the number actually written into the Win16
                // output buffer, matching the SDK's retrieved-count rule.
                count: if pair_count == 0 {
                    filtered_count
                } else {
                    guest_entries.len() as u32
                },
                entries: guest_entries,
            })
        }
        Op::IsMetafileDc { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::Bool(false));
            };
            // SAFETY: `dc_use` pins a live native HDC for the duration of the
            // type query; the guest supplied only an opaque checked token.
            Ok(Value::Bool(unsafe {
                GetObjectType(dc_use.native()) == OBJ_METADC as u32
            }))
        }
        Op::IsGdiObject {
            identity: Win16HostGdiIdentity::Dc(dc),
        } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(Value::Bool(false));
            };
            // SAFETY: `dc_use` pins a live native HDC. HDC and HGDIOBJ are
            // Windows handle aliases; no guest value is cast or forwarded.
            Ok(Value::Bool(unsafe { GetObjectType(dc_use.native()) != 0 }))
        }
        Op::IsGdiObject {
            identity: Win16HostGdiIdentity::Object(object),
        } => {
            let known_type = objects.native_region(object).is_some()
                || objects.native_bitmap(object).is_some()
                || objects.native_brush(object).is_some()
                || objects.native_palette(object).is_some()
                || objects.native_font(object).is_some();
            if known_type {
                return Ok(Value::Bool(true));
            }
            // The remaining currently mapped GDI kind is a pen. Querying only
            // after type-specific checks avoids creating a borrowed alias for
            // a pattern brush as a side effect of an object-validity query.
            let info = objects.query_object(object, dcs.text_codec())?;
            Ok(Value::Bool(matches!(
                info,
                Some(Win16GdiObjectInfo::Pen(_))
            )))
        }
    }
}

fn create_scalable_font_resource(
    filesystem: &mut Filesystem,
    hidden: u16,
    resource_file: &[u8],
    font_file: &[u8],
    current_path: Option<&[u8]>,
) -> Result<ResultValue, RuntimeError> {
    let Some(resource) = font_resource_path(filesystem, resource_file, true) else {
        return Ok(ResultValue::Bool(false));
    };
    // A bare filename is stored in the font resource file unchanged. The
    // current path is only the directory from which the TrueType file is
    // read, so the resource stays portable. A font path that already has a
    // directory is stored after DOS resolution, with no current path.
    let (font, directory) = if let Some(directory) = current_path {
        let Some(located) = join_guest_font_path(directory, font_file) else {
            return Ok(ResultValue::Bool(false));
        };
        let Some(absolute) = font_resource_path(filesystem, &located, false) else {
            return Ok(ResultValue::Bool(false));
        };
        let Some(directory) = wide_parent_directory(&absolute) else {
            return Ok(ResultValue::Bool(false));
        };
        let Some(font) = guest_filename_wide(filesystem, font_file) else {
            return Ok(ResultValue::Bool(false));
        };
        (font, Some(directory))
    } else {
        let Some(font) = font_resource_path(filesystem, font_file, false) else {
            return Ok(ResultValue::Bool(false));
        };
        (font, None)
    };
    // SAFETY: `resource`, `font`, and the optional directory are owned
    // NUL-terminated UTF-16 strings from the DOS filesystem mapping. The
    // current-path pointer is null when the font path is already absolute.
    // No guest pointer is forwarded.
    let created = unsafe {
        CreateScalableFontResourceW(
            u32::from(hidden),
            resource.as_ptr(),
            font.as_ptr(),
            directory.as_ref().map_or(ptr::null(), |path| path.as_ptr()),
        ) != 0
    };
    Ok(ResultValue::Bool(created))
}

fn join_guest_font_path(directory: &[u8], file: &[u8]) -> Option<Vec<u8>> {
    let separator = !directory.ends_with(b"\\") && !directory.ends_with(b"/");
    let length = directory
        .len()
        .checked_add(file.len())?
        .checked_add(usize::from(separator))?;
    let mut joined = Vec::new();
    joined.try_reserve_exact(length).ok()?;
    joined.extend_from_slice(directory);
    if separator {
        joined.push(b'\\');
    }
    joined.extend_from_slice(file);
    Some(joined)
}

fn guest_filename_wide(filesystem: &Filesystem, file: &[u8]) -> Option<Vec<u16>> {
    let text = filesystem.guest_code_page().decode(file).ok()?;
    if text.is_empty()
        || text
            .chars()
            .any(|character| matches!(character, '\0' | '\\' | '/' | ':'))
    {
        return None;
    }
    let mut wide = Vec::new();
    let length = text.encode_utf16().count().checked_add(1)?;
    wide.try_reserve_exact(length).ok()?;
    wide.extend(text.encode_utf16());
    wide.push(0);
    Some(wide)
}

fn wide_parent_directory(file: &[u16]) -> Option<Vec<u16>> {
    let path = file.strip_suffix(&[0])?;
    let split = path
        .iter()
        .rposition(|unit| *unit == u16::from(b'\\') || *unit == u16::from(b'/'))?;
    let end = if split == 0 || path.get(split.wrapping_sub(1)) == Some(&u16::from(b':')) {
        split + 1
    } else {
        split
    };
    let mut directory = Vec::new();
    directory.try_reserve_exact(end.checked_add(1)?).ok()?;
    directory.extend_from_slice(&path[..end]);
    directory.push(0);
    Some(directory)
}

fn font_resource_path(
    filesystem: &mut Filesystem,
    guest_path: &[u8],
    allow_missing_final: bool,
) -> Option<Vec<u16>> {
    // `resolve_path` follows the active DOS filesystem mapping, including
    // native-volume mounts; `confined_path` resolves the guest entry under
    // that mount before a host-native UTF-16 path is formed. The font
    // resource file may be created, so its final component can be absent.
    let relative = filesystem.resolve_path(guest_path, false).ok()?;
    let confined = filesystem
        .confined_path(&relative, true, allow_missing_final)
        .ok()?;
    let full = filesystem.canonical_root.join(confined);
    use std::os::windows::ffi::OsStrExt;
    let mut path = Vec::new();
    let wide = full.as_os_str().encode_wide();
    let length = full.as_os_str().encode_wide().count().checked_add(1)?;
    path.try_reserve_exact(length).ok()?;
    path.extend(wide);
    path.push(0);
    Some(path)
}

fn guest_character_range(
    codec: super::guest_text::GuestTextCodec,
    first: u16,
    last: u16,
) -> Option<Vec<u16>> {
    if first > last {
        return None;
    }
    let count = usize::from(last - first) + 1;
    let mut wide = Vec::new();
    wide.try_reserve_exact(count).ok()?;
    for guest_code in first..=last {
        let encoded = if guest_code <= u16::from(u8::MAX) {
            [guest_code as u8, 0]
        } else {
            // GDI numeric DBCS codes use lead << 8 | trail (Microsoft KB244046):
            // https://ftp.zx.net.nz/pub/archive/ftp.microsoft.com/MISC/KB/en-us/244/046.HTM
            guest_code.to_be_bytes()
        };
        let byte_count = if guest_code <= u16::from(u8::MAX) {
            1
        } else {
            2
        };
        let Ok(character) = codec.to_wide(&encoded[..byte_count]) else {
            return None;
        };
        if character.len() != 1 {
            return None;
        }
        wide.push(character[0]);
    }
    Some(wide)
}

fn get_abc_widths_for_guest_chars(
    hdc: windows_sys::Win32::Graphics::Gdi::HDC,
    wide_chars: &[u16],
    entries: &mut [ABC],
) -> bool {
    if wide_chars.is_empty() || wide_chars.len() != entries.len() {
        return false;
    }
    let mut start = 0;
    while start < wide_chars.len() {
        let mut end = start;
        while end + 1 < wide_chars.len()
            && wide_chars[end].checked_add(1) == Some(wide_chars[end + 1])
        {
            end += 1;
        }
        // SAFETY: `start..=end` is contained in both same-length owned slices;
        // GetCharABCWidthsW writes one ABC per requested UTF-16 code unit.
        let success = unsafe {
            GetCharABCWidthsW(
                hdc,
                u32::from(wide_chars[start]),
                u32::from(wide_chars[end]),
                entries.as_mut_ptr().add(start),
            ) != 0
        };
        if !success {
            return false;
        }
        start = end + 1;
    }
    true
}

fn guest_character_from_wide(
    codec: super::guest_text::GuestTextCodec,
    character: u16,
) -> Option<u16> {
    let encoded = codec.from_wide(&[character]).ok()?;
    if encoded.used_default_char == Some(true) {
        return None;
    }
    match encoded.bytes.as_slice() {
        [single] => Some(u16::from(*single)),
        // GetKerningPairsA uses this same numeric packing (NT 3.5 DCQUERY.C).
        // The runtime separately stores each WORD in little-endian guest memory.
        [lead, trail] => Some(u16::from_be_bytes([*lead, *trail])),
        _ => None,
    }
}

fn allocate_defaulted<T: Default + Copy>(count: usize) -> Option<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).ok()?;
    values.resize(count, T::default());
    Some(values)
}

fn allocate_zeroed_bytes(count: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(count).ok()?;
    bytes.resize(count, 0);
    Some(bytes)
}

fn to_native_rect(rect: runtime::Win16DrawingRect) -> RECT {
    RECT {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn from_native_rect(rect: RECT) -> runtime::Win16DrawingRect {
    runtime::Win16DrawingRect {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn zero_rect() -> runtime::Win16DrawingRect {
    runtime::Win16DrawingRect {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    }
}

#[cfg(test)]
#[path = "win16_gdi_services_dbcs_tests.rs"]
mod dbcs_tests;

#[cfg(test)]
mod scalable_font_path_tests {
    use super::{join_guest_font_path, wide_parent_directory};

    #[test]
    fn join_inserts_one_separator() {
        assert_eq!(
            join_guest_font_path(b"C:\\FONTS", b"A.TTF").unwrap(),
            b"C:\\FONTS\\A.TTF"
        );
        assert_eq!(
            join_guest_font_path(b"C:\\FONTS\\", b"A.TTF").unwrap(),
            b"C:\\FONTS\\A.TTF"
        );
        assert_eq!(
            join_guest_font_path(b"C:/FONTS/", b"A.TTF").unwrap(),
            b"C:/FONTS/A.TTF"
        );
    }

    #[test]
    fn parent_keeps_the_drive_root_separator() {
        let nested: Vec<u16> = "C:\\FONTS\\A.TTF\0".encode_utf16().collect();
        let nested_parent: Vec<u16> = "C:\\FONTS\0".encode_utf16().collect();
        assert_eq!(wide_parent_directory(&nested).unwrap(), nested_parent);
        let root: Vec<u16> = "C:\\A.TTF\0".encode_utf16().collect();
        let drive: Vec<u16> = "C:\\\0".encode_utf16().collect();
        assert_eq!(wide_parent_directory(&root).unwrap(), drive);
    }
}

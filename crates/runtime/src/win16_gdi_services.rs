//! Runtime translation for Win16 GDI DC state, font queries, and object tests.

#[path = "win16_glyph_outline.rs"]
mod glyph_outline;

use guest_core::memory::Memory;
use win16_abi::{
    Access, Win16FontResourceInput, Win16GdiServicesRequest as Request, Win16ModuleReference,
};
use zerocopy::byteorder::little_endian::{I16, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::Win16State;
use crate::{
    DiagnosticKind, RuntimeError, RuntimeHost, Win16GdiServicesOperation as Operation,
    Win16GdiServicesResult as ResultValue, Win16HostGdiIdentity,
};

const DCB_RESET: u32 = 0x0001;
const DCB_SET: u32 = DCB_RESET | 0x0002;
const GDI_ERROR: u32 = u32::MAX;

mod wire {
    use super::*;

    // WINDOWS.H (Windows 3.1) defines ABC, KERNINGPAIR, and RASTERIZER_STATUS
    // with 16-bit guest fields. These private zerocopy records keep their
    // packed little-endian wire bytes separate from Win32 native structures.
    #[repr(C)]
    #[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    pub(super) struct Abc16 {
        pub abc_a: I16,
        pub abc_b: U16,
        pub abc_c: I16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    pub(super) struct KerningPair16 {
        pub first: U16,
        pub second: U16,
        pub amount: I16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    pub(super) struct RasterizerStatus16 {
        pub size: I16,
        pub flags: I16,
        pub language_id: I16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    pub(super) struct Size16 {
        pub width: I16,
        pub height: I16,
    }
}

impl Win16State {
    pub(super) fn execute_gdi_services(
        &mut self,
        request: Request,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        use Request as Req;
        use ResultValue as Value;

        match request {
            request @ Req::GetGlyphOutline { .. } =>
                self.execute_glyph_outline(request, memory, host),
            Req::SetBoundsRect { dc, rect, flags } => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                // The Windows 3.1 Programmer's Reference explicitly permits
                // a NULL rectangle; preserve it for flag-only updates.
                match host.win16_gdi_services(Operation::SetBoundsRect {
                    dc,
                    rect: rect.map(|rect| crate::Win16DrawingRect {
                        left: i32::from(rect.left),
                        top: i32::from(rect.top),
                        right: i32::from(rect.right),
                        bottom: i32::from(rect.bottom),
                    }),
                    flags: u32::from(flags),
                })? {
                    Value::Dword(previous) => Ok(u32::from(previous as u16)),
                    _ => Err(wrong_result("SetBoundsRect")),
                }
            }
            Req::GetBoundsRect { dc, output, flags } => {
                if output == 0 {
                    return Ok(0);
                }
                let target = preflight_guest_output(&self.selectors, memory, output, 8)?;
                let bounds = match self.guest_gdi.dc(dc) {
                    Some(dc) => match host.win16_gdi_services(Operation::GetBoundsRect {
                        dc,
                        flags: u32::from(flags),
                    })? {
                        Value::BoundsRect { flags, rect } => (flags, rect),
                        _ => return Err(wrong_result("GetBoundsRect")),
                    },
                    None => (
                        0,
                        crate::Win16DrawingRect {
                            left: 0,
                            top: 0,
                            right: 0,
                            bottom: 0,
                        },
                    ),
                };
                let bytes = win16_abi::window_geometry::Rect16 {
                    left: bounds.1.left as i16,
                    top: bounds.1.top as i16,
                    right: bounds.1.right as i16,
                    bottom: bounds.1.bottom as i16,
                }
                .encode();
                write_guest_output(&self.selectors, memory, target, &bytes)?;
                // Windows 3.1 returns only DCB_SET or DCB_RESET from this API.
                // XP NTVDM explicitly normalizes the native flag combination.
                Ok(if bounds.0 & DCB_SET != 0 {
                    DCB_SET
                } else {
                    DCB_RESET
                })
            }
            Req::SetMapperFlags { dc, flags } => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(GDI_ERROR);
                };
                match host.win16_gdi_services(Operation::SetMapperFlags { dc, flags })? {
                    Value::Dword(previous) => Ok(previous),
                    _ => Err(wrong_result("SetMapperFlags")),
                }
            }
            Req::GetAspectRatioFilter { dc } => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi_services(Operation::GetAspectRatioFilter { dc })? {
                    Value::AspectRatio {
                        success: true,
                        width,
                        height,
                    } => Ok(u32::from(width as u16) | (u32::from(height as u16) << 16)),
                    Value::AspectRatio { success: false, .. } => Ok(0),
                    _ => Err(wrong_result("GetAspectRatioFilter")),
                }
            }
            Req::GetAspectRatioFilterEx { dc, output } => {
                if output == 0 {
                    return Ok(0);
                }
                let target = preflight_guest_output(&self.selectors, memory, output, 4)?;
                let ratio = match self.guest_gdi.dc(dc) {
                    Some(dc) => {
                        match host.win16_gdi_services(Operation::GetAspectRatioFilterEx { dc })? {
                            Value::AspectRatio {
                                success,
                                width,
                                height,
                            } => (success, width, height),
                            _ => return Err(wrong_result("GetAspectRatioFilterEx")),
                        }
                    }
                    None => (false, 0, 0),
                };
                // The NTVDM thunk writes SIZE16 even when the native BOOL is
                // false; zero-initialized host output keeps failure bytes safe.
                let bytes: [u8; 4] = zerocopy::transmute!(wire::Size16 {
                    width: I16::new(ratio.1 as i16),
                    height: I16::new(ratio.2 as i16),
                });
                write_guest_output(&self.selectors, memory, target, &bytes)?;
                Ok(u32::from(ratio.0))
            }
            Req::AddFontResource { input } => {
                let Some(guest_path) = self.guest_font_resource_path(&input) else {
                    return Ok(0);
                };
                match host.win16_gdi_services(Operation::AddFontResource { guest_path })? {
                    Value::FontResourceCount(count) => Ok(u32::from(count as u16)),
                    _ => Err(wrong_result("AddFontResource")),
                }
            }
            Req::RemoveFontResource { input } => {
                let Some(guest_path) = self.guest_font_resource_path(&input) else {
                    return Ok(0);
                };
                match host.win16_gdi_services(Operation::RemoveFontResource { guest_path })? {
                    Value::Bool(removed) => Ok(u32::from(removed)),
                    _ => Err(wrong_result("RemoveFontResource")),
                }
            }
            Req::CreateScalableFontResource {
                hidden,
                resource_file,
                font_file,
                current_path,
            } => {
                let Some(resource_file) = resource_file.filter(|path| !path.is_empty()) else {
                    return Ok(0);
                };
                let Some(font_file) = font_file.filter(|path| !path.is_empty()) else {
                    return Ok(0);
                };
                // NULL and a pointer to a NUL omit the current path. A bare
                // filename must name that directory; a font path that already
                // has a directory must omit it. The filename itself stays
                // intact so the font resource file records the caller's form.
                let current_path = current_path.filter(|path| !path.is_empty());
                let current_path = if font_file_has_directory(&font_file) {
                    if current_path.is_some() {
                        return Ok(0);
                    }
                    None
                } else {
                    let Some(current_path) = current_path else {
                        return Ok(0);
                    };
                    Some(current_path)
                };
                match host.win16_gdi_services(Operation::CreateScalableFontResource {
                    hidden,
                    resource_file,
                    font_file,
                    current_path,
                })? {
                    Value::Bool(created) => Ok(u32::from(created)),
                    _ => Err(wrong_result("CreateScalableFontResource")),
                }
            }
            Req::GetCharWidth { dc, first, last, output } => {
                if output == 0 || first > last {
                    return Ok(0);
                }
                let count = usize::from(last - first) + 1;
                let Some(byte_count) = count.checked_mul(2) else {
                    return Ok(0);
                };
                // LPINT is a normal FAR pointer, not a huge pointer: the
                // complete signed-int array must fit in its 16-bit segment.
                // In particular, 0..=0xffff requires 131072 bytes, not zero.
                if byte_count > 0x1_0000 - usize::from(output as u16) {
                    return Ok(0);
                }
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                // Validate the entire destination before host work. Host
                // failure or a malformed result never changes guest memory.
                let target = preflight_guest_output(&self.selectors, memory, output, byte_count)?;
                match host.win16_gdi_services(Operation::GetCharWidth { dc, first, last })? {
                    Value::CharWidths { success: false, .. } => Ok(0),
                    Value::CharWidths { success: true, entries } if entries.len() == count => {
                        let Some(bytes) = encode_char_widths(&entries) else {
                            return Ok(0);
                        };
                        write_guest_output(&self.selectors, memory, target, &bytes)?;
                        Ok(1)
                    }
                    _ => Err(wrong_result("GetCharWidth")),
                }
            }
            Req::GetCharAbcWidths {
                dc,
                first,
                last,
                output,
            } => {
                if output == 0 || first > last {
                    return Ok(0);
                }
                let count = usize::from(last - first) + 1;
                let Some(byte_count) = count.checked_mul(6) else {
                    return Ok(0);
                };
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi_services(Operation::GetCharAbcWidths { dc, first, last })? {
                    Value::AbcWidths { success: false, .. } => Ok(0),
                    Value::AbcWidths {
                        success: true,
                        entries,
                    } if entries.len() == count => {
                        let target =
                            preflight_guest_output(&self.selectors, memory, output, byte_count)?;
                        let Some(bytes) = encode_abc_widths(&entries) else {
                            return Ok(0);
                        };
                        write_guest_output(&self.selectors, memory, target, &bytes)?;
                        Ok(1)
                    }
                    _ => Err(wrong_result("GetCharABCWidths")),
                }
            }
            Req::GetFontData {
                dc,
                table,
                offset,
                output,
                byte_count,
            } => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(GDI_ERROR);
                };
                let target = if output != 0 && byte_count != 0 {
                    Some(preflight_guest_output(
                        &self.selectors,
                        memory,
                        output,
                        byte_count as usize,
                    )?)
                } else {
                    None
                };
                match host.win16_gdi_services(Operation::GetFontData {
                    dc,
                    table,
                    offset,
                    byte_count,
                    copy_buffer: output != 0,
                })? {
                    Value::FontData { result, bytes } => {
                        if result != GDI_ERROR {
                            if let Some(target) = target {
                                if bytes.len() > byte_count as usize {
                                    return Err(wrong_result("GetFontData output length"));
                                }
                                write_guest_output(&self.selectors, memory, target, &bytes)?;
                            }
                        }
                        Ok(result)
                    }
                    _ => Err(wrong_result("GetFontData")),
                }
            }
            Req::GetRasterizerCaps { output, byte_count } => {
                if output == 0 {
                    return Ok(0);
                }
                let target = preflight_guest_output(&self.selectors, memory, output, 6)?;
                match host.win16_gdi_services(Operation::GetRasterizerCaps {
                    byte_count: byte_count as i16,
                })? {
                    Value::RasterizerCaps { success, caps } => {
                        let bytes: [u8; 6] = zerocopy::transmute!(wire::RasterizerStatus16 {
                            size: I16::new(caps.size),
                            flags: I16::new(caps.flags),
                            language_id: I16::new(caps.language_id),
                        });
                        // XP's thunk stores all three fields after the call,
                        // including the initialized fields from a false result.
                        write_guest_output(&self.selectors, memory, target, &bytes)?;
                        Ok(u32::from(success))
                    }
                    _ => Err(wrong_result("GetRasterizerCaps")),
                }
            }
            Req::GetKerningPairs {
                dc,
                pair_count,
                output,
            } => {
                if pair_count < 0 && output != 0 {
                    return Ok(0);
                }
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                // A non-NULL zero-capacity buffer is an empty copy, whereas
                // NULL requests the total count (SDK 3.1 Programmer's Reference).
                if pair_count == 0 && output != 0 {
                    return Ok(0);
                }
                let target = if pair_count > 0 && output != 0 {
                    let byte_count = (pair_count as usize).checked_mul(6).ok_or_else(|| {
                        RuntimeError::new(
                            DiagnosticKind::ResourceExhausted,
                            "Win16 kerning-pair output size overflow",
                        )
                    })?;
                    Some(preflight_guest_output(
                        &self.selectors,
                        memory,
                        output,
                        byte_count,
                    )?)
                } else {
                    None
                };
                match host.win16_gdi_services(Operation::GetKerningPairs {
                    dc,
                    // A NULL output is the SDK's count query, independently
                    // of the guest count. Native W uses count zero for it.
                    pair_count: if output == 0 { 0 } else { pair_count as u16 },
                })? {
                    Value::KerningPairs { count, entries } => {
                        if let Some(target) = target {
                            if entries.len() > pair_count as usize {
                                return Err(wrong_result("GetKerningPairs output length"));
                            }
                            let Some(bytes) = encode_kerning_pairs(&entries) else {
                                return Ok(0);
                            };
                            write_guest_output(&self.selectors, memory, target, &bytes)?;
                        }
                        Ok(u32::from(count as u16))
                    }
                    _ => Err(wrong_result("GetKerningPairs")),
                }
            }
            Req::IsGdiObject { object } => {
                let identity = if let Some(dc) = self.guest_gdi.dc(object) {
                    Win16HostGdiIdentity::Dc(dc)
                } else if let Some(object) = self.guest_gdi.object(object) {
                    Win16HostGdiIdentity::Object(object)
                } else {
                    return Ok(0);
                };
                match host.win16_gdi_services(Operation::IsGdiObject { identity })? {
                    Value::Bool(is_object) => Ok(u32::from(is_object)),
                    _ => Err(wrong_result("IsGDIObject")),
                }
            }
        }
    }

    fn guest_font_resource_path(&self, input: &Win16FontResourceInput) -> Option<Vec<u8>> {
        match input {
            Win16FontResourceInput::Null => None,
            Win16FontResourceInput::Path(path) => Some(path.clone()),
            Win16FontResourceInput::Module(module) => {
                let handle = self.module_handle(&Win16ModuleReference::Handle(*module))?;
                let record = self.modules.records.get(&handle)?;
                let path = record
                    .external_application
                    .as_ref()
                    .and_then(|external| external.association_path())
                    .unwrap_or(record.path.as_slice());
                (!path.is_empty()).then(|| path.to_vec())
            }
        }
    }
}

fn preflight_guest_output(
    selectors: &win16_abi::SelectorTable,
    memory: &mut Memory,
    far: u32,
    byte_count: usize,
) -> Result<win16_abi::SegmentedPointer, RuntimeError> {
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    selectors
        .translate(pointer, Access::Write, byte_count, memory)
        .map_err(crate::runtime_error)?;
    Ok(pointer)
}

fn write_guest_output(
    selectors: &win16_abi::SelectorTable,
    memory: &mut Memory,
    pointer: win16_abi::SegmentedPointer,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    selectors
        .write(memory, pointer, bytes)
        .map_err(crate::runtime_error)
}

fn encode_abc_widths(entries: &[crate::Win16HostAbcWidth]) -> Option<Vec<u8>> {
    let capacity = entries.len().checked_mul(6)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).ok()?;
    for entry in entries {
        let wire = wire::Abc16 {
            abc_a: I16::new(entry.abc_a as i16),
            abc_b: U16::new(entry.abc_b as u16),
            abc_c: I16::new(entry.abc_c as i16),
        };
        let encoded: [u8; 6] = zerocopy::transmute!(wire);
        bytes.extend_from_slice(&encoded);
    }
    Some(bytes)
}

fn encode_kerning_pairs(entries: &[crate::Win16HostKerningPair]) -> Option<Vec<u8>> {
    let capacity = entries.len().checked_mul(6)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).ok()?;
    for entry in entries {
        let wire = wire::KerningPair16 {
            first: U16::new(entry.first),
            second: U16::new(entry.second),
            amount: I16::new(entry.amount as i16),
        };
        let encoded: [u8; 6] = zerocopy::transmute!(wire);
        bytes.extend_from_slice(&encoded);
    }
    Some(bytes)
}

fn font_file_has_directory(path: &[u8]) -> bool {
    path.iter().any(|byte| matches!(*byte, b'\\' | b'/')) || path.get(1) == Some(&b':')
}

fn wrong_result(api: &'static str) -> RuntimeError {
    RuntimeError::new(
        DiagnosticKind::InternalInvariant,
        format!("Win16 {api} received the wrong native result"),
    )
}

// Native logical widths are signed 32-bit integers; the SDK's int FAR*
// stores signed 16-bit values. A result outside that range has no verified
// historical overflow contract here: fail the entire query rather than
// reporting a fabricated wrapped/saturated width. Encoding stays private until
// every element has passed, so overflow never leaves a partial guest array.
fn encode_char_widths(entries: &[i32]) -> Option<Vec<u8>> {
    let capacity = entries.len().checked_mul(2)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).ok()?;
    for width in entries {
        bytes.extend_from_slice(&i16::try_from(*width).ok()?.to_le_bytes());
    }
    Some(bytes)
}

#[cfg(test)]
#[path = "win16_gdi_char_width_tests.rs"]
mod char_width_tests;

#[cfg(test)]
#[path = "win16_gdi_services_wire_tests.rs"]
mod wire_tests;

#[cfg(test)]
#[path = "win16_gdi_scalable_font_tests.rs"]
mod scalable_font_tests;

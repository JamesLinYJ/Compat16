//! Stack decoding for the remaining GDI ordinals.

use guest_core::GuestMemory;

use super::super::request::{Win16GdiInternalArg as Arg, Win16GdiInternalRequest as Request};
use super::super::{Win16ExportDescriptor, Win16ParameterType};
use crate::{SelectorTable, Win16Argument, Win16Error};

/// Inclusive binding block claimed for these GDI ordinals.
const GDI_INTERNAL_ID_FIRST: u32 = 3_000_000;
const GDI_INTERNAL_ID_LAST: u32 = 3_000_206;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    let id = descriptor.id as u32;
    if !(GDI_INTERNAL_ID_FIRST..=GDI_INTERNAL_ID_LAST).contains(&id) {
        return Ok(None);
    }
    if !descriptor.module().eq_ignore_ascii_case("GDI") {
        return Err(Win16Error::InvalidRange);
    }
    if descriptor.parameters.len() != arguments.len() {
        return Err(Win16Error::InvalidRange);
    }
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(arguments.len())
        .map_err(|_| Win16Error::OutOfMemory)?;
    for (parameter, argument) in descriptor.parameters.iter().zip(arguments) {
        decoded.push(match parameter.parameter_type {
            Win16ParameterType::Scalar | Win16ParameterType::SignedScalar => match argument {
                Win16Argument::Word(value) => Arg::Word(*value),
                Win16Argument::Dword(value) => Arg::Dword(*value),
                Win16Argument::Byte(value) => Arg::Word(u16::from(*value)),
            },
            Win16ParameterType::FarString => {
                Arg::Ansi(Some(read_ansi(dword(argument)?, selectors, memory)?))
            }
            Win16ParameterType::NullableFarString => {
                let far = dword(argument)?;
                Arg::Ansi(if far == 0 {
                    None
                } else {
                    Some(read_ansi(far, selectors, memory)?)
                })
            }
            Win16ParameterType::FarPointer
            | Win16ParameterType::FarBuffer
            | Win16ParameterType::FarOutputBuffer
            | Win16ParameterType::FarStringOrChar
            | Win16ParameterType::ResourceName
            | Win16ParameterType::AtomName
            | Win16ParameterType::ClassName => Arg::Far(dword(argument)?),
        });
    }
    Ok(Some(Request {
        ordinal: descriptor.ordinal(),
        arguments: decoded,
    }))
}

fn dword(argument: &Win16Argument) -> Result<u32, Win16Error> {
    match argument {
        Win16Argument::Dword(value) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn read_ansi(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    crate::strings::read_ansi_z(selectors, memory, far, crate::MAX_WIN16_STRING_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exports::{ExportEntryKind, ExportImplementationState, ExportSignatureKind};
    use crate::{
        AccessRights, ExportLookupTarget, ReturnAddressWidth, SegmentedPointer, SelectorTable,
        Win16CallFrame, Win16ReturnKind, decode_export_call, lookup_export,
    };
    use guest_core::{GuestMemory, PhysAddr, memory::Memory};

    #[test]
    fn gdi_exports_keep_unknown_frames_declaration_only() {
        let mut exports = 0;
        for group in crate::exports::WIN16_EXPORTS {
            for entry in *group {
                if entry.module != "GDI" {
                    continue;
                }
                exports += 1;
                let resolved = crate::exports::resolve_export(
                    b"GDI",
                    ExportLookupTarget::Ordinal(entry.ordinal),
                )
                .unwrap_or_else(|| panic!("GDI.{} missing", entry.ordinal));
                let unknown_frame = entry.kind == ExportEntryKind::Stub
                    && entry.abi.is_some_and(|abi| {
                        abi.signature == ExportSignatureKind::Unknown && abi.arguments.is_empty()
                    });
                let expected = if unknown_frame {
                    ExportImplementationState::DeclaredOnly
                } else {
                    ExportImplementationState::BoundToRequest
                };
                assert_eq!(
                    resolved.state,
                    expected,
                    "GDI.{} {}",
                    entry.ordinal,
                    entry.name.unwrap_or("")
                );
            }
        }
        assert!(exports > 0);
    }

    #[test]
    fn set_rel_abs_frame_is_far_pascal_and_bitmapbits_has_no_descriptor() {
        let set_rel_abs = lookup_export(b"GDI", ExportLookupTarget::Ordinal(5)).unwrap();
        assert_eq!(set_rel_abs.return_kind, Win16ReturnKind::Word);
        assert_eq!(set_rel_abs.parameters.len(), 2);
        assert!((GDI_INTERNAL_ID_FIRST..=GDI_INTERNAL_ID_LAST).contains(&(set_rel_abs.id as u32)));
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors
            .alloc_block(PhysAddr(0x1000), 8, AccessRights::read_write(), &memory)
            .unwrap();
        let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&0x0100_u16.to_le_bytes());
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        let decoded = decode_export_call(
            set_rel_abs,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors,
            &memory,
        )
        .unwrap();
        let crate::Win16ApiRequest::GdiInternal(request) = decoded.request else {
            panic!("SetRelAbs request");
        };
        assert_eq!(request.ordinal, 5);
        assert_eq!(request.arguments, vec![Arg::Word(0x0100), Arg::Word(2)]);
        assert_eq!(decoded.stack_cleanup.callee_pop_bytes, 4);

        let bits = crate::exports::resolve_export(b"GDI", ExportLookupTarget::Ordinal(46)).unwrap();
        assert_eq!(bits.state, ExportImplementationState::DeclaredOnly);
        assert!(bits.descriptor.is_none());
        assert!(lookup_export(b"GDI", ExportLookupTarget::Ordinal(46)).is_none());
        let entry = lookup_export(b"GDI", ExportLookupTarget::Ordinal(5000)).unwrap();
        assert_eq!(entry.return_kind, Win16ReturnKind::Dword);
        assert_eq!(entry.parameters.len(), 6);
    }
}

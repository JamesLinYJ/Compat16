//! Stack decoding for driver and deferred-device exports.
//!
//! Binding ids `5000000`–`5999999` belong to COMM, DISPLAY, KEYBOARD, MOUSE,
//! SOUND, SYSTEM, TIMER, WINSPOOL, PENWIN, STRESS, MSVIDEO, DISPDIB, and AVIFILE.

use super::super::request::{Win16DriverArg as Arg, Win16DriverCall as Call};
use super::super::{Win16ExportDescriptor, Win16ParameterType};
use crate::{Win16Argument, Win16Error};

/// Inclusive binding block claimed for these driver ordinals.
pub(super) const DRIVER_ID_FIRST: u32 = 5_000_000;
pub(super) const DRIVER_ID_LAST: u32 = 5_000_305;

const MODULES: &[&str] = &[
    "COMM", "DISPLAY", "KEYBOARD", "MOUSE", "SOUND", "SYSTEM", "TIMER", "WINSPOOL", "PENWIN",
    "STRESS", "MSVIDEO", "DISPDIB", "AVIFILE",
];

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
) -> Result<Option<Call>, Win16Error> {
    let id = descriptor.id as u32;
    if !(DRIVER_ID_FIRST..=DRIVER_ID_LAST).contains(&id) {
        return Ok(None);
    }
    if !MODULES
        .iter()
        .any(|module| descriptor.module().eq_ignore_ascii_case(module))
    {
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
            Win16ParameterType::FarString
            | Win16ParameterType::NullableFarString
            | Win16ParameterType::FarPointer
            | Win16ParameterType::FarBuffer
            | Win16ParameterType::FarOutputBuffer
            | Win16ParameterType::FarStringOrChar
            | Win16ParameterType::ResourceName
            | Win16ParameterType::AtomName
            | Win16ParameterType::ClassName => Arg::Dword(dword(argument)?),
        });
    }
    Ok(Some(Call { arguments: decoded }))
}

fn dword(argument: &Win16Argument) -> Result<u32, Win16Error> {
    match argument {
        Win16Argument::Dword(value) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exports::{ExportEntryKind, ExportImplementationState};
    use crate::{
        AccessRights, ExportLookupTarget, ReturnAddressWidth, SegmentedPointer, SelectorTable,
        Win16CallFrame, Win16ReturnKind, decode_export_call, lookup_export,
    };
    use guest_core::{GuestMemory, PhysAddr, memory::Memory};

    const OWNED: &[&str] = MODULES;

    #[test]
    fn every_owned_export_is_bound_or_kept_as_data() {
        let mut seen = 0;
        for group in crate::exports::WIN16_EXPORTS {
            for entry in *group {
                if !OWNED.iter().any(|module| entry.module == *module) {
                    continue;
                }
                seen += 1;
                let resolved = crate::exports::resolve_export(
                    entry.module.as_bytes(),
                    ExportLookupTarget::Ordinal(entry.ordinal),
                )
                .unwrap_or_else(|| panic!("{}:{} missing", entry.module, entry.ordinal));
                let data = matches!(
                    entry.kind,
                    ExportEntryKind::Variable | ExportEntryKind::Equate
                );
                let expected = if data {
                    ExportImplementationState::DeclaredOnly
                } else {
                    ExportImplementationState::BoundToRequest
                };
                assert_eq!(
                    resolved.state,
                    expected,
                    "{}:{} {}",
                    entry.module,
                    entry.ordinal,
                    entry.name.unwrap_or("")
                );
                if !data {
                    assert!(resolved.descriptor.is_some());
                }
            }
        }
        assert!(seen > 300);
    }

    #[test]
    fn comm_stub_pops_nothing_and_display_dib_pops_its_frame() {
        let comm = lookup_export(b"COMM", ExportLookupTarget::Ordinal(1)).unwrap();
        assert_eq!(comm.return_kind, Win16ReturnKind::Dword);
        assert!(comm.parameters.is_empty());
        assert!((DRIVER_ID_FIRST..=DRIVER_ID_LAST).contains(&(comm.id as u32)));

        let display = lookup_export(b"DISPDIB", ExportLookupTarget::Ordinal(1)).unwrap();
        assert_eq!(display.return_kind, Win16ReturnKind::Word);
        assert_eq!(display.parameters.len(), 3);
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors
            .alloc_block(PhysAddr(0x1000), 32, AccessRights::read_write(), &memory)
            .unwrap();
        let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
        bytes.extend_from_slice(&3_u16.to_le_bytes());
        bytes.extend_from_slice(&0x2222_1111_u32.to_le_bytes());
        bytes.extend_from_slice(&0x4444_3333_u32.to_le_bytes());
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        let decoded = decode_export_call(
            display,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors,
            &memory,
        )
        .unwrap();
        let crate::Win16ApiRequest::Driver(request) = decoded.request else {
            panic!("DisplayDib request");
        };
        assert_eq!(
            request.arguments,
            vec![
                Arg::Dword(0x4444_3333),
                Arg::Dword(0x2222_1111),
                Arg::Word(3),
            ]
        );
        assert_eq!(decoded.stack_cleanup.callee_pop_bytes, 10);
    }
}

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

    #[test]
    fn unknown_driver_frames_are_not_callable_and_avi_guids_remain_data() {
        for (module, ordinal) in [
            ("COMM", 1),
            ("DISPLAY", 1),
            ("KEYBOARD", 9),
            ("MOUSE", 4),
            ("SOUND", 17),
            ("SYSTEM", 13),
            ("WINSPOOL", 1000),
            ("MSVIDEO", 240),
            ("AVIFILE", 4),
        ] {
            let resolved = crate::exports::resolve_export(
                module.as_bytes(),
                ExportLookupTarget::Ordinal(ordinal),
            )
            .unwrap();
            assert_eq!(resolved.state, ExportImplementationState::DeclaredOnly);
            assert!(resolved.descriptor.is_none(), "{module}:{ordinal}");
        }
        for ordinal in 10..=14 {
            let resolved =
                crate::exports::resolve_export(b"AVIFILE", ExportLookupTarget::Ordinal(ordinal))
                    .unwrap();
            assert_eq!(resolved.declaration.kind, ExportEntryKind::Variable);
            assert!(crate::exports::lookup_data_export_source(resolved.declaration).is_some());
        }
    }

    #[test]
    fn display_dib_pops_its_frame() {
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

    #[test]
    fn avi_constructor_frames_follow_the_win16_sdk() {
        for (ordinal, arguments, pop) in [
            (
                2,
                vec![
                    Arg::Dword(0x1111_0001),
                    Arg::Dword(0x2222_0002),
                    Arg::Dword(0x3333_0003),
                ],
                12,
            ),
            (
                105,
                vec![
                    Arg::Dword(0x1111_0001),
                    Arg::Dword(0x2222_0002),
                    Arg::Dword(0x3333_0003),
                    Arg::Dword(0x4444_0004),
                ],
                16,
            ),
            (
                106,
                vec![
                    Arg::Dword(0x1111_0001),
                    Arg::Word(2),
                    Arg::Dword(0x3333_0003),
                ],
                10,
            ),
            (
                107,
                vec![Arg::Word(3), Arg::Word(4), Arg::Dword(0x3333_0003)],
                8,
            ),
        ] {
            let descriptor =
                lookup_export(b"AVIFILE", ExportLookupTarget::Ordinal(ordinal)).unwrap();
            let mut memory = Memory::with_size(0x10_0000).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let stack = selectors
                .alloc_block(PhysAddr(0x1000), 64, AccessRights::read_write(), &memory)
                .unwrap();
            let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
            for argument in arguments.iter().rev() {
                match argument {
                    Arg::Word(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                    Arg::Dword(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                }
            }
            memory.write(PhysAddr(0x1000), &bytes).unwrap();
            let decoded = decode_export_call(
                descriptor,
                Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
                &selectors,
                &memory,
            )
            .unwrap();
            let crate::Win16ApiRequest::Driver(request) = decoded.request else {
                panic!("AVI request")
            };
            assert_eq!(request.arguments, arguments);
            assert_eq!(decoded.stack_cleanup.callee_pop_bytes, pop);
        }
    }
}

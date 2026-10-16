//! Independent SDK-backed USER.233 identity and physical Pascal frame coverage.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup,
    Win16ApiRequest, Win16CallFrame, Win16ExportAbiKind, Win16ExportId,
    Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind,
    Win16WindowDataRequest, decode_export_call, lookup_export,
};
use crate::exports::{
    ExportArgumentType, ExportImplementationState, ExportReturnModifier,
    lookup_export_metadata, resolve_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

const CLEANUP: StackCleanup = StackCleanup { callee_pop_bytes: 4, caller_pop_bytes: 0 };

#[test]
fn set_parent_descriptor_matches_original_sdk_word_pascal_contract() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(233)).unwrap();
    assert_eq!(descriptor, lookup_export(b"user.exe", ExportLookupTarget::Name(b"SETPARENT")).unwrap());
    assert_eq!(descriptor.id, Win16ExportId::UserSetParent);
    assert_eq!(descriptor.name(), "SetParent");
    assert_eq!(descriptor.module(), "USER");
    assert_eq!(descriptor.ordinal(), 233);
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(CLEANUP));
    assert_eq!(descriptor.parameters.len(), 2);
    assert_eq!(descriptor.parameters[0].kind, ArgumentKind::Word);
    assert_eq!(descriptor.parameters[0].parameter_type, Win16ParameterType::Scalar);
    assert_eq!(descriptor.parameters[1].kind, ArgumentKind::Word);
    assert_eq!(descriptor.parameters[1].parameter_type, Win16ParameterType::Scalar);
    let metadata = lookup_export_metadata(b"USER", ExportLookupTarget::Ordinal(233)).unwrap();
    let abi = metadata.abi.unwrap();
    assert_eq!(abi.arguments, &[ExportArgumentType::Word, ExportArgumentType::Word]);
    assert_eq!(abi.return_modifier, ExportReturnModifier::Ret16);
    assert_eq!(resolve_export(b"USER", ExportLookupTarget::Ordinal(233)).unwrap().state,
        ExportImplementationState::BoundToRequest);
}

#[test]
fn set_parent_decodes_two_words_in_physical_pascal_order() {
    for (window, parent) in [(0_u16, 0_u16), (1, 0), (0x8765, 0xabcd), (u16::MAX, 1)] {
        for stack_size in 4..=8 {
            let mut memory = Memory::with_size(0x10_0000).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let stack = selectors.alloc_block(PhysAddr(0x1000), stack_size,
                AccessRights::read_write(), &memory).unwrap();
            let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
            bytes.extend_from_slice(&parent.to_le_bytes());
            bytes.extend_from_slice(&window.to_le_bytes());
            memory.write(PhysAddr(0x1000), &bytes).unwrap();
            let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(233)).unwrap();
            let decoded = decode_export_call(descriptor,
                Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
                &selectors, &memory);
            if stack_size < 8 {
                assert!(decoded.is_err(), "partial HWND slots must not decode");
            } else {
                let decoded = decoded.unwrap();
                assert_eq!(decoded.stack_cleanup, CLEANUP);
                assert_eq!(decoded.request, Win16ApiRequest::WindowData(
                    Win16WindowDataRequest::SetParent { window, parent },
                ));
            }
            let mut unchanged = [0; 8];
            memory.read(PhysAddr(0x1000), &mut unchanged).unwrap();
            assert_eq!(unchanged.as_slice(), bytes.as_slice());
        }
    }
}

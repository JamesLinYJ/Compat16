//! Independent SDK-backed USER.44 identity and physical Pascal frame coverage.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup,
    Win16ApiRequest, Win16CallFrame, Win16ExportAbiKind, Win16ExportId,
    Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind,
    Win16UserRequest, Win16UserWindowRequest, decode_export_call, lookup_export,
};
use crate::exports::{
    ExportArgumentType, ExportImplementationState, ExportReturnModifier,
    lookup_export_metadata, resolve_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

const CLEANUP: StackCleanup = StackCleanup { callee_pop_bytes: 2, caller_pop_bytes: 0 };

#[test]
fn open_icon_descriptor_matches_original_sdk_word_pascal_contract() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(44)).unwrap();
    assert_eq!(descriptor, lookup_export(b"user.exe", ExportLookupTarget::Name(b"OPENICON")).unwrap());
    assert_eq!(descriptor.id, Win16ExportId::UserOpenIcon);
    assert_eq!(descriptor.name(), "OpenIcon");
    assert_eq!(descriptor.module(), "USER");
    assert_eq!(descriptor.ordinal(), 44);
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(CLEANUP));
    assert_eq!(descriptor.parameters.len(), 1);
    assert_eq!(descriptor.parameters[0].kind, ArgumentKind::Word);
    assert_eq!(descriptor.parameters[0].parameter_type, Win16ParameterType::Scalar);
    let metadata = lookup_export_metadata(b"USER", ExportLookupTarget::Ordinal(44)).unwrap();
    let abi = metadata.abi.unwrap();
    assert_eq!(abi.arguments, &[ExportArgumentType::Word]);
    assert_eq!(abi.return_modifier, ExportReturnModifier::Ret16);
    assert_eq!(resolve_export(b"USER", ExportLookupTarget::Ordinal(44)).unwrap().state,
        ExportImplementationState::BoundToRequest);
}

#[test]
fn open_icon_decodes_one_word_and_rejects_truncated_selector_frame() {
    for handle in [0_u16, 1, 0x8765, u16::MAX] {
        for stack_size in [4, 5, 6] {
            // Backing stays above the ROM boundary; only selector bounds vary.
            let mut memory = Memory::with_size(0x10_0000).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let stack = selectors.alloc_block(PhysAddr(0x1000), stack_size,
                AccessRights::read_write(), &memory).unwrap();
            let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
            bytes.extend_from_slice(&handle.to_le_bytes());
            memory.write(PhysAddr(0x1000), &bytes).unwrap();
            let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(44)).unwrap();
            let decoded = decode_export_call(descriptor,
                Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
                &selectors, &memory);
            if stack_size < 6 {
                assert!(decoded.is_err(), "a partial HWND slot must not decode");
            } else {
                let decoded = decoded.unwrap();
                assert_eq!(decoded.stack_cleanup, CLEANUP);
                assert_eq!(decoded.request, Win16ApiRequest::User(Win16UserRequest::Window(
                    Win16UserWindowRequest::OpenIcon { window: handle },
                )));
            }
            let mut unchanged = [0; 6];
            memory.read(PhysAddr(0x1000), &mut unchanged).unwrap();
            assert_eq!(unchanged.as_slice(), bytes.as_slice());
        }
    }
}

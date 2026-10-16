//! Independently sourced GDI.350 ABI and physical Pascal frame coverage.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16CallFrame, Win16Error, Win16ExportAbiKind, Win16ExportId, Win16ExportStackCleanup,
    Win16GdiServicesRequest, Win16ParameterType, Win16ReturnKind, decode_export_call,
    lookup_export,
};
use crate::exports::GDI_GET_CHAR_WIDTH;
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn get_char_width_catalog_matches_sdk_import_and_prototype() {
    let descriptor = &GDI_GET_CHAR_WIDTH;
    assert_eq!(descriptor.id, Win16ExportId::GdiGetCharWidth);
    assert_eq!(descriptor.module(), "GDI");
    assert_eq!(descriptor.ordinal(), 350);
    assert_eq!(descriptor.name(), "GetCharWidth");
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 10, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.len(), 4);
    for parameter in &descriptor.parameters[..3] {
        assert_eq!(parameter.kind, ArgumentKind::Word);
    }
    assert_eq!(descriptor.parameters[3].kind, ArgumentKind::Dword);
    assert_eq!(descriptor.parameters[3].parameter_type, Win16ParameterType::FarOutputBuffer);
    assert_eq!(lookup_export(b"GDI", ExportLookupTarget::Ordinal(350)), Some(descriptor));
    assert_eq!(lookup_export(b"GDI", ExportLookupTarget::Name(b"GetCharWidth")), Some(descriptor));
}

#[test]
fn get_char_width_physical_frame_preserves_unsigned_range_and_far_output() {
    for (first, last) in [(0x41_u16, 0x43_u16), (0x8000, 0xffff), (0xffff, 0), (0, 0xffff)] {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors.alloc_block(PhysAddr(0x1000), 14, AccessRights::read_write(), &memory).unwrap();
        let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
        // Pascal: return IP:CS, output offset:selector, last, first, HDC.
        bytes.extend_from_slice(&0xabcd_f012_u32.to_le_bytes());
        bytes.extend_from_slice(&last.to_le_bytes());
        bytes.extend_from_slice(&first.to_le_bytes());
        bytes.extend_from_slice(&0x8765_u16.to_le_bytes());
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        let decoded = decode_export_call(&GDI_GET_CHAR_WIDTH,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors, &memory).unwrap();
        assert_eq!(decoded.request, Win16ApiRequest::GdiServices(Win16GdiServicesRequest::GetCharWidth {
            dc: 0x8765, first, last, output: 0xabcd_f012,
        }));
        assert_eq!(decoded.stack_cleanup, StackCleanup { callee_pop_bytes: 10, caller_pop_bytes: 0 });
    }
}

#[test]
fn get_char_width_physical_frame_rejects_truncated_word_slot() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), 13, AccessRights::read_write(), &memory).unwrap();
    memory.write(PhysAddr(0x1000), &[0; 14]).unwrap();
    assert!(matches!(decode_export_call(&GDI_GET_CHAR_WIDTH,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors, &memory), Err(Win16Error::LimitViolation { .. })));
}

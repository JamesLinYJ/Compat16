//! USER.221: Windows 3.1 SDK ScrollDC prototype and physical Pascal frame.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16CallFrame, Win16Error, Win16ExportAbiKind, Win16ExportId, Win16ExportStackCleanup,
    Win16ParameterType, Win16ReturnKind, decode_export_call, lookup_export,
};
use crate::exports::{USER_SCROLL_DC, Win16UserUpdateRequest};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn scroll_dc_catalog_matches_sdk_prototype_and_import() {
    let descriptor = &USER_SCROLL_DC;
    assert_eq!(descriptor.id, Win16ExportId::UserScrollDC);
    assert_eq!(descriptor.module(), "USER");
    assert_eq!(descriptor.ordinal(), 221);
    assert_eq!(descriptor.name(), "ScrollDC");
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 20, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.iter().map(|p| p.kind).collect::<Vec<_>>(),
        [ArgumentKind::Word, ArgumentKind::Word, ArgumentKind::Word,
         ArgumentKind::Dword, ArgumentKind::Dword, ArgumentKind::Word, ArgumentKind::Dword]);
    assert_eq!(descriptor.parameters[1].parameter_type, Win16ParameterType::SignedScalar);
    assert_eq!(descriptor.parameters[2].parameter_type, Win16ParameterType::SignedScalar);
    assert_eq!(descriptor.parameters[6].parameter_type, Win16ParameterType::FarOutputBuffer);
    assert_eq!(lookup_export(b"USER", ExportLookupTarget::Ordinal(221)), Some(descriptor));
    assert_eq!(lookup_export(b"USER", ExportLookupTarget::Name(b"ScrollDC")), Some(descriptor));
}

#[test]
fn scroll_dc_physical_pascal_frame_keeps_signed_deltas_and_nullable_far_values() {
    for (dx, dy, scroll_rect, clip_rect, update_region, update_rect) in [
        (-32768_i16, 32767_i16, 0xfedc_1234_u32, 0xabcd_5678_u32, 0x9876_u16, 0xface_2345_u32),
        (-1, -2, 0, 0, 0, 0),
    ] {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors.alloc_block(PhysAddr(0x1000), 24, AccessRights::read_write(), &memory).unwrap();
        let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
        // Pascal: return IP:CS, then arguments in reverse declaration order.
        bytes.extend_from_slice(&update_rect.to_le_bytes());
        bytes.extend_from_slice(&update_region.to_le_bytes());
        bytes.extend_from_slice(&clip_rect.to_le_bytes());
        bytes.extend_from_slice(&scroll_rect.to_le_bytes());
        bytes.extend_from_slice(&dy.to_le_bytes());
        bytes.extend_from_slice(&dx.to_le_bytes());
        bytes.extend_from_slice(&0x8765_u16.to_le_bytes());
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        let decoded = decode_export_call(&USER_SCROLL_DC,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors, &memory).unwrap();
        assert_eq!(decoded.request, Win16ApiRequest::UserUpdate(Win16UserUpdateRequest::ScrollDC {
            dc: 0x8765, dx, dy, scroll_rect, clip_rect, update_region, update_rect,
        }));
        assert_eq!(decoded.stack_cleanup, StackCleanup { callee_pop_bytes: 20, caller_pop_bytes: 0 });
    }
}

#[test]
fn scroll_dc_physical_frame_rejects_truncated_hdc_slot() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), 23, AccessRights::read_write(), &memory).unwrap();
    memory.write(PhysAddr(0x1000), &[0; 24]).unwrap();
    assert!(matches!(decode_export_call(&USER_SCROLL_DC,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors, &memory), Err(Win16Error::LimitViolation { .. })));
}

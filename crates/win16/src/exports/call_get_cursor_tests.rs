//! Original Windows 3.1 SDK WINDOWS.H: HCURSOR WINAPI GetCursor(void), USER.247.
use crate::{
    AccessRights, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest, Win16CallFrame,
    Win16ExportAbiKind, Win16ExportId, Win16ExportStackCleanup, Win16ReturnKind,
    Win16UserCursorAcceleratorRequest, decode_export_call, lookup_export,
};
use crate::exports::{ExportImplementationState, resolve_export};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn get_cursor_descriptor_and_zero_argument_pascal_frame_match_original_sdk() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(247)).unwrap();
    assert_eq!(descriptor, lookup_export(b"user.exe", ExportLookupTarget::Name(b"GETCURSOR")).unwrap());
    assert_eq!(descriptor.id, Win16ExportId::UserGetCursor);
    assert_eq!(descriptor.name(), "GetCursor");
    assert_eq!(descriptor.ordinal(), 247);
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert!(descriptor.parameters.is_empty());
    let cleanup = StackCleanup { callee_pop_bytes: 0, caller_pop_bytes: 0 };
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(cleanup));
    assert_eq!(resolve_export(b"USER", ExportLookupTarget::Ordinal(247)).unwrap().state,
        ExportImplementationState::BoundToRequest);
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), 4,
        AccessRights::read_write(), &memory).unwrap();
    let bytes = [0x34, 0x12, 0x78, 0x56];
    memory.write(PhysAddr(0x1000), &bytes).unwrap();
    let decoded = decode_export_call(descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors, &memory).unwrap();
    assert_eq!(decoded.stack_cleanup, cleanup);
    assert_eq!(decoded.request, Win16ApiRequest::UserCursorAccelerator(
        Win16UserCursorAcceleratorRequest::GetCursor));
    let mut actual = [0; 4];
    memory.read(PhysAddr(0x1000), &mut actual).unwrap();
    assert_eq!(actual, bytes);
}

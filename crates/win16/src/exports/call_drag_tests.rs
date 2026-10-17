//! USER.86 IconSize, USER.464 DragObject, and USER.465 DragDetect frames.
use crate::exports::{ExportImplementationState, resolve_export};
use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest, Win16CallFrame,
    Win16ExportId, Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind,
    Win16UserSystemRequest, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

fn fixed(pop: u16) -> Win16ExportStackCleanup {
    Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: pop,
        caller_pop_bytes: 0,
    })
}

#[test]
fn icon_size_is_a_dword_with_no_arguments() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(86)).unwrap();
    assert_eq!(
        descriptor,
        lookup_export(b"user.exe", ExportLookupTarget::Name(b"ICONSIZE")).unwrap()
    );
    assert_eq!(descriptor.id, Win16ExportId::UserIconSize);
    assert_eq!(descriptor.ordinal(), 86);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Dword);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert!(descriptor.parameters.is_empty());
    assert_eq!(descriptor.stack_cleanup, fixed(0));
    assert_eq!(
        resolve_export(b"USER", ExportLookupTarget::Ordinal(86))
            .unwrap()
            .state,
        ExportImplementationState::BoundToRequest
    );
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 4, AccessRights::read_write(), &memory)
        .unwrap();
    let bytes = [0x34, 0x12, 0x78, 0x56];
    memory.write(PhysAddr(0x1000), &bytes).unwrap();
    let decoded = decode_export_call(
        descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors,
        &memory,
    )
    .unwrap();
    assert_eq!(decoded.stack_cleanup, StackCleanup { callee_pop_bytes: 0, caller_pop_bytes: 0 });
    assert_eq!(decoded.request, Win16ApiRequest::UserSystem(Win16UserSystemRequest::IconSize));
    let mut actual = [0; 4];
    memory.read(PhysAddr(0x1000), &mut actual).unwrap();
    assert_eq!(actual, bytes);
}

#[test]
fn drag_object_decodes_twelve_byte_pascal_frame_as_scalars() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(464)).unwrap();
    assert_eq!(descriptor.id, Win16ExportId::UserDragObject);
    assert_eq!(descriptor.name(), "DragObject");
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Dword);
    assert_eq!(descriptor.parameters.len(), 5);
    assert_eq!(descriptor.parameters[3].kind, ArgumentKind::Dword);
    assert_eq!(descriptor.parameters[3].parameter_type, Win16ParameterType::Scalar);
    assert_eq!(descriptor.stack_cleanup, fixed(12));
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 16, AccessRights::read_write(), &memory)
        .unwrap();
    let mut frame = [0_u8; 16];
    frame[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    frame[6..10].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    frame[10..12].copy_from_slice(&0x0007u16.to_le_bytes());
    frame[12..14].copy_from_slice(&0x2222u16.to_le_bytes());
    frame[14..16].copy_from_slice(&0x1111u16.to_le_bytes());
    memory.write(PhysAddr(0x1000), &frame).unwrap();
    let decoded = decode_export_call(
        descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors,
        &memory,
    )
    .unwrap();
    assert_eq!(
        decoded.request,
        Win16ApiRequest::UserSystem(Win16UserSystemRequest::DragObject {
            parent: 0x1111,
            source: 0x2222,
            format: 7,
            data: 0xDEAD_BEEF,
            cursor: 0xFFFF,
        })
    );
    let mut actual = [0; 16];
    memory.read(PhysAddr(0x1000), &mut actual).unwrap();
    assert_eq!(actual, frame);
}

#[test]
fn drag_detect_decodes_hwnd_and_screen_point() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(465)).unwrap();
    assert_eq!(
        descriptor,
        lookup_export(b"USER", ExportLookupTarget::Name(b"dragdetect")).unwrap()
    );
    assert_eq!(descriptor.id, Win16ExportId::UserDragDetect);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.parameters.len(), 2);
    assert_eq!(descriptor.parameters[1].kind, ArgumentKind::Dword);
    assert_eq!(descriptor.stack_cleanup, fixed(6));
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 10, AccessRights::read_write(), &memory)
        .unwrap();
    let mut frame = [0_u8; 10];
    frame[4..6].copy_from_slice(&(-2_i16).to_le_bytes());
    frame[6..8].copy_from_slice(&7_i16.to_le_bytes());
    frame[8..10].copy_from_slice(&0x0042u16.to_le_bytes());
    memory.write(PhysAddr(0x1000), &frame).unwrap();
    let decoded = decode_export_call(
        descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors,
        &memory,
    )
    .unwrap();
    assert_eq!(
        decoded.request,
        Win16ApiRequest::UserSystem(Win16UserSystemRequest::DragDetect {
            window: 0x0042,
            x: -2,
            y: 7,
        })
    );
}

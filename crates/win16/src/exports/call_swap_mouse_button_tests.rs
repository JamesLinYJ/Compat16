//! Win16 USER.186 SwapMouseButton ABI and argument decoding.

use crate::{
    AccessRights, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorTable, Win16ApiRequest, Win16CallFrame, Win16ExportId,
    Win16ReturnKind, Win16UserSystemRequest, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn swap_mouse_button_matches_win31_abi_and_decodes_nonzero_bool() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(186)).unwrap();
    assert_eq!(descriptor.id, Win16ExportId::UserSwapMouseButton);
    assert_eq!(
        descriptor.calling_convention,
        ExportCallingConvention::Pascal
    );
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.parameters.len(), 1);

    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 6, AccessRights::read_write(), &memory)
        .unwrap();
    let mut frame = [0_u8; 6];
    frame[4..6].copy_from_slice(&(-1_i16).to_le_bytes());
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
        Win16ApiRequest::UserSystem(Win16UserSystemRequest::SwapMouseButton { swap: true })
    );
}

#[test]
fn swap_mouse_button_decodes_zero_as_false() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(186)).unwrap();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 6, AccessRights::read_write(), &memory)
        .unwrap();
    let frame = [0_u8; 6];
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
        Win16ApiRequest::UserSystem(Win16UserSystemRequest::SwapMouseButton { swap: false })
    );
}

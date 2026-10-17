//! Register-image decoding for USER.289 keybd_event and USER.299 mouse_event.

use super::*;
use crate::{
    AccessRights, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorTable, Win16CallFrame, Win16Error, Win16ExportAbiKind,
    Win16ExportStackCleanup, Win16RegisterContext, Win16ReturnKind, Win16UserInputRequest,
    Win16UserRequest, decode_export_call, decode_export_call_with_register_context, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

fn context(values: [u32; 6]) -> Win16RegisterContext {
    Win16RegisterContext {
        eax: values[0],
        ebx: values[1],
        ecx: values[2],
        edx: values[3],
        esi: values[4],
        edi: values[5],
        ..Win16RegisterContext::default()
    }
}

fn decode(ordinal: u16, registers: Win16RegisterContext) -> DecodedWin16Call {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 16, AccessRights::read_write(), &memory)
        .unwrap();
    memory.write(PhysAddr(0x1000), &[0; 16]).unwrap();
    decode_export_call_with_register_context(
        descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        registers,
        &selectors,
        &memory,
    )
    .unwrap()
}

#[test]
fn keybd_event_is_a_register_export_and_promotes_only_the_driver_flag_bits() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(289)).unwrap();
    assert_eq!(descriptor.id, Win16ExportId::UserKeybdEvent);
    assert_eq!(descriptor.name(), "keybd_event");
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::RegisterContext);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::RegisterContext);
    assert_eq!(
        descriptor.calling_convention,
        ExportCallingConvention::Pascal
    );
    assert!(descriptor.parameters.is_empty());
    assert!(matches!(
        descriptor.stack_cleanup,
        Win16ExportStackCleanup::Fixed(cleanup)
            if cleanup.callee_pop_bytes == 0 && cleanup.caller_pop_bytes == 0
    ));

    let decoded = decode(
        289,
        context([0x7fff_0041, 0x00fe_001c, 0, 0, 0xaaaa_1111, 0xbbbb_2222]),
    );
    assert_eq!(
        decoded.request,
        Win16ApiRequest::User(Win16UserRequest::Input(Win16UserInputRequest::KeybdEvent {
            virtual_key: 0x41,
            scan: 0x1c,
            flags: 0,
            extra_info: 0x2222_1111,
        }))
    );

    let decoded = decode(
        289,
        context([0x0000_8041, 0x0000_011e, 9, 9, 0x0000_00ab, 0x0000_00cd]),
    );
    assert_eq!(
        decoded.request,
        Win16ApiRequest::User(Win16UserRequest::Input(Win16UserInputRequest::KeybdEvent {
            virtual_key: 0x41,
            scan: 0x1e,
            flags: 0x0001 | 0x0002,
            extra_info: 0x00cd_00ab,
        }))
    );
}

#[test]
fn mouse_event_keeps_absolute_coordinates_and_sign_extends_relative_motion() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(299)).unwrap();
    assert_eq!(descriptor.id, Win16ExportId::UserMouseEvent);
    assert_eq!(descriptor.name(), "mouse_event");
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::RegisterContext);
    assert!(descriptor.parameters.is_empty());

    let decoded = decode(
        299,
        context([
            0x1111_8001,
            0x2222_9c40,
            0x3333_0001,
            0x4444_0002,
            0x5555_00aa,
            0x6666_00bb,
        ]),
    );
    assert_eq!(
        decoded.request,
        Win16ApiRequest::User(Win16UserRequest::Input(Win16UserInputRequest::MouseEvent {
            flags: 0x8001,
            dx: 0x9c40,
            dy: 1,
            buttons: 2,
            extra_info: 0x00bb_00aa,
        }))
    );

    let decoded = decode(
        299,
        context([0x0001, 0xffff, 0x0005, 0, 0xffff_ffff, 0xffff_ffff]),
    );
    assert_eq!(
        decoded.request,
        Win16ApiRequest::User(Win16UserRequest::Input(Win16UserInputRequest::MouseEvent {
            flags: 0x0001,
            dx: -1,
            dy: 5,
            buttons: 0,
            extra_info: 0xffff_ffff,
        }))
    );
}

#[test]
fn input_events_reject_a_pascal_stack_decoder() {
    for ordinal in [289, 299] {
        let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors
            .alloc_block(PhysAddr(0x1000), 16, AccessRights::read_write(), &memory)
            .unwrap();
        memory.write(PhysAddr(0x1000), &[0; 16]).unwrap();
        let error = decode_export_call(
            descriptor,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors,
            &memory,
        )
        .unwrap_err();
        assert!(matches!(error, Win16Error::RegisterContextRequired));
    }
}

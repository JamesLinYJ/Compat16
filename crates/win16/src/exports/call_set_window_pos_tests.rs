//! USER.232 keeps two HWND16 words, four signed coordinates and UINT16 flags.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup,
    Win16ApiRequest, Win16CallFrame, Win16Error, Win16ExportId,
    Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind,
    Win16UserGeometryRequest, Win16UserRequest, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

fn frame(insert_after: u16, flags: u16) -> Vec<u8> {
    let mut bytes = vec![0x34, 0x12, 0x78, 0x56]; // FAR return IP:CS
    // Physical Pascal order: flags, cy, cx, y, x, insert-after, window.
    for word in [flags, 0xffff, 0x8000, 0x7fff, 0xffed, insert_after, 0xa135] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn decode(bytes: &[u8], stack_bytes: u32) -> Result<Win16ApiRequest, Win16Error> {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), stack_bytes,
        AccessRights::read_write(), &memory).unwrap();
    memory.write(PhysAddr(0x1000), bytes).unwrap();
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(232)).unwrap();
    let decoded = decode_export_call(descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors, &memory)?;
    assert_eq!(decoded.export, Win16ExportId::UserSetWindowPos);
    assert_eq!(decoded.stack_cleanup, StackCleanup {
        callee_pop_bytes: 14, caller_pop_bytes: 0,
    });
    Ok(decoded.request)
}

#[test]
fn set_window_pos_catalog_preserves_word_bool_and_pascal_argument_contract() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(232)).unwrap();
    assert_eq!(lookup_export(b"USER", ExportLookupTarget::Name(b"SetWindowPos")), Some(descriptor));
    assert_eq!(descriptor.id, Win16ExportId::UserSetWindowPos);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 14, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.len(), 7);
    for (index, slot) in descriptor.parameters.iter().enumerate() {
        assert_eq!(slot.kind, ArgumentKind::Word);
        assert_eq!(slot.parameter_type, if (2..6).contains(&index) {
            Win16ParameterType::SignedScalar
        } else { Win16ParameterType::Scalar });
    }
}

#[test]
fn set_window_pos_decodes_signed_geometry_pseudo_handles_and_ignored_bits() {
    for insert_after in [0, 1, 0xffff, 0xfffe, 0x3456, 0xdead] {
        for flags in [0, 4, 0x8013, 0xffff] {
            let bytes = frame(insert_after, flags);
            assert_eq!(decode(&bytes, bytes.len() as u32).unwrap(),
                Win16ApiRequest::User(Win16UserRequest::Geometry(
                    Win16UserGeometryRequest::SetWindowPos {
                        window: 0xa135, insert_after, x: -19, y: i16::MAX,
                        width: i16::MIN, height: -1, flags,
                    })));
        }
    }
}

#[test]
fn set_window_pos_rejects_every_truncated_argument_frame() {
    let bytes = frame(0x3456, 4);
    for length in 4..bytes.len() {
        assert!(matches!(decode(&bytes, length as u32),
            Err(Win16Error::LimitViolation { .. })), "length {length}");
    }
}

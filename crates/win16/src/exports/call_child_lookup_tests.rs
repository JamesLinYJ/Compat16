//! Physical Pascal frames for USER child and descendant queries.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup,
    Win16ApiRequest, Win16CallFrame, Win16Error, Win16ExportId,
    Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind,
    Win16UserChildLookupRequest as Request, Win16UserRequest,
    decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

fn frame(ordinal: u16, parent: u16, value: u32, flags: u16) -> Vec<u8> {
    let mut bytes = vec![0x34, 0x12, 0x78, 0x56]; // FAR return IP:CS
    if ordinal == 399 { bytes.extend_from_slice(&flags.to_le_bytes()); }
    if ordinal == 48 {
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
    } else {
        bytes.extend_from_slice(&value.to_le_bytes()); // POINT.x, POINT.y
    }
    bytes.extend_from_slice(&parent.to_le_bytes());
    bytes
}

fn decode(ordinal: u16, bytes: &[u8], stack_bytes: u32) -> Result<Win16ApiRequest, Win16Error> {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), stack_bytes,
        AccessRights::read_write(), &memory).unwrap();
    memory.write(PhysAddr(0x1000), bytes).unwrap();
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let decoded = decode_export_call(descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors, &memory)?;
    assert_eq!(decoded.export, descriptor.id);
    assert_eq!(decoded.stack_cleanup, StackCleanup {
        callee_pop_bytes: (bytes.len() - 4) as u16, caller_pop_bytes: 0,
    });
    Ok(decoded.request)
}

#[test]
fn child_lookup_catalog_has_word_returns_and_by_value_point_slots() {
    for (ordinal, name, id, slots, cleanup) in [
        (48, "IsChild", Win16ExportId::UserIsChild,
            vec![ArgumentKind::Word, ArgumentKind::Word], 4),
        (191, "ChildWindowFromPoint", Win16ExportId::UserChildWindowFromPoint,
            vec![ArgumentKind::Word, ArgumentKind::Dword], 6),
        (399, "ChildWindowFromPointEx", Win16ExportId::UserChildWindowFromPointEx,
            vec![ArgumentKind::Word, ArgumentKind::Dword, ArgumentKind::Word], 8),
    ] {
        let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(lookup_export(b"USER", ExportLookupTarget::Name(name.as_bytes())), Some(descriptor));
        assert_eq!(descriptor.id, id);
        assert_eq!(descriptor.name(), name);
        assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
        assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: cleanup, caller_pop_bytes: 0,
        }));
        assert_eq!(descriptor.parameters.iter().map(|slot| slot.kind).collect::<Vec<_>>(), slots);
        assert!(descriptor.parameters.iter().all(|slot| slot.parameter_type == Win16ParameterType::Scalar));
    }
}

#[test]
fn child_lookup_decodes_physical_pascal_frames_without_dereferencing_points() {
    for parent in [0, 1, 0xa135, 0xffff] {
        for point in [0, 0x7fff_8000, 0x8000_7fff, 0xffff_ffff, 0x5678_1234] {
            let bytes = frame(191, parent, point, 0);
            assert_eq!(decode(191, &bytes, bytes.len() as u32).unwrap(),
                Win16ApiRequest::User(Win16UserRequest::ChildLookup(
                    Request::ChildWindowFromPoint { parent, point })));
            for flags in [0, 1, 2, 4, 7, 0x8000, 0xffff] {
                let bytes = frame(399, parent, point, flags);
                assert_eq!(decode(399, &bytes, bytes.len() as u32).unwrap(),
                    Win16ApiRequest::User(Win16UserRequest::ChildLookup(
                        Request::ChildWindowFromPointEx { parent, point, flags })));
            }
        }
        for child in [0, 1, 0xb246, 0xffff] {
            let bytes = frame(48, parent, u32::from(child), 0);
            assert_eq!(decode(48, &bytes, bytes.len() as u32).unwrap(),
                Win16ApiRequest::User(Win16UserRequest::ChildLookup(Request::IsChild { parent, child })));
        }
    }
}

#[test]
fn child_lookup_rejects_every_truncated_argument_frame() {
    for ordinal in [48, 191, 399] {
        let bytes = frame(ordinal, 0x1234, 0x8000_7fff, 7);
        for length in 4..bytes.len() {
            assert!(matches!(decode(ordinal, &bytes, length as u32),
                Err(Win16Error::LimitViolation { .. })), "ordinal {ordinal}, length {length}");
        }
    }
}

//! Physical USER.403 Pascal frame and checked class-selector decoding.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup,
    Win16ApiRequest, Win16CallFrame, Win16ClassName, Win16Error, Win16ExportId,
    Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind, Win16UserRequest, Win16UserWindowRequest,
    decode_export_call, lookup_export,
};
use crate::exports::USER_UNREGISTER_CLASS;
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

fn decode(name: u32, instance: u16, stack_bytes: u32, string: Option<&[u8]>)
    -> Result<Win16ApiRequest, Win16Error>
{
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), stack_bytes,
        AccessRights::read_write(), &memory).unwrap();
    let name = if let Some(bytes) = string {
        memory.write(PhysAddr(0x2000), bytes).unwrap();
        let data = selectors.alloc_block(PhysAddr(0x2000), bytes.len() as u32,
            AccessRights::read_write(), &memory).unwrap();
        u32::from(data.raw().0) << 16
    } else { name };
    // FAR return, instance WORD, class-name offset WORD, class-name selector WORD.
    let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
    bytes.extend_from_slice(&instance.to_le_bytes());
    bytes.extend_from_slice(&name.to_le_bytes());
    memory.write(PhysAddr(0x1000), &bytes).unwrap();
    let decoded = decode_export_call(&USER_UNREGISTER_CLASS,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors, &memory)?;
    assert_eq!(decoded.export, Win16ExportId::UserUnregisterClass);
    assert_eq!(decoded.stack_cleanup, StackCleanup { callee_pop_bytes: 6, caller_pop_bytes: 0 });
    Ok(decoded.request)
}

#[test]
fn unregister_class_catalog_and_physical_name_atom_frames() {
    let descriptor = &USER_UNREGISTER_CLASS;
    assert_eq!(descriptor.ordinal(), 403);
    assert_eq!(descriptor.name(), "UnregisterClass");
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 6, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.iter().map(|slot| slot.kind).collect::<Vec<_>>(),
        vec![ArgumentKind::Dword, ArgumentKind::Word]);
    assert_eq!(descriptor.parameters.iter().map(|slot| slot.parameter_type).collect::<Vec<_>>(),
        vec![Win16ParameterType::ClassName, Win16ParameterType::Scalar]);
    for target in [ExportLookupTarget::Ordinal(403), ExportLookupTarget::Name(b"UnregisterClass")] {
        assert_eq!(lookup_export(b"USER", target), Some(descriptor));
    }
    for atom in [0, 1, 0xa135, 0xffff] {
        assert_eq!(decode(u32::from(atom), 0xc246, 10, None).unwrap(),
            Win16ApiRequest::User(Win16UserRequest::Window(Win16UserWindowRequest::UnregisterClass {
                class_name: Win16ClassName::Atom(atom), instance: 0xc246,
            })));
    }
    assert_eq!(decode(0, 0xabcd, 10, Some(b"Class\x82\x60\0")).unwrap(),
        Win16ApiRequest::User(Win16UserRequest::Window(Win16UserWindowRequest::UnregisterClass {
            class_name: Win16ClassName::Name(b"Class\x82\x60".to_vec()), instance: 0xabcd,
        })));
}

#[test]
fn unregister_class_rejects_truncated_frames_and_invalid_string_spans() {
    for length in 4..10 {
        assert!(matches!(decode(0xc123, 0x1234, length, None),
            Err(Win16Error::LimitViolation { .. })));
    }
    assert!(decode(0xffff_0020, 0x1234, 10, None).is_err());
    assert!(decode(0, 0x1234, 10, Some(b"NoTerminator")).is_err());
    assert_eq!(lookup_export(b"USER", ExportLookupTarget::Ordinal(404)).unwrap().id,
        Win16ExportId::UserGetClassInfo);
}

//! Library remainder ids 6000000–6999999 and 9200000–9299999 decode to one request.

use super::*;
use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorTable, StackCleanup, Win16CallFrame, Win16ExportAbiKind,
    Win16ExportStackCleanup, Win16ParameterType, Win16RegisterContext, Win16ReturnKind,
    lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn library_remainder_contract_every_new_id_decodes() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 256, AccessRights::read_write(), &memory)
        .unwrap();
    memory.write(PhysAddr(0x1000), &[0u8; 256]).unwrap();
    let frame = Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far);
    let mut seen = 0u16;
    for descriptor in export_descriptors() {
        let id = descriptor.id as u32;
        if !(6_000_000..7_000_000).contains(&id) {
            continue;
        }
        seen += 1;
        let decoded = decode_export_call_with_register_context(
            descriptor,
            frame,
            Win16RegisterContext::default(),
            &selectors,
            &memory,
        )
        .unwrap_or_else(|error| {
            panic!(
                "{}:{} decode failed: {error}",
                descriptor.module(),
                descriptor.ordinal()
            )
        });
        assert!(
            matches!(
                decoded.request,
                Win16ApiRequest::Libraries(Win16LibraryRequest::LibraryRemainder { ordinal })
                    if ordinal == descriptor.ordinal()
            ),
            "{}:{}",
            descriptor.module(),
            descriptor.name()
        );
        if descriptor.abi_kind == Win16ExportAbiKind::RegisterContext {
            assert!(decode_export_call(descriptor, frame, &selectors, &memory).is_err());
        }
    }
    assert_eq!(seen, 135);
    let mut recovered = 0u16;
    for descriptor in export_descriptors() {
        let id = descriptor.id as u32;
        if !(9_200_000..9_300_000).contains(&id) {
            continue;
        }
        recovered += 1;
        let decoded = decode_export_call_with_register_context(
            descriptor,
            frame,
            Win16RegisterContext::default(),
            &selectors,
            &memory,
        )
        .unwrap_or_else(|error| {
            panic!(
                "{}:{} decode failed: {error}",
                descriptor.module(),
                descriptor.ordinal()
            )
        });
        let crate::exports::Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup
        else {
            panic!(
                "{}:{} is not a fixed frame",
                descriptor.module(),
                descriptor.ordinal()
            );
        };
        assert_eq!(cleanup.caller_pop_bytes, 0);
        if descriptor.module() == "MMSYSTEM" && descriptor.ordinal() == 111 {
            assert_eq!(cleanup.callee_pop_bytes, 4);
            assert!(matches!(
                decoded.request,
                Win16ApiRequest::Joystick(Win16JoystickRequest::ConfigChanged { flags: 0 })
            ));
        } else if descriptor.module() == "MMSYSTEM" && descriptor.ordinal() == 34 {
            assert_eq!(cleanup.callee_pop_bytes, 12);
            assert!(
                matches!(
                    decoded.request,
                    Win16ApiRequest::Libraries(Win16LibraryRequest::LibraryRemainder {
                        ordinal: 34
                    })
                ),
                "{}",
                descriptor.name()
            );
        } else {
            assert_eq!(cleanup.callee_pop_bytes, 2, "{}", descriptor.name());
            assert!(
                matches!(
                    decoded.request,
                    Win16ApiRequest::Libraries(Win16LibraryRequest::LibraryRemainder { ordinal })
                        if ordinal == descriptor.ordinal()
                ),
                "{}:{}",
                descriptor.module(),
                descriptor.name()
            );
        }
    }
    assert_eq!(recovered, 3);
}

#[test]
fn mmdrvinstall_uses_the_mmiscapi_far_pascal_frame() {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(34)).unwrap();
    assert_eq!(descriptor.id as u32, 9_200_002);
    assert_eq!(descriptor.name(), "MMDRVINSTALL");
    let by_name = lookup_export(b"MMSYSTEM", ExportLookupTarget::Name(b"MMDRVINSTALL")).unwrap();
    assert_eq!(by_name.id as u32, descriptor.id as u32);
    assert_eq!(by_name.ordinal(), descriptor.ordinal());
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(
        descriptor.calling_convention,
        ExportCallingConvention::Pascal
    );
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(
        descriptor.stack_cleanup,
        Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: 12,
            caller_pop_bytes: 0,
        })
    );
    assert_eq!(
        descriptor
            .parameters
            .iter()
            .map(|parameter| (parameter.name, parameter.kind, parameter.parameter_type))
            .collect::<Vec<_>>(),
        vec![
            ("hDriver", ArgumentKind::Word, Win16ParameterType::Scalar),
            (
                "wszDrvEntry",
                ArgumentKind::Dword,
                Win16ParameterType::FarPointer,
            ),
            (
                "drvMessage",
                ArgumentKind::Dword,
                Win16ParameterType::FarPointer,
            ),
            ("wFlags", ArgumentKind::Word, Win16ParameterType::Scalar),
        ]
    );
}

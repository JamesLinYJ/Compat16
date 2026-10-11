//! SDK-sourced Escape ABI, including its semantic signed-int AX return.

use crate::exports::GDI_ESCAPE;
use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget, GdiDeviceRequest,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16CallFrame, Win16Error, Win16ExportAbiKind, Win16ExportId, Win16ExportStackCleanup,
    Win16ParameterType, Win16ReturnKind, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn escape_catalog_matches_sdk_signature_without_changing_historical_declaration() {
    let descriptor = &GDI_ESCAPE;
    assert_eq!(descriptor.id, Win16ExportId::GdiEscape);
    assert_eq!(descriptor.module(), "GDI");
    assert_eq!(descriptor.ordinal(), 38);
    assert_eq!(descriptor.name(), "Escape");
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(
        descriptor.calling_convention,
        ExportCallingConvention::Pascal
    );
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(
        descriptor.stack_cleanup,
        Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: 14,
            caller_pop_bytes: 0,
        })
    );
    assert_eq!(descriptor.parameters.len(), 5);
    assert!(
        descriptor.parameters[..3]
            .iter()
            .all(|p| p.kind == ArgumentKind::Word)
    );
    assert!(
        descriptor.parameters[3..]
            .iter()
            .all(|p| p.kind == ArgumentKind::Dword)
    );
    assert_eq!(
        descriptor.parameters[3].parameter_type,
        Win16ParameterType::FarBuffer
    );
    assert_eq!(
        descriptor.parameters[4].parameter_type,
        Win16ParameterType::FarOutputBuffer
    );
    assert_eq!(
        lookup_export(b"GDI", ExportLookupTarget::Ordinal(38)),
        Some(descriptor)
    );
    assert_eq!(
        lookup_export(b"GDI", ExportLookupTarget::Name(b"Escape")),
        Some(descriptor)
    );
}

#[test]
fn escape_physical_pascal_frame_preserves_signed_words_and_far_pointer_order() {
    for (escape, input_size) in [(8_i16, 2_i16), (12, 0), (-32768, -1), (32767, 32767)] {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors
            .alloc_block(PhysAddr(0x1000), 18, AccessRights::read_write(), &memory)
            .unwrap();
        let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
        // Physical Pascal frame: return IP:CS, output, input, count, code, HDC.
        bytes.extend_from_slice(&0xabcd_f012_u32.to_le_bytes());
        bytes.extend_from_slice(&0x8765_4321_u32.to_le_bytes());
        bytes.extend_from_slice(&input_size.to_le_bytes());
        bytes.extend_from_slice(&escape.to_le_bytes());
        bytes.extend_from_slice(&0xfedc_u16.to_le_bytes());
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        let decoded = decode_export_call(
            &GDI_ESCAPE,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors,
            &memory,
        )
        .unwrap();
        assert_eq!(
            decoded.request,
            Win16ApiRequest::GdiDevice(GdiDeviceRequest::Escape {
                dc: 0xfedc,
                escape,
                input_size,
                input: 0x8765_4321,
                output: 0xabcd_f012,
            })
        );
        assert_eq!(
            decoded.stack_cleanup,
            StackCleanup {
                callee_pop_bytes: 14,
                caller_pop_bytes: 0
            }
        );
    }
}

#[test]
fn escape_physical_frame_rejects_each_truncated_argument_slot() {
    for size in 4..18 {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors
            .alloc_block(PhysAddr(0x1000), size, AccessRights::read_write(), &memory)
            .unwrap();
        memory.write(PhysAddr(0x1000), &[0; 18]).unwrap();
        assert!(matches!(
            decode_export_call(
                &GDI_ESCAPE,
                Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
                &selectors,
                &memory
            ),
            Err(Win16Error::LimitViolation { .. })
        ));
    }
}

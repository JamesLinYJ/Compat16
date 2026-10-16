//! GDI.308 unsigned WORD/WORD/FAR output ABI and physical Pascal frames.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16CallFrame, Win16Error, Win16ExportAbiKind, Win16ExportId, Win16ExportStackCleanup,
    Win16GdiTextRequest, Win16ParameterType, Win16ReturnKind, decode_export_call,
    lookup_export,
};
use crate::exports::GDI_GET_OUTLINE_TEXT_METRICS;
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn get_outline_text_metrics_catalog_has_unsigned_count_and_word_result() {
    let descriptor = &GDI_GET_OUTLINE_TEXT_METRICS;
    assert_eq!(descriptor.id, Win16ExportId::GdiGetOutlineTextMetrics);
    assert_eq!(descriptor.module(), "GDI");
    assert_eq!(descriptor.ordinal(), 308);
    assert_eq!(descriptor.name(), "GetOutlineTextMetrics");
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 8, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.iter().map(|parameter| parameter.kind).collect::<Vec<_>>(),
        [ArgumentKind::Word, ArgumentKind::Word, ArgumentKind::Dword]);
    assert_eq!(descriptor.parameters[0].parameter_type, Win16ParameterType::Scalar);
    assert_eq!(descriptor.parameters[1].parameter_type, Win16ParameterType::Scalar);
    assert_eq!(descriptor.parameters[2].parameter_type, Win16ParameterType::FarOutputBuffer);
    assert_eq!(lookup_export(b"GDI", ExportLookupTarget::Ordinal(308)), Some(descriptor));
    assert_eq!(lookup_export(b"GDI", ExportLookupTarget::Name(b"GetOutlineTextMetrics")), Some(descriptor));
}

#[test]
fn get_outline_text_metrics_physical_frame_preserves_count_and_raw_output() {
    for (count, output) in [
        (0_u16, 0_u32), (0, 0xabcd_f012), (106, 0x0000_1234),
        (107, 0xabcd_f012), (0x8000, 0xabcd_f012), (0xffff, 0xffff_ffff),
    ] {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors.alloc_block(PhysAddr(0x1000), 12, AccessRights::read_write(), &memory).unwrap();
        let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
        // Pascal: return IP:CS, output offset:selector, unsigned count, HDC.
        bytes.extend_from_slice(&output.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&0x8765_u16.to_le_bytes());
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        let decoded = decode_export_call(&GDI_GET_OUTLINE_TEXT_METRICS,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors, &memory).unwrap();
        assert_eq!(decoded.request, Win16ApiRequest::GdiText(Win16GdiTextRequest::GetOutlineTextMetrics {
            dc: 0x8765, count, output,
        }));
        assert_eq!(decoded.stack_cleanup, StackCleanup { callee_pop_bytes: 8, caller_pop_bytes: 0 });
    }
}

#[test]
fn get_outline_text_metrics_physical_frame_rejects_truncated_slots() {
    for size in [7, 9, 11] {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors.alloc_block(PhysAddr(0x1000), size,
            AccessRights::read_write(), &memory).unwrap();
        memory.write(PhysAddr(0x1000), &[0; 12]).unwrap();
        assert!(matches!(decode_export_call(&GDI_GET_OUTLINE_TEXT_METRICS,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors, &memory), Err(Win16Error::LimitViolation { .. })));
    }
}

use super::*;
use crate::{
    AccessRights, ReturnAddressWidth, SegmentedPointer, SelectorTable, Win16ApiRequest,
    Win16CallFrame, Win16LibraryRequest, decode_export_call,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn ole_remainder_contract_class_factories_pop_three_far_pointers() {
    for (module, ordinal) in [("OLE2DISP", 1), ("OLE2PROX", 1), ("STORAGE", 103)] {
        let descriptor =
            lookup_export(module.as_bytes(), ExportLookupTarget::Ordinal(ordinal)).unwrap();
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors
            .alloc_block(PhysAddr(0x1000), 32, AccessRights::read_write(), &memory)
            .unwrap();
        let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
        for slot in [0x1111_0001_u32, 0x2222_0002, 0x3333_0003] {
            bytes.extend_from_slice(&slot.to_le_bytes());
        }
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        let decoded = decode_export_call(
            descriptor,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors,
            &memory,
        )
        .unwrap();
        assert_eq!(
            decoded.stack_cleanup.callee_pop_bytes, 12,
            "{module}:{ordinal}"
        );
        assert!(matches!(decoded.request, Win16ApiRequest::Libraries(
            Win16LibraryRequest::OleRemainder { ordinal: actual, .. }) if actual == ordinal));
    }
}

#[test]
fn ole_remainder_contract_variant_date_results_are_win16_ints() {
    for (ordinal, pop) in [(13, 16), (14, 8)] {
        let descriptor = lookup_export(b"OLE2DISP", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
        assert_eq!(
            descriptor.stack_cleanup,
            Win16ExportStackCleanup::Fixed(StackCleanup {
                callee_pop_bytes: pop,
                caller_pop_bytes: 0
            })
        );
    }
    let alloc = lookup_export(b"COMPOBJ", ExportLookupTarget::Ordinal(503)).unwrap();
    assert_eq!(alloc.calling_convention, ExportCallingConvention::Cdecl);
    assert_eq!(
        alloc.stack_cleanup,
        Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: 0,
            caller_pop_bytes: 8
        })
    );
}

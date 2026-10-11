//! Catch/Throw's context-sensitive completion still uses far Pascal arguments.
use crate::exports::{ExportArgumentType, ExportAttributes, lookup_export_metadata};
use crate::*;
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn catch_throw_catalog_retains_register_metadata_and_stack_contract() {
    for (ordinal, id, stable, bytes, result) in [
        (
            55,
            Win16ExportId::KernelCatch,
            1222,
            4,
            Win16ReturnKind::Word,
        ),
        (
            56,
            Win16ExportId::KernelThrow,
            1223,
            6,
            Win16ReturnKind::Void,
        ),
    ] {
        let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(descriptor.id, id);
        assert_eq!(id as u32, stable);
        assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
        assert_eq!(
            descriptor.calling_convention,
            ExportCallingConvention::Pascal
        );
        assert_eq!(descriptor.return_kind, result);
        assert_eq!(
            descriptor.stack_cleanup,
            Win16ExportStackCleanup::Fixed(StackCleanup {
                callee_pop_bytes: bytes,
                caller_pop_bytes: 0,
            })
        );
        let metadata =
            lookup_export_metadata(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert!(metadata.flags.contains(ExportAttributes::REGISTER));
    }
    assert_eq!(
        lookup_export_metadata(b"KERNEL", ExportLookupTarget::Ordinal(55))
            .unwrap()
            .abi
            .unwrap()
            .arguments,
        [ExportArgumentType::SegmentedPointer]
    );
}

#[test]
fn catch_throw_decode_far_pascal_buffer_and_exact_word_value() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 0x100, AccessRights::read_write(), &memory)
        .unwrap();
    let buffer = 0x1234_5678u32;
    for value in [0u16, 1, 0x8000, 0xffff] {
        let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes.extend_from_slice(&buffer.to_le_bytes());
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(56)).unwrap();
        let decoded = decode_export_call(
            descriptor,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors,
            &memory,
        )
        .unwrap();
        assert_eq!(
            decoded.request,
            Win16ApiRequest::Kernel(Win16KernelRequest::Throw { buffer, value })
        );
    }
    let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
    bytes.extend_from_slice(&buffer.to_le_bytes());
    memory.write(PhysAddr(0x1000), &bytes).unwrap();
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(55)).unwrap();
    let decoded = decode_export_call(
        descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors,
        &memory,
    )
    .unwrap();
    assert_eq!(
        decoded.request,
        Win16ApiRequest::Kernel(Win16KernelRequest::Catch { buffer })
    );
}

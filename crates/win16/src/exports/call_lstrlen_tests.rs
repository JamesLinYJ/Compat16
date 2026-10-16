//! KERNEL.90 decodes a scalar ANSI byte count while retaining its Win16 ABI.

use super::decode;
use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16Argument, Win16CallFrame, Win16Error, Win16ExportAbiKind, Win16ExportId,
    Win16ExportStackCleanup, Win16KernelRequest, Win16KernelStringsRequest,
    Win16ParameterType, Win16ReturnKind, decode_export_call, lookup_export,
};
use crate::exports::{KERNEL_LSTRCAT, KERNEL_LSTRCPY, KERNEL_LSTRLEN};
use guest_core::{GuestMemory, MemoryError, PhysAddr, memory::Memory};

fn length_request(byte_count: u16) -> Win16ApiRequest {
    Win16ApiRequest::Kernel(Win16KernelRequest::Strings(
        Win16KernelStringsRequest::StringLength { byte_count },
    ))
}

#[test]
fn lstrlen_catalog_preserves_ordinal_pascal_far_slot_and_word_result() {
    let descriptor = &KERNEL_LSTRLEN;
    assert_eq!(descriptor.id, Win16ExportId::KernelLstrlen);
    assert_eq!(descriptor.module(), "KERNEL");
    assert_eq!(descriptor.ordinal(), 90);
    assert_eq!(descriptor.name(), "lstrlen");
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 4, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.len(), 1);
    assert_eq!(descriptor.parameters[0].kind, ArgumentKind::Dword);
    assert_eq!(descriptor.parameters[0].parameter_type,
        Win16ParameterType::NullableFarString);
    assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(90)), Some(descriptor));
    assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Name(b"lstrlen")), Some(descriptor));
}

#[test]
fn lstrlen_null_decodes_zero_without_resolving_or_reading_guest_memory() {
    struct NoReadMemory;
    impl GuestMemory for NoReadMemory {
        fn len(&self) -> u32 { panic!("null string must not inspect guest memory") }
        fn read(&self, _: PhysAddr, _: &mut [u8]) -> Result<(), MemoryError> { panic!("unexpected read") }
        fn write(&mut self, _: PhysAddr, _: &[u8]) -> Result<(), MemoryError> { panic!("unexpected write") }
    }
    assert_eq!(decode(&KERNEL_LSTRLEN, &[Win16Argument::Dword(0)],
        &SelectorTable::new().unwrap(), &NoReadMemory), Ok(Some(length_request(0))));
}

#[test]
fn lstrlen_physical_frame_decodes_byte_counts_including_maximum_word() {
    for source in [Vec::new(), b"ASCII".to_vec(), b"\x81\x40A\x82\xa0".to_vec(), vec![b'x'; 65535]] {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors.alloc_block(PhysAddr(0x1000), 8, AccessRights::read_write(), &memory).unwrap();
        let text = selectors.alloc_block(PhysAddr(0x2000), source.len() as u32 + 1,
            AccessRights::read_only(), &memory).unwrap();
        memory.write(PhysAddr(0x2000), &source).unwrap();
        memory.write(PhysAddr(0x2000 + source.len() as u32), &[0]).unwrap();
        // Real Pascal entry frame: return IP, return CS, offset, selector.
        memory.write(PhysAddr(0x1000), &[0x34, 0x12, 0x78, 0x56]).unwrap();
        memory.write(PhysAddr(0x1004), &SegmentedPointer::new(text, 0).far_value().to_le_bytes()).unwrap();
        let decoded = decode_export_call(&KERNEL_LSTRLEN,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors, &memory).unwrap();
        assert_eq!(decoded.export, Win16ExportId::KernelLstrlen);
        assert_eq!(decoded.request, length_request(source.len() as u16));
        assert_eq!(decoded.stack_cleanup, StackCleanup { callee_pop_bytes: 4, caller_pop_bytes: 0 });
    }
}

#[test]
fn lstrlen_physical_frame_rejects_truncated_far_argument() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), 7, AccessRights::read_write(), &memory).unwrap();
    memory.write(PhysAddr(0x1000), &[0; 8]).unwrap();
    assert!(matches!(decode_export_call(&KERNEL_LSTRLEN,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors, &memory), Err(Win16Error::LimitViolation { .. })));
}

#[test]
fn lstrlen_optimization_leaves_copy_and_concat_source_snapshots_owned() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let source = b"\x81\x40ABC";
    let text = selectors.alloc_block(PhysAddr(0x2000), source.len() as u32 + 1,
        AccessRights::read_only(), &memory).unwrap();
    memory.write(PhysAddr(0x2000), source).unwrap();
    let arguments = [Win16Argument::Dword(0x1234_5678),
        Win16Argument::Dword(SegmentedPointer::new(text, 0).far_value())];
    let copy = decode(&KERNEL_LSTRCPY, &arguments, &selectors, &memory).unwrap();
    let concat = decode(&KERNEL_LSTRCAT, &arguments, &selectors, &memory).unwrap();
    memory.write(PhysAddr(0x2000), b"xxxxx").unwrap();
    selectors.free_block(text).unwrap();
    assert_eq!(copy, Some(Win16ApiRequest::Kernel(Win16KernelRequest::Strings(
        Win16KernelStringsRequest::StringCopy { destination: 0x1234_5678, source: Some(source.to_vec()) },
    ))));
    assert_eq!(concat, Some(Win16ApiRequest::Kernel(Win16KernelRequest::Strings(
        Win16KernelStringsRequest::StringConcat { destination: 0x1234_5678, source: source.to_vec() },
    ))));
}

//! LocalHandleDelta is imported as KERNEL ordinal 310 by the original Windows
//! 3.1 SDK LIBW.LIB. The KRNL286.EXE entry at segment 2:2baf queries on zero,
//! stores a nonzero WORD unchanged, returns that current/new value, and RETF 2.
//! This contract is binary evidence; WINDOWS.H has no declaration for it.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup,
    Win16ApiRequest, Win16CallFrame, Win16ExportAbiKind, Win16ExportId,
    Win16ExportStackCleanup, Win16KernelLocalHeapRequest, Win16KernelRequest,
    Win16ParameterType, Win16ReturnKind, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn local_handle_delta_catalog_is_word_pascal_kernel_310() {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(310)).unwrap();
    assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Name(b"LocalHandleDelta")), Some(descriptor));
    assert_eq!(descriptor.id, Win16ExportId::KernelLocalHandleDelta);
    assert_eq!(descriptor.name(), "LocalHandleDelta");
    assert_eq!(descriptor.module(), "KERNEL");
    assert_eq!(descriptor.ordinal(), 310);
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 2, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.len(), 1);
    assert_eq!(descriptor.parameters[0].name, "delta");
    assert_eq!(descriptor.parameters[0].kind, ArgumentKind::Word);
    assert_eq!(descriptor.parameters[0].parameter_type, Win16ParameterType::Scalar);
}

#[test]
fn local_handle_delta_decodes_unsigned_word_and_two_byte_cleanup() {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(310)).unwrap();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), 0x100,
        AccessRights::read_write(), &memory).unwrap();
    for delta in [0u16, 1, 2, 0x7fff, 0x8000, 0xffff] {
        let mut frame = vec![0x34, 0x12, 0x78, 0x56];
        frame.extend_from_slice(&delta.to_le_bytes());
        memory.write(PhysAddr(0x1000), &frame).unwrap();
        let decoded = decode_export_call(descriptor,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors, &memory).unwrap();
        assert_eq!(decoded.export, Win16ExportId::KernelLocalHandleDelta);
        assert_eq!(decoded.request, Win16ApiRequest::Kernel(Win16KernelRequest::LocalHeap(
            Win16KernelLocalHeapRequest::LocalHandleDelta { delta },
        )));
        assert_eq!(decoded.stack_cleanup, StackCleanup { callee_pop_bytes: 2, caller_pop_bytes: 0 });
    }
}

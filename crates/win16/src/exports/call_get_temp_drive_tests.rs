//! SDK GetTempDrive(char): byte value, word-sized Pascal argument, AL result.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention,
    ExportLookupTarget, ReturnAddressWidth, SegmentedPointer,
    SelectorTable, StackCleanup, Win16ApiRequest, Win16CallFrame, Win16ExportAbiKind,
    Win16ExportId, Win16ExportStackCleanup, Win16KernelPathInfoRequest,
    Win16ParameterType, Win16ReturnKind, decode_export_call, lookup_export,
};
use crate::exports::{ExportArgumentType, ExportReturnModifier, lookup_export_metadata};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn get_temp_drive_catalog_preserves_legacy_metadata_and_byte_pascal_contract() {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(92)).unwrap();
    assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Name(b"GetTempDrive")), Some(descriptor));
    assert_eq!(descriptor.id, Win16ExportId::KernelGetTempDrive);
    assert_eq!(descriptor.id as u32, 1219);
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    // AL is the public BYTE. Word return additionally preserves observed AH=':'.
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 2, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.len(), 1);
    assert_eq!(descriptor.parameters[0].name, "drive");
    assert_eq!(descriptor.parameters[0].kind, ArgumentKind::Byte);
    assert_eq!(descriptor.parameters[0].parameter_type, Win16ParameterType::Scalar);

    let metadata = lookup_export_metadata(b"KERNEL", ExportLookupTarget::Ordinal(92)).unwrap();
    let abi = metadata.abi.unwrap();
    assert_eq!(abi.arguments, [ExportArgumentType::Word]);
    assert_eq!(abi.return_modifier, ExportReturnModifier::Unspecified);
    assert_eq!(metadata.source.spec_path, "groups/kernel/declarations.toml");
    assert_eq!(metadata.source.line, 0);
}

#[test]
fn get_temp_drive_decodes_only_low_byte_but_cleans_whole_word_slot() {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(92)).unwrap();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), 0x100,
        AccessRights::read_write(), &memory).unwrap();
    for word in [0_u16, 0x0080, 0x00e3, 0x0043, 0x0063, 0xff00, 0xff80, 0xffe3, 0xffff] {
        let mut frame = vec![0x34, 0x12, 0x78, 0x56];
        frame.extend_from_slice(&word.to_le_bytes());
        memory.write(PhysAddr(0x1000), &frame).unwrap();
        let decoded = decode_export_call(descriptor,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors, &memory).unwrap();
        assert_eq!(decoded.export, Win16ExportId::KernelGetTempDrive);
        assert_eq!(decoded.request, Win16ApiRequest::KernelPathInfo(
            Win16KernelPathInfoRequest::GetTempDrive { drive: word as u8 }));
        assert_eq!(decoded.stack_cleanup, StackCleanup { callee_pop_bytes: 2, caller_pop_bytes: 0 });
    }
}

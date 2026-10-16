//! KERNEL.74 conditional filename input and ten-byte Pascal call boundary.

use super::file_control_calls::decode;
use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16Argument, Win16CallFrame, Win16ExportAbiKind, Win16ExportId,
    Win16ExportStackCleanup, Win16KernelFilesRequest, Win16KernelRequest, Win16ReturnKind,
    decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, MemoryError, PhysAddr, memory::Memory};

const OF_REOPEN: u16 = 0x8000;
const OF_VERIFY: u16 = 0x0400;

fn request(path: Vec<u8>, ofstruct: u32, style: u16) -> Win16ApiRequest {
    Win16ApiRequest::Kernel(Win16KernelRequest::Files(
        Win16KernelFilesRequest::OpenStructuredFile { path, ofstruct, style },
    ))
}

#[test]
fn open_file_catalog_keeps_ten_byte_pascal_frame_and_word_hfile() {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(74)).unwrap();
    assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Name(b"OpenFile")), Some(descriptor));
    assert_eq!(descriptor.id, Win16ExportId::KernelOpenFile);
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.parameters.iter().map(|p| p.kind).collect::<Vec<_>>(),
        [ArgumentKind::Dword, ArgumentKind::Dword, ArgumentKind::Word]);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 10, caller_pop_bytes: 0,
    }));
}

#[test]
fn open_file_reopen_never_resolves_or_reads_the_ignored_filename() {
    struct NoReadMemory;
    impl GuestMemory for NoReadMemory {
        fn len(&self) -> u32 { panic!("OF_REOPEN must not inspect filename memory") }
        fn read(&self, _: PhysAddr, _: &mut [u8]) -> Result<(), MemoryError> { panic!("unexpected read") }
        fn write(&mut self, _: PhysAddr, _: &[u8]) -> Result<(), MemoryError> { panic!("unexpected write") }
    }
    for path in [0, 1, 0xfff8_ffff] {
        for style in [OF_REOPEN, OF_REOPEN | OF_VERIFY] {
            assert_eq!(decode(Win16ExportId::KernelOpenFile,
                &[Win16Argument::Dword(path), Win16Argument::Dword(0x1234_5678),
                    Win16Argument::Word(style)],
                &SelectorTable::new().unwrap(), &NoReadMemory).unwrap(),
                request(Vec::new(), 0x1234_5678, style));
        }
    }
}

#[test]
fn open_file_reopen_physical_frame_still_checks_all_ten_argument_bytes() {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(74)).unwrap();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), 14,
        AccessRights::read_write(), &memory).unwrap();
    let mut frame = vec![0x34, 0x12, 0x78, 0x56];
    frame.extend_from_slice(&(OF_REOPEN | OF_VERIFY).to_le_bytes());
    frame.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
    frame.extend_from_slice(&0xfff8_ffff_u32.to_le_bytes());
    memory.write(PhysAddr(0x1000), &frame).unwrap();
    let decoded = decode_export_call(descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors, &memory).unwrap();
    assert_eq!(decoded.request, request(Vec::new(), 0x1234_5678, OF_REOPEN | OF_VERIFY));
    assert_eq!(decoded.stack_cleanup, StackCleanup { callee_pop_bytes: 10, caller_pop_bytes: 0 });
    let truncated = selectors.alloc_block(PhysAddr(0x1000), 13,
        AccessRights::read_only(), &memory).unwrap();
    assert!(decode_export_call(descriptor,
        Win16CallFrame::new(SegmentedPointer::new(truncated, 0), ReturnAddressWidth::Far),
        &selectors, &memory).is_err());
}

#[test]
fn open_file_without_reopen_owns_filename_bytes_and_rejects_invalid_input() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let source = b"C:\\DATA\\\x81\x40.TXT\0";
    let text = selectors.alloc_block(PhysAddr(0x2000), source.len() as u32,
        AccessRights::read_only(), &memory).unwrap();
    memory.write(PhysAddr(0x2000), source).unwrap();
    for style in [0, OF_VERIFY] {
        let decoded = decode(Win16ExportId::KernelOpenFile,
            &[Win16Argument::Dword(SegmentedPointer::new(text, 0).far_value()),
                Win16Argument::Dword(0x1234_5678), Win16Argument::Word(style)],
            &selectors, &memory).unwrap();
        memory.write(PhysAddr(0x2000), &vec![0; source.len()]).unwrap();
        assert_eq!(decoded, request(source[..source.len() - 1].to_vec(), 0x1234_5678, style));
        memory.write(PhysAddr(0x2000), source).unwrap();
        assert!(decode(Win16ExportId::KernelOpenFile,
            &[Win16Argument::Dword(0xfff8_ffff), Win16Argument::Dword(0x1234_5678),
                Win16Argument::Word(style)], &selectors, &memory).is_err());
    }
    let unterminated = selectors.alloc_block(PhysAddr(0x2000), source.len() as u32 - 1,
        AccessRights::read_only(), &memory).unwrap();
    for style in [0, OF_VERIFY, OF_REOPEN, OF_REOPEN | OF_VERIFY] {
        let decoded = decode(Win16ExportId::KernelOpenFile,
            &[Win16Argument::Dword(SegmentedPointer::new(unterminated, 0).far_value()),
                Win16Argument::Dword(0x1234_5678), Win16Argument::Word(style)],
            &selectors, &memory);
        assert_eq!(decoded.is_ok(), style & OF_REOPEN != 0);
    }
}

//! GDI.330 Windows 3.1 SDK WORD/FAR/FAR/LONG Pascal ABI.
use crate::{AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16CallFrame, Win16ExportId, Win16ExportStackCleanup, Win16GdiTextRequest,
    Win16ReturnKind, decode_export_call, lookup_export};
use crate::exports::GDI_ENUM_FONT_FAMILIES;
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn enum_font_families_catalog_and_physical_pascal_frame() {
    let descriptor = &GDI_ENUM_FONT_FAMILIES;
    assert_eq!(descriptor.id, Win16ExportId::GdiEnumFontFamilies);
    assert_eq!(descriptor.ordinal(), 330);
    assert_eq!(descriptor.name(), "EnumFontFamilies");
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 14, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.iter().map(|p| p.kind).collect::<Vec<_>>(),
        vec![ArgumentKind::Word, ArgumentKind::Dword, ArgumentKind::Dword, ArgumentKind::Dword]);
    assert_eq!(lookup_export(b"GDI", ExportLookupTarget::Ordinal(330)), Some(descriptor));
    assert_eq!(lookup_export(b"GDI", ExportLookupTarget::Name(b"EnumFontFamilies")), Some(descriptor));
    for named in [false, true] {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors.alloc_block(PhysAddr(0x1000), 18, AccessRights::read_write(), &memory).unwrap();
        let name = selectors.alloc_block(PhysAddr(0x2000), 5, AccessRights::read_write(), &memory).unwrap();
        memory.write(PhysAddr(0x2000), b"Face\0").unwrap();
        let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
        bytes.extend_from_slice(&0x89abcdef_u32.to_le_bytes());
        bytes.extend_from_slice(&0xabcd1234_u32.to_le_bytes());
        bytes.extend_from_slice(&if named { SegmentedPointer::new(name, 0).far_value() } else { 0 }.to_le_bytes());
        bytes.extend_from_slice(&0x8765_u16.to_le_bytes());
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        let decoded = decode_export_call(descriptor,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors, &memory).unwrap();
        assert_eq!(decoded.request, Win16ApiRequest::GdiText(Win16GdiTextRequest::EnumFontFamilies {
            dc: 0x8765, face_name: named.then(|| b"Face".to_vec()), callback: 0xabcd1234,
            parameter: 0x89abcdef_u32 as i32,
        }));
    }
}

#[test]
fn enum_font_families_rejects_short_frames_and_invalid_family_pointer() {
    for (length, name) in [(17, 0_u32), (18, 0xffff0000_u32)] {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors.alloc_block(PhysAddr(0x1000), length, AccessRights::read_write(), &memory).unwrap();
        let mut bytes = [0; 18]; bytes[12..16].copy_from_slice(&name.to_le_bytes());
        memory.write(PhysAddr(0x1000), &bytes).unwrap();
        assert!(decode_export_call(&GDI_ENUM_FONT_FAMILIES,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors, &memory).is_err());
    }
}

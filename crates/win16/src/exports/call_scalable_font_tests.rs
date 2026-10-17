//! GDI.310 path strings, Pascal frame, and owned ANSI copies.

use crate::exports::GDI_CREATE_SCALABLE_FONT_RESOURCE;
use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorRef, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16Argument as Arg, Win16CallFrame, Win16Error, Win16ExportAbiKind, Win16ExportId,
    Win16ExportStackCleanup, Win16GdiServicesRequest as Request, Win16ParameterType,
    Win16ReturnKind, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

struct Fixture {
    memory: Memory,
    selectors: SelectorTable,
    stack: SelectorRef,
}

impl Fixture {
    fn new() -> Self {
        let memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors
            .alloc_block(PhysAddr(0x1000), 256, AccessRights::read_write(), &memory)
            .unwrap();
        Self {
            memory,
            selectors,
            stack,
        }
    }

    fn input(&mut self, base: u32, bytes: &[u8]) -> u32 {
        self.memory.write(PhysAddr(base), bytes).unwrap();
        let selector = self
            .selectors
            .alloc_block(
                PhysAddr(base),
                bytes.len() as u32,
                AccessRights::read_only(),
                &self.memory,
            )
            .unwrap();
        SegmentedPointer::new(selector, 0).far_value()
    }

    fn call(&mut self, arguments: &[Arg]) -> Result<Win16ApiRequest, Win16Error> {
        let mut frame = vec![0; 4];
        for arg in arguments.iter().rev() {
            match arg {
                Arg::Byte(_) => panic!("CreateScalableFontResource has no byte parameters"),
                Arg::Word(value) => frame.extend_from_slice(&value.to_le_bytes()),
                Arg::Dword(value) => frame.extend_from_slice(&value.to_le_bytes()),
            }
        }
        self.memory.write(PhysAddr(0x1000), &frame).unwrap();
        decode_export_call(
            &GDI_CREATE_SCALABLE_FONT_RESOURCE,
            Win16CallFrame::new(
                SegmentedPointer::new(self.stack, 0),
                ReturnAddressWidth::Far,
            ),
            &self.selectors,
            &self.memory,
        )
        .map(|decoded| decoded.request)
    }
}

#[test]
fn create_scalable_font_resource_catalog_is_word_pascal_gdi_310() {
    let descriptor = &GDI_CREATE_SCALABLE_FONT_RESOURCE;
    assert_eq!(descriptor.id, Win16ExportId::GdiCreateScalableFontResource);
    assert_eq!(descriptor.id as u32, 1324);
    assert_eq!(descriptor.module(), "GDI");
    assert_eq!(descriptor.ordinal(), 310);
    assert_eq!(descriptor.name(), "CreateScalableFontResource");
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
    assert_eq!(descriptor.parameters.len(), 4);
    assert_eq!(descriptor.parameters[0].kind, ArgumentKind::Word);
    assert_eq!(descriptor.parameters[0].name, "hidden");
    for parameter in &descriptor.parameters[1..] {
        assert_eq!(parameter.kind, ArgumentKind::Dword);
        assert_eq!(
            parameter.parameter_type,
            Win16ParameterType::NullableFarString
        );
    }
    assert_eq!(
        lookup_export(b"GDI", ExportLookupTarget::Ordinal(310)),
        Some(descriptor)
    );
    assert_eq!(
        lookup_export(
            b"GDI",
            ExportLookupTarget::Name(b"CreateScalableFontResource")
        ),
        Some(descriptor)
    );
}

#[test]
fn create_scalable_font_resource_copies_ansi_and_keeps_null_distinct_from_empty() {
    let mut f = Fixture::new();
    let resource = f.input(0x2000, &[b'A', 0x82, 0xa0, b'.', b'F', b'O', b'T', 0]);
    let font = f.input(0x3000, b"C:\\FONT.TTF\0");
    let empty = f.input(0x4000, b"\0");
    assert_eq!(
        f.call(&[
            Arg::Word(0x8001),
            Arg::Dword(resource),
            Arg::Dword(font),
            Arg::Dword(0),
        ])
        .unwrap(),
        Win16ApiRequest::GdiServices(Request::CreateScalableFontResource {
            hidden: 0x8001,
            resource_file: Some(vec![b'A', 0x82, 0xa0, b'.', b'F', b'O', b'T']),
            font_file: Some(b"C:\\FONT.TTF".to_vec()),
            current_path: None,
        })
    );
    assert_eq!(
        f.call(&[
            Arg::Word(0),
            Arg::Dword(0),
            Arg::Dword(0),
            Arg::Dword(empty),
        ])
        .unwrap(),
        Win16ApiRequest::GdiServices(Request::CreateScalableFontResource {
            hidden: 0,
            resource_file: None,
            font_file: None,
            current_path: Some(Vec::new()),
        })
    );
}

#[test]
fn create_scalable_font_resource_rejects_short_and_selectorless_pointers() {
    let mut f = Fixture::new();
    let short = f.input(0x2000, b"AB");
    let resource = f.input(0x3000, b"FONT.FOT\0");
    for font in [short, 0x0000_1234, 0xffff_0000] {
        assert!(
            f.call(&[
                Arg::Word(0),
                Arg::Dword(resource),
                Arg::Dword(font),
                Arg::Dword(0),
            ])
            .is_err()
        );
    }
}

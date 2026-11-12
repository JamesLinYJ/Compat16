//! ExtTextOut reads one spacing int per ANSI byte, including option 0x2000.

use crate::{
    AccessRights, ExportLookupTarget, ReturnAddressWidth, SegmentedPointer, SelectorRef,
    SelectorTable, Win16ApiRequest, Win16Argument as Arg, Win16CallFrame, Win16Error,
    decode_export_call, lookup_export,
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
                Arg::Byte(_) => panic!("ExtTextOut has no byte parameters"),
                Arg::Word(value) => frame.extend_from_slice(&value.to_le_bytes()),
                Arg::Dword(value) => frame.extend_from_slice(&value.to_le_bytes()),
            }
        }
        self.memory.write(PhysAddr(0x1000), &frame).unwrap();
        let descriptor = lookup_export(b"GDI", ExportLookupTarget::Name(b"ExtTextOut")).unwrap();
        decode_export_call(
            descriptor,
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
fn spacing_option_reads_one_int_per_byte() {
    let mut fixture = Fixture::new();
    let text = fixture.input(0x2000, b"AB");
    let mut spacing = Vec::new();
    spacing.extend_from_slice(&10_i16.to_le_bytes());
    spacing.extend_from_slice(&20_i16.to_le_bytes());
    let spacing = fixture.input(0x3000, &spacing);
    let request = fixture
        .call(&[
            Arg::Word(1),
            Arg::Word(4),
            Arg::Word(5),
            Arg::Word(0x2000),
            Arg::Dword(0),
            Arg::Dword(text),
            Arg::Word(2),
            Arg::Dword(spacing),
        ])
        .unwrap();
    match request {
        Win16ApiRequest::GdiText(crate::Win16GdiTextRequest::ExtTextOut {
            options,
            text,
            count,
            spacing,
            ..
        }) => {
            assert_eq!(options, 0x2000);
            assert_eq!(text, b"AB");
            assert_eq!(count, 2);
            assert_eq!(spacing, Some(vec![10, 20]));
        }
        other => panic!("unexpected request {other:?}"),
    }
}

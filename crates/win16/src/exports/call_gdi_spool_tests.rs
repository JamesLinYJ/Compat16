//! PRINT.H widths, Pascal frames and process-owned input spans.
use crate::{
    AccessRights, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorRef, SelectorTable, Win16ApiRequest, Win16Argument as Arg,
    Win16CallFrame, Win16Error, Win16ExportStackCleanup, Win16GdiSpoolRequest as Request,
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
    fn call(&mut self, ordinal: u16, arguments: &[Arg]) -> Result<Win16ApiRequest, Win16Error> {
        let mut frame = vec![0; 4];
        for arg in arguments.iter().rev() {
            match arg {
                Arg::Byte(_) => panic!("PRINT.H has no byte parameters"),
                Arg::Word(value) => frame.extend_from_slice(&value.to_le_bytes()),
                Arg::Dword(value) => frame.extend_from_slice(&value.to_le_bytes()),
            }
        }
        self.memory.write(PhysAddr(0x1000), &frame).unwrap();
        let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
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
fn gdi_spool_exports_have_sdk_names_word_results_and_pascal_cleanup() {
    for (ordinal, name, pop) in [
        (240, b"OpenJob".as_slice(), 10),
        (241, b"WriteSpool", 8),
        (243, b"CloseJob", 2),
        (244, b"DeleteJob", 4),
        (246, b"StartSpoolPage", 2),
        (247, b"EndSpoolPage", 2),
    ] {
        let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(
            descriptor.id,
            lookup_export(b"GDI", ExportLookupTarget::Name(name))
                .unwrap()
                .id
        );
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
        assert_eq!(
            descriptor.calling_convention,
            ExportCallingConvention::Pascal
        );
        let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
            panic!("fixed frame")
        };
        assert_eq!(
            (cleanup.callee_pop_bytes, cleanup.caller_pop_bytes),
            (pop, 0)
        );
    }
}

#[test]
fn gdi_spool_open_copies_ansi_bytes_and_preserves_the_third_word() {
    let mut f = Fixture::new();
    let output = f.input(0x2000, b"LPT1:\0");
    let title = f.input(0x3000, &[0x82, 0xa0, 0xff, 0]);
    assert_eq!(
        f.call(
            240,
            &[Arg::Dword(output), Arg::Dword(title), Arg::Word(0xface)]
        )
        .unwrap(),
        Win16ApiRequest::GdiSpool(Request::OpenJob {
            output_target: b"LPT1:".to_vec(),
            document_name: vec![0x82, 0xa0, 0xff],
            legacy_argument: 0xface
        })
    );
}

#[test]
fn gdi_spool_write_is_binary_and_zero_or_negative_counts_do_not_read_the_pointer() {
    let mut f = Fixture::new();
    let far = f.input(0x2000, &[0, 0xff, 0x82, 0, 0x7f]);
    for (count, pointer, bytes) in [
        (5, far, vec![0, 0xff, 0x82, 0, 0x7f]),
        (0, 0xffff_ffff, Vec::new()),
        (0xffff, 0xffff_ffff, Vec::new()),
    ] {
        assert_eq!(
            f.call(241, &[Arg::Word(7), Arg::Dword(pointer), Arg::Word(count)])
                .unwrap(),
            Win16ApiRequest::GdiSpool(Request::WriteSpool {
                job: 7,
                byte_count: count as i16,
                bytes
            })
        );
    }
}

#[test]
fn gdi_spool_write_accepts_the_maximum_count_across_an_owned_selector_boundary() {
    let mut f = Fixture::new();
    let bytes: Vec<u8> = (0..0x18000).map(|n| (n % 251) as u8).collect();
    let far = f.input(0x10000, &bytes) | 0xfffc;
    assert_eq!(
        f.call(241, &[Arg::Word(1), Arg::Dword(far), Arg::Word(0x7fff)])
            .unwrap(),
        Win16ApiRequest::GdiSpool(Request::WriteSpool {
            job: 1,
            byte_count: 0x7fff,
            bytes: bytes[0xfffc..0xfffc + 0x7fff].to_vec()
        })
    );
}

#[test]
fn gdi_spool_write_rejects_truncated_freed_and_unrelated_adjacent_selectors() {
    let mut f = Fixture::new();
    let first = f.input(0x2000, &[0x41, 0x42]);
    let _next = f.input(0x2002, &[0x43, 0x44]);
    assert!(
        f.call(241, &[Arg::Word(1), Arg::Dword(first), Arg::Word(4)])
            .is_err()
    );
    let selector = f.selectors.pointer_from_far(first).unwrap().selector();
    f.selectors.free_block(selector).unwrap();
    assert!(
        f.call(241, &[Arg::Word(1), Arg::Dword(first), Arg::Word(1)])
            .is_err()
    );
    assert!(
        f.call(241, &[Arg::Word(1), Arg::Dword(0xffff_ffff), Arg::Word(1)])
            .is_err()
    );
}

#[test]
fn gdi_spool_lifecycle_frames_preserve_full_handle_and_dummy_words() {
    let mut f = Fixture::new();
    for (ordinal, request) in [
        (243, Request::CloseJob { job: 0xabcd }),
        (246, Request::StartSpoolPage { job: 0xabcd }),
        (247, Request::EndSpoolPage { job: 0xabcd }),
    ] {
        assert_eq!(
            f.call(ordinal, &[Arg::Word(0xabcd)]).unwrap(),
            Win16ApiRequest::GdiSpool(request)
        );
    }
    assert_eq!(
        f.call(244, &[Arg::Word(0xabcd), Arg::Word(0x8001)])
            .unwrap(),
        Win16ApiRequest::GdiSpool(Request::DeleteJob {
            job: 0xabcd,
            legacy_argument: -32767
        })
    );
}

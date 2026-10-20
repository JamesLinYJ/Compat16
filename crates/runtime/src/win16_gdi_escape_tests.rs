//! GDI.38 service gate, typed queries, checked memory and signed POINT16 output.

use super::super::super::{ImportBinding, test_support::tiny_ne_executable};
use super::*;
use crate::{DiagnosticKind as Kind, Runtime, Win16HostDc, Win16PrintOperation};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup, Win16ReturnKind,
    lookup_export,
};

const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);

#[derive(Default)]
struct EscapeHost {
    calls: Vec<Operation>,
    result: Option<HostResult>,
    results: Vec<HostResult>,
    fail: bool,
    fail_at: Option<usize>,
}

impl DosHost for EscapeHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
        _sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(
        &mut self,
        _file: DosHostFile,
        _offset: i32,
        _origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(
        &mut self,
        _drive: u8,
        _output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for EscapeHost {
    fn win16_gdi_device(&mut self, operation: Operation) -> Result<HostResult, RuntimeError> {
        let index = self.calls.len();
        self.calls.push(operation);
        if self.fail || self.fail_at == Some(index) {
            return Err(RuntimeError::new(Kind::HostFailure, "test native failure"));
        }
        if !self.results.is_empty() {
            return Ok(self.results.remove(0));
        }
        Ok(self.result.take().expect("test supplies a native result"))
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeDdeHost for EscapeHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for EscapeHost {}
impl crate::RuntimeMidiHost for EscapeHost {}
impl crate::RuntimeNetbiosHost for EscapeHost {}

fn fixture() -> (Runtime, u16, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\ESCAPE.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(NATIVE_DC).unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(0x70000),
            0x10000,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    let pointer = SegmentedPointer::new(selector, 0);
    state
        .selectors
        .write(&mut runtime.memory, pointer, &[0x5a; 32])
        .unwrap();
    (runtime, dc, pointer.far_value())
}

fn read_output(runtime: &Runtime, far: u32) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = vec![0; 32];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    bytes
}

fn prepare(
    runtime: &mut Runtime,
    dc: u16,
    escape: i16,
    input_size: i16,
    input: u32,
    output: u32,
) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(38)).unwrap();
    assert_eq!(
        descriptor.id,
        lookup_export(b"GDI", ExportLookupTarget::Name(b"Escape"))
            .unwrap()
            .id
    );
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("fixed Pascal frame required");
    };
    assert_eq!(cleanup.callee_pop_bytes, 14);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&output.to_le_bytes());
    bytes.extend_from_slice(&input.to_le_bytes());
    bytes.extend_from_slice(&input_size.to_le_bytes());
    bytes.extend_from_slice(&escape.to_le_bytes());
    bytes.extend_from_slice(&dc.to_le_bytes());
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &bytes)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = 0xa1b2_a55a;
    runtime.cpu.regs.edx = 0xc3d4_5aa5;
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(runtime: &mut Runtime, host: &mut EscapeHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), result: u16) {
    assert_eq!(runtime.cpu.regs.eax, 0xa1b2_0000 | u32::from(result));
    assert_eq!(runtime.cpu.regs.edx, 0xc3d4_5aa5);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
}

fn write_input(runtime: &mut Runtime, far: u32, query: i16) {
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &query.to_le_bytes())
        .unwrap();
}

#[test]
fn escape_support_reads_exactly_one_win16_int_and_preserves_register_halves() {
    for (code, query) in [
        (8_i16, Query::QuerySupport),
        (12, Query::PhysicalPageSize),
        (13, Query::PrintingOffset),
        (14, Query::ScalingFactor),
    ] {
        for supported in [false, true] {
            let (mut runtime, dc, output) = fixture();
            // Exactly two readable bytes at the end of the segment, not a
            // native four-byte int. No output may be touched for escape 8.
            let input = output | 0xfffe;
            write_input(&mut runtime, input, code);
            let mut host = EscapeHost {
                result: Some(HostResult::Bool(supported)),
                ..Default::default()
            };
            let return_to = prepare(&mut runtime, dc, 8, 2, input, u32::MAX);
            dispatch(&mut runtime, &mut host).unwrap();
            assert_return(&runtime, return_to, u16::from(supported));
            assert_eq!(
                host.calls,
                [Operation::QueryEscapeSupport {
                    dc: NATIVE_DC,
                    query
                }]
            );
            assert_eq!(read_output(&runtime, output), [0x5a; 32]);
        }
    }
}

#[test]
fn escape_point_queries_use_exact_dc_and_four_signed_output_bytes() {
    for (code, query, x, y) in [
        (12, Query::PhysicalPageSize, 5100, 6600),
        (13, Query::PrintingOffset, -32768, 32767),
        (14, Query::ScalingFactor, 3, 0),
    ] {
        let (mut runtime, dc, output) = fixture();
        let mut host = EscapeHost {
            result: Some(HostResult::Point {
                success: true,
                x,
                y,
            }),
            ..Default::default()
        };
        let return_to = prepare(&mut runtime, dc, code, 0, u32::MAX, output);
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 1);
        assert_eq!(
            host.calls,
            [Operation::EscapeQuery {
                dc: NATIVE_DC,
                query
            }]
        );
        let bytes = read_output(&runtime, output);
        assert_eq!(&bytes[..2], &(x as i16).to_le_bytes());
        assert_eq!(&bytes[2..4], &(y as i16).to_le_bytes());
        assert_eq!(&bytes[4..], &[0x5a; 28]);
    }
}

#[test]
fn escape_unsupported_commands_and_query_codes_never_reach_host() {
    // NEXTBAND, SETCOPYCOUNT, PASSTHROUGH, negative/private.
    // SETABORTPROC (9) installs a guest AbortProc and is covered separately.
    for code in [3, 17, 19, -1, -32768, 32767] {
        let (mut runtime, dc, output) = fixture();
        let mut host = EscapeHost::default();
        let return_to = prepare(&mut runtime, dc, code, -1, u32::MAX, u32::MAX);
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0);
        let input = output | 32;
        write_input(&mut runtime, input, code);
        let return_to = prepare(&mut runtime, dc, 8, 2, input, u32::MAX);
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0);
        assert!(host.calls.is_empty());
        assert_eq!(read_output(&runtime, output), [0x5a; 32]);
    }
}

#[test]
fn escape_invalid_dc_counts_null_and_wrapping_buffers_fail_without_host_work() {
    for (code, count, input, output, unknown) in [
        (8, 2, u32::MAX, u32::MAX, true),
        (12, 0, u32::MAX, u32::MAX, true),
        (8, -1, u32::MAX, u32::MAX, false),
        (8, 0, u32::MAX, u32::MAX, false),
        (8, 1, u32::MAX, u32::MAX, false),
        (8, 4, u32::MAX, u32::MAX, false),
        (8, 2, 0, u32::MAX, false),
        (8, 2, u32::MAX, 0, false),
        (12, -1, u32::MAX, u32::MAX, false),
        (12, 2, u32::MAX, u32::MAX, false),
        (13, 0, 0, 0, false),
        (14, 0, 0, u32::MAX, false),
    ] {
        let (mut runtime, dc, original) = fixture();
        let mut host = EscapeHost::default();
        let return_to = prepare(
            &mut runtime,
            if unknown { 0xffff } else { dc },
            code,
            count,
            input,
            output,
        );
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0);
        assert!(host.calls.is_empty());
        assert_eq!(read_output(&runtime, original), [0x5a; 32]);
    }
}

#[test]
fn escape_preflights_short_readonly_and_rom_outputs_before_host_query() {
    for (base, size, rights) in [
        (0x70000, 3, AccessRights::read_write()),
        (0x70000, 4, AccessRights::read_only()),
        (0xf0000, 4, AccessRights::read_only()),
    ] {
        let (mut runtime, dc, original) = fixture();
        let mut previous = [0; 4];
        runtime
            .memory
            .read_physical(PhysAddr(base), &mut previous)
            .unwrap();
        let state = runtime.win16.as_mut().unwrap();
        if base == guest_core::memory::ROM_START {
            // Writable ROM selectors are refused at construction. Verify that
            // separately, then use the supported read-only ROM selector.
            assert!(matches!(
                state.selectors.alloc_block(
                    PhysAddr(base),
                    size,
                    AccessRights::read_write(),
                    &runtime.memory
                ),
                Err(win16_abi::Win16Error::Memory(
                    guest_core::MemoryError::ReadOnly {
                        address: 0xf0000,
                        length: 4,
                    }
                ))
            ));
        }
        let selector = state
            .selectors
            .alloc_block(PhysAddr(base), size, rights, &runtime.memory)
            .unwrap();
        let output = SegmentedPointer::new(selector, 0).far_value();
        let mut host = EscapeHost::default();
        prepare(&mut runtime, dc, 12, 0, u32::MAX, output);
        assert_eq!(
            dispatch(&mut runtime, &mut host).unwrap_err().kind(),
            Kind::GuestFault
        );
        assert!(host.calls.is_empty());
        assert_eq!(read_output(&runtime, original), [0x5a; 32]);
        let mut actual = [0; 4];
        runtime
            .memory
            .read_physical(PhysAddr(base), &mut actual)
            .unwrap();
        assert_eq!(actual, previous);
    }
}

#[test]
fn escape_rejects_short_and_unknown_input_selectors_before_host_query() {
    for short in [false, true] {
        let (mut runtime, dc, original) = fixture();
        let input = if short {
            let state = runtime.win16.as_mut().unwrap();
            let selector = state
                .selectors
                .alloc_block(
                    PhysAddr(0x70000),
                    1,
                    AccessRights::read_only(),
                    &runtime.memory,
                )
                .unwrap();
            SegmentedPointer::new(selector, 0).far_value()
        } else {
            0xffff_0000
        };
        let mut host = EscapeHost::default();
        prepare(&mut runtime, dc, 8, 2, input, u32::MAX);
        assert_eq!(
            dispatch(&mut runtime, &mut host).unwrap_err().kind(),
            Kind::GuestFault
        );
        assert!(host.calls.is_empty());
        assert_eq!(read_output(&runtime, original), [0x5a; 32]);
    }
}

#[test]
fn escape_failed_malformed_and_overflowing_host_results_leave_output_unchanged() {
    for (result, fail, error) in [
        (
            Some(HostResult::Point {
                success: false,
                x: 1,
                y: 2,
            }),
            false,
            None,
        ),
        (
            Some(HostResult::Point {
                success: true,
                x: 1,
                y: 32768,
            }),
            false,
            None,
        ),
        (
            Some(HostResult::Point {
                success: true,
                x: -32769,
                y: 2,
            }),
            false,
            None,
        ),
        (
            Some(HostResult::Bool(true)),
            false,
            Some(Kind::InternalInvariant),
        ),
        (None, true, Some(Kind::HostFailure)),
    ] {
        let (mut runtime, dc, output) = fixture();
        let mut host = EscapeHost {
            result,
            fail,
            ..Default::default()
        };
        let return_to = prepare(&mut runtime, dc, 13, 0, u32::MAX, output);
        let actual = dispatch(&mut runtime, &mut host);
        if let Some(kind) = error {
            assert_eq!(actual.unwrap_err().kind(), kind);
        } else {
            actual.unwrap();
            assert_return(&runtime, return_to, 0);
        }
        assert_eq!(host.calls.len(), 1);
        assert_eq!(read_output(&runtime, output), [0x5a; 32]);
    }
    let (mut runtime, dc, output) = fixture();
    write_input(&mut runtime, output | 32, 12);
    let mut host = EscapeHost {
        result: Some(HostResult::Count(-1)),
        ..Default::default()
    };
    prepare(&mut runtime, dc, 8, 2, output | 32, u32::MAX);
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::InternalInvariant
    );
    assert_eq!(read_output(&runtime, output), [0x5a; 32]);
}

#[test]
fn escape_query_support_for_print_jobs_uses_the_host_bool_and_leaves_output() {
    for (code, query) in [
        (10_i16, Query::StartDocument),
        (1, Query::NewFrame),
        (11, Query::EndDocument),
        (2, Query::AbortDocument),
    ] {
        for supported in [false, true] {
            let (mut runtime, dc, output) = fixture();
            let input = output | 0xfffe;
            write_input(&mut runtime, input, code);
            let mut host = EscapeHost {
                result: Some(HostResult::Bool(supported)),
                ..Default::default()
            };
            let return_to = prepare(&mut runtime, dc, 8, 2, input, output);
            dispatch(&mut runtime, &mut host).unwrap();
            assert_return(&runtime, return_to, u16::from(supported));
            assert_eq!(
                host.calls,
                [Operation::QueryEscapeSupport {
                    dc: NATIVE_DC,
                    query
                }]
            );
            // The probed int is at the end of the segment. Neither that word's
            // neighbors in the watched window nor the unused output are written.
            assert_eq!(read_output(&runtime, output), [0x5a; 32]);
        }
    }
}

#[test]
fn escape_start_doc_copies_the_counted_name_and_opens_the_first_page() {
    // 6 is lstrlen. 7 includes the terminator, which is not part of the name.
    for counted in [6_i16, 7] {
        let (mut runtime, dc, output) = fixture();
        let mut name = b"Report\0".to_vec();
        name.resize(32, 0x5a);
        let state = runtime.win16.as_mut().unwrap();
        let pointer = state.selectors.pointer_from_far(output).unwrap();
        state
            .selectors
            .write(&mut runtime.memory, pointer, &name)
            .unwrap();
        let mut host = EscapeHost {
            results: vec![HostResult::Count(42), HostResult::Count(1)],
            ..Default::default()
        };
        let return_to = prepare(&mut runtime, dc, 10, counted, output, output | 16);
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 42);
        assert_eq!(
            host.calls,
            [
                Operation::StartDoc {
                    dc: NATIVE_DC,
                    document_name: Some(b"Report".to_vec()),
                    output: None,
                },
                Operation::Print {
                    operation: Win16PrintOperation::StartPage,
                    dc: NATIVE_DC,
                },
            ]
        );
        let bytes = read_output(&runtime, output);
        assert_eq!(&bytes[..7], b"Report\0");
        assert_eq!(&bytes[7..], &[0x5a; 25]);
    }
}

#[test]
fn escape_start_doc_rejects_a_bad_name_before_host_work() {
    for (count, input, handle) in [
        (0_i16, u32::MAX, true),
        (-1, u32::MAX, true),
        (4, 0, true),
        (4, 0x0000_0010, true),
        (7, u32::MAX, false),
        (7, 0xffff_0000, false),
    ] {
        let (mut runtime, dc, output) = fixture();
        let input = if input == u32::MAX { output } else { input };
        let mut host = EscapeHost::default();
        let return_to = prepare(
            &mut runtime,
            if handle { dc } else { 0xffff },
            10,
            count,
            input,
            u32::MAX,
        );
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0xffff);
        assert!(host.calls.is_empty());
        assert_eq!(read_output(&runtime, output), [0x5a; 32]);
    }
    let (mut runtime, dc, output) = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(output).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, b"Re\0port")
        .unwrap();
    let mut host = EscapeHost::default();
    let return_to = prepare(&mut runtime, dc, 10, 7, output, u32::MAX);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0xffff);
    assert!(host.calls.is_empty());
    let bytes = read_output(&runtime, output);
    assert_eq!(&bytes[..7], b"Re\0port");
    assert_eq!(&bytes[7..], &[0x5a; 25]);

    let (mut runtime, dc, output) = fixture();
    let mut host = EscapeHost::default();
    let return_to = prepare(&mut runtime, dc, 10, 32, output | 0xfff0, u32::MAX);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0xffff);
    assert!(host.calls.is_empty());
    assert_eq!(read_output(&runtime, output), [0x5a; 32]);

    let (mut runtime, dc, original) = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(0x80000),
            1,
            AccessRights::read_only(),
            &runtime.memory,
        )
        .unwrap();
    let mut host = EscapeHost::default();
    prepare(
        &mut runtime,
        dc,
        10,
        4,
        SegmentedPointer::new(selector, 0).far_value(),
        u32::MAX,
    );
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::GuestFault
    );
    assert!(host.calls.is_empty());
    assert_eq!(read_output(&runtime, original), [0x5a; 32]);
}

#[test]
fn escape_start_doc_stops_when_the_job_or_the_first_page_fails() {
    let (mut runtime, dc, output) = fixture();
    write_name(&mut runtime, output);
    let mut host = EscapeHost {
        result: Some(HostResult::Count(-1)),
        ..Default::default()
    };
    let return_to = prepare(&mut runtime, dc, 10, 7, output, u32::MAX);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0xffff);
    assert!(matches!(
        host.calls.as_slice(),
        [Operation::StartDoc { .. }]
    ));

    let (mut runtime, dc, output) = fixture();
    write_name(&mut runtime, output);
    let mut host = EscapeHost {
        results: vec![
            HostResult::Count(42),
            HostResult::Count(-1),
            HostResult::Count(1),
        ],
        ..Default::default()
    };
    let return_to = prepare(&mut runtime, dc, 10, 7, output, u32::MAX);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0xffff);
    assert_eq!(host.calls.len(), 3);
    assert!(matches!(
        &host.calls[1],
        Operation::Print {
            operation: Win16PrintOperation::StartPage,
            ..
        }
    ));
    assert!(matches!(
        &host.calls[2],
        Operation::Print {
            operation: Win16PrintOperation::AbortDocument,
            ..
        }
    ));

    let (mut runtime, dc, output) = fixture();
    write_name(&mut runtime, output);
    let mut host = EscapeHost {
        results: vec![HostResult::Count(42), HostResult::Count(1)],
        fail_at: Some(1),
        ..Default::default()
    };
    prepare(&mut runtime, dc, 10, 7, output, u32::MAX);
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::HostFailure
    );
    assert_eq!(host.calls.len(), 3);
    assert!(matches!(
        &host.calls[2],
        Operation::Print {
            operation: Win16PrintOperation::AbortDocument,
            ..
        }
    ));
}

#[test]
fn escape_page_commands_pair_end_page_and_ignore_unused_pointers() {
    let (mut runtime, dc, output) = fixture();
    let mut host = EscapeHost {
        results: vec![HostResult::Count(3), HostResult::Count(4)],
        ..Default::default()
    };
    let return_to = prepare(&mut runtime, dc, 1, -1, u32::MAX, u32::MAX);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 4);
    assert_eq!(
        host.calls,
        [
            Operation::Print {
                operation: Win16PrintOperation::EndPage,
                dc: NATIVE_DC,
            },
            Operation::Print {
                operation: Win16PrintOperation::StartPage,
                dc: NATIVE_DC,
            },
        ]
    );
    assert_eq!(read_output(&runtime, output), [0x5a; 32]);

    let (mut runtime, dc, output) = fixture();
    let mut host = EscapeHost {
        result: Some(HostResult::Count(-1)),
        ..Default::default()
    };
    let return_to = prepare(&mut runtime, dc, 1, 0, 0, 0);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0xffff);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(read_output(&runtime, output), [0x5a; 32]);

    let (mut runtime, dc, _) = fixture();
    let mut host = EscapeHost {
        results: vec![HostResult::Count(1), HostResult::Count(5)],
        ..Default::default()
    };
    let return_to = prepare(&mut runtime, dc, 11, 0, u32::MAX, u32::MAX);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 5);
    assert_eq!(
        host.calls,
        [
            Operation::Print {
                operation: Win16PrintOperation::EndPage,
                dc: NATIVE_DC,
            },
            Operation::Print {
                operation: Win16PrintOperation::EndDocument,
                dc: NATIVE_DC,
            },
        ]
    );

    let (mut runtime, dc, _) = fixture();
    let mut host = EscapeHost {
        result: Some(HostResult::Count(0)),
        ..Default::default()
    };
    let return_to = prepare(&mut runtime, dc, 11, 9, 0xffff_0000, 0xffff_0000);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0);
    assert!(matches!(
        host.calls.as_slice(),
        [Operation::Print {
            operation: Win16PrintOperation::EndPage,
            ..
        }]
    ));

    for (code, status) in [(2_i16, 1_i32), (2, -2)] {
        let (mut runtime, dc, output) = fixture();
        let mut host = EscapeHost {
            result: Some(HostResult::Count(status)),
            ..Default::default()
        };
        let return_to = prepare(&mut runtime, dc, code, 0, 0, 0);
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, status as u16);
        assert_eq!(
            host.calls,
            [Operation::Print {
                operation: Win16PrintOperation::AbortDocument,
                dc: NATIVE_DC,
            }]
        );
        assert_eq!(read_output(&runtime, output), [0x5a; 32]);
    }
}

fn write_name(runtime: &mut Runtime, far: u32) {
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = b"Report".to_vec();
    bytes.resize(32, 0x5a);
    state
        .selectors
        .write(&mut runtime.memory, pointer, &bytes)
        .unwrap();
}

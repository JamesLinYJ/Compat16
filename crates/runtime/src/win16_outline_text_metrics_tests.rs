//! GDI.308 service-gate return, packed-prefix, owned-name and writeback checks.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostDc,
    Win16HostOutlineTextMetrics};
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup,
    Win16ReturnKind, lookup_export};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};

const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);
const OUTPUT_OFFSET: u16 = 0x20;
const WATCHED_BYTES: usize = 512;
const SENTINEL: u8 = 0x5a;

#[derive(Default)]
struct OutlineHost {
    calls: Vec<Win16HostDc>,
    metric: Option<Win16HostOutlineTextMetrics>,
    fail: bool,
}

impl DosHost for OutlineHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, _path: &[u8], _access: DosFileAccess) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open_with_sharing(&mut self, _path: &[u8], _access: DosFileAccess, _sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_seek(&mut self, _file: DosHostFile, _offset: i32, _origin: DosSeekOrigin) -> Result<u32, DosHostError> { panic!("unexpected host call") }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_get_current(&mut self, _drive: u8, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> { panic!("unexpected host call") }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> { panic!("unexpected host call") }
    fn directory_search_next(&mut self, _search: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> { panic!("unexpected host call") }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn guest_code_page(&self) -> text_codec::CodePage { panic!("unexpected host call") }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { panic!("unexpected host call") }
}

impl RuntimeHost for OutlineHost {
    fn win16_get_outline_text_metrics(
        &mut self,
        dc: Win16HostDc,
    ) -> Result<Option<Win16HostOutlineTextMetrics>, RuntimeError> {
        self.calls.push(dc);
        if self.fail {
            return Err(RuntimeError::new(Kind::HostFailure, "test native failure"));
        }
        Ok(self.metric.take())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for OutlineHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for OutlineHost {}
impl crate::RuntimeMidiHost for OutlineHost {}
impl crate::RuntimeNetbiosHost for OutlineHost {}

fn metric() -> Win16HostOutlineTextMetrics {
    Win16HostOutlineTextMetrics {
        fixed: std::array::from_fn(|index| (index as u8).wrapping_add(0x81)),
        // Include code units whose low byte is zero and surrogate halves.
        // This legacy output takes each low byte without an ANSI conversion.
        names: [vec![0x0046, 0x00e9, 0x4e2d], vec![0x0100, 0x03a9],
            vec![0xd83d, 0xde00], Vec::new()],
    }
}

fn successful_host() -> OutlineHost {
    OutlineHost { metric: Some(metric()), ..Default::default() }
}

fn fixture() -> (Runtime, u16, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\OUTLINE.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(NATIVE_DC).unwrap();
    let selector = state.selectors.alloc_block(PhysAddr(0x70000), 0x10000,
        AccessRights::read_write(), &runtime.memory).unwrap();
    state.selectors.write(&mut runtime.memory, SegmentedPointer::new(selector, 0),
        &[SENTINEL; WATCHED_BYTES]).unwrap();
    (runtime, dc, SegmentedPointer::new(selector, OUTPUT_OFFSET).far_value())
}

fn read_watched(runtime: &Runtime, far: u32) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far & 0xffff_0000).unwrap();
    let mut bytes = vec![0; WATCHED_BYTES];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn prepare(runtime: &mut Runtime, dc: u16, count: u16, output: u32) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(308)).unwrap();
    assert_eq!(descriptor.id,
        lookup_export(b"GDI", ExportLookupTarget::Name(b"GetOutlineTextMetrics")).unwrap().id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("fixed Pascal frame required");
    };
    assert_eq!(cleanup.callee_pop_bytes, 8);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&output.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&dc.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = 0xa1b2_a55a;
    runtime.cpu.regs.edx = 0xc3d4_5aa5;
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(runtime: &mut Runtime, host: &mut OutlineHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), result: u16) {
    assert_eq!(runtime.cpu.regs.eax, 0xa1b2_0000 | u32::from(result));
    assert_eq!(runtime.cpu.regs.edx, 0xc3d4_5aa5);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
}

fn expected_full_output() -> Vec<u8> {
    let mut bytes = metric().fixed.to_vec();
    // 114 + (3 + 1) + (2 + 1) + (2 + 1) + (0 + 1) = 125.
    // otmSize is word-rounded; the query result and copied length are not.
    bytes[..2].copy_from_slice(&126_u16.to_le_bytes());
    bytes.extend_from_slice(&[114, 0, 118, 0, 121, 0, 124, 0]);
    bytes.extend_from_slice(&[0x46, 0xe9, 0x2d, 0, 0, 0xa9, 0, 0x3d, 0, 0, 0]);
    assert_eq!(bytes.len(), 125);
    bytes
}

fn assert_output(runtime: &Runtime, far: u32, expected: &[u8]) {
    let bytes = read_watched(runtime, far);
    let start = usize::from(OUTPUT_OFFSET);
    assert_eq!(&bytes[..start], &[SENTINEL; OUTPUT_OFFSET as usize]);
    assert_eq!(&bytes[start..start + expected.len()], expected);
    assert!(bytes[start + expected.len()..].iter().all(|byte| *byte == SENTINEL));
}

#[test]
fn get_outline_text_metrics_selector_zero_queries_ignore_count_and_offset() {
    for output in [0_u32, 0x0000_1234, 0x0000_ffff] {
        for count in [0_u16, 1, 106, 114, 0x8000, 0xffff] {
            let (mut runtime, dc, watched) = fixture();
            let return_to = prepare(&mut runtime, dc, count, output);
            let mut host = successful_host();
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
            assert_return(&runtime, return_to, 125);
            assert_eq!(host.calls, [NATIVE_DC]);
            assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
        }
    }
}

#[test]
fn get_outline_text_metrics_zero_count_keeps_nonnull_success_without_writing() {
    for invalid_pointer in [false, true] {
        let (mut runtime, dc, watched) = fixture();
        let output = if invalid_pointer { 0xffff_ffff } else { watched };
        let return_to = prepare(&mut runtime, dc, 0, output);
        let mut host = successful_host();
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 1);
        assert_eq!(host.calls, [NATIVE_DC]);
        assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
    }
}

#[test]
fn get_outline_text_metrics_copies_every_raw_prefix_without_padding_or_extra_terminator() {
    let expected = expected_full_output();
    // Exercise odd fixed fields, the 106-byte boundary, every partial WORD
    // offset, partial names, and counts larger than the actual owned result.
    for count in (1_u16..=126).chain([512, 0x8000, 0xffe0]) {
        let (mut runtime, dc, output) = fixture();
        let return_to = prepare(&mut runtime, dc, count, output);
        let mut host = successful_host();
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 1);
        assert_eq!(host.calls, [NATIVE_DC]);
        assert_output(&runtime, output, &expected[..usize::from(count).min(expected.len())]);
    }
}

#[test]
fn get_outline_text_metrics_name_offsets_are_struct_relative_and_use_utf16_low_bytes() {
    let (mut runtime, dc, output) = fixture();
    let return_to = prepare(&mut runtime, dc, 125, output);
    let mut host = successful_host();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    let bytes = read_watched(&runtime, output);
    let record = &bytes[usize::from(OUTPUT_OFFSET)..];
    assert_eq!(&record[106..114], &[114, 0, 118, 0, 121, 0, 124, 0]);
    assert_eq!(&record[114..118], &[b'F', 0xe9, 0x2d, 0]);
    assert_eq!(&record[118..121], &[0, 0xa9, 0]);
    assert_eq!(&record[121..124], &[0x3d, 0, 0]);
    assert_eq!(record[124], 0);
    assert_output(&runtime, output, &expected_full_output());
}

#[test]
fn get_outline_text_metrics_otm_size_rounds_full_length_even_for_fixed_only_prefix() {
    for (extra_unit, required, rounded) in [(false, 125_u16, 126_u16), (true, 126, 126)] {
        let mut value = metric();
        if extra_unit { value.names[3].push(0x0058); }
        let (mut query, dc, watched) = fixture();
        let return_to = prepare(&mut query, dc, 0, 0);
        let mut host = OutlineHost { metric: Some(value.clone()), ..Default::default() };
        dispatch(&mut query, &mut host).unwrap();
        assert_return(&query, return_to, required);
        assert_eq!(read_watched(&query, watched), [SENTINEL; WATCHED_BYTES]);

        for count in [2_u16, 105, 106] {
            let (mut runtime, dc, output) = fixture();
            let return_to = prepare(&mut runtime, dc, count, output);
            let mut host = OutlineHost { metric: Some(value.clone()), ..Default::default() };
            dispatch(&mut runtime, &mut host).unwrap();
            assert_return(&runtime, return_to, 1);
            let mut expected = value.fixed[..usize::from(count)].to_vec();
            expected[..2].copy_from_slice(&rounded.to_le_bytes());
            assert_output(&runtime, output, &expected);
        }
    }
}

#[test]
fn get_outline_text_metrics_rejects_short_declared_capacity_before_host_work() {
    let (mut runtime, dc, watched) = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let selector = state.selectors.alloc_block(PhysAddr(0x70000 + u32::from(OUTPUT_OFFSET)), 125,
        AccessRights::read_write(), &runtime.memory).unwrap();
    prepare(&mut runtime, dc, 0xffff, SegmentedPointer::new(selector, 0).far_value());
    let mut host = successful_host();
    // This is the runtime's conservative memory-safety policy: validate the
    // declared capacity even if the eventual copied prefix would fit.
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
    assert!(host.calls.is_empty());
    assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
}

#[test]
fn get_outline_text_metrics_invalid_destinations_never_write_a_partial_prefix() {
    for (size, rights) in [(124, AccessRights::read_write()), (125, AccessRights::read_only())] {
        let (mut runtime, dc, watched) = fixture();
        let state = runtime.win16.as_mut().unwrap();
        let selector = state.selectors.alloc_block(PhysAddr(0x70000 + u32::from(OUTPUT_OFFSET)), size,
            rights, &runtime.memory).unwrap();
        prepare(&mut runtime, dc, 125, SegmentedPointer::new(selector, 0).far_value());
        let mut host = successful_host();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
    }
    for output in [0xffff_0000_u32, 0xffff_ffff] {
        let (mut runtime, dc, watched) = fixture();
        prepare(&mut runtime, dc, 125, output);
        let mut host = successful_host();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
    }
}

#[test]
fn get_outline_text_metrics_native_failure_and_host_error_preserve_guest_bytes() {
    for fail in [false, true] {
        for count in [0_u16, 1, 106, 125, 0xffe0] {
            let (mut runtime, dc, output) = fixture();
            let return_to = prepare(&mut runtime, dc, count, output);
            let mut host = OutlineHost { fail, ..Default::default() };
            let result = dispatch(&mut runtime, &mut host);
            if fail {
                assert_eq!(result.unwrap_err().kind(), Kind::HostFailure);
            } else {
                result.unwrap();
                assert_return(&runtime, return_to, 0);
            }
            assert_eq!(host.calls, [NATIVE_DC]);
            assert_eq!(read_watched(&runtime, output), [SENTINEL; WATCHED_BYTES]);
        }
    }
}

#[test]
fn get_outline_text_metrics_unknown_dc_fails_before_host_work() {
    for query in [false, true] {
        let (mut runtime, _, watched) = fixture();
        let return_to = prepare(&mut runtime, 0xffff, 125, if query { 0 } else { watched });
        let mut host = successful_host();
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0);
        assert!(host.calls.is_empty());
        assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
    }
}


#[test]
fn get_outline_text_metrics_max_unsigned_capacity_does_not_add_padding() {
    let (mut runtime, dc, watched) = fixture();
    let output = watched & 0xffff_0000;
    let return_to = prepare(&mut runtime, dc, 0xffff, output);
    let mut host = successful_host();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert_eq!(host.calls, [NATIVE_DC]);
    let expected = expected_full_output();
    let actual = read_watched(&runtime, watched);
    assert_eq!(&actual[..expected.len()], expected);
    assert!(actual[expected.len()..].iter().all(|byte| *byte == SENTINEL));
}

#[test]
fn get_outline_text_metrics_unrepresentable_rounded_size_fails_without_writes() {
    for required in [65534_usize, 65535, 65536] {
        for query in [false, true] {
            let (mut runtime, dc, watched) = fixture();
            let value = Win16HostOutlineTextMetrics {
                fixed: [0xa5; 106],
                names: [vec![0x0041; required - 118], Vec::new(), Vec::new(), Vec::new()],
            };
            let return_to = prepare(&mut runtime, dc, 2, if query { 0 } else { watched });
            let mut host = OutlineHost { metric: Some(value), ..Default::default() };
            dispatch(&mut runtime, &mut host).unwrap();
            let representable = required == 65534;
            let expected_result = if representable {
                if query { 65534 } else { 1 }
            } else { 0 };
            assert_return(&runtime, return_to, expected_result);
            assert_eq!(host.calls, [NATIVE_DC]);
            if representable && !query {
                assert_output(&runtime, watched, &65534_u16.to_le_bytes());
            } else {
                assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
            }
        }
    }
}

#[test]
fn get_outline_text_metrics_embedded_fullword_nul_is_a_malformed_owned_name() {
    for query in [false, true] {
        let (mut runtime, dc, watched) = fixture();
        let mut value = metric();
        value.names[0].insert(1, 0);
        let return_to = prepare(&mut runtime, dc, 125, if query { 0 } else { watched });
        let mut host = OutlineHost { metric: Some(value), ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0);
        assert_eq!(host.calls, [NATIVE_DC]);
        assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
    }
}

#[test]
fn get_outline_text_metrics_query_propagates_native_failure_and_host_error() {
    for fail in [false, true] {
        let (mut runtime, dc, watched) = fixture();
        let return_to = prepare(&mut runtime, dc, 0, 0x0000_1234);
        let mut host = OutlineHost { fail, ..Default::default() };
        let result = dispatch(&mut runtime, &mut host);
        if fail {
            assert_eq!(result.unwrap_err().kind(), Kind::HostFailure);
        } else {
            result.unwrap();
            assert_return(&runtime, return_to, 0);
        }
        assert_eq!(host.calls, [NATIVE_DC]);
        assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
    }
}


#[test]
fn get_outline_text_metrics_far_buffer_cannot_cross_even_owned_adjacent_selectors() {
    let (mut runtime, dc, watched) = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let selector = state.selectors.alloc_block(PhysAddr(0x70000), 0x10100,
        AccessRights::read_write(), &runtime.memory).unwrap();
    let pointer = SegmentedPointer::new(selector, 0xffa0);
    let last = state.selectors.add_bytes(pointer, 124).unwrap();
    assert_ne!(pointer.selector(), last.selector());
    runtime.memory.write_physical(PhysAddr(0x7ff80), &[SENTINEL; 256]).unwrap();
    prepare(&mut runtime, dc, 125, pointer.far_value());
    let mut host = successful_host();
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
    assert!(host.calls.is_empty());
    assert_eq!(read_watched(&runtime, watched), [SENTINEL; WATCHED_BYTES]);
    let mut actual = [0; 256];
    runtime.memory.read_physical(PhysAddr(0x7ff80), &mut actual).unwrap();
    assert_eq!(actual, [SENTINEL; 256]);
}

#[test]
fn get_outline_text_metrics_output_may_end_exactly_at_far_segment_boundary() {
    let (mut runtime, dc, watched) = fixture();
    let output = (watched & 0xffff_0000) | (0x10000 - 125);
    runtime.memory.write_physical(PhysAddr(0x7ff63), &[SENTINEL; 256]).unwrap();
    let return_to = prepare(&mut runtime, dc, 125, output);
    let mut host = successful_host();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert_eq!(host.calls, [NATIVE_DC]);
    let mut actual = [0; 256];
    runtime.memory.read_physical(PhysAddr(0x7ff63), &mut actual).unwrap();
    assert_eq!(&actual[..32], &[SENTINEL; 32]);
    assert_eq!(&actual[32..157], expected_full_output());
    assert_eq!(&actual[157..], &[SENTINEL; 99]);
}

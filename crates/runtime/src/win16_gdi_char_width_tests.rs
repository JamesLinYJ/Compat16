//! GDI.350 service gate, guest-range validation and signed-int writeback.

use super::*;
use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{DiagnosticKind as Kind, Runtime, Win16HostDc};
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup,
    Win16ReturnKind, lookup_export};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};

const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);

#[derive(Default)]
struct WidthHost {
    calls: Vec<Operation>,
    result: Option<ResultValue>,
    fail: bool,
}

impl DosHost for WidthHost {
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

impl RuntimeHost for WidthHost {
    fn win16_gdi_services(&mut self, operation: Operation) -> Result<ResultValue, RuntimeError> {
        self.calls.push(operation);
        if self.fail {
            return Err(RuntimeError::new(Kind::HostFailure, "test native failure"));
        }
        Ok(self.result.take().expect("test supplies a native result"))
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for WidthHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for WidthHost {}
impl crate::RuntimeMidiHost for WidthHost {}
impl crate::RuntimeNetbiosHost for WidthHost {}

fn fixture() -> (Runtime, u16, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\WIDTH.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(NATIVE_DC).unwrap();
    let selector = state.selectors.alloc_block(PhysAddr(0x70000), 0x10000,
        AccessRights::read_write(), &runtime.memory).unwrap();
    let pointer = SegmentedPointer::new(selector, 0);
    state.selectors.write(&mut runtime.memory, pointer, &[0x5a; 32]).unwrap();
    (runtime, dc, pointer.far_value())
}

fn read_output(runtime: &Runtime, far: u32) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = vec![0; 32];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn prepare(runtime: &mut Runtime, dc: u16, first: u16, last: u16, output: u32) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(350)).unwrap();
    assert_eq!(descriptor.id, lookup_export(b"GDI", ExportLookupTarget::Name(b"GetCharWidth")).unwrap().id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else { panic!("fixed Pascal frame required"); };
    assert_eq!(cleanup.callee_pop_bytes, 10);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&output.to_le_bytes());
    bytes.extend_from_slice(&last.to_le_bytes());
    bytes.extend_from_slice(&first.to_le_bytes());
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

fn dispatch(runtime: &mut Runtime, host: &mut WidthHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), result: u16) {
    assert_eq!(runtime.cpu.regs.eax, 0xa1b2_0000 | u32::from(result));
    assert_eq!(runtime.cpu.regs.edx, 0xc3d4_5aa5);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
}

#[test]
fn get_char_width_gate_preserves_unsigned_codes_register_halves_and_signed_output() {
    let (mut runtime, dc, output) = fixture();
    let widths = vec![-32768, -1, 0, 32767];
    let mut host = WidthHost {
        result: Some(ResultValue::CharWidths { success: true, entries: widths }),
        ..Default::default()
    };
    let return_to = prepare(&mut runtime, dc, 0xfffc, 0xffff, output);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_return(&runtime, return_to, 1);
    assert_eq!(host.calls, [Operation::GetCharWidth { dc: NATIVE_DC, first: 0xfffc, last: 0xffff }]);
    let bytes = read_output(&runtime, output);
    let expected: Vec<u8> = [-32768_i16, -1, 0, 32767]
        .iter().flat_map(|width| width.to_le_bytes()).collect();
    assert_eq!(&bytes[..8], expected);
    assert_eq!(&bytes[8..], &[0x5a; 24]);
}

#[test]
fn get_char_width_invalid_ranges_null_and_unknown_dc_fail_without_host_work() {
    for (first, last, null, unknown) in [
        (10, 9, false, false), (0, 0xffff, false, false),
        (0, 0x8000, false, false), (65, 65, true, false),
        (65, 65, false, true),
    ] {
        let (mut runtime, dc, output) = fixture();
        let return_to = prepare(&mut runtime, if unknown { 0xffff } else { dc }, first, last,
            if null { 0 } else { output });
        let mut host = WidthHost::default();
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0);
        assert!(host.calls.is_empty());
        assert_eq!(read_output(&runtime, output), [0x5a; 32]);
    }
}

#[test]
fn get_char_width_far_output_cannot_wrap_its_segment() {
    let (mut runtime, dc, output) = fixture();
    let return_to = prepare(&mut runtime, dc, 65, 66, output | 0xfffe);
    let mut host = WidthHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0);
    assert!(host.calls.is_empty());
    assert_eq!(read_output(&runtime, output), [0x5a; 32]);
}

#[test]
fn get_char_width_preflights_read_only_short_and_rom_destinations() {
    for (base, size, rights) in [
        (0x70000, 3, AccessRights::read_write()),
        (0x70000, 4, AccessRights::read_only()),
        (0xf0000, 4, AccessRights::read_write()),
    ] {
        let (mut runtime, dc, output) = fixture();
        let state = runtime.win16.as_mut().unwrap();
        let alias = state.selectors.alloc_block(PhysAddr(base), size, rights, &runtime.memory).unwrap();
        prepare(&mut runtime, dc, 65, 66, SegmentedPointer::new(alias, 0).far_value());
        let mut host = WidthHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert!(host.calls.is_empty());
        assert_eq!(read_output(&runtime, output), [0x5a; 32]);
    }
}

#[test]
fn get_char_width_failures_and_malformed_results_do_not_write_partial_output() {
    for (result, fail, error) in [
        (Some(ResultValue::CharWidths { success: false, entries: vec![123, 456] }), false, None),
        (Some(ResultValue::CharWidths { success: true, entries: vec![123] }), false, Some(Kind::InternalInvariant)),
        (Some(ResultValue::CharWidths { success: true, entries: vec![1, 2, 3] }), false, Some(Kind::InternalInvariant)),
        (Some(ResultValue::Bool(true)), false, Some(Kind::InternalInvariant)),
        (None, true, Some(Kind::HostFailure)),
    ] {
        let (mut runtime, dc, output) = fixture();
        let return_to = prepare(&mut runtime, dc, 65, 66, output);
        let mut host = WidthHost { result, fail, ..Default::default() };
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
}

#[test]
fn get_char_width_maximum_far_array_is_65536_bytes_not_zero() {
    let (mut runtime, dc, output) = fixture();
    let return_to = prepare(&mut runtime, dc, 0, 0x7fff, output);
    let mut host = WidthHost {
        result: Some(ResultValue::CharWidths { success: true, entries: vec![-2; 0x8000] }),
        ..Default::default()
    };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    let state = runtime.win16.as_ref().unwrap();
    let mut last = [0; 2];
    let pointer = state.selectors.pointer_from_far(output | 0xfffe).unwrap();
    state.selectors.read(&runtime.memory, pointer, &mut last).unwrap();
    assert_eq!(last, (-2_i16).to_le_bytes());
}

#[test]
fn get_char_width_unrepresentable_native_width_fails_without_wrapping_or_partial_write() {
    for width in [32768, -32769, i32::MIN, i32::MAX] {
        let (mut runtime, dc, output) = fixture();
        let return_to = prepare(&mut runtime, dc, 65, 66, output);
        let mut host = WidthHost {
            result: Some(ResultValue::CharWidths { success: true, entries: vec![12, width] }),
            ..Default::default()
        };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0);
        assert_eq!(host.calls.len(), 1);
        assert_eq!(read_output(&runtime, output), [0x5a; 32]);
    }
}

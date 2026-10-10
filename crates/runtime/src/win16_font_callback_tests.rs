//! Real Pascal guest callback returns and copied family record ownership.
use super::*;
use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{Runtime, Win16HostDc};
use guest_core::{GuestMemory, Selector, io::NoPorts};
use win16_abi::{ExportLookupTarget, lookup_export};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};

#[derive(Default)]
struct FontHost { calls: Vec<(bool, Option<Vec<u8>>)>, records: Vec<Win16HostFontRecord> }
impl DosHost for FontHost {
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


impl RuntimeHost for FontHost {
    fn win16_enum_fonts(&mut self, _: Win16HostDc, face: Option<&[u8]>) -> Result<Vec<Win16HostFontRecord>, RuntimeError> {
        self.calls.push((false, face.map(Vec::from))); Ok(self.records.clone())
    }
    fn win16_enum_font_families(&mut self, _: Win16HostDc, face: Option<&[u8]>) -> Result<Vec<Win16HostFontRecord>, RuntimeError> {
        self.calls.push((true, face.map(Vec::from))); Ok(self.records.clone())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for FontHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for FontHost {}
impl crate::RuntimeMidiHost for FontHost {}
impl crate::RuntimeNetbiosHost for FontHost {}

fn record() -> Win16HostFontRecord {
    let mut record = Win16HostFontRecord {
        logfont_dimensions: [-17, 8, 0, 0, 700], logfont_styles: [1, 0, 0, 0, 1, 2, 3, 4],
        face_name: [0; 32], full_name: [0; 64], style: [0; 32],
        textmetric_dimensions: [19, 15, 4, 1, 2, 8, 20, 700],
        textmetric_styles: [1, 0, 0, 32, 255, 63, 32, 4, 0],
        textmetric_extra: [1, 96, 96], newtextmetric_extra: Some([0x12345678, 2048, 19, 8]), font_type: 4,
    };
    record.face_name[..5].copy_from_slice(b"Face\0");
    record.full_name[..10].copy_from_slice(b"Full Name\0");
    record.style[..5].copy_from_slice(b"Bold\0");
    record
}

fn fixture() -> (Runtime, u16, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\FONTS.NE").unwrap();
    let callback = (u32::from(runtime.cpu.regs.cs) << 16) | 0x80;
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(Win16HostDc(0x1234)).unwrap();
    let pointer = state.selectors.pointer_from_far(callback).unwrap();
    let physical = state.selectors.translate(pointer, Access::Execute, 3, &runtime.memory).unwrap();
    runtime.memory.write(physical, &[0xca, 14, 0]).unwrap();
    (runtime, dc, callback)
}

fn prepare(runtime: &mut Runtime, ordinal: u16, dc: u16, callback: u32) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_to = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp() + 18);
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_to.1.to_le_bytes());
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(&0x89abcdef_u32.to_le_bytes());
    bytes.extend_from_slice(&callback.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&dc.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    return_to
}

fn dispatch(runtime: &mut Runtime, host: &mut FontHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0)
}

fn finish(runtime: &mut Runtime, result: u16) {
    let state = runtime.win16.as_mut().unwrap();
    runtime.cpu.regs.set_ax(result);
    let segments = crate::win16_loader::Win16Segments { selectors: &state.selectors, memory_len: runtime.memory.len() };
    runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments).unwrap();
    assert_eq!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::FarReturn));
    state.finish_font_callback(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).unwrap();
}

#[test]
fn enum_font_families_callback_layout_zero_stop_and_cleanup() {
    for (ordinal, font_size) in [(330, 146), (70, 50)] {
        let (mut runtime, dc, callback) = fixture();
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        let mut host = FontHost { records: vec![record(), record()], ..Default::default() };
        let return_to = prepare(&mut runtime, ordinal, dc, callback);
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls, vec![(ordinal == 330, None)]);
        let state = runtime.win16.as_ref().unwrap();
        let frame = state.font_callbacks.last().unwrap();
        let mut bytes = vec![0; font_size + 41];
        state.selectors.read(&runtime.memory, frame.data, &mut bytes).unwrap();
        assert_eq!(&bytes[..2], &(-17_i16).to_le_bytes());
        assert_eq!(&bytes[18..23], b"Face\0");
        if ordinal == 330 {
            assert_eq!(&bytes[50..114], &record().full_name);
            assert_eq!(&bytes[114..146], &record().style);
        }
        assert_eq!(&bytes[font_size..font_size + 2], &19_i16.to_le_bytes());
        assert_eq!(&bytes[font_size + 31..font_size + 35], &0x12345678_u32.to_le_bytes());
        let stack = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
        let mut args = [0; 18]; state.selectors.read(&runtime.memory, stack, &mut args).unwrap();
        assert_eq!(&args[4..8], &0x89abcdef_u32.to_le_bytes());
        assert_eq!(&args[8..10], &4_u16.to_le_bytes());
        assert_eq!(u32::from_le_bytes(args[14..18].try_into().unwrap()), frame.data.far_value());
        assert_eq!(u32::from_le_bytes(args[10..14].try_into().unwrap()), frame.data.far_value() + font_size as u32);
        let retired_data = frame.data;
        finish(&mut runtime, 0);
        assert_eq!(runtime.cpu.regs.ax(), 0);
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
        assert!(runtime.win16.as_ref().unwrap().font_callbacks.is_empty());
        assert_eq!(runtime.win16.as_ref().unwrap().heap.allocation_count(), allocations);
        let state = runtime.win16.as_mut().unwrap();
        assert!(state.callback_kinds.is_empty());
        assert!(state.callback_frame_ids.is_empty());
        assert!(state.legacy_cpu_frames.is_empty());
        assert!(state.selectors.translate(retired_data, Access::Read, 1, &runtime.memory).is_err());
        assert!(state.finish_font_callback(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).is_err());
    }
}

#[test]
fn enum_font_families_last_return_snapshot_and_nested_fonts() {
    let (mut runtime, dc, callback) = fixture();
    let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
    let mut host = FontHost { records: vec![record(), record()], ..Default::default() };
    let return_to = prepare(&mut runtime, 330, dc, callback);
    dispatch(&mut runtime, &mut host).unwrap();
    // Mutating subsequent host results must not alter the outer copied snapshot.
    host.records = vec![record()];
    let outer_data = runtime.win16.as_ref().unwrap().font_callbacks[0].data;
    // Model a guest FAR CALL: reserve its API frame below the outer callback stack.
    let outer_sp = runtime.cpu.regs.sp();
    runtime.cpu.regs.set_sp(outer_sp - 18);
    prepare(&mut runtime, 70, dc, callback);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.win16.as_ref().unwrap().font_callbacks.len(), 2);
    assert_ne!(runtime.win16.as_ref().unwrap().font_callbacks[1].data, outer_data);
    finish(&mut runtime, 7);
    assert_eq!(runtime.cpu.regs.sp(), outer_sp);
    finish(&mut runtime, 1);
    assert_eq!(runtime.win16.as_ref().unwrap().font_callbacks.len(), 1);
    finish(&mut runtime, 0xfffe);
    assert_eq!(runtime.cpu.regs.ax(), 0xfffe);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert_eq!(host.calls, vec![(true, None), (false, None)]);
    assert_eq!(runtime.win16.as_ref().unwrap().heap.allocation_count(), allocations);
}

#[test]
fn enum_font_families_invalid_dc_empty_result_bad_callback_and_stack() {
    for case in 0..4 {
        let (mut runtime, dc, callback) = fixture();
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        let mut host = FontHost { records: if case == 1 { vec![] } else { vec![record()] }, ..Default::default() };
        if case == 3 { runtime.cpu.regs.set_sp(16); }
        prepare(&mut runtime, 330, if case == 0 { 0xffff } else { dc }, if case == 2 { 0 } else { callback });
        let result = dispatch(&mut runtime, &mut host);
        if case < 2 { result.unwrap(); assert_eq!(runtime.cpu.regs.ax(), 0); }
        else { assert!(result.is_err()); }
        assert_eq!(host.calls.len(), usize::from(case != 0));
        assert!(runtime.win16.as_ref().unwrap().font_callbacks.is_empty());
        assert_eq!(runtime.win16.as_ref().unwrap().heap.allocation_count(), allocations);
    }
}

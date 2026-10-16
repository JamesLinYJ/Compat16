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

fn return_font_callback(runtime: &mut Runtime, result: u16) -> Result<(), RuntimeError> {
    let state = runtime.win16.as_mut().unwrap();
    runtime.cpu.regs.set_ax(result);
    let segments = crate::win16_loader::Win16Segments { selectors: &state.selectors, memory_len: runtime.memory.len() };
    runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments).unwrap();
    assert_eq!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::FarReturn));
    state.finish_font_callback(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory)
}

fn finish(runtime: &mut Runtime, result: u16) {
    return_font_callback(runtime, result).unwrap();
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

#[test]
fn returned_font_callback_page_lock_cleanup_retries_without_reentering_guest() {
    // Exercise the actual selector-based guest API and RETF. Only the terminal
    // execution-ended token is injected because this test steps the CPU itself.
    for (ordinal, terminal, cancel_while_locked) in [
        (70, false, false), (70, true, false), (70, true, true),
        (330, false, false), (330, true, false), (330, true, true),
    ] {
        let (mut runtime, dc, callback) = fixture();
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        let mut host = FontHost { records: vec![record()], ..Default::default() };
        let return_to = prepare(&mut runtime, ordinal, dc, callback);
        dispatch(&mut runtime, &mut host).unwrap();
        let state = runtime.win16.as_mut().unwrap();
        let data = state.font_callbacks.last().unwrap().data;
        let selector = (data.far_value() >> 16) as u16;
        assert_eq!(state.kernel_global_page_lock(selector).unwrap(), 1);
        assert_eq!(state.legacy_cpu_frames.len(), 1);

        let error = return_font_callback(&mut runtime, 7).unwrap_err();
        assert_eq!(error.to_string(), crate::runtime_error(Win16Error::Locked).to_string());
        let state = runtime.win16.as_mut().unwrap();
        assert!(state.legacy_cpu_frames.is_empty());
        assert_eq!(state.font_callbacks.len(), 1);
        assert!(state.font_callbacks.last().unwrap().active_call.is_some());
        assert!(!state.font_callbacks.last().unwrap().allocation_locked);
        assert_eq!(state.heap.allocation_count(), allocations + 1);
        assert!(state.font_code_references().contains(&callback));
        let bindings = state.callback_frame_ids.clone();
        let code_references = state.font_code_references();
        // Retry completion while still pinned. The cached return must be
        // retained, with no second guest execution or CPU owner required.
        assert!(state.finish_font_callback(&mut runtime.cpu,
            &mut runtime.dos, &mut runtime.memory).is_err());
        assert_eq!(state.callback_frame_ids, bindings);
        assert_eq!(state.font_code_references(), code_references);

        let ended = super::super::execute::Win16TaskExecutionEnded::for_test();
        runtime.cpu.regs.set_ax(0x4567);
        let terminal_registers = runtime.cpu.regs.clone();
        if cancel_while_locked {
            for _ in 0..2 {
                assert!(state.cancel_font_callback_for_teardown(&ended,
                    &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).is_err());
                assert!(state.font_callbacks.last().unwrap().active_call.as_ref()
                    .unwrap().is_terminal_aborted());
                assert_eq!(runtime.cpu.regs, terminal_registers);
                assert_eq!(state.callback_frame_ids, bindings);
                assert_eq!(state.font_code_references(), code_references);
                assert!(state.legacy_cpu_frames.is_empty());
            }
            assert!(state.finish_font_callback(&mut runtime.cpu,
                &mut runtime.dos, &mut runtime.memory).is_err());
        }
        assert_eq!(state.kernel_global_page_unlock(selector).unwrap(), 0);
        if terminal {
            state.cancel_font_callback_for_teardown(&ended,
                &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).unwrap();
            assert_eq!(runtime.cpu.regs, terminal_registers);
            assert!(state.cancel_font_callback_for_teardown(&ended,
                &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).is_err());
            assert_eq!(runtime.cpu.regs, terminal_registers);
        } else {
            state.finish_font_callback(&mut runtime.cpu,
                &mut runtime.dos, &mut runtime.memory).unwrap();
            assert_eq!(runtime.cpu.regs.ax(), 7);
            assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
        }
        assert!(state.font_callbacks.is_empty());
        assert!(state.callback_kinds.is_empty());
        assert!(state.callback_frame_ids.is_empty());
        assert!(state.legacy_cpu_frames.is_empty());
        assert!(state.font_code_references().is_empty());
        assert_eq!(state.heap.allocation_count(), allocations);
        assert!(state.selectors.translate(data, Access::Read, 1, &runtime.memory).is_err());
        assert_eq!(host.calls.len(), 1);
    }
}

fn write_callback_code(runtime: &mut Runtime, callback: u32, bytes: &[u8]) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(callback).unwrap();
    let physical = state.selectors.translate(pointer, Access::Execute,
        bytes.len(), &runtime.memory).unwrap();
    runtime.memory.write(physical, bytes).unwrap();
}

#[test]
fn enum_font_families_nested_locked_inner_cleanup_preserves_outer_until_retirement() {
    for terminal in [false, true] {
        let (mut runtime, dc, callback) = fixture();
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        let inner_callback = callback + 0x40;
        write_callback_code(&mut runtime, inner_callback, &[0xca, 14, 0]);
        let state = runtime.win16.as_mut().unwrap();
        let inner_gate = (state.bindings.len() * 2) as u16;
        state.bindings.push(ImportBinding::Supported(
            lookup_export(b"GDI", ExportLookupTarget::Ordinal(70)).unwrap()));
        let gate_selector = state.gate_selector.0;
        // The outer callback actually pushes Pascal arguments and FAR CALLs
        // EnumFonts. No synthetic nested CPU context or return proof is used.
        let mut code = vec![0x68];
        code.extend_from_slice(&dc.to_le_bytes());
        for value in [0_u32, inner_callback, 0x89abcdef] {
            code.extend_from_slice(&[0x66, 0x68]);
            code.extend_from_slice(&value.to_le_bytes());
        }
        code.push(0x9a);
        code.extend_from_slice(&inner_gate.to_le_bytes());
        code.extend_from_slice(&gate_selector.to_le_bytes());
        let outer_resume_ip = (callback as u16) + code.len() as u16;
        code.extend_from_slice(&[0xca, 14, 0]);
        write_callback_code(&mut runtime, callback, &code);
        let mut host = FontHost { records: vec![record()], ..Default::default() };
        let return_to = prepare(&mut runtime, 330, dc, callback);
        let outer_saved = runtime.cpu.regs.clone();
        dispatch(&mut runtime, &mut host).unwrap();
        let state = runtime.win16.as_ref().unwrap();
        let outer_data = state.font_callbacks[0].data;
        let outer_allocation = state.font_callbacks[0].allocation;
        let outer_binding = state.callback_frame_ids.clone();
        let outer_references = state.font_code_references();
        let outer_call = format!("{:?}", state.font_callbacks[0].active_call);
        let outer_code_root = state.selectors.reference(Selector(outer_saved.cs)).unwrap();
        let outer_stack_root = state.selectors.reference(Selector(outer_saved.ss)).unwrap();
        assert!(state.legacy_cpu_frames[0].owner.owns_selector(outer_code_root));
        assert!(state.legacy_cpu_frames[0].owner.owns_selector(outer_stack_root));
        let outer_sp = runtime.cpu.regs.sp();
        let mut outer_bytes = [0; 187];
        state.selectors.read(&runtime.memory, outer_data, &mut outer_bytes).unwrap();
        for _ in 0..5 {
            let state = runtime.win16.as_ref().unwrap();
            let segments = crate::win16_loader::Win16Segments {
                selectors: &state.selectors, memory_len: runtime.memory.len(),
            };
            runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments).unwrap();
        }
        assert!(matches!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::FarCall { .. })));
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip()), (gate_selector, inner_gate));
        dispatch(&mut runtime, &mut host).unwrap();
        let state = runtime.win16.as_mut().unwrap();
        let inner_data = state.font_callbacks[1].data;
        let inner_selector = (inner_data.far_value() >> 16) as u16;
        assert_eq!(state.legacy_cpu_frames.len(), 2);
        assert_eq!(state.kernel_global_page_lock(inner_selector).unwrap(), 1);
        let bindings = state.callback_frame_ids.clone();
        let references = state.font_code_references();
        assert_eq!(return_font_callback(&mut runtime, 7).unwrap_err().to_string(),
            crate::runtime_error(Win16Error::Locked).to_string());
        // Only the terminal execution-ended token is injected: the nested
        // entry, FAR return and failed payload free above executed normally.
        let ended = super::super::execute::Win16TaskExecutionEnded::for_test();
        runtime.cpu.regs.set_ax(0x4567);
        let retained_registers = runtime.cpu.regs.clone();
        for _ in 0..2 {
            let state = runtime.win16.as_mut().unwrap();
            let result = if terminal {
                state.cancel_font_callback_for_teardown(&ended,
                    &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory)
            } else {
                state.finish_font_callback(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory)
            };
            assert_eq!(result.unwrap_err().to_string(), crate::runtime_error(Win16Error::Locked).to_string());
            assert_eq!(runtime.cpu.regs, retained_registers);
            assert_eq!(state.heap.allocation_count(), allocations + 2);
            assert_eq!(state.callback_frame_ids, bindings);
            assert_eq!(state.callback_kinds.len(), 2);
            assert_eq!(state.font_code_references(), references);
            assert_eq!(state.legacy_cpu_frames.len(), 1);
            assert_eq!(format!("{:?}", state.font_callbacks[0].active_call), outer_call);
            assert!(state.legacy_cpu_frames[0].owner.owns_selector(outer_code_root));
            assert!(state.legacy_cpu_frames[0].owner.owns_selector(outer_stack_root));
            let outer = &state.font_callbacks[0];
            assert_eq!(outer.allocation, outer_allocation);
            assert!(outer.allocation_locked);
            assert_eq!(outer.next_index, 1);
            assert_eq!(outer.last_result, 0);
            assert!(!outer.active_call.as_ref().unwrap().is_terminal_aborted());
            let mut bytes = [0; 187];
            state.selectors.read(&runtime.memory, outer_data, &mut bytes).unwrap();
            assert_eq!(bytes, outer_bytes);
        }
        let state = runtime.win16.as_mut().unwrap();
        assert_eq!(state.kernel_global_page_unlock(inner_selector).unwrap(), 0);
        if terminal {
            state.cancel_font_callback_for_teardown(&ended,
                &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).unwrap();
            assert_eq!(runtime.cpu.regs, retained_registers);
        } else {
            state.finish_font_callback(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).unwrap();
            assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
                ((callback >> 16) as u16, outer_resume_ip, outer_sp));
            assert_eq!(runtime.cpu.regs.ax(), 7);
        }
        assert_eq!(state.font_callbacks.len(), 1);
        assert_eq!(state.callback_frame_ids, outer_binding);
        assert_eq!(state.callback_kinds.len(), 1);
        assert_eq!(state.font_code_references(), outer_references);
        assert_eq!(state.legacy_cpu_frames.len(), 1);
        assert_eq!(format!("{:?}", state.font_callbacks[0].active_call), outer_call);
        assert!(state.legacy_cpu_frames[0].owner.owns_selector(outer_code_root));
        assert!(state.legacy_cpu_frames[0].owner.owns_selector(outer_stack_root));
        assert_eq!(state.heap.allocation_count(), allocations + 1);
        assert!(state.selectors.translate(inner_data, Access::Read, 1, &runtime.memory).is_err());
        assert!(state.selectors.translate(outer_data, Access::Read, 187, &runtime.memory).is_ok());
        if terminal {
            state.cancel_font_callback_for_teardown(&ended,
                &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).unwrap();
            assert_eq!(runtime.cpu.regs, outer_saved);
        } else {
            finish(&mut runtime, 9);
            assert_eq!(runtime.cpu.regs.ax(), 9);
            assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
        }
        let retired_registers = runtime.cpu.regs.clone();
        let state = runtime.win16.as_mut().unwrap();
        assert!(state.font_callbacks.is_empty());
        assert!(state.callback_frame_ids.is_empty());
        assert!(state.callback_kinds.is_empty());
        assert!(state.font_code_references().is_empty());
        assert!(state.legacy_cpu_frames.is_empty());
        assert_eq!(state.heap.allocation_count(), allocations);
        assert!(state.selectors.translate(outer_data, Access::Read, 1, &runtime.memory).is_err());
        assert!(state.cancel_font_callback_for_teardown(&ended,
            &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).is_err());
        assert!(state.finish_font_callback(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).is_err());
        assert_eq!(runtime.cpu.regs, retired_registers);
        assert_eq!(host.calls, vec![(true, None), (false, None)]);
    }
}

#[test]
fn enum_font_families_entered_fault_terminal_cleanup_retries_without_return_proof() {
    for (code, malformed_return) in [(&[0x0f, 0x0b][..], false), (&[0xca, 12, 0][..], true)] {
        let (mut runtime, dc, callback) = fixture();
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        write_callback_code(&mut runtime, callback, code);
        let mut host = FontHost { records: vec![record(), record()], ..Default::default() };
        prepare(&mut runtime, 330, dc, callback);
        let saved_registers = runtime.cpu.regs.clone();
        dispatch(&mut runtime, &mut host).unwrap();
        let state = runtime.win16.as_mut().unwrap();
        let data = state.font_callbacks[0].data;
        let selector = (data.far_value() >> 16) as u16;
        let bindings = state.callback_frame_ids.clone();
        let references = state.font_code_references();
        assert_eq!(state.kernel_global_page_lock(selector).unwrap(), 1);
        let segments = crate::win16_loader::Win16Segments {
            selectors: &state.selectors, memory_len: runtime.memory.len(),
        };
        let step = runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments);
        if malformed_return {
            step.unwrap();
            assert_eq!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::FarReturn));
        } else {
            assert!(step.is_err());
        }
        // A real invalid instruction or RETF with the wrong Pascal stack
        // adjustment cannot manufacture successful callback completion.
        assert!(state.finish_font_callback(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).is_err());
        assert_eq!(state.legacy_cpu_frames.len(), 1);
        assert_eq!(state.font_callbacks[0].next_index, 1);
        assert_eq!(state.font_callbacks[0].last_result, 0);
        // This manually stepped fixture injects only the sealed terminal
        // boundary token, never a guest return or CPU completion proof.
        let ended = super::super::execute::Win16TaskExecutionEnded::for_test();
        let mut terminal_registers = saved_registers.clone();
        for attempt in 0..2 {
            assert_eq!(state.cancel_font_callback_for_teardown(&ended,
                &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).unwrap_err().to_string(),
                crate::runtime_error(Win16Error::Locked).to_string());
            assert_eq!(runtime.cpu.regs, terminal_registers);
            assert!(state.legacy_cpu_frames.is_empty());
            assert_eq!(state.callback_frame_ids, bindings);
            assert_eq!(state.callback_kinds.len(), 1);
            assert_eq!(state.font_code_references(), references);
            assert_eq!(state.heap.allocation_count(), allocations + 1);
            assert_eq!(state.font_callbacks[0].next_index, 1);
            assert_eq!(state.font_callbacks[0].last_result, 0);
            assert!(state.font_callbacks[0].active_call.as_ref().unwrap().is_terminal_aborted());
            assert!(state.selectors.translate(data, Access::Read, 1, &runtime.memory).is_ok());
            assert!(state.finish_font_callback(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).is_err());
            assert_eq!(runtime.cpu.regs, terminal_registers);
            if attempt == 0 {
                // A second cancellation must not replay the first CPU restore.
                runtime.cpu.regs.set_ax(0x4567);
                terminal_registers = runtime.cpu.regs.clone();
            }
        }
        assert_eq!(state.kernel_global_page_unlock(selector).unwrap(), 0);
        state.cancel_font_callback_for_teardown(&ended,
            &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).unwrap();
        assert!(state.font_callbacks.is_empty());
        assert!(state.callback_frame_ids.is_empty());
        assert!(state.callback_kinds.is_empty());
        assert!(state.font_code_references().is_empty());
        assert!(state.legacy_cpu_frames.is_empty());
        assert_eq!(state.heap.allocation_count(), allocations);
        assert!(state.selectors.translate(data, Access::Read, 1, &runtime.memory).is_err());
        assert!(state.cancel_font_callback_for_teardown(&ended,
            &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory).is_err());
        assert_eq!(runtime.cpu.regs, terminal_registers);
        assert_eq!(host.calls, vec![(true, None)]);
    }
}

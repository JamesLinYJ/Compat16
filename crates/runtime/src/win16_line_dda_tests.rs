//! Mock LineDDA service-gate calls and actual guest RETF execution.
use super::*;
use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::Runtime;
use guest_core::{GuestMemory, io::NoPorts};
use win16_abi::{ExportLookupTarget, lookup_export};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};

#[derive(Default)]
struct LineHost {
    calls: Vec<(i32, i32, i32, i32)>,
    points: Vec<Win16DrawingPoint>,
    success: bool,
    fail: bool,
    wrong_result: bool,
}
impl DosHost for LineHost {
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

impl RuntimeHost for LineHost {
    fn win16_gdi(&mut self, operation: DrawingOperation) -> Result<DrawingResult, RuntimeError> {
        let DrawingOperation::LineDda { x_start, y_start, x_end, y_end } = operation else {
            panic!("unexpected drawing call")
        };
        self.calls.push((x_start, y_start, x_end, y_end));
        if self.fail { return Err(RuntimeError::new(Kind::HostFailure, "mock LineDDA failure")); }
        if self.wrong_result { return Ok(DrawingResult::Bool(true)); }
        Ok(DrawingResult::LineDda { success: self.success, points: self.points.clone() })
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for LineHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for LineHost {}
impl crate::RuntimeMidiHost for LineHost {}
impl crate::RuntimeNetbiosHost for LineHost {}

fn fixture(null_callback: bool, pop: u16) -> (Runtime, (u16, u16, u16), u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\LINEDDA.NE").unwrap();
    let callback = (u32::from(runtime.cpu.regs.cs) << 16) | 0x80;
    let return_to = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp() + 20);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(callback).unwrap();
    let physical = state.selectors.translate(pointer, Access::Execute, 3, &runtime.memory).unwrap();
    runtime.memory.write(physical, &[0xca, pop as u8, (pop >> 8) as u8]).unwrap();
    let mut bytes = Vec::from(return_to.1.to_le_bytes());
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(&0x89abcdef_u32.to_le_bytes());
    bytes.extend_from_slice(&(if null_callback { 0 } else { callback }).to_le_bytes());
    for word in [-1_i16, i16::MAX, -19, i16::MIN] { bytes.extend_from_slice(&word.to_le_bytes()); }
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(lookup_export(b"GDI", ExportLookupTarget::Ordinal(100)).unwrap()));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    (runtime, return_to, callback)
}

fn dispatch(runtime: &mut Runtime, host: &mut impl RuntimeHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0)
}
fn assert_retired(runtime: &Runtime, allocations: usize) {
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.line_dda_callbacks.is_empty());
    assert!(state.callback_kinds.is_empty());
    assert!(state.callback_frame_ids.is_empty());
    assert!(state.legacy_cpu_frames.is_empty());
    assert!(state.line_dda_code_references().is_empty());
    assert_eq!(state.heap.allocation_count(), allocations);
}
fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16)) {
    // Local deterministic Void policy, not a historical AX/DX guarantee.
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0xa55a, 0x5aa5));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
}
fn retf(runtime: &mut Runtime) -> Result<(), RuntimeError> {
    let state = runtime.win16.as_mut().unwrap();
    let segments = crate::win16_loader::Win16Segments { selectors: &state.selectors, memory_len: runtime.memory.len() };
    runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments).unwrap();
    assert_eq!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::FarReturn));
    state.finish_line_dda_callback(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory)
}

#[test]
fn line_dda_void_null_failed_and_empty_results_preserve_caller() {
    for (null, success, points) in [(true, true, vec![Win16DrawingPoint { x: 1, y: 2 }]),
        (false, false, vec![Win16DrawingPoint { x: 1, y: 2 }]), (false, true, vec![])] {
        let (mut runtime, return_to, _) = fixture(null, 8);
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        let mut host = LineHost { success, points, ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to);
        assert_retired(&runtime, allocations);
        assert_eq!(host.calls, if null { vec![] } else { vec![(-32768, -19, 32767, -1)] });
    }
}

#[test]
fn line_dda_void_real_retf_steps_all_points_ignores_zero_callback_ax_and_cleans_up() {
    let (mut runtime, return_to, callback) = fixture(false, 8);
    let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
    let points = vec![Win16DrawingPoint { x: -32768, y: 32767 }, Win16DrawingPoint { x: -19, y: -1 }];
    let mut host = LineHost { success: true, points: points.clone(), ..Default::default() };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(host.calls, [(-32768, -19, 32767, -1)]);
    for point in points {
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip()), ((callback >> 16) as u16, callback as u16));
        assert!(state.line_dda_code_references().contains(&callback));
        let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
        let mut bytes = [0; 12]; state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
        assert_eq!(&bytes[4..8], &0x89abcdef_u32.to_le_bytes());
        assert_eq!(&bytes[8..10], &(point.y as i16).to_le_bytes());
        assert_eq!(&bytes[10..12], &(point.x as i16).to_le_bytes());
        // A void callback has no zero/false stop convention.
        runtime.cpu.regs.set_ax(0);
        runtime.cpu.regs.set_dx(0xdead);
        retf(&mut runtime).unwrap();
    }
    assert_return(&runtime, return_to);
    assert_retired(&runtime, allocations);
}

#[test]
fn line_dda_void_host_errors_and_malformed_results_do_not_commit_return() {
    for host in [LineHost { fail: true, ..Default::default() },
        LineHost { wrong_result: true, ..Default::default() },
        LineHost { success: true, points: vec![Win16DrawingPoint { x: 32768, y: 0 }], ..Default::default() },
        LineHost { success: true, points: vec![Win16DrawingPoint { x: 0, y: 0 }; 65_537], ..Default::default() }] {
        let (mut runtime, _, _) = fixture(false, 8);
        let before = runtime.cpu.regs.clone();
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        let mut host = host;
        let expected = if host.fail { Kind::HostFailure } else { Kind::InternalInvariant };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), expected);
        assert_eq!(runtime.cpu.regs, before);
        assert_retired(&runtime, allocations);
        assert_eq!(host.calls.len(), 1);
    }
    let (mut runtime, _, _) = fixture(false, 8);
    let before = runtime.cpu.regs.clone();
    assert_eq!(dispatch(&mut runtime, &mut NoHost).unwrap_err().kind(), Kind::CompatibilityGap);
    assert_eq!(runtime.cpu.regs, before);
}

#[test]
fn line_dda_void_bad_retf_or_stopped_callback_teardown_preserves_terminal_registers() {
    for bad_return in [false, true] {
        let (mut runtime, _, _) = fixture(false, if bad_return { 6 } else { 8 });
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        let mut host = LineHost { success: true, points: vec![Win16DrawingPoint { x: 1, y: 2 }; 2], ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        if bad_return { assert!(retf(&mut runtime).is_err()); }
        runtime.cpu.regs.set_ax(0x1234); runtime.cpu.regs.set_dx(0x5678);
        let terminal = runtime.cpu.regs.clone();
        let ended = super::super::execute::Win16TaskExecutionEnded::for_test();
        let state = runtime.win16.as_mut().unwrap();
        state.cancel_line_dda_callback_for_teardown(&ended, &mut runtime.cpu,
            &mut runtime.dos, &mut runtime.memory).unwrap();
        assert_eq!(runtime.cpu.regs, terminal);
        assert_retired(&runtime, allocations);
    }
}

#[test]
fn line_dda_void_invalid_callback_and_short_callback_stack_never_reach_host() {
    for invalid_pointer in [false, true] {
        let (mut runtime, return_to, callback) = fixture(false, 8);
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        let state = runtime.win16.as_mut().unwrap();
        if invalid_pointer {
            let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp() + 8).unwrap();
            state.selectors.write(&mut runtime.memory, pointer, &0xffff0000_u32.to_le_bytes()).unwrap();
        } else {
            // The export frame fits at SP=8, but a 12-byte callback frame does not.
            let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), 8).unwrap();
            let mut bytes = vec![0; 20];
            bytes[..2].copy_from_slice(&return_to.1.to_le_bytes());
            bytes[2..4].copy_from_slice(&return_to.0.to_le_bytes());
            bytes[8..12].copy_from_slice(&callback.to_le_bytes());
            state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
            runtime.cpu.regs.set_sp(8);
        }
        let before = runtime.cpu.regs.clone();
        let mut host = LineHost::default();
        let error = dispatch(&mut runtime, &mut host).unwrap_err();
        if !invalid_pointer { assert!(error.to_string().contains("LineDDA callback stack underflow")); }
        assert_eq!(runtime.cpu.regs, before);
        assert!(host.calls.is_empty());
        assert_retired(&runtime, allocations);
    }
}

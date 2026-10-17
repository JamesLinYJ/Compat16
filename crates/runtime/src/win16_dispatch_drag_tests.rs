//! Dispatch coverage for USER.86, USER.464, and USER.465.
use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16DragSample,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use std::collections::BTreeMap;
use win16_abi::{ExportLookupTarget, Win16ExportStackCleanup, lookup_export};

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;

#[derive(Default)]
struct DragHost {
    samples: Vec<Win16DragSample>,
    waits: Vec<bool>,
    metrics: BTreeMap<i32, i32>,
    metric_order: Vec<i32>,
    fail_metric: bool,
    fail_poll: bool,
}

impl DragHost {
    fn sample(x: i16, y: i16, left_down: bool, escape_down: bool) -> Win16DragSample {
        Win16DragSample { x, y, left_down, escape_down }
    }
}

impl DosHost for DragHost {
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

impl RuntimeHost for DragHost {
    fn win16_get_system_metrics(&mut self, index: i32) -> Result<i32, RuntimeError> {
        self.metric_order.push(index);
        if self.fail_metric {
            return Err(RuntimeError::new(Kind::HostFailure, "metric test failure"));
        }
        self.metrics.get(&index).copied().ok_or_else(|| {
            RuntimeError::new(Kind::HostFailure, "unexpected system metric")
        })
    }
    fn win16_drag_poll(&mut self, wait_for_change: bool) -> Result<Win16DragSample, RuntimeError> {
        self.waits.push(wait_for_change);
        if self.fail_poll {
            return Err(RuntimeError::new(Kind::HostFailure, "drag sample test failure"));
        }
        self.samples.pop().ok_or_else(|| {
            RuntimeError::new(Kind::HostFailure, "drag sample queue is empty")
        })
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for DragHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for DragHost {}
impl crate::RuntimeMidiHost for DragHost {}
impl crate::RuntimeNetbiosHost for DragHost {}

fn prepare(ordinal: u16, args: &[u8]) -> (Runtime, (u16, u16, u16), Vec<u8>) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\DRAG.NE").unwrap();
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("drag exports use a fixed stack");
    };
    let return_to: (u16, u16, u16) = (
        runtime.cpu.regs.cs,
        0x12,
        runtime.cpu.regs.sp() + 4 + cleanup.callee_pop_bytes,
    );
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_to.1.to_le_bytes());
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(args);
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp())
        .unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    (runtime, return_to, bytes)
}

fn stack_bytes(runtime: &Runtime, stack: u16, len: usize) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    let mut bytes = vec![0; len];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn point_args(window: u16, x: i16, y: i16) -> Vec<u8> {
    let mut args = Vec::from(x.to_le_bytes());
    args.extend_from_slice(&y.to_le_bytes());
    args.extend_from_slice(&window.to_le_bytes());
    args
}

#[test]
fn icon_size_packs_width_low_and_height_high() {
    let (mut runtime, return_to, bytes) = prepare(86, &[]);
    let mut host = DragHost::default();
    host.metrics.insert(11, 32);
    host.metrics.insert(12, 16);
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (32, 16));
    assert_eq!(host.metric_order, [11, 12]);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert_eq!(stack_bytes(&runtime, return_to.2 - 4, bytes.len()), bytes);
}

#[test]
fn icon_size_truncates_each_metric_to_sixteen_bits() {
    let (mut runtime, _, _) = prepare(86, &[]);
    let mut host = DragHost::default();
    host.metrics.insert(11, 0x1_0020);
    host.metrics.insert(12, -1);
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0x0020, 0xFFFF));
}

#[test]
fn icon_size_host_failure_leaves_the_guest_return_uncommitted() {
    let (mut runtime, return_to, bytes) = prepare(86, &[]);
    let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
    let mut host = DragHost { fail_metric: true, ..DragHost::default() };
    let error = runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap_err();
    assert_eq!(error.kind(), Kind::HostFailure);
    assert_eq!(host.metric_order, [11]);
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX, DX));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
    assert_eq!(stack_bytes(&runtime, return_to.2 - 4, bytes.len()), bytes);
}

#[test]
fn drag_object_returns_zero_without_calling_the_host() {
    let mut args = Vec::from(0xFFFFu16.to_le_bytes());
    args.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    args.extend_from_slice(&7u16.to_le_bytes());
    args.extend_from_slice(&0x2222u16.to_le_bytes());
    args.extend_from_slice(&0x1111u16.to_le_bytes());
    let (mut runtime, return_to, bytes) = prepare(464, &args);
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0,
    ).unwrap();
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0, 0));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert_eq!(stack_bytes(&runtime, return_to.2 - 16, bytes.len()), bytes);
}

#[test]
fn drag_detect_classifies_the_four_pixel_rectangle() {
    let cases = [
        (vec![DragHost::sample(13, 20, true, false), DragHost::sample(13, 20, true, false)], 0, 2),
        (vec![DragHost::sample(13, 20, true, false), DragHost::sample(14, 20, true, false)], 1, 2),
        (vec![DragHost::sample(10, 23, true, false), DragHost::sample(10, 24, true, false)], 1, 2),
        (vec![DragHost::sample(6, 20, true, false), DragHost::sample(6, 20, true, false)], 0, 2),
        (vec![DragHost::sample(5, 20, true, false)], 1, 1),
        (vec![DragHost::sample(10, 20, false, false)], 0, 1),
        (vec![DragHost::sample(10, 20, true, false), DragHost::sample(14, 24, true, true)], 0, 2),
        (vec![DragHost::sample(-12, -8, true, false), DragHost::sample(-12, -8, true, false)], 0, 2),
        (vec![DragHost::sample(-13, -8, true, false)], 1, 1),
    ];
    for (mut queued, ax, polls) in cases {
        queued.reverse();
        let args = if queued.iter().any(|sample| sample.x < 0) {
            point_args(0x99, -8, -8)
        } else {
            point_args(0x99, 10, 20)
        };
        let (mut runtime, return_to, bytes) = prepare(465, &args);
        let mut host = DragHost { samples: queued, ..DragHost::default() };
        runtime.win16.as_mut().unwrap().dispatch(
            &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
        ).unwrap();
        assert_eq!(runtime.cpu.regs.ax(), ax);
        assert_eq!(runtime.cpu.regs.dx(), DX);
        assert_eq!(host.waits.len(), polls);
        assert!(!host.waits[0]);
        assert!(host.waits.iter().skip(1).all(|wait| *wait));
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
        assert_eq!(stack_bytes(&runtime, return_to.2 - 10, bytes.len()), bytes);
    }
}

#[test]
fn drag_detect_stops_after_the_sample_cap_while_still_inside() {
    let mut samples = Vec::new();
    for index in 0..256 {
        let x = if index % 2 == 0 { 0 } else { 1 };
        samples.push(DragHost::sample(x, 0, true, false));
    }
    samples.reverse();
    let host_samples = samples;
    let mut host = DragHost { samples: host_samples, ..DragHost::default() };
    let result = super::drag_detect(&mut host, 0x99, 0, 0).unwrap();
    assert_eq!(result, 0);
    assert_eq!(host.waits.len(), 256);
    assert!(host.samples.is_empty());
}

#[test]
fn drag_detect_host_failure_leaves_the_guest_return_uncommitted() {
    let args = point_args(1, 0, 0);
    let (mut runtime, return_to, bytes) = prepare(465, &args);
    let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
    let mut host = DragHost { fail_poll: true, ..DragHost::default() };
    let error = runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap_err();
    assert_eq!(error.kind(), Kind::HostFailure);
    assert_eq!(host.waits, [false]);
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX, DX));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
    assert_eq!(stack_bytes(&runtime, return_to.2 - 10, bytes.len()), bytes);
}

#[test]
fn drag_detect_without_a_host_sample_is_a_compatibility_gap() {
    let args = point_args(1, 4, 5);
    let (mut runtime, return_to, bytes) = prepare(465, &args);
    let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
    let error = runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0,
    ).unwrap_err();
    assert_eq!(error.kind(), Kind::CompatibilityGap);
    assert!(error.to_string().contains("host Win16 drag sample is unavailable"));
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX, DX));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
    assert_eq!(stack_bytes(&runtime, return_to.2 - 10, bytes.len()), bytes);
}

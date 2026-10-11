//! Service-gate coverage for GDI.172 SetRectRgn's semantic void ABI.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16DrawingOperation as Operation,
    Win16DrawingRect, Win16DrawingResult as HostResult, Win16HostDc, Win16HostGdiObject,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::{
    ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup, Win16ReturnKind, lookup_export,
};

const NATIVE_REGION: Win16HostGdiObject = Win16HostGdiObject(0xfedc_ba98_7654);
const EAX_SENTINEL: u32 = 0xa1b2_a55a;
const EDX_SENTINEL: u32 = 0xc3d4_5aa5;
const INITIAL_RECT: Win16DrawingRect = Win16DrawingRect {
    left: 10, top: 20, right: 30, bottom: 40,
};

struct RegionHost {
    calls: Vec<Operation>,
    rect: Win16DrawingRect,
    success: bool,
    fail: bool,
    wrong_result: bool,
}

impl RegionHost {
    fn new(success: bool) -> Self {
        Self { calls: Vec::new(), rect: INITIAL_RECT, success, fail: false, wrong_result: false }
    }
}

impl DosHost for RegionHost {
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

impl RuntimeHost for RegionHost {
    fn win16_gdi(&mut self, operation: Operation) -> Result<HostResult, RuntimeError> {
        let Operation::SetRectRgn { region, rect } = operation else {
            panic!("unexpected host operation");
        };
        assert_eq!(region, NATIVE_REGION);
        self.calls.push(Operation::SetRectRgn { region, rect });
        if self.success {
            self.rect = rect;
        }
        if self.fail {
            return Err(RuntimeError::new(Kind::HostFailure, "test native failure"));
        }
        if self.wrong_result {
            return Ok(HostResult::Mode(1));
        }
        Ok(HostResult::Bool(self.success))
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for RegionHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for RegionHost {}
impl crate::RuntimeMidiHost for RegionHost {}
impl crate::RuntimeNetbiosHost for RegionHost {}

fn fixture() -> (Runtime, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\REGION.NE").unwrap();
    let region = runtime.win16.as_mut().unwrap().guest_gdi.allocate_object(NATIVE_REGION).unwrap();
    (runtime, region)
}

fn drawing_rect(edges: [i16; 4]) -> Win16DrawingRect {
    Win16DrawingRect {
        left: i32::from(edges[0]), top: i32::from(edges[1]),
        right: i32::from(edges[2]), bottom: i32::from(edges[3]),
    }
}

struct PreparedCall {
    return_to: (u16, u16, u16),
    frame: SegmentedPointer,
    guarded_bytes: Vec<u8>,
}

fn prepare(runtime: &mut Runtime, region: u16, edges: [i16; 4]) -> PreparedCall {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(172)).unwrap();
    assert_eq!(descriptor.id,
        lookup_export(b"GDI", ExportLookupTarget::Name(b"SetRectRgn")).unwrap().id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("SetRectRgn requires a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, 10);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    // Physical FAR Pascal frame: return IP:CS, bottom, right, top, left, HRGN.
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    for edge in edges.into_iter().rev() {
        bytes.extend_from_slice(&edge.to_le_bytes());
    }
    bytes.extend_from_slice(&region.to_le_bytes());
    assert_eq!(bytes.len(), 14);
    let frame = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack - 2).unwrap();
    let mut guarded_bytes = vec![0xa7, 0x3c];
    guarded_bytes.extend_from_slice(&bytes);
    guarded_bytes.extend_from_slice(&[0x5d, 0xe9]);
    state.selectors.write(&mut runtime.memory, frame, &guarded_bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = EAX_SENTINEL;
    runtime.cpu.regs.edx = EDX_SENTINEL;
    PreparedCall { return_to: (return_cs, return_ip, stack + 4 + 10), frame, guarded_bytes }
}

fn dispatch(runtime: &mut Runtime, host: &mut RegionHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn assert_frame_unchanged(runtime: &Runtime, call: &PreparedCall) {
    let mut bytes = vec![0; call.guarded_bytes.len()];
    runtime.win16.as_ref().unwrap().selectors.read(&runtime.memory, call.frame, &mut bytes).unwrap();
    assert_eq!(bytes, call.guarded_bytes);
}

fn assert_return(runtime: &Runtime, call: &PreparedCall) {
    // Register preservation is this project's deterministic Void policy;
    // it does not assert incidental register values from historical binaries.
    assert_eq!(runtime.cpu.regs.eax, EAX_SENTINEL);
    assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), call.return_to);
    assert_frame_unchanged(runtime, call);
}

#[test]
fn set_rect_rgn_mutates_a_mapped_region_and_ignores_native_bool_in_void_return() {
    let edges = [-123, -45, 678, 901];
    for success in [false, true] {
        let (mut runtime, region) = fixture();
        let return_to = prepare(&mut runtime, region, edges);
        let mut host = RegionHost::new(success);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
        assert_eq!(host.calls, [Operation::SetRectRgn {
            region: NATIVE_REGION, rect: drawing_rect(edges),
        }]);
        assert_eq!(host.rect, if success { drawing_rect(edges) } else { INITIAL_RECT });
        assert_eq!(runtime.win16.as_ref().unwrap().guest_gdi.object(region), Some(NATIVE_REGION));
        assert_return(&runtime, &return_to);
    }
}

#[test]
fn set_rect_rgn_sign_extends_extrema_and_preserves_empty_or_inverted_edge_order() {
    for edges in [
        [i16::MIN, -123, 456, i16::MAX],
        [i16::MAX, 456, -123, i16::MIN],
        [-8, i16::MIN, i16::MAX, 12],
        [123, i16::MAX, i16::MIN, -456],
        [5, -7, 5, 9],
        [-8, 4, 12, 4],
    ] {
        let (mut runtime, region) = fixture();
        let return_to = prepare(&mut runtime, region, edges);
        let mut host = RegionHost::new(true);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
        assert_eq!(host.calls, [Operation::SetRectRgn {
            region: NATIVE_REGION, rect: drawing_rect(edges),
        }]);
        assert_eq!(host.rect, drawing_rect(edges));
        assert_return(&runtime, &return_to);
    }
}

#[test]
fn set_rect_rgn_invalid_handles_skip_host_and_preserve_void_return() {
    let (mut runtime, region) = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(Win16HostDc(0x1234_5678_9abc)).unwrap();
    let reserved = state.guest_gdi.reserve_object().unwrap();
    assert!(state.guest_gdi.forget_object(region, NATIVE_REGION));
    for invalid in [0, u16::MAX, dc, reserved, region] {
        let return_to = prepare(&mut runtime, invalid, [i16::MIN, -123, 456, i16::MAX]);
        let mut host = RegionHost::new(true);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
        assert!(host.calls.is_empty());
        assert_eq!(host.rect, INITIAL_RECT);
        assert_return(&runtime, &return_to);
    }
}

#[test]
fn set_rect_rgn_host_errors_do_not_publish_a_return_or_queue_repeated_mutation() {
    let edges = [-123, -45, 678, 901];
    for (fail, wrong_result, expected_kind) in [
        (true, false, Kind::HostFailure),
        (false, true, Kind::InternalInvariant),
    ] {
        let (mut runtime, region) = fixture();
        let call = prepare(&mut runtime, region, edges);
        let gate = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
        // Model a native effect followed by an unavailable or malformed result.
        let mut host = RegionHost { fail, wrong_result, ..RegionHost::new(true) };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), expected_kind);
        assert_eq!(host.rect, drawing_rect(edges));
        // Synchronous GDI does not retain a completion or a retry obligation.
        // Draining the shared completion path must not resubmit the operation.
        assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
        runtime.win16.as_mut().unwrap().drive_pending_window_completion(
            &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
        ).unwrap();
        assert_eq!(host.calls, [Operation::SetRectRgn {
            region: NATIVE_REGION, rect: drawing_rect(edges),
        }]);
        assert_eq!(runtime.cpu.regs.eax, EAX_SENTINEL);
        assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), gate);
        assert_frame_unchanged(&runtime, &call);
    }
}

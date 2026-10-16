//! Service-gate and retained RECT16 output coverage for USER.221 ScrollDC.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostDc,
    Win16HostGdiObject, Win16HostRect, Win16HostUpdateOperation, Win16HostUpdateResult,
    Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState,
    Win16WindowOperation, Win16WindowResult, Win16WindowSourceRetiredProof, Win16WindowStep,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use std::sync::Arc;
use win16_abi::{
    Access, AccessRights, ExportLookupTarget, Rect16, SegmentedPointer,
    Win16ExportStackCleanup, Win16ReturnKind, lookup_export,
};

const OFFSET: u16 = 0x10;
const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);
const NATIVE_REGION: Win16HostGdiObject = Win16HostGdiObject(0xabcd_1234_5678);
const ORIGINAL: Rect16 = Rect16 { left: -123, top: 456, right: -789, bottom: 321 };
const OUTPUT: Win16HostRect = Win16HostRect { left: -22, top: 33, right: 44, bottom: -55 };

#[derive(Default)]
struct ScrollDcHost {
    calls: Vec<Win16HostUpdateOperation>,
    result: Option<Win16HostUpdateResult>,
    consumed: usize,
    fail_readback_once: bool,
    fail_consumed_once: bool,
}

fn proof() -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(41),
            kind: Win16NativeWindowOperationKind::UpdateRegion,
        },
        worker_generation: 7,
        state: Win16NativeWindowOperationState::Returned,
    })
}

impl DosHost for ScrollDcHost {
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

impl RuntimeHost for ScrollDcHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::UpdateRegion(operation) = operation else {
            panic!("unexpected host operation");
        };
        assert!(matches!(&operation, Win16HostUpdateOperation::ScrollDC { .. }));
        self.calls.push(operation);
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::UpdateRegion(
                    self.result.take().unwrap_or(Win16HostUpdateResult::Rect { value: 0, rect: None }),
                ))),
            }),
        })
    }
    fn win16_window_source_retirement(
        &mut self, operation: Win16NativeWindowOperationProof, worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = proof();
        assert_eq!(operation, proof.operation);
        assert_eq!(worker_generation, proof.worker_generation);
        if std::mem::take(&mut self.fail_readback_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers the retained result"));
        }
        Ok(Some(proof))
    }
    fn win16_window_source_retirement_consumed(&mut self, actual: &Win16WindowSourceRetiredProof) -> Result<(), RuntimeError> {
        assert_eq!(actual, proof().as_ref());
        if std::mem::take(&mut self.fail_consumed_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers source consumption"));
        }
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for ScrollDcHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for ScrollDcHost {}
impl crate::RuntimeMidiHost for ScrollDcHost {}
impl crate::RuntimeNetbiosHost for ScrollDcHost {}

fn fixture() -> (Runtime, u16, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\SCROLL.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(NATIVE_DC).unwrap();
    let region = state.guest_gdi.allocate_object(NATIVE_REGION).unwrap();
    write_rect(&mut runtime, ORIGINAL);
    (runtime, dc, region)
}

fn far(runtime: &Runtime) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(OFFSET)
}

fn write_rect(runtime: &mut Runtime, rect: Rect16) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far(runtime)).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &rect.encode()).unwrap();
}

fn read_rect(runtime: &Runtime) -> Rect16 {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far(runtime)).unwrap();
    let mut bytes = [0; Rect16::SIZE];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    Rect16::decode(&bytes)
}

fn host_rect(rect: Rect16) -> Win16HostRect {
    Win16HostRect { left: i32::from(rect.left), top: i32::from(rect.top),
        right: i32::from(rect.right), bottom: i32::from(rect.bottom) }
}

fn output_rect() -> Rect16 {
    Rect16 { left: -22, top: 33, right: 44, bottom: -55 }
}

fn success() -> ScrollDcHost {
    ScrollDcHost { result: Some(Win16HostUpdateResult::Rect { value: 1, rect: Some(OUTPUT) }),
        ..Default::default() }
}

fn prepare(runtime: &mut Runtime, dc: u16, region: u16, scroll_rect: u32,
    clip_rect: u32, update_rect: u32) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(221)).unwrap();
    assert_eq!(descriptor.id, lookup_export(b"USER", ExportLookupTarget::Name(b"ScrollDC")).unwrap().id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("ScrollDC requires a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, 20);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    // Physical Pascal order is the reverse of the declared arguments.
    bytes.extend_from_slice(&update_rect.to_le_bytes());
    bytes.extend_from_slice(&region.to_le_bytes());
    bytes.extend_from_slice(&clip_rect.to_le_bytes());
    bytes.extend_from_slice(&scroll_rect.to_le_bytes());
    bytes.extend_from_slice(&i16::MAX.to_le_bytes()); // dy
    bytes.extend_from_slice(&i16::MIN.to_le_bytes()); // dx
    bytes.extend_from_slice(&dc.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(runtime: &mut Runtime, host: &mut ScrollDcHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn retry(runtime: &mut Runtime, host: &mut ScrollDcHost) -> Result<(), RuntimeError> {
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host,
    ).map(|_| ())
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), value: u16) {
    assert_eq!(runtime.cpu.regs.ax(), value);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

#[test]
fn scroll_dc_snapshots_aliased_inputs_and_returns_bool_with_pascal_cleanup() {
    let (mut runtime, dc, region) = fixture();
    let pointer = far(&runtime);
    let return_to = prepare(&mut runtime, dc, region, pointer, pointer, pointer);
    let mut host = success();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(host.calls, vec![Win16HostUpdateOperation::ScrollDC {
        dc: NATIVE_DC, dx: i16::MIN, dy: i16::MAX,
        scroll_rect: Some(host_rect(ORIGINAL)), clip_rect: Some(host_rect(ORIGINAL)),
        update_region: Some(NATIVE_REGION), update_rect_is_null: false,
    }]);
    assert_eq!(read_rect(&runtime), output_rect());
    assert_eq!(host.consumed, 1);
    assert_return(&runtime, return_to, 1);
}

#[test]
fn scroll_dc_preserves_each_nullable_rect_and_region_argument() {
    for mask in 0..16 {
        let (mut runtime, dc, region) = fixture();
        let pointer = far(&runtime);
        let scroll = if mask & 1 != 0 { pointer } else { 0 };
        let clip = if mask & 2 != 0 { pointer } else { 0 };
        let output = if mask & 4 != 0 { pointer } else { 0 };
        let region = if mask & 8 != 0 { region } else { 0 };
        let return_to = prepare(&mut runtime, dc, region, scroll, clip, output);
        let mut host = success();
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls, vec![Win16HostUpdateOperation::ScrollDC {
            dc: NATIVE_DC, dx: i16::MIN, dy: i16::MAX,
            scroll_rect: (scroll != 0).then_some(host_rect(ORIGINAL)),
            clip_rect: (clip != 0).then_some(host_rect(ORIGINAL)),
            update_region: (region != 0).then_some(NATIVE_REGION),
            update_rect_is_null: output == 0,
        }]);
        assert_eq!(read_rect(&runtime), if output == 0 { ORIGINAL } else { output_rect() });
        assert_eq!(host.consumed, 1);
        assert_return(&runtime, return_to, 1);
    }
}

#[test]
fn scroll_dc_rejects_null_unknown_and_wrong_kind_handles_without_host_work() {
    for case in 0..5 {
        let (mut runtime, dc, region) = fixture();
        let (dc, region) = match case {
            0 => (0, region),
            1 => (0xffff, region),
            2 => (region, 0),
            3 => (dc, 0xffff),
            _ => (dc, dc),
        };
        let pointer = far(&runtime);
        let return_to = prepare(&mut runtime, dc, region, 0, 0, pointer);
        let mut host = success();
        dispatch(&mut runtime, &mut host).unwrap();
        assert!(host.calls.is_empty());
        assert_eq!(host.consumed, 0);
        assert_eq!(read_rect(&runtime), ORIGINAL);
        assert_return(&runtime, return_to, 0);
    }
}

#[test]
fn scroll_dc_preflights_the_complete_writable_output_before_host_work() {
    for (size, rights) in [(7, AccessRights::read_write()), (8, AccessRights::read_only())] {
        let (mut runtime, dc, region) = fixture();
        let original_far = far(&runtime);
        let state = runtime.win16.as_mut().unwrap();
        let pointer = state.selectors.pointer_from_far(original_far).unwrap();
        let base = state.selectors.translate(pointer, Access::Read, 8, &runtime.memory).unwrap();
        let alias = state.selectors.alloc_block(base, size, rights, &runtime.memory).unwrap();
        let output = SegmentedPointer::new(alias, 0).far_value();
        prepare(&mut runtime, dc, region, original_far, original_far, output);
        let mut host = success();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert!(host.calls.is_empty());
        assert_eq!(read_rect(&runtime), ORIGINAL);
    }
}

#[test]
fn scroll_dc_rejects_invalid_nonnull_input_and_output_far_pointers() {
    for case in 0..3 {
        let (mut runtime, dc, region) = fixture();
        let mut pointers = [0; 3];
        pointers[case] = u32::MAX;
        prepare(&mut runtime, dc, region, pointers[0], pointers[1], pointers[2]);
        let mut host = success();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert!(host.calls.is_empty());
        assert_eq!(read_rect(&runtime), ORIGINAL);
    }
}

#[test]
fn scroll_dc_native_failure_leaves_guest_output_untouched() {
    let (mut runtime, dc, region) = fixture();
    let pointer = far(&runtime);
    let return_to = prepare(&mut runtime, dc, region, pointer, pointer, pointer);
    let mut host = ScrollDcHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(read_rect(&runtime), ORIGINAL);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 1);
    assert_return(&runtime, return_to, 0);
}

#[test]
fn scroll_dc_retained_result_rejects_reused_output_selector() {
    let (mut runtime, dc, region) = fixture();
    let original_far = far(&runtime);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(original_far).unwrap();
    let base = state.selectors.translate(pointer, Access::Read, 8, &runtime.memory).unwrap();
    let alias = state.selectors.alloc_block(base, 8, AccessRights::read_write(), &runtime.memory).unwrap();
    prepare(&mut runtime, dc, region, 0, 0, SegmentedPointer::new(alias, 0).far_value());
    let mut host = ScrollDcHost { fail_readback_once: true, ..success() };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(read_rect(&runtime), ORIGINAL);
    let state = runtime.win16.as_mut().unwrap();
    state.selectors.free_block(alias).unwrap();
    let replacement = state.selectors.alloc_block(base, 8, AccessRights::read_write(), &runtime.memory).unwrap();
    assert_eq!(alias.raw(), replacement.raw());
    assert_ne!(alias.generation(), replacement.generation());
    assert_eq!(retry(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
    assert_eq!(read_rect(&runtime), ORIGINAL);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 0);
}

#[test]
fn scroll_dc_retries_retained_completion_without_repeating_native_call() {
    let (mut runtime, dc, region) = fixture();
    let pointer = far(&runtime);
    let return_to = prepare(&mut runtime, dc, region, pointer, pointer, pointer);
    let mut host = ScrollDcHost { fail_readback_once: true, ..success() };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(read_rect(&runtime), ORIGINAL);
    retry(&mut runtime, &mut host).unwrap();
    assert_eq!(read_rect(&runtime), output_rect());
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 1);
    assert_return(&runtime, return_to, 1);
}

#[test]
fn scroll_dc_source_consumption_retry_never_replays_committed_output() {
    let (mut runtime, dc, region) = fixture();
    let pointer = far(&runtime);
    let return_to = prepare(&mut runtime, dc, region, 0, 0, pointer);
    let mut host = ScrollDcHost { fail_consumed_once: true, ..success() };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(read_rect(&runtime), output_rect());
    write_rect(&mut runtime, ORIGINAL);
    retry(&mut runtime, &mut host).unwrap();
    assert_eq!(read_rect(&runtime), ORIGINAL);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 1);
    assert_return(&runtime, return_to, 1);
}

#[test]
fn scroll_dc_output_uses_existing_coordinate_clamping_policy() {
    let (mut runtime, dc, region) = fixture();
    let pointer = far(&runtime);
    let return_to = prepare(&mut runtime, dc, region, 0, 0, pointer);
    let mut host = ScrollDcHost {
        result: Some(Win16HostUpdateResult::Rect { value: 1, rect: Some(Win16HostRect {
            left: i32::MIN, top: i32::MAX, right: -32769, bottom: 32768,
        }) }),
        ..Default::default()
    };
    dispatch(&mut runtime, &mut host).unwrap();
    // This protects the runtime's established policy, not a historical Win16
    // overflow assertion. The native integration test uses in-range coordinates.
    assert_eq!(read_rect(&runtime), Rect16 {
        left: i16::MIN, top: i16::MAX, right: i16::MIN, bottom: i16::MAX,
    });
    assert_return(&runtime, return_to, 1);
}

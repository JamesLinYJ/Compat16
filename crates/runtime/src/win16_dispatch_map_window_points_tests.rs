//! Service-gate and retained-output coverage for USER.258 MapWindowPoints.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostPoint,
    Win16HostWindow, Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState, Win16WindowCall,
    Win16WindowCallResult, Win16WindowOperation, Win16WindowResult,
    Win16WindowSourceRetiredProof, Win16WindowStep, Win16WindowTarget,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use std::sync::Arc;
use win16_abi::{
    Access, AccessRights, ExportLookupTarget, Point16, SegmentedPointer,
    Win16ExportStackCleanup, Win16ReturnKind, lookup_export,
};

const OFFSET: u16 = 0x10;
const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;

#[derive(Default)]
struct MapPointsHost {
    calls: Vec<(Win16WindowTarget, Win16WindowTarget, Vec<Win16HostPoint>)>,
    result: Option<Vec<Win16HostPoint>>,
    consumed: usize,
    fail_readback_once: bool,
}

fn proof() -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(41),
            kind: Win16NativeWindowOperationKind::WindowCall,
        },
        worker_generation: 7,
        state: Win16NativeWindowOperationState::Returned,
    })
}

impl DosHost for MapPointsHost {
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

impl RuntimeHost for MapPointsHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::WindowCall(Win16WindowCall::MapWindowPoints { from, to, points }) = operation else {
            panic!("unexpected host operation");
        };
        self.calls.push((from, to, points));
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(
                    Win16WindowCallResult::Points(self.result.take()),
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
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for MapPointsHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for MapPointsHost {}
impl crate::RuntimeMidiHost for MapPointsHost {}
impl crate::RuntimeNetbiosHost for MapPointsHost {}

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\POINTS.NE").unwrap()
}

fn far(runtime: &Runtime) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(OFFSET)
}

fn write_points(runtime: &mut Runtime, points: &[Point16]) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far(runtime)).unwrap();
    let bytes: Vec<u8> = points.iter().flat_map(|point| point.encode()).collect();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
}

fn read_points(runtime: &Runtime, count: usize) -> Vec<Point16> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far(runtime)).unwrap();
    let mut bytes = vec![0; count * Point16::SIZE];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes.chunks_exact(Point16::SIZE).map(|bytes| Point16::decode(bytes.try_into().unwrap())).collect()
}

fn prepare(runtime: &mut Runtime, from: u16, to: u16, points: u32, count: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(258)).unwrap();
    assert_eq!(descriptor.id, lookup_export(b"USER", ExportLookupTarget::Name(b"MapWindowPoints")).unwrap().id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("MapWindowPoints requires a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, 10);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&points.to_le_bytes());
    bytes.extend_from_slice(&to.to_le_bytes());
    bytes.extend_from_slice(&from.to_le_bytes());
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

fn dispatch(runtime: &mut Runtime, host: &mut MapPointsHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16)) {
    assert_eq!(runtime.cpu.regs.ax(), AX);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

#[test]
fn map_window_points_maps_signed_arrays_and_preserves_void_abi() {
    let input = [Point16 { x: -32768, y: 32767 }, Point16 { x: 123, y: -456 }, Point16 { x: 32767, y: -32768 }];
    let output = [Win16HostPoint { x: -32769, y: 32768 }, Win16HostPoint { x: 3, y: -4 }, Win16HostPoint { x: 65537, y: -65538 }];
    let expected = [Point16 { x: 32767, y: -32768 }, Point16 { x: 3, y: -4 }, Point16 { x: 1, y: -2 }];
    // The count-two case is also a RECT16 whose first x remains greater than
    // its second x. Neither marshalling nor completion may sort its edges.
    for count in 1..=3 {
        let mut runtime = fixture();
        write_points(&mut runtime, &input);
        let native_from = Win16HostWindow(0x1234_5678_9abc);
        let native_to = Win16HostWindow(0xabcd_1234_5678);
        runtime.win16.as_mut().unwrap().window_handles.insert(0x1234, native_from);
        runtime.win16.as_mut().unwrap().window_handles.insert(0x2345, native_to);
        let pointer = far(&runtime);
        let return_to = prepare(&mut runtime, 0x1234, 0x2345, pointer, count as u16);
        let mut host = MapPointsHost { result: Some(output[..count].to_vec()), ..Default::default() };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
        assert_eq!(host.calls, vec![(Win16WindowTarget::Mapped(native_from), Win16WindowTarget::Mapped(native_to),
            input[..count].iter().map(|point| Win16HostPoint { x: i32::from(point.x), y: i32::from(point.y) }).collect())]);
        let mut expected_all = input;
        expected_all[..count].copy_from_slice(&expected[..count]);
        assert_eq!(read_points(&runtime, 3), expected_all);
        assert_eq!(host.consumed, 1);
        assert_return(&runtime, return_to);
    }
}

#[test]
fn map_window_points_distinguishes_screen_and_invalid_window_tokens() {
    let point = Point16 { x: -19, y: 23 };
    let native = Win16HostWindow(0x9876_5432_1000);
    for (from, to, expected_from, expected_to) in [
        (0, 2, Win16WindowTarget::Null, Win16WindowTarget::Mapped(native)),
        (2, 0, Win16WindowTarget::Mapped(native), Win16WindowTarget::Null),
        (0, 0, Win16WindowTarget::Null, Win16WindowTarget::Null),
        (3, 2, Win16WindowTarget::Invalid, Win16WindowTarget::Mapped(native)),
        (2, 3, Win16WindowTarget::Mapped(native), Win16WindowTarget::Invalid),
    ] {
        let mut runtime = fixture();
        runtime.win16.as_mut().unwrap().window_handles.insert(2, native);
        write_points(&mut runtime, &[point]);
        let pointer = far(&runtime);
        let return_to = prepare(&mut runtime, from, to, pointer, 1);
        // Native failure must leave the original guest coordinates intact.
        let mut host = MapPointsHost::default();
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls[0].0, expected_from);
        assert_eq!(host.calls[0].1, expected_to);
        assert_eq!(read_points(&runtime, 1), [point]);
        assert_eq!(host.consumed, 1);
        assert_return(&runtime, return_to);
    }
}

#[test]
fn map_window_points_zero_count_never_dereferences_points() {
    for pointer in [0, u32::MAX] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, 0xffff, 0xffff, pointer, 0);
        let mut host = MapPointsHost::default();
        dispatch(&mut runtime, &mut host).unwrap();
        assert!(host.calls.is_empty());
        assert_return(&runtime, return_to);
    }
}

#[test]
fn map_window_points_preflights_the_entire_read_write_array() {
    for (size, rights, count) in [
        (7, AccessRights::read_write(), 2),
        (8, AccessRights::read_only(), 2),
        (8, AccessRights::read_write(), u16::MAX),
    ] {
        let mut runtime = fixture();
        let original = [Point16 { x: 1, y: 2 }, Point16 { x: 3, y: 4 }];
        write_points(&mut runtime, &original);
        let original_far = far(&runtime);
        let state = runtime.win16.as_mut().unwrap();
        let pointer = state.selectors.pointer_from_far(original_far).unwrap();
        let base = state.selectors.translate(pointer, Access::Read, 8, &runtime.memory).unwrap();
        let alias = state.selectors.alloc_block(base, size, rights, &runtime.memory).unwrap();
        let pointer = SegmentedPointer::new(alias, 0).far_value();
        prepare(&mut runtime, 0, 0, pointer, count);
        let mut host = MapPointsHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert!(host.calls.is_empty());
        assert_eq!(read_points(&runtime, 2), original);
    }
    let mut runtime = fixture();
    prepare(&mut runtime, 0, 0, 0, 1);
    assert_eq!(dispatch(&mut runtime, &mut MapPointsHost::default()).unwrap_err().kind(), Kind::GuestFault);
}

#[test]
fn map_window_points_rejects_wrong_host_array_lengths_before_writeback() {
    for count in [0, 1, 3] {
        let mut runtime = fixture();
        let original = [Point16 { x: 1, y: 2 }, Point16 { x: 3, y: 4 }];
        write_points(&mut runtime, &original);
        let pointer = far(&runtime);
        prepare(&mut runtime, 0, 0, pointer, 2);
        let mut host = MapPointsHost { result: Some(vec![Win16HostPoint { x: 99, y: 98 }; count]), ..Default::default() };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::InternalInvariant);
        assert_eq!(read_points(&runtime, 2), original);
        assert_eq!(host.calls.len(), 1);
        assert_eq!(host.consumed, 0);
    }
}

#[test]
fn map_window_points_retained_result_rejects_reused_output_selector() {
    let mut runtime = fixture();
    let original = [Point16 { x: 1, y: 2 }, Point16 { x: 3, y: 4 }];
    write_points(&mut runtime, &original);
    let original_far = far(&runtime);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(original_far).unwrap();
    let base = state.selectors.translate(pointer, Access::Read, 8, &runtime.memory).unwrap();
    let alias = state.selectors.alloc_block(base, 8, AccessRights::read_write(), &runtime.memory).unwrap();
    prepare(&mut runtime, 0, 0, SegmentedPointer::new(alias, 0).far_value(), 2);
    let mut host = MapPointsHost {
        result: Some(vec![Win16HostPoint { x: 99, y: 98 }; 2]),
        fail_readback_once: true,
        ..Default::default()
    };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(read_points(&runtime, 2), original);
    let state = runtime.win16.as_mut().unwrap();
    state.selectors.free_block(alias).unwrap();
    let replacement = state.selectors.alloc_block(base, 8, AccessRights::read_write(), &runtime.memory).unwrap();
    assert_eq!(alias.raw(), replacement.raw());
    assert_ne!(alias.generation(), replacement.generation());
    let error = state.drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
    ).unwrap_err();
    assert_eq!(error.kind(), Kind::GuestFault);
    assert_eq!(read_points(&runtime, 2), original);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 0);
}

#[test]
fn map_window_points_retries_retained_completion_without_repeating_host_call() {
    let mut runtime = fixture();
    let original = [Point16 { x: -12, y: 34 }];
    write_points(&mut runtime, &original);
    let pointer = far(&runtime);
    let return_to = prepare(&mut runtime, 0, 0, pointer, 1);
    let mut host = MapPointsHost {
        result: Some(vec![Win16HostPoint { x: 56, y: -78 }]),
        fail_readback_once: true,
        ..Default::default()
    };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(read_points(&runtime, 1), original);
    let state = runtime.win16.as_mut().unwrap();
    state.drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
    ).unwrap();
    assert_eq!(read_points(&runtime, 1), [Point16 { x: 56, y: -78 }]);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 1);
    assert_return(&runtime, return_to);
}

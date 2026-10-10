//! Service-gate coverage for the six void Win16 caret APIs.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16CaretShape,
    Win16HostPoint, Win16HostWindow, Win16HostWindowOperationId,
    Win16NativeWindowOperationKind, Win16NativeWindowOperationProof,
    Win16NativeWindowOperationState, Win16WindowCall, Win16WindowCallResult,
    Win16WindowOperation, Win16WindowResult, Win16WindowSourceRetiredProof,
    Win16WindowStep, Win16WindowTarget,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use std::sync::Arc;
use win16_abi::{
    Access, AccessRights, ExportLookupTarget, Point16, SegmentedPointer, Win16Argument,
    Win16ExportStackCleanup, Win16ReturnKind, lookup_export,
};
use Win16Argument::{Dword, Word};

const OFFSET: u16 = 0x10;
const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;

#[derive(Clone, Debug, Eq, PartialEq)]
enum CaretCall {
    Create { window: Win16WindowTarget, shape: Win16CaretShape, width: i16, height: i16 },
    Destroy,
    SetPos { x: i16, y: i16 },
    Hide(Win16WindowTarget),
    Show(Win16WindowTarget),
    GetPos,
}

#[derive(Default)]
struct CaretHost {
    calls: Vec<CaretCall>,
    result: Option<Win16WindowCallResult>,
    consumed: usize,
    fail_readback_once: bool,
}

impl CaretHost {
    fn proof(&self) -> Arc<Win16WindowSourceRetiredProof> {
        Arc::new(Win16WindowSourceRetiredProof {
            operation: Win16NativeWindowOperationProof {
                operation_id: Win16HostWindowOperationId(41 + self.calls.len() as u64),
                kind: Win16NativeWindowOperationKind::WindowCall,
            },
            worker_generation: 7,
            state: Win16NativeWindowOperationState::Returned,
        })
    }
}

impl DosHost for CaretHost {
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

impl RuntimeHost for CaretHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::WindowCall(call) = operation else {
            panic!("unexpected host operation");
        };
        let call = match call {
            Win16WindowCall::CreateCaret { window, shape, width, height } =>
                CaretCall::Create { window, shape, width, height },
            Win16WindowCall::DestroyCaret => CaretCall::Destroy,
            Win16WindowCall::SetCaretPos { x, y } => CaretCall::SetPos { x, y },
            Win16WindowCall::HideCaret { window } => CaretCall::Hide(window),
            Win16WindowCall::ShowCaret { window } => CaretCall::Show(window),
            Win16WindowCall::GetCaretPos => CaretCall::GetPos,
            _ => panic!("unexpected window call"),
        };
        let result = self.result.take().unwrap_or_else(|| match &call {
            CaretCall::GetPos => Win16WindowCallResult::Point(None),
            _ => Win16WindowCallResult::Boolean(false),
        });
        self.calls.push(call);
        let proof = self.proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(result))),
            }),
        })
    }
    fn win16_window_source_retirement(
        &mut self, operation: Win16NativeWindowOperationProof, worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = self.proof();
        assert_eq!(operation, proof.operation);
        assert_eq!(worker_generation, proof.worker_generation);
        if std::mem::take(&mut self.fail_readback_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers the retained caret result"));
        }
        Ok(Some(proof))
    }
    fn win16_window_source_retirement_consumed(&mut self, actual: &Win16WindowSourceRetiredProof) -> Result<(), RuntimeError> {
        assert_eq!(actual, self.proof().as_ref());
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for CaretHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for CaretHost {}
impl crate::RuntimeMidiHost for CaretHost {}
impl crate::RuntimeNetbiosHost for CaretHost {}

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\CARET.NE").unwrap()
}

fn far(runtime: &Runtime) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(OFFSET)
}

fn write_output(runtime: &mut Runtime, bytes: [u8; 8]) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far(runtime)).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
}

fn read_output(runtime: &Runtime) -> [u8; 8] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far(runtime)).unwrap();
    let mut bytes = [0; 8];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn prepare(runtime: &mut Runtime, ordinal: u16, arguments: &[Win16Argument]) -> (u16, u16, u16) {
    let (name, stack_bytes): (&[u8], u16) = match ordinal {
        163 => (b"CreateCaret", 8),
        164 => (b"DestroyCaret", 0),
        165 => (b"SetCaretPos", 4),
        166 => (b"HideCaret", 2),
        167 => (b"ShowCaret", 2),
        183 => (b"GetCaretPos", 4),
        _ => panic!("not a caret export"),
    };
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.id, lookup_export(b"USER", ExportLookupTarget::Name(name)).unwrap().id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("caret exports require fixed Pascal frames");
    };
    assert_eq!(cleanup.callee_pop_bytes, stack_bytes);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    for argument in arguments.iter().rev() {
        match argument {
            Word(value) => bytes.extend_from_slice(&value.to_le_bytes()),
            Dword(value) => bytes.extend_from_slice(&value.to_le_bytes()),
            _ => panic!("unexpected caret argument width"),
        }
    }
    assert_eq!(bytes.len(), 4 + usize::from(stack_bytes));
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

fn dispatch(runtime: &mut Runtime, host: &mut CaretHost) -> Result<Option<u8>, RuntimeError> {
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
fn caret_create_preserves_shape_signed_dimensions_and_void_abi() {
    let native = Win16HostWindow(0x1234_5678_9abc);
    for (bitmap, shape) in [(0, Win16CaretShape::Solid), (1, Win16CaretShape::Gray)] {
        for (width, height) in [(0, 0), (1, 17), (i16::MIN, i16::MAX)] {
            for succeeded in [false, true] {
                let mut runtime = fixture();
                runtime.win16.as_mut().unwrap().window_handles.insert(2, native);
                let return_to = prepare(&mut runtime, 163, &[Word(2), Word(bitmap), Word(width as u16), Word(height as u16)]);
                let mut host = CaretHost { result: Some(Win16WindowCallResult::Boolean(succeeded)), ..Default::default() };
                assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
                assert_eq!(host.calls, [CaretCall::Create { window: Win16WindowTarget::Mapped(native), shape, width, height }]);
                assert_eq!(host.consumed, 1);
                assert_return(&runtime, return_to);
            }
        }
    }
}

#[test]
fn caret_bitmap_gap_does_not_replace_the_existing_native_caret() {
    for bitmap in [2, 0x1234, u16::MAX] {
        let mut runtime = fixture();
        let native = Win16HostWindow(0x1234_5678_9abc);
        runtime.win16.as_mut().unwrap().window_handles.insert(2, native);
        let return_to = prepare(&mut runtime, 163, &[Word(2), Word(1), Word(3), Word(4)]);
        let mut host = CaretHost { result: Some(Win16WindowCallResult::Boolean(true)), ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to);
        prepare(&mut runtime, 163, &[Word(2), Word(bitmap), Word(5), Word(6)]);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::CompatibilityGap);
        assert_eq!(host.calls, [CaretCall::Create { window: Win16WindowTarget::Mapped(native), shape: Win16CaretShape::Gray, width: 3, height: 4 }]);
        assert_eq!(host.consumed, 1);
        assert_eq!(runtime.cpu.regs.ax(), AX);
        assert_eq!(runtime.cpu.regs.dx(), DX);
    }
}

#[test]
fn caret_operations_do_not_require_a_runtime_created_caret_or_shadow_nesting() {
    for succeeded in [false, true] {
        let mut runtime = fixture();
        let mut host = CaretHost::default();
        let calls = [
            (165, vec![Word(i16::MIN as u16), Word(i16::MAX as u16)], CaretCall::SetPos { x: i16::MIN, y: i16::MAX }),
            (166, vec![Word(0)], CaretCall::Hide(Win16WindowTarget::Null)),
            (166, vec![Word(0)], CaretCall::Hide(Win16WindowTarget::Null)),
            (167, vec![Word(0)], CaretCall::Show(Win16WindowTarget::Null)),
            (167, vec![Word(0)], CaretCall::Show(Win16WindowTarget::Null)),
            (167, vec![Word(0)], CaretCall::Show(Win16WindowTarget::Null)),
            (164, vec![], CaretCall::Destroy),
            (164, vec![], CaretCall::Destroy),
        ];
        for (ordinal, arguments, expected) in calls {
            let return_to = prepare(&mut runtime, ordinal, &arguments);
            host.result = Some(Win16WindowCallResult::Boolean(succeeded));
            dispatch(&mut runtime, &mut host).unwrap();
            assert_eq!(host.calls.last(), Some(&expected));
            assert_eq!(host.calls.len(), host.consumed);
            assert_return(&runtime, return_to);
        }
        assert_eq!(host.calls.len(), 8);
    }
}

#[test]
fn caret_window_targets_distinguish_null_mapped_and_invalid() {
    let native = Win16HostWindow(0x1234_5678_9abc);
    for (window, expected) in [(0, Win16WindowTarget::Null), (2, Win16WindowTarget::Mapped(native)), (3, Win16WindowTarget::Invalid)] {
        for ordinal in [163, 166, 167] {
            let mut runtime = fixture();
            runtime.win16.as_mut().unwrap().window_handles.insert(2, native);
            let (arguments, expected) = match ordinal {
                163 => (vec![Word(window), Word(0), Word(2), Word(3)], CaretCall::Create { window: expected, shape: Win16CaretShape::Solid, width: 2, height: 3 }),
                166 => (vec![Word(window)], CaretCall::Hide(expected)),
                _ => (vec![Word(window)], CaretCall::Show(expected)),
            };
            let return_to = prepare(&mut runtime, ordinal, &arguments);
            let mut host = CaretHost::default();
            dispatch(&mut runtime, &mut host).unwrap();
            assert_eq!(host.calls, [expected]);
            assert_return(&runtime, return_to);
        }
    }
}

#[test]
fn caret_get_pos_writes_exact_point16_only_on_native_success() {
    for result in [None, Some(Win16HostPoint { x: -32769, y: 32768 })] {
        let mut runtime = fixture();
        let original = [0x91, 0x92, 0x93, 0x94, 0xa1, 0xa2, 0xa3, 0xa4];
        write_output(&mut runtime, original);
        let pointer = far(&runtime);
        let return_to = prepare(&mut runtime, 183, &[Dword(pointer)]);
        let mut host = CaretHost { result: Some(Win16WindowCallResult::Point(result)), ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        let mut expected = original;
        if result.is_some() { expected[..4].copy_from_slice(&Point16 { x: 32767, y: -32768 }.encode()); }
        assert_eq!(read_output(&runtime), expected);
        assert_eq!(host.calls, [CaretCall::GetPos]);
        assert_eq!(host.consumed, 1);
        assert_return(&runtime, return_to);
    }
}

#[test]
fn caret_get_pos_preflights_writable_full_point_before_host_call() {
    for (size, rights) in [(3, AccessRights::read_write()), (4, AccessRights::read_only())] {
        let mut runtime = fixture();
        let original = [0xa5; 8];
        write_output(&mut runtime, original);
        let pointer = far(&runtime);
        let state = runtime.win16.as_mut().unwrap();
        let pointer = state.selectors.pointer_from_far(pointer).unwrap();
        let base = state.selectors.translate(pointer, Access::Read, 8, &runtime.memory).unwrap();
        let alias = state.selectors.alloc_block(base, size, rights, &runtime.memory).unwrap();
        prepare(&mut runtime, 183, &[Dword(SegmentedPointer::new(alias, 0).far_value())]);
        let mut host = CaretHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert!(host.calls.is_empty());
        assert_eq!(read_output(&runtime), original);
    }
    for pointer in [0, u32::MAX] {
        let mut runtime = fixture();
        prepare(&mut runtime, 183, &[Dword(pointer)]);
        let mut host = CaretHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert!(host.calls.is_empty());
    }
}

#[test]
fn caret_get_pos_retained_result_rejects_reused_output_selector() {
    let mut runtime = fixture();
    let original = [0xa5; 8];
    write_output(&mut runtime, original);
    let pointer = far(&runtime);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(pointer).unwrap();
    let base = state.selectors.translate(pointer, Access::Read, 8, &runtime.memory).unwrap();
    let alias = state.selectors.alloc_block(base, 4, AccessRights::read_write(), &runtime.memory).unwrap();
    prepare(&mut runtime, 183, &[Dword(SegmentedPointer::new(alias, 0).far_value())]);
    let mut host = CaretHost {
        result: Some(Win16WindowCallResult::Point(Some(Win16HostPoint { x: 99, y: 98 }))),
        fail_readback_once: true,
        ..Default::default()
    };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(read_output(&runtime), original);
    let state = runtime.win16.as_mut().unwrap();
    state.selectors.free_block(alias).unwrap();
    let replacement = state.selectors.alloc_block(base, 4, AccessRights::read_write(), &runtime.memory).unwrap();
    assert_eq!(alias.raw(), replacement.raw());
    assert_ne!(alias.generation(), replacement.generation());
    let error = state.drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
    ).unwrap_err();
    assert_eq!(error.kind(), Kind::GuestFault);
    assert_eq!(read_output(&runtime), original);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 0);
}

#[test]
fn caret_get_pos_retries_retained_completion_without_repeating_native_call() {
    let mut runtime = fixture();
    let original = [0xa5; 8];
    write_output(&mut runtime, original);
    let pointer = far(&runtime);
    let return_to = prepare(&mut runtime, 183, &[Dword(pointer)]);
    let mut host = CaretHost {
        result: Some(Win16WindowCallResult::Point(Some(Win16HostPoint { x: -17, y: 31 }))),
        fail_readback_once: true,
        ..Default::default()
    };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(read_output(&runtime), original);
    let state = runtime.win16.as_mut().unwrap();
    state.drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
    ).unwrap();
    let mut expected = original;
    expected[..4].copy_from_slice(&Point16 { x: -17, y: 31 }.encode());
    assert_eq!(read_output(&runtime), expected);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 1);
    assert_return(&runtime, return_to);
}

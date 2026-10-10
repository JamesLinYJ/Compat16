//! Service-gate and retained-output coverage for USER.309 GetClipCursor.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostRect,
    Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState, Win16WindowCall,
    Win16WindowCallResult, Win16WindowOperation, Win16WindowResult,
    Win16WindowSourceRetiredProof, Win16WindowStep,
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

#[derive(Default)]
struct ClipHost {
    calls: usize,
    result: Option<Win16HostRect>,
    consumed: usize,
    fail_readback_once: bool,
    fail_consume_once: bool,
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

impl DosHost for ClipHost {
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

impl RuntimeHost for ClipHost {
    fn observe_win16_io(&mut self, event: &crate::Win16IoEvent<'_>) {
        assert!(!matches!(event, crate::Win16IoEvent::WindowRectResult { .. }),
            "cursor clipping must not emit an HWND rectangle observation");
    }
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::WindowCall(Win16WindowCall::GetClipCursor) = operation else {
            panic!("unexpected host operation");
        };
        self.calls += 1;
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(
                    Win16WindowCallResult::Rect(self.result.take()),
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
        if std::mem::take(&mut self.fail_consume_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers consumption after output commitment"));
        }
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for ClipHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for ClipHost {}
impl crate::RuntimeMidiHost for ClipHost {}
impl crate::RuntimeNetbiosHost for ClipHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\CLIP.NE").unwrap();
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), OFFSET - 1).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &[0xa7; 10]).unwrap();
    runtime
}

fn far(runtime: &Runtime) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(OFFSET)
}

fn bytes(runtime: &Runtime) -> [u8; 10] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), OFFSET - 1).unwrap();
    let mut bytes = [0; 10];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn prepare(runtime: &mut Runtime, rect: u32) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(309)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("GetClipCursor requires a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, 4);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&rect.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    (return_cs, return_ip, stack + 8)
}

fn dispatch(runtime: &mut Runtime, host: &mut ClipHost) -> Result<Option<u8>, RuntimeError> {
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
fn get_clip_cursor_writes_exact_rect16_preserves_void_and_narrows_signed_edges() {
    for result in [None,
        Some(Win16HostRect { left: -10, top: -20, right: 500, bottom: 700 }),
        Some(Win16HostRect { left: -32769, top: 32768, right: 65537, bottom: -65538 }),
    ] {
        let mut runtime = fixture();
        let pointer = far(&runtime);
        let return_to = prepare(&mut runtime, pointer);
        let mut host = ClipHost { result, ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        let mut expected = [0xa7; 10];
        if let Some(rect) = result {
            expected[1..9].copy_from_slice(&Rect16 {
                left: rect.left as i16, top: rect.top as i16,
                right: rect.right as i16, bottom: rect.bottom as i16,
            }.encode());
        }
        assert_eq!(bytes(&runtime), expected);
        assert_eq!((host.calls, host.consumed), (1, 1));
        assert_return(&runtime, return_to);
    }
}

fn output_alias(runtime: &mut Runtime, size: u32, rights: AccessRights) -> win16_abi::SelectorRef {
    let original = far(runtime);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(original).unwrap();
    let base = state.selectors.translate(pointer, Access::Read, 8, &runtime.memory).unwrap();
    state.selectors.alloc_block(base, size, rights, &runtime.memory).unwrap()
}

#[test]
fn get_clip_cursor_preflights_null_short_read_only_and_invalid_outputs_without_submission() {
    for (size, rights) in [(7, AccessRights::read_write()), (8, AccessRights::read_only())] {
        let mut runtime = fixture();
        let alias = output_alias(&mut runtime, size, rights);
        prepare(&mut runtime, SegmentedPointer::new(alias, 0).far_value());
        let mut host = ClipHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(host.calls, 0);
        assert_eq!(bytes(&runtime), [0xa7; 10]);
    }
    for pointer in [0, u32::MAX] {
        let mut runtime = fixture();
        prepare(&mut runtime, pointer);
        let mut host = ClipHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(host.calls, 0);
        assert_eq!(bytes(&runtime), [0xa7; 10]);
    }
}

#[test]
fn get_clip_cursor_retained_result_rejects_stale_and_reused_output_selectors() {
    for reuse in [false, true] {
        let mut runtime = fixture();
        let alias = output_alias(&mut runtime, 8, AccessRights::read_write());
        prepare(&mut runtime, SegmentedPointer::new(alias, 0).far_value());
        let mut host = ClipHost {
            result: Some(Win16HostRect { left: -1, top: -2, right: 3, bottom: 4 }),
            fail_readback_once: true, ..Default::default()
        };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
        runtime.win16.as_mut().unwrap().selectors.free_block(alias).unwrap();
        if reuse {
            let replacement = output_alias(&mut runtime, 8, AccessRights::read_write());
            assert_eq!(alias.raw(), replacement.raw());
            assert_ne!(alias.generation(), replacement.generation());
        }
        let error = runtime.win16.as_mut().unwrap().drive_pending_window_completion(
            &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
        ).unwrap_err();
        assert_eq!(error.kind(), Kind::GuestFault);
        assert_eq!(bytes(&runtime), [0xa7; 10]);
        assert_eq!((host.calls, host.consumed), (1, 0));
        assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX, DX));
    }
}

#[test]
fn get_clip_cursor_retries_deferred_completion_without_repeating_native_read() {
    let mut runtime = fixture();
    let pointer = far(&runtime);
    let return_to = prepare(&mut runtime, pointer);
    let mut host = ClipHost {
        result: Some(Win16HostRect { left: -1, top: -2, right: 3, bottom: 4 }),
        fail_readback_once: true, ..Default::default()
    };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(bytes(&runtime), [0xa7; 10]);
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
    ).unwrap();
    let mut expected = [0xa7; 10];
    expected[1..9].copy_from_slice(&Rect16 { left: -1, top: -2, right: 3, bottom: 4 }.encode());
    assert_eq!(bytes(&runtime), expected);
    assert_eq!((host.calls, host.consumed), (1, 1));
    assert_return(&runtime, return_to);
}

#[test]
fn get_clip_cursor_retry_after_output_commit_never_rewrites_guest_bytes() {
    let mut runtime = fixture();
    let pointer = far(&runtime);
    let return_to = prepare(&mut runtime, pointer);
    let mut host = ClipHost {
        result: Some(Win16HostRect { left: -1, top: -2, right: 3, bottom: 4 }),
        fail_consume_once: true, ..Default::default()
    };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    let mut expected = [0xa7; 10];
    expected[1..9].copy_from_slice(&Rect16 { left: -1, top: -2, right: 3, bottom: 4 }.encode());
    assert_eq!(bytes(&runtime), expected);
    let state = runtime.win16.as_ref().unwrap();
    let output = state.selectors.pointer_from_far(pointer).unwrap();
    state.selectors.write(&mut runtime.memory, output, &[0x5c; 8]).unwrap();
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
    ).unwrap();
    expected[1..9].fill(0x5c);
    assert_eq!(bytes(&runtime), expected);
    assert_eq!((host.calls, host.consumed), (1, 1));
    assert_return(&runtime, return_to);
}

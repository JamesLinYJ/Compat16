//! USER.247 service gate, identity, exhaustion and retained-result coverage.
use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostCursor,
    Win16HostIcon, Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState,
    Win16HostUserCursorAcceleratorOperation, Win16HostUserCursorAcceleratorResult,
    Win16WindowOperation, Win16WindowResult, Win16WindowSourceRetiredProof, Win16WindowStep,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};
use guest_core::Selector;
use std::sync::Arc;
use win16_abi::{ExportLookupTarget, Win16ExportStackCleanup, Win16ReturnKind, lookup_export};
const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;

#[derive(Default)]
struct CursorHost {
    calls: usize,
    result: Option<Win16HostCursor>,
    consumed: usize,
    fail_readback_once: bool,
    fail_consume_once: bool,
}

fn proof() -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(41),
            kind: Win16NativeWindowOperationKind::UserCursorAccelerator,
        },
        worker_generation: 7,
        state: Win16NativeWindowOperationState::Returned,
    })
}

impl DosHost for CursorHost {
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

impl RuntimeHost for CursorHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::UserCursorAccelerator(Win16HostUserCursorAcceleratorOperation::GetCursor) = operation else {
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
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::UserCursorAccelerator(
                    Win16HostUserCursorAcceleratorResult::GetCursor(self.result),
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
impl crate::RuntimeDdeHost for CursorHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for CursorHost {}
impl crate::RuntimeMidiHost for CursorHost {}
impl crate::RuntimeNetbiosHost for CursorHost {}

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\CURSOR.NE").unwrap()
}

fn prepare(runtime: &mut Runtime) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(247)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("GetCursor requires a fixed Pascal frame");
    };
    assert_eq!((cleanup.callee_pop_bytes, cleanup.caller_pop_bytes), (0, 0));
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    (return_cs, return_ip, stack + 4)
}

fn dispatch(runtime: &mut Runtime, host: &mut CursorHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0)
}

fn resume(runtime: &mut Runtime, host: &mut CursorHost) -> Result<(), RuntimeError> {
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host)
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), cursor: u16) {
    assert_eq!(runtime.cpu.regs.ax(), cursor);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

#[test]
fn get_cursor_null_known_new_and_repeated_reads_preserve_typed_guest_identity() {
    for known in [false, true] {
        for result in [None, Some(Win16HostCursor(0x1234_5678_9abc_def0))] {
            let mut runtime = fixture();
            let images = &mut runtime.win16.as_mut().unwrap().guest_images;
            let icon = images.allocate_icon(Win16HostIcon(0x1234_5678_9abc_def0)).unwrap().0;
            let existing = if known { result.map(|cursor| images.allocate_cursor(cursor).unwrap()) } else { None };
            let mut host = CursorHost { result, ..Default::default() };
            let mut previous = None;
            for call in 1..=2 {
                let return_to = prepare(&mut runtime);
                dispatch(&mut runtime, &mut host).unwrap();
                let handle = runtime.cpu.regs.ax();
                assert_return(&runtime, return_to, handle);
                if let Some(cursor) = result {
                    assert!(handle >= 2);
                    assert_ne!(handle, icon);
                    assert_eq!(runtime.win16.as_ref().unwrap().guest_images.cursor(handle), Some(cursor));
                } else { assert_eq!(handle, 0); }
                if let Some(existing) = existing { assert_eq!(handle, existing); }
                if let Some(previous) = previous { assert_eq!(handle, previous); }
                previous = Some(handle);
                assert_eq!((host.calls, host.consumed), (call, call));
            }
        }
    }
}

#[test]
fn get_cursor_deferred_readback_and_consumption_retry_never_repeat_native_read() {
    for consume in [false, true] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime);
        let token = Win16HostCursor(0xfeed);
        let mut host = CursorHost { result: Some(token),
            fail_readback_once: !consume, fail_consume_once: consume, ..Default::default() };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
        assert_eq!(host.calls, 1);
        resume(&mut runtime, &mut host).unwrap();
        let handle = runtime.cpu.regs.ax();
        assert_eq!(runtime.win16.as_ref().unwrap().guest_images.cursor(handle), Some(token));
        assert_return(&runtime, return_to, handle);
        assert_eq!((host.calls, host.consumed), (1, 1));
    }
}

#[test]
fn get_cursor_exhaustion_retains_result_until_guest_slot_is_available() {
    let mut runtime = fixture();
    runtime.win16.as_mut().unwrap().guest_images.fill_for_get_cursor_test();
    let return_to = prepare(&mut runtime);
    let token = Win16HostCursor(u64::MAX);
    let mut host = CursorHost { result: Some(token), ..Default::default() };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::ResourceExhausted);
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX, DX));
    assert_eq!((host.calls, host.consumed), (1, 0));
    // Free a guest-only icon fixture entry without sending any native release.
    assert!(runtime.win16.as_mut().unwrap().guest_images.take_unpublished_icon(2, Win16HostIcon(2)));
    resume(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 2);
    assert_eq!(runtime.win16.as_ref().unwrap().guest_images.cursor(2), Some(token));
    assert_eq!((host.calls, host.consumed), (1, 1));
}

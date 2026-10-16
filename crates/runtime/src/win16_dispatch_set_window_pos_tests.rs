//! Service-gate coverage for USER.232 insertion identity and ignored operands.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostWindow,
    Win16HostWindowOperationId, Win16IoEvent, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState, Win16WindowCall,
    Win16WindowCallResult, Win16WindowInsertAfter, Win16WindowOperation, Win16WindowResult,
    Win16WindowSourceRetiredProof, Win16WindowStep, Win16WindowTarget,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use std::sync::Arc;
use win16_abi::{ExportLookupTarget, lookup_export};

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
const TARGET: Win16HostWindow = Win16HostWindow(0x1234_5678_9abc);
const INSERTION: Win16HostWindow = Win16HostWindow(0xabcd_1234_5678);
const NOZORDER: u16 = 4;

#[derive(Debug, Eq, PartialEq)]
struct Position {
    window: Win16WindowTarget,
    insert_after: Win16WindowInsertAfter,
    x: i16, y: i16, width: i16, height: i16, flags: u16,
}

#[derive(Default)]
struct PositionHost {
    calls: Vec<Position>,
    observed: Vec<(u16, u16, u16)>,
    result: bool,
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

impl DosHost for PositionHost {
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

impl RuntimeHost for PositionHost {
    fn observe_win16_io(&mut self, event: &Win16IoEvent<'_>) {
        if let Win16IoEvent::WindowPositionRequest { window, insert_after, flags, .. } = event {
            self.observed.push((*window, *insert_after, *flags));
        }
    }
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::WindowCall(Win16WindowCall::SetWindowPos {
            window, insert_after, x, y, width, height, flags,
        }) = operation else { panic!("unexpected host operation"); };
        self.calls.push(Position { window, insert_after, x, y, width, height, flags });
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(
                    Win16WindowCallResult::Boolean(self.result),
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
            return Err(RuntimeError::new(Kind::HostFailure, "test defers position result readback"));
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
impl crate::RuntimeDdeHost for PositionHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for PositionHost {}
impl crate::RuntimeMidiHost for PositionHost {}
impl crate::RuntimeNetbiosHost for PositionHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\POSITION.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.window_handles.insert(0x1234, TARGET);
    state.window_handles.insert(0x2345, INSERTION);
    state.owned_window_handles.insert(0x1234);
    runtime
}

fn prepare(runtime: &mut Runtime, window: u16, insert_after: u16, flags: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(232)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    for word in [flags, 0xffff, 0x8000, 0x7fff, 0xffed, insert_after, window] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
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

fn dispatch(runtime: &mut Runtime, host: &mut PositionHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), value: u16) {
    assert_eq!(runtime.cpu.regs.ax(), value);
    assert_eq!(runtime.cpu.regs.dx(), DX, "WORD result preserves DX");
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

fn expected(insert_after: Win16WindowInsertAfter, flags: u16) -> Position {
    Position { window: Win16WindowTarget::Mapped(TARGET), insert_after,
        x: -19, y: i16::MAX, width: i16::MIN, height: -1, flags }
}

#[test]
fn set_window_pos_ignores_unknown_retired_and_mapped_insertions_under_nozorder() {
    for insertion in [0, 1, 0xffff, 0xfffe, 0x2345, 0x3456, 0xdead] {
        for flags in [NOZORDER, 0x8017, 0xffff] {
            for result in [false, true] {
                let mut runtime = fixture();
                // Retire one previously issued guest handle. It must be just
                // as harmless as an unknown value when the operand is ignored.
                let state = runtime.win16.as_mut().unwrap();
                state.window_handles.insert(0x3456, Win16HostWindow(77));
                state.window_handles.remove(&0x3456);
                let handles = state.window_handles.clone();
                let owners = state.owned_window_handles.clone();
                let return_to = prepare(&mut runtime, 0x1234, insertion, flags);
                let mut host = PositionHost { result, ..Default::default() };
                dispatch(&mut runtime, &mut host).unwrap();
                assert_eq!(host.calls, [expected(Win16WindowInsertAfter::Top, flags)]);
                assert_eq!(host.observed, [(0x1234, insertion, flags)]);
                assert_eq!(host.consumed, 1);
                assert_return(&runtime, return_to, u16::from(result));
                let state = runtime.win16.as_ref().unwrap();
                assert_eq!(state.window_handles, handles);
                assert_eq!(state.owned_window_handles, owners);
            }
        }
    }
}

#[test]
fn set_window_pos_preserves_pseudo_handles_opaque_identity_geometry_and_flags() {
    for (guest, insertion) in [
        (0, Win16WindowInsertAfter::Top), (1, Win16WindowInsertAfter::Bottom),
        (0xffff, Win16WindowInsertAfter::Topmost), (0xfffe, Win16WindowInsertAfter::NotTopmost),
        (0x2345, Win16WindowInsertAfter::Window(INSERTION)),
    ] {
        for flags in [0, 0x8013, 0xfffb] {
            let mut runtime = fixture();
            let return_to = prepare(&mut runtime, 0x1234, guest, flags);
            let mut host = PositionHost { result: true, ..Default::default() };
            dispatch(&mut runtime, &mut host).unwrap();
            assert_eq!(host.calls, [expected(insertion, flags)]);
            assert_return(&runtime, return_to, 1);
        }
    }
}

#[test]
fn set_window_pos_rejects_unmapped_used_insertions_without_starting_native_work() {
    for insertion in [0x2345, 0xdead] {
        let mut runtime = fixture();
        runtime.win16.as_mut().unwrap().window_handles.remove(&0x2345);
        let return_to = prepare(&mut runtime, 0x1234, insertion, 0x13);
        let mut host = PositionHost { result: true, ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert!(host.calls.is_empty());
        assert_eq!(host.consumed, 0);
        assert_return(&runtime, return_to, 0);
    }
}

#[test]
fn set_window_pos_nozorder_does_not_bypass_target_window_validation() {
    for (guest, target) in [(0, Win16WindowTarget::Null), (0xdead, Win16WindowTarget::Invalid)] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, guest, 0xbeef, NOZORDER);
        let mut host = PositionHost::default();
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls, [Position { window: target,
            ..expected(Win16WindowInsertAfter::Top, NOZORDER) }]);
        assert_return(&runtime, return_to, 0);
    }
}

#[test]
fn set_window_pos_retries_result_readback_without_repeating_native_mutation() {
    let mut runtime = fixture();
    let return_to = prepare(&mut runtime, 0x1234, 0x2345, 0x13);
    let mut host = PositionHost { result: true, fail_readback_once: true, ..Default::default() };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 0);
    assert_eq!(runtime.cpu.regs.ax(), AX);
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
    ).unwrap();
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed, 1);
    assert_return(&runtime, return_to, 1);
}

//! USER.233 and field setters retain native outcomes across fallible projection.

use super::super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostWindow,
    Win16HostWindowLiveness, Win16HostWindowParentObservation,
    Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState, Win16WindowCall,
    Win16WindowCallResult, Win16WindowDataCall, Win16WindowDataResult,
    Win16WindowOperation, Win16WindowResult,
    Win16WindowSourceRetiredProof, Win16WindowStep, Win16WindowTarget,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, Selector};
use std::sync::Arc;
use win16_abi::{ExportLookupTarget, lookup_export};

const CHILD: Win16HostWindow = Win16HostWindow(0x1234_5678_9abc);
const OLD: Win16HostWindow = Win16HostWindow(0x2345_6789_abcd);
const NEW: Win16HostWindow = Win16HostWindow(0x3456_789a_bcde);
const DX: u16 = 0x5aa5;

struct SetParentHost {
    calls: Vec<Win16WindowDataCall>,
    malformed_result: Option<Win16WindowDataResult>,
    attempted: bool,
    succeeded: bool,
    previous: Option<Win16HostWindow>,
    final_parent: Option<Win16HostWindow>,
    retired_previous: bool,
    retired_child: bool,
    fail_parent_once: bool,
    fail_liveness_once: bool,
    parent_queries: usize,
    liveness_queries: usize,
    consumed: usize,
}
impl Default for SetParentHost {
    fn default() -> Self {
        Self { calls: vec![], malformed_result: None, attempted: true, succeeded: true, previous: Some(OLD),
            final_parent: Some(NEW), retired_previous: false, retired_child: false,
            fail_parent_once: false, fail_liveness_once: false,
            parent_queries: 0, liveness_queries: 0, consumed: 0 }
    }
}
fn proof() -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(41),
            kind: Win16NativeWindowOperationKind::WindowCall,
        }, worker_generation: 7, state: Win16NativeWindowOperationState::Returned,
    })
}
impl DosHost for SetParentHost {
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


impl RuntimeHost for SetParentHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation)
        -> Result<Win16WindowStep, RuntimeError>
    {
        let Win16WindowOperation::WindowCall(Win16WindowCall::WindowData(call)) = operation
            else { panic!("unexpected native operation"); };
        self.calls.push(call);
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id, worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(
                    Win16WindowCallResult::WindowData(self.malformed_result.take().unwrap_or(
                        Win16WindowDataResult::ParentMutation {
                            attempted: self.attempted, succeeded: self.succeeded, previous: self.previous,
                        },
                    )),
                ))),
            }),
        })
    }
    fn win16_host_window_parent(&mut self, window: Win16HostWindow)
        -> Result<Win16HostWindowParentObservation, RuntimeError>
    {
        assert_eq!(window, CHILD, "query the original child's exact token");
        self.parent_queries += 1;
        if std::mem::take(&mut self.fail_parent_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test parent observation unavailable"));
        }
        Ok(if self.retired_child { Win16HostWindowParentObservation::Retired }
            else { Win16HostWindowParentObservation::Live { child_parent: self.final_parent } })
    }
    fn win16_host_window_liveness(&mut self, window: Win16HostWindow)
        -> Result<Win16HostWindowLiveness, RuntimeError>
    {
        assert_eq!(window, OLD);
        self.liveness_queries += 1;
        if std::mem::take(&mut self.fail_liveness_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test previous identity unavailable"));
        }
        Ok(if self.retired_previous { Win16HostWindowLiveness::Retired }
            else { Win16HostWindowLiveness::Live })
    }
    fn win16_window_source_retirement(&mut self,
        operation: Win16NativeWindowOperationProof, worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = proof();
        assert_eq!(operation, proof.operation);
        assert_eq!(worker_generation, proof.worker_generation);
        Ok(Some(proof))
    }
    fn win16_window_source_retirement_consumed(&mut self, actual: &Win16WindowSourceRetiredProof)
        -> Result<(), RuntimeError>
    {
        assert_eq!(actual, proof().as_ref());
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for SetParentHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for SetParentHost {}
impl crate::RuntimeMidiHost for SetParentHost {}
impl crate::RuntimeNetbiosHost for SetParentHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\SETPARENT.NE").unwrap();
    assert!(runtime.memory.len() >= 1024 * 1024);
    let state = runtime.win16.as_mut().unwrap();
    state.window_handles.extend([(0x1234, CHILD), (0x2345, OLD), (0x3456, NEW)]);
    state.owned_window_handles.insert(0x1234);
    state.window_parents.insert(0x1234, 0x2345);
    runtime
}
fn prepare(runtime: &mut Runtime, ordinal: u16, parent: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&parent.to_le_bytes());
    if ordinal == 136 { bytes.extend_from_slice(&0xdead_u16.to_le_bytes()); }
    if ordinal != 233 { bytes.extend_from_slice(&(-8_i16).to_le_bytes()); }
    bytes.extend_from_slice(&0x1234_u16.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(DX);
    (return_cs, return_ip, stack + bytes.len() as u16)
}
fn dispatch(runtime: &mut Runtime, host: &mut SetParentHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}
fn resume(runtime: &mut Runtime, host: &mut SetParentHost) {
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host,
    ).unwrap();
}
fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), value: u16, ordinal: u16) {
    assert_eq!(runtime.cpu.regs.ax(), value);
    assert_eq!(runtime.cpu.regs.dx(), if ordinal == 136 { 0 } else { DX });
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

#[test]
fn set_parent_abi_and_old_field_setters_keep_distinct_native_calls() {
    for ordinal in [233, 134, 136] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, ordinal, 0x3456);
        let mut host = SetParentHost::default();
        dispatch(&mut runtime, &mut host).unwrap();
        let window = Win16WindowTarget::Mapped(CHILD);
        let parent = Win16WindowTarget::Mapped(NEW);
        assert_eq!(host.calls, [if ordinal == 233 { Win16WindowDataCall::Reparent { window, parent } }
            else { Win16WindowDataCall::SetParent { window, parent } }]);
        assert_return(&runtime, return_to, 0x2345, ordinal);
        assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x3456);
    }
}

#[test]
fn parent_mutation_projection_retries_queries_without_repeating_native_call() {
    for ordinal in [233, 134, 136] {
        for liveness_failure in [false, true] {
            let mut runtime = fixture();
            let return_to = prepare(&mut runtime, ordinal, 0x3456);
            let mut host = SetParentHost { fail_parent_once: !liveness_failure,
                fail_liveness_once: liveness_failure, ..Default::default() };
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
            assert_eq!(host.calls.len(), 1);
            assert_eq!(runtime.cpu.regs.ax(), 0xa55a);
            if !liveness_failure {
                assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x2345);
            }
            resume(&mut runtime, &mut host);
            assert_eq!(host.calls.len(), 1);
            assert_eq!(host.parent_queries, if liveness_failure { 1 } else { 2 });
            assert_return(&runtime, return_to, 0x2345, ordinal);
            assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x3456);
        }
    }
}

#[test]
fn failed_native_parent_mutation_still_reconciles_observed_nested_move() {
    for ordinal in [233, 134, 136] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, ordinal, 0x3456);
        let mut host = SetParentHost { succeeded: false, ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0, ordinal);
        assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x3456);
        assert_eq!(host.parent_queries, 1);
        assert_eq!(host.liveness_queries, 0);
    }
}

#[test]
fn retired_previous_parent_returns_zero_without_reviving_alias() {
    let mut runtime = fixture();
    runtime.win16.as_mut().unwrap().window_handles.remove(&0x2345);
    let return_to = prepare(&mut runtime, 233, 0x3456);
    let mut host = SetParentHost { retired_previous: true, ..Default::default() };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0, 233);
    assert!(!runtime.win16.as_ref().unwrap().window_handles.values().any(|token| *token == OLD));
}

#[test]
fn parent_projection_does_not_change_a_replacement_child_incarnation() {
    let mut runtime = fixture();
    let return_to = prepare(&mut runtime, 233, 0x3456);
    let mut host = SetParentHost { fail_parent_once: true, ..Default::default() };
    assert!(dispatch(&mut runtime, &mut host).is_err());
    let replacement = Win16HostWindow(CHILD.0 + 1);
    runtime.win16.as_mut().unwrap().window_handles.insert(0x1234, replacement);
    runtime.win16.as_mut().unwrap().window_parents.insert(0x1234, 0x2345);
    resume(&mut runtime, &mut host);
    assert_return(&runtime, return_to, 0x2345, 233);
    assert_eq!(runtime.win16.as_ref().unwrap().window_handles[&0x1234], replacement);
    assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x2345);
    assert_eq!(host.calls.len(), 1);
}

#[test]
fn set_parent_invalid_nonzero_parent_is_never_null() {
    for (guest, expected) in [(0, Win16WindowTarget::Null), (0xdead, Win16WindowTarget::Invalid)] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, 233, guest);
        let mut host = SetParentHost { attempted: false, succeeded: false, previous: None,
            ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls, [Win16WindowDataCall::Reparent {
            window: Win16WindowTarget::Mapped(CHILD), parent: expected,
        }]);
        assert_return(&runtime, return_to, 0, 233);
        assert_eq!(host.parent_queries, 0);
        assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x2345);
    }
}

#[test]
fn retired_child_observation_is_not_a_successful_detachment() {
    let mut runtime = fixture();
    let return_to = prepare(&mut runtime, 233, 0x3456);
    let mut host = SetParentHost { retired_child: true, ..Default::default() };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0x2345, 233);
    // Exact destruction receipts, not this observation, retire the child.
    assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x2345);
}

#[test]
fn missing_child_handle_finishes_without_native_mutation_or_queries() {
    let mut runtime = fixture();
    runtime.win16.as_mut().unwrap().window_handles.remove(&0x1234);
    let return_to = prepare(&mut runtime, 233, 0x3456);
    let mut host = SetParentHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0, 233);
    assert!(host.calls.is_empty());
    assert_eq!((host.parent_queries, host.liveness_queries), (0, 0));
}

#[test]
fn mutation_continuations_reject_legacy_getter_result_before_projection() {
    for ordinal in [233, 134, 136] {
        let mut runtime = fixture();
        prepare(&mut runtime, ordinal, 0x3456);
        let mut host = SetParentHost {
            malformed_result: Some(Win16WindowDataResult::Parent {
                succeeded: true, previous: Some(OLD), child_parent: Some(NEW),
            }), ..Default::default()
        };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::InternalInvariant);
        assert_eq!(host.calls.len(), 1);
        assert_eq!((host.parent_queries, host.liveness_queries), (0, 0));
        assert_eq!(runtime.cpu.regs.ax(), 0xa55a);
        assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x2345);
    }
}

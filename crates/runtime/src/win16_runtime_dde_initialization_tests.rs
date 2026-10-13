//! Direct DdeInitialize completion retains its exact source and caller owners.

use super::super::{
    ImportBinding, execute::Win16TaskExecutionEnded, test_support::tiny_ne_executable,
};
use super::*;
use crate::*;
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::{
    Access, AccessRights, ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup,
    lookup_export,
};

const OPERATION: Win16HostDdeOperation = Win16HostDdeOperation(41);
const OWNER: Win16HostDdeOwner = Win16HostDdeOwner(7);
const GENERATION: u64 = 3;
const INSTANCE: Win16HostDdeInstance = Win16HostDdeInstance(91);
const OUTPUT_OFFSET: u16 = 0x10;

enum BeginResult {
    SourceRetired,
    RawComplete,
    StartedFailure(Arc<Win16DdeOperationStartedFailure>),
}

struct InitializationHost {
    begin_result: BeginResult,
    calls: Vec<Win16HostDdeCall>,
    proof: Arc<Win16DdeSourceRetiredProof>,
    fail_source_readback_once: bool,
    source_readbacks: usize,
    consumed: Vec<Win16DdeSourceRetiredProof>,
    retired: Vec<Win16DdeOperationRetirementProof>,
    resources_retired: usize,
    result: Option<Win16HostDdeResult>,
    additional_proofs: Vec<Win16DdeSourceRetiredProof>,
    terminal_source: Option<Win16WindowTerminalSourceTop>,
    fail_retirement_before_once: bool,
    fail_terminal_source_once: bool,
    fail_retirement_reply_once: bool,
}

impl Default for InitializationHost {
    fn default() -> Self {
        Self {
            begin_result: BeginResult::SourceRetired,
            calls: Vec::new(),
            proof: Arc::new(Win16DdeSourceRetiredProof {
                operation: OPERATION,
                owner: OWNER,
                worker_generation: GENERATION,
            }),
            fail_source_readback_once: false,
            source_readbacks: 0,
            consumed: Vec::new(),
            retired: Vec::new(),
            resources_retired: 0,
            result: None,
            additional_proofs: Vec::new(),
            terminal_source: None,
            fail_retirement_before_once: false,
            fail_terminal_source_once: false,
            fail_retirement_reply_once: false,
        }
    }
}

fn native_result() -> Win16HostDdeResult {
    Win16HostDdeResult {
        value: Win16HostDdeValue::Instance(Some(INSTANCE)),
        dde_error: dde_error::NO_ERROR,
        transaction_result: None,
        data_transfer: None,
    }
}

fn source_retired(proof: Arc<Win16DdeSourceRetiredProof>) -> Win16WindowStep {
    Win16WindowStep::DdeSourceRetired {
        proof,
        result: Box::new(Win16WindowStep::Complete(Win16WindowResult::Dde(
            native_result(),
        ))),
    }
}

impl RuntimeHost for InitializationHost {
    fn win16_window_begin(
        &mut self,
        operation: Win16WindowOperation,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::Dde(call) = operation
        else {
            panic!("unexpected native operation");
        };
        self.calls.push(call);
        Ok(match &self.begin_result {
            BeginResult::SourceRetired => Win16WindowStep::DdeSourceRetired {
                proof: Arc::clone(&self.proof),
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::Dde(
                    self.result.clone().unwrap_or_else(native_result)))),
            },
            BeginResult::RawComplete => {
                Win16WindowStep::Complete(Win16WindowResult::Dde(native_result()))
            }
            BeginResult::StartedFailure(failure) => {
                Win16WindowStep::DdeStartedFailure(Arc::clone(failure))
            }
        })
    }
    fn win16_window_terminal_source_top(
        &mut self, _receipt: &Win16WindowAbortReceipt,
    ) -> Result<Option<Win16WindowTerminalSourceTop>, RuntimeError> {
        if std::mem::take(&mut self.fail_terminal_source_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers shared-source query"));
        }
        Ok(self.terminal_source)
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}

impl RuntimeDdeHost for InitializationHost {
    fn win16_dde_abort(&mut self) -> Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
    fn win16_dde_source_retirement(
        &mut self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<bool, RuntimeError> {
        assert!(proof == self.proof.as_ref() || self.additional_proofs.contains(proof));
        assert!(!self.retired.iter().any(|retired| retired.cancellation.operation == proof.operation),
            "normal proof readback replayed after shutdown ACK");
        self.source_readbacks += 1;
        if std::mem::take(&mut self.fail_source_readback_once) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "test defers exact DDE tombstone consumption",
            ));
        }
        Ok(true)
    }
    fn win16_dde_source_retirement_consumed(
        &mut self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        assert!(proof == self.proof.as_ref() || self.additional_proofs.contains(proof));
        assert!(
            !self.consumed.iter().any(|entry| entry.operation == proof.operation),
            "DDE source ACK replayed after consumption"
        );
        self.consumed.push(proof.clone());
        Ok(())
    }
    fn win16_dde_operation_retired(
        &mut self,
        proof: &Win16DdeOperationRetirementProof,
        receipt: &Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        assert!(proof.matches_receipt(receipt));
        assert_eq!(proof.owner, OWNER);
        assert_eq!(proof.worker_generation, GENERATION);
        assert!(proof.cancellation.operation == OPERATION
            || self.additional_proofs.iter().any(|normal| normal.operation == proof.cancellation.operation));
        if let BeginResult::StartedFailure(failure) = &self.begin_result {
            assert!(proof.matches_started_failure(failure));
        }
        if std::mem::take(&mut self.fail_retirement_before_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers exact shutdown ACK"));
        }
        if let Some(cached) = self.retired.iter().find(|cached|
            cached.cancellation.operation == proof.cancellation.operation)
        {
            assert_eq!(cached, proof, "terminal ACK changed across reply-loss retry");
        } else {
            self.retired.push(proof.clone());
        }
        if std::mem::take(&mut self.fail_retirement_reply_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test loses exact shutdown ACK reply"));
        }
        Ok(())
    }
    fn win16_dde_runtime_resources_retired(
        &mut self,
        receipt: &Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        assert_eq!(
            self.retired.len(),
            1,
            "DDE storage closed before exact operation ACK"
        );
        assert!(self.retired[0].matches_receipt(receipt));
        assert_eq!(receipt.owner, Some(OWNER));
        assert_eq!(receipt.worker_generation, Some(GENERATION));
        assert_eq!(receipt.request_id, Some(19));
        assert_eq!(self.resources_retired, 0);
        self.resources_retired += 1;
        Ok(())
    }
}
impl RuntimeMciHost for InitializationHost {}
impl RuntimeMidiHost for InitializationHost {}
impl RuntimeNetbiosHost for InitializationHost {}

impl DosHost for InitializationHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
        _sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(
        &mut self,
        _file: DosHostFile,
        _offset: i32,
        _origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(
        &mut self,
        _drive: u8,
        _output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\DDE.NE").unwrap()
}

fn output(runtime: &Runtime) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(OUTPUT_OFFSET)
}

fn read_instance(runtime: &Runtime) -> u32 {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(output(runtime)).unwrap();
    let mut bytes = [0; 4];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    u32::from_le_bytes(bytes)
}

fn write_instance(runtime: &mut Runtime, instance: u32) {
    let pointer = output(runtime);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(pointer).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &instance.to_le_bytes())
        .unwrap();
}

fn dde_continuation(runtime: &Runtime) -> &Win16DdeContinuation {
    let frame = runtime
        .win16
        .as_ref()
        .unwrap()
        .window_operations
        .last()
        .unwrap();
    let Some(WindowReturn::Dde(continuation)) = frame.continuation() else {
        panic!("missing exact DDE continuation");
    };
    continuation
}

/// Use the same full-context/CPU-owner seam as dispatch, but stop before its
/// completion driver so the unprojected native carrier can be inspected.
fn begin(
    runtime: &mut Runtime,
    host: &mut InitializationHost,
    instance_output: u32,
) -> Result<(u16, u16, u32), RuntimeError> {
    let request = Win16DdeRequest::Initialize {
        instance_output,
        initial_instance: read_instance(runtime),
        callback: u32::from(runtime.cpu.regs.cs) << 16,
        flags: 0,
        reserved: 0,
    };
    begin_request(runtime, host, request)
}

fn begin_request(
    runtime: &mut Runtime,
    host: &mut InitializationHost,
    request: Win16DdeRequest,
) -> Result<(u16, u16, u32), RuntimeError> {
    let return_to = (runtime.cpu.regs.cs, 0x12, u32::from(runtime.cpu.regs.sp()) + 20);
    let context = runtime.cpu.capture_context();
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.capture_legacy_cpu_call_frame(
        &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory,
    )?;
    assert!(state.window_dispatch_context.replace(context).is_none());
    assert!(state.active_dispatch_call_owner.replace(owner).is_none());
    let return_kind = super::api::dde_return_kind(&request);
    let result = state.begin_dde_request(
        request, &mut runtime.cpu.regs, &mut runtime.memory, host,
        return_to, return_kind,
    );
    state.window_dispatch_context = None;
    assert!(
        state.active_dispatch_call_owner.is_none(),
        "DDE begin left the dispatch owner set: {result:?}"
    );
    result?;
    Ok(return_to)
}

fn prepare_dispatch(runtime: &mut Runtime) -> (u16, u16, u32) {
    let descriptor = lookup_export(b"DDEML", ExportLookupTarget::Name(b"DdeInitialize")).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("DdeInitialize must use a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, 16);
    let return_to = (
        runtime.cpu.regs.cs,
        0x12_u16,
        u32::from(runtime.cpu.regs.sp()) + 20,
    );
    let callback = u32::from(runtime.cpu.regs.cs) << 16;
    let arguments = [0_u32, 0, callback, output(runtime)];
    let mut bytes = return_to.1.to_le_bytes().to_vec();
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    for value in arguments {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp())
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &bytes)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    return_to
}

fn dispatch(
    runtime: &mut Runtime,
    host: &mut InitializationHost,
) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

fn drive(runtime: &mut Runtime, host: &mut InitializationHost) -> Result<(), RuntimeError> {
    runtime
        .win16
        .as_mut()
        .unwrap()
        .drive_pending_window_completion(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            host,
        )
}

fn assert_caller(runtime: &Runtime, return_to: (u16, u16, u32)) {
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            u32::from(runtime.cpu.regs.sp())
        ),
        return_to
    );
    assert_eq!(runtime.cpu.regs.ax(), 0);
}

#[test]
fn initialize_dispatch_binds_direct_completion_and_releases_exact_owners() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let return_to = prepare_dispatch(&mut runtime);
    let mut host = InitializationHost::default();
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    let guest = read_instance(&runtime);
    assert_ne!(guest, 0);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.dde.host_instance(guest), Some(INSTANCE));
    assert!(state.window_operations.is_empty());
    assert!(state.legacy_cpu_frames.is_empty());
    assert_eq!(host.calls.len(), 1);
    assert!(matches!(host.calls[0], Win16HostDdeCall::Initialize {
        existing: None, callback_route, flags: 0, reserved: 0,
    } if callback_route != 0));
    assert_eq!(host.consumed, [host.proof.as_ref().clone()]);
    assert_caller(&runtime, return_to);
    assert_eq!(runtime.cpu.regs.dx(), 0x5aa5);
}

#[test]
fn initialize_source_ack_waits_for_projection_and_checked_caller_restore() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let saved = runtime.cpu.regs.clone();
    let mut host = InitializationHost {
        fail_source_readback_once: true,
        ..Default::default()
    };
    let pointer = output(&runtime);
    let return_to = begin(&mut runtime, &mut host, pointer).unwrap();
    let continuation = dde_continuation(&runtime);
    assert_eq!(continuation.host_operation(), Some(OPERATION));
    assert_eq!(
        continuation.host_owner_identity(),
        Some((OWNER, GENERATION))
    );
    assert_eq!(
        continuation.cached_native_completion(OPERATION),
        Some(&native_result())
    );
    let record = &continuation.normal_source_retirements()[0];
    assert!(Arc::ptr_eq(record.proof(), &host.proof));
    assert!(!record.consumed());
    assert_eq!(read_instance(&runtime), 0);
    assert_eq!(runtime.cpu.regs, saved);
    assert!(host.consumed.is_empty());
    assert_eq!(host.source_readbacks, 0);

    assert_eq!(
        drive(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::HostFailure
    );
    let guest = read_instance(&runtime);
    assert_ne!(guest, 0);
    assert_caller(&runtime, return_to);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.dde.host_instance(guest), Some(INSTANCE));
    let frame = state.window_operations.last().unwrap();
    let cpu_owner = frame.cpu_call_owner.unwrap();
    assert!(state.legacy_cpu_frame_is_top(cpu_owner));
    assert!(!frame.source_retirement_consumed);
    assert!(host.consumed.is_empty());
    assert_eq!(host.calls.len(), 1);
    assert_eq!(
        dde_continuation(&runtime).cached_native_completion(OPERATION),
        Some(&native_result())
    );

    drive(&mut runtime, &mut host).unwrap();
    drive(&mut runtime, &mut host).unwrap();
    assert_eq!(read_instance(&runtime), guest);
    assert_caller(&runtime, return_to);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.source_readbacks, 2);
    assert_eq!(host.consumed, [host.proof.as_ref().clone()]);
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.window_operations.is_empty());
    assert!(state.legacy_cpu_frames.is_empty());
}

#[test]
fn initialize_projection_failure_retains_proof_and_caller() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let pointer = output(&runtime);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(pointer).unwrap();
    let base = state
        .selectors
        .translate(pointer, Access::Read, 4, &runtime.memory)
        .unwrap();
    let alias = state
        .selectors
        .alloc_block(base, 4, AccessRights::read_write(), &runtime.memory)
        .unwrap();
    let saved = runtime.cpu.regs.clone();
    let mut host = InitializationHost::default();
    begin(
        &mut runtime,
        &mut host,
        SegmentedPointer::new(alias, 0).far_value(),
    )
    .unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.selectors.free_block(alias).unwrap();
    let replacement = state
        .selectors
        .alloc_block(base, 4, AccessRights::read_write(), &runtime.memory)
        .unwrap();
    assert_eq!(alias.raw(), replacement.raw());
    assert_ne!(alias.generation(), replacement.generation());
    assert_eq!(
        drive(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::GuestFault
    );
    assert_eq!(read_instance(&runtime), 0);
    assert_eq!(runtime.cpu.regs, saved);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.source_readbacks, 0);
    assert!(host.consumed.is_empty());
    assert_eq!(
        dde_continuation(&runtime).cached_native_completion(OPERATION),
        Some(&native_result())
    );
    assert!(!dde_continuation(&runtime).normal_source_retirements()[0].consumed());
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_operations.len(), 1);
    assert!(state.window_operations[0].cpu_call_owner.is_some());
    assert_eq!(state.legacy_cpu_frames.len(), 1);

    install_terminal_receipts(&mut runtime, shutdown_receipt(None));
    host.fail_terminal_source_once = true;
    assert_eq!(terminal_retire(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
    assert!(host.retired.is_empty());
    assert_eq!(host.source_readbacks, 0);
    host.fail_retirement_before_once = true;
    let error = terminal_retire(&mut runtime, &mut host).unwrap_err();
    assert_eq!(error.kind(), Kind::GuestFault, "projection failure remains the primary cause");
    assert!(host.retired.is_empty());
    assert_eq!(runtime.win16.as_ref().unwrap().window_operations.len(), 1);
    terminal_retire(&mut runtime, &mut host).unwrap();
    assert_eq!(read_instance(&runtime), 0, "terminal cleanup must not project again");
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.retired.len(), 1);
    assert!(host.consumed.is_empty());
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
    assert!(runtime.win16.as_ref().unwrap().legacy_cpu_frames.is_empty());
}

#[test]
fn initialize_raw_complete_cannot_bypass_exact_source_proof() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let return_to = prepare_dispatch(&mut runtime);
    let saved = runtime.cpu.regs.clone();
    let mut host = InitializationHost {
        begin_result: BeginResult::RawComplete,
        ..Default::default()
    };
    assert!(dispatch(&mut runtime, &mut host).is_err());
    drive(&mut runtime, &mut host).unwrap();
    assert_eq!(read_instance(&runtime), 0);
    assert_eq!(runtime.cpu.regs, saved);
    assert_ne!(runtime.cpu.regs.cs, return_to.0);
    assert_eq!(dde_continuation(&runtime).host_operation(), None);
    assert!(
        dde_continuation(&runtime)
            .normal_source_retirements()
            .is_empty()
    );
    assert_eq!(host.calls.len(), 1);
    assert!(host.consumed.is_empty());
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_operations.len(), 1);
    assert_eq!(state.legacy_cpu_frames.len(), 1);
}

#[test]
fn initialize_source_proof_cannot_replace_prebound_operation_owner_or_generation() {
    for proof in [
        Win16DdeSourceRetiredProof {
            operation: Win16HostDdeOperation(42),
            owner: OWNER,
            worker_generation: GENERATION,
        },
        Win16DdeSourceRetiredProof {
            operation: OPERATION,
            owner: Win16HostDdeOwner(8),
            worker_generation: GENERATION,
        },
        Win16DdeSourceRetiredProof {
            operation: OPERATION,
            owner: OWNER,
            worker_generation: GENERATION + 1,
        },
        Win16DdeSourceRetiredProof {
            operation: Win16HostDdeOperation(0),
            owner: OWNER,
            worker_generation: GENERATION,
        },
    ] {
        let mut runtime = fixture();
        write_instance(&mut runtime, 0);
        let mut host = InitializationHost {
            begin_result: BeginResult::RawComplete,
            ..Default::default()
        };
        let pointer = output(&runtime);
        assert!(begin(&mut runtime, &mut host, pointer).is_err());
        let saved = runtime.cpu.regs.clone();
        let state = runtime.win16.as_mut().unwrap();
        let Some(WindowReturn::Dde(continuation)) = state
            .window_operations
            .last_mut()
            .unwrap()
            .continuation_mut()
        else {
            panic!("missing retained DDE continuation");
        };
        continuation
            .bind_host_operation_identity(OPERATION, OWNER, GENERATION)
            .unwrap();
        assert!(
            state
                .advance_window_operation(
                    &mut runtime.cpu.regs,
                    &mut runtime.memory,
                    &mut host,
                    source_retired(Arc::new(proof))
                )
                .is_err()
        );
        assert_eq!(dde_continuation(&runtime).host_operation(), Some(OPERATION));
        assert_eq!(
            dde_continuation(&runtime).host_owner_identity(),
            Some((OWNER, GENERATION))
        );
        assert!(
            dde_continuation(&runtime)
                .normal_source_retirements()
                .is_empty()
        );
        assert_eq!(read_instance(&runtime), 0);
        assert_eq!(runtime.cpu.regs, saved);
        assert!(host.consumed.is_empty());
        assert_eq!(host.source_readbacks, 0);
        assert_eq!(runtime.win16.as_ref().unwrap().window_operations.len(), 1);
    }
}

fn shutdown_receipt(instance: Option<Win16HostDdeInstance>) -> Win16DdeAbortReceipt {
    let request_id = 19;
    Win16DdeAbortReceipt {
        owner: Some(OWNER),
        worker_generation: Some(GENERATION),
        request_id: Some(request_id),
        native_owner_receipt: Some(Win16DdeNativeOwnerShutdownReceipt {
            owner: OWNER,
            worker_generation: GENERATION,
            request_id,
            all_native_callbacks_returned: true,
            all_active_operations_returned: true,
            all_native_replies_released_or_transferred: true,
            all_native_transfer_guards_retired: true,
            all_native_instances_uninitialized: true,
            control_window_destroyed: true,
        }),
        owner_status: Win16DdeAbortOwnerStatus::Quiesced,
        worker_status: Win16DdeAbortWorkerStatus::Joined,
        cancelled_callbacks: Vec::new(),
        cancelled_operations: vec![Win16DdeOperationCancellation {
            operation: OPERATION,
            instance,
            status: Win16DdeOperationCancellationStatus::NativeCompleteReturned,
            failure: None,
        }],
        native_instances: vec![Win16DdeNativeInstanceReceipt {
            instance: INSTANCE,
            status: Win16DdeCleanupStatus::Released,
            failure: None,
        }],
        native_replies: Vec::new(),
        native_transfer_guards: Vec::new(),
        cleanup_failures: Vec::new(),
    }
}

#[test]
fn initialize_started_return_failure_retires_only_with_exact_shutdown_receipt() {
    started_return_failure_case(false);
}

#[test]
fn reinitialize_started_return_failure_preserves_existing_native_instance_owner() {
    started_return_failure_case(true);
}

fn started_return_failure_case(reinitializing: bool) {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    if reinitializing {
        let mut initial_host = InitializationHost {
            proof: Arc::new(Win16DdeSourceRetiredProof {
                operation: Win16HostDdeOperation(OPERATION.0 - 1),
                owner: OWNER,
                worker_generation: GENERATION,
            }),
            ..Default::default()
        };
        prepare_dispatch(&mut runtime);
        dispatch(&mut runtime, &mut initial_host).unwrap();
    }
    let original_guest = read_instance(&runtime);
    let existing = reinitializing.then_some(INSTANCE);
    prepare_dispatch(&mut runtime);
    let failure = Arc::new(Win16DdeOperationStartedFailure {
        operation: OPERATION,
        owner: OWNER,
        worker_generation: GENERATION,
        request_phase: Win16DdeOperationRequestPhase::NativeCompleteReturned,
        cause: Arc::new(RuntimeError::new(
            Kind::HostFailure,
            "test source retirement failure",
        )),
    });
    let mut host = InitializationHost {
        begin_result: BeginResult::StartedFailure(Arc::clone(&failure)),
        ..Default::default()
    };
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::HostFailure
    );
    assert_eq!(read_instance(&runtime), original_guest);
    assert_eq!(dde_continuation(&runtime).host_operation(), Some(OPERATION));
    assert_eq!(
        dde_continuation(&runtime).host_owner_identity(),
        Some((OWNER, GENERATION))
    );
    assert!(Arc::ptr_eq(
        dde_continuation(&runtime).started_failure().unwrap(),
        &failure
    ));
    let guest = dde_continuation(&runtime).guest_instance().unwrap();
    let candidate = dde_continuation(&runtime).callback_candidate.unwrap();
    assert_eq!(
        runtime.win16.as_ref().unwrap().dde.host_instance(guest),
        existing
    );
    assert!(
        matches!(host.calls[0], Win16HostDdeCall::Initialize { existing: actual, .. }
        if actual == existing)
    );
    let frame_id = runtime
        .win16
        .as_ref()
        .unwrap()
        .window_operations
        .last()
        .unwrap()
        .id;
    let receipt = shutdown_receipt(existing);
    assert!(receipt.is_quiesced());
    let ended = Win16TaskExecutionEnded::for_test();
    for mismatch in 0..6 {
        let mut foreign = receipt.clone();
        match mismatch {
            0 => foreign.cancelled_operations[0].operation = Win16HostDdeOperation(OPERATION.0 + 1),
            1 => {
                foreign.owner = Some(Win16HostDdeOwner(OWNER.0 + 1));
                foreign.native_owner_receipt.as_mut().unwrap().owner = foreign.owner.unwrap();
            }
            2 => {
                foreign.worker_generation = Some(GENERATION + 1);
                foreign
                    .native_owner_receipt
                    .as_mut()
                    .unwrap()
                    .worker_generation = GENERATION + 1;
            }
            3 => {
                foreign.cancelled_operations[0].instance =
                    if reinitializing { None } else { Some(INSTANCE) }
            }
            4 => {
                foreign.cancelled_operations[0].status =
                    Win16DdeOperationCancellationStatus::NativeCompleteError
            }
            5 => foreign.cancelled_operations[0].failure = Some(Arc::clone(&failure.cause)),
            _ => unreachable!(),
        }
        let state = runtime.win16.as_mut().unwrap();
        state.dde_abort_receipt = Some(foreign);
        assert!(
            state
                .retire_dde_window_operation_top(
                    &ended,
                    &mut runtime.cpu,
                    &mut runtime.dos,
                    &mut runtime.memory,
                    &mut host,
                    frame_id
                )
                .is_err()
        );
        assert!(host.retired.is_empty());
        assert_eq!(dde_continuation(&runtime).host_operation(), Some(OPERATION));
        assert_eq!(
            dde_continuation(&runtime).host_owner_identity(),
            Some((OWNER, GENERATION))
        );
        assert!(Arc::ptr_eq(
            dde_continuation(&runtime).started_failure().unwrap(),
            &failure
        ));
        assert_eq!(
            runtime
                .win16
                .as_ref()
                .unwrap()
                .window_operations
                .last()
                .unwrap()
                .id,
            frame_id
        );
    }

    let state = runtime.win16.as_mut().unwrap();
    state.dde_abort_receipt = Some(receipt.clone());
    assert!(state.close_dde(&mut runtime.memory, &mut host).is_err());
    assert_eq!(state.dde.instance_for_route(candidate.route), Some(guest));
    assert_eq!(
        state.dde.callback_for_route(candidate.route),
        Some(candidate.callback)
    );
    assert!(
        state
            .callback_scheduler
            .code_references()
            .contains(&candidate.callback)
    );
    assert!(host.retired.is_empty());
    assert_eq!(host.resources_retired, 0);

    state
        .retire_dde_window_operation_top(
            &ended,
            &mut runtime.cpu,
            &mut runtime.dos,
            &mut runtime.memory,
            &mut host,
            frame_id,
        )
        .unwrap();
    assert!(state.window_operations.is_empty());
    assert!(state.legacy_cpu_frames.is_empty());
    assert_eq!(host.retired.len(), 1);
    let proof = &host.retired[0];
    assert!(proof.matches_started_failure(&failure));
    assert!(proof.matches_receipt(&receipt));
    assert_eq!(proof.cancellation.instance, existing);
    assert_eq!(
        proof.cancellation.status,
        Win16DdeOperationCancellationStatus::NativeCompleteReturned
    );
    assert!(proof.cancellation.failure.is_none());
    assert_eq!(host.calls.len(), 1);
    assert!(host.consumed.is_empty());
    assert_eq!(read_instance(&runtime), original_guest);

    let state = runtime.win16.as_mut().unwrap();
    assert!(state.dde.has_callback_owners());
    assert_eq!(state.dde.instance_for_route(candidate.route), Some(guest));
    assert!(
        state
            .callback_scheduler
            .code_references()
            .contains(&candidate.callback)
    );
    state.close_dde(&mut runtime.memory, &mut host).unwrap();
    assert_eq!(host.resources_retired, 1);
    assert_eq!(host.retired.len(), 1);
    assert!(!state.dde.has_callback_owners());
    assert!(state.dde.guest_instances().is_empty());
    assert_eq!(state.dde.instance_for_route(candidate.route), None);
    assert_eq!(state.dde.callback_for_route(candidate.route), None);
    assert!(state.callback_scheduler.native_sources_quiescent());
    assert!(state.unregister_guest_callback(candidate.token).is_none());
    assert!(state.dde_retired_callback_tokens.is_empty());
    assert!(state.dde_retired_guest_blocks.is_empty());
    assert!(state.dde_callbacks.is_empty());
    assert!(state.dde_guest_contexts.is_empty());
    assert!(state.dde_context_restores.is_empty());
    assert_eq!(read_instance(&runtime), original_guest);
}

#[path = "win16_runtime_dde_terminal_tests.rs"]
mod terminal_tests;
use terminal_tests::{install_terminal_receipts, terminal_retire};

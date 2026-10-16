//! USER.222/223: SDK WINDOWS.H declares void WINAPI (BYTE FAR*).
//! Original USER wrappers pop four bytes; the shared body copies 128 words.
//! Native keyboard state is never touched: all host operations below are mocks.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16MessageCall, Win16MessageCallResult,
    Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState,
    Win16WindowOperation, Win16WindowResult,
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
    Access, AccessRights, ExportLookupTarget, SegmentedPointer, Win16ParameterType, ArgumentKind,
    Win16ExportStackCleanup, Win16ReturnKind, lookup_export,
};

const OFFSET: u16 = 0x110;
const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;

#[derive(Default)]
struct KeyboardHost {
    calls: usize,
    result: Option<Win16MessageCallResult>,
    snapshots: Vec<[u8; 256]>,
    replies: Vec<i32>,
    zero_arg_calls: Vec<u16>,
    park_wait: bool,
    wait_resumes: usize,
    dde_polls: usize,
    fail_begin: bool,
    consumed: usize,
    fail_readback_once: bool,
    fail_consume_once: bool,
}

fn proof() -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(41),
            kind: Win16NativeWindowOperationKind::MessageCall,
        },
        worker_generation: 7,
        state: Win16NativeWindowOperationState::Returned,
    })
}

impl DosHost for KeyboardHost {
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

impl RuntimeHost for KeyboardHost {
    fn win16_window_resume(&mut self, reply: Option<crate::Win16WindowReply>) -> Result<Win16WindowStep, RuntimeError> {
        assert!(self.park_wait && reply.is_none());
        self.wait_resumes += 1;
        assert_eq!(self.wait_resumes, 1, "resume the original wait exactly once");
        Ok(Win16WindowStep::SourceRetired { proof: proof(), result: Box::new(
            Win16WindowStep::Complete(Win16WindowResult::MessageCall(self.result.take().unwrap()))) })
    }
    fn win16_classic_dde_begin(&mut self, call: crate::Win16HostClassicDdeCall) -> Result<crate::Win16HostClassicDdeStep, RuntimeError> {
        let crate::Win16HostClassicDdeCall::PollOwner { owner } = call else { panic!("unexpected DDE operation") };
        self.dde_polls += 1;
        let operation = crate::Win16ClassicDdeOperationIdentity {
            owner, id: crate::Win16ClassicDdeOperationId(self.dde_polls as u64), worker_generation: 1,
        };
        Ok(crate::Win16HostClassicDdeStep::Started(operation))
    }
    fn win16_classic_dde_resume(&mut self, resume: crate::Win16HostClassicDdeResume) -> Result<crate::Win16HostClassicDdeStep, RuntimeError> {
        assert!(resume.reply.is_none());
        let operation = resume.operation;
        assert_eq!(operation.id, crate::Win16ClassicDdeOperationId(self.dde_polls as u64));
        Ok(crate::Win16HostClassicDdeStep::Complete { operation,
            result: crate::Win16HostClassicDdeResult::Event(None),
            source_retired: Arc::new(crate::Win16HostClassicDdeSourceRetiredProof { operation, callbacks: vec![] }),
        })
    }
    fn win16_classic_dde_source_retirement_consumed(&mut self, _proof: &crate::Win16HostClassicDdeSourceRetiredProof) -> Result<(), RuntimeError> { Ok(()) }
    fn win16_host_window_parent(&mut self, _window: crate::Win16HostWindow) -> Result<crate::Win16HostWindowParentObservation, RuntimeError> {
        panic!("these USER calls must not observe child ancestry")
    }

    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        match operation {
            Win16WindowOperation::MessageCall(Win16MessageCall::GetKeyboardState) => {}
            Win16WindowOperation::MessageCall(Win16MessageCall::SetKeyboardState { state }) => {
                self.snapshots.push(state);
            }
            Win16WindowOperation::MessageCall(Win16MessageCall::ReleaseCapture) => self.zero_arg_calls.push(19),
            Win16WindowOperation::MessageCall(Win16MessageCall::WaitMessage) => self.zero_arg_calls.push(112),
            Win16WindowOperation::MessageCall(Win16MessageCall::ReplyMessage { result }) => self.replies.push(result),
            _ => panic!("unexpected host operation"),
        }
        self.calls += 1;
        if self.fail_begin {
            return Err(RuntimeError::new(Kind::HostFailure, "mock native failure"));
        }
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(if self.park_wait {
                assert_eq!(self.zero_arg_calls, [112]);
                Win16WindowStep::PendingGuestWork { operation_id: proof.operation.operation_id, generation: 1 }
            } else { Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::MessageCall(
                    self.result.take().expect("mock result"),
                ))),
            } }),
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
impl crate::RuntimeDdeHost for KeyboardHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for KeyboardHost {}
impl crate::RuntimeMidiHost for KeyboardHost {}
impl crate::RuntimeNetbiosHost for KeyboardHost {}

fn fixture() -> Runtime {
    let mut image = tiny_ne_executable();
    image[0x8e..0x90].copy_from_slice(&0x400_u16.to_le_bytes());
    let mut runtime = Runtime::load(&image, &[], br"C:\KEYS.NE").unwrap();
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), OFFSET - 1).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &[0xa7; 258]).unwrap();
    runtime
}

fn far(runtime: &Runtime) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(OFFSET)
}

fn bytes(runtime: &Runtime) -> [u8; 258] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), OFFSET - 1).unwrap();
    let mut bytes = [0; 258];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn prepare(runtime: &mut Runtime, ordinal: u16, pointer: u32) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("Keyboard state requires a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, 4);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&pointer.to_le_bytes());
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

fn dispatch(runtime: &mut Runtime, host: &mut KeyboardHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16)) {
    // AX/DX preservation is Compat16's deterministic Void policy,
    // not a guarantee made by the historical Windows binaries.
    assert_eq!(runtime.cpu.regs.ax(), AX);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

fn resume(runtime: &mut Runtime, host: &mut KeyboardHost) -> Result<(), RuntimeError> {
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host,
    )
}

fn pattern() -> [u8; 256] { std::array::from_fn(|i| (i as u8).wrapping_mul(37)) }

fn getter(succeeded: bool) -> KeyboardHost {
    KeyboardHost { result: Some(Win16MessageCallResult::KeyboardState {
        succeeded, state: pattern(),
    }), ..Default::default() }
}

fn expected() -> [u8; 258] {
    let mut bytes = [0xa7; 258];
    bytes[1..257].copy_from_slice(&pattern());
    bytes
}

fn alias(runtime: &mut Runtime, size: u32, rights: AccessRights) -> win16_abi::SelectorRef {
    let original = far(runtime);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(original).unwrap();
    let base = state.selectors.translate(pointer, Access::Read, 256, &runtime.memory).unwrap();
    state.selectors.alloc_block(base, size, rights, &runtime.memory).unwrap()
}

#[test]
fn keyboard_state_name_ordinal_void_and_far_pointer_direction() {
    for (ordinal, name, direction) in [
        (222, b"GetKeyboardState".as_slice(), Win16ParameterType::FarOutputBuffer),
        (223, b"SetKeyboardState".as_slice(), Win16ParameterType::FarBuffer),
    ] {
        let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        let named = lookup_export(b"USER", ExportLookupTarget::Name(name)).unwrap();
        assert_eq!(descriptor.id, named.id);
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
        assert_eq!(descriptor.parameters.len(), 1);
        assert_eq!(descriptor.parameters[0].kind, ArgumentKind::Dword);
        assert_eq!(descriptor.parameters[0].parameter_type, direction);
        let mut runtime = fixture();
        let pointer = far(&runtime);
        prepare(&mut runtime, ordinal, pointer); // checks Pascal cleanup: four bytes
    }
}

#[test]
fn get_keyboard_state_success_and_false_preserve_void_and_exact_output_canaries() {
    for succeeded in [false, true] {
        let mut runtime = fixture();
        let pointer = far(&runtime);
        let return_to = prepare(&mut runtime, 222, pointer);
        let mut host = getter(succeeded);
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(bytes(&runtime), if succeeded { expected() } else { [0xa7; 258] });
        assert_eq!((host.calls, host.consumed), (1, 1));
        assert_return(&runtime, return_to);
    }
}

#[test]
fn keyboard_state_bad_null_short_and_read_only_output_never_reach_host() {
    for ordinal in [222, 223] {
        for size in [0, 255] {
            let mut runtime = fixture();
            // A zero-length selector is not allocatable; use a bad far pointer instead.
            let pointer = if size == 0 { 0 } else {
                SegmentedPointer::new(alias(&mut runtime, size, AccessRights::read_write()), 0).far_value()
            };
            prepare(&mut runtime, ordinal, pointer);
            let mut host = KeyboardHost::default();
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
            assert_eq!(host.calls, 0);
            assert_eq!(bytes(&runtime), [0xa7; 258]);
        }
        let mut runtime = fixture();
        prepare(&mut runtime, ordinal, u32::MAX);
        let mut host = KeyboardHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(host.calls, 0);
    }
    let mut runtime = fixture();
    let output = alias(&mut runtime, 256, AccessRights::read_only());
    prepare(&mut runtime, 222, SegmentedPointer::new(output, 0).far_value());
    let mut host = KeyboardHost::default();
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
    assert_eq!(host.calls, 0);
    assert_eq!(bytes(&runtime), [0xa7; 258]);
}

#[test]
fn get_keyboard_state_retained_success_rejects_stale_and_reused_output_selector() {
    for reuse in [false, true] {
        let mut runtime = fixture();
        let output = alias(&mut runtime, 256, AccessRights::read_write());
        prepare(&mut runtime, 222, SegmentedPointer::new(output, 0).far_value());
        let mut host = getter(true);
        host.fail_readback_once = true;
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
        runtime.win16.as_mut().unwrap().selectors.free_block(output).unwrap();
        if reuse {
            let replacement = alias(&mut runtime, 256, AccessRights::read_write());
            assert_eq!(output.raw(), replacement.raw());
            assert_ne!(output.generation(), replacement.generation());
        }
        assert_eq!(resume(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(bytes(&runtime), [0xa7; 258]);
        assert_eq!((host.calls, host.consumed), (1, 0));
        assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX, DX));
    }
}

#[test]
fn get_keyboard_state_false_does_not_revalidate_or_rewrite_retired_output() {
    let mut runtime = fixture();
    let output = alias(&mut runtime, 256, AccessRights::read_write());
    let return_to = prepare(&mut runtime, 222, SegmentedPointer::new(output, 0).far_value());
    let mut host = getter(false);
    host.fail_readback_once = true;
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    runtime.win16.as_mut().unwrap().selectors.free_block(output).unwrap();
    resume(&mut runtime, &mut host).unwrap();
    assert_eq!(bytes(&runtime), [0xa7; 258]);
    assert_eq!((host.calls, host.consumed), (1, 1));
    assert_return(&runtime, return_to);
}

#[test]
fn get_keyboard_state_deferred_result_and_output_commit_retry_never_replay() {
    for after_commit in [false, true] {
        let mut runtime = fixture();
        let pointer = far(&runtime);
        let return_to = prepare(&mut runtime, 222, pointer);
        let mut host = getter(true);
        host.fail_readback_once = !after_commit;
        host.fail_consume_once = after_commit;
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
        assert_eq!(bytes(&runtime), if after_commit { expected() } else { [0xa7; 258] });
        assert_eq!(host.consumed, 0);
        // A resumed getter must use its entry-captured output, never re-read
        // a changed far-pointer argument from the guest stack.
        let state = runtime.win16.as_ref().unwrap();
        let argument = state.selectors.pointer_from_raw(
            Selector(runtime.cpu.regs.ss), return_to.2 - 4,
        ).unwrap();
        state.selectors.write(&mut runtime.memory, argument, &u32::MAX.to_le_bytes()).unwrap();
        if after_commit {
            let state = runtime.win16.as_ref().unwrap();
            let output = state.selectors.pointer_from_far(pointer).unwrap();
            state.selectors.write(&mut runtime.memory, output, &[0x5c; 256]).unwrap();
        }
        resume(&mut runtime, &mut host).unwrap();
        let mut wanted = expected();
        if after_commit { wanted[1..257].fill(0x5c); }
        assert_eq!(bytes(&runtime), wanted);
        assert_eq!((host.calls, host.consumed), (1, 1));
        assert_return(&runtime, return_to);
    }
}

#[test]
fn set_keyboard_state_snapshots_exact_read_only_256_bytes_and_returns_void_without_replay() {
    for succeeded in [false, true] {
        for after_commit in [false, true] {
            let mut runtime = fixture();
            let pointer = far(&runtime);
            let state = runtime.win16.as_ref().unwrap();
            let output = state.selectors.pointer_from_far(pointer).unwrap();
            state.selectors.write(&mut runtime.memory, output, &pattern()).unwrap();
            let input = alias(&mut runtime, 256, AccessRights::read_only());
            let return_to = prepare(&mut runtime, 223, SegmentedPointer::new(input, 0).far_value());
            let mut host = KeyboardHost {
                result: Some(Win16MessageCallResult::Boolean(succeeded)),
                fail_readback_once: !after_commit, fail_consume_once: after_commit,
                ..Default::default()
            };
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
            assert_eq!(host.snapshots, vec![pattern()]);
            assert_eq!(bytes(&runtime), expected());
            runtime.win16.as_mut().unwrap().selectors.free_block(input).unwrap();
            let state = runtime.win16.as_ref().unwrap();
            state.selectors.write(&mut runtime.memory, output, &[0x5c; 256]).unwrap();
            resume(&mut runtime, &mut host).unwrap();
            assert_eq!(host.snapshots, vec![pattern()]);
            let mut wanted = expected();
            wanted[1..257].fill(0x5c);
            assert_eq!(bytes(&runtime), wanted);
            assert_eq!((host.calls, host.consumed), (1, 1));
            assert_return(&runtime, return_to);
        }
    }
}

#[test]
fn keyboard_state_host_errors_and_malformed_results_do_not_publish_success_or_output() {
    for ordinal in [222, 223] {
        for begin_error in [false, true] {
            let mut runtime = fixture();
            let pointer = far(&runtime);
            prepare(&mut runtime, ordinal, pointer);
            let mut host = KeyboardHost {
                result: Some(Win16MessageCallResult::Dword(0xdeadbeef)),
                fail_begin: begin_error, ..Default::default()
            };
            let error = dispatch(&mut runtime, &mut host).unwrap_err();
            assert_eq!(error.kind(), if begin_error { Kind::HostFailure } else { Kind::InternalInvariant });
            assert_eq!(bytes(&runtime), [0xa7; 258]);
            assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX, DX));
            assert_eq!((host.calls, host.consumed), (1, 0));
        }
    }
}

#[path = "win16_dispatch_message_void_tests.rs"]
mod message_void_tests;

#[path = "win16_reply_message_tests.rs"]
mod reply_message_tests;

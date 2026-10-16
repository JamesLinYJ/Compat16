//! USER.37 semantic void completion and exactly-once native text mutation.

use super::super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostWindow,
    Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState,
    Win16WindowOperation, Win16WindowResult, Win16WindowSourceRetiredProof, Win16WindowStep};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};
use guest_core::{GuestMemory, Selector};
use std::sync::Arc;
use win16_abi::{ExportLookupTarget, lookup_export};

const EAX: u32 = 0x1234_a55a;
const EDX: u32 = 0x5678_5aa5;
const WINDOW: Win16HostWindow = Win16HostWindow(0x1234_5678_9abc);

#[derive(Default)]
struct TextHost {
    calls: Vec<Option<Vec<u8>>>,
    title: Vec<u8>,
    result: bool,
    consumed: usize,
    fail_readback_once: bool,
    fail_consume_once: bool,
    fail_begin: bool,
    malformed_result: bool,
    callback_class: Option<crate::Win16HostClass>,
    callback_window: Option<Win16HostWindow>,
    replies: Vec<u32>,
}

fn proof() -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(41),
            kind: Win16NativeWindowOperationKind::SetWindowText,
        },
        worker_generation: 7,
        state: Win16NativeWindowOperationState::Returned,
    })
}

impl DosHost for TextHost {
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

impl RuntimeHost for TextHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::SetWindowText { window, text } = operation else {
            panic!("unexpected host operation");
        };
        assert_eq!(window, self.callback_window.unwrap_or(WINDOW));
        self.calls.push(text.clone());
        if self.fail_begin {
            return Err(RuntimeError::new(Kind::HostFailure, "test rejects native text begin"));
        }
        if self.result { self.title = text.unwrap_or_default(); }
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(if let Some(class) = self.callback_class {
                Win16WindowStep::Callback {
                    operation_id: proof.operation.operation_id,
                    callback: crate::Win16HostCallback(41), creation: None, creation_data: None,
                    window, class,
                    message: crate::Win16HostMessage::Scalar {
                        kind: crate::Win16ScalarMessage::Size, w_param: 1, l_param: 0,
                    },
                    source: crate::Win16NativeCallbackSource::WindowMessage {
                        window, class: Some(class), message: 0x0005,
                    },
                }
            } else { Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(if self.malformed_result {
                    Win16WindowResult::WindowTextLength(7)
                } else { Win16WindowResult::WindowTextSet(self.result) })),
            } }),
        })
    }
    fn win16_window_resume(&mut self, reply: Option<crate::Win16WindowReply>) -> Result<Win16WindowStep, RuntimeError> {
        let reply = reply.expect("resume the synchronous guest callback");
        assert_eq!(reply.callback, crate::Win16HostCallback(41));
        self.replies.push(reply.result.value);
        Ok(Win16WindowStep::SourceRetired {
            proof: proof(),
            result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowTextSet(self.result))),
        })
    }
    fn win16_window_source_retirement(
        &mut self, operation: Win16NativeWindowOperationProof, worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = proof();
        assert_eq!(operation, proof.operation);
        assert_eq!(worker_generation, proof.worker_generation);
        if std::mem::take(&mut self.fail_readback_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers text result readback"));
        }
        Ok(Some(proof))
    }
    fn win16_window_source_retirement_consumed(&mut self, actual: &Win16WindowSourceRetiredProof) -> Result<(), RuntimeError> {
        assert_eq!(actual, proof().as_ref());
        if std::mem::take(&mut self.fail_consume_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers text result consumption"));
        }
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for TextHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for TextHost {}
impl crate::RuntimeMidiHost for TextHost {}
impl crate::RuntimeNetbiosHost for TextHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TEXT.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.window_handles.insert(0x1234, WINDOW);
    state.owned_window_handles.insert(0x1234);
    runtime
}

fn prepare(runtime: &mut Runtime, window: u16, text: Option<&[u8]>) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(37)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let guard = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x1e).unwrap();
    state.selectors.write(&mut runtime.memory, guard, &[0x5a; 36]).unwrap();
    let far = if let Some(text) = text {
        let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x20).unwrap();
        let mut bytes = text.to_vec();
        bytes.push(0);
        state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
        pointer.far_value()
    } else { 0 };
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&far.to_le_bytes());
    bytes.extend_from_slice(&window.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let guard = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack - 2).unwrap();
    state.selectors.write(&mut runtime.memory, guard, &[0x69, 0x96]).unwrap();
    let guard = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack + 10).unwrap();
    state.selectors.write(&mut runtime.memory, guard, &[0x96, 0x69]).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = EAX;
    runtime.cpu.regs.edx = EDX;
    (return_cs, return_ip, stack + 10)
}

fn input_snapshot(runtime: &Runtime, stack: u16) -> (Vec<u8>, Vec<u8>) {
    let state = runtime.win16.as_ref().unwrap();
    let mut frame = vec![0; 14];
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack - 2).unwrap();
    state.selectors.read(&runtime.memory, pointer, &mut frame).unwrap();
    let mut text = vec![0; 36];
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x1e).unwrap();
    state.selectors.read(&runtime.memory, pointer, &mut text).unwrap();
    (frame, text)
}

fn dispatch(runtime: &mut Runtime, host: &mut TextHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0)
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16)) {
    // This is Compat16's deterministic void policy, not a claim about the
    // undefined register contents left by the original Windows binary.
    assert_eq!((runtime.cpu.regs.eax, runtime.cpu.regs.edx), (EAX, EDX));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

#[test]
fn set_window_text_success_failure_and_null_text_return_void() {
    for result in [false, true] {
        for text in [None, Some(b"changed".as_slice()), Some(b"".as_slice())] {
            let mut runtime = fixture();
            let return_to = prepare(&mut runtime, 0x1234, text);
            let input = input_snapshot(&runtime, return_to.2 - 10);
            let mut host = TextHost { result, title: b"original".to_vec(), ..Default::default() };
            dispatch(&mut runtime, &mut host).unwrap();
            assert_eq!(host.calls, [text.map(<[u8]>::to_vec)]);
            assert_eq!(host.title, if result { text.unwrap_or_default() } else { b"original" });
            assert_eq!(host.consumed, 1);
            assert_eq!(input_snapshot(&runtime, return_to.2 - 10), input);
            assert_return(&runtime, return_to);
        }
    }
}

#[test]
fn set_window_text_invalid_window_returns_void_without_native_mutation() {
    for window in [0, 0xdead] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, window, Some(b"changed"));
        let input = input_snapshot(&runtime, return_to.2 - 10);
        let mut host = TextHost { result: true, title: b"original".to_vec(), ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert!(host.calls.is_empty());
        assert_eq!(host.title, b"original");
        assert_eq!(host.consumed, 0);
        assert_eq!(input_snapshot(&runtime, return_to.2 - 10), input);
        assert_return(&runtime, return_to);
    }
}

#[test]
fn set_window_text_deferred_success_and_failure_retry_without_repeating_mutation() {
    for result in [false, true] {
        for consume in [false, true] {
            let mut runtime = fixture();
            let return_to = prepare(&mut runtime, 0x1234, Some(b"changed"));
            let input = input_snapshot(&runtime, return_to.2 - 10);
            let mut host = TextHost { result, title: b"original".to_vec(),
                fail_readback_once: !consume, fail_consume_once: consume, ..Default::default() };
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
            assert_eq!(host.calls.len(), 1);
            assert_eq!(host.consumed, 0);
            assert_eq!((runtime.cpu.regs.eax, runtime.cpu.regs.edx), (EAX, EDX));
            runtime.win16.as_mut().unwrap().drive_pending_window_completion(
                &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host).unwrap();
            assert_eq!(host.calls, [Some(b"changed".to_vec())]);
            assert_eq!(host.title, if result { b"changed".as_slice() } else { b"original" });
            assert_eq!(host.consumed, 1);
            assert_eq!(input_snapshot(&runtime, return_to.2 - 10), input);
            assert_return(&runtime, return_to);
        }
    }
}

#[test]
fn set_window_text_host_errors_and_wrong_result_shapes_do_not_publish_guest_success() {
    for malformed in [false, true] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, 0x1234, Some(b"changed"));
        let before = runtime.cpu.regs.clone();
        let input = input_snapshot(&runtime, return_to.2 - 10);
        let mut host = TextHost { title: b"original".to_vec(), fail_begin: !malformed,
            malformed_result: malformed, ..Default::default() };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(),
            if malformed { Kind::InternalInvariant } else { Kind::HostFailure });
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(input_snapshot(&runtime, return_to.2 - 10), input);
        assert_eq!(host.calls, [Some(b"changed".to_vec())]);
        assert_eq!(host.title, b"original");
        assert_eq!(host.consumed, 0);
        assert!(!runtime.win16.as_ref().unwrap().window_operations.is_empty());
    }
}

#[test]
fn set_window_text_synchronous_guest_callback_preserves_void_registers_and_exactly_once_mutation() {
    use guest_core::io::NoPorts;
    for reply in [0_u32, 1] {
        let mut runtime = fixture();
        let mut class_host = super::ClassDataHost::default();
        let class = super::named_class(&mut runtime, &mut class_host, b"SetWindowTextCallback", 0);
        let guest = super::window(&mut runtime, class, 71);
        let native = runtime.win16.as_ref().unwrap().window_handles[&guest];
        let return_to = prepare(&mut runtime, guest, Some(b"changed"));
        let mut host = TextHost { callback_class: Some(class.class), callback_window: Some(native), result: true, ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls, [Some(b"changed".to_vec())]);
        let state = runtime.win16.as_mut().unwrap();
        assert_eq!(state.window_callbacks.len(), 1);
        let frame = state.window_callbacks.last().unwrap();
        assert_eq!(frame.payload.message, 0x0005);
        assert_eq!(frame.payload.w_param, 1);
        assert_eq!(frame.payload.l_param, 0);
        assert_eq!(frame.native_source, Some(crate::Win16NativeCallbackSource::WindowMessage {
            window: native, class: Some(class.class), message: 0x0005,
        }));
        let code = (frame.callback_address & 0xffff_0000) | 0x60;
        let pointer = state.selectors.pointer_from_far(code).unwrap();
        let physical = state.selectors.translate(pointer, win16_abi::Access::Execute, 3,
            &runtime.memory).unwrap();
        runtime.memory.write(physical, &[0xca, 10, 0]).unwrap();
        runtime.cpu.regs.cs = (code >> 16) as u16;
        runtime.cpu.regs.set_ip(code as u16);
        runtime.cpu.regs.ss = frame.saved.ss;
        runtime.cpu.regs.set_sp(frame.saved.sp() - 14);
        runtime.cpu.regs.set_ax(reply as u16);
        runtime.cpu.regs.set_dx(0);
        let segments = crate::win16_loader::Win16Segments {
            selectors: &state.selectors, memory_len: runtime.memory.len(),
        };
        runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments).unwrap();
        state.record_window_callback_return(crate::win16_runtime::CallbackKind::Window,
            x86_cpu::ControlTransfer::FarReturn).unwrap();
        state.finish_window_callback(&mut runtime.cpu.regs, &mut runtime.memory, &mut host).unwrap();
        state.drive_pending_window_completion(&mut runtime.cpu, &mut runtime.memory,
            &mut runtime.dos, &mut host).unwrap();
        assert_eq!(host.replies, [reply]);
        assert_eq!(host.calls, [Some(b"changed".to_vec())]);
        assert_eq!(state.window_handles[&guest], native);
        assert!(state.window_callbacks.is_empty());
        assert_eq!(host.consumed, 1);
        assert_eq!(host.title, b"changed");
        // This generic synchronous callback exercises continuation ownership,
        // not WM_SETTEXT payload encoding. Neither callback LRESULT nor the
        // native BOOL becomes the Win16 void result.
        assert_return(&runtime, return_to);
    }
}

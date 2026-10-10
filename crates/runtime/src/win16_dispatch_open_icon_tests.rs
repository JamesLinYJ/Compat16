//! USER.44: SDK BOOL WINAPI OpenIcon(HWND), one WORD argument and WORD result.
//! Windows 3.1 SDK WINDOWS.H declares the prototype and WM_QUERYOPEN=0x0013;
//! LIBW.LIB IMPDEF at 0x615d independently binds OPENICON to USER ordinal 44.

use super::super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostWindow,
    Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState, Win16WindowCall,
    Win16WindowCallResult, Win16WindowOperation, Win16WindowResult,
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

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
const TARGET: Win16HostWindow = Win16HostWindow(0x1234_5678_9abc);
#[derive(Default)]
struct OpenIconHost {
    calls: Vec<Win16WindowTarget>,
    callback_class: Option<crate::Win16HostClass>,
    replies: Vec<u32>,
    result: bool,
    malformed_result: Option<Win16WindowCallResult>,
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

impl DosHost for OpenIconHost {
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

impl RuntimeHost for OpenIconHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::WindowCall(Win16WindowCall::OpenIcon { window }) = operation
            else { panic!("unexpected host operation"); };
        self.calls.push(window);
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(if let Some(class) = self.callback_class {
                let Win16WindowTarget::Mapped(window) = window else { panic!("callback needs mapped target"); };
                Win16WindowStep::Callback {
                    operation_id: proof.operation.operation_id,
                    callback: crate::Win16HostCallback(41), creation: None, creation_data: None,
                    window, class,
                    message: crate::Win16HostMessage::Scalar {
                        kind: crate::Win16ScalarMessage::QueryOpen, w_param: 0, l_param: 0,
                    },
                    source: crate::Win16NativeCallbackSource::WindowMessage {
                        window, class: Some(class), message: 0x0013,
                    },
                }
            } else { Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(
                    self.malformed_result.take().unwrap_or(Win16WindowCallResult::Boolean(self.result)),
                ))),
            } }),
        })
    }
    fn win16_window_resume(&mut self, reply: Option<crate::Win16WindowReply>) -> Result<Win16WindowStep, RuntimeError> {
        let reply = reply.expect("resume the pending WM_QUERYOPEN");
        assert_eq!(reply.callback, crate::Win16HostCallback(41));
        self.replies.push(reply.result.value);
        Ok(Win16WindowStep::SourceRetired {
            proof: proof(),
            result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(
                Win16WindowCallResult::Boolean(self.result),
            ))),
        })
    }
    fn win16_window_source_retirement(
        &mut self, operation: Win16NativeWindowOperationProof, worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = proof();
        assert_eq!(operation, proof.operation);
        assert_eq!(worker_generation, proof.worker_generation);
        if std::mem::take(&mut self.fail_readback_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers OpenIcon result readback"));
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
impl crate::RuntimeDdeHost for OpenIconHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for OpenIconHost {}
impl crate::RuntimeMidiHost for OpenIconHost {}
impl crate::RuntimeNetbiosHost for OpenIconHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\OPENICON.NE").unwrap();
    assert!(runtime.memory.len() >= 1024 * 1024);
    let state = runtime.win16.as_mut().unwrap();
    state.window_handles.insert(0x1234, TARGET);
    state.owned_window_handles.insert(0x1234);
    runtime
}

fn prepare(runtime: &mut Runtime, window: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(44)).unwrap();
    assert_eq!(descriptor.id, lookup_export(b"USER", ExportLookupTarget::Name(b"OpenIcon")).unwrap().id);
    let win16_abi::Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup
        else { panic!("OpenIcon must use fixed Pascal cleanup"); };
    assert_eq!(cleanup.callee_pop_bytes, 2);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    assert_eq!(descriptor.return_kind, win16_abi::Win16ReturnKind::Word);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    for word in [window] {
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

fn dispatch(runtime: &mut Runtime, host: &mut OpenIconHost) -> Result<Option<u8>, RuntimeError> {
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

#[test]
fn open_icon_preserves_word_abi_and_opaque_target_identity() {
    for result in [false, true] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, 0x1234);
        let mut host = OpenIconHost { result, ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls, [Win16WindowTarget::Mapped(TARGET)]);
        assert_eq!(host.consumed, 1);
        assert_return(&runtime, return_to, u16::from(result));
        assert_eq!(runtime.win16.as_ref().unwrap().window_handles[&0x1234], TARGET);
    }
}

#[test]
fn open_icon_distinguishes_null_unknown_and_retired_handles() {
    for (guest, expected) in [(0, Win16WindowTarget::Null),
        (0xdead, Win16WindowTarget::Invalid), (0x1234, Win16WindowTarget::Invalid)] {
        let mut runtime = fixture();
        runtime.win16.as_mut().unwrap().window_handles.remove(&0x1234);
        let return_to = prepare(&mut runtime, guest);
        let mut host = OpenIconHost::default();
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls, [expected]);
        assert_return(&runtime, return_to, 0);
    }
}

#[test]
fn open_icon_retries_completion_without_reopening_or_rebinding_window() {
    let mut runtime = fixture();
    let return_to = prepare(&mut runtime, 0x1234);
    let mut host = OpenIconHost { result: true, fail_readback_once: true, ..Default::default() };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(host.calls, [Win16WindowTarget::Mapped(TARGET)]);
    assert_eq!(host.consumed, 0);
    assert_eq!(runtime.cpu.regs.ax(), AX);
    // A guest handle remapped while completion is suspended must not retarget
    // or repeat the native call. The pending operation owns its original token.
    let replacement = Win16HostWindow(TARGET.0 + 1);
    runtime.win16.as_mut().unwrap().window_handles.insert(0x1234, replacement);
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
    ).unwrap();
    assert_eq!(host.calls, [Win16WindowTarget::Mapped(TARGET)]);
    assert_eq!(host.consumed, 1);
    assert_eq!(runtime.win16.as_ref().unwrap().window_handles[&0x1234], replacement);
    assert_return(&runtime, return_to, 1);
}

#[test]
fn query_open_is_a_pointer_free_scalar_message() {
    assert_eq!(crate::Win16ScalarMessage::from_raw(0x0013), Some(crate::Win16ScalarMessage::QueryOpen));
}

#[test]
fn open_icon_guest_query_callback_preserves_identity_and_reply() {
    use guest_core::io::NoPorts;
    for reply in [0_u32, 1] {
        let mut runtime = fixture();
        let mut class_host = super::ClassDataHost::default();
        let class = super::named_class(&mut runtime, &mut class_host, b"OpenIconQuery", 0);
        let guest = super::window(&mut runtime, class, 71);
        let native = runtime.win16.as_ref().unwrap().window_handles[&guest];
        let return_to = prepare(&mut runtime, guest);
        let mut host = OpenIconHost { callback_class: Some(class.class), result: true, ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls, [Win16WindowTarget::Mapped(native)]);
        let state = runtime.win16.as_mut().unwrap();
        assert_eq!(state.window_callbacks.len(), 1);
        let frame = state.window_callbacks.last().unwrap();
        assert_eq!(frame.payload.message, 0x0013);
        assert_eq!(frame.payload.w_param, 0);
        assert_eq!(frame.payload.l_param, 0);
        assert_eq!(frame.native_source, Some(crate::Win16NativeCallbackSource::WindowMessage {
            window: native, class: Some(class.class), message: 0x0013,
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
        assert_eq!(host.calls, [Win16WindowTarget::Mapped(native)]);
        assert_eq!(state.window_handles[&guest], native);
        assert!(state.window_callbacks.is_empty());
        assert_eq!(host.consumed, 1);
        // The native BOOL is independent of the WndProc LRESULT.
        assert_return(&runtime, return_to, 1);
    }
}

#[test]
fn open_icon_rejects_non_boolean_results_without_publishing_or_mapping() {
    for malformed in [
        Win16WindowCallResult::Integer(7),
        Win16WindowCallResult::Window(None),
        Win16WindowCallResult::Window(Some(Win16HostWindow(0xfedc_ba98_7654))),
        Win16WindowCallResult::Destroyed {
            succeeded: true,
            retirements: crate::Win16HostWindowRetirementBatch {
                receipts: vec![], invalidated_menus: vec![],
            },
        },
    ] {
        let mut runtime = fixture();
        prepare(&mut runtime, 0x1234);
        let before = runtime.cpu.regs.clone();
        let handles = runtime.win16.as_ref().unwrap().window_handles.clone();
        let owners = runtime.win16.as_ref().unwrap().owned_window_handles.clone();
        let mut host = OpenIconHost { malformed_result: Some(malformed), ..Default::default() };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::InternalInvariant);
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(host.calls, [Win16WindowTarget::Mapped(TARGET)]);
        assert_eq!(runtime.win16.as_ref().unwrap().window_handles, handles);
        assert_eq!(runtime.win16.as_ref().unwrap().owned_window_handles, owners);
    }
}

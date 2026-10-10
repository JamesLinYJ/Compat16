//! Existing GWW_HWNDPARENT setters must reconcile native ancestry before reentry.

use super::*;
use crate::{
    Win16HostCallback, Win16HostMessage, Win16HostWindowOperationId,
    Win16NativeCallbackSource, Win16NativeWindowOperationProof,
    Win16NativeWindowOperationState, Win16ScalarMessage, Win16WindowCall,
    Win16WindowCallResult, Win16WindowDataCall, Win16WindowDataResult,
    Win16WindowOperation, Win16WindowReply, Win16WindowResult,
    Win16WindowSourceRetiredProof, Win16WindowStep, Win16WindowTarget,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use guest_core::{GuestMemory, io::NoPorts};
use win16_abi::exports::window_data::GWW_HWNDPARENT;

struct ParentHost {
    class: Win16HostClass,
    child: Win16HostWindow,
    old_parent: Win16HostWindow,
    new_parent: Option<Win16HostWindow>,
    null_child_parent: Option<Win16HostWindow>,
    setter_callback_window: Option<Win16HostWindow>,
    fail_resume: Option<u64>,
    observed_parent: Option<Win16HostWindow>,
    query_count: usize,
    fail_query: Option<usize>,
    retired: bool,
    before_move_callback: bool,
    dialog_destroy: bool,
    parent_overrides: BTreeMap<Win16HostWindow, Option<Win16HostWindow>>,
    setters: BTreeSet<u64>,
    active: Vec<u64>,
    proofs: BTreeMap<u64, Arc<Win16WindowSourceRetiredProof>>,
    began: usize,
    resumed: usize,
}

impl ParentHost {
    fn callback(&self, operation: u64, window: Win16HostWindow,
        message: Win16ScalarMessage,
    ) -> Win16WindowStep {
        Win16WindowStep::Callback {
            operation_id: Win16HostWindowOperationId(operation),
            callback: Win16HostCallback(operation), creation: None, creation_data: None,
            window, class: self.class,
            message: Win16HostMessage::Scalar { kind: message, w_param: 0, l_param: 0 },
            source: Win16NativeCallbackSource::WindowMessage {
                window, class: Some(self.class), message: message as u32,
            },
        }
    }
}

impl DosHost for ParentHost {
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

impl RuntimeHost for ParentHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation)
        -> Result<Win16WindowStep, RuntimeError>
    {
        let kind = operation.native_operation_kind();
        self.began += 1;
        let id = self.began as u64;
        let callback = match operation {
            Win16WindowOperation::WindowCall(Win16WindowCall::WindowData(
                Win16WindowDataCall::SetParent { window, parent },
            )) => {
                assert_eq!(window, Win16WindowTarget::Mapped(self.child));
                self.new_parent = match parent {
                    Win16WindowTarget::Mapped(parent) => Some(parent),
                    Win16WindowTarget::Null => None,
                    Win16WindowTarget::Invalid => panic!("unexpected invalid parent"),
                };
                self.setters.insert(id);
                if !self.before_move_callback {
                    self.observed_parent = self.new_parent.or(self.null_child_parent);
                }
                self.callback(id, self.setter_callback_window.unwrap_or(self.child),
                    Win16ScalarMessage::Move)
            }
            Win16WindowOperation::WindowCall(Win16WindowCall::DestroyWindow { window }) => {
                assert_eq!(window, Win16WindowTarget::Mapped(self.old_parent));
                // Native destruction reaches only the old parent: the child
                // has already moved and therefore receives no WM_NCDESTROY.
                if self.dialog_destroy {
                    Win16WindowStep::DialogCallback {
                        operation_id: Win16HostWindowOperationId(id),
                        callback: Win16HostCallback(id), window: self.old_parent,
                        message: crate::Win16HostDialogMessage::Message(Win16HostMessage::Scalar {
                            kind: Win16ScalarMessage::NcDestroy, w_param: 0, l_param: 0,
                        }),
                        source: Win16NativeCallbackSource::WindowMessage {
                            window: self.old_parent, class: Some(self.class), message: 0x82,
                        },
                    }
                } else {
                    self.callback(id, self.old_parent, Win16ScalarMessage::NcDestroy)
                }
            }
            _ => panic!("unexpected parent lifecycle operation"),
        };
        self.proofs.insert(id, Arc::new(Win16WindowSourceRetiredProof {
            operation: Win16NativeWindowOperationProof {
                operation_id: Win16HostWindowOperationId(id), kind,
            }, worker_generation: 7, state: Win16NativeWindowOperationState::Returned,
        }));
        self.active.push(id);
        Ok(Win16WindowStep::Started {
            operation_id: Win16HostWindowOperationId(id), worker_generation: 7, kind,
            step: Box::new(callback),
        })
    }

    fn win16_window_resume(&mut self, reply: Option<Win16WindowReply>)
        -> Result<Win16WindowStep, RuntimeError>
    {
        let id = *self.active.last().unwrap();
        assert_eq!(reply.unwrap().callback, Win16HostCallback(id));
        self.resumed += 1;
        if self.fail_resume == Some(id) {
            return Err(RuntimeError::new(Kind::HostFailure, "test native callback resume failure"));
        }
        let result = if self.setters.contains(&id) {
            if self.before_move_callback {
                self.observed_parent = self.new_parent.or(self.null_child_parent);
            }
            Win16WindowResult::WindowCall(Win16WindowCallResult::WindowData(
                Win16WindowDataResult::Parent {
                    succeeded: true, previous: None, child_parent: self.observed_parent,
                },
            ))
        } else {
            Win16WindowResult::WindowCall(Win16WindowCallResult::Destroyed {
                succeeded: true,
                retirements: crate::Win16HostWindowRetirementBatch {
                    receipts: vec![crate::Win16HostWindowRetirementReceipt {
                        window: self.old_parent,
                    }],
                    invalidated_menus: vec![],
                },
            })
        };
        Ok(Win16WindowStep::SourceRetired {
            proof: Arc::clone(&self.proofs[&id]), result: Box::new(Win16WindowStep::Complete(result)),
        })
    }

    fn win16_host_window_parent(&mut self, window: Win16HostWindow)
        -> Result<crate::Win16HostWindowParentObservation, RuntimeError>
    {
        assert!(window == self.child || self.parent_overrides.contains_key(&window));
        self.query_count += 1;
        if self.fail_query == Some(self.query_count) {
            return Err(RuntimeError::new(Kind::HostFailure, "test exact parent query failure"));
        }
        if self.retired { return Ok(crate::Win16HostWindowParentObservation::Retired); }
        Ok(crate::Win16HostWindowParentObservation::Live {
            child_parent: self.parent_overrides.get(&window).copied().unwrap_or(self.observed_parent),
        })
    }

    fn win16_window_source_retirement(&mut self, operation: Win16NativeWindowOperationProof,
        worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = &self.proofs[&operation.operation_id.0];
        assert_eq!(proof.operation, operation);
        assert_eq!(proof.worker_generation, worker_generation);
        Ok(Some(Arc::clone(proof)))
    }

    fn win16_window_source_retirement_consumed(&mut self, proof: &Win16WindowSourceRetiredProof)
        -> Result<(), RuntimeError>
    {
        assert_eq!(self.active.pop(), Some(proof.operation.operation_id.0));
        assert_eq!(proof, self.proofs[&proof.operation.operation_id.0].as_ref());
        Ok(())
    }

    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for ParentHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for ParentHost {}
impl crate::RuntimeMidiHost for ParentHost {}
impl crate::RuntimeNetbiosHost for ParentHost {}

fn gate(runtime: &mut Runtime, host: &mut ParentHost, ordinal: u16, args: &[u8])
    -> (u16, u16, u16)
{
    try_gate(runtime, host, ordinal, args).unwrap()
}

fn try_gate(runtime: &mut Runtime, host: &mut ParentHost, ordinal: u16, args: &[u8])
    -> Result<(u16, u16, u16), RuntimeError>
{
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else { unreachable!() };
    assert_eq!(usize::from(cleanup.callee_pop_bytes), args.len());
    let return_to = (runtime.cpu.regs.cs, 0x12_u16, runtime.cpu.regs.sp() + args.len() as u16 + 4);
    let mut bytes = Vec::from(return_to.1.to_le_bytes());
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(args);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss),
        runtime.cpu.regs.sp()).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    state.dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0)?;
    Ok(return_to)
}

fn return_callback(runtime: &mut Runtime, host: &mut ParentHost) {
    let state = runtime.win16.as_mut().unwrap();
    let frame = state.window_callbacks.last().unwrap();
    let code = (frame.callback_address & 0xffff_0000) | 0x60;
    let pointer = state.selectors.pointer_from_far(code).unwrap();
    let physical = state.selectors.translate(pointer, win16_abi::Access::Execute, 3,
        &runtime.memory).unwrap();
    runtime.memory.write(physical, &[0xca, 10, 0]).unwrap();
    runtime.cpu.regs.cs = (code >> 16) as u16;
    runtime.cpu.regs.set_ip(code as u16);
    runtime.cpu.regs.ss = frame.saved.ss;
    runtime.cpu.regs.set_sp(frame.saved.sp() - 14);
    runtime.cpu.regs.set_ax(0);
    runtime.cpu.regs.set_dx(0);
    let segments = crate::win16_loader::Win16Segments {
        selectors: &state.selectors, memory_len: runtime.memory.len(),
    };
    runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments).unwrap();
    assert_eq!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::FarReturn));
    state.record_window_callback_return(crate::win16_runtime::CallbackKind::Window,
        x86_cpu::ControlTransfer::FarReturn).unwrap();
    state.finish_window_callback(&mut runtime.cpu.regs, &mut runtime.memory, host).unwrap();
}

fn project(runtime: &mut Runtime, host: &mut ParentHost, return_to: (u16, u16, u16)) {
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(&mut runtime.cpu,
        &mut runtime.memory, &mut runtime.dos, host).unwrap();
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
}

#[test]
fn parent_setter_callback_destruction_keeps_the_reparented_child_live() {
    for (desktop, callback_on_parent) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut runtime = fixture();
        let mut class_host = ClassDataHost::default();
        let class = named_class(&mut runtime, &mut class_host, b"ParentLifecycle", 0);
        let old_parent = window(&mut runtime, class, 1);
        let new_parent = window(&mut runtime, class, 2);
        let child = window(&mut runtime, class, 3);
        let descendant = window(&mut runtime, class, 4);
        let state = runtime.win16.as_mut().unwrap();
        state.link_window_parent(child, old_parent).unwrap();
        state.link_window_parent(descendant, child).unwrap();
        let native_descendant = state.window_handles[&descendant];
        let native_child = state.window_handles[&child];
        let mut host = ParentHost { class: class.class, child: native_child,
            old_parent: state.window_handles[&old_parent],
            new_parent: (!desktop).then_some(state.window_handles[&new_parent]),
            null_child_parent: Some(Win16HostWindow(0x1000)),
            setter_callback_window: callback_on_parent.then_some(state.window_handles[&old_parent]),
            fail_resume: None,
            observed_parent: Some(state.window_handles[&old_parent]),
            query_count: 0, fail_query: None, retired: false,
            before_move_callback: false, dialog_destroy: false, parent_overrides: BTreeMap::new(),
            setters: BTreeSet::new(),
            active: vec![], proofs: BTreeMap::new(), began: 0, resumed: 0 };
        let parent_arg = if desktop { 0_u16 } else { new_parent };
        let mut args = Vec::from(parent_arg.to_le_bytes());
        args.extend_from_slice(&GWW_HWNDPARENT.to_le_bytes());
        args.extend_from_slice(&child.to_le_bytes());
        let setter_return = gate(&mut runtime, &mut host, 134, &args);
        assert_eq!(runtime.win16.as_ref().unwrap().window_callbacks.len(), 1);
        let callback_stack = runtime.cpu.regs.sp();
        runtime.cpu.regs.set_sp(callback_stack - 6);
        let destroy_return = gate(&mut runtime, &mut host, 53, &old_parent.to_le_bytes());
        assert_eq!(runtime.win16.as_ref().unwrap().window_callbacks.len(), 2);
        return_callback(&mut runtime, &mut host);
        // Regression: outer SetParent is still suspended, but WM_NCDESTROY
        // cleanup must not retire its moved, live child using the old edge.
        assert_eq!(runtime.win16.as_ref().unwrap().window_handles.get(&child), Some(&native_child));
        project(&mut runtime, &mut host, destroy_return);
        assert_eq!(runtime.cpu.regs.ax(), 1);
        assert!(!runtime.win16.as_ref().unwrap().window_handles.contains_key(&old_parent));
        runtime.cpu.regs.set_sp(callback_stack);
        return_callback(&mut runtime, &mut host);
        project(&mut runtime, &mut host, setter_return);
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!(state.window_handles.get(&child), Some(&native_child));
        let expected_parent = if desktop {
            state.window_handles.iter().find_map(|(guest, native)|
                (Some(*native) == host.null_child_parent).then_some(*guest)).unwrap()
        } else { new_parent };
        assert_eq!(state.window_parents.get(&child), Some(&expected_parent));
        assert!(state.owned_window_handles.contains(&child));
        assert_eq!(state.window_handles.get(&descendant), Some(&native_descendant));
        assert!(state.owned_window_handles.contains(&descendant));
        for live in [child, descendant] {
            assert!(state.window_procedures.contains_key(&live));
            assert!(state.window_data.contains_key(&live));
        }
        assert!(state.window_operations.is_empty());
        assert_eq!((host.began, host.resumed), (2, 2));
        if !desktop {
            host.old_parent = state.window_handles[&new_parent];
            let destroy_new = gate(&mut runtime, &mut host, 53, &new_parent.to_le_bytes());
            return_callback(&mut runtime, &mut host);
            project(&mut runtime, &mut host, destroy_new);
            let state = runtime.win16.as_ref().unwrap();
            for retired in [new_parent, child, descendant] {
                assert!(!state.window_handles.contains_key(&retired));
                assert!(!state.window_procedures.contains_key(&retired));
                assert!(!state.window_data.contains_key(&retired));
                assert!(!state.owned_window_handles.contains(&retired));
            }
        }
    }
}

fn parent_fixture() -> (Runtime, ParentHost, u16, u16, u16) {
    let mut runtime = fixture();
    let mut class_host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut class_host, b"ParentObservation", 0);
    let old_parent = window(&mut runtime, class, 1);
    let new_parent = window(&mut runtime, class, 2);
    let child = window(&mut runtime, class, 3);
    let state = runtime.win16.as_mut().unwrap();
    state.link_window_parent(child, old_parent).unwrap();
    let host = ParentHost {
        class: class.class, child: state.window_handles[&child],
        old_parent: state.window_handles[&old_parent],
        new_parent: Some(state.window_handles[&new_parent]),
        null_child_parent: Some(Win16HostWindow(0x1000)),
        setter_callback_window: None, fail_resume: None,
        observed_parent: Some(state.window_handles[&old_parent]),
        query_count: 0, fail_query: None, retired: false,
        before_move_callback: false, dialog_destroy: false, parent_overrides: BTreeMap::new(),
        setters: BTreeSet::new(),
        active: vec![], proofs: BTreeMap::new(), began: 0, resumed: 0,
    };
    (runtime, host, old_parent, new_parent, child)
}

fn parent_args(child: u16, parent: u16) -> Vec<u8> {
    let mut args = Vec::from(parent.to_le_bytes());
    args.extend_from_slice(&GWW_HWNDPARENT.to_le_bytes());
    args.extend_from_slice(&child.to_le_bytes());
    args
}

#[test]
fn parent_setter_pre_move_callback_preserves_observed_old_ancestry() {
    let (mut runtime, mut host, old, new, child) = parent_fixture();
    host.before_move_callback = true;
    let return_to = gate(&mut runtime, &mut host, 134, &parent_args(child, new));
    assert_eq!(runtime.win16.as_ref().unwrap().window_parents.get(&child), Some(&old));
    assert_eq!(host.query_count, 1);
    return_callback(&mut runtime, &mut host);
    project(&mut runtime, &mut host, return_to);
    assert_eq!(runtime.win16.as_ref().unwrap().window_parents.get(&child), Some(&new));
}

#[test]
fn parent_setter_query_failure_retains_exact_callback_without_detaching_child() {
    let (mut runtime, mut host, old, new, child) = parent_fixture();
    host.fail_query = Some(1);
    let error = try_gate(&mut runtime, &mut host, 134, &parent_args(child, new)).unwrap_err();
    assert_eq!(error.kind(), Kind::HostFailure);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_parents.get(&child), Some(&old));
    assert!(state.window_parent_observations.is_empty());
    let frame = state.window_callbacks.last().unwrap();
    assert_eq!(frame.host_operation, Some(Win16HostWindowOperationId(1)));
    assert_eq!(frame.entry_phase,
        crate::win16_runtime::windows::WindowCallbackEntryPhase::SetupFailed);
    assert!(frame.setup_error.is_some());
    assert_eq!(runtime.cpu.regs.cs, state.gate_selector.0,
        "failed parent observation must not commit guest callback CS:IP");
    assert!(matches!(frame.continuation,
        crate::win16_runtime::windows::WindowCallbackContinuation::Host {
            callback: Win16HostCallback(1), native_window, ..
        } if native_window == host.child));
    assert!(state.window_operations.last().unwrap().terminal_error.is_some());
    assert_eq!((host.began, host.resumed), (1, 0));
}

#[test]
fn parent_setter_null_dialog_destruction_keeps_source_owned_until_default_reply() {
    for fail in [false, true] {
        let (mut runtime, mut host, old, new, child) = parent_fixture();
        let instance = runtime.win16.as_ref().unwrap().window_procedures[&old].instance;
        runtime.win16.as_mut().unwrap().dialog_procedures.insert(old, (0, instance));
        host.dialog_destroy = true;
        let setter_return = gate(&mut runtime, &mut host, 134, &parent_args(child, new));
        let callback_stack = runtime.cpu.regs.sp();
        // Refresh is needed for the outer setter even though DestroyWindow
        // is the current operation and the dialog has no guest procedure.
        host.fail_query = fail.then_some(2);
        runtime.cpu.regs.set_sp(callback_stack - 6);
        let outcome = try_gate(&mut runtime, &mut host, 53, &old.to_le_bytes());
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!(state.window_handles.get(&child), Some(&host.child));
        if fail {
            assert_eq!(outcome.unwrap_err().kind(), Kind::HostFailure);
            assert!(state.window_handles.contains_key(&old));
            assert_eq!(state.window_callbacks.len(), 2);
            let frame = state.window_callbacks.last().unwrap();
            assert_eq!(frame.callback_address, 0);
            assert_eq!(frame.host_operation, Some(Win16HostWindowOperationId(2)));
            assert_eq!(frame.entry_phase,
                crate::win16_runtime::windows::WindowCallbackEntryPhase::SetupFailed);
            assert!(frame.guest_return_value.is_none());
            assert_eq!(host.resumed, 0);
        } else {
            let destroy_return = outcome.unwrap();
            assert!(!state.window_handles.contains_key(&old));
            assert_eq!(state.window_callbacks.len(), 1);
            assert_eq!(state.window_operations.len(), 1);
            assert_eq!(host.resumed, 1);
            assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), destroy_return);
            runtime.cpu.regs.set_sp(callback_stack);
            return_callback(&mut runtime, &mut host);
            project(&mut runtime, &mut host, setter_return);
            assert!(runtime.win16.as_ref().unwrap().window_callbacks.is_empty());
        }
    }
}

#[test]
fn parent_setter_nested_same_child_observes_current_parent_once_per_callback() {
    let (mut runtime, mut host, _old, new, child) = parent_fixture();
    let third_native = Win16HostWindow(0xfedc_0000_0099);
    let third = runtime.win16.as_mut().unwrap().map_window_handle(third_native, false).unwrap();
    let outer_return = gate(&mut runtime, &mut host, 134, &parent_args(child, new));
    let callback_stack = runtime.cpu.regs.sp();
    runtime.cpu.regs.set_sp(callback_stack - 10);
    let inner_return = gate(&mut runtime, &mut host, 134, &parent_args(child, third));
    assert_eq!(host.query_count, 2, "deduplicate the two active setters for one incarnation");
    assert_eq!(runtime.win16.as_ref().unwrap().window_parents.get(&child), Some(&third));
    return_callback(&mut runtime, &mut host);
    project(&mut runtime, &mut host, inner_return);
    runtime.cpu.regs.set_sp(callback_stack);
    return_callback(&mut runtime, &mut host);
    project(&mut runtime, &mut host, outer_return);
    assert_eq!(runtime.win16.as_ref().unwrap().window_parents.get(&child), Some(&third));
    assert_eq!((host.began, host.resumed), (2, 2));
}

#[test]
fn parent_observation_retirement_and_reused_guest_identity_are_not_detachments() {
    let (mut runtime, mut host, old, new, child) = parent_fixture();
    host.retired = true;
    gate(&mut runtime, &mut host, 134, &parent_args(child, new));
    assert_eq!(runtime.win16.as_ref().unwrap().window_parents.get(&child), Some(&old));
    let state = runtime.win16.as_mut().unwrap();
    state.retire_window_handle(child).unwrap();
    state.next_window_handle = child;
    let replacement = Win16HostWindow(0xabcdef);
    assert_eq!(state.allocate_window_handle(replacement), Some(child));
    state.link_window_parent(child, old).unwrap();
    host.retired = false;
    state.refresh_pending_window_parents(&mut host).unwrap();
    assert_eq!(host.query_count, 1, "never query the setter through a reused guest HWND");
    assert_eq!(state.window_parents.get(&child), Some(&old));
    assert_eq!(state.window_handles.get(&child), Some(&replacement));
}

#[test]
fn parent_observations_batch_reversal_is_validated_before_committing_edges() {
    for invalid_cycle in [false, true] {
        let (mut runtime, mut host, old, new, child) = parent_fixture();
        gate(&mut runtime, &mut host, 134, &parent_args(child, new));
        let native_child = host.child;
        let native_old = host.old_parent;
        let stack = runtime.cpu.regs.sp();
        host.parent_overrides.insert(native_child, None);
        host.child = native_old;
        runtime.cpu.regs.set_sp(stack - 10);
        gate(&mut runtime, &mut host, 134, &parent_args(old, child));
        let state = runtime.win16.as_mut().unwrap();
        // Rebuild the stale snapshot present before both native observations.
        // Updating old->child before removing child->old would falsely cycle.
        state.window_parents.remove(&old);
        state.window_parents.insert(child, old);
        state.window_parent_observations.clear();
        if invalid_cycle { host.parent_overrides.insert(native_child, Some(native_old)); }
        let before = state.window_parents.clone();
        let result = state.refresh_pending_window_parents(&mut host);
        if invalid_cycle {
            assert_eq!(result.unwrap_err().kind(), Kind::InternalInvariant);
            assert_eq!(state.window_parents, before);
            assert!(state.window_parent_observations.is_empty());
        } else {
            result.unwrap();
            assert_eq!(state.window_parents.get(&old), Some(&child));
            assert!(!state.window_parents.contains_key(&child));
        }
    }
}

#[test]
fn parent_observation_failure_in_later_batch_leaves_every_prior_edge_intact() {
    let (mut runtime, mut host, old, new, child) = parent_fixture();
    gate(&mut runtime, &mut host, 134, &parent_args(child, new));
    let native_child = host.child;
    let native_old = host.old_parent;
    let stack = runtime.cpu.regs.sp();
    host.parent_overrides.insert(native_child, None);
    host.child = native_old;
    runtime.cpu.regs.set_sp(stack - 10);
    gate(&mut runtime, &mut host, 134, &parent_args(old, child));
    let state = runtime.win16.as_mut().unwrap();
    let before = state.window_parents.clone();
    let observations = state.window_parent_observations.clone();
    host.parent_overrides.insert(native_child, Some(state.window_handles[&new]));
    host.observed_parent = None;
    host.fail_query = Some(host.query_count + 2);
    assert_eq!(state.refresh_pending_window_parents(&mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(state.window_parents, before);
    assert_eq!(state.window_parent_observations, observations);
}

#[test]
fn parent_setter_null_dialog_resume_failure_keeps_cleaned_native_owner() {
    let (mut runtime, mut host, old, new, child) = parent_fixture();
    let instance = runtime.win16.as_ref().unwrap().window_procedures[&old].instance;
    runtime.win16.as_mut().unwrap().dialog_procedures.insert(old, (0, instance));
    host.dialog_destroy = true;
    host.fail_resume = Some(2);
    gate(&mut runtime, &mut host, 134, &parent_args(child, new));
    let callback_stack = runtime.cpu.regs.sp();
    runtime.cpu.regs.set_sp(callback_stack - 6);
    assert_eq!(try_gate(&mut runtime, &mut host, 53, &old.to_le_bytes()).unwrap_err().kind(),
        Kind::HostFailure);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_handles.get(&child), Some(&host.child));
    assert!(!state.window_handles.contains_key(&old));
    assert_eq!(state.window_callbacks.len(), 2);
    assert_eq!(state.window_operations.len(), 2);
    let frame = state.window_callbacks.last().unwrap();
    assert_eq!(frame.callback_address, 0);
    assert_eq!(frame.host_operation, Some(Win16HostWindowOperationId(2)));
    assert!(frame.payload_cleaned && frame.window_tree_retired);
    assert!(frame.native_resume_error.is_some());
    assert!(frame.guest_return_value.is_none());
    assert!(state.window_operations.last().unwrap().guest_return_transfer.is_none());
    assert_eq!(host.active, [1, 2]);
    assert_eq!(host.resumed, 1);
}

#[test]
fn parent_setter_under_mdi_client_does_not_change_immutable_window_claims() {
    let (mut runtime, mut host, _old, new, child) = parent_fixture();
    let state = runtime.win16.as_mut().unwrap();
    state.window_system_classes.insert(new, Win16HostSystemClass::MdiClient);
    let creations = state.window_creations.clone();
    let mdi = state.mdi_children.clone();
    let owners = state.owned_window_handles.clone();
    let return_to = gate(&mut runtime, &mut host, 134, &parent_args(child, new));
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_parents.get(&child), Some(&new));
    assert_eq!(state.window_creations, creations);
    assert_eq!(state.mdi_children, mdi);
    assert_eq!(state.owned_window_handles, owners);
    return_callback(&mut runtime, &mut host);
    project(&mut runtime, &mut host, return_to);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_creations, creations);
    assert_eq!(state.mdi_children, mdi);
    assert_eq!(state.owned_window_handles, owners);
}

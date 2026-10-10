//! Class WndProc replacement during ordinary and MDI creation callbacks.

use super::*;
use crate::win16_runtime::{
    messages::MessageOutput,
    messages_mdi::{MdiOutputPlan, WM_MDICREATE16, encode_mdi_create_wire},
    windows::{WindowCallbackContinuation, WindowClassRoot, WindowReturn},
};
use crate::{
    Win16CreationId, Win16HostCallback, Win16HostClassName, Win16HostCreationData,
    Win16HostMdiChildCreation, Win16HostMdiCreate, Win16HostMdiCreateFields,
    Win16HostMdiMessage, Win16HostMdiOutput, Win16HostMessage, Win16HostMessageOutput,
    Win16HostMessageResult, Win16HostWindowCreationResult, Win16HostWindowOperationId,
    Win16NativeCallbackSource, Win16NativeWindowApiReturn,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState, Win16WindowOperation,
    Win16WindowReply, Win16WindowResult, Win16WindowSourceRetiredProof, Win16WindowStep,
};
use std::{collections::VecDeque, sync::Arc};
use guest_core::{GuestMemory, io::NoPorts};
use win16_abi::exports::class_data::GCL_WNDPROC;

struct CreationHost {
    native: Win16HostWindow,
    pending: VecDeque<Win16WindowStep>,
    proof: Option<Arc<Win16WindowSourceRetiredProof>>,
    replies: Vec<Win16WindowReply>,
    return_to: Option<(u16, u16, u16)>,
    return_kind: Win16ReturnKind,
    consumed: usize,
    native_calls: Vec<(Win16HostProcedure, Win16HostWindow, Option<Win16HostCallback>, Win16HostMessage)>,
}

impl CreationHost {
    fn new(native: u64) -> Self {
        Self { native: Win16HostWindow(native), pending: VecDeque::new(),
            proof: None, replies: Vec::new(), return_to: None,
            return_kind: Win16ReturnKind::Word, consumed: 0, native_calls: Vec::new() }
    }

    fn callback(&self, creation: Win16CreationId, data: &Win16HostCreationData,
        mdi: Option<&Win16HostMdiCreate>, non_client: bool,
    ) -> Win16WindowStep {
        let message = if let Some(mdi) = mdi {
            Win16HostMessage::MdiChildCreation { non_client,
                data: Win16HostMdiChildCreation { creation: data.clone(), mdi: mdi.clone() } }
        } else {
            Win16HostMessage::Creation { non_client, data: data.clone() }
        };
        Win16WindowStep::Callback {
            operation_id: Win16HostWindowOperationId(self.native.0),
            callback: Win16HostCallback(if non_client { 1 } else { 2 }),
            creation: Some(creation), creation_data: Some(data.clone()),
            window: self.native, class: data.class, message,
            source: Win16NativeCallbackSource::WindowMessage {
                window: self.native, class: Some(data.class),
                message: if non_client { 0x81 } else { 1 },
            },
        }
    }
}

impl DosHost for CreationHost {
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

impl RuntimeHost for CreationHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation)
        -> Result<Win16WindowStep, RuntimeError>
    {
        assert!(self.pending.is_empty());
        let kind = operation.native_operation_kind();
        let operation = match operation {
            Win16WindowOperation::CallProcedure { procedure, window, callback, message } => {
                self.native_calls.push((procedure, window, callback, message));
                let proof = Arc::new(Win16WindowSourceRetiredProof {
                    operation: Win16NativeWindowOperationProof {
                        operation_id: Win16HostWindowOperationId(self.native.0), kind,
                    },
                    worker_generation: 7, state: Win16NativeWindowOperationState::Returned,
                });
                self.proof = Some(Arc::clone(&proof));
                return Ok(Win16WindowStep::Started {
                    operation_id: proof.operation.operation_id, worker_generation: 7, kind,
                    step: Box::new(Win16WindowStep::SourceRetired {
                        proof, result: Box::new(Win16WindowStep::Complete(
                            Win16WindowResult::Message(Some(Win16HostMessageResult {
                                dialog_result: None, value: 0x89ab_cdef,
                                output: Win16HostMessageOutput::None,
                            })),
                        )),
                    }),
                });
            }
            operation => operation,
        };
        let (creation, data, mdi) = match operation {
            Win16WindowOperation::Create { creation, data } => (creation, data, None),
            Win16WindowOperation::Send {
                window: client, message: Win16HostMessage::Mdi(Win16HostMdiMessage::Create(mdi)),
            } => {
                let data = Win16HostCreationData {
                    class: mdi.class, guest_instance: mdi.owner_instance,
                    guest_class_name: mdi.guest_class_name.clone(), guest_menu: 17,
                    class_menu_template: None, create_parameter: mdi.parameter,
                    creation_data: None, mdi_client: None, dialog_root: false, menu: None,
                    title: mdi.title.clone(), style: mdi.style | 0x4000_0000,
                    ex_style: 0x40, x: mdi.x, y: mdi.y, width: mdi.cx, height: mdi.cy,
                    parent: Some(client), child_id: Some(17),
                };
                (mdi.creation, data, Some(mdi))
            }
            _ => panic!("unexpected native creation operation"),
        };
        let proof = Arc::new(Win16WindowSourceRetiredProof {
            operation: Win16NativeWindowOperationProof {
                operation_id: Win16HostWindowOperationId(self.native.0), kind,
            },
            worker_generation: 7, state: Win16NativeWindowOperationState::Returned,
        });
        let result = if let Some(mdi) = &mdi {
            Win16WindowResult::Message(Some(Win16HostMessageResult {
                dialog_result: None, value: 0,
                output: Win16HostMessageOutput::Mdi(Win16HostMdiOutput::Created {
                    child: Some(self.native), fields: Win16HostMdiCreateFields {
                        x: mdi.x, y: mdi.y, cx: mdi.cx, cy: mdi.cy,
                        style: mdi.style, parameter: mdi.parameter,
                    },
                }),
            }))
        } else {
            Win16WindowResult::Created(Win16HostWindowCreationResult {
                native_api_return: Win16NativeWindowApiReturn::ReturnedWindow,
                preflight_rejection: None, live_window: Some(self.native),
            })
        };
        self.pending.push_back(self.callback(creation, &data, mdi.as_ref(), false));
        self.pending.push_back(Win16WindowStep::SourceRetired {
            proof: Arc::clone(&proof), result: Box::new(Win16WindowStep::Complete(result)),
        });
        self.proof = Some(proof);
        Ok(Win16WindowStep::Started {
            operation_id: Win16HostWindowOperationId(self.native.0), worker_generation: 7, kind,
            step: Box::new(self.callback(creation, &data, mdi.as_ref(), true)),
        })
    }

    fn win16_window_resume(&mut self, reply: Option<Win16WindowReply>)
        -> Result<Win16WindowStep, RuntimeError>
    {
        let reply = reply.expect("creation callbacks must return their exact reply");
        assert_eq!(reply.callback, Win16HostCallback(self.replies.len() as u64 + 1));
        self.replies.push(reply);
        Ok(self.pending.pop_front().expect("unexpected creation resume"))
    }

    fn win16_window_source_retirement(&mut self, operation: Win16NativeWindowOperationProof,
        worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = self.proof.as_ref().unwrap();
        assert_eq!(proof.operation, operation);
        assert_eq!(proof.worker_generation, worker_generation);
        Ok(Some(Arc::clone(proof)))
    }

    fn win16_window_source_retirement_consumed(&mut self, proof: &Win16WindowSourceRetiredProof)
        -> Result<(), RuntimeError>
    {
        assert_eq!(proof, self.proof.as_ref().unwrap().as_ref());
        self.consumed += 1;
        Ok(())
    }

    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for CreationHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for CreationHost {}
impl crate::RuntimeMidiHost for CreationHost {}
impl crate::RuntimeNetbiosHost for CreationHost {}

fn registered_class(runtime: &mut Runtime, host: &mut ClassDataHost) -> Registered {
    let info = class_info(runtime, 0);
    let atom = runtime.win16.as_mut().unwrap().register_class(info,
        Win16ClassName::Name(b"CreationProcedure".to_vec()), None, &runtime.memory, host).unwrap();
    assert_ne!(atom, 0);
    Registered { class: host.registrations.last().unwrap().1.class, atom, info }
}

fn prepare_gate(runtime: &mut Runtime, ordinal: u16, args: &[u8]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("creation tests require a fixed Pascal frame");
    };
    assert_eq!(usize::from(cleanup.callee_pop_bytes), args.len());
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_to = (runtime.cpu.regs.cs, 0x12_u16,
        runtime.cpu.regs.sp() + args.len() as u16 + 4);
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
    return_to
}

fn begin_creation(runtime: &mut Runtime, host: &mut CreationHost, class: Registered, mdi: bool) {
    let mut args = Vec::new();
    let ordinal = if mdi {
        let state = runtime.win16.as_mut().unwrap();
        let client_native = Win16HostWindow(host.native.0 + 0x1000);
        let client = state.allocate_window_handle(client_native).unwrap();
        state.window_system_classes.insert(client, Win16HostSystemClass::MdiClient);
        let data = Win16HostMdiCreate {
            creation: Win16CreationId(0), class: class.class,
            guest_class_name: Win16HostClassName::Atom(class.atom),
            owner_instance: class.info.h_instance, title: None,
            x: 2, y: 3, cx: 40, cy: 50, style: 0, parameter: 0x1234_5678,
        };
        let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x10).unwrap();
        state.selectors.write(&mut runtime.memory, pointer,
            &encode_mdi_create_wire(&data, u32::from(class.atom), 0)).unwrap();
        args.extend_from_slice(&pointer.far_value().to_le_bytes());
        args.extend_from_slice(&0_u16.to_le_bytes());
        args.extend_from_slice(&WM_MDICREATE16.to_le_bytes());
        args.extend_from_slice(&client.to_le_bytes());
        host.return_kind = Win16ReturnKind::Dword;
        111
    } else {
        args.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
        for value in [class.info.h_instance, 0, 0, 50, 40, 3, 2] {
            args.extend_from_slice(&value.to_le_bytes());
        }
        args.extend_from_slice(&0_u32.to_le_bytes());
        args.extend_from_slice(&0_u32.to_le_bytes());
        args.extend_from_slice(&u32::from(class.atom).to_le_bytes());
        41
    };
    host.return_to = Some(prepare_gate(runtime, ordinal, &args));
    assert_eq!(runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu,
        &mut runtime.memory, &mut runtime.dos, host, 0).unwrap(), None);
}

fn selected_window(runtime: &Runtime) -> u16 {
    match runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap().continuation {
        WindowCallbackContinuation::Host { window, .. } => window,
        _ => panic!("creation must be in its native WndProc callback"),
    }
}

fn retained_procedure(runtime: &Runtime) -> u32 {
    match runtime.win16.as_ref().unwrap().window_operations.last().unwrap().continuation().unwrap() {
        WindowReturn::Create { procedure, .. } => procedure.address,
        WindowReturn::Message { output: MessageOutput::Mdi(Some(MdiOutputPlan::Create(plan))) } =>
            plan.child_procedure,
        _ => panic!("creation lost its exact continuation"),
    }
}

fn return_creation_callback(runtime: &mut Runtime, host: &mut CreationHost, value: u32)
    -> Result<(), RuntimeError>
{
    let state = runtime.win16.as_mut().unwrap();
    let frame = state.window_callbacks.last().unwrap();
    // Execute a real RETF 10 through the checked Win16 segment resolver.
    // Keeping this tiny stub away from P and N also avoids overlapping them.
    let code = (frame.callback_address & 0xffff_0000) | 0x60;
    let pointer = state.selectors.pointer_from_far(code).unwrap();
    let physical = state.selectors.translate(pointer, win16_abi::Access::Execute, 3,
        &runtime.memory).unwrap();
    runtime.memory.write(physical, &[0xca, 10, 0]).unwrap();
    runtime.cpu.regs.cs = (code >> 16) as u16;
    runtime.cpu.regs.set_ip(code as u16);
    runtime.cpu.regs.ss = frame.saved.ss;
    runtime.cpu.regs.set_sp(frame.saved.sp() - 14);
    runtime.cpu.regs.set_ax(value as u16);
    runtime.cpu.regs.set_dx((value >> 16) as u16);
    let segments = crate::win16_loader::Win16Segments {
        selectors: &state.selectors, memory_len: runtime.memory.len(),
    };
    assert_eq!(runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts,
        &segments).unwrap(), x86_cpu::StepOutcome::Continue);
    assert_eq!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::FarReturn));
    state.record_window_callback_return(crate::win16_runtime::CallbackKind::Window,
        x86_cpu::ControlTransfer::FarReturn)?;
    state.finish_window_callback(&mut runtime.cpu.regs, &mut runtime.memory, host)
}

fn replace_during_callback(runtime: &mut Runtime, host: &mut ClassDataHost,
    class: Registered, selected: u16, replacement: u32,
) {
    let state = runtime.win16.as_ref().unwrap();
    let frame = state.window_callbacks.last().unwrap();
    let callback_id = frame.callback_id;
    let saved = (frame.saved.cs, frame.saved.ip(), frame.saved.sp());
    let stack = runtime.cpu.regs.sp();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    let mut callback_stack = [0; 14];
    state.selectors.read(&runtime.memory, pointer, &mut callback_stack).unwrap();
    // The nested Pascal API frame lives below the suspended WndProc frame.
    runtime.cpu.regs.set_sp(stack - 12);
    assert_eq!(call(runtime, host, 132, selected, GCL_WNDPROC, Some(replacement)),
        class.info.lpfn_wnd_proc);
    runtime.cpu.regs.set_sp(stack);
    let state = runtime.win16.as_ref().unwrap();
    let frame = state.window_callbacks.last().unwrap();
    assert_eq!(frame.callback_id, callback_id);
    assert_eq!(frame.callback_address, class.info.lpfn_wnd_proc);
    assert_eq!(frame.class_root, WindowClassRoot::Class(class.class));
    assert_eq!((frame.saved.cs, frame.saved.ip(), frame.saved.sp()), saved);
    let mut after = [0; 14];
    state.selectors.read(&runtime.memory, pointer, &mut after).unwrap();
    assert_eq!(after, callback_stack);
    assert_eq!(retained_procedure(runtime), class.info.lpfn_wnd_proc);
    assert_eq!(state.window_procedures[&selected].address, replacement);
    assert!(state.window_code_references().contains(&class.info.lpfn_wnd_proc));
    assert!(state.window_code_references().contains(&replacement));
}

fn project_creation(runtime: &mut Runtime, host: &mut CreationHost)
    -> Result<(u32, Win16ReturnKind), RuntimeError>
{
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(&mut runtime.cpu,
        &mut runtime.memory, &mut runtime.dos, host)?;
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        host.return_to.unwrap());
    assert_eq!(host.consumed, 1);
    let value = u32::from(runtime.cpu.regs.ax()) | if host.return_kind == Win16ReturnKind::Dword {
        u32::from(runtime.cpu.regs.dx()) << 16
    } else { 0 };
    Ok((value, host.return_kind))
}

#[test]
fn class_data_procedure_replacement_preserves_creation_snapshot_and_updates_later_callbacks() {
    for mdi in [false, true] {
        let mut runtime = fixture();
        let mut class_host = ClassDataHost::default();
        let class = registered_class(&mut runtime, &mut class_host);
        let sibling = window(&mut runtime, class, 1);
        let mut host = CreationHost::new(0x2000);
        begin_creation(&mut runtime, &mut host, class, mdi);
        let selected = selected_window(&runtime);
        let replacement = class.info.lpfn_wnd_proc + 2;
        assert_eq!(runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap()
            .payload.message, 0x81);
        replace_during_callback(&mut runtime, &mut class_host, class, selected, replacement);
        assert_eq!(runtime.win16.as_ref().unwrap().window_procedures[&sibling].address,
            class.info.lpfn_wnd_proc);

        // A reentrant creation captures N while the suspended outer plan
        // and its already-entered WM_NCCREATE callback still own P.
        let outer_stack = runtime.cpu.regs.sp();
        runtime.cpu.regs.set_sp(outer_stack - if mdi { 14 } else { 34 });
        let mut future_host = CreationHost::new(0x5000);
        begin_creation(&mut runtime, &mut future_host, class, mdi);
        let future = selected_window(&runtime);
        assert_ne!(future, selected);
        assert_eq!(retained_procedure(&runtime), replacement);
        let callbacks = &runtime.win16.as_ref().unwrap().window_callbacks;
        assert_eq!(callbacks.len(), 2);
        assert_eq!(callbacks[0].callback_address, class.info.lpfn_wnd_proc);
        assert_eq!(callbacks[0].class_root, WindowClassRoot::Class(class.class));
        assert_eq!(callbacks[1].callback_address, replacement);
        return_creation_callback(&mut runtime, &mut future_host, 1).unwrap();
        return_creation_callback(&mut runtime, &mut future_host, 0).unwrap();
        assert_eq!(project_creation(&mut runtime, &mut future_host).unwrap().0, u32::from(future));
        assert_eq!(runtime.cpu.regs.sp(), outer_stack);
        assert_eq!(selected_window(&runtime), selected);
        assert_eq!(retained_procedure(&runtime), class.info.lpfn_wnd_proc);
        assert_eq!(runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap()
            .callback_address, class.info.lpfn_wnd_proc);
        assert_eq!(runtime.win16.as_ref().unwrap().window_procedures[&future].address, replacement);

        return_creation_callback(&mut runtime, &mut host, 1).unwrap();
        assert_eq!(selected_window(&runtime), selected);
        let frame = runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap();
        assert_eq!(frame.payload.message, 1);
        assert_eq!(frame.callback_address, replacement);
        assert_eq!(frame.class_root, WindowClassRoot::Class(class.class));
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip()),
            ((replacement >> 16) as u16, replacement as u16));
        assert_eq!(retained_procedure(&runtime), class.info.lpfn_wnd_proc);
        return_creation_callback(&mut runtime, &mut host, 0).unwrap();
        assert!(runtime.win16.as_ref().unwrap().window_callbacks.is_empty());
        assert_eq!(retained_procedure(&runtime), class.info.lpfn_wnd_proc);
        assert_eq!(project_creation(&mut runtime, &mut host).unwrap(),
            (u32::from(selected), if mdi { Win16ReturnKind::Dword } else { Win16ReturnKind::Word }));
        assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
        assert_eq!(runtime.win16.as_ref().unwrap().window_procedures[&selected].address, replacement);
        assert_eq!(runtime.win16.as_ref().unwrap().window_procedures[&sibling].address,
            class.info.lpfn_wnd_proc);
        assert_eq!(host.replies.len(), 2);
        assert!(host.pending.is_empty());

    }
}

#[derive(Clone, Copy, Debug)]
enum MdiClaimMismatch {
    Class, ClassProvenance, Instance, Creation, Membership, Parent, SystemClass, MissingProcedure,
    NativeWindow, DuplicateAlias, ClientWindow, ClientSystemClass,
}

fn corrupt_mdi_claim(runtime: &mut Runtime, selected: u16, mismatch: MdiClaimMismatch) {
    let state = runtime.win16.as_mut().unwrap();
    let client = state.window_parents[&selected];
    match mismatch {
        MdiClaimMismatch::Class => state.window_procedures.get_mut(&selected).unwrap().class =
            Win16HostClass(0xdead_beef),
        MdiClaimMismatch::ClassProvenance => {
            state.window_data.remove(&selected);
            state.initialize_window_data(selected, Some(Win16HostClass(0xdead_beef)),
                state.window_procedures[&selected].instance, false, Some(6)).unwrap();
        }
        MdiClaimMismatch::Instance => state.window_procedures.get_mut(&selected).unwrap().instance ^= 1,
        MdiClaimMismatch::Creation => { state.window_creations.insert(selected, Win16CreationId(999)); }
        MdiClaimMismatch::Membership => { state.mdi_children.remove(&selected); }
        MdiClaimMismatch::Parent => { state.window_parents.remove(&selected); }
        MdiClaimMismatch::SystemClass => {
            state.window_system_classes.insert(selected, Win16HostSystemClass::MdiClient);
        }
        MdiClaimMismatch::MissingProcedure => { state.window_procedures.remove(&selected); }
        MdiClaimMismatch::NativeWindow => {
            state.window_handles.insert(selected, Win16HostWindow(0xdead_beef));
        }
        MdiClaimMismatch::DuplicateAlias => {
            state.window_handles.insert(0xff00, state.window_handles[&selected]);
        }
        MdiClaimMismatch::ClientWindow => {
            state.window_handles.insert(client, Win16HostWindow(0xdead_beef));
        }
        MdiClaimMismatch::ClientSystemClass => { state.window_system_classes.remove(&client); }
    }
}

#[test]
fn class_data_procedure_replacement_does_not_weaken_mdi_callback_or_completion_identity() {
    use MdiClaimMismatch::*;
    for completion in [false, true] {
        for mismatch in [Class, ClassProvenance, Instance, Creation, Membership, Parent, SystemClass,
            MissingProcedure, NativeWindow, DuplicateAlias, ClientWindow, ClientSystemClass]
        {
            let mut runtime = fixture();
            let mut class_host = ClassDataHost::default();
            let class = registered_class(&mut runtime, &mut class_host);
            let mut host = CreationHost::new(0x2000);
            begin_creation(&mut runtime, &mut host, class, true);
            let selected = selected_window(&runtime);
            replace_during_callback(&mut runtime, &mut class_host, class, selected,
                class.info.lpfn_wnd_proc + 2);
            if completion {
                return_creation_callback(&mut runtime, &mut host, 1).unwrap();
                return_creation_callback(&mut runtime, &mut host, 0).unwrap();
            }
            corrupt_mdi_claim(&mut runtime, selected, mismatch);
            let state = runtime.win16.as_ref().unwrap();
            let claims = (state.window_handles.clone(), state.window_creations.clone(),
                state.window_procedures.clone(), state.window_parents.clone(),
                state.mdi_children.clone(), state.window_system_classes.clone());
            let result = if completion {
                project_creation(&mut runtime, &mut host).map(|_| ())
            } else {
                return_creation_callback(&mut runtime, &mut host, 1)
            };
            assert!(result.is_err(), "accepted {mismatch:?} (completion={completion})");
            if completion {
                let state = runtime.win16.as_ref().unwrap();
                assert!((state.window_handles.clone(), state.window_creations.clone(),
                    state.window_procedures.clone(), state.window_parents.clone(),
                    state.mdi_children.clone(), state.window_system_classes.clone()) == claims,
                    "rejected completion changed {mismatch:?} ownership");
                assert_eq!(host.consumed, 0);
            } else if matches!(mismatch, ClientWindow | ClientSystemClass) {
                // callback_window preserves the child claim. The subsequent
                // CREATESTRUCT payload setup independently requires the live
                // MDIClient parent alias and rejects stale client provenance.
                let frame = runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap();
                assert!(frame.setup_error.is_some());
            }
        }
    }
}


#[test]
fn class_data_saved_native_procedure_gate_preserves_call_window_proc_and_forwarding() {
    for active in [false, true] {
        for low_bit_alias in [false, true] {
            let mut runtime = fixture();
            let mut class_host = ClassDataHost::default();
            let class = registered_class(&mut runtime, &mut class_host);
            let selected = window(&mut runtime, class, 1);
            let token = Win16HostProcedure(0xfedc_ba98_7654_3210);
            let gate = runtime.win16.as_mut().unwrap()
                .native_procedure_gate(token, &mut runtime.memory).unwrap();
            assert_ne!(gate, 0);
            assert_eq!(call(&mut runtime, &mut class_host, 132, selected, GCL_WNDPROC,
                Some(gate)), class.info.lpfn_wnd_proc);
            let replacement = class.info.lpfn_wnd_proc + 2;
            let saved = call(&mut runtime, &mut class_host, 132, selected, GCL_WNDPROC,
                Some(replacement));
            assert_eq!(saved, gate);
            let saved = if low_bit_alias { saved | 0x0003_0000 } else { saved };
            let mut creation_host = CreationHost::new(0x2000);
            let (window, message, w_param, l_param, callback) = if active {
                begin_creation(&mut runtime, &mut creation_host, class, false);
                let window = selected_window(&runtime);
                let frame = runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap();
                assert_eq!(frame.callback_address, replacement);
                (window, frame.payload.message, frame.payload.w_param, frame.payload.l_param,
                    Some(Win16HostCallback(1)))
            } else {
                (selected, 0x100, 7, 9, None)
            };
            let native = runtime.win16.as_ref().unwrap().window_handles[&window];
            let mut args = Vec::from(l_param.to_le_bytes());
            args.extend_from_slice(&w_param.to_le_bytes());
            args.extend_from_slice(&message.to_le_bytes());
            args.extend_from_slice(&window.to_le_bytes());
            args.extend_from_slice(&saved.to_le_bytes());
            let stack = runtime.cpu.regs.sp();
            runtime.cpu.regs.set_sp(stack - 18);
            let return_to = prepare_gate(&mut runtime, 122, &args);
            let mut host = CreationHost::new(0x7000);
            assert_eq!(runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu,
                &mut runtime.memory, &mut runtime.dos, &mut host, 0).unwrap(), None);
            assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
            assert_eq!(runtime.cpu.regs.sp(), stack);
            assert_eq!((runtime.cpu.regs.dx(), runtime.cpu.regs.ax()), (0x89ab, 0xcdef));
            assert_eq!(host.consumed, 1);
            assert_eq!(host.native_calls.len(), 1);
            let (actual_token, actual_window, actual_callback, actual_message) = &host.native_calls[0];
            assert_eq!((*actual_token, *actual_window, *actual_callback), (token, native, callback));
            if active {
                assert!(matches!(actual_message, Win16HostMessage::Creation { non_client: true, data }
                    if data.class == class.class));
                let frame = runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap();
                assert_eq!(frame.callback_address, replacement);
                assert_eq!(frame.class_root, WindowClassRoot::Class(class.class));
                return_creation_callback(&mut runtime, &mut creation_host, 1).unwrap();
                return_creation_callback(&mut runtime, &mut creation_host, 0).unwrap();
                assert_eq!(project_creation(&mut runtime, &mut creation_host).unwrap().0,
                    u32::from(window));
            } else {
                assert!(matches!(actual_message, Win16HostMessage::Scalar {
                    kind: crate::Win16ScalarMessage::KeyDown, w_param: 7, l_param: 9,
                }));
            }
            assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
        }
    }
}

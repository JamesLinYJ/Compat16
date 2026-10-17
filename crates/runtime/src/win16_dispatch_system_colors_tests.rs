//! Checked USER system setters through the real import gate and callback CPU.
use super::super::super::{ImportBinding, test_support::NoHost};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostCallback, Win16HostClass,
    Win16HostWindow, Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState, Win16WindowCall,
    Win16WindowCallResult, Win16WindowOperation, Win16WindowReply, Win16WindowResult,
    Win16WindowSourceRetiredProof, Win16WindowStep,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, Selector};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use win16_abi::{ExportLookupTarget, Win16Argument, Win16ReturnKind, lookup_export};

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
struct Active {
    operation: Win16NativeWindowOperationProof,
    current: Win16HostCallback,
    remaining: VecDeque<(Win16HostWindow, Win16HostClass)>,
}
#[derive(Default)]
struct SystemHost {
    colors: Vec<(Vec<i32>, Vec<u32>)>,
    notify: VecDeque<(Win16HostWindow, Win16HostClass)>,
    active: Vec<Active>,
    proofs: HashMap<u64, Arc<Win16WindowSourceRetiredProof>>,
    replies: Vec<Win16WindowReply>,
    consumed: Vec<u64>,
    next_callback: u64,
    result: bool,
    malformed: Option<Win16WindowCallResult>,
    fail_begin: bool,
    fail_readback_once: bool,
    swaps: Vec<bool>,
    swap_error: bool,
}
impl SystemHost {
    fn callback(
        &mut self,
        operation: Win16NativeWindowOperationProof,
        window: Win16HostWindow,
        class: Win16HostClass,
    ) -> (Win16HostCallback, Win16WindowStep) {
        self.next_callback += 1;
        let callback = Win16HostCallback(self.next_callback);
        (
            callback,
            Win16WindowStep::Callback {
                operation_id: operation.operation_id,
                callback,
                creation: None,
                creation_data: None,
                window,
                class,
                message: crate::Win16HostMessage::Scalar {
                    kind: crate::Win16ScalarMessage::SystemColorChange,
                    w_param: 0,
                    l_param: 0,
                },
                source: crate::Win16NativeCallbackSource::WindowMessage {
                    window,
                    class: Some(class),
                    message: 0x0015,
                },
            },
        )
    }
    fn complete(&mut self, operation: Win16NativeWindowOperationProof) -> Win16WindowStep {
        let proof = Arc::new(Win16WindowSourceRetiredProof {
            operation,
            worker_generation: 7,
            state: Win16NativeWindowOperationState::Returned,
        });
        self.proofs
            .insert(operation.operation_id.0, Arc::clone(&proof));
        Win16WindowStep::SourceRetired {
            proof,
            result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(
                self.malformed
                    .take()
                    .unwrap_or(Win16WindowCallResult::Boolean(self.result)),
            ))),
        }
    }
}
impl DosHost for SystemHost {
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

impl RuntimeHost for SystemHost {
    fn win16_window_begin(
        &mut self,
        operation: Win16WindowOperation,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::WindowCall(Win16WindowCall::SetSysColors { indices, colors }) =
            operation
        else {
            panic!("unexpected native operation")
        };
        self.colors.push((indices, colors));
        if self.fail_begin {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "system-color begin failed",
            ));
        }
        let operation = Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(self.colors.len() as u64),
            kind: Win16NativeWindowOperationKind::WindowCall,
        };
        let mut targets = std::mem::take(&mut self.notify);
        let step = if let Some((window, class)) = targets.pop_front() {
            let (current, step) = self.callback(operation, window, class);
            self.active.push(Active {
                operation,
                current,
                remaining: targets,
            });
            step
        } else {
            self.complete(operation)
        };
        Ok(Win16WindowStep::Started {
            operation_id: operation.operation_id,
            worker_generation: 7,
            kind: operation.kind,
            step: Box::new(step),
        })
    }
    fn win16_window_resume(
        &mut self,
        reply: Option<Win16WindowReply>,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let reply = reply.expect("complete the pending system-color callback");
        let mut active = self
            .active
            .pop()
            .expect("an active native system-color call");
        assert_eq!(reply.callback, active.current);
        self.replies.push(reply);
        if let Some((window, class)) = active.remaining.pop_front() {
            let (current, step) = self.callback(active.operation, window, class);
            active.current = current;
            self.active.push(active);
            Ok(step)
        } else {
            Ok(self.complete(active.operation))
        }
    }
    fn win16_window_source_retirement(
        &mut self,
        operation: Win16NativeWindowOperationProof,
        generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        assert_eq!(generation, 7);
        if std::mem::take(&mut self.fail_readback_once) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "system-color completion readback failed",
            ));
        }
        let proof = self.proofs.get(&operation.operation_id.0).cloned();
        if let Some(proof) = &proof {
            assert_eq!(proof.operation, operation);
        }
        Ok(proof)
    }
    fn win16_window_source_retirement_consumed(
        &mut self,
        proof: &Win16WindowSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        assert!(!self.consumed.contains(&proof.operation.operation_id.0));
        assert_eq!(
            self.proofs
                .get(&proof.operation.operation_id.0)
                .unwrap()
                .as_ref(),
            proof
        );
        self.consumed.push(proof.operation.operation_id.0);
        Ok(())
    }
    fn win16_swap_mouse_button(&mut self, swap: bool) -> Result<bool, RuntimeError> {
        self.swaps.push(swap);
        if self.swap_error {
            Err(RuntimeError::new(
                Kind::HostFailure,
                "mouse-button service failed",
            ))
        } else {
            Ok(self.result)
        }
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
impl crate::RuntimeDdeHost for SystemHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for SystemHost {}
impl crate::RuntimeMidiHost for SystemHost {}
impl crate::RuntimeNetbiosHost for SystemHost {}

fn write(runtime: &mut Runtime, far: u32, bytes: &[u8]) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, bytes)
        .unwrap();
}
fn arrays(runtime: &mut Runtime) -> (u32, u32) {
    let base = u32::from(runtime.cpu.regs.ds) << 16;
    write(
        runtime,
        base | 0x10,
        &[-1_i16, 7]
            .into_iter()
            .flat_map(i16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    write(
        runtime,
        base | 0x20,
        &[0x00ab_cdef_u32, 0xff01_0203]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    (base | 0x10, base | 0x20)
}
fn prepare(runtime: &mut Runtime, ordinal: u16, args: &[Win16Argument]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let (name, kind, argument_bytes) = match ordinal {
        181 => (b"SetSysColors".as_slice(), Win16ReturnKind::Void, 10),
        186 => (b"SwapMouseButton".as_slice(), Win16ReturnKind::Word, 2),
        _ => panic!("unexpected system export"),
    };
    assert_eq!(
        descriptor.id,
        lookup_export(b"USER", ExportLookupTarget::Name(name))
            .unwrap()
            .id
    );
    assert_eq!(descriptor.return_kind, kind);
    let win16_abi::Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("fixed Pascal frame")
    };
    assert_eq!(cleanup.callee_pop_bytes, argument_bytes);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let target = (
        runtime.cpu.regs.cs,
        0x12_u16,
        runtime.cpu.regs.sp() + 4 + argument_bytes,
    );
    let mut bytes = Vec::from(target.1.to_le_bytes());
    bytes.extend_from_slice(&target.0.to_le_bytes());
    for arg in args.iter().rev() {
        match arg {
            Win16Argument::Word(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            Win16Argument::Dword(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            _ => panic!("unexpected argument"),
        }
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
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    target
}
fn colors_call(runtime: &mut Runtime, count: u16, indices: u32, colors: u32) -> (u16, u16, u16) {
    prepare(
        runtime,
        181,
        &[
            Win16Argument::Word(count),
            Win16Argument::Dword(indices),
            Win16Argument::Dword(colors),
        ],
    )
}
fn dispatch(runtime: &mut Runtime, host: &mut SystemHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}
fn assert_void(runtime: &Runtime, target: (u16, u16, u16)) {
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX, DX));
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        target
    );
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.window_operations.is_empty());
    assert!(state.window_callbacks.is_empty());
}
fn return_callback(runtime: &mut Runtime, host: &mut SystemHost, reply: u32) {
    use guest_core::io::NoPorts;
    let state = runtime.win16.as_mut().unwrap();
    let frame = state.window_callbacks.last().unwrap();
    assert_eq!(frame.payload.message, 0x15);
    assert_eq!(frame.payload.w_param, 0);
    assert_eq!(frame.payload.l_param, 0);
    let code = (frame.callback_address & 0xffff_0000) | 0x60;
    let pointer = state.selectors.pointer_from_far(code).unwrap();
    let physical = state
        .selectors
        .translate(pointer, win16_abi::Access::Execute, 3, &runtime.memory)
        .unwrap();
    runtime.memory.write(physical, &[0xca, 10, 0]).unwrap();
    runtime.cpu.regs.cs = (code >> 16) as u16;
    runtime.cpu.regs.set_ip(code as u16);
    runtime.cpu.regs.ss = frame.saved.ss;
    runtime.cpu.regs.set_sp(frame.saved.sp() - 14);
    runtime.cpu.regs.set_ax(reply as u16);
    runtime.cpu.regs.set_dx((reply >> 16) as u16);
    let segments = crate::win16_loader::Win16Segments {
        selectors: &state.selectors,
        memory_len: runtime.memory.len(),
    };
    runtime
        .cpu
        .step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments)
        .unwrap();
    state
        .record_window_callback_return(
            crate::win16_runtime::CallbackKind::Window,
            x86_cpu::ControlTransfer::FarReturn,
        )
        .unwrap();
    state
        .finish_window_callback(&mut runtime.cpu.regs, &mut runtime.memory, host)
        .unwrap();
    state
        .drive_pending_window_completion(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            host,
        )
        .unwrap();
}

#[test]
fn set_sys_colors_copies_signed_indices_and_dwords_and_preserves_void_caller() {
    for result in [false, true] {
        let mut runtime = super::fixture();
        let (indices, colors) = arrays(&mut runtime);
        let target = colors_call(&mut runtime, 2, indices, colors);
        let mut host = SystemHost {
            result,
            ..Default::default()
        };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.colors, [(vec![-1, 7], vec![0x00ab_cdef, 0xff01_0203])]);
        assert_eq!(host.consumed, [1]);
        assert_void(&runtime, target);
    }
}
#[test]
fn set_sys_colors_zero_count_ignores_unmapped_far_pointers() {
    let mut runtime = super::fixture();
    let target = colors_call(&mut runtime, 0, 0, 0xdead_beef);
    let mut host = SystemHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(host.colors, [(vec![], vec![])]);
    assert_void(&runtime, target);
}
#[test]
fn set_sys_colors_invalid_inputs_never_start_a_partial_host_update() {
    for (count, which) in [(0xffff, 0), (1, 1), (1, 2), (2, 3), (2, 4)] {
        let mut runtime = super::fixture();
        let (mut indices, mut colors) = arrays(&mut runtime);
        match which {
            1 => indices = 0,
            2 => colors = 0xdead_beef,
            3 => indices |= 0xffff,
            4 => colors |= 0xffff,
            _ => {}
        }
        colors_call(&mut runtime, count, indices, colors);
        let before = runtime.cpu.regs.clone();
        let mut host = SystemHost::default();
        assert!(dispatch(&mut runtime, &mut host).is_err());
        assert!(host.colors.is_empty());
        assert_eq!(runtime.cpu.regs, before);
    }
}
#[test]
fn set_sys_colors_retries_retained_completion_without_reading_or_updating_again() {
    let mut runtime = super::fixture();
    let (indices, colors) = arrays(&mut runtime);
    let target = colors_call(&mut runtime, 2, indices, colors);
    let before = runtime.cpu.regs.clone();
    let mut host = SystemHost {
        fail_readback_once: true,
        result: true,
        ..Default::default()
    };
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::HostFailure
    );
    assert_eq!(runtime.cpu.regs, before);
    assert!(host.consumed.is_empty());
    write(&mut runtime, indices, &[0; 4]);
    write(&mut runtime, colors, &[0; 8]);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .drive_pending_window_completion(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
        )
        .unwrap();
    assert_eq!(host.colors, [(vec![-1, 7], vec![0x00ab_cdef, 0xff01_0203])]);
    assert_eq!(host.consumed, [1]);
    assert_void(&runtime, target);
}
#[test]
fn set_sys_colors_rejects_wrong_completion_types_without_mapping_handles() {
    for malformed in [
        Win16WindowCallResult::Integer(1),
        Win16WindowCallResult::Window(None),
        Win16WindowCallResult::Window(Some(Win16HostWindow(0xfeed_beef))),
    ] {
        let mut runtime = super::fixture();
        let (indices, colors) = arrays(&mut runtime);
        colors_call(&mut runtime, 2, indices, colors);
        let before = runtime.cpu.regs.clone();
        let handles = runtime.win16.as_ref().unwrap().window_handles.clone();
        let mut host = SystemHost {
            malformed: Some(malformed),
            ..Default::default()
        };
        assert_eq!(
            dispatch(&mut runtime, &mut host).unwrap_err().kind(),
            Kind::InternalInvariant
        );
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(runtime.win16.as_ref().unwrap().window_handles, handles);
        assert_eq!(host.colors.len(), 1);
    }
}
#[test]
fn set_sys_colors_broadcast_callbacks_allow_nested_update_and_restore_original_caller() {
    let mut runtime = super::fixture();
    let mut class_host = super::ClassDataHost::default();
    let class = super::named_class(
        &mut runtime,
        &mut class_host,
        b"SystemColorNotifications",
        0,
    );
    let guests = [
        super::window(&mut runtime, class, 71),
        super::window(&mut runtime, class, 72),
    ];
    let targets: Vec<_> = guests
        .into_iter()
        .map(|w| {
            (
                runtime.win16.as_ref().unwrap().window_handles[&w],
                class.class,
            )
        })
        .collect();
    let (indices, colors) = arrays(&mut runtime);
    let target = colors_call(&mut runtime, 2, indices, colors);
    let mut host = SystemHost {
        notify: targets.clone().into(),
        result: true,
        ..Default::default()
    };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.win16.as_ref().unwrap().window_callbacks.len(), 1);
    // A nested FAR Pascal call pushes a fresh frame below the WndProc frame.
    // Its return must not overwrite the outer callback's return gate/arguments.
    runtime.cpu.regs.set_sp(runtime.cpu.regs.sp() - 14);
    let nested = colors_call(&mut runtime, 0, 0xdead_beef, 0);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        nested
    );
    assert_eq!(runtime.win16.as_ref().unwrap().window_callbacks.len(), 1);
    write(&mut runtime, indices, &[0; 4]);
    write(&mut runtime, colors, &[0; 8]);
    for (index, (native, class)) in targets.iter().enumerate() {
        let state = runtime.win16.as_ref().unwrap();
        let frame = state.window_callbacks.last().unwrap();
        assert_eq!(
            frame.native_source,
            Some(crate::Win16NativeCallbackSource::WindowMessage {
                window: *native,
                class: Some(*class),
                message: 0x15
            })
        );
        return_callback(&mut runtime, &mut host, 0x8123_4500 + index as u32);
    }
    assert_eq!(
        host.colors,
        [
            (vec![-1, 7], vec![0x00ab_cdef, 0xff01_0203]),
            (vec![], vec![])
        ]
    );
    assert_eq!(
        host.replies
            .iter()
            .map(|r| r.result.value)
            .collect::<Vec<_>>(),
        [0x8123_4500, 0x8123_4501]
    );
    assert_eq!(host.consumed, [2, 1]);
    assert!(host.active.is_empty());
    assert_void(&runtime, target);
}
#[test]
fn swap_mouse_button_returns_previous_mapping_and_cleans_the_pascal_frame() {
    for input in [0, 1, 0xffff] {
        for result in [false, true] {
            let mut runtime = super::fixture();
            let target = prepare(&mut runtime, 186, &[Win16Argument::Word(input)]);
            let mut host = SystemHost {
                result,
                ..Default::default()
            };
            dispatch(&mut runtime, &mut host).unwrap();
            assert_eq!(host.swaps, [input != 0]);
            assert!(host.colors.is_empty());
            assert_eq!(
                (runtime.cpu.regs.ax(), runtime.cpu.regs.dx()),
                (u16::from(result), DX)
            );
            assert_eq!(
                (
                    runtime.cpu.regs.cs,
                    runtime.cpu.regs.ip(),
                    runtime.cpu.regs.sp()
                ),
                target
            );
        }
    }
}
#[test]
fn system_setter_host_failures_never_commit_a_guest_return() {
    for ordinal in [181, 186] {
        let mut runtime = super::fixture();
        if ordinal == 181 {
            colors_call(&mut runtime, 0, 0, 0);
        } else {
            prepare(&mut runtime, 186, &[Win16Argument::Word(1)]);
        }
        let before = runtime.cpu.regs.clone();
        let mut host = SystemHost {
            fail_begin: true,
            swap_error: true,
            ..Default::default()
        };
        assert_eq!(
            dispatch(&mut runtime, &mut host).unwrap_err().kind(),
            Kind::HostFailure
        );
        assert_eq!(runtime.cpu.regs, before);
    }
}
#[test]
fn system_setter_default_host_reports_missing_functionality() {
    for ordinal in [181, 186] {
        let mut runtime = super::fixture();
        if ordinal == 181 {
            colors_call(&mut runtime, 0, 0, 0);
        } else {
            prepare(&mut runtime, 186, &[Win16Argument::Word(1)]);
        }
        let before = runtime.cpu.regs.clone();
        let error = runtime
            .win16
            .as_mut()
            .unwrap()
            .dispatch(
                &mut runtime.cpu,
                &mut runtime.memory,
                &mut runtime.dos,
                &mut NoHost,
                0,
            )
            .unwrap_err();
        assert_eq!(error.kind(), Kind::CompatibilityGap);
        assert_eq!(runtime.cpu.regs, before);
    }
}

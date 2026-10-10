//! Win16 USER Set/Get/Remove/EnumProps and guest callback continuation.
//!
//! The Win16 contract is from the bundled SDK 3.1 `WINDOWS.H` and Programmer's
//! Reference: Vol. 1 §1.17 (Property Functions) and Vol. 2, printed pp. 281
//! (`EnumProps`) and 854 (`SetProp`). These specify global-atom property keys,
//! original atom-versus-string callback form, current-item removal, early
//! termination when another property is removed, and `-1` when no property is
//! enumerated. Host calls use Microsoft's SetPropA/GetPropA/RemovePropA/
//! EnumPropsA contract. Win16 `HANDLE` data remains an opaque WORD; the host
//! stores it in a private sidecar rather than exposing the native HANDLE.

use std::sync::Arc;

use dos_kernel::DosKernel;
use guest_core::{memory::Memory, OwnerId, Registers};
use win16_abi::{
    AllocationFlags, GlobalHandle, Win16Error, Win16ReturnKind,
    Win16WindowPropertyName, Win16WindowPropertyRequest,
};

use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use super::{windows::WindowReturn, CallbackKind, Win16State};
use x86_cpu::Cpu;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostCallback,
    Win16HostPropertyCallbackName, Win16HostPropertyName, Win16HostWindow,
    Win16WindowCall, Win16WindowOperation, Win16WindowReply,
    Win16WindowTarget,
};

// Private callback storage must not join a guest task's GlobalFreeAll owner.
const PROPERTY_CALLBACK_OWNER: OwnerId = OwnerId(u32::MAX);
const MAX_PROPERTY_NAME_BYTES: usize = 255;

#[derive(Clone, Copy)]
pub(super) enum WindowPropertyReturn {
    Set,
    Get,
    Remove,
    Enum { procedure: u32, guest_window: u16 },
}

pub(super) struct WindowPropertyCallbackFrame {
    pub(super) callback_id: super::CallbackFrameId,
    callback: Win16HostCallback,
    procedure: u32,
    guest_window: u16,
    data: u16,
    name_argument: u32,
    entry_pending: bool,
    saved: Registers,
    active_call: Option<Win16FarCallbackFrame>,
    allocation: Option<GlobalHandle>,
    allocation_locked: bool,
    pub(super) host_operation: crate::Win16HostWindowOperationId,
    native_source: crate::Win16NativeCallbackSource,
    entry_error: Option<Arc<RuntimeError>>,
    guest_return: Option<u32>,
    return_error: Option<Arc<RuntimeError>>,
    native_resume_error: Option<Arc<RuntimeError>>,
    resumed_step: Option<crate::Win16WindowStep>,
}

impl Win16State {
    pub(super) fn terminal_window_property_callback_identity(
        &self,
        callback_id: super::CallbackFrameId,
    ) -> Option<(
        crate::Win16HostCallback,
        crate::Win16HostWindowOperationId,
        crate::Win16NativeCallbackSource,
    )> {
        let frame = self.window_property_callbacks.last()
            .filter(|frame| frame.callback_id == callback_id)?;
        Some((frame.callback, frame.host_operation, frame.native_source))
    }

    pub(super) fn begin_window_properties(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16WindowPropertyRequest,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        use Win16WindowPropertyRequest as Request;
        match request {
            Request::Set { window, name, data } => {
                let Some(name) = host_name(name) else {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                };
                self.begin_property_call(registers, memory, host,
                    Win16WindowCall::SetWindowProperty {
                        window: self.property_window_target(window), name, data,
                    }, WindowPropertyReturn::Set, return_to)
            }
            Request::Get { window, name } => {
                let Some(name) = host_name(name) else {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                };
                self.begin_property_call(registers, memory, host,
                    Win16WindowCall::GetWindowProperty {
                        window: self.property_window_target(window), name,
                    }, WindowPropertyReturn::Get, return_to)
            }
            Request::Remove { window, name } => {
                let Some(name) = host_name(name) else {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                };
                self.begin_property_call(registers, memory, host,
                    Win16WindowCall::RemoveWindowProperty {
                        window: self.property_window_target(window), name,
                    }, WindowPropertyReturn::Remove, return_to)
            }
            Request::Enum { window, callback } => {
                self.begin_property_call(registers, memory, host,
                    Win16WindowCall::EnumWindowProperties {
                        window: self.property_window_target(window),
                    }, WindowPropertyReturn::Enum {
                        procedure: callback,
                        guest_window: window,
                    }, return_to)
            }
        }
    }

    fn begin_property_call(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        call: Win16WindowCall,
        result: WindowPropertyReturn,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::WindowCall(call),
            WindowReturn::WindowProperties(result),
            return_to,
        )
    }

    fn property_window_target(&self, guest: u16) -> Win16WindowTarget {
        if guest == 0 {
            Win16WindowTarget::Null
        } else {
            self.window_handles.get(&guest).copied()
                .map(Win16WindowTarget::Mapped)
                .unwrap_or(Win16WindowTarget::Invalid)
        }
    }

    pub(super) fn retain_window_property_callback(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        callback: Win16HostCallback,
        native_window: Win16HostWindow,
        name: Win16HostPropertyCallbackName,
        data: u16,
        host_operation: crate::Win16HostWindowOperationId,
        native_source: crate::Win16NativeCallbackSource,
    ) -> Result<(), RuntimeError> {
        let (procedure, guest_window) = self.pending_window_property_enum().ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "Win16 property callback has no pending EnumProps operation")
        })?;
        if self.window_handles.get(&guest_window) != Some(&native_window) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 property callback window identity changed during enumeration"));
        }

        self.window_property_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "retain exact Win16 EnumProps callback owner", error)
        })?;
        let callback_id = self.reserve_callback_frame_id()?;
        let saved = registers.clone();
        self.push_callback_kind(CallbackKind::WindowProperty, callback_id)?;
        self.window_property_callbacks.push(WindowPropertyCallbackFrame {
            callback_id,
            callback,
            procedure,
            guest_window,
            data,
            name_argument: 0,
            entry_pending: true,
            saved,
            active_call: None,
            allocation: None,
            allocation_locked: false,
            host_operation,
            native_source,
            entry_error: None,
            guest_return: None,
            return_error: None,
            native_resume_error: None,
            resumed_step: None,
        });

        let setup = (|| {
            self.refresh_pending_window_parents(host)?;
            let name_argument = match name {
                Win16HostPropertyCallbackName::Atom(atom) => u32::from(atom),
                Win16HostPropertyCallbackName::String(bytes) => {
                    self.allocate_property_name(callback_id, memory, &bytes)?
                }
            };
            let frame = self.window_property_callbacks.last_mut().ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant,
                    "Win16 EnumProps callback owner disappeared during native retention")
            })?;
            if frame.callback_id != callback_id || frame.active_call.is_some()
                || !frame.entry_pending
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 EnumProps retention changed its exact callback owner"));
            }
            frame.name_argument = name_argument;
            Ok(())
        })();
        if let Err(error) = setup {
            return Err(self.fail_window_property_callback_entry(callback_id, error));
        }
        Ok(())
    }

    /// Enter only at a real full-CPU safe point. The native property frame,
    /// callback ID, copied name and source identity remain installed if setup
    /// fails, so terminal cleanup can retire the exact owner later.
    pub(in crate::win16_runtime) fn service_pending_window_property_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let Some((callback_id, procedure, guest_window, data, name_argument, entry_pending,
            active, failure, guest_return)) = self.window_property_callbacks.last().map(|frame| (
                frame.callback_id,
                frame.procedure,
                frame.guest_window,
                frame.data,
                frame.name_argument,
                frame.entry_pending,
                frame.active_call.is_some(),
                frame.entry_error.as_ref().map(Arc::clone),
                frame.guest_return,
            )) else { return Ok(false); };
        if let Some(error) = failure {
            return Err(super::callback_lifo::shared_runtime_error(error)
                .with_context("Win16 EnumProps entry setup remains owned by its exact frame"));
        }
        if !entry_pending || active || guest_return.is_some() {
            return Ok(false);
        }
        if self.require_callback_top(CallbackKind::WindowProperty)? != callback_id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "pending EnumProps entry is not the exact shared callback top"));
        }

        let entered = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            procedure,
            &[
                Win16FarCallbackArgument::Word(guest_window),
                Win16FarCallbackArgument::Dword(name_argument),
                Win16FarCallbackArgument::Word(data),
            ],
            // PROPENUMPROC is FAR PASCAL: HWND, LPSTR and HANDLE occupy eight
            // stack bytes, and AX returns the original INT16.
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        );
        match entered {
            Ok(active_call) => {
                let frame = self.window_property_callbacks.last_mut().filter(|frame|
                    frame.callback_id == callback_id && frame.active_call.is_none()
                        && frame.entry_pending).ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "EnumProps callback owner changed during checked CPU entry",
                ))?;
                frame.active_call = Some(active_call);
                frame.entry_pending = false;
                Ok(true)
            }
            Err(error) => Err(self.fail_window_property_callback_entry(callback_id, error)),
        }
    }

    fn fail_window_property_callback_entry(
        &mut self,
        callback_id: super::CallbackFrameId,
        error: RuntimeError,
    ) -> RuntimeError {
        let frame = self.window_property_callbacks.last_mut()
            .expect("EnumProps callback owner retained after setup failure");
        debug_assert_eq!(frame.callback_id, callback_id);
        let kind = error.kind();
        let error = Arc::new(error);
        if frame.entry_error.is_none() {
            frame.entry_error = Some(Arc::clone(&error));
        }
        RuntimeError::with_source(kind, "Win16 EnumProps callback setup failed", error)
    }

    pub(in crate::win16_runtime) fn finish_window_property_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::WindowProperty)?;
        let (callback, cached_value, prior_error) = {
            let frame = self.window_property_callbacks.last().ok_or_else(|| RuntimeError::new(
                Kind::GuestFault, "Win16 callback gate has no active EnumProps callback"))?;
            if frame.callback_id != callback_id {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 property callback differs from the exact shared LIFO identity"));
            }
            let error = frame.entry_error.as_ref()
                .or(frame.return_error.as_ref())
                .or(frame.native_resume_error.as_ref())
                .map(Arc::clone);
            (frame.callback, frame.guest_return, error)
        };
        if let Some(error) = prior_error {
            return Err(super::callback_lifo::shared_runtime_error(error)
                .with_context("Win16 EnumProps callback remains on its exact owner"));
        }

        let value = if let Some(value) = cached_value {
            value
        } else {
            let mut active_call = self.window_property_callbacks.last_mut()
                .and_then(|frame| frame.active_call.take()).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "entered EnumProps callback has no retained FAR call frame",
            ))?;
            match self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active_call) {
                Ok(value) => {
                    let frame = self.window_property_callbacks.last_mut()
                        .expect("EnumProps callback frame checked");
                    frame.guest_return = Some(value);
                    frame.active_call = Some(active_call);
                    value
                }
                Err(error) => {
                    let kind = error.kind();
                    let error = Arc::new(error);
                    let frame = self.window_property_callbacks.last_mut()
                        .expect("EnumProps callback frame checked");
                    if frame.return_error.is_none() {
                        frame.return_error = Some(Arc::clone(&error));
                    }
                    frame.active_call = Some(active_call);
                    return Err(RuntimeError::with_source(
                        kind,
                        "Win16 EnumProps guest return failed validation",
                        error,
                    ));
                }
            }
        };

        // Keep the callback frame and shared ID live across any failed free;
        // release_property_name_for_frame records a completed unlock so retry
        // resumes at the exact remaining cleanup step.
        self.release_property_name_for_frame()?;
        let resumed_step = self.window_property_callbacks.last()
            .expect("EnumProps callback frame retained after cleanup")
            .resumed_step.is_some();
        if !resumed_step {
            let step = match host.win16_window_resume(Some(Win16WindowReply {
                callback,
                result: crate::Win16HostMessageResult {
                    dialog_result: None,
                    value,
                    output: crate::Win16HostMessageOutput::None,
                },
            })) {
                Ok(step) => step,
                Err(error) => {
                    let kind = error.kind();
                    let error = Arc::new(error);
                    let frame = self.window_property_callbacks.last_mut()
                        .expect("EnumProps callback frame retained after native resume failure");
                    if frame.native_resume_error.is_none() {
                        frame.native_resume_error = Some(Arc::clone(&error));
                    }
                    return Err(RuntimeError::with_source(
                        kind,
                        "Win16 EnumProps native resume remains on its exact callback owner",
                        error,
                    ));
                }
            };
            self.window_property_callbacks.last_mut()
                .expect("EnumProps callback frame retained after native resume")
                .resumed_step = Some(step);
        }

        let mut active_call = self.window_property_callbacks.last_mut()
            .and_then(|frame| frame.active_call.take()).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "EnumProps native acknowledgement has no retained FAR owner",
            ))?;
        if let Err(error) = self.release_guest_far_callback_owner(&mut active_call, dos, memory) {
            self.window_property_callbacks.last_mut()
                .expect("EnumProps callback frame retained after owner-release failure")
                .active_call = Some(active_call);
            return Err(error);
        }
        self.window_property_callbacks.last_mut()
            .expect("EnumProps callback frame retained after owner release")
            .active_call = Some(active_call);

        self.retire_callback_binding(CallbackKind::WindowProperty, callback_id)?;
        let mut frame = self.window_property_callbacks.pop()
            .expect("EnumProps callback frame checked before LIFO retirement");
        debug_assert_eq!(frame.callback_id, callback_id);
        let step = frame.resumed_step.take()
            .expect("successful native resume step retained before callback retirement");
        self.advance_window_operation(&mut cpu.regs, memory, host, step)
    }

    pub(in crate::win16_runtime) fn cancel_window_property_callback_for_teardown(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if self.window_teardown_state != super::WindowTeardownState::NativeQuiescent {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 property callback cancellation preceded USER quiescence"));
        }
        let callback_id = self.require_callback_top(CallbackKind::WindowProperty)?;
        if self.window_property_callbacks.last()
            .is_none_or(|frame| frame.callback_id != callback_id)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 property callback is not the exact shared LIFO owner"));
        }
        let (callback, operation, source) = self
            .terminal_window_property_callback_identity(callback_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 property callback identity disappeared before terminal cleanup"))?;
        self.validate_terminal_callback_source(callback, operation, source)?;
        let cancellation = crate::Win16NativeCallbackCancellation {
            callback,
            operation_id: operation,
            source,
        };
        let owner = self.prepare_terminal_callback_retirement(callback_id, cancellation)?;
        if let Some(mut active_call) = self.window_property_callbacks.last_mut()
            .and_then(|frame| frame.active_call.take())
        {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                CallbackKind::WindowProperty,
                callback_id,
                cpu,
                dos,
                memory,
                &mut active_call,
            ) {
                self.window_property_callbacks.last_mut()
                    .expect("EnumProps frame retained after terminal CPU abort failure")
                    .active_call = Some(active_call);
                let error = Arc::new(error);
                self.retain_callback_terminal_error(owner, Arc::clone(&error))?;
                return Err(super::callback_lifo::shared_runtime_error(error)
                    .with_context("Win16 EnumProps terminal CPU frame remains owned"));
            }
            self.window_property_callbacks.last_mut()
                .expect("EnumProps frame retained after terminal CPU abort")
                .active_call = Some(active_call);
        }
        if let Err(error) = self.release_property_name_for_frame() {
            let error = Arc::new(error);
            self.retain_callback_terminal_error(owner, Arc::clone(&error))?;
            return Err(super::callback_lifo::shared_runtime_error(error)
                .with_context("Win16 property name cleanup remains owned by its callback"));
        }
        self.set_terminal_callback_phase(
            owner,
            callback_id,
            cancellation,
            |proof| proof.guest_payload_cleaned = true,
        )?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::WindowProperty, callback_id) {
            let error = Arc::new(error);
            self.retain_callback_terminal_error(owner, Arc::clone(&error))?;
            return Err(super::callback_lifo::shared_runtime_error(error)
                .with_context("Win16 property callback LIFO retirement remains pending"));
        }
        let frame = self.window_property_callbacks.pop()
            .expect("EnumProps callback owner checked before LIFO retirement");
        debug_assert_eq!(frame.callback_id, callback_id);
        self.set_terminal_callback_phase(
            owner,
            callback_id,
            cancellation,
            |proof| proof.runtime_frame_retired = true,
        )
    }

    fn release_property_name_for_frame(&mut self) -> Result<(), RuntimeError> {
        let (allocation, locked) = {
            let frame = self.window_property_callbacks.last().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 property callback frame disappeared during cleanup"))?;
            (frame.allocation, frame.allocation_locked)
        };
        let Some(allocation) = allocation else { return Ok(()); };
        if locked {
            self.heap.unlock(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
            self.window_property_callbacks.last_mut().expect("frame checked").allocation_locked = false;
        }
        self.heap.free(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
        self.window_property_callbacks.last_mut().expect("frame checked").allocation = None;
        Ok(())
    }

    fn allocate_property_name(
        &mut self,
        callback_id: super::CallbackFrameId,
        memory: &mut Memory,
        bytes: &[u8],
    ) -> Result<u32, RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_PROPERTY_NAME_BYTES || bytes.contains(&0) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 EnumProps supplied an invalid string property name"));
        }
        let length = bytes.len() + 1;
        let allocation = self.heap.alloc(
            memory,
            PROPERTY_CALLBACK_OWNER,
            u32::try_from(length).map_err(|_| RuntimeError::new(
                Kind::ResourceExhausted, "Win16 property callback name is too long"))?,
            AllocationFlags::fixed().with_zero_init(),
        ).map_err(|error| match error {
            Win16Error::OutOfMemory | Win16Error::HandleTableFull => RuntimeError::new(
                Kind::ResourceExhausted, "Win16 heap cannot allocate an EnumProps name"),
            other => crate::runtime_error(other),
        })?;
        let frame = self.window_property_callbacks.last_mut().ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "EnumProps name allocation has no retained callback owner")
        })?;
        if frame.callback_id != callback_id || frame.allocation.is_some() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "EnumProps name allocation changed its exact callback owner"));
        }
        frame.allocation = Some(allocation);
        let pointer = match self.heap.lock(allocation, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(error) => return Err(crate::runtime_error(error)),
        };
        self.window_property_callbacks.last_mut()
            .expect("EnumProps callback owner retained").allocation_locked = true;
        let mut data = bytes.to_vec();
        data.push(0);
        if let Err(error) = self.selectors.write(memory, pointer, &data) {
            return Err(crate::runtime_error(error));
        }
        Ok(pointer.far_value())
    }

    pub(super) fn window_property_code_references(&self) -> Vec<u32> {
        let mut references = Vec::with_capacity(
            self.window_property_callbacks.len().saturating_mul(2),
        );
        for frame in &self.window_property_callbacks {
            if let Some(active_call) = &frame.active_call {
                references.extend(active_call.code_references());
            } else {
                references.push(frame.procedure);
                references.push((u32::from(frame.saved.cs) << 16)
                    | u32::from(frame.saved.ip()));
            }
        }
        references
    }

    pub(super) fn close_window_property_callbacks(&mut self) -> Result<(), RuntimeError> {
        if !self.window_property_callbacks.is_empty()
            || self.callback_kinds.contains(&CallbackKind::WindowProperty)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "EnumProps callback owner must retire through the shared callback LIFO"));
        }
        Ok(())
    }
}

pub(super) fn host_name(name: Win16WindowPropertyName) -> Option<Win16HostPropertyName> {
    Some(match name {
        Win16WindowPropertyName::Atom(0) => return None,
        Win16WindowPropertyName::Atom(atom) => Win16HostPropertyName::Atom(atom),
        Win16WindowPropertyName::String(bytes)
            if bytes.is_empty() || bytes.len() > MAX_PROPERTY_NAME_BYTES || bytes.contains(&0) => {
                return None;
            }
        Win16WindowPropertyName::String(bytes) => Win16HostPropertyName::String(bytes),
    })
}

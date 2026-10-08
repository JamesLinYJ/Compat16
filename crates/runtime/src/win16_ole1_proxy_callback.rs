//! Runtime callback gate for guest OLE 1.0 client interfaces.

#[path = "win16_ole1_com_callback_resume.rs"]
mod com_callback_resume;

use dos_kernel::DosKernel;
use guest_core::{Registers, Selector, memory::Memory};
use win16_abi::{
    Access, ArgumentKind, ReturnAddressWidth, Win16Argument, Win16CallFrame,
    Win16CallingConvention, Win16ReturnKind,
};
use x86_cpu::Cpu;

use super::super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackReturn,
};
use super::super::{CallbackFrameId, CallbackKind, Win16State};
use super::methods::OLEOBJECT_BYTES;
use super::{
    OLE1_ERROR_ADDRESS, OLE1_OK, OLE1_RELEASE_NOTIFICATION, Win16Ole1CallbackFrame,
    Win16Ole1CallbackStage, Win16Ole1ClientProxyCall, Win16Ole1ReleaseEvidence,
};
use crate::{DiagnosticKind as Kind, RuntimeError};

const OLE1_NOTIFICATION_COUNT: u16 = 7;
const OLE1_QUERY_RELEASE_STATUS_SLOT: u32 = 33;
const OLE1_QUERY_RELEASE_ERROR_SLOT: u32 = 34;
const OLE1_QUERY_RELEASE_METHOD_SLOT: u32 = 35;

impl Win16State {
    /// Dispatch the runtime-owned `OLECLIENTVTBL::CallBack` FAR gate. The
    /// proxy pointer is accepted only for its registered identity; the
    /// original guest `LPOLECLIENT` and callback FAR are revalidated before
    /// entering the application callback.
    pub(in crate::win16_runtime) fn begin_ole1_client_proxy_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Option<u8>, RuntimeError> {
        let stack = self
            .selectors
            .pointer_from_raw(Selector(cpu.regs.ss), cpu.regs.sp())
            .map_err(crate::runtime_error)?;
        let call = Win16CallFrame::new(stack, ReturnAddressWidth::Far);
        let signature = [ArgumentKind::Dword, ArgumentKind::Word, ArgumentKind::Dword];
        let cleanup = call
            .cleanup(Win16CallingConvention::Pascal, &signature)
            .map_err(crate::runtime_error)?;
        let return_to = self.far_return(&cpu.regs, memory, cleanup.callee_pop_bytes)?;
        let decoded = call.decode_arguments(
            &self.selectors,
            memory,
            Win16CallingConvention::Pascal,
            &signature,
        );
        let (proxy_far, notification, object_far) = match decoded {
            Ok(arguments) => match arguments.as_slice() {
                [
                    Win16Argument::Dword(proxy_far),
                    Win16Argument::Word(notification),
                    Win16Argument::Dword(object_far),
                ] => (*proxy_far, *notification, *object_far),
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 client callback stack decoder returned an unexpected signature",
                    ));
                }
            },
            Err(_) => {
                return self.return_ole1_client_proxy_gate(&mut cpu.regs, return_to, 0);
            }
        };
        let Some(binding) = self.ole1_client_proxy_for_far(proxy_far) else {
            return self.return_ole1_client_proxy_gate(&mut cpu.regs, return_to, 0);
        };
        if binding.proxy_far != proxy_far {
            return self.return_ole1_client_proxy_gate(&mut cpu.regs, return_to, 0);
        }
        if let Err(error) = self.validate_ole1_client_proxy(binding, memory) {
            match error.status_or_runtime() {
                Ok(_status) => {
                    return self.return_ole1_client_proxy_gate(&mut cpu.regs, return_to, 0);
                }
                Err(error) => return Err(error),
            }
        }
        if notification >= OLE1_NOTIFICATION_COUNT {
            return self.return_ole1_client_proxy_gate(&mut cpu.regs, return_to, 0);
        }
        if object_far != 0
            && self
                .checked_ole1_pointer(object_far, Access::Read, 4, OLE1_ERROR_ADDRESS, memory)
                .is_err()
        {
            return self.return_ole1_client_proxy_gate(&mut cpu.regs, return_to, 0);
        }
        if let Err(error) = self.ole1_client_callback_address(binding.client_far, memory) {
            match error.status_or_runtime() {
                Ok(_status) => {
                    return self.return_ole1_client_proxy_gate(&mut cpu.regs, return_to, 0);
                }
                Err(error) => return Err(error),
            }
        }

        self.ole1_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve OLE1 client proxy callback continuation",
                error,
            )
        })?;
        let callback_id = self.reserve_callback_frame_id()?;
        let pending_operation = (notification == OLE1_RELEASE_NOTIFICATION)
            .then(|| {
                self.ole1_client_documents
                    .release_callback_generation(binding.id, object_far)
            })
            .flatten();
        let proxy_call = Win16Ole1ClientProxyCall {
            proxy_id: binding.id,
            proxy_operation_id: binding.operation_id,
            proxy_far,
            client_far: binding.client_far,
            client_pointer: binding.client_pointer,
            notification,
            object_far,
            pending_operation,
            release_status: None,
            release_error: None,
        };
        self.ole1_callbacks.push(Win16Ole1CallbackFrame {
            callback_id,
            saved: cpu.regs.clone(),
            return_to: Some(return_to),
            return_kind: Some(Win16ReturnKind::Word),
            stage: Win16Ole1CallbackStage::ClientProxyNotification {
                call: proxy_call,
                completion: None,
            },
            object_effect: None,
            pending_proxy_retirement: None,
            active_call: None,
        });
        if let Err(error) = self.push_callback_kind(CallbackKind::Ole1, callback_id) {
            self.ole1_callbacks.pop();
            return Err(error);
        }

        let mut entered = false;
        if pending_operation.is_some() {
            if let Ok(vtable) = self.ole1_object_vtable_wire(object_far, memory) {
                if let Ok(method) =
                    self.ole1_method_address(vtable, OLE1_QUERY_RELEASE_STATUS_SLOT, memory)
                {
                    entered = self.enter_ole1_client_proxy_guest_call(
                        cpu,
                        dos,
                        memory,
                        callback_id,
                        Win16Ole1CallbackStage::ClientProxyQueryStatus(proxy_call),
                        method,
                        &[Win16FarCallbackArgument::GuestPointer {
                            far: object_far,
                            access: Access::Read,
                            bytes: OLEOBJECT_BYTES as u32,
                        }],
                    )?;
                }
            }
        }
        if !entered {
            entered = self.enter_ole1_client_proxy_notification(
                cpu,
                dos,
                memory,
                callback_id,
                proxy_call,
                None,
            )?;
        }
        if !entered {
            self.finish_ole1_client_proxy_call_without_guest(cpu, memory, callback_id, None)?;
        }
        Ok(None)
    }

    /// Return from a guest object's direct FAR call into the client proxy.
    /// This is nested within a Win16 export dispatch, so it must not consume
    /// the outer export's staged `active_dispatch_return`.
    fn return_ole1_client_proxy_gate(
        &mut self,
        registers: &mut Registers,
        return_to: (u16, u16, u32),
        value: u32,
    ) -> Result<Option<u8>, RuntimeError> {
        self.retire_far_return(return_to.0, u32::from(return_to.1), registers.ss);
        registers.cs = return_to.0;
        registers.set_ip(return_to.1);
        registers.set_sp(return_to.2 as u16);
        registers.set_ax(value as u16);
        Ok(None)
    }

    fn enter_ole1_client_proxy_guest_call(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        callback_id: CallbackFrameId,
        stage: Win16Ole1CallbackStage,
        procedure: u32,
        arguments: &[Win16FarCallbackArgument],
    ) -> Result<bool, RuntimeError> {
        // Pointer preflight handles ordinary guest rejection before entry.
        // Entry failures may retain a CPU frame or failed rollback ownership;
        // preserve the exact callback claim and propagate their typed cause.
        let active_call = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            procedure,
            arguments,
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        )?;
        let Some(frame) = self.ole1_callbacks.last_mut() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 client proxy callback frame disappeared after guest entry",
            ));
        };
        if frame.callback_id != callback_id || frame.active_call.is_some() {
            // The guest call has been entered, so keep its owner in the frame
            // before reporting the violated continuation invariant.
            frame.active_call = Some(active_call);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 client proxy callback changed its active continuation",
            ));
        }
        frame.stage = stage;
        frame.active_call = Some(active_call);
        Ok(true)
    }

    fn enter_ole1_client_proxy_notification(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        callback_id: CallbackFrameId,
        call: Win16Ole1ClientProxyCall,
        completion: Option<Win16Ole1ReleaseEvidence>,
    ) -> Result<bool, RuntimeError> {
        if !self.ole1_client_proxy_call_is_current(call, memory)? {
            return Ok(false);
        }
        let method = match self.ole1_client_callback_address(call.client_far, memory) {
            Ok(method) => method,
            Err(error) => match error.status_or_runtime() {
                Ok(_status) => return Ok(false),
                Err(error) => return Err(error),
            },
        };
        let object_argument = if call.object_far == 0 {
            Win16FarCallbackArgument::Dword(0)
        } else {
            Win16FarCallbackArgument::GuestPointer {
                far: call.object_far,
                access: Access::Read,
                bytes: OLEOBJECT_BYTES as u32,
            }
        };
        let arguments = [
            Win16FarCallbackArgument::GuestPointer {
                far: call.client_far,
                access: Access::Read,
                bytes: 4,
            },
            Win16FarCallbackArgument::Word(call.notification),
            object_argument,
        ];
        self.enter_ole1_client_proxy_guest_call(
            cpu,
            dos,
            memory,
            callback_id,
            Win16Ole1CallbackStage::ClientProxyNotification { call, completion },
            method,
            &arguments,
        )
    }

    /// A guest object method may reenter the application and free or reuse
    /// the original client's selector. Resolve the proxy by its runtime id
    /// and compare the full selector-generation identity before callback.
    fn ole1_client_proxy_call_is_current(
        &mut self,
        call: Win16Ole1ClientProxyCall,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let Some(binding) = self.ole1_client_proxy(call.proxy_id) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 client proxy binding disappeared during a retained callback",
            ));
        };
        if binding.proxy_far != call.proxy_far
            || binding.operation_id != call.proxy_operation_id
            || binding.client_far != call.client_far
            || binding.client_pointer != call.client_pointer
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "retained OLE1 client proxy identity changed during its callback",
            ));
        }
        match self.validate_ole1_client_proxy(binding, memory) {
            Ok(()) => Ok(true),
            Err(error) => match error.status_or_runtime() {
                Ok(_status) => Ok(false),
                Err(error) => Err(error),
            },
        }
    }

    fn finish_ole1_client_proxy_call_without_guest(
        &mut self,
        cpu: &mut Cpu,
        _memory: &mut Memory,
        callback_id: CallbackFrameId,
        completion: Option<Win16Ole1ReleaseEvidence>,
    ) -> Result<(), RuntimeError> {
        let (frame_stage, saved, return_to, return_kind) = {
            let Some(frame) = self.ole1_callbacks.last() else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 client proxy frame disappeared before direct return",
                ));
            };
            if frame.callback_id != callback_id || frame.active_call.is_some() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 client proxy direct return does not own an idle frame",
                ));
            }
            (
                frame.stage,
                frame.saved.clone(),
                frame.return_to,
                frame.return_kind,
            )
        };
        if let Some(evidence) = completion {
            let call = match frame_stage {
                Win16Ole1CallbackStage::ClientProxyNotification {
                    call,
                    completion: Some(claimed),
                } if claimed == evidence => call,
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 proxy frame lost the exact claimed release evidence before fallback",
                    ));
                }
            };
            self.ole1_callbacks
                .last_mut()
                .expect("proxy frame checked")
                .stage = Win16Ole1CallbackStage::ClientProxyNotification {
                call,
                completion: None,
            };
            self.ole1_client_documents
                .unclaim_release_notification(evidence.operation_id);
        }
        cpu.regs = saved;
        match (return_to, return_kind) {
            (Some((selector, offset, stack)), Some(Win16ReturnKind::Word)) => {
                self.return_ole1_client_proxy_gate(&mut cpu.regs, (selector, offset, stack), 0)?;
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 client proxy frame has an invalid return contract",
                ));
            }
        }
        let frame = self.ole1_callbacks.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 client proxy frame disappeared during direct return",
            )
        })?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::Ole1, callback_id) {
            self.ole1_callbacks.push(frame);
            return Err(error);
        }
        self.retry_pending_ole1_proxy_retirements()?;
        Ok(())
    }

    fn start_ole1_client_proxy_release_query(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        callback_id: CallbackFrameId,
        call: Win16Ole1ClientProxyCall,
        slot: u32,
        stage: Win16Ole1CallbackStage,
    ) -> Result<bool, RuntimeError> {
        let vtable = match self.ole1_object_vtable_wire(call.object_far, memory) {
            Ok(vtable) => vtable,
            Err(_) => return Ok(false),
        };
        let method = match self.ole1_method_address(vtable, slot, memory) {
            Ok(method) => method,
            Err(_) => return Ok(false),
        };
        let arguments = [Win16FarCallbackArgument::GuestPointer {
            far: call.object_far,
            access: Access::Read,
            bytes: OLEOBJECT_BYTES as u32,
        }];
        self.enter_ole1_client_proxy_guest_call(
            cpu,
            dos,
            memory,
            callback_id,
            stage,
            method,
            &arguments,
        )
    }

    fn forward_ole1_client_proxy_notification(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        callback_id: CallbackFrameId,
        call: Win16Ole1ClientProxyCall,
        actual_method: Option<u16>,
    ) -> Result<(), RuntimeError> {
        if !self.ole1_client_proxy_call_is_current(call, memory)? {
            return self.finish_ole1_client_proxy_call_without_guest(
                cpu,
                memory,
                callback_id,
                None,
            );
        }
        let mut completion = None;
        if let (Some((operation_id, initiating_callback_id)), Some(status), Some(error), Some(method)) = (
            call.pending_operation,
            call.release_status,
            call.release_error,
            actual_method,
        ) {
            let evidence = Win16Ole1ReleaseEvidence {
                operation_id,
                initiating_callback_id,
                object_far: call.object_far,
                status,
                error,
                method,
            };
            if self
                .ole1_client_documents
                .release_notification_target(evidence)
                .is_some()
            {
                match self
                    .ole1_client_documents
                    .claim_release_notification(evidence)
                {
                    Ok(client_far) if client_far == call.client_far => {
                        completion = Some(evidence);
                    }
                    Ok(_) => self
                        .ole1_client_documents
                        .unclaim_release_notification(operation_id),
                    Err(_) => {}
                }
            }
        }
        if let Some(evidence) = completion {
            let Some(frame) = self.ole1_callbacks.last_mut() else {
                self.ole1_client_documents
                    .unclaim_release_notification(evidence.operation_id);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 proxy frame disappeared after claiming a release notification",
                ));
            };
            if frame.callback_id != callback_id || frame.active_call.is_some() {
                self.ole1_client_documents
                    .unclaim_release_notification(evidence.operation_id);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 proxy frame cannot own the claimed release notification",
                ));
            }
            // The claim owns a detached proxy before any further memory read or
            // checked guest entry can fail. Teardown can now exact-ACK it.
            frame.stage = Win16Ole1CallbackStage::ClientProxyNotification {
                call,
                completion: Some(evidence),
            };
        }
        let entered = self.enter_ole1_client_proxy_notification(
            cpu,
            dos,
            memory,
            callback_id,
            call,
            completion,
        )?;
        if entered {
            return Ok(());
        }
        self.finish_ole1_client_proxy_call_without_guest(cpu, memory, callback_id, completion)
    }

    pub(super) fn finish_ole1_proxy_callback_stage(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        callback_id: CallbackFrameId,
        stage: Win16Ole1CallbackStage,
        callback_status: u32,
    ) -> Result<(), RuntimeError> {
        match stage {
            Win16Ole1CallbackStage::ClientComAdviseNotification { call, callback } => {
                if !self.ole1_client_proxy_call_is_current(call, memory)? {
                    return Err(RuntimeError::new(
                        Kind::GuestFault,
                        "OLE1 COM callback client selector generation changed during guest reentry",
                    ));
                }
                let Some(frame) = self.ole1_callbacks.last() else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 COM callback continuation disappeared before resume staging",
                    ));
                };
                if frame.callback_id != callback_id || frame.active_call.is_some() {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 COM callback does not own an idle exact continuation",
                    ));
                }
                let saved = frame.saved.clone();
                cpu.regs = saved;
                let reply = crate::Win16ComHostResume {
                    frame: callback.frame,
                    parent: callback.parent,
                    owner: callback.owner,
                    outcome: crate::Win16ComHostCallbackOutcome::Reply(
                        crate::Win16ComHostCallbackReply::AdviseSinkClientWord(
                            callback_status as u16,
                        ),
                    ),
                };
                self.ole1_com_callback_resumes.push(reply);
                let frame = self.ole1_callbacks.pop().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 COM callback continuation disappeared during retirement",
                    )
                })?;
                if let Err(error) = self.retire_callback_binding(CallbackKind::Ole1, callback_id) {
                    self.ole1_callbacks.push(frame);
                    self.ole1_com_callback_resumes.pop();
                    return Err(error);
                }
                Ok(())
            }
            Win16Ole1CallbackStage::ClientProxyQueryStatus(mut call) => {
                if !self.ole1_client_proxy_call_is_current(call, memory)? {
                    return self.finish_ole1_client_proxy_call_without_guest(
                        cpu,
                        memory,
                        callback_id,
                        None,
                    );
                }
                let status = callback_status as u16;
                call.release_status = Some(status);
                if status != OLE1_OK {
                    return self.forward_ole1_client_proxy_notification(
                        cpu,
                        dos,
                        memory,
                        callback_id,
                        call,
                        None,
                    );
                }
                let entered = self.start_ole1_client_proxy_release_query(
                    cpu,
                    dos,
                    memory,
                    callback_id,
                    call,
                    OLE1_QUERY_RELEASE_ERROR_SLOT,
                    Win16Ole1CallbackStage::ClientProxyQueryError(call),
                )?;
                if !entered {
                    self.forward_ole1_client_proxy_notification(
                        cpu,
                        dos,
                        memory,
                        callback_id,
                        call,
                        None,
                    )?;
                }
                Ok(())
            }
            Win16Ole1CallbackStage::ClientProxyQueryError(mut call) => {
                if !self.ole1_client_proxy_call_is_current(call, memory)? {
                    return self.finish_ole1_client_proxy_call_without_guest(
                        cpu,
                        memory,
                        callback_id,
                        None,
                    );
                }
                call.release_error = Some(callback_status as u16);
                let entered = self.start_ole1_client_proxy_release_query(
                    cpu,
                    dos,
                    memory,
                    callback_id,
                    call,
                    OLE1_QUERY_RELEASE_METHOD_SLOT,
                    Win16Ole1CallbackStage::ClientProxyQueryMethod(call),
                )?;
                if !entered {
                    self.forward_ole1_client_proxy_notification(
                        cpu,
                        dos,
                        memory,
                        callback_id,
                        call,
                        None,
                    )?;
                }
                Ok(())
            }
            Win16Ole1CallbackStage::ClientProxyQueryMethod(call) => {
                if !self.ole1_client_proxy_call_is_current(call, memory)? {
                    return self.finish_ole1_client_proxy_call_without_guest(
                        cpu,
                        memory,
                        callback_id,
                        None,
                    );
                }
                self.forward_ole1_client_proxy_notification(
                    cpu,
                    dos,
                    memory,
                    callback_id,
                    call,
                    Some(callback_status as u16),
                )
            }
            Win16Ole1CallbackStage::ClientProxyNotification { call, completion } => {
                let Some(binding) = self.ole1_client_proxy(call.proxy_id) else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 client proxy binding disappeared during its callback",
                    ));
                };
                if binding.proxy_far != call.proxy_far
                    || binding.operation_id != call.proxy_operation_id
                    || binding.client_far != call.client_far
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 client proxy identity changed during its callback",
                    ));
                }
                if let Some(evidence) = completion {
                    let proxy_id = self
                        .ole1_client_documents
                        .complete_release_notification(evidence)
                        .map_err(|status| {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                format!("OLE1 client callback completion no longer matches its claimed generation (status {status})"),
                            )
                        })?;
                    self.ole1_callbacks
                        .last_mut()
                        .expect("OLE1 frame checked")
                        .stage = Win16Ole1CallbackStage::ClientProxyNotification {
                        call,
                        completion: None,
                    };
                    if let Some(proxy_id) = proxy_id {
                        self.retire_ole1_client_operation_proxy(proxy_id)?;
                    }
                }
                let Some(frame) = self.ole1_callbacks.last() else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 proxy callback frame disappeared before direct return",
                    ));
                };
                if frame.callback_id != callback_id || frame.active_call.is_some() {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 proxy callback does not own an idle continuation",
                    ));
                }
                let saved = frame.saved.clone();
                let return_to = frame.return_to;
                let return_kind = frame.return_kind;
                cpu.regs = saved;
                match (return_to, return_kind) {
                    (Some(return_to), Some(Win16ReturnKind::Word)) => {
                        self.return_ole1_client_proxy_gate(
                            &mut cpu.regs,
                            return_to,
                            callback_status,
                        )?;
                    }
                    _ => {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "OLE1 proxy callback has an invalid WORD return target",
                        ));
                    }
                }
                let frame = self.ole1_callbacks.pop().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 proxy callback frame disappeared during direct return",
                    )
                })?;
                if let Err(error) = self.retire_callback_binding(CallbackKind::Ole1, callback_id) {
                    self.ole1_callbacks.push(frame);
                    return Err(error);
                }
                self.retry_pending_ole1_proxy_retirements()?;
                Ok(())
            }
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-proxy OLE1 continuation reached the proxy callback finisher",
            )),
        }
    }
}

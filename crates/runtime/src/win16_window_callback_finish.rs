//! USER callback return validation and retained native-resume retirement.

use std::sync::Arc;

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn record_window_callback_return(
        &mut self,
        kind: CallbackKind,
        transfer: x86_cpu::ControlTransfer,
    ) -> Result<(), RuntimeError> {
        let adapted_native_return = kind == CallbackKind::NativeFunction
            && transfer == x86_cpu::ControlTransfer::AdapterReturn
            && self.native_function_has_returned_value();
        let (callback_id, host_operation) = match kind {
            CallbackKind::Window => self.window_callbacks.last().map(|callback|
                (callback.callback_id, callback.host_operation)).ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "returned USER callback has no retained window callback frame"))?,
            CallbackKind::NativeFunction => self.native_function_callbacks.last().map(|callback|
                (callback.callback_id, Some(callback.host_operation))).ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "returned property callback has no retained callback frame"))?,
            _ => return Ok(()),
        };
        let frame = self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "returned USER callback has no exact parent operation frame"))?;
        let owned = match host_operation {
            Some(operation) => frame.host_operation == Some(operation),
            None => frame.guest_callback_id == Some(callback_id),
        };
        if !owned {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "returned USER callback does not match the exact top operation owner"));
        }
        // Retry consistency belongs to one callback identity. After that
        // callback retires, a later callback on the same native operation may
        // legitimately return via RETF or the checked ABI adapter instead.
        if frame.guest_return_transfer.is_some_and(|(prior_id, prior)|
            prior_id == callback_id && prior != transfer) && !adapted_native_return
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "USER callback retry changed its observed return transfer"));
        }
        frame.guest_return_transfer = Some((callback_id, transfer));
        Ok(())
    }

    pub(in crate::win16_runtime) fn finish_window_callback(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Window)?;
        let (saved, continuation, guest_value, native_resume_error) = {
            let frame = self.window_callbacks.last().ok_or_else(|| RuntimeError::new(
                Kind::GuestFault,
                "Win16 window callback gate has no active call",
            ))?;
            if frame.callback_id != callback_id {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 window callback identity changed before guest return",
                ));
            }
            if frame.guest_return_value.is_none()
                && (registers.ip() != 0
                    || registers.ss != frame.saved.ss
                    || registers.sp() != frame.saved.sp())
            {
                return Err(RuntimeError::new(
                    Kind::GuestFault,
                    "Win16 window callback returned with an invalid address or stack",
                ));
            }
            (
                frame.saved.clone(),
                frame.continuation,
                frame.guest_return_value,
                frame.native_resume_error.as_ref().map(Arc::clone),
            )
        };
        if let Some(error) = native_resume_error {
            *registers = saved;
            return Err(super::super::callback_lifo::shared_runtime_error(error));
        }
        let value = guest_value.unwrap_or_else(|| {
            u32::from(registers.ax()) | (u32::from(registers.dx()) << 16)
        });
        if guest_value.is_none() {
            self.window_callbacks
                .last_mut()
                .expect("frame checked")
                .guest_return_value = Some(value);
        }
        *registers = saved;

        match continuation {
            WindowCallbackContinuation::HostTimer { callback } => {
                self.retire_callback_payload()?;
                let reply = Win16WindowReply {
                    callback,
                    result: crate::Win16HostMessageResult {
                        dialog_result: None,
                        value: 0,
                        output: crate::Win16HostMessageOutput::None,
                    },
                };
                let step = self.resume_native_window_callback(reply, host)?;
                self.retire_window_callback_frame(callback_id)?;
                self.advance_window_operation(registers, memory, host, step)
            }
            WindowCallbackContinuation::Host {
                callback,
                window,
                destroyed,
                ..
            } => {
                let message = self.window_callbacks.last().expect("frame checked").payload.message;
                self.project_and_cleanup_window_payload(value, None, false, memory, host)?;
                self.retire_host_window_side_effects(
                    window,
                    message,
                    destroyed,
                    host,
                    value,
                    None,
                    callback,
                    crate::Win16WindowCallbackProcedure::WindowProcedure,
                )?;
                let result = self.window_callbacks.last()
                    .and_then(|frame| frame.payload_result.as_ref())
                    .ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 WndProc result disappeared before native resume",
                    ))?
                    .clone();
                let step = self.resume_native_window_callback(
                    Win16WindowReply { callback, result },
                    host,
                )?;
                self.retire_window_callback_frame(callback_id)?;
                self.advance_window_operation(registers, memory, host, step)
            }
            WindowCallbackContinuation::HostDialog {
                callback,
                window,
                destroyed,
                ..
            } => {
                let message = self.window_callbacks.last().expect("frame checked").payload.message;
                let dialog_result = self.dialog_message_result(window);
                self.project_and_cleanup_window_payload(
                    value as u16 as u32,
                    dialog_result,
                    true,
                    memory,
                    host,
                )?;
                self.retire_host_window_side_effects(
                    window,
                    message,
                    destroyed,
                    host,
                    value as u16 as u32,
                    dialog_result,
                    callback,
                    crate::Win16WindowCallbackProcedure::DialogProcedure,
                )?;
                let result = self.window_callbacks.last()
                    .and_then(|frame| frame.payload_result.as_ref())
                    .ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 DLGPROC result disappeared before native resume",
                    ))?
                    .clone();
                let step = self.resume_native_window_callback(
                    Win16WindowReply { callback, result },
                    host,
                )?;
                self.retire_window_callback_frame(callback_id)?;
                self.advance_window_operation(registers, memory, host, step)
            }
            WindowCallbackContinuation::GuestDispatch => {
                self.retire_callback_payload()?;
                self.retire_window_callback_frame(callback_id)?;
                self.complete_window_operation(
                    registers,
                    host,
                    Win16WindowResult::Dispatched(value as i32),
                )
            }
            WindowCallbackContinuation::GuestDialogDispatch { window } => {
                let result = if value as u16 != 0 {
                    self.dialog_message_result(window).unwrap_or(0) as i32
                } else {
                    0
                };
                self.retire_callback_payload()?;
                self.retire_window_callback_frame(callback_id)?;
                self.complete_window_operation(
                    registers,
                    host,
                    Win16WindowResult::Dispatched(result),
                )
            }
            WindowCallbackContinuation::GuestTimer => {
                self.retire_callback_payload()?;
                self.retire_window_callback_frame(callback_id)?;
                self.complete_window_operation(
                    registers,
                    host,
                    Win16WindowResult::Dispatched(0),
                )
            }
            WindowCallbackContinuation::GuestProcedureCall { .. } => {
                self.retire_callback_payload()?;
                self.retire_window_callback_frame(callback_id)?;
                self.complete_window_operation(
                    registers,
                    host,
                    Win16WindowResult::Dispatched(value as i32),
                )
            }
        }
    }

    fn project_and_cleanup_window_payload(
        &mut self,
        value: u32,
        dialog_result: Option<u32>,
        dialog_proc: bool,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let needs_projection = self.window_callbacks.last().is_some_and(|frame| {
            frame.payload_result.is_none() && frame.payload_error.is_none()
        });
        if needs_projection {
            let payload = self.window_callbacks.last().expect("frame checked").payload.projection();
            let result = self.project_callback_window_payload(
                payload,
                value,
                dialog_result,
                dialog_proc,
                memory,
                host,
            );
            let frame = self.window_callbacks.last_mut().expect("frame checked");
            match result {
                Ok(result) => frame.payload_result = Some(result),
                Err(error) => frame.payload_error = Some(Arc::new(error)),
            }
        }
        self.retire_callback_payload()
    }

    fn retire_callback_payload(&mut self) -> Result<(), RuntimeError> {
        if self.window_callbacks.last().is_some_and(|frame| frame.payload_cleaned) {
            return Ok(());
        }
        let result = super::payload_retirement::retire_active_window_callback_payload(self);
        if let Err(cleanup) = result {
            let frame = self.window_callbacks.last().expect("frame retained");
            if let Some(primary) = frame.payload_error.as_ref() {
                return Err(super::super::window_payloads::combine_callback_payload_failure(
                    Arc::clone(primary),
                    cleanup,
                ));
            }
            return Err(cleanup);
        }
        if matches!(result, Ok(WindowCallbackPayloadCleanup::RetainedInFrame)) {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 callback payload still has an active selector alias or pin"));
        }
        let frame = self.window_callbacks.last_mut().expect("frame retained");
        frame.payload_cleaned = true;
        if let Some(error) = frame.payload_error.as_ref() {
            return Err(super::super::window_payloads::repeat_callback_payload_failure(
                Arc::clone(error),
            ));
        }
        Ok(())
    }

    fn retire_host_window_side_effects(
        &mut self,
        window: u16,
        message: u16,
        destroyed: bool,
        host: &mut impl RuntimeHost,
        value: u32,
        dialog_result: Option<u32>,
        callback: crate::Win16HostCallback,
        procedure: crate::Win16WindowCallbackProcedure,
    ) -> Result<(), RuntimeError> {
        let (tree_retired, clipboard_retired, trace_observed) = self.window_callbacks.last()
            .map(|frame| (frame.window_tree_retired, frame.clipboard_retired, frame.trace_observed))
            .ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 window callback frame disappeared before native resume",
            ))?;
        if destroyed && !tree_retired {
            self.retire_window_tree(window)?;
            self.window_callbacks.last_mut().expect("frame retained").window_tree_retired = true;
        }
        if message == Win16ScalarMessage::DestroyClipboard as u16 && !clipboard_retired {
            self.retire_all_clipboard_data()?;
            self.window_callbacks.last_mut().expect("frame retained").clipboard_retired = true;
        }
        if !trace_observed && host.win16_service_trace_enabled() {
            host.observe_win16_io(&crate::Win16IoEvent::WindowCallback {
                callback: callback.0,
                window,
                procedure,
                phase: crate::Win16WindowCallbackPhase::GuestReturn,
                message,
                return_value: Some(match procedure {
                    crate::Win16WindowCallbackProcedure::WindowProcedure => {
                        crate::Win16WindowCallbackReturn::WindowProcedure(value)
                    }
                    crate::Win16WindowCallbackProcedure::DialogProcedure => {
                        crate::Win16WindowCallbackReturn::DialogProcedure(value as u16)
                    }
                }),
                dialog_message_result: dialog_result,
            });
            self.window_callbacks.last_mut().expect("frame retained").trace_observed = true;
        }
        Ok(())
    }

    pub(super) fn resume_native_window_callback(
        &mut self,
        reply: Win16WindowReply,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16WindowStep, RuntimeError> {
        if let Some(error) = self.window_callbacks.last()
            .and_then(|frame| frame.native_resume_error.as_ref())
        {
            return Err(super::super::callback_lifo::shared_runtime_error(Arc::clone(error)));
        }
        match host.win16_window_resume(Some(reply)) {
            Ok(step) => Ok(step),
            Err(error) => {
                let error = Arc::new(error);
                let returned = super::super::callback_lifo::shared_runtime_error(Arc::clone(&error));
                self.window_callbacks.last_mut().expect("frame retained").native_resume_error = Some(error);
                Err(returned)
            }
        }
    }

    pub(super) fn retire_window_callback_frame(
        &mut self,
        callback_id: super::super::CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 window callback frame disappeared before retirement",
        ))?;
        if frame.callback_id != callback_id || !frame.payload_cleaned {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 window callback retirement lost its exact cleaned frame",
            ));
        }
        self.retire_callback_binding(CallbackKind::Window, callback_id)?;
        // The identity binding and its cleaned payload frame are paired LIFO
        // owners. Keeping this frame would hide the suspended outer callback
        // when a nested native call returns.
        self.window_callbacks.pop();
        if let Some(parent) = self.window_operations.last_mut()
            .filter(|operation| operation.guest_callback_id == Some(callback_id))
        {
            parent.guest_callback_retired = true;
        }
        Ok(())
    }
}

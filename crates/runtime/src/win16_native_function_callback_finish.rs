//! Native function callback return, source acknowledgement and terminal retirement.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn finish_native_function_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::NativeFunction)?;
        let (callback, cached_value, prior_error) = {
            let frame = self.native_function_callbacks.last().ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "Win16 callback gate has no active native function callback",
                )
            })?;
            if frame.callback_id != callback_id {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 native function callback differs from the exact shared LIFO identity",
                ));
            }
            let error = frame
                .entry_error
                .as_ref()
                .or(frame.return_error.as_ref())
                .or(frame.native_resume_error.as_ref())
                .map(Arc::clone);
            (frame.callback, frame.guest_return, error)
        };
        if let Some(error) = prior_error {
            return Err(super::super::callback_lifo::shared_runtime_error(error)
                .with_context("Win16 native function callback remains on its exact owner"));
        }

        let value = if let Some(value) = cached_value {
            value
        } else {
            let mut active_call = self
                .native_function_callbacks
                .last_mut()
                .and_then(|frame| frame.active_call.take())
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "entered native function callback has no retained FAR call frame",
                    )
                })?;
            match self.finish_native_function_far_callback(cpu, dos, memory, &mut active_call) {
                Ok(value) => {
                    let frame = self
                        .native_function_callbacks
                        .last_mut()
                        .expect("native function callback frame checked");
                    frame.guest_return = Some(value);
                    frame.active_call = Some(active_call);
                    let transfer = cpu.control_transfer().ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant, "native callback restore lost its checked ABI return"))?;
                    self.record_window_callback_return(CallbackKind::NativeFunction, transfer)?;
                    value
                }
                Err(error) => {
                    let kind = error.kind();
                    let error = Arc::new(error);
                    let frame = self
                        .native_function_callbacks
                        .last_mut()
                        .expect("native function callback frame checked");
                    if frame.return_error.is_none() {
                        frame.return_error = Some(Arc::clone(&error));
                    }
                    frame.active_call = Some(active_call);
                    return Err(RuntimeError::with_source(
                        kind,
                        "Win16 native function guest return failed validation",
                        error,
                    ));
                }
            }
        };

        // Keep the callback frame and shared ID live across any failed free;
        // release_native_function_payload records a completed unlock so retry
        // resumes at the exact remaining cleanup step.
        self.commit_metafile_callback_table(memory, host)?;
        self.release_native_function_payload()?;
        let resumed_step = self
            .native_function_callbacks
            .last()
            .expect("native function callback frame retained after cleanup")
            .resumed_step
            .is_some();
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
                    let frame = self.native_function_callbacks.last_mut().expect(
                        "native function callback frame retained after native resume failure",
                    );
                    if frame.native_resume_error.is_none() {
                        frame.native_resume_error = Some(Arc::clone(&error));
                    }
                    return Err(RuntimeError::with_source(
                        kind,
                        "Win16 native function native resume remains on its exact callback owner",
                        error,
                    ));
                }
            };
            self.native_function_callbacks
                .last_mut()
                .expect("native function callback frame retained after native resume")
                .resumed_step = Some(step);
        }

        let mut active_call = self
            .native_function_callbacks
            .last_mut()
            .and_then(|frame| frame.active_call.take())
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "native function native acknowledgement has no retained FAR owner",
                )
            })?;
        if let Err(error) = self.release_guest_far_callback_owner(&mut active_call, dos, memory) {
            self.native_function_callbacks
                .last_mut()
                .expect("native function callback frame retained after owner-release failure")
                .active_call = Some(active_call);
            return Err(error);
        }
        self.native_function_callbacks
            .last_mut()
            .expect("native function callback frame retained after owner release")
            .active_call = Some(active_call);

        self.retire_callback_binding(CallbackKind::NativeFunction, callback_id)?;
        let mut frame = self
            .native_function_callbacks
            .pop()
            .expect("native function callback frame checked before LIFO retirement");
        debug_assert_eq!(frame.callback_id, callback_id);
        let step = frame
            .resumed_step
            .take()
            .expect("successful native resume step retained before callback retirement");
        self.advance_window_operation(&mut cpu.regs, memory, host, step)
    }

    pub(in crate::win16_runtime) fn cancel_native_function_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if self.window_teardown_state != super::super::WindowTeardownState::NativeQuiescent {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 native function callback cancellation preceded USER quiescence",
            ));
        }
        let callback_id = self.require_callback_top(CallbackKind::NativeFunction)?;
        if self
            .native_function_callbacks
            .last()
            .is_none_or(|frame| frame.callback_id != callback_id)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 native function callback is not the exact shared LIFO owner",
            ));
        }
        let (callback, operation, source) = self
            .terminal_native_function_callback_identity(callback_id)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 native function callback identity disappeared before terminal cleanup",
                )
            })?;
        self.validate_terminal_callback_source(callback, operation, source)?;
        let cancellation = crate::Win16NativeCallbackCancellation {
            callback,
            operation_id: operation,
            source,
        };
        let owner = self.prepare_terminal_callback_retirement(callback_id, cancellation)?;
        if let Some(mut active_call) = self
            .native_function_callbacks
            .last_mut()
            .and_then(|frame| frame.active_call.take())
        {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                CallbackKind::NativeFunction,
                callback_id,
                cpu,
                dos,
                memory,
                &mut active_call,
            ) {
                self.native_function_callbacks
                    .last_mut()
                    .expect("native function frame retained after terminal CPU abort failure")
                    .active_call = Some(active_call);
                let error = Arc::new(error);
                self.retain_callback_terminal_error(owner, Arc::clone(&error))?;
                return Err(super::super::callback_lifo::shared_runtime_error(error)
                    .with_context("Win16 native function terminal CPU frame remains owned"));
            }
            self.native_function_callbacks
                .last_mut()
                .expect("native function frame retained after terminal CPU abort")
                .active_call = Some(active_call);
        }
        if let Err(error) = self.release_native_function_payload() {
            let error = Arc::new(error);
            self.retain_callback_terminal_error(owner, Arc::clone(&error))?;
            return Err(super::super::callback_lifo::shared_runtime_error(error)
                .with_context("Win16 property name cleanup remains owned by its callback"));
        }
        self.set_terminal_callback_phase(owner, callback_id, cancellation, |proof| {
            proof.guest_payload_cleaned = true
        })?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::NativeFunction, callback_id)
        {
            let error = Arc::new(error);
            self.retain_callback_terminal_error(owner, Arc::clone(&error))?;
            return Err(super::super::callback_lifo::shared_runtime_error(error)
                .with_context("Win16 native function callback LIFO retirement remains pending"));
        }
        let frame = self
            .native_function_callbacks
            .pop()
            .expect("native function callback owner checked before LIFO retirement");
        debug_assert_eq!(frame.callback_id, callback_id);
        self.set_terminal_callback_phase(owner, callback_id, cancellation, |proof| {
            proof.runtime_frame_retired = true
        })
    }
}

//! Checked scheduling while an exact native USER wait remains suspended.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use x86_cpu::Cpu;

use super::{Win16DdeCallbackOrigin, Win16State, windows::WindowReturn};
use crate::Win16WindowStep;
use crate::win16_host_message_calls::Win16MessageCallContinuation;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostWindowOperationId};

pub(super) struct PendingWindowGuestWork {
    frame_id: u64,
    host_operation: Win16HostWindowOperationId,
    generation: u64,
    callback_depth: usize,
    cpu_owner: Option<u64>,
    resume_step: Option<Win16WindowStep>,
    resume_failure: Option<std::sync::Arc<RuntimeError>>,
}

pub(super) struct PendingModalGuestWork {
    frame_id: u64,
    host_operation: Win16HostWindowOperationId,
    scope_id: u64,
    generation: u64,
    marker_id: Option<u64>,
    wake_generation: Option<u64>,
    callback_depth: usize,
    cpu_owner: Option<u64>,
    failure: Option<std::sync::Arc<RuntimeError>>,
    resume_step: Option<Win16WindowStep>,
    resume_failure: Option<std::sync::Arc<RuntimeError>>,
}

impl PendingModalGuestWork {
    pub(in crate::win16_runtime) fn scope_id(&self) -> u64 {
        self.scope_id
    }

    pub(super) fn terminal_retirement(
        &self,
    ) -> Result<Option<crate::Win16NativeModalGuestWorkRetirement>, RuntimeError> {
        match (self.marker_id, self.wake_generation) {
            (Some(marker_id), Some(wake_generation)) if marker_id != 0 && wake_generation != 0 => {
                Ok(Some(crate::Win16NativeModalGuestWorkRetirement {
                    operation_id: self.host_operation,
                    scope_id: self.scope_id,
                    generation: self.generation,
                    marker_id,
                    wake_generation,
                }))
            }
            (None, None) if self.failure.is_some() => Ok(None),
            _ => Err(invalid_wait(
                "retained modal work has incomplete native source identities",
            )),
        }
    }
}

fn invalid_wait(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

impl Win16State {
    pub(super) fn park_window_guest_work(
        &mut self,
        operation: Win16HostWindowOperationId,
        generation: u64,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| {
            invalid_wait("guest work wake has no suspended runtime USER operation")
        })?;
        let is_wait = matches!(
            frame.continuation(),
            Some(
                WindowReturn::GetMessage { .. }
                    | WindowReturn::MessageCall(Win16MessageCallContinuation::WaitMessage { .. })
            )
        );
        if !is_wait
            || frame.pending_work.is_some()
            || generation <= frame.last_work_generation
            || frame.host_wait.is_some_and(|bound| bound != operation)
        {
            return Err(invalid_wait(
                "guest work wake does not match the exact runtime USER wait",
            ));
        }
        frame.host_wait = Some(operation);
        frame.pending_work = Some(PendingWindowGuestWork {
            frame_id: frame.id,
            host_operation: operation,
            generation,
            callback_depth: self.callback_kinds.len(),
            cpu_owner: None,
            resume_step: None,
            resume_failure: None,
        });
        Ok(())
    }

    pub(super) fn park_modal_guest_work(
        &mut self,
        operation: Win16HostWindowOperationId,
        scope_id: u64,
        generation: u64,
        marker_id: Option<u64>,
        wake_generation: Option<u64>,
        failure: Option<RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| {
            invalid_wait("modal guest-work marker has no suspended runtime USER operation")
        })?;
        if scope_id == 0
            || frame.pending_modal_work.is_some()
            || frame.pending_work.is_some()
            || generation <= frame.last_modal_work_generation
            || frame
                .host_modal_operation
                .is_some_and(|bound| bound != operation)
        {
            return Err(invalid_wait(
                "modal guest-work marker does not match the exact suspended runtime operation",
            ));
        }
        if failure.is_none()
            && !matches!((marker_id, wake_generation), (Some(marker), Some(wake))
                if marker != 0 && wake != 0)
        {
            return Err(invalid_wait(
                "successful modal guest-work marker has no actual source identities",
            ));
        }
        frame.host_modal_operation = Some(operation);
        frame.pending_modal_work = Some(PendingModalGuestWork {
            frame_id: frame.id,
            host_operation: operation,
            scope_id,
            generation,
            marker_id,
            wake_generation,
            callback_depth: self.callback_kinds.len(),
            cpu_owner: None,
            failure: failure.map(std::sync::Arc::new),
            resume_step: None,
            resume_failure: None,
        });
        Ok(())
    }

    /// Return true when the loop must reconsider the parked wait before CPU
    /// dispatch. An injected callback returns false so its actual guest code
    /// runs; its full CPU restore precedes any subsequent wait continuation.
    pub(super) fn service_pending_window_guest_work(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        host: &mut impl RuntimeHost,
        guest_dispatch_allowed: bool,
    ) -> Result<bool, RuntimeError> {
        let Some(frame) = self.window_operations.last() else {
            return Ok(false);
        };
        let Some(work) = frame.pending_work.as_ref() else {
            return Ok(false);
        };
        if frame.id != work.frame_id
            || frame.host_wait != Some(work.host_operation)
            || work.generation <= frame.last_work_generation
        {
            return Err(invalid_wait(
                "parked USER wait identity or wake generation changed",
            ));
        }
        let (callback_depth, cpu_owner) = (work.callback_depth, work.cpu_owner);
        if self.callback_kinds.len() < callback_depth {
            return Err(invalid_wait(
                "parked USER wait lost its enclosing guest callback",
            ));
        }
        if self.callback_kinds.len() != callback_depth {
            return Ok(false);
        }
        // A DOS child or active PE32 call owns the current CPU and memory
        // view. Keep the original USER operation parked until Win16 regains
        // control; do not capture, dispatch, or resume it from that view.
        if !guest_dispatch_allowed {
            return Ok(false);
        }
        if cpu.interrupt_shadow_active() {
            return Err(invalid_wait(
                "parked USER wait has no scheduler boundary outside the interrupt shadow",
            ));
        }
        if cpu_owner.is_none() {
            let owner = self.capture_legacy_cpu_parked_frame(cpu, dos, memory)?;
            self.window_operations
                .last_mut()
                .and_then(|frame| frame.pending_work.as_mut())
                .ok_or_else(|| invalid_wait("parked USER wait disappeared during CPU capture"))?
                .cpu_owner = Some(owner);
        }
        if self.window_operations.last().is_some_and(|frame| {
            frame
                .pending_work
                .as_ref()
                .is_some_and(|work| work.resume_step.is_some() || work.resume_failure.is_some())
        }) {
            return self.complete_parked_window_resume(cpu, dos, memory, host, false);
        }

        // Classic DDE retains its own source and nested host-operation stack;
        // servicing it here must leave the enclosing USER wait proof intact.
        if self.service_classic_dde_safe_point(cpu, dos, memory, host)? {
            return Ok(true);
        }
        // Native modal pumps can consume WM_DROPFILES without completing the
        // parked GetMessage/WaitMessage. Retire its exact HGLOBAL queue lease
        // here as an independent safe-point receipt; this never resumes or
        // acknowledges the parked USER source.
        let _ = self.poll_native_drop_retirement(host)?;

        // A parked GetMessage/WaitMessage is also a multimedia safe point.
        // Poll the source owners before deciding whether the exact suspended
        // USER operation can resume; neither poll completes that operation.
        self.poll_network_events(memory, host)?;
        self.dispatch_pending_network_print_notification(host)?;
        self.poll_wave_events(memory, host, true)?;
        self.poll_sound(memory, host)?;

        if matches!(
            self.dispatch_pending_netbios_notification(cpu, memory, host)?,
            super::netbios_async::NetbiosDispatch::CallbackEntered
        ) {
            return Ok(false);
        }
        if self.dispatch_pending_wave_function_callback(cpu, memory, host)? {
            // The exact host USER operation remains parked in its original
            // frame while this guest callback runs. Its terminal receipt
            // restores the full interrupted context before this wait resumes.
            return Ok(false);
        }
        if !self.dispatch_pending_midi_notification(cpu, memory, host)? {
            // The exact host USER wait remains parked while a MIDI callback
            // owns its complete interrupted CPU context.
            return Ok(false);
        }
        if self.service_pending_window_dde_callback(
            cpu,
            dos,
            memory,
            host,
            guest_dispatch_allowed,
        )? {
            return Ok(true);
        }
        if let Some(event) = host.win16_take_guest_callback()? {
            let entered = self
                .begin_asynchronous_guest_callback(cpu, memory, event)?
                .is_some();
            return Ok(!entered);
        }
        if let Some(step) = host.win16_dde_poll_callback()? {
            let frame = step.frame;
            self.capture_dde_guest_context(cpu, dos, memory, frame)?;
            let origin = Win16DdeCallbackOrigin::GuestExecution { frame };
            if let Some((origin, next)) =
                self.begin_dde_callback(step, origin, cpu, dos, memory, host)?
            {
                self.route_dde_callback_step(cpu, dos, memory, host, origin, next)?;
            }
            while self.restore_next_dde_context(cpu, dos, memory)? {}
            return Ok(self.callback_kinds.len() == callback_depth);
        }

        // Nothing has completed GetMessage/WaitMessage yet. The host retains
        // the exact operation and validates its own nonce, generation and kind
        // before continuing the original native wait. No guest MSG is written.
        self.restore_parked_window_work(cpu, dos, memory, false)?;
        let result = host.win16_window_resume(None);
        self.cache_parked_window_resume(false, result)?;
        self.complete_parked_window_resume(cpu, dos, memory, host, false)
    }

    /// Service only the exact native modal continuation that yielded this
    /// operation/scope/generation. The hook step is not a source ACK or
    /// callback retirement receipt.
    pub(super) fn service_pending_modal_guest_work(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        host: &mut impl RuntimeHost,
        guest_dispatch_allowed: bool,
    ) -> Result<bool, RuntimeError> {
        let Some((
            operation,
            scope_id,
            generation,
            marker_id,
            wake_generation,
            callback_depth,
            cpu_owner,
            failure,
            resume_cached,
        )) = self
            .window_operations
            .last()
            .and_then(|frame| {
                frame.pending_modal_work.as_ref().map(|work| {
                    if frame.id != work.frame_id
                        || frame.host_modal_operation != Some(work.host_operation)
                        || work.generation <= frame.last_modal_work_generation
                    {
                        return Err(invalid_wait(
                            "parked modal guest-work tuple or generation changed",
                        ));
                    }
                    Ok((
                        work.host_operation,
                        work.scope_id,
                        work.generation,
                        work.marker_id,
                        work.wake_generation,
                        work.callback_depth,
                        work.cpu_owner,
                        work.failure.clone(),
                        work.resume_step.is_some() || work.resume_failure.is_some(),
                    ))
                })
            })
            .transpose()?
        else {
            return Ok(false);
        };
        if self.callback_kinds.len() < callback_depth {
            return Err(invalid_wait(
                "parked modal work lost its enclosing guest callback",
            ));
        }
        if self.callback_kinds.len() != callback_depth || !guest_dispatch_allowed {
            return Ok(false);
        }
        if cpu.interrupt_shadow_active() {
            return Err(invalid_wait(
                "parked modal guest work has no safe guest callback boundary",
            ));
        }

        if cpu_owner.is_none() {
            let owner = self.capture_legacy_cpu_parked_frame(cpu, dos, memory)?;
            self.window_operations
                .last_mut()
                .and_then(|frame| frame.pending_modal_work.as_mut())
                .ok_or_else(|| invalid_wait("parked modal work disappeared during CPU capture"))?
                .cpu_owner = Some(owner);
        }
        if resume_cached {
            return self.complete_parked_window_resume(cpu, dos, memory, host, true);
        }

        // Modal guest-work keeps the exact native USER source parked. Poll
        // the independent drop-retirement transport without resuming that
        // modal source or consuming its marker history.
        let _ = self.poll_native_drop_retirement(host)?;

        if let Some(failure) = failure {
            return Err(RuntimeError::with_source(
                failure.kind(),
                "Win16 modal guest-work ingress failed; teardown must obtain the real native-return receipt",
                failure,
            ));
        }

        if self.service_classic_dde_safe_point(cpu, dos, memory, host)? {
            return Ok(true);
        }

        // Modal pumping is another API safe point. Use the same owned WAVE
        // event and source-receipt path as USER waits before resuming native
        // code; a modal marker itself does not complete any source callback.
        self.poll_network_events(memory, host)?;
        self.dispatch_pending_network_print_notification(host)?;
        self.poll_wave_events(memory, host, true)?;
        self.poll_sound(memory, host)?;
        if matches!(
            self.dispatch_pending_netbios_notification(cpu, memory, host)?,
            super::netbios_async::NetbiosDispatch::CallbackEntered
        ) {
            return Ok(false);
        }
        if self.dispatch_pending_wave_function_callback(cpu, memory, host)? {
            return Ok(false);
        }
        if !self.dispatch_pending_midi_notification(cpu, memory, host)? {
            // Keep the exact native modal continuation parked for the guest
            // MIDI callback and its source-identity return receipt.
            return Ok(false);
        }
        if self.service_pending_window_dde_callback(
            cpu,
            dos,
            memory,
            host,
            guest_dispatch_allowed,
        )? {
            return Ok(true);
        }

        if let Some(event) = host.win16_take_guest_callback()? {
            let entered = self
                .begin_asynchronous_guest_callback(cpu, memory, event)?
                .is_some();
            return Ok(!entered);
        }
        if let Some(step) = host.win16_dde_poll_callback()? {
            let frame = step.frame;
            self.capture_dde_guest_context(cpu, dos, memory, frame)?;
            let origin = Win16DdeCallbackOrigin::GuestExecution { frame };
            if let Some((origin, next)) =
                self.begin_dde_callback(step, origin, cpu, dos, memory, host)?
            {
                self.route_dde_callback_step(cpu, dos, memory, host, origin, next)?;
            }
            while self.restore_next_dde_context(cpu, dos, memory)? {}
            return Ok(self.callback_kinds.len() == callback_depth);
        }

        self.restore_parked_window_work(cpu, dos, memory, true)?;
        let result = host.win16_window_resume_modal_guest_work(
            operation,
            scope_id,
            generation,
            marker_id,
            wake_generation,
        );
        self.cache_parked_window_resume(true, result)?;
        self.complete_parked_window_resume(cpu, dos, memory, host, true)
    }

    fn restore_parked_window_work(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        modal: bool,
    ) -> Result<(), RuntimeError> {
        let owner = self
            .window_operations
            .last()
            .and_then(|frame| {
                if modal {
                    frame
                        .pending_modal_work
                        .as_ref()
                        .and_then(|work| work.cpu_owner)
                } else {
                    frame.pending_work.as_ref().and_then(|work| work.cpu_owner)
                }
            })
            .ok_or_else(|| invalid_wait("parked USER work has no retained CPU owner"))?;
        self.restore_legacy_cpu_parked_frame(owner, cpu, dos, memory)?;
        Ok(())
    }

    fn cache_parked_window_resume(
        &mut self,
        modal: bool,
        result: Result<Win16WindowStep, RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| {
            invalid_wait("parked USER operation disappeared at host resume boundary")
        })?;
        let (resume_step, resume_failure) = if modal {
            let work = frame.pending_modal_work.as_mut().ok_or_else(|| {
                invalid_wait("parked modal work disappeared at host resume boundary")
            })?;
            (&mut work.resume_step, &mut work.resume_failure)
        } else {
            let work = frame.pending_work.as_mut().ok_or_else(|| {
                invalid_wait("parked USER work disappeared at host resume boundary")
            })?;
            (&mut work.resume_step, &mut work.resume_failure)
        };
        if resume_step.is_some() || resume_failure.is_some() {
            return Err(invalid_wait("parked USER host resume was already recorded"));
        }
        match result {
            Ok(step) => {
                *resume_step = Some(step);
                Ok(())
            }
            Err(error) => {
                let retained = std::sync::Arc::new(error);
                let returned =
                    super::callback_lifo::shared_runtime_error(std::sync::Arc::clone(&retained));
                *resume_failure = Some(retained);
                Err(returned)
            }
        }
    }

    fn complete_parked_window_resume(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        modal: bool,
    ) -> Result<bool, RuntimeError> {
        let (frame_id, operation, generation, callback_depth, owner, has_step, failure) = {
            let frame = self.window_operations.last().ok_or_else(|| {
                invalid_wait("parked USER operation disappeared before cached resume")
            })?;
            if modal {
                let work = frame.pending_modal_work.as_ref().ok_or_else(|| {
                    invalid_wait("parked modal work disappeared before cached resume")
                })?;
                (
                    work.frame_id,
                    work.host_operation,
                    work.generation,
                    work.callback_depth,
                    work.cpu_owner,
                    work.resume_step.is_some(),
                    work.resume_failure.clone(),
                )
            } else {
                let work = frame.pending_work.as_ref().ok_or_else(|| {
                    invalid_wait("parked USER work disappeared before cached resume")
                })?;
                (
                    work.frame_id,
                    work.host_operation,
                    work.generation,
                    work.callback_depth,
                    work.cpu_owner,
                    work.resume_step.is_some(),
                    work.resume_failure.clone(),
                )
            }
        };
        if let Some(failure) = failure {
            return Err(super::callback_lifo::shared_runtime_error(failure));
        }
        if !has_step {
            return Err(invalid_wait(
                "parked USER work has no cached native resume result",
            ));
        }
        let matches = self.window_operations.last().is_some_and(|frame| {
            frame.id == frame_id
                && if modal {
                    frame.host_modal_operation == Some(operation)
                        && frame.pending_modal_work.as_ref().is_some_and(|work| {
                            work.frame_id == frame_id
                                && work.generation == generation
                                && work.callback_depth == callback_depth
                                && work.cpu_owner == owner
                                && work.resume_step.is_some()
                        })
                } else {
                    frame.host_wait == Some(operation)
                        && frame.pending_work.as_ref().is_some_and(|work| {
                            work.frame_id == frame_id
                                && work.generation == generation
                                && work.callback_depth == callback_depth
                                && work.cpu_owner == owner
                                && work.resume_step.is_some()
                        })
                }
        });
        if !matches || self.callback_kinds.len() != callback_depth {
            return Err(invalid_wait(
                "parked USER owner changed before cached resume retirement",
            ));
        }
        let owner = owner.ok_or_else(|| {
            invalid_wait("parked USER host result has no exact checked CPU owner")
        })?;
        self.restore_legacy_cpu_parked_frame(owner, cpu, dos, memory)?;
        self.release_legacy_cpu_frame(owner, dos, memory)?;

        let frame = self
            .window_operations
            .last_mut()
            .ok_or_else(|| invalid_wait("parked USER frame disappeared after owner release"))?;
        let step =
            if modal {
                let work = frame.pending_modal_work.as_mut().ok_or_else(|| {
                    invalid_wait("parked modal work disappeared after owner release")
                })?;
                work.cpu_owner = None;
                work.resume_step.take().ok_or_else(|| {
                    invalid_wait("parked modal work lost its cached native resume step")
                })?
            } else {
                let work = frame.pending_work.as_mut().ok_or_else(|| {
                    invalid_wait("parked USER work disappeared after owner release")
                })?;
                work.cpu_owner = None;
                work.resume_step.take().ok_or_else(|| {
                    invalid_wait("parked USER work lost its cached native resume step")
                })?
            };
        if modal {
            frame.pending_modal_work = None;
            frame.last_modal_work_generation = generation;
        } else {
            frame.pending_work = None;
            frame.last_work_generation = generation;
        }
        self.advance_window_operation(&mut cpu.regs, memory, host, step)?;
        self.drive_pending_window_completion(cpu, memory, dos, host)?;
        Ok(true)
    }
}

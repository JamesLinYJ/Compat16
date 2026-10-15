//! KERNEL WaitEvent suspension over exact runtime-owned task and CPU roots.
//!
//! WaitEvent is not declared in the public Windows 3.1 WINDOWS.H. Its WORD
//! task argument/return match the export catalog and KERNEL31 CONTEXT.ASM:
//! consume a task event, returning zero immediately or nonzero after yielding.
//! No native USER message or readiness hint is fabricated into a task event.
use super::{Win16State, task_state::TaskEventTarget};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};
use dos_kernel::DosKernel;
use guest_core::{OwnerId, Registers, memory::Memory};
use std::time::{Duration, Instant};
use win16_abi::Win16ReturnKind;
use x86_cpu::{Cpu, LegacyCpuCheckpointStamp};

const POLL_INTERVAL: Duration = Duration::from_millis(16);
#[derive(Clone, Copy)]
enum Phase {
    Waiting,
    EventConsumed,
    Returned,
}
pub(super) struct PendingTaskEventWait {
    caller: OwnerId,
    target: TaskEventTarget,
    cpu_owner: u64,
    stamp: LegacyCpuCheckpointStamp,
    registers: Registers,
    return_to: (u16, u16, u32),
    callback_depth: usize,
    yielded: bool,
    phase: Phase,
    next_poll: Instant,
}
impl Win16State {
    pub(super) fn begin_task_event_wait(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        task: u16,
        return_to: (u16, u16, u32),
    ) -> Result<(), RuntimeError> {
        let target = self.task_event_target(task, memory)?;
        let caller = self
            .tasks
            .current()
            .ok_or_else(|| invariant("task wait has no running caller"))?;
        let stamp = cpu.legacy_checkpoint_stamp().map_err(checkpoint_error)?;
        self.task_event_waits.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve a Win16 task-event wait",
                error,
            )
        })?;
        // This frame owns selector generations and their backing allocations.
        // Checkpoint stamps alone grant no authority over guest addresses.
        let cpu_owner = self.capture_legacy_cpu_parked_frame(cpu, dos, memory)?;
        self.task_event_waits.push(PendingTaskEventWait {
            caller,
            target,
            cpu_owner,
            stamp,
            registers: cpu.regs.clone(),
            return_to,
            callback_depth: self.callback_kinds.len(),
            yielded: false,
            phase: Phase::Waiting,
            next_poll: Instant::now(),
        });
        if !self.finish_ready_task_event_wait(cpu, dos, memory)? {
            self.task_event_waits
                .last_mut()
                .ok_or_else(|| invariant("task wait disappeared"))?
                .yielded = true;
        }
        Ok(())
    }
    fn finish_ready_task_event_wait(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let Some(frame) = self.task_event_waits.last() else {
            return Ok(false);
        };
        let (owner, target, phase, return_to) =
            (frame.cpu_owner, frame.target, frame.phase, frame.return_to);
        if !matches!(phase, Phase::Returned) {
            let value = if frame.yielded { 0x00ff } else { 0 };
            let transfer = super::call_return::checked_return_target(
                &frame.registers,
                return_to,
                value,
                Win16ReturnKind::Word,
            );
            let stamp = frame.stamp.clone();
            self.retain_legacy_cpu_frame_roots(owner, &transfer.registers, dos, memory)?;
            let prepared =
                self.prepare_legacy_cpu_checkpoint_return(owner, cpu, memory, &stamp, transfer)?;
            if matches!(phase, Phase::Waiting) {
                if !self.take_task_event(target, memory)? {
                    return Ok(false);
                }
                self.task_event_waits
                    .last_mut()
                    .ok_or_else(|| invariant("task wait disappeared during event consumption"))?
                    .phase = Phase::EventConsumed;
            }
            // No CPU mutation/execution intervenes after prepare. The counter
            // write and registry commit above cannot invalidate this transfer.
            // Retain EventConsumed if a return fails; a retry cannot eat a
            // second token or resubmit a source notification.
            cpu.commit_legacy_checkpoint_return(prepared)
                .map_err(checkpoint_error)?;
            self.retire_far_return(return_to.0, u32::from(return_to.1), cpu.regs.ss);
            self.task_event_waits
                .last_mut()
                .ok_or_else(|| invariant("task wait disappeared during return"))?
                .phase = Phase::Returned;
        }
        self.release_legacy_cpu_frame(owner, dos, memory)?;
        self.task_event_waits.pop();
        Ok(true)
    }
    /// True keeps the interpreter parked without charging another service
    /// instruction. False permits actual nested callback instructions to run.
    pub(super) fn service_pending_task_event_wait(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let Some(frame) = self.task_event_waits.last() else {
            return Ok(false);
        };
        if self.callback_kinds.len() < frame.callback_depth {
            return Err(invariant("task wait lost its enclosing callback"));
        }
        if self.callback_kinds.len() != frame.callback_depth {
            return Ok(false);
        }
        if self.tasks.current() != Some(frame.caller) {
            return Err(invariant("task wait resumed under a different task owner"));
        }
        // A classic DDE pump may itself hold a newer exact CPU owner. Let its
        // existing driver restore/retire that owner before touching our frame.
        if self.service_classic_dde_safe_point(cpu, dos, memory, host)? {
            return Ok(true);
        }
        let frame = self
            .task_event_waits
            .last()
            .ok_or_else(|| invariant("task wait disappeared during source progress"))?;
        if !self.legacy_cpu_frame_is_top(frame.cpu_owner) {
            return Err(invariant("task wait is covered by an unserviced CPU owner"));
        }
        if self.finish_ready_task_event_wait(cpu, dos, memory)? {
            return Ok(true);
        }
        let frame = self
            .task_event_waits
            .last_mut()
            .ok_or_else(|| invariant("task wait disappeared before polling"))?;
        let now = Instant::now();
        if now < frame.next_poll {
            // Bound host polling while leaving the guest instruction budget
            // untouched. Native producers retain and signal their own payloads.
            std::thread::sleep((frame.next_poll - now).min(POLL_INTERVAL));
            return Ok(true);
        }
        frame.next_poll = now + POLL_INTERVAL;
        host.pump_events()?;
        self.refresh_pending_window_parents(host)?;
        let _ = self.poll_native_drop_retirement(host)?;
        self.poll_network_events(memory, host)?;
        self.dispatch_pending_network_print_notification(host)?;
        self.poll_wave_events(memory, host, true)?;
        self.poll_sound(memory, host)?;
        if matches!(
            self.dispatch_pending_netbios_notification(cpu, memory, host)?,
            super::netbios_async::NetbiosDispatch::CallbackEntered
        ) || self.dispatch_pending_wave_function_callback(cpu, memory, host)?
            || !self.dispatch_pending_midi_notification(cpu, memory, host)?
            || self.dispatch_pending_toolhelp_notify(cpu, dos, memory)?
        {
            return Ok(false);
        }
        if self.service_pending_window_dde_callback(cpu, dos, memory, host, true)? {
            return Ok(true);
        }
        if let Some(event) = host.win16_take_guest_callback()? {
            return Ok(self
                .begin_asynchronous_guest_callback(cpu, memory, event)?
                .is_none());
        }
        if let Some(step) = host.win16_dde_poll_callback()? {
            let frame = step.frame;
            self.capture_dde_guest_context(cpu, dos, memory, frame)?;
            let origin = super::dde_callback::Win16DdeCallbackOrigin::GuestExecution { frame };
            if let Some((origin, next)) =
                self.begin_dde_callback(step, origin, cpu, dos, memory, host)?
            {
                self.route_dde_callback_step(cpu, dos, memory, host, origin, next)?;
            }
            while self.restore_next_dde_context(cpu, dos, memory)? {}
            return Ok(self.callback_kinds.len()
                == self
                    .task_event_waits
                    .last()
                    .ok_or_else(|| invariant("task wait disappeared during DDE dispatch"))?
                    .callback_depth);
        }
        Ok(true)
    }
}
fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn checkpoint_error(error: x86_cpu::CpuCallResumeError) -> RuntimeError {
    RuntimeError::with_source(Kind::GuestFault, "checked Win16 task-event return", error)
}

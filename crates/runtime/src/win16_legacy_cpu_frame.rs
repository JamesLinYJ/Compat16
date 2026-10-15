//! Runtime-owned caller and parked CPU frames with exact LIFO lease cleanup.

use dos_kernel::DosKernel;
use guest_core::{memory::Memory, Registers};
use win16_abi::SelectorRef;
use x86_cpu::{
    CallEffectPolicy, CallResumeBoundary, LegacyCpuCallContinuation,
    LegacyCpuParkedContinuation, LegacyCpuBinding, LegacyRegisterTransfer,
    LegacyStackPointerTarget, CpuContext,
};

use super::{
    legacy_cpu_binding::{Win16LegacyCpuBinding, Win16LegacyCpuBindingOwner, Win16LegacyCpuBindingProof},
    Win16State, execute::Win16TaskExecutionEnded,
};
use crate::{DiagnosticKind, RuntimeError};

pub(super) struct Win16LegacyCpuFrame {
    pub(super) id: u64,
    saved_registers: Registers,
    saved_context: CpuContext,
    pub(in crate::win16_runtime) owner: Win16LegacyCpuBindingOwner,
    continuation: Win16LegacyCpuContinuation,
    restored: bool,
    terminal_restored: bool,
}

enum Win16LegacyCpuContinuation {
    Call(Option<LegacyCpuCallContinuation<Win16LegacyCpuBindingProof>>),
    Parked(Option<LegacyCpuParkedContinuation<Win16LegacyCpuBindingProof>>, Registers),
    OwnerOnly,
    /// Capture never installed a continuation or changed CPU state.
    CaptureFailed { cause: std::sync::Arc<RuntimeError> },
}

impl Win16State {
    /// Compare against the retained owner snapshot, not the guest CPU state
    /// which may currently be executing a nested callback.
    pub(super) fn legacy_cpu_frame_matches_context(&self, id: u64, context: &CpuContext) -> bool {
        let mut matches = self.legacy_cpu_frames.iter().filter(|frame| frame.id == id);
        let Some(frame) = matches.next() else { return false; };
        matches.next().is_none() && &frame.saved_context == context
    }

    pub(super) fn legacy_cpu_frame_is_top(&self, id: u64) -> bool {
        self.legacy_cpu_frames.last().is_some_and(|frame| frame.id == id)
    }

    pub(super) fn preflight_legacy_cpu_frame(
        &self,
        id: u64,
        cpu: &x86_cpu::Cpu,
    ) -> Result<(), RuntimeError> {
        let mut matches = self.legacy_cpu_frames.iter().filter(|frame| frame.id == id);
        let frame = matches.next().ok_or_else(|| RuntimeError::new(
            DiagnosticKind::InternalInvariant,
            "legacy CPU context preflight has no exact owner frame",
        ))?;
        if matches.next().is_some() {
            return Err(RuntimeError::new(DiagnosticKind::InternalInvariant,
                "legacy CPU context preflight found duplicate owner identities"));
        }
        cpu.check_context(&frame.saved_context).map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::GuestFault,
                "preflight complete Win16 CPU architecture context",
                error,
            )
        })
    }

    pub(super) fn legacy_cpu_frame_owns_selector(&self, reference: SelectorRef) -> bool {
        self.legacy_cpu_frames.iter().any(|frame| frame.owner.owns_selector(reference))
            || self.toolhelp_interrupt_owns_selector(reference)
    }

    pub(super) fn legacy_cpu_owner_owns_selector(
        &self,
        id: u64,
        reference: SelectorRef,
    ) -> bool {
        self.legacy_cpu_frames.iter().any(|frame| {
            frame.id == id && frame.owner.owns_selector(reference)
        })
    }

    pub(super) fn legacy_cpu_frame_saved_code(&self, id: u64) -> Option<(u16, u16)> {
        self.legacy_cpu_frames.iter().find(|frame| frame.id == id)
            .map(|frame| (frame.saved_registers.cs, frame.saved_registers.ip()))
    }

    fn reserve_legacy_cpu_frame(&mut self) -> Result<u64, RuntimeError> {
        self.legacy_cpu_frames.try_reserve(1).map_err(|error| RuntimeError::with_source(
            DiagnosticKind::ResourceExhausted, "reserve a legacy CPU owner frame", error,
        ))?;
        let id = self.next_legacy_cpu_frame;
        self.next_legacy_cpu_frame = id.checked_add(1).ok_or_else(|| RuntimeError::new(
            DiagnosticKind::ResourceExhausted, "legacy CPU owner frame identities exhausted",
        ))?;
        Ok(id)
    }

    pub(super) fn capture_legacy_cpu_call_frame(
        &mut self, cpu: &x86_cpu::Cpu, dos: &mut DosKernel, memory: &mut Memory,
    ) -> Result<u64, RuntimeError> {
        let id = self.reserve_legacy_cpu_frame()?;
        let registers = cpu.regs.clone();
        let saved_context = cpu.capture_context();
        let owner = match self.capture_legacy_cpu_binding_owner(&registers, dos, memory) {
            Ok(owner) => owner,
            Err(error) => {
                let cause = RuntimeError::with_source(DiagnosticKind::GuestFault,
                    "retain Win16 caller selector roots", error.cause);
                return self.rollback_failed_legacy_cpu_capture(id, registers, saved_context,
                    error.owner, cause, dos, memory);
            }
        };
        let ticket = {
            let binding = Win16LegacyCpuBinding::new(self, memory, &owner);
            cpu.capture_legacy_call_continuation(&binding)
        };
        match ticket {
            Ok(ticket) => {
                self.legacy_cpu_frames.push(Win16LegacyCpuFrame {
                    id, saved_registers: registers, saved_context, owner,
                    continuation: Win16LegacyCpuContinuation::Call(Some(ticket)),
                    restored: false,
                    terminal_restored: false,
                });
                Ok(id)
            }
            Err(error) => {
                let cause = RuntimeError::with_source(DiagnosticKind::GuestFault,
                    "capture Win16 caller CPU continuation", error);
                self.rollback_failed_legacy_cpu_capture(id, registers, saved_context,
                    owner, cause, dos, memory)
            }
        }
    }

    pub(super) fn capture_legacy_cpu_parked_frame(
        &mut self, cpu: &x86_cpu::Cpu, dos: &mut DosKernel, memory: &mut Memory,
    ) -> Result<u64, RuntimeError> {
        let id = self.reserve_legacy_cpu_frame()?;
        let registers = cpu.regs.clone();
        let saved_context = cpu.capture_context();
        let owner = match self.capture_legacy_cpu_binding_owner(&registers, dos, memory) {
            Ok(owner) => owner,
            Err(error) => {
                let cause = RuntimeError::with_source(DiagnosticKind::GuestFault,
                    "retain parked USER selector roots", error.cause);
                return self.rollback_failed_legacy_cpu_capture(id, registers, saved_context,
                    error.owner, cause, dos, memory);
            }
        };
        let ticket = {
            let binding = Win16LegacyCpuBinding::new(self, memory, &owner);
            cpu.capture_legacy_parked_continuation(&binding)
        };
        match ticket {
            Ok(ticket) => {
                self.legacy_cpu_frames.push(Win16LegacyCpuFrame {
                    id, saved_registers: registers.clone(), saved_context, owner,
                    continuation: Win16LegacyCpuContinuation::Parked(Some(ticket), registers),
                    restored: false,
                    terminal_restored: false,
                });
                Ok(id)
            }
            Err(error) => {
                let cause = RuntimeError::with_source(DiagnosticKind::GuestFault,
                    "capture parked USER CPU continuation", error);
                self.rollback_failed_legacy_cpu_capture(id, registers, saved_context,
                    owner, cause, dos, memory)
            }
        }
    }

    fn rollback_failed_legacy_cpu_capture(
        &mut self, id: u64, registers: Registers, saved_context: CpuContext,
        mut owner: Win16LegacyCpuBindingOwner, cause: RuntimeError,
        dos: &mut DosKernel, memory: &mut Memory,
    ) -> Result<u64, RuntimeError> {
        // Capture has not changed CPU state. Release partial roots before
        // exposing a failure, so no unregistered owner blocks an older frame.
        if let Err(cleanup) = self.release_legacy_cpu_binding_owner(&mut owner, dos, memory) {
            let cause = std::sync::Arc::new(cause);
            self.legacy_cpu_frames.push(Win16LegacyCpuFrame {
                id, saved_registers: registers, saved_context, owner,
                continuation: Win16LegacyCpuContinuation::CaptureFailed {
                    cause: std::sync::Arc::clone(&cause),
                },
                restored: false, terminal_restored: false,
            });
            return Err(RuntimeError::with_source(DiagnosticKind::GuestFault,
                format!("CPU capture rollback remains owned: {cleanup}"), cause));
        }
        Err(cause)
    }

    /// Only failed captures may be removed before USER source retirement.
    /// They never installed a CPU continuation and require no context restore.
    pub(super) fn retire_failed_legacy_cpu_captures(
        &mut self, _ended: &Win16TaskExecutionEnded,
        dos: &mut DosKernel, memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        while self.legacy_cpu_frames.last().is_some_and(|frame|
            matches!(frame.continuation, Win16LegacyCpuContinuation::CaptureFailed { .. })) {
            let mut frame = self.legacy_cpu_frames.pop().expect("checked exact capture top");
            if let Err(error) = self.release_legacy_cpu_binding_owner(&mut frame.owner, dos, memory) {
                let Win16LegacyCpuContinuation::CaptureFailed { ref cause } = frame.continuation
                    else { unreachable!() };
                let failure = RuntimeError::with_source(DiagnosticKind::GuestFault,
                    format!("terminal CPU capture rollback remains owned: {error}"),
                    std::sync::Arc::clone(cause));
                self.legacy_cpu_frames.push(frame);
                return Err(failure);
            }
        }
        Ok(())
    }

    pub(super) fn retain_legacy_cpu_frame_roots(
        &mut self, id: u64, registers: &Registers, dos: &mut DosKernel, memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let mut frame = self.take_legacy_cpu_frame(id)?;
        let result = self.retain_legacy_cpu_binding_roots(&mut frame.owner, registers, dos, memory);
        self.legacy_cpu_frames.push(frame);
        result.map_err(|error| RuntimeError::with_source(DiagnosticKind::GuestFault,
            "retain Win16 callback target selector roots", error))
    }

    /// A scheduler callback may restore CpuContext and revoke ordinary call
    /// tickets. Require the exact caller register image and revalidate all
    /// selector/backing roots before a narrow checkpoint ABI return. Floating
    /// state and pending CPU events stay live under the callback owner's own
    /// restoration policy; a kernel wait must not rewind them.
    pub(super) fn prepare_legacy_cpu_checkpoint_return(
        &self, id: u64, cpu: &x86_cpu::Cpu, memory: &Memory,
        stamp: &x86_cpu::LegacyCpuCheckpointStamp, target: LegacyRegisterTransfer,
    ) -> Result<x86_cpu::PreparedLegacyCheckpointTransfer, RuntimeError> {
        let frame = self.legacy_cpu_frames.last().filter(|frame| frame.id == id)
            .ok_or_else(|| RuntimeError::new(DiagnosticKind::InternalInvariant,
                "task wait has no exact top CPU backing owner"))?;
        if frame.saved_registers != cpu.regs {
            return Err(RuntimeError::new(DiagnosticKind::GuestFault,
                "task wait cannot return before its caller register image is restored"));
        }
        let mut expected = frame.saved_registers.clone();
        let r = &target.registers;
        expected.cs = r.cs; expected.set_ip(r.ip()); expected.set_sp(r.sp()); expected.set_ax(r.ax());
        if &expected != r {
            return Err(RuntimeError::new(DiagnosticKind::InternalInvariant,
                "task wait return changed registers outside its word-return ABI"));
        }
        let binding_error = |error| RuntimeError::with_source(DiagnosticKind::GuestFault,
            "revalidate retained task-wait selector roots", error);
        let binding = Win16LegacyCpuBinding::new(self, memory, &frame.owner);
        let saved = binding.capture(&frame.saved_registers).map_err(binding_error)?;
        let current = binding.capture(&cpu.regs).map_err(binding_error)?;
        let projected = binding.capture(r).map_err(binding_error)?;
        let transfer = x86_cpu::LegacyBindingTransfer { current: &current, target: &projected,
            current_registers: &cpu.regs, target_registers: r, stack_pointer: target.stack_pointer };
        binding.revalidate(&saved, &current, &transfer).map_err(binding_error)?;
        binding.revalidate(&saved, &projected, &transfer).map_err(binding_error)?;
        let code = self.selectors.pointer_from_raw(guest_core::Selector(r.cs), r.ip())
            .map_err(crate::runtime_error)?;
        self.selectors.translate(code, win16_abi::Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        cpu.prepare_legacy_checkpoint_transfer(stamp, x86_cpu::LegacyCheckpointRegisters {
            cs: r.cs, ip: r.ip(), ss: r.ss, sp: r.sp(), bp: r.bp(), si: r.si(), di: r.di(), ds: r.ds,
            stack_pointer: target.stack_pointer,
        }, r.ax()).map_err(|error| RuntimeError::with_source(DiagnosticKind::GuestFault,
            "prepare checked task-wait ABI return", error))
    }

    pub(super) fn restore_legacy_cpu_call_frame(
        &mut self, id: u64, cpu: &mut x86_cpu::Cpu, memory: &Memory,
        policy: CallEffectPolicy, boundary: CallResumeBoundary,
        target: LegacyRegisterTransfer,
    ) -> Result<(), RuntimeError> {
        self.resume_legacy_cpu_call_frame(id, cpu, memory, policy, boundary, target, false)
    }

    pub(super) fn return_legacy_cpu_call_frame(
        &mut self, id: u64, cpu: &mut x86_cpu::Cpu, memory: &Memory,
        policy: CallEffectPolicy, boundary: CallResumeBoundary,
        target: LegacyRegisterTransfer,
    ) -> Result<(), RuntimeError> {
        self.resume_legacy_cpu_call_frame(id, cpu, memory, policy, boundary, target, true)
    }

    fn resume_legacy_cpu_call_frame(
        &mut self, id: u64, cpu: &mut x86_cpu::Cpu, memory: &Memory,
        policy: CallEffectPolicy, boundary: CallResumeBoundary,
        target: LegacyRegisterTransfer, return_to_caller: bool,
    ) -> Result<(), RuntimeError> {
        let mut frame = self.take_legacy_cpu_frame(id)?;
        let result = if frame.restored {
            Ok(())
        } else {
            let prepared = match &frame.continuation {
                Win16LegacyCpuContinuation::Call(Some(saved)) => {
                    let binding = Win16LegacyCpuBinding::new(self, memory, &frame.owner);
                    cpu.prepare_legacy_call_resume(saved, policy, boundary, target, &binding)
                }
                _ => {
                    self.legacy_cpu_frames.push(frame);
                    return Err(RuntimeError::new(DiagnosticKind::InternalInvariant,
                        "legacy CPU call owner has no retryable captured continuation"));
                }
            };
            match prepared {
                Ok(prepared) => {
                    let binding = Win16LegacyCpuBinding::new(self, memory, &frame.owner);
                    let result = if return_to_caller {
                        cpu.commit_legacy_call_return(prepared, &binding)
                    } else {
                        cpu.commit_legacy_call_resume(prepared, &binding)
                    };
                    if result.is_ok() {
                        frame.continuation = Win16LegacyCpuContinuation::Call(None);
                        frame.restored = true;
                    }
                    result
                }
                Err(error) => Err(error),
            }.map_err(|error| RuntimeError::with_source(DiagnosticKind::GuestFault,
                "restore checked Win16 caller CPU state", error))
        };
        self.legacy_cpu_frames.push(frame);
        result
    }

    pub(super) fn restore_legacy_cpu_parked_frame(
        &mut self, id: u64, cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel, memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let target = self.legacy_cpu_frames.last()
            .filter(|frame| frame.id == id)
            .and_then(|frame| match &frame.continuation {
                Win16LegacyCpuContinuation::Parked(_, registers) => Some(registers.clone()),
                _ => None,
            }).ok_or_else(|| RuntimeError::new(DiagnosticKind::InternalInvariant,
                "parked legacy CPU owner has no retained register target"))?;
        self.restore_legacy_cpu_parked_frame_to(id, cpu, dos, memory, target)
    }

    pub(super) fn restore_legacy_cpu_parked_frame_to(
        &mut self, id: u64, cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel, memory: &mut Memory,
        target: Registers,
    ) -> Result<(), RuntimeError> {
        let mut frame = self.take_legacy_cpu_frame(id)?;
        let result = if frame.restored {
            Ok(())
        } else {
            let prepared = match &frame.continuation {
                Win16LegacyCpuContinuation::Parked(Some(saved), _) => {
                    if let Err(error) = self.retain_legacy_cpu_binding_roots(
                        &mut frame.owner, &target, dos, memory,
                    ) {
                        self.legacy_cpu_frames.push(frame);
                        return Err(RuntimeError::with_source(DiagnosticKind::GuestFault,
                            "retain checked parked CPU return roots", error));
                    }
                    let binding = Win16LegacyCpuBinding::new(self, memory, &frame.owner);
                    cpu.prepare_legacy_parked_resume(saved, CallEffectPolicy::RestoreSavedX87,
                        LegacyRegisterTransfer {
                            registers: target.clone(),
                            stack_pointer: LegacyStackPointerTarget::RegisterValue,
                        },
                        &binding)
                }
                _ => {
                    self.legacy_cpu_frames.push(frame);
                    return Err(RuntimeError::new(DiagnosticKind::InternalInvariant,
                        "parked USER owner has no retryable continuation"));
                }
            };
            match prepared {
                Ok(prepared) => {
                    let binding = Win16LegacyCpuBinding::new(self, memory, &frame.owner);
                    let result = cpu.commit_legacy_parked_resume(prepared, &binding);
                    if result.is_ok() {
                        frame.restored = true;
                        frame.continuation = Win16LegacyCpuContinuation::Parked(None, target);
                    }
                    result
                }
                Err(error) => Err(error),
            }.map_err(|error| RuntimeError::with_source(DiagnosticKind::GuestFault,
                "restore checked parked USER CPU state", error))
        };
        self.legacy_cpu_frames.push(frame);
        result
    }

    pub(super) fn release_legacy_cpu_frame(
        &mut self, id: u64, dos: &mut DosKernel, memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let mut frame = self.take_legacy_cpu_frame(id)?;
        match self.release_legacy_cpu_binding_owner(&mut frame.owner, dos, memory) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.legacy_cpu_frames.push(frame);
                Err(error)
            }
        }
    }

    /// Once the execution loop has really ended and task cleanup has already
    /// quiesced native producers, release retained frame roots in exact LIFO
    /// order. A failed owner release leaves that frame at the top for retry.
    pub(super) fn retire_legacy_cpu_frames_after_task_execution_ended(
        &mut self,
        ended: &Win16TaskExecutionEnded,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        while let Some(id) = self.legacy_cpu_frames.last().map(|frame| frame.id) {
            self.abort_legacy_cpu_frame_after_task_execution_ended(
                ended, id, cpu, dos, memory,
            )?;
        }
        self.task_event_waits.clear();
        Ok(())
    }

    /// Restore the exact full architecture snapshot for one LIFO owner after
    /// the Win16 run loop has stopped. This is a terminal abort path: it never
    /// fabricates a guest RETF/IRET or a normal no-execution return boundary.
    pub(super) fn abort_legacy_cpu_frame_after_task_execution_ended(
        &mut self,
        ended: &Win16TaskExecutionEnded,
        id: u64,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if self.legacy_cpu_frames.last().is_some_and(|frame| frame.id == id
            && matches!(frame.continuation, Win16LegacyCpuContinuation::CaptureFailed { .. })) {
            return self.retire_failed_legacy_cpu_captures(ended, dos, memory);
        }
        self.restore_legacy_cpu_frame_after_task_execution_ended(ended, id, cpu, memory)?;
        let mut frame = self.take_legacy_cpu_frame(id)?;
        match self.release_legacy_cpu_binding_owner(&mut frame.owner, dos, memory) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.legacy_cpu_frames.push(frame);
                Err(error)
            }
        }
    }

    /// Restore a terminally abandoned continuation without releasing any of
    /// its selector or DOS backing roots. Source owners may ACK only after
    /// this succeeds, then release the retained owner through the exact-top
    /// release API. Repeated calls are safe after a later ACK failure.
    pub(super) fn restore_legacy_cpu_frame_after_task_execution_ended(
        &mut self,
        _ended: &Win16TaskExecutionEnded,
        id: u64,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let mut frame = self.take_legacy_cpu_frame(id)?;
        if frame.terminal_restored {
            self.legacy_cpu_frames.push(frame);
            return Ok(());
        }
        if let Err(error) = cpu.check_context(&frame.saved_context) {
            self.legacy_cpu_frames.push(frame);
            return Err(RuntimeError::with_source(DiagnosticKind::GuestFault,
                "validate terminal Win16 CPU frame profile", error));
        }
        // A completed checked restore may have reached a partially successful
        // root release. Its original binding was already validated; terminal
        // cleanup must finish that release without requiring the released roots
        // to become live again. The ended token forbids further guest execution.
        if !frame.restored {
            let proof = {
                let binding = Win16LegacyCpuBinding::new(self, memory, &frame.owner);
                binding.capture(&frame.saved_registers)
            };
            if let Err(error) = proof {
                self.legacy_cpu_frames.push(frame);
                return Err(RuntimeError::with_source(DiagnosticKind::GuestFault,
                    "validate exact terminal Win16 selector roots and generations", error));
            }
        }
        if let Err(error) = cpu.restore_context(&frame.saved_context) {
            self.legacy_cpu_frames.push(frame);
            return Err(RuntimeError::with_source(DiagnosticKind::GuestFault,
                "restore complete terminal Win16 CPU architecture context", error));
        }
        frame.terminal_restored = true;
        frame.continuation = Win16LegacyCpuContinuation::OwnerOnly;
        self.legacy_cpu_frames.push(frame);
        Ok(())
    }

    pub(super) fn release_legacy_cpu_frame_after_task_execution_ended(
        &mut self,
        _ended: &Win16TaskExecutionEnded,
        id: u64,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let frame = self.legacy_cpu_frames.last().filter(|frame| frame.id == id)
            .ok_or_else(|| RuntimeError::new(DiagnosticKind::InternalInvariant,
                "terminal legacy CPU owner is not the exact LIFO top"))?;
        if !frame.terminal_restored {
            return Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
                "terminal legacy CPU owner cannot release before full context restoration"));
        }
        self.release_legacy_cpu_frame(id, dos, memory)
    }

    fn take_legacy_cpu_frame(&mut self, id: u64) -> Result<Win16LegacyCpuFrame, RuntimeError> {
        if self.legacy_cpu_frames.last().is_none_or(|frame| frame.id != id) {
            return Err(RuntimeError::new(DiagnosticKind::InternalInvariant,
                "legacy CPU owner is not the exact LIFO top"));
        }
        self.legacy_cpu_frames.pop().ok_or_else(|| RuntimeError::new(
            DiagnosticKind::InternalInvariant, "legacy CPU owner disappeared at exact-top take",
        ))
    }
}

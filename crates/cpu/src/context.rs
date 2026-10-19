//! Complete modeled CPU context for scheduler-owned interruptions.

use super::{
    ControlTransfer, Cpu, CpuError, CpuModel, Registers,
    system::{ArchitecturalContext, CR0_PE, CpuSystem},
    x87_state,
};
use crate::CpuArchitecturalStateError;
use crate::registers::SegmentRegister;

/// Explicit machine-owned data-segment loads at a real-address ABI boundary.
/// Omitted registers retain their hidden caches, including unreal-mode limits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RealModeDataSegmentOutputs {
    pub ds: Option<u16>,
    pub es: Option<u16>,
    pub fs: Option<u16>,
    pub gs: Option<u16>,
}

/// A snapshot can only be restored into the immutable CPU profile that
/// captured it. The snapshot remains owned by the caller when this is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuContextRestoreError {
    destination_model: CpuModel,
    context_model: CpuModel,
    boundary_sequence_exhausted: bool,
}

impl CpuContextRestoreError {
    /// Whether this restore ran out of nonwrapping continuation identities.
    pub const fn boundary_sequence_exhausted(&self) -> bool {
        self.boundary_sequence_exhausted
    }

    pub const fn destination_model(self) -> CpuModel {
        self.destination_model
    }

    pub const fn context_model(self) -> CpuModel {
        self.context_model
    }
}

impl std::fmt::Display for CpuContextRestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.boundary_sequence_exhausted {
            return formatter.write_str("CPU instruction-boundary sequence is exhausted");
        }
        write!(
            formatter,
            "CPU context profile {} does not match destination profile {}",
            model_name(self.context_model),
            model_name(self.destination_model),
        )
    }
}

impl std::error::Error for CpuContextRestoreError {}

fn model_name(model: CpuModel) -> &'static str {
    match model {
        CpuModel::I486 => "I486",
        CpuModel::PentiumCompat => "PentiumCompat",
        CpuModel::PentiumProCompat => "PentiumProCompat",
    }
}

/// Owned snapshot of the currently modeled CPU state.
#[derive(Clone, Eq, PartialEq)]
pub struct CpuContext {
    pub(super) registers: Registers,
    pub(super) model: CpuModel,
    pub(super) x87: x87_state::X87State,
    pub(super) pending_x87_irq13: bool,
    pub(super) pending_non_maskable_interrupt: bool,
    pub(super) non_maskable_interrupt_blocked: bool,
    pub(super) pending_task_debug_trap: bool,
    pub(super) system: CpuSystem,
    pub(super) halted: bool,
    pub(super) shutdown_reason: Option<CpuError>,
    pub(super) maskable_interrupt_shadow: bool,
    pub(super) debug_exception_shadow: bool,
    pub(super) deferred_data_breakpoint_hits: super::memory_access::DataBreakpointHits,
    pub(super) intermediate_rep_boundary: bool,
    pub(super) control_transfer: Option<ControlTransfer>,
}

impl Cpu {
    /// Publish real-address data-segment outputs with the same cache reload as
    /// a guest segment load. Equal visible values still reload an output;
    /// unrelated CS/SS/data caches remain intact. Reject protected/VM86 or
    /// uninitialized contexts before changing any state.
    pub fn set_real_mode_data_segment_outputs(
        &mut self,
        outputs: RealModeDataSegmentOutputs,
    ) -> Result<(), CpuArchitecturalStateError> {
        if !self.has_architectural_context()
            || self.architectural_execution_mode() != Some(super::CpuExecutionMode::RealAddress)
        {
            return Err(CpuArchitecturalStateError::InvalidControlRegister);
        }
        for (register, value) in [
            (SegmentRegister::Ds, outputs.ds), (SegmentRegister::Es, outputs.es),
            (SegmentRegister::Fs, outputs.fs), (SegmentRegister::Gs, outputs.gs),
        ] {
            if let Some(value) = value {
                match register {
                    SegmentRegister::Ds => self.regs.ds = value,
                    SegmentRegister::Es => self.regs.es = value,
                    SegmentRegister::Fs => self.regs.fs = value,
                    SegmentRegister::Gs => self.regs.gs = value,
                    _ => unreachable!("only data registers are accepted"),
                }
                self.system.load_real_segment(register, value);
            }
        }
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        Ok(())
    }
    /// Import machine-owned architectural mode and hidden state at an explicit
    /// execution boundary. The visible selectors in `regs` must match the
    /// supplied caches. Real-address imports preserve supplied hidden caches,
    /// including caches retained after PE is cleared. This CPU-only interface
    /// has no DOS, Win16, or host types.
    pub fn import_architectural_context(
        &mut self,
        context: ArchitecturalContext,
    ) -> Result<(), CpuArchitecturalStateError> {
        self.system.import_architectural_context(
            context,
            [
                self.regs.cs,
                self.regs.ss,
                self.regs.ds,
                self.regs.es,
                self.regs.fs,
                self.regs.gs,
            ],
            self.regs.eflags,
        )?;
        self.normalize_model_eflags();
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        Ok(())
    }

    /// Refresh real-address hidden caches after the machine owner initializes
    /// the public register file. Calling this while PE is set is rejected so a
    /// protected cache can never be silently replaced with a real-mode one.
    pub fn reset_real_mode_segments_from_visible_registers(
        &mut self,
    ) -> Result<(), CpuArchitecturalStateError> {
        if self.system.cr0 & CR0_PE != 0 {
            return Err(CpuArchitecturalStateError::InvalidControlRegister);
        }
        self.normalize_model_eflags();
        self.system.initialize_real_mode_segments(&self.regs);
        self.system.architectural_context_initialized = true;
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        Ok(())
    }

    /// Capture current architectural state for a scheduler-owned interruption.
    /// Guest memory and device side effects are deliberately not rolled back.
    pub fn capture_context(&self) -> CpuContext {
        CpuContext {
            registers: self.regs.clone(),
            model: self.model,
            x87: self.x87.clone(),
            pending_x87_irq13: self.pending_x87_irq13,
            pending_non_maskable_interrupt: self.pending_non_maskable_interrupt,
            non_maskable_interrupt_blocked: self.non_maskable_interrupt_blocked,
            pending_task_debug_trap: self.pending_task_debug_trap,
            system: self.system,
            halted: self.halted,
            shutdown_reason: self.shutdown_reason.clone(),
            maskable_interrupt_shadow: self.maskable_interrupt_shadow,
            debug_exception_shadow: self.debug_exception_shadow,
            deferred_data_breakpoint_hits: self.deferred_data_breakpoint_hits,
            intermediate_rep_boundary: self.intermediate_rep_boundary,
            control_transfer: self.control_transfer,
        }
    }

    pub fn restore_context(
        &mut self,
        context: &CpuContext,
    ) -> Result<(), CpuContextRestoreError> {
        self.check_context(context)?;
        let next_sequence = self
            .next_call_boundary_sequence()
            .ok_or(CpuContextRestoreError {
                destination_model: self.model,
                context_model: context.model,
                boundary_sequence_exhausted: true,
            })?;
        let next_generation = self.call_continuation_generation.checked_add(1).ok_or(
            CpuContextRestoreError {
                destination_model: self.model,
                context_model: context.model,
                boundary_sequence_exhausted: true,
            },
        )?;
        self.call_boundary_sequence = next_sequence;
        self.call_continuation_generation = next_generation;
        self.control_transfer_sequence = None;
        self.regs = context.registers.clone();
        self.normalize_model_eflags();
        self.x87 = context.x87.clone();
        self.pending_x87_irq13 = context.pending_x87_irq13;
        self.pending_non_maskable_interrupt = context.pending_non_maskable_interrupt;
        self.non_maskable_interrupt_blocked = context.non_maskable_interrupt_blocked;
        self.pending_task_debug_trap = context.pending_task_debug_trap;
        self.system = context.system;
        self.halted = context.halted;
        self.shutdown_reason = context.shutdown_reason.clone();
        self.maskable_interrupt_shadow = context.maskable_interrupt_shadow;
        self.debug_exception_shadow = context.debug_exception_shadow;
        self.deferred_data_breakpoint_hits = context.deferred_data_breakpoint_hits;
        self.intermediate_rep_boundary = context.intermediate_rep_boundary;
        self.control_transfer = context.control_transfer;
        Ok(())
    }

    /// Check whether this exact snapshot belongs to the immutable CPU profile
    /// without changing any architectural state. Scheduler owners use this
    /// before consuming callbacks or continuation frames.
    pub fn check_context(&self, context: &CpuContext) -> Result<(), CpuContextRestoreError> {
        // The profile belongs to the CPU machine, not to a task image. Context
        // snapshots are usable only by the profile from which they were captured.
        if self.model != context.model {
            return Err(CpuContextRestoreError {
                destination_model: self.model,
                context_model: context.model,
                boundary_sequence_exhausted: false,
            });
        }
        Ok(())
    }

    /// SS/STI delay boundaries are unsuitable for scheduler-injected calls,
    /// independently of whether their notification family consults IF.
    pub fn interrupt_shadow_active(&self) -> bool {
        self.maskable_interrupt_shadow
    }
}

#[cfg(test)]
#[path = "context/output_tests.rs"]
mod output_tests;

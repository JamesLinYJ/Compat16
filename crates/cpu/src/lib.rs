//! Portable, safe 16/32-bit x86 instruction interpreter.
//!
//! The core decodes with the upstream `iced-x86` package through a local
//! adapter, then executes instructions against checked guest memory and an
//! explicit emulated I/O bus. The default context is real mode; a supplied
//! segment context selects code/stack sizes. Unsupported behavior is an error.
#![forbid(unsafe_code)]

use std::sync::Arc;

mod arith;
mod error;
mod execute;
mod execution_boundary;
mod flags;
mod guest_descriptor_lease;
mod interrupt;
mod interrupt_delivery;
mod memory;
mod memory_access;
mod memory_values;
mod model;
mod registers;
mod step;
mod system;
mod task_switch;
#[cfg(test)]
mod tests;
mod x86_decode;
mod jit;
pub use jit::{ExecutionEngine, JitStatistics};
#[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
pub use compat16_jit::{Artifact as JitArtifact, ArtifactStore as JitArtifactStore};
mod x87;
mod x87_math;
mod x87_state;
mod x87_transcendental;

use guest_core::Registers;

pub(crate) use arith::{
    ascii_adjust, decimal_adjust, execute_divide, execute_multiply, execute_shift,
};
pub use error::CpuArchitecturalStateError;
pub use error::{CpuCompatibilityGap, CpuError, SegmentAccess, SegmentFaultReason};
pub use guest_descriptor_lease::{
    CpuGuestLdtDataSegmentLease, CpuGuestLdtDescriptorInstallError,
    CpuGuestLdtDescriptorLeaseError,
};
pub(crate) use flags::{
    AF, AluOp, CF, DF, IF, OF, PF, SF, TF, ZF, alu_compute, apply_flags, condition, signed_value,
    update_szp, width_mask,
};
pub use memory::{CpuExecutionMode, RealModeSegments, SegmentResolver};
pub use model::CpuModel;
pub(crate) use registers::{read_register, read_segment, write_register};
pub use system::{
    ArchitecturalContext as CpuArchitecturalContext, CpuSegmentCacheState, CpuSystemSegmentState,
    CpuSystemTables, SystemTableRegister,
};

/// Result of executing one guest instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepOutcome {
    Continue,
    /// Software interrupt; IP has advanced past the INT instruction.
    Interrupt(u8),
    Halt,
}

/// A completed control transfer observed at an execution boundary.
///
/// This decoder-independent event lets the machine owner track guest control
/// flow without exposing iced-x86 types or changing instruction outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlTransfer {
    FarCall {
        /// CS value before the call, used as the saved return selector.
        return_selector: u16,
        /// Next instruction offset after applying the active code-size wrap.
        return_offset: u32,
        /// SS value before the call, identifying the stack that received the frame.
        stack_selector: u16,
    },
    /// A far return completed successfully, including any immediate cleanup.
    FarReturn,
    /// An IRET or IRETD completed successfully and restored an interrupt frame.
    InterruptReturn,
    /// A checked external ABI adapter committed a far caller return. No RETF
    /// instruction was executed; this event is issued only by continuation commit.
    AdapterReturn,
}

impl ControlTransfer {
    pub const fn is_far_return(self) -> bool {
        matches!(self, Self::FarReturn | Self::AdapterReturn)
    }

    pub const fn is_call_return(self) -> bool {
        self.is_far_return() || matches!(self, Self::InterruptReturn)
    }
}

/// Architectural state shared by the instruction engine and machine owner.
pub struct Cpu {
    pub regs: Registers,
    // Nonarchitectural reuse, deliberately excluded from CpuContext. Every
    // hit is checked against bytes fetched from the current memory context.
    decode_cache: x86_decode::DecodeCache,
    jit: jit::IntegerTranslator,
    model: CpuModel,
    x87: x87_state::X87State,
    pending_x87_irq13: bool,
    pending_non_maskable_interrupt: bool,
    non_maskable_interrupt_blocked: bool,
    pending_task_debug_trap: bool,
    system: system::CpuSystem,
    halted: bool,
    shutdown_reason: Option<CpuError>,
    maskable_interrupt_shadow: bool,
    debug_exception_shadow: bool,
    deferred_data_breakpoint_hits: memory_access::DataBreakpointHits,
    /// The immediately preceding execution boundary yielded inside REP.
    /// Event frames use this explicit fact to preserve RF; EIP equality alone
    /// cannot distinguish an unfinished REP from a completed self-branch.
    intermediate_rep_boundary: bool,
    control_transfer: Option<ControlTransfer>,
    /// Identity for continuation tickets created by this CPU instance.
    call_continuation_origin: Arc<u8>,
    /// Monotonic instruction-boundary count. Context restores advance it too.
    call_boundary_sequence: u64,
    /// Invalidates every pre-checkpoint ticket without replacing CPU identity.
    call_continuation_generation: u64,
    /// Latched if an instruction boundary is entered after sequence exhaustion.
    call_boundary_sequence_exhausted: bool,
    /// Provenance from a completed instruction or checked adapter commit, never
    /// from a restored transfer marker.
    control_transfer_sequence: Option<u64>,
    /// Enabled only around a machine-owned step that may inspect CPU events.
    defer_cpu_events: bool,
    deferred_cpu_event: Option<event_observer::CpuDeferredEvent>,
}

mod event_observer;
pub use event_observer::{
    CpuDeferredEvent, CpuDeferredEventCompletionError, CpuDeferredEventResolution,
    CpuDeferredEventResumeError, CpuEventObservation, CpuEventSource,
    CpuGuest16BitReturnFrame, CpuObservedStepOutcome, CpuRealModeReturnFrame,
};

mod context;
pub use context::{CpuContext, CpuContextRestoreError, RealModeDataSegmentOutputs};
mod call_continuation;
pub use call_continuation::{
    CallEffectPolicy, CallResumeBoundary, CpuCallContinuation, CpuCallResumeError,
    CpuEventObserverCompletionError, CpuEventObserverContinuation,
    CpuParkedContinuation, PreparedCallResume, PreparedParkedResume,
};
mod legacy_checkpoint;
pub use legacy_checkpoint::{
    LegacyCheckpointRegisters, LegacyCpuCheckpointStamp, PreparedLegacyCheckpointTransfer,
};
mod legacy_continuation;
pub use legacy_continuation::{
    LegacyBindingTransfer, LegacyCpuBinding, LegacyCpuCallContinuation,
    LegacyCpuContinuationError, LegacyCpuParkedContinuation, LegacyRegisterTransfer,
    LegacyStackPointerTarget, PreparedLegacyCallResume, PreparedLegacyParkedResume,
    PreparedLegacyParkedCallResume,
};

impl Cpu {
    pub fn new(regs: Registers) -> Self {
        Self::new_with_model(regs, CpuModel::default())
    }

    /// Create a CPU with an explicit guest compatibility profile.
    pub fn new_with_model(mut regs: Registers, model: CpuModel) -> Self {
        regs.eflags |= 2;
        regs.eflags = model.normalize_eflags(regs.eflags);
        let system = system::CpuSystem::reset_for_registers(&regs);
        Self {
            regs,
            decode_cache: x86_decode::DecodeCache::default(),
            jit: jit::IntegerTranslator::default(),
            model,
            x87: x87_state::X87State::default(),
            pending_x87_irq13: false,
            pending_non_maskable_interrupt: false,
            non_maskable_interrupt_blocked: false,
            pending_task_debug_trap: false,
            system,
            halted: false,
            shutdown_reason: None,
            maskable_interrupt_shadow: false,
            debug_exception_shadow: false,
            deferred_data_breakpoint_hits: memory_access::DataBreakpointHits::default(),
            intermediate_rep_boundary: false,
            control_transfer: None,
            call_continuation_origin: Arc::new(1),
            call_boundary_sequence: 0,
            call_continuation_generation: 0,
            call_boundary_sequence_exhausted: false,
            control_transfer_sequence: None,
            defer_cpu_events: false,
            deferred_cpu_event: None,
        }
    }

    /// Return the immutable guest compatibility profile selected at creation.
    pub const fn model(&self) -> CpuModel {
        self.model
    }

    /// Select interpreter-only execution or the hot-integer JIT translator.
    /// Single-step execution retains its normal boundary; opt-in integer loops
    /// retire an exact bounded count through the machine scheduler.
    pub fn set_execution_engine(&mut self, engine: ExecutionEngine) {
        self.jit.set_engine(engine);
    }

    pub fn jit_statistics(&self) -> JitStatistics { self.jit.statistics() }
    pub fn execution_engine(&self) -> ExecutionEngine { self.jit.engine() }

    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub fn set_jit_artifact_store(&mut self, store: Option<Arc<dyn JitArtifactStore>>) {
        self.jit.set_artifact_store(store);
    }
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub fn jit_artifact_store(&self) -> Option<Arc<dyn JitArtifactStore>> { self.jit.artifact_store() }

    pub(crate) fn normalize_model_eflags(&mut self) {
        self.regs.eflags = self.model.normalize_eflags(self.regs.eflags);
    }

    /// Read the transfer event from the most recent successful instruction or
    /// checked adapter return. The value is cleared at the next step entry.
    pub fn control_transfer(&self) -> Option<ControlTransfer> {
        self.control_transfer
    }

    pub(crate) fn next_call_boundary_sequence(&self) -> Option<u64> {
        (!self.call_boundary_sequence_exhausted)
            .then(|| self.call_boundary_sequence.checked_add(1))
            .flatten()
    }

    pub(crate) fn invalidate_control_transfer_provenance(&mut self) {
        self.control_transfer_sequence = None;
    }

    /// Return a mode only after the machine has imported or explicitly
    /// initialized CPU-owned hidden state. Legacy selector projection is
    /// intentionally reported as unknown.
    pub fn architectural_execution_mode(&self) -> Option<CpuExecutionMode> {
        self.system
            .architectural_context_initialized
            .then(|| self.system.execution_mode(self.regs.eflags))
            .flatten()
    }

    /// Whether system interrupts and exceptions are owned by the CPU rather
    /// than a legacy checked-selector adapter.
    pub fn has_architectural_context(&self) -> bool {
        self.system.architectural_context_initialized
    }

    /// Whether DOS firmware and service-address interceptions still use the
    /// real-address compatibility boundary. They are never applied while an
    /// imported protected or virtual-8086 context owns instruction fetches.
    pub fn allows_real_mode_service_intercepts(&self) -> bool {
        if self.has_architectural_context() {
            self.architectural_execution_mode() == Some(CpuExecutionMode::RealAddress)
        } else {
            // An unimported context is not evidence that PE is clear. The
            // legacy resolver may own real-mode service addresses only while
            // PE and the virtual-8086 flag both leave the CPU outside those
            // architectural modes. VM with PE clear is not valid guest state,
            // and must not be treated as permission to enter a host service.
            self.system.cr0 & system::CR0_PE == 0 && self.regs.eflags & (1 << 17) == 0
        }
    }

    /// Return the latched triple-fault shutdown cause, if the processor has
    /// entered the modeled shutdown state.
    pub fn shutdown_reason(&self) -> Option<&CpuError> {
        self.shutdown_reason.as_ref()
    }

    /// Consume the pending external x87 error interrupt used when CR0.NE is
    /// clear. The machine owner routes this request through its guest PIC.
    pub fn take_pending_x87_irq13(&mut self) -> bool {
        if self.must_service_cpu_event_before_maskable_interrupt() {
            return false;
        }
        std::mem::replace(&mut self.pending_x87_irq13, false)
    }

    /// Latch an NMI edge from the machine's interrupt controller. This source
    /// is independent of IF and never aliases a maskable vector-2 request.
    pub fn request_non_maskable_interrupt(&mut self) {
        self.pending_non_maskable_interrupt = true;
    }

    /// Whether an NMI is pending and the processor is not in its NMI handler
    /// blocking interval. Machine owners use this to arbitrate NMI before
    /// maskable IRQ and x87 IRQ13 delivery at the same boundary.
    pub fn can_accept_non_maskable_interrupt(&self) -> bool {
        self.shutdown_reason.is_none()
            && self.pending_non_maskable_interrupt
            && !self.non_maskable_interrupt_blocked
    }

    /// Whether a CPU-owned event must be serviced before the machine asks its
    /// PIC for a maskable vector at this boundary.
    pub fn must_service_cpu_event_before_maskable_interrupt(&self) -> bool {
        self.can_accept_non_maskable_interrupt()
            || (self.system.architectural_context_initialized && self.pending_task_debug_trap)
    }

    /// Whether a pending maskable interrupt may be acknowledged at this
    /// instruction boundary. This does not consume a PIC request; callers
    /// should check it before acknowledging a vector. Protected-mode delivery
    /// still requires the caller to use its IDT entry path.
    pub fn can_accept_maskable_interrupt(&self) -> bool {
        self.shutdown_reason.is_none()
            && !self.must_service_cpu_event_before_maskable_interrupt()
            && self.regs.eflags & IF != 0
            && !self.maskable_interrupt_shadow
    }

    /// Read the guest x87 control word without translating or normalizing its
    /// reserved bits. This matches the interpreter's `FNSTCW` behavior.
    pub fn x87_control_word(&self) -> u16 {
        self.x87.control_word
    }

    /// Count occupied physical x87 stack entries. TOP changes their logical
    /// order, while each architectural tag records whether an entry is empty.
    /// This reads only emulated CPU state, independently of host floating point.
    pub fn x87_stack_depth(&self) -> u16 {
        (0..8)
            .filter(|&index| self.x87.tag(index) != x87_state::X87Tag::Empty)
            .count() as u16
    }

    /// Set the guest x87 control word exactly as a guest `FLDCW` does.
    /// Reserved bits are retained as supplied, matching the instruction path.
    pub fn set_x87_control_word(&mut self, control_word: u16) {
        self.x87.set_control_word(control_word);
    }

    /// Reset x87 environment state to `FNINIT` defaults.
    ///
    /// As with the instruction, physical register payloads are left alone;
    /// all stack tags are marked empty and the environment fields are reset.
    pub fn reset_x87(&mut self) {
        self.x87.reset();
    }

    /// Clear x87 exception flags, stack-fault state, and pending summary bits
    /// as `FNCLEX` does, while preserving TOP and condition-code bits.
    pub fn clear_x87_exceptions(&mut self) {
        self.x87.clear_exceptions();
    }
}

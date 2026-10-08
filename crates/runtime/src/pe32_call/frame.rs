use guest_core::{MemoryError, PhysAddr, memory::Memory};
use x86_cpu::Cpu;

use crate::pe32::{
    Pe32CallCompletion, Pe32CallLease, Pe32CallLeaseState, Pe32CallReason, Pe32CallableTarget,
    Pe32ModuleRegistry,
};
use crate::{DiagnosticKind as Kind, RuntimeError};

use super::environment::{Pe32GuestCodeRange, Pe32GuestExecutionEnvironment, validate_guest_ram};

const MAX_DWORD_ARGUMENTS: usize = 32;
const RETURN_GATE_MARKER: [u8; 2] = [0x0f, 0x0b]; // UD2: missed gate dispatch faults closed.
const DIRECTION_FLAG: u32 = 1 << 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32CallConvention {
    Cdecl,
    Stdcall,
}

/// Unique scheduler-side identity for the active call-continuation gate.
///
/// The token is never written into guest memory. The scheduler must compare it
/// against the top call frame before treating a matching CS:EIP as a return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32CallNonce(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32ReturnObservation {
    NotReturned,
    Returned(u32),
}

enum PreparedState {
    Entered,
    Finished,
}

/// An executing x86 call. It owns the complete pre-call CPU snapshot and the
/// registry lease until exactly one return/fault finalization is attempted.
#[must_use = "an executing PE32 call must be finished on return, fault, or limit"]
pub(crate) struct Pe32ExecutingCall {
    lease: Pe32CallLease,
    state: PreparedState,
    saved_context: Option<x86_cpu::CpuContext>,
    environment: Pe32GuestExecutionEnvironment,
    expected_return_stack_pointer: u32,
    nonce: Pe32CallNonce,
}

impl Pe32ExecutingCall {
    pub(crate) const fn nonce(&self) -> Pe32CallNonce {
        self.nonce
    }

    pub(crate) const fn is_finished(&self) -> bool {
        matches!(self.state, PreparedState::Finished)
    }

    pub(crate) fn segment_resolver(&self) -> super::environment::Pe32SegmentResolver<'_> {
        self.environment.resolver()
    }

    /// Refresh code visibility after a service has changed the exact live PE32
    /// module set. The caller supplies a bounded registry-derived snapshot.
    pub(crate) fn refresh_executable_ranges(
        &mut self,
        active_nonce: Pe32CallNonce,
        ranges: Vec<Pe32GuestCodeRange>,
    ) -> Result<(), RuntimeError> {
        self.ensure_nonce(active_nonce)?;
        if !matches!(self.state, PreparedState::Entered) {
            return Err(invariant(
                "PE32 executable map refreshed outside an executing call",
            ));
        }
        self.environment.replace_executable_ranges(ranges)
    }

    /// Inspect only an instruction-boundary state. The CPU loop must call this
    /// before fetching the UD2 byte at the reserved gate.
    pub(crate) fn observe_return(
        &self,
        cpu: &Cpu,
        active_nonce: Pe32CallNonce,
    ) -> Result<Pe32ReturnObservation, RuntimeError> {
        self.ensure_nonce(active_nonce)?;
        if !matches!(self.state, PreparedState::Entered) {
            return Err(invariant(
                "PE32 return was observed outside an executing call",
            ));
        }
        let code = self.environment.code_selector;
        if cpu.regs.cs != code || cpu.regs.eip != self.environment.return_gate_offset {
            return Ok(Pe32ReturnObservation::NotReturned);
        }
        if cpu.regs.ss != self.environment.stack_selector
            || cpu.regs.esp != self.expected_return_stack_pointer
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "PE32 call reached its continuation gate with an invalid SS:ESP cleanup state",
            ));
        }
        Ok(Pe32ReturnObservation::Returned(cpu.regs.eax))
    }

    /// Finish when execution reaches the checked continuation gate; preserve EAX.
    pub(crate) fn finish_return(
        &mut self,
        registry: &mut Pe32ModuleRegistry,
        cpu: &mut Cpu,
        active_nonce: Pe32CallNonce,
    ) -> Result<Pe32CallCompletion, RuntimeError> {
        let value = match self.observe_return(cpu, active_nonce)? {
            Pe32ReturnObservation::Returned(value) => value,
            Pe32ReturnObservation::NotReturned => {
                return Err(invariant(
                    "PE32 completion was requested before its continuation gate",
                ));
            }
        };
        self.finish(registry, cpu, Ok(value))
    }

    /// Finish an entered guest call after an x86 fault, storage failure, or
    /// execution limit. Executing leases are never cancelled as Prepared.
    pub(crate) fn finish_fault(
        &mut self,
        registry: &mut Pe32ModuleRegistry,
        cpu: &mut Cpu,
        active_nonce: Pe32CallNonce,
        error: RuntimeError,
    ) -> Result<Pe32CallCompletion, RuntimeError> {
        self.ensure_nonce(active_nonce)?;
        if !matches!(self.state, PreparedState::Entered) {
            return Err(invariant(
                "PE32 fault completion was requested outside an executing call",
            ));
        }
        self.finish(registry, cpu, Err(error))
    }

    fn finish(
        &mut self,
        registry: &mut Pe32ModuleRegistry,
        cpu: &mut Cpu,
        outcome: Result<u32, RuntimeError>,
    ) -> Result<Pe32CallCompletion, RuntimeError> {
        let Some(context) = self.saved_context.as_ref() else {
            let error = invariant("PE32 call lost its saved CPU context");
            return Err(match outcome {
                Ok(_) => error,
                Err(operation) => operation.with_cleanup(
                    "restore the PE32 call's saved CPU context",
                    error,
                ),
            });
        };
        if let Err(restore_error) = cpu.restore_context(context) {
            let restore_error = RuntimeError::from(restore_error);
            return Err(match outcome {
                Ok(_) => restore_error,
                Err(operation) => operation.with_cleanup(
                    "restore the PE32 call's saved CPU context",
                    restore_error,
                ),
            });
        }
        let result = registry.finish_guest_call(&self.lease, outcome);
        self.saved_context = None;
        self.state = PreparedState::Finished;
        result
    }

    fn ensure_nonce(&self, supplied: Pe32CallNonce) -> Result<(), RuntimeError> {
        if self.nonce != supplied {
            return Err(invariant(
                "PE32 return gate nonce does not match the active call frame",
            ));
        }
        Ok(())
    }
}

/// Prepare guest stack/gate storage, transition the lease, and enter PE32 code.
/// All fallible memory checks and writes occur before `begin_call`; after a
/// successful transition only infallible register assignments remain.
pub(crate) fn begin_pe32_call(
    registry: &mut Pe32ModuleRegistry,
    cpu: &mut Cpu,
    memory: &mut Memory,
    lease: Pe32CallLease,
    environment: Pe32GuestExecutionEnvironment,
) -> Result<Pe32ExecutingCall, RuntimeError> {
    if registry.lease_state(lease.id()) != Some(Pe32CallLeaseState::Prepared) {
        return Err(invariant(
            "PE32 call frame requires the exact lease in Prepared state",
        ));
    }
    let prepared = match environment
        .validate()
        .and_then(|()| prepare_guest_frame(cpu, memory, &lease, environment))
    {
        Ok(frame) => frame,
        Err(error) => return Err(cancel_after_error(registry, &lease, error)),
    };
    if let Err(error) = registry.begin_call(&lease) {
        return Err(cancel_after_error(registry, &lease, error));
    }

    let mut registers = cpu.regs.clone();
    registers.cs = prepared.environment.code_selector;
    registers.eip = prepared.target_offset;
    registers.ss = prepared.environment.stack_selector;
    registers.esp = prepared.entry_stack_pointer;
    registers.ds = prepared.environment.data_selector;
    registers.es = prepared
        .environment
        .es_selector
        .unwrap_or(prepared.environment.data_selector);
    registers.fs = prepared.environment.fs_selector.unwrap_or(0);
    registers.gs = prepared.environment.gs_selector.unwrap_or(0);
    // The Win32 x86 ABI enters with DF clear. Preserve the remaining caller
    // flags; full Win16 state is restored after return/fault.
    registers.eflags = (registers.eflags | 2) & !DIRECTION_FLAG;
    cpu.regs = registers;

    Ok(Pe32ExecutingCall {
        lease,
        state: PreparedState::Entered,
        saved_context: Some(prepared.saved_context),
        environment: prepared.environment,
        expected_return_stack_pointer: prepared.expected_return_stack_pointer,
        nonce: prepared.nonce,
    })
}

struct PreparedFrame {
    saved_context: x86_cpu::CpuContext,
    environment: Pe32GuestExecutionEnvironment,
    target_offset: u32,
    entry_stack_pointer: u32,
    expected_return_stack_pointer: u32,
    nonce: Pe32CallNonce,
}

fn prepare_guest_frame(
    cpu: &Cpu,
    memory: &mut Memory,
    lease: &Pe32CallLease,
    environment: Pe32GuestExecutionEnvironment,
) -> Result<PreparedFrame, RuntimeError> {
    let Pe32CallableTarget::GuestCode { address } = lease.target();
    let arguments = lease.arguments();
    if arguments.len() > MAX_DWORD_ARGUMENTS {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "PE32 call frame exceeds the supported 32 DWORD argument limit",
        ));
    }
    let fixed_lifecycle_arguments = match lease.reason() {
        Pe32CallReason::ProcessAttach => Some([arguments.first().copied().unwrap_or(0), 1, 0]),
        Pe32CallReason::ProcessDetach => Some([arguments.first().copied().unwrap_or(0), 0, 0]),
        Pe32CallReason::Export => None,
    };
    if let Some(expected) = fixed_lifecycle_arguments
        && (lease.convention() != Pe32CallConvention::Stdcall || arguments != expected.as_slice())
    {
        return Err(invariant(
            "PE32 DLL lifecycle lease does not contain its fixed stdcall DllMain arguments",
        ));
    }

    let target_offset = environment.validate_target(address.0, memory)?;
    let code = environment.code_segment()?;
    let stack = environment.stack_segment()?;
    let argument_bytes = u32::try_from(arguments.len())
        .ok()
        .and_then(|count| count.checked_mul(4))
        .ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "PE32 argument extent overflowed")
        })?;
    let frame_bytes = argument_bytes.checked_add(4).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "PE32 return frame extent overflowed",
        )
    })?;
    let entry_stack_pointer = environment
        .stack
        .top_offset
        .checked_sub(frame_bytes)
        .filter(|pointer| *pointer >= environment.stack.start_offset)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::GuestFault,
                "PE32 guest stack has insufficient space for the call frame",
            )
        })?;
    let expected_return_stack_pointer = match lease.convention() {
        Pe32CallConvention::Cdecl => entry_stack_pointer.checked_add(4),
        Pe32CallConvention::Stdcall => entry_stack_pointer.checked_add(frame_bytes),
    }
    .ok_or_else(|| RuntimeError::new(Kind::GuestFault, "PE32 return ESP overflowed"))?;
    if expected_return_stack_pointer > environment.stack.end_offset
        || expected_return_stack_pointer > stack.limit.saturating_add(1)
    {
        return Err(invariant(
            "PE32 expected return ESP exceeds its checked stack range",
        ));
    }

    let stack_linear = u64::from(stack.base) + u64::from(entry_stack_pointer);
    let stack_linear = u32::try_from(stack_linear)
        .map(PhysAddr)
        .map_err(|_| invariant("PE32 stack address overflowed"))?;
    let gate_linear = u64::from(code.base) + u64::from(environment.return_gate_offset);
    let gate_linear = u32::try_from(gate_linear)
        .map(PhysAddr)
        .map_err(|_| invariant("PE32 return gate address overflowed"))?;
    validate_guest_ram(
        memory,
        stack_linear,
        frame_bytes as usize,
        true,
        "PE32 call stack is not writable guest RAM",
    )?;
    validate_guest_ram(
        memory,
        gate_linear,
        RETURN_GATE_MARKER.len(),
        true,
        "PE32 runtime return gate is not writable guest RAM",
    )?;

    let mut stack_image = Vec::new();
    stack_image
        .try_reserve_exact(frame_bytes as usize)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 call stack bytes",
                error,
            )
        })?;
    stack_image.extend_from_slice(&environment.return_gate_offset.to_le_bytes());
    for argument in arguments {
        stack_image.extend_from_slice(&argument.to_le_bytes());
    }

    // Preflight both ranges before either write. A backing-store error remains
    // fatal and is never undone by replaying a guessed snapshot.
    memory
        .write_physical(gate_linear, &RETURN_GATE_MARKER)
        .map_err(|error| memory_error("write PE32 reserved return gate", error))?;
    memory
        .write_physical(stack_linear, &stack_image)
        .map_err(|error| memory_error("stage PE32 guest call stack", error))?;

    Ok(PreparedFrame {
        saved_context: cpu.capture_context(),
        environment,
        target_offset,
        entry_stack_pointer,
        expected_return_stack_pointer,
        nonce: Pe32CallNonce(lease.id().raw()),
    })
}

fn cancel_after_error(
    registry: &mut Pe32ModuleRegistry,
    lease: &Pe32CallLease,
    original: RuntimeError,
) -> RuntimeError {
    match registry.cancel_prepared_call(lease) {
        Ok(()) => original,
        Err(cancel) => RuntimeError::with_source(
            Kind::InternalInvariant,
            "PE32 call preparation and Prepared lease cancellation both failed",
            PreparedLeaseCancellationError {
                primary: original,
                cancellation: cancel,
            },
        ),
    }
}

#[derive(Debug)]
struct PreparedLeaseCancellationError {
    primary: RuntimeError,
    cancellation: RuntimeError,
}

impl std::fmt::Display for PreparedLeaseCancellationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "primary: {}; cancellation: {}",
            self.primary, self.cancellation
        )
    }
}

impl std::error::Error for PreparedLeaseCancellationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

fn memory_error(message: &'static str, error: MemoryError) -> RuntimeError {
    let kind = match &error {
        MemoryError::StorageAccess { .. } => Kind::HostFailure,
        MemoryError::AllocationFailed => Kind::ResourceExhausted,
        _ => Kind::InternalInvariant,
    };
    RuntimeError::with_source(kind, message, error)
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

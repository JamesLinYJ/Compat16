//! One-boundary PE32 guest driver; orchestration owns frames and service work.
//!
//! This keeps PE32 stepping out of the Win16 scheduler. Callers observe an
//! exact service gate before fetch, dispatch an owned request, then resume the
//! same frame. INT/HLT and incomplete ring-3, TEB/TLS and SEH behavior remain
//! explicit faults rather than being routed through Win16 machinery.

mod memory;

use guest_core::{io::NoPorts, memory::Memory};
use x86_cpu::{Cpu, StepOutcome};

use crate::{DiagnosticKind as Kind, RuntimeError};
use crate::pe32_call::{Pe32CallNonce, Pe32ExecutingCall, Pe32ReturnObservation};

use self::memory::{Pe32RamMemory, disallowed_device_access};

pub(crate) enum Pe32CallBoundary {
    Returned,
    ServiceGate(u32),
    CpuStep,
    Fault(RuntimeError),
}

/// Advance through at most one actual CPU step or stop at a checked boundary.
/// The caller owns finalization so a nested service can pause this exact frame.
pub(crate) fn step_pe32_call(
    cpu: &mut Cpu,
    memory: &mut Memory,
    frame: &Pe32ExecutingCall,
    active_nonce: Pe32CallNonce,
    is_service_gate: impl FnOnce(u16, u32) -> bool,
    before_instruction: impl FnOnce() -> Result<(), RuntimeError>,
) -> Result<Pe32CallBoundary, RuntimeError> {
    if frame.nonce() != active_nonce {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "PE32 frame nonce differs from its active dispatcher lease"));
    }
    if let Some(error) = memory.storage_failure() {
        return Err(crate::runtime_error(error).with_context("PE32 guest memory backing"));
    }
    match frame.observe_return(cpu, active_nonce)? {
        Pe32ReturnObservation::Returned(_) => return Ok(Pe32CallBoundary::Returned),
        Pe32ReturnObservation::NotReturned => {}
    }
    if is_service_gate(cpu.regs.cs, cpu.regs.eip) {
        return Ok(Pe32CallBoundary::ServiceGate(cpu.regs.eip));
    }

    // A return or service boundary consumes no instruction budget. Check only
    // after those exact boundaries are observed and before the CPU can mutate
    // guest state with one more instruction.
    before_instruction()?;

    let instruction = (cpu.regs.cs, cpu.regs.eip);
    let (outcome, rejected_device_range) = {
        let mut guest_memory = Pe32RamMemory::new(memory);
        let mut ports = NoPorts;
        let segments = frame.segment_resolver();
        let outcome = cpu.step_with_context(&mut guest_memory, &mut ports, &segments);
        (outcome, guest_memory.take_device_rejection())
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            let primary = match memory.storage_failure() {
                Some(storage) => crate::runtime_error(storage),
                None => match rejected_device_range {
                    Some(device) => disallowed_device_access(device),
                    None => crate::runtime_error(error),
                },
            };
            return Err(primary.with_context(instruction_context(instruction)));
        }
    };
    if let Some(error) = memory.storage_failure() {
        return Err(crate::runtime_error(error)
            .with_context(instruction_context(instruction))
            .with_context("PE32 guest memory backing"));
    }
    if let Some(error) = rejected_device_range {
        return Err(disallowed_device_access(error).with_context(instruction_context(instruction)));
    }
    match outcome {
        StepOutcome::Continue => Ok(Pe32CallBoundary::CpuStep),
        StepOutcome::Interrupt(vector) => Ok(Pe32CallBoundary::Fault(RuntimeError::new(Kind::CompatibilityGap,
            format!("PE32 software interrupt 0x{vector:02X} needs unsupported interrupt/SEH delivery"))
            .with_context(instruction_context(instruction)))),
        StepOutcome::Halt => Ok(Pe32CallBoundary::Fault(RuntimeError::new(Kind::CompatibilityGap,
            "PE32 HLT needs guest privilege and task-scheduling behavior not modeled here")
            .with_context(instruction_context(instruction)))),
    }
}

fn instruction_context((selector, offset): (u16, u32)) -> String {
    format!("PE32 instruction at {selector:04X}:{offset:08X}")
}

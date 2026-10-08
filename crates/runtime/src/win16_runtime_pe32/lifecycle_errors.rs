//! Typed call-boundary errors that retain setup and guest-fault causes.

use std::{error::Error, fmt};

use x86_cpu::Cpu;

use crate::pe32::{Pe32CallCompletion, Pe32CallLease, Pe32ModuleRegistry};
use crate::pe32_call::{Pe32CallNonce, Pe32ExecutingCall};
use crate::{DiagnosticKind as Kind, RuntimeError};

pub(super) fn cancel_prepared(
    registry: &mut Pe32ModuleRegistry,
    lease: &Pe32CallLease,
    primary: RuntimeError,
) -> RuntimeError {
    match registry.cancel_prepared_call(lease) {
        Ok(()) => primary,
        Err(cleanup) => RuntimeError::with_source(
            Kind::InternalInvariant,
            "PE32 call setup failed and its Prepared lease could not be cancelled",
            PreparedCancelFailure { primary, cleanup },
        ),
    }
}

pub(super) fn finish_fault(
    registry: &mut Pe32ModuleRegistry,
    cpu: &mut Cpu,
    frame: &mut Pe32ExecutingCall,
    nonce: Pe32CallNonce,
    primary: RuntimeError,
) -> Result<Pe32CallCompletion, RuntimeError> {
    match frame.finish_fault(registry, cpu, nonce, primary) {
        Err(error) => Err(error),
        Ok(_) => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "PE32 fault path unexpectedly completed as a normal return",
        )),
    }
}

#[derive(Debug)]
struct PreparedCancelFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl fmt::Display for PreparedCancelFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; cancellation failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for PreparedCancelFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}

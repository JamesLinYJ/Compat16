use crate::{DiagnosticKind as Kind, RuntimeError};

/// Budget CPU step boundaries rather than guessed REP micro-iterations.
///
/// The portable CPU keeps REP execution inside `Cpu::step_with_context` and
/// yields after at most 4096 iterations. This runtime boundary cannot know how
/// many iterations CMPS/SCAS completed after a fault, so inferring a count from
/// ECX would be ambiguous and would disagree with the existing Win16 loop.
pub(crate) struct Pe32StepBudget {
    limit: u64,
    charged_boundaries: u64,
    cpu_step_boundaries: u64,
}

impl Pe32StepBudget {
    pub(crate) const fn new(limit: u64) -> Self {
        Self {
            limit,
            charged_boundaries: 0,
            cpu_step_boundaries: 0,
        }
    }

    pub(crate) const fn step_boundaries(&self) -> u64 {
        self.cpu_step_boundaries
    }

    pub(crate) const fn charged_boundaries(&self) -> u64 {
        self.charged_boundaries
    }

    pub(crate) fn ensure_available(&self) -> Result<(), RuntimeError> {
        if self.charged_boundaries >= self.limit {
            return Err(RuntimeError::new(
                Kind::ExecutionLimit,
                "PE32 execution boundary budget exhausted",
            ));
        }
        Ok(())
    }

    pub(crate) fn retire_cpu_step(&mut self) {
        // Availability is checked before entering the CPU; with a u64 limit,
        // increment cannot overflow while maintaining `charged < limit`.
        self.charged_boundaries += 1;
        self.cpu_step_boundaries += 1;
    }

    /// Future synchronous callback/service dispatch must use this same budget
    /// before its side effects, instead of pumping events from the CPU loop.
    #[allow(dead_code)]
    pub(crate) fn charge_non_cpu_boundary(&mut self) -> Result<(), RuntimeError> {
        self.ensure_available()?;
        self.charged_boundaries += 1;
        Ok(())
    }
}

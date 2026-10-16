//! Deadline and readiness policy; source payloads remain with their owners.

use std::time::{Duration, Instant};

use crate::Win16SchedulerReadiness;

// Sampling an atomic readiness hint is cheap; native calls and clock queries
// are kept off ordinary instruction dispatch. Time limits host input latency
// independently of guest instruction throughput.
const READINESS_INSTRUCTION_BUDGET: u64 = 64;
const INPUT_PERIOD: Duration = Duration::from_millis(16);
const SOURCE_PROGRESS_PERIOD: Duration = Duration::from_millis(16);

#[derive(Default)]
pub(super) struct ScheduleTurn {
    pub(super) pump_host: bool,
    pub(super) poll_sources: bool,
}

pub(super) struct ExecutionSchedule {
    next_instruction: u64,
    input_deadline: Instant,
    source_deadline: Instant,
    retry_deadline: Instant,
    generation: Option<u64>,
    pending: bool,
    drain_pending: bool,
    previously_dispatchable: bool,
}

impl ExecutionSchedule {
    pub(super) fn new(instruction: u64) -> Self {
        let now = Instant::now();
        Self {
            next_instruction: instruction,
            input_deadline: now,
            source_deadline: now,
            retry_deadline: now,
            generation: None,
            pending: true,
            drain_pending: false,
            previously_dispatchable: false,
        }
    }

    pub(super) fn checkpoint(&self, instruction: u64) -> bool {
        instruction >= self.next_instruction
    }
    pub(super) fn instruction_quantum(&self, instruction: u64) -> u64 {
        self.next_instruction.saturating_sub(instruction).clamp(1, READINESS_INSTRUCTION_BUDGET)
    }

    pub(super) fn turn(
        &mut self,
        instruction: u64,
        readiness: Option<Win16SchedulerReadiness>,
        active_sources: impl FnOnce() -> bool,
        dispatchable: bool,
    ) -> ScheduleTurn {
        self.next_instruction = instruction.saturating_add(READINESS_INSTRUCTION_BUDGET);
        let now = Instant::now();
        let signaled = readiness.is_some_and(|ready| {
            let changed = self.generation != Some(ready.generation);
            self.generation = Some(ready.generation);
            changed || ready.callback_pending
        });
        if signaled {
            self.pending = true;
        }
        // Some sources require measured-position queries or retry retained
        // cleanup without publishing a native completion. Revisit only while
        // such an owner exists. Unknown hosts keep their polling contract.
        if now >= self.source_deadline {
            self.source_deadline = now + SOURCE_PROGRESS_PERIOD;
            if readiness.is_none() || active_sources() {
                self.pending = true;
            }
        }
        let newly_dispatchable = dispatchable && !self.previously_dispatchable;
        self.previously_dispatchable = dispatchable;
        let poll_sources = self.pending
            && (now >= self.retry_deadline
                || (signaled || self.drain_pending) && dispatchable
                || newly_dispatchable);
        if poll_sources {
            self.retry_deadline = now + SOURCE_PROGRESS_PERIOD;
            self.source_deadline = now + SOURCE_PROGRESS_PERIOD;
        }
        let pump_host = now >= self.input_deadline;
        if pump_host {
            self.input_deadline = now + INPUT_PERIOD;
        }
        ScheduleTurn {
            pump_host,
            poll_sources,
        }
    }

    /// A deferred callback remains pending. This only clears scheduler demand;
    /// it never resets the host wake or acknowledges any family's payload.
    pub(super) fn finish_sources(&mut self, dispatch_completed: bool, progress: bool) {
        // A real dequeue/ACK or callback entry earns another drain turn. An
        // idle pass clears it; idle open devices never create a busy loop.
        self.drain_pending = progress;
        self.pending = progress || !dispatch_completed;
    }
}

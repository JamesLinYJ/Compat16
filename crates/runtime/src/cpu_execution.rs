//! Select execution instrumentation once at the CPU instruction boundary.

use guest_core::{GuestMemory, Registers, io::PortIo};
use x86_cpu::{Cpu, CpuError, CpuObservedStepOutcome, SegmentResolver, StepOutcome};

use crate::trace::{GuestMemoryWriteObserver, GuestMemoryWriteWatch, GuestWriteBoundary};

pub(crate) struct IoStepResult {
    pub(crate) outcome: Result<StepOutcome, CpuError>,
    /// The same pre-instruction writer identifies a software INT's stack writes.
    /// No diagnostic snapshot is captured when the memory watch is disabled.
    pub(crate) writer: Option<Registers>,
}

pub(crate) fn step_with_io(
    cpu: &mut Cpu,
    mut memory: impl GuestMemory,
    ports: &mut impl PortIo,
    watch: Option<&mut GuestMemoryWriteWatch>,
    instruction_count: u64,
) -> IoStepResult {
    match watch {
        None => IoStepResult {
            outcome: cpu.step_with_io(&mut memory, ports),
            writer: None,
        },
        Some(watch) => {
            let writer = cpu.regs.clone();
            let mut memory = GuestMemoryWriteObserver::new(
                memory,
                Some(watch),
                instruction_count,
                &writer,
                GuestWriteBoundary::CpuStep,
            );
            IoStepResult {
                outcome: cpu.step_with_io(&mut memory, ports),
                writer: Some(writer),
            }
        }
    }
}

pub(crate) fn step_observing_events(
    cpu: &mut Cpu,
    mut memory: impl GuestMemory,
    ports: &mut impl PortIo,
    segments: &impl SegmentResolver,
    watch: Option<&mut GuestMemoryWriteWatch>,
    instruction_count: u64,
) -> Result<CpuObservedStepOutcome, CpuError> {
    match watch {
        None => cpu.step_with_context_observing_events(&mut memory, ports, segments),
        Some(watch) => {
            let writer = cpu.regs.clone();
            let mut memory = GuestMemoryWriteObserver::new(
                memory,
                Some(watch),
                instruction_count,
                &writer,
                GuestWriteBoundary::CpuStep,
            );
            cpu.step_with_context_observing_events(&mut memory, ports, segments)
        }
    }
}

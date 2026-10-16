//! Progress is independent of EIP, legacy outcomes, and event provenance.

use super::*;
use crate::execution_boundary::{ExecutionBoundaryReport, ExecutionProgress as Progress};
use guest_core::io::{PortError, PortIo, PortWidth};

fn report(cpu: &mut Cpu, ram: &mut Ram) -> ExecutionBoundaryReport<StepOutcome> {
    cpu.step_with_context_report(ram, &mut NoPorts, &RealModeSegments)
}

fn observed(cpu: &mut Cpu, ram: &mut Ram) -> ExecutionBoundaryReport<CpuObservedStepOutcome> {
    cpu.step_with_context_observing_events_report(ram, &mut NoPorts, &RealModeSegments)
}

fn deferred(outcome: Result<CpuObservedStepOutcome, CpuError>) -> crate::CpuDeferredEvent {
    match outcome.unwrap() {
        CpuObservedStepOutcome::EventDeferred(event) => event,
        other => panic!("expected a deferred event, got {other:?}"),
    }
}

#[test]
fn body_completion_does_not_require_ip_movement_and_halted_poll_is_not_completion() {
    let (mut cpu, mut ram) = cpu_with(&[0xeb, 0xfe], 0x20000);
    let boundary = report(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionBodyCompleted);
    assert_eq!(boundary.outcome, Ok(StepOutcome::Continue));
    assert_eq!(cpu.regs.eip, 0);

    let (mut cpu, mut ram) = cpu_with(&[0xf4], 0x20000);
    let boundary = report(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionBodyCompleted);
    assert_eq!(boundary.outcome, Ok(StepOutcome::Halt));
    let boundary = report(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::NoInstruction);
    assert_eq!(boundary.outcome, Ok(StepOutcome::Halt));
}

#[test]
fn repeat_progress_distinguishes_batched_partial_final_and_zero_count_boundaries() {
    let (mut cpu, mut ram) = cpu_with(&[0xf3, 0xaa], 0x20000); // REP STOSB
    cpu.regs.es = 0x200;
    cpu.regs.set_al(0x5a);
    cpu.regs.set_cx(4097);
    let boundary = report(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::RepeatPartial);
    assert_eq!(boundary.outcome, Ok(StepOutcome::Continue));
    assert_eq!((cpu.regs.eip, cpu.regs.cx(), cpu.regs.di()), (0, 1, 4096));
    assert!(ram.bytes[0x2000..0x3000].iter().all(|&byte| byte == 0x5a));
    assert!(cpu.intermediate_rep_boundary);
    let boundary = report(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionBodyCompleted);
    assert_eq!((cpu.regs.eip, cpu.regs.cx(), cpu.regs.di()), (2, 0, 4097));
    assert!(!cpu.intermediate_rep_boundary);

    let (mut cpu, mut ram) = cpu_with(&[0xf3, 0xaa], 0x20000);
    cpu.regs.es = 0xffff; // Zero count must not access this invalid destination.
    let boundary = report(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionBodyCompleted);
    assert_eq!(boundary.outcome, Ok(StepOutcome::Continue));
    assert_eq!(cpu.regs.eip, 2);
}

#[test]
fn incomplete_repeat_retains_committed_memory_and_register_effects() {
    let (mut cpu, mut ram) = cpu_with(&[0xf3, 0xaa], 0x20000);
    cpu.regs.es = 0x200;
    cpu.regs.set_al(0x5a);
    cpu.regs.set_cx(3);
    ram.reject_write_at(0x2001);
    let boundary = observed(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionIncomplete);
    assert!(matches!(boundary.outcome, Err(CpuError::Memory(MemoryError::ReadOnly { .. }))));
    assert_eq!((cpu.regs.eip, cpu.regs.cx(), cpu.regs.di()), (0, 2, 1));
    assert_eq!(&ram.bytes[0x2000..0x2003], &[0x5a, 0, 0]);
    assert!(!cpu.intermediate_rep_boundary);
}

#[test]
fn incomplete_comparison_repeat_restores_flags_without_undoing_progress() {
    for code in [&[0xf3, 0xa6][..], &[0xf2, 0xae]] { // REPE CMPSB / REPNE SCASB
        let (mut cpu, mut ram) = cpu_with(code, 0x3001);
        let (mut legacy, mut legacy_ram) = cpu_with(code, 0x3001);
        for (cpu, ram) in [(&mut cpu, &mut ram), (&mut legacy, &mut legacy_ram)] {
            cpu.regs.ds = 0x100;
            cpu.regs.es = 0x300;
            cpu.regs.set_al(9);
            cpu.regs.set_cx(3);
            cpu.regs.eflags = 2 | crate::ZF | crate::CF;
            ram.put(0x1000, &[7, 7]);
            ram.put(0x3000, &[7]); // The next iteration faults on its read.
        }
        let flags = cpu.regs.eflags;
        let boundary = observed(&mut cpu, &mut ram);
        let legacy_outcome = legacy.step_with_context_observing_events(
            &mut legacy_ram, &mut NoPorts, &RealModeSegments,
        );
        assert_eq!(boundary.progress, Progress::InstructionIncomplete);
        assert!(matches!(boundary.outcome, Err(CpuError::Memory(_))));
        assert_eq!(boundary.outcome.unwrap_err(), legacy_outcome.unwrap_err());
        assert_eq!((cpu.regs.eip, cpu.regs.cx(), cpu.regs.di()), (0, 2, 1));
        assert_eq!(cpu.regs.eflags, flags);
        assert!(cpu.capture_context() == legacy.capture_context());
        assert_eq!(ram.bytes, legacy_ram.bytes);
    }
}

#[derive(Default)]
struct InputPorts {
    reads: usize,
    fail_after: Option<usize>,
}

impl PortIo for InputPorts {
    fn read(&mut self, port: u16, width: PortWidth) -> Result<u32, PortError> {
        if self.fail_after == Some(self.reads) {
            return Err(PortError::Unsupported { port, width, write: false });
        }
        self.reads += 1;
        Ok(0x5a)
    }

    fn write(&mut self, port: u16, width: PortWidth, _value: u32) -> Result<(), PortError> {
        Err(PortError::Unsupported { port, width, write: true })
    }
}

#[test]
fn repeated_io_reports_partial_completion_and_incomplete_side_effects() {
    for fail_after in [None, Some(1)] {
        let (mut cpu, mut ram) = cpu_with(&[0xf3, 0x6c], 0x20000); // REP INSB
        cpu.regs.es = 0x200;
        cpu.regs.set_cx(4097);
        let mut ports = InputPorts { reads: 0, fail_after };
        let boundary = cpu.step_with_context_report(&mut ram, &mut ports, &RealModeSegments);
        if fail_after.is_some() {
            assert_eq!(boundary.progress, Progress::InstructionIncomplete);
            assert!(matches!(boundary.outcome, Err(CpuError::Io(_))));
            assert_eq!((ports.reads, cpu.regs.cx(), cpu.regs.di()), (1, 4096, 1));
            assert_eq!(&ram.bytes[0x2000..0x2002], &[0x5a, 0]);
        } else {
            assert_eq!(boundary.progress, Progress::RepeatPartial);
            assert_eq!(boundary.outcome, Ok(StepOutcome::Continue));
            assert_eq!((ports.reads, cpu.regs.cx(), cpu.regs.di()), (4096, 1, 4096));
            let boundary = cpu.step_with_context_report(&mut ram, &mut ports, &RealModeSegments);
            assert_eq!(boundary.progress, Progress::InstructionBodyCompleted);
            assert_eq!(boundary.outcome, Ok(StepOutcome::Continue));
            assert_eq!((ports.reads, cpu.regs.cx(), cpu.regs.di()), (4097, 0, 4097));
        }
    }
}

#[test]
fn pending_events_do_not_claim_an_instruction_even_if_delivery_fails() {
    for task_debug in [false, true] {
        let (mut cpu, mut ram) = cpu_with(&[0x90, 0x90], 0x20000);
        cpu.step(&mut ram).unwrap(); // Establish architectural context.
        if task_debug {
            cpu.pending_task_debug_trap = true;
        } else {
            cpu.request_non_maskable_interrupt();
        }
        let boundary = observed(&mut cpu, &mut ram);
        assert_eq!(boundary.progress, Progress::NoInstruction);
        let event = deferred(boundary.outcome).observation();
        assert_eq!(event.source, if task_debug { CpuEventSource::Trap } else {
            CpuEventSource::NonMaskableInterrupt
        });
        assert_eq!(event.saved_ip, 1);
        assert_eq!(cpu.regs.eip, 1);
    }

    let (mut cpu, mut ram) = cpu_with(&[0x90], 0x1000);
    cpu.request_non_maskable_interrupt();
    let boundary = report(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::NoInstruction);
    assert!(matches!(boundary.outcome, Err(CpuError::Memory(_))));
    assert_eq!(cpu.regs.eip, 0);
}

#[test]
fn fetch_unsupported_model_and_instruction_breakpoint_faults_are_incomplete() {
    let (mut cpu, mut ram) = cpu_with(&[], 0);
    let boundary = report(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionIncomplete);
    assert!(boundary.outcome.is_err());

    let (mut cpu, mut ram) = cpu_with(&[0x0f, 0x0b], 0x20000); // UD2
    let boundary = observed(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionIncomplete);
    // UD2 currently reaches the unsupported executor path, not architectural
    // #UD delivery. The report must preserve that compatibility error.
    assert_eq!(boundary.outcome.unwrap_err(), CpuError::UnsupportedOpcode { opcode: 0x0f, ip: 0 });
    assert_eq!(cpu.regs.eip, 0);

    // CPUID on the explicit I486 profile is an established architectural #UD.
    let (cpu, mut ram) = cpu_with(&[0x0f, 0xa2], 0x20000);
    let mut cpu = Cpu::new_with_model(cpu.regs, CpuModel::I486);
    let boundary = observed(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionIncomplete);
    let event = deferred(boundary.outcome).observation();
    assert_eq!((event.vector, event.source, event.saved_ip), (6, CpuEventSource::Fault, 0));

    let (mut cpu, mut ram) = cpu_with(&[0x90], 0x20000);
    cpu.system.debug.addresses[0] = 0;
    cpu.system.debug.control = 1;
    let boundary = observed(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionIncomplete);
    let event = deferred(boundary.outcome).observation();
    assert_eq!((event.vector, event.source, event.saved_ip),
        (1, CpuEventSource::InstructionBreakpointFault, 0));
    assert_eq!(cpu.regs.eip, 0);
}

#[test]
fn post_execution_events_keep_body_progress_and_repeat_token_authority() {
    for (code, source) in [(&[0xcd, 0x21][..], CpuEventSource::SoftwareInterrupt),
        (&[0x90][..], CpuEventSource::Trap)]
    {
        let (mut cpu, mut ram) = cpu_with(code, 0x20000);
        if source == CpuEventSource::Trap { cpu.regs.eflags |= crate::TF; }
        let boundary = observed(&mut cpu, &mut ram);
        assert_eq!(boundary.progress, Progress::InstructionBodyCompleted);
        let event = deferred(boundary.outcome).observation();
        assert_eq!(event.source, source);
        assert_eq!(event.saved_ip, code.len() as u32);
    }

    let (mut cpu, mut ram) = cpu_with(&[0xf3, 0xaa], 0x20000);
    cpu.regs.es = 0x200;
    cpu.regs.set_cx(2);
    cpu.regs.eflags |= crate::TF;
    let boundary = observed(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::RepeatPartial);
    let event = deferred(boundary.outcome);
    assert_eq!(event.observation().source, CpuEventSource::Trap);
    assert_eq!(event.observation().saved_ip, 0);
    assert_eq!(cpu.regs.cx(), 1);
    assert!(cpu.capture_event_observer_continuation().is_err());
    assert!(cpu.capture_deferred_event_observer_continuation(&event).is_ok());
    let (other, _) = cpu_with(&[0x90], 0x20000);
    assert!(other.capture_deferred_event_observer_continuation(&event).is_err());
}

#[test]
fn stack_debug_shadow_preserves_progress_event_and_wrapper_parity() {
    for next_faults in [false, true] {
        let code = if next_faults { &[0x8e, 0x16, 0x00, 0x02, 0x0f, 0xa2][..] }
            else { &[0x8e, 0x16, 0x00, 0x02, 0x90][..] }; // MOV SS,[0200]
        let (cpu, mut ram) = cpu_with(code, 0x20000);
        let (legacy, mut legacy_ram) = cpu_with(code, 0x20000);
        // CPUID must produce #UD, rather than an unsupported-executor error.
        let mut cpu = Cpu::new_with_model(cpu.regs, CpuModel::I486);
        let mut legacy = Cpu::new_with_model(legacy.regs, CpuModel::I486);
        for (cpu, ram) in [(&mut cpu, &mut ram), (&mut legacy, &mut legacy_ram)] {
            cpu.regs.eflags |= crate::TF;
            cpu.system.debug.addresses[0] = 0x200;
            cpu.system.debug.control = 1 | (3 << 16) | (1 << 18); // Word read/write match.
            ram.put(0x200, &[0x00, 0x01]);
        }
        let boundary = observed(&mut cpu, &mut ram);
        let legacy_outcome = legacy.step_with_context_observing_events(
            &mut legacy_ram, &mut NoPorts, &RealModeSegments,
        );
        assert_eq!(boundary.progress, Progress::InstructionBodyCompleted);
        assert!(matches!(boundary.outcome, Ok(CpuObservedStepOutcome::Executed(StepOutcome::Continue))));
        assert!(matches!(legacy_outcome, Ok(CpuObservedStepOutcome::Executed(StepOutcome::Continue))));
        assert!(cpu.debug_exception_shadow);
        assert_eq!(cpu.deferred_data_breakpoint_hits.enabled, 1);
        assert!(cpu.capture_context() == legacy.capture_context());

        let boundary = observed(&mut cpu, &mut ram);
        let legacy_event = deferred(legacy.step_with_context_observing_events(
            &mut legacy_ram, &mut NoPorts, &RealModeSegments,
        ));
        assert_eq!(boundary.progress, if next_faults { Progress::InstructionIncomplete }
            else { Progress::InstructionBodyCompleted });
        let event = deferred(boundary.outcome);
        assert_eq!(event.observation(), legacy_event.observation());
        assert_eq!(event.observation().source, if next_faults { CpuEventSource::Fault }
            else { CpuEventSource::Trap });
        assert!(!cpu.debug_exception_shadow);
        assert_eq!(cpu.deferred_data_breakpoint_hits.enabled, 0);
        if !next_faults { assert_eq!(cpu.system.debug.status & ((1 << 14) | 1), (1 << 14) | 1); }
        assert!(cpu.capture_context() == legacy.capture_context());
        assert_eq!(ram.bytes, legacy_ram.bytes);
    }
}

#[test]
fn post_body_delivery_error_keeps_progress_without_changing_the_legacy_error() {
    let (mut cpu, mut ram) = cpu_with(&[0xcd, 0x21], 0x1000);
    let (mut legacy, mut legacy_ram) = cpu_with(&[0xcd, 0x21], 0x1000);
    let boundary = report(&mut cpu, &mut ram);
    assert_eq!(boundary.progress, Progress::InstructionBodyCompleted);
    assert!(matches!(boundary.outcome, Err(CpuError::Memory(_))));
    assert_eq!(boundary.outcome, legacy.step(&mut legacy_ram));
    assert!(cpu.capture_context() == legacy.capture_context());
    assert_eq!(ram.bytes, legacy_ram.bytes);
}

#[test]
fn x87_new_exception_completes_body_but_pending_wait_does_not() {
    use crate::x87_state::Ext80;
    for native_exception in [false, true] {
        let (mut cpu, mut ram) = cpu_with(&[0xd8, 0xc1, 0x9b], 0x20000);
        if native_exception {
            cpu.system.write_cr0(cpu.system.cr0 | crate::system::CR0_NE).unwrap();
        }
        cpu.x87.control_word &= !0x20;
        cpu.x87.write_st(0, Ext80 { significand: 1 << 63, sign_exponent: 0x3fff });
        cpu.x87.write_st(1, Ext80 {
            significand: 0xc000_0000_0000_0000, sign_exponent: 0x3fc0,
        });
        let boundary = observed(&mut cpu, &mut ram);
        assert_eq!(boundary.progress, Progress::InstructionBodyCompleted);
        assert!(matches!(boundary.outcome, Ok(CpuObservedStepOutcome::Executed(StepOutcome::Continue))));
        assert_eq!(cpu.regs.eip, 2);
        assert_eq!(cpu.x87.pending_unmasked_exceptions(), 0x20);
        let boundary = observed(&mut cpu, &mut ram);
        assert_eq!(boundary.progress, Progress::InstructionIncomplete);
        assert_eq!(cpu.regs.eip, 2);
        if native_exception {
            let event = deferred(boundary.outcome).observation();
            assert_eq!((event.vector, event.source), (16, CpuEventSource::Fault));
        } else {
            assert!(matches!(boundary.outcome, Ok(CpuObservedStepOutcome::Executed(StepOutcome::Continue))));
            assert!(cpu.take_pending_x87_irq13());
        }
    }
}

#[test]
fn legacy_wrappers_preserve_outcomes_context_memory_and_boundary_sequences() {
    // Ordinary, same-IP branch, REP, and faulting execution use the same seam.
    for code in [&[0x90][..], &[0xeb, 0xfe], &[0xf3, 0xaa], &[0x0f, 0x0b]] {
        for wrapper in 0..3 {
            let (mut cpu, mut ram) = cpu_with(code, 0x20000);
            let (mut legacy, mut legacy_ram) = cpu_with(code, 0x20000);
            cpu.regs.es = 0x200;
            legacy.regs.es = 0x200;
            cpu.regs.set_cx(4097);
            legacy.regs.set_cx(4097);
            let boundary = report(&mut cpu, &mut ram);
            let outcome = match wrapper {
                0 => legacy.step(&mut legacy_ram),
                1 => legacy.step_with_io(&mut legacy_ram, &mut NoPorts),
                _ => legacy.step_with_context(&mut legacy_ram, &mut NoPorts, &RealModeSegments),
            };
            assert_eq!(boundary.outcome, outcome);
            assert!(cpu.capture_context() == legacy.capture_context());
            assert_eq!(cpu.call_boundary_sequence, legacy.call_boundary_sequence);
            assert_eq!(cpu.control_transfer_sequence, legacy.control_transfer_sequence);
            assert_eq!(ram.bytes, legacy_ram.bytes);
        }
    }
}

#[test]
fn observing_wrapper_preserves_event_and_replay_context() {
    let (mut cpu, mut ram) = cpu_with(&[0xcd, 0x21], 0x20000);
    let (mut legacy, mut legacy_ram) = cpu_with(&[0xcd, 0x21], 0x20000);
    let boundary = observed(&mut cpu, &mut ram);
    let event = deferred(boundary.outcome);
    let legacy_event = deferred(legacy.step_with_context_observing_events(
        &mut legacy_ram, &mut NoPorts, &RealModeSegments,
    ));
    assert_eq!(event.observation(), legacy_event.observation());
    assert!(cpu.capture_context() == legacy.capture_context());
    assert_eq!(cpu.call_boundary_sequence, legacy.call_boundary_sequence);
    cpu.resume_deferred_event(event, &mut ram, &RealModeSegments).unwrap();
    legacy.resume_deferred_event(legacy_event, &mut legacy_ram, &RealModeSegments).unwrap();
    assert!(cpu.capture_context() == legacy.capture_context());
    assert_eq!(ram.bytes, legacy_ram.bytes);
}

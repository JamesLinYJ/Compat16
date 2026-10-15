//! Differential checks through the public scheduler quantum entrypoint.
use super::*;
use crate::{CpuArchitecturalContext, CpuSegmentCacheState};
use guest_core::memory::Memory as OwnedMemory;

const CODE: u32 = 0x10000;
const PROGRAM: &[u8] = &[
    0x83, 0xc0, 3, 0xa8, 1, 0x74, 3, 0x83, 0xd3, 7, 0x49, 0x75, 0xf3, 0xf4,
];
fn machine(bits: u32, engine: ExecutionEngine) -> (Cpu, OwnedMemory) {
    let mut cpu = Cpu::new(Registers {
        eax: 0xabcd_1234,
        ebx: 0x9876_ffff,
        ecx: 1000,
        cs: 8,
        ss: 16,
        ds: 16,
        es: 16,
        fs: 16,
        gs: 16,
        eflags: 0x203,
        ..Registers::default()
    });
    cpu.set_execution_engine(engine);
    let data = CpuSegmentCacheState {
        selector: 16,
        base: 0x50000,
        limit: 0x3ffff,
        access: 0x93,
        flags: if bits == 32 { 0x40 } else { 0 },
        usable: true,
    };
    let mut segments = [data; 6];
    segments[0] = CpuSegmentCacheState {
        selector: 8,
        base: CODE,
        access: 0x9b,
        ..data
    };
    cpu.import_architectural_context(CpuArchitecturalContext {
        cr0: 0x11,
        cr2: 0,
        cr3: 0,
        cpl: 0,
        segments,
        tables: Default::default(),
        ldt: Default::default(),
        task: Default::default(),
    })
    .unwrap();
    let mut memory = OwnedMemory::with_size(0x100000).unwrap();
    memory.write(PhysAddr(CODE), PROGRAM).unwrap();
    (cpu, memory)
}
fn run(cpu: &mut Cpu, memory: &mut OwnedMemory, budget: u32) -> Option<u32> {
    cpu.try_run_jit_loop(memory, &RealModeSegments, budget)
        .unwrap()
}
fn warm(cpu: &mut Cpu, memory: &mut OwnedMemory) {
    let original = cpu.regs.clone();
    for _ in 0..32 {
        cpu.regs = original.clone();
        if run(cpu, memory, 256).is_some() {
            break;
        }
    }
    cpu.regs = original;
    assert!(
        cpu.jit_statistics().regions_compiled > 0,
        "{:?}",
        cpu.jit_statistics()
    );
    assert_eq!(cpu.jit_statistics().failures, 0);
}
fn interpret(cpu: &mut Cpu, memory: &mut OwnedMemory, retired: u32) {
    for _ in 0..retired {
        assert_eq!(
            cpu.step_with_context(memory, &mut NoPorts, &RealModeSegments)
                .unwrap(),
            StepOutcome::Continue
        );
    }
}

#[test]
fn linked_protected_graphs_resume_every_budget_and_match_precise_retirement() {
    for bits in [16, 32] {
        let (mut jit, mut memory) = machine(bits, ExecutionEngine::Jit);
        let (mut reference, mut ram) = machine(bits, ExecutionEngine::Interpreter);
        warm(&mut jit, &mut memory);
        let initial = jit.regs.clone();
        for budget in 1..=256 {
            for count in [1, 2, 31, 1000] {
                jit.regs = initial.clone();
                jit.regs.ecx = count;
                reference.regs = jit.regs.clone();
                let mut before = jit.call_boundary_sequence;
                reference.call_boundary_sequence = before;
                let retired = run(&mut jit, &mut memory, budget).unwrap();
                assert!(retired > 0 && retired <= budget);
                interpret(&mut reference, &mut ram, retired);
                assert!(
                    jit.capture_context() == reference.capture_context(),
                    "bits={bits} budget={budget}"
                );
                assert_eq!(jit.call_boundary_sequence, before + u64::from(retired));
                // Even one-instruction quanta resume compiled prefixes. No
                // decoder/interpreter step is needed between linked quanta.
                if jit.regs.eip != 13 {
                    before = jit.call_boundary_sequence;
                    assert_eq!(run(&mut jit, &mut memory, 1), Some(1));
                    interpret(&mut reference, &mut ram, 1);
                    assert!(jit.capture_context() == reference.capture_context());
                    assert_eq!(jit.call_boundary_sequence, before + 1);
                }
            }
        }
        assert!(jit.jit_statistics().direct_links > 0);
        assert!(jit.jit_statistics().branches_fallthrough > 0);
    }
}

#[test]
fn linked_resume_revalidates_all_blocks_permissions_remapping_and_observers() {
    let (mut cpu, mut memory) = machine(16, ExecutionEngine::Jit);
    warm(&mut cpu, &mut memory);
    assert_eq!(run(&mut cpu, &mut memory, 1), Some(1));
    // Change a successor that has not executed in this quantum.
    memory.write(PhysAddr(CODE + 9), &[8]).unwrap();
    let before = cpu.capture_context();
    assert_eq!(run(&mut cpu, &mut memory, 1), None);
    assert!(cpu.capture_context() == before);
    cpu.regs.eip = 0;
    warm(&mut cpu, &mut memory);
    assert_eq!(run(&mut cpu, &mut memory, 1), Some(1));
    let limit = cpu.system.segments[0].descriptor.limit;
    cpu.system.segments[0].descriptor.limit = 2;
    let before = cpu.capture_context();
    assert_eq!(run(&mut cpu, &mut memory, 1), None);
    assert!(cpu.capture_context() == before);
    cpu.system.segments[0].descriptor.limit = limit;
    cpu.regs.eip = 0;
    warm(&mut cpu, &mut memory);
    assert_eq!(run(&mut cpu, &mut memory, 1), Some(1));
    cpu.system.segments[0].descriptor.base += 0x1000;
    let before = cpu.capture_context();
    assert_eq!(run(&mut cpu, &mut memory, 1), None);
    assert!(cpu.capture_context() == before);
    cpu.system.segments[0].descriptor.base = CODE;
    cpu.regs.eip = 0;
    warm(&mut cpu, &mut memory);
    assert_eq!(run(&mut cpu, &mut memory, 1), Some(1));
    let mut observed = Memory {
        ram: Ram::new(0x20000),
        trace: RefCell::default(),
        reject_data_read: false,
    };
    observed.ram.put(CODE as usize, PROGRAM);
    let before = cpu.capture_context();
    assert_eq!(
        cpu.try_run_jit_loop(&mut observed, &RealModeSegments, 256)
            .unwrap(),
        None
    );
    assert!(cpu.capture_context() == before);
    assert!(observed.trace.borrow().is_empty());
}

#[test]
fn linked_exits_leave_unsupported_operations_and_bad_near_targets_unretired() {
    let (mut cpu, mut memory) = machine(16, ExecutionEngine::Jit);
    // An invalid near target must fault at the JMP, not at its destination
    // after the compiled graph has already retired the branch.
    memory
        .write(PhysAddr(CODE + 13), &[0xe9, 0xf0, 0x07])
        .unwrap();
    cpu.system.segments[0].descriptor.limit = 0x7f;
    warm(&mut cpu, &mut memory);
    cpu.regs.ecx = 1;
    assert!(run(&mut cpu, &mut memory, 256).is_some());
    assert_eq!(cpu.regs.eip, 13);
    let boundary = cpu
        .step_with_context_observing_events(&mut memory, &mut NoPorts, &RealModeSegments)
        .unwrap();
    let CpuObservedStepOutcome::EventDeferred(event) = boundary else {
        panic!("expected branch fault");
    };
    assert_eq!(event.observation().vector, 13);
    assert_eq!(event.observation().saved_ip, 13);

    let (mut cpu, mut memory) = machine(16, ExecutionEngine::Jit);
    memory.write(PhysAddr(CODE + 13), &[0xd9, 0xe8]).unwrap(); // FLD1 remains an x87 boundary.
    warm(&mut cpu, &mut memory);
    cpu.regs.ecx = 1;
    assert!(run(&mut cpu, &mut memory, 256).is_some());
    assert_eq!(cpu.regs.eip, 13);
    assert_eq!(cpu.x87, crate::x87_state::X87State::default());
    cpu.step_with_context(&mut memory, &mut NoPorts, &RealModeSegments)
        .unwrap();
    assert_ne!(cpu.x87.tag_word, 0xffff);
}

#[test]
fn linked_graphs_decline_debug_events_and_stop_at_counter_exhaustion() {
    let (mut cpu, mut memory) = machine(16, ExecutionEngine::Jit);
    warm(&mut cpu, &mut memory);
    for guard in 0..8 {
        match guard {
            0 => cpu.regs.eflags |= 1 << 8,
            1 => cpu.regs.eflags |= 1 << 16,
            2 => cpu.system.debug.control = 1,
            3 => cpu.pending_non_maskable_interrupt = true,
            4 => cpu.maskable_interrupt_shadow = true,
            5 => cpu.debug_exception_shadow = true,
            6 => cpu.system.cr0 |= crate::system::CR0_PG,
            7 => cpu.pending_x87_irq13 = true,
            _ => unreachable!(),
        }
        let before = cpu.capture_context();
        assert_eq!(run(&mut cpu, &mut memory, 256), None);
        assert!(cpu.capture_context() == before);
        cpu.regs.eflags = 0x203;
        cpu.system.debug.control = 0;
        cpu.pending_non_maskable_interrupt = false;
        cpu.maskable_interrupt_shadow = false;
        cpu.debug_exception_shadow = false;
        cpu.system.cr0 &= !crate::system::CR0_PG;
        cpu.pending_x87_irq13 = false;
    }
    cpu.call_boundary_sequence = u64::MAX - 1;
    assert_eq!(run(&mut cpu, &mut memory, 256), Some(1));
    assert_eq!(cpu.call_boundary_sequence, u64::MAX);
    assert_eq!(run(&mut cpu, &mut memory, 256), None);
}

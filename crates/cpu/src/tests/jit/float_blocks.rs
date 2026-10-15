//! Compare complete scheduler-prefix state with ordinary checked execution.
use super::*;
use crate::x87_state::{Ext80, X87State};
use guest_core::memory::Memory as OwnedMemory;
const CODE: u32 = 0x10000;
const DATA: u32 = 0x50300;
const REGISTERS: &[u8] = &[
    0xd8, 0xc1, 0xd8, 0xe1, 0xd8, 0xc9, 0xd8, 0xf1, 0xd9, 0xc0, 0xd9, 0xc9, 0xd9, 0xe0, 0xd9, 0xe1,
    0xdd, 0xd9, 0xf4,
];
const POPPING: &[u8] = &[
    0xd9, 0xc0, 0xde, 0xe1, 0xd9, 0xe8, 0xde, 0xf9, 0xd9, 0xe8, 0xde, 0xe9, 0xd9, 0xe8, 0xde, 0xf1,
    0xd9, 0xc0, 0xde, 0xc1, 0xd9, 0xe8, 0xde, 0xc9, 0xf4,
];
const UNARY: &[u8] = &[0xd9, 0xe0, 0xd9, 0xe1, 0xf4];
const MEMORY: &[u8] = &[
    0xdb, 0x2e, 0x00, 0x03, 0xd8, 0xc9, 0xd8, 0xc1, 0xd8, 0xe1, 0xd8, 0xf1, 0xdb, 0x3e, 0x10, 0x03,
    0xf4,
];
fn machine(bits: u32, engine: ExecutionEngine, program: &[u8]) -> (Cpu, OwnedMemory) {
    let (mut cpu, mut memory) = super::linked::machine(bits, engine);
    // This fixture encodes 16-bit absolute addresses; add the address-size
    // override in a 32-bit CS while retaining the same guest program.
    let program = if bits == 32 && program == MEMORY {
        let mut bytes = vec![0x67];
        bytes.extend_from_slice(&program[..12]);
        bytes.push(0x67);
        bytes.extend_from_slice(&program[12..]);
        bytes
    } else {
        program.to_vec()
    };
    memory.write(PhysAddr(CODE), &program).unwrap();
    cpu.x87 = X87State::default();
    cpu.x87.set_top(6);
    cpu.x87.status_word |= 0xc780; // Include a raw restored ES/B with no pending flags.
    cpu.x87.write_st(
        0,
        Ext80 {
            significand: (1 << 63) + 1,
            sign_exponent: 0x3fff,
        },
    );
    cpu.x87.write_st(
        1,
        Ext80 {
            significand: 0xc000_0000_0000_0000,
            sign_exponent: 0x3fff,
        },
    );
    memory
        .write(
            PhysAddr(DATA),
            &Ext80 {
                significand: (1 << 63) + 1,
                sign_exponent: 0x3fff,
            }
            .to_le_bytes(),
        )
        .unwrap();
    if program == UNARY {
        cpu.x87.set_tag(6, crate::x87_state::X87Tag::Special);
    }
    (cpu, memory)
}
fn run(cpu: &mut Cpu, memory: &mut OwnedMemory, budget: u32) -> Option<u32> {
    super::linked::run(cpu, memory, budget)
}
fn warm(cpu: &mut Cpu, memory: &mut OwnedMemory) {
    let regs = cpu.regs.clone();
    let floating = cpu.x87.clone();
    for _ in 0..32 {
        cpu.regs = regs.clone();
        cpu.x87 = floating.clone();
        cpu.pending_x87_irq13 = false;
        run(cpu, memory, 32);
    }
    cpu.regs = regs;
    cpu.x87 = floating;
    cpu.pending_x87_irq13 = false;
    assert!(
        cpu.jit_statistics().float_blocks_compiled > 0,
        "{:?}",
        cpu.jit_statistics()
    );
    assert_eq!(cpu.jit_statistics().failures, 0);
}
fn interpret(cpu: &mut Cpu, memory: &mut OwnedMemory, count: u32) {
    for _ in 0..count {
        assert_eq!(
            cpu.step_with_context(memory, &mut NoPorts, &RealModeSegments)
                .unwrap(),
            StepOutcome::Continue
        );
    }
}
#[test]
fn floating_blocks_match_complete_register_ram_and_budget_prefixes() {
    for bits in [16, 32] {
        for program in [REGISTERS, MEMORY, UNARY, POPPING] {
            for pc in [0, 2, 3] {
                for rc in 0..4 {
                    let (mut jit, mut memory) = machine(bits, ExecutionEngine::Jit, program);
                    let (mut reference, mut ram) =
                        machine(bits, ExecutionEngine::Interpreter, program);
                    jit.x87.control_word = 0x7f | pc << 8 | rc << 10;
                    warm(&mut jit, &mut memory);
                    let regs = jit.regs.clone();
                    let floating = jit.x87.clone();
                    let mut saved = [0; 256];
                    memory.read(PhysAddr(DATA & !255), &mut saved).unwrap();
                    for budget in 1..=32 {
                        jit.regs = regs.clone();
                        jit.x87 = floating.clone();
                        reference.regs = regs.clone();
                        reference.x87 = floating.clone();
                        reference.call_boundary_sequence = jit.call_boundary_sequence;
                        memory.write(PhysAddr(DATA & !255), &saved).unwrap();
                        ram.write(PhysAddr(DATA & !255), &saved).unwrap();
                        let retired = run(&mut jit, &mut memory, budget).unwrap();
                        assert_eq!(
                            retired,
                            budget.min(if program == REGISTERS {
                                9
                            } else if program == MEMORY {
                                6
                            } else if program == UNARY {
                                2
                            } else {
                                12
                            })
                        );
                        interpret(&mut reference, &mut ram, retired);
                        assert!(
                            jit.capture_context() == reference.capture_context(),
                            "bits={bits} pc={pc} rc={rc} budget={budget} program={program:02x?}\njit={:?}\nref={:?}",
                            jit.x87,
                            reference.x87
                        );
                        let mut actual = [0; 256];
                        let mut expected = [0; 256];
                        memory.read(PhysAddr(DATA & !255), &mut actual).unwrap();
                        ram.read(PhysAddr(DATA & !255), &mut expected).unwrap();
                        assert_eq!(actual, expected);
                        assert_eq!(jit.call_boundary_sequence, reference.call_boundary_sequence);
                    }
                }
            }
        }
    }
}
#[test]
fn floating_blocks_leave_special_stack_and_unmasked_exception_instructions_at_precise_boundaries() {
    let program = &[0xd8, 0xc9, 0xd8, 0xc9, 0xd8, 0xc9, 0xf4];
    for legacy_irq in [false, true] {
        let (mut jit, mut memory) = machine(16, ExecutionEngine::Jit, program);
        let (mut reference, mut ram) = machine(16, ExecutionEngine::Interpreter, program);
        jit.x87.control_word = 0x35f;
        jit.x87.write_st(1, jit.x87.read_st(0).unwrap());
        warm(&mut jit, &mut memory);
        reference.regs = jit.regs.clone();
        reference.x87 = jit.x87.clone();
        reference.call_boundary_sequence = jit.call_boundary_sequence;
        if legacy_irq {
            jit.system.cr0 &= !crate::system::CR0_NE;
            reference.system.cr0 &= !crate::system::CR0_NE;
        } else {
            jit.system.cr0 |= crate::system::CR0_NE;
            reference.system.cr0 |= crate::system::CR0_NE;
        }
        assert_eq!(run(&mut jit, &mut memory, 32), Some(1));
        interpret(&mut reference, &mut ram, 1);
        assert!(jit.capture_context() == reference.capture_context());
        assert_eq!(jit.pending_x87_irq13, reference.pending_x87_irq13);
        assert_eq!(run(&mut jit, &mut memory, 32), None);
        assert_eq!(
            jit.step_with_context(&mut memory, &mut NoPorts, &RealModeSegments),
            reference.step_with_context(&mut ram, &mut NoPorts, &RealModeSegments)
        );
    }
    let program = &[0xd8, 0xc1, 0xd8, 0xf1, 0xf4]; // add zero; divide by zero
    let (mut jit, mut memory) = machine(16, ExecutionEngine::Jit, program);
    let (mut reference, mut ram) = machine(16, ExecutionEngine::Interpreter, program);
    warm(&mut jit, &mut memory);
    jit.x87.write_st(1, Ext80::default());
    reference.regs = jit.regs.clone();
    reference.x87 = jit.x87.clone();
    reference.call_boundary_sequence = jit.call_boundary_sequence;
    assert_eq!(run(&mut jit, &mut memory, 32), Some(1));
    interpret(&mut reference, &mut ram, 1);
    assert!(jit.capture_context() == reference.capture_context());
    assert_eq!(
        jit.step_with_context(&mut memory, &mut NoPorts, &RealModeSegments),
        reference.step_with_context(&mut ram, &mut NoPorts, &RealModeSegments)
    );
    assert!(jit.capture_context() == reference.capture_context());
}
#[test]
fn floating_block_guards_recheck_code_model_fpu_state_and_segment_permissions() {
    let (mut cpu, mut memory) = machine(16, ExecutionEngine::Jit, MEMORY);
    warm(&mut cpu, &mut memory);
    let before = cpu.capture_context();
    let cr0 = cpu.system.cr0;
    cpu.system.cr0 |= crate::system::CR0_TS;
    assert_eq!(run(&mut cpu, &mut memory, 32), None);
    cpu.system.cr0 = cr0;
    assert!(cpu.capture_context() == before);
    let limit = cpu.system.segments[0].descriptor.limit;
    cpu.system.segments[0].descriptor.limit = 3;
    assert_eq!(run(&mut cpu, &mut memory, 32), None);
    cpu.system.segments[0].descriptor.limit = limit;
    assert!(cpu.capture_context() == before);
    memory.write(PhysAddr(CODE + 4), &[0xd8, 0xc1]).unwrap();
    assert_eq!(run(&mut cpu, &mut memory, 32), None);
    assert!(cpu.capture_context() == before);
    warm(&mut cpu, &mut memory);
    let before = cpu.capture_context();
    cpu.x87.empty_st(0);
    let empty = cpu.capture_context();
    // FLD is allowed to commit, then arithmetic discovers the empty source.
    assert_eq!(run(&mut cpu, &mut memory, 32), Some(1));
    assert!(cpu.capture_context() != empty);
    assert!(cpu.capture_context() != before);
}

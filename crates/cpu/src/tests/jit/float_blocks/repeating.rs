//! Cross the floating/integer backedge at every budget and compare the full
//! architectural context, including the last x87 instruction/data pointers.
use super::*;
fn program(bits: u32, kind: usize) -> Vec<u8> {
    let mut body = match kind {
        0 => vec![0xd8, 0xc1, 0xd8, 0xe1],
        1 => vec![0xd8, 0xc9],
        _ if bits == 32 => {
            let mut bytes = vec![0xd8, 0xc1, 0xd8, 0xe1, 0x67];
            bytes.extend_from_slice(&MEMORY[..12]);
            bytes.push(0x67);
            bytes.extend_from_slice(&MEMORY[12..16]);
            bytes
        }
        _ => {
            let mut b = vec![0xd8, 0xc1, 0xd8, 0xe1];
            b.extend_from_slice(&MEMORY[..16]);
            b
        }
    };
    body.push(0x49); // DEC CX/ECX, preserving CF.
    let displacement = -((body.len() + 2) as i8);
    body.extend_from_slice(&[0x75, displacement as u8, 0xf4]);
    body
}
#[test]
fn floating_integer_loops_match_every_budget_and_recheck_the_entire_backedge() {
    for bits in [16, 32] {
        for kind in 0..3 {
            let code = program(bits, kind);
            for pc in [0, 2, 3] {
                for rc in 0..4 {
                    let (mut jit, mut memory) = machine(bits, ExecutionEngine::Jit, &code);
                    let (mut reference, mut ram) =
                        machine(bits, ExecutionEngine::Interpreter, &code);
                    jit.regs.ecx = 3;
                    jit.regs.eflags |= 1;
                    jit.x87.control_word = 0x7f | pc << 8 | rc << 10;
                    warm(&mut jit, &mut memory);
                    let regs = jit.regs.clone();
                    let floating = jit.x87.clone();
                    let mut saved = [0; 256];
                    memory.read(PhysAddr(DATA & !255), &mut saved).unwrap();
                    let mut batched = false;
                    for budget in (1..=40).chain([255, 256, 257]) {
                        jit.regs = regs.clone();
                        jit.x87 = floating.clone();
                        if budget >= 255 {
                            jit.regs.ecx = if bits == 16 { 0xabcd_0000 } else { 0 };
                        }
                        reference.regs = jit.regs.clone();
                        reference.x87 = floating.clone();
                        reference.call_boundary_sequence = jit.call_boundary_sequence;
                        memory.write(PhysAddr(DATA & !255), &saved).unwrap();
                        ram.write(PhysAddr(DATA & !255), &saved).unwrap();
                        let retired = run(&mut jit, &mut memory, budget).unwrap();
                        assert!(retired > 0 && retired <= budget);
                        batched |= retired
                            > if kind == 0 {
                                2
                            } else if kind == 1 {
                                1
                            } else {
                                8
                            };
                        interpret(&mut reference, &mut ram, retired);
                        assert!(
                            jit.capture_context() == reference.capture_context(),
                            "bits={bits} kind={kind} pc={pc} rc={rc} budget={budget} retired={retired}\njit={:?}\nref={:?}",
                            jit.x87,
                            reference.x87
                        );
                        let mut actual = [0; 256];
                        let mut expected = [0; 256];
                        memory.read(PhysAddr(DATA & !255), &mut actual).unwrap();
                        ram.read(PhysAddr(DATA & !255), &mut expected).unwrap();
                        assert_eq!(actual, expected);
                    }
                    assert!(batched);
                    jit.regs = regs;
                    jit.x87 = floating;
                    let before = jit.capture_context();
                    memory
                        .write(PhysAddr(CODE + code.len() as u32 - 2), &[0])
                        .unwrap();
                    assert_eq!(run(&mut jit, &mut memory, 40), None);
                    assert!(jit.capture_context() == before);
                }
            }
        }
    }
}
#[test]
fn floating_integer_loops_stop_before_tail_for_unmasked_precision_and_irq13() {
    for legacy in [false, true] {
        let code = program(16, 1);
        let (mut jit, mut memory) = machine(16, ExecutionEngine::Jit, &code);
        let (mut reference, mut ram) = machine(16, ExecutionEngine::Interpreter, &code);
        jit.regs.ecx = 3;
        jit.x87.control_word = 0x35f;
        jit.x87.write_st(1, jit.x87.read_st(0).unwrap());
        warm(&mut jit, &mut memory);
        if legacy {
            jit.system.cr0 &= !crate::system::CR0_NE;
        } else {
            jit.system.cr0 |= crate::system::CR0_NE;
        }
        reference.regs = jit.regs.clone();
        reference.x87 = jit.x87.clone();
        reference.system = jit.system.clone();
        reference.call_boundary_sequence = jit.call_boundary_sequence;
        let retired = run(&mut jit, &mut memory, 32).unwrap();
        assert_eq!(retired, 1);
        assert_eq!(jit.regs.ecx, 3);
        interpret(&mut reference, &mut ram, retired);
        assert!(jit.capture_context() == reference.capture_context());
        assert_eq!(jit.pending_x87_irq13, reference.pending_x87_irq13);
    }
}

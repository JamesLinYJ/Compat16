use super::*;

fn program(bits: u32, wide: bool) -> Vec<u8> {
    let mut code = Vec::new();
    for (opcode, modrm, offset) in [
        (if wide { 0xdd } else { 0xd9 }, 0x06, 0x300u16),
        (if wide { 0xdc } else { 0xd8 }, 0x06, 0x308), // add
        (if wide { 0xdc } else { 0xd8 }, 0x0e, 0x308), // multiply
        (if wide { 0xdc } else { 0xd8 }, 0x26, 0x308), // subtract
        (if wide { 0xdc } else { 0xd8 }, 0x2e, 0x308), // reverse subtract
        (if wide { 0xdc } else { 0xd8 }, 0x36, 0x308), // divide
        (if wide { 0xdc } else { 0xd8 }, 0x3e, 0x308), // reverse divide
        (0xdb, 0x3e, 0x320),                           // store and pop 80 bits
    ] {
        if bits == 32 {
            code.push(0x67);
        }
        code.extend_from_slice(&[opcode, modrm]);
        code.extend_from_slice(&offset.to_le_bytes());
    }
    code.push(0xf4);
    code
}
fn input(memory: &mut OwnedMemory, wide: bool) {
    let (left, right) = if wide {
        (0x3ff0_0000_0000_0001u64, 0x3ff8_0000_0000_0000u64)
    } else {
        (0x3f80_0001, 0x3fc0_0000)
    };
    let width = if wide { 8 } else { 4 };
    memory
        .write(PhysAddr(DATA), &left.to_le_bytes()[..width])
        .unwrap();
    memory
        .write(PhysAddr(DATA + 8), &right.to_le_bytes()[..width])
        .unwrap();
}
#[test]
fn ieee_memory_blocks_match_cpu_context_and_ram_at_every_prefix() {
    for bits in [16, 32] {
        for wide in [false, true] {
            let code = program(bits, wide);
            for pc in [0, 2, 3] {
                for rc in 0..4 {
                    let (mut jit, mut memory) = machine(bits, ExecutionEngine::Jit, &code);
                    let (mut reference, mut ram) =
                        machine(bits, ExecutionEngine::Interpreter, &code);
                    input(&mut memory, wide);
                    jit.x87.control_word = 0x7f | pc << 8 | rc << 10;
                    warm(&mut jit, &mut memory);
                    let regs = jit.regs.clone();
                    let floating = jit.x87.clone();
                    let mut saved = [0; 256];
                    memory.read(PhysAddr(DATA), &mut saved).unwrap();
                    for budget in 1..=32 {
                        jit.regs = regs.clone();
                        jit.x87 = floating.clone();
                        reference.regs = regs.clone();
                        reference.x87 = floating.clone();
                        reference.call_boundary_sequence = jit.call_boundary_sequence;
                        memory.write(PhysAddr(DATA), &saved).unwrap();
                        ram.write(PhysAddr(DATA), &saved).unwrap();
                        let retired = run(&mut jit, &mut memory, budget).unwrap();
                        assert_eq!(retired, budget.min(8));
                        interpret(&mut reference, &mut ram, retired);
                        assert!(
                            jit.capture_context() == reference.capture_context(),
                            "bits={bits} wide={wide} pc={pc} rc={rc} budget={budget}\njit={:?}\nreference={:?}",
                            jit.x87,
                            reference.x87
                        );
                        let mut actual = [0; 256];
                        let mut expected = [0; 256];
                        memory.read(PhysAddr(DATA), &mut actual).unwrap();
                        ram.read(PhysAddr(DATA), &mut expected).unwrap();
                        assert_eq!(actual, expected);
                    }
                }
            }
        }
    }
}
#[test]
fn ieee_memory_special_operands_exit_before_the_instruction_and_recheck_permissions() {
    for wide in [false, true] {
        let code = program(16, wide);
        let (mut jit, mut memory) = machine(16, ExecutionEngine::Jit, &code);
        let (mut reference, mut ram) = machine(16, ExecutionEngine::Interpreter, &code);
        input(&mut memory, wide);
        warm(&mut jit, &mut memory);
        let regs = jit.regs.clone();
        let floating = jit.x87.clone();
        for at_source in [false, true] {
            let cases = if wide {
                [
                    1u64,
                    0x7ff0_0000_0000_0000,
                    0x7ff8_0000_0000_0001,
                    0x7ff0_0000_0000_0001,
                ]
            } else {
                [1, 0x7f80_0000, 0x7fc0_0001, 0x7f80_0001]
            };
            for value in cases {
                jit.regs = regs.clone();
                jit.x87 = floating.clone();
                reference.regs = regs.clone();
                reference.x87 = floating.clone();
                reference.call_boundary_sequence = jit.call_boundary_sequence;
                input(&mut memory, wide);
                input(&mut ram, wide);
                let address = PhysAddr(DATA + if at_source { 8 } else { 0 });
                let width = if wide { 8 } else { 4 };
                memory
                    .write(address, &value.to_le_bytes()[..width])
                    .unwrap();
                ram.write(address, &value.to_le_bytes()[..width]).unwrap();
                let retired = run(&mut jit, &mut memory, 32);
                assert_eq!(retired, if at_source { Some(1) } else { None });
                if at_source {
                    interpret(&mut reference, &mut ram, 1);
                }
                assert!(jit.capture_context() == reference.capture_context());
                assert_eq!(
                    jit.step_with_context(&mut memory, &mut NoPorts, &RealModeSegments),
                    reference.step_with_context(&mut ram, &mut NoPorts, &RealModeSegments)
                );
                assert!(jit.capture_context() == reference.capture_context());
            }
        }
        jit.regs = regs;
        jit.x87 = floating;
        input(&mut memory, wide);
        let before = jit.capture_context();
        let ds = crate::registers::SegmentRegister::Ds;
        let limit = jit.system.segment_cache_mut(ds).descriptor.limit;
        jit.system.segment_cache_mut(ds).descriptor.limit = 0x307;
        assert_eq!(run(&mut jit, &mut memory, 32), None);
        jit.system.segment_cache_mut(ds).descriptor.limit = limit;
        assert!(jit.capture_context() == before);
    }
}

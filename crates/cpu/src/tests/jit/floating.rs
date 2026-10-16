//! The JIT's integer implementation is compared with the existing APFloat
//! arithmetic, then exercised through checked x87 decode/access/retirement.
use super::*;
use crate::x87_state::{Ext80, X87State};

fn extended(significand: u64, sign_exponent: u16) -> Ext80 {
    Ext80 {
        significand,
        sign_exponent,
    }
}
fn warm(cpu: &mut Cpu, control: u16) {
    for _ in 0..32 {
        cpu.jit.multiply_float(
            extended(1 << 63, 0x3fff),
            extended(1 << 63, 0x3fff),
            control,
        );
    }
    assert!(cpu.jit_statistics().float_compiled > 0);
    assert_eq!(cpu.jit_statistics().failures, 0);
}
#[test]
fn jit_extended_products_match_apfloat_all_precision_rounding_and_range_classes() {
    let mut cpu = Cpu::new(Registers::default());
    cpu.set_execution_engine(ExecutionEngine::Jit);
    let mut random = 0x1357_2468_abcdu64;
    let mut accepted = 0;
    for pc in 0..4 {
        for rc in 0..4 {
            let control = 0x7f | pc << 8 | rc << 10;
            warm(&mut cpu, control);
            for sample in 0..4096 {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                let left = extended(
                    random | (1 << 63),
                    if sample & 1 != 0 { 0xbfff } else { 0x3fff },
                );
                random = random.rotate_left(23).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                let right = extended(
                    random | (1 << 63),
                    [0x0001, 0x3fff, 0x4000, 0x7ffe][sample % 4],
                );
                let expected =
                    crate::x87_math::binary(crate::x87_math::BinaryOp::Mul, left, right, control);
                if let Some(result) = cpu.jit.multiply_float(left, right, control) {
                    assert_eq!(result, expected, "pc={pc} rc={rc} sample={sample}");
                    accepted += 1;
                }
            }
            // Products arbitrarily close to the largest finite value, and
            // precision carries at the normal/subnormal boundary. Include
            // unmasked range controls so biased exception results cannot be
            // mistaken for an ordinary normal product.
            for exponent in [1, 2, 0x3fff, 0x7ffd, 0x7ffe] {
                for left_sig in [1 << 63, (1 << 63) + 1, u64::MAX - 1, u64::MAX] {
                    for right_sig in [1 << 63, (1 << 63) + 1, 0xc000_0000_0000_0000, u64::MAX] {
                        for masks in [control, control & !8, control & !16] {
                            let left = extended(left_sig, exponent);
                            let right = extended(right_sig, 0x3fff);
                            let expected = crate::x87_math::binary(
                                crate::x87_math::BinaryOp::Mul,
                                left,
                                right,
                                masks,
                            );
                            if let Some(result) = cpu.jit.multiply_float(left, right, masks) {
                                assert_eq!(
                                    result, expected,
                                    "pc={pc} rc={rc} exponent={exponent:x} masks={masks:x} left={left_sig:x} right={right_sig:x}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(accepted > 45_000);
    assert_eq!(cpu.jit_statistics().failures, 0);
}

fn input(pair: &mut [Fixture; 2], control: u16, left: Ext80, right: Ext80) {
    for fixture in pair {
        fixture.cpu.regs.eip = 0;
        fixture.cpu.x87 = X87State {
            control_word: control,
            ..X87State::default()
        };
        fixture.cpu.x87.write_st(0, left);
        fixture.cpu.x87.write_st(1, right);
    }
}
#[test]
fn jit_x87_register_pop_and_checked_memory_operands_keep_complete_state_and_accesses() {
    let mut pair = pair();
    let one = extended((1 << 63) + 1, 0x3fff);
    for bytes in [
        vec![0xd8, 0xc9],
        vec![0xdc, 0xc9],
        vec![0xde, 0xc9],
        vec![0xd8, 0x0e, 0x00, 0x02],
        vec![0xdc, 0x0e, 0x00, 0x02],
        vec![0xda, 0x0e, 0x00, 0x02],
    ] {
        code(&mut pair, &bytes);
        for fixture in &mut pair {
            fixture
                .memory
                .ram
                .put(DATA as usize, &0x3ff8_0000_3fc0_0000u64.to_le_bytes());
        }
        warm(&mut pair[0].cpu, 0x37f);
        let before = pair[0].cpu.jit_statistics().float_executed;
        for _ in 0..40 {
            input(
                &mut pair,
                0x37f,
                one,
                extended(0xc000_0000_0000_0000, 0x3fff),
            );
            assert_eq!(step(&mut pair).outcome, Ok(StepOutcome::Continue));
        }
        assert!(
            pair[0].cpu.jit_statistics().float_executed > before,
            "{bytes:02x?}"
        );
        // Failure remains a single checked access, even after warming.
        if bytes.len() > 2 {
            input(&mut pair, 0x37f, one, one);
            for fixture in &mut pair {
                fixture.memory.reject_data_read = true;
            }
            assert!(step(&mut pair).outcome.is_err());
            for fixture in &mut pair {
                fixture.memory.reject_data_read = false;
            }
        }
    }
}

#[test]
fn jit_x87_exceptional_inputs_empty_stack_and_unmasked_precision_keep_fault_boundaries() {
    let mut pair = pair();
    code(&mut pair, &[0xd8, 0xc9, 0x9b]); // FMUL; WAIT
    warm(&mut pair[0].cpu, 0x37f);
    let one = extended(1 << 63, 0x3fff);
    for value in [
        extended(0, 0),
        extended(1, 0),
        extended(1 << 63, 0),
        extended(1, 0x3fff),
        extended(1 << 63, 0x7fff),
        extended(0xc000_0000_0000_0001, 0x7fff),
        extended(u64::MAX, 0x7ffe),
    ] {
        input(&mut pair, 0x37f, value, extended(1 << 63, 0x4000));
        step(&mut pair);
    }
    input(&mut pair, 0x37f, one, one);
    for fixture in &mut pair {
        fixture.cpu.x87.empty_st(1);
    }
    step(&mut pair);
    input(
        &mut pair,
        0x35f,
        extended((1 << 63) + 1, 0x3fff),
        extended((1 << 63) + 1, 0x3fff),
    );
    assert_eq!(step(&mut pair).outcome, Ok(StepOutcome::Continue));
    assert_ne!(pair[0].cpu.x87.status_word & 32, 0);
    assert_eq!(pair[0].cpu.regs.eip, 2);
    assert!(step(&mut pair).outcome.is_err());
    // CR0.TS is still checked before any warmed generated arithmetic.
    input(&mut pair, 0x37f, one, one);
    for fixture in &mut pair {
        fixture.cpu.system.cr0 |= crate::system::CR0_TS;
    }
    let before = pair[0].cpu.jit_statistics().float_executed;
    step(&mut pair);
    assert_eq!(pair[0].cpu.jit_statistics().float_executed, before);
}

#[test]
#[ignore = "explicit x87 arithmetic throughput comparison"]
fn jit_x87_multiply_throughput_measurement() {
    use std::time::Instant;
    let mut cpu = Cpu::new(Registers::default());
    cpu.set_execution_engine(ExecutionEngine::Jit);
    warm(&mut cpu, 0x37f);
    let right = extended(0xcccc_cccc_cccc_cccd, 0x3fff);
    let mut checksums = [0u64; 2];
    let mut timings = [Vec::new(), Vec::new()];
    for round in 0..5 {
        for kind in if round % 2 == 0 { [0, 1] } else { [1, 0] } {
            let start = Instant::now();
            let mut checksum = 0;
            for i in 0..30_000u64 {
                let left = extended(0x8123_4567_89ab_cdefu64.wrapping_add(i * 137), 0x3fff);
                let result = if kind == 0 {
                    cpu.jit.multiply_float(left, right, 0x37f).unwrap()
                } else {
                    crate::x87_math::binary(crate::x87_math::BinaryOp::Mul, left, right, 0x37f)
                };
                let result = std::hint::black_box(result);
                checksum ^=
                    result.value.significand ^ u64::from(result.exceptions) ^ u64::from(result.c1);
            }
            timings[kind].push(start.elapsed().as_nanos());
            checksums[kind] = checksum;
        }
    }
    assert_eq!(checksums[0], checksums[1]);
    let median = timings.map(|mut samples| {
        samples.sort_unstable();
        samples[2]
    });
    eprintln!(
        "JIT_X87_MULTIPLY target={} operations=30000 jit_median_ns={} software_median_ns={} speedup={:.3}",
        std::env::consts::ARCH,
        median[0],
        median[1],
        median[1] as f64 / median[0] as f64
    );
}

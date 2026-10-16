//! Compare memory expansion and each rounded prefix with the APFloat adapter.
use super::*;
use compat16_jit::{
    FloatBlock, FloatBlockCache, FloatInstruction as I, FloatMemoryFormat as F, FloatRegisters,
};

#[test]
fn ieee_memory_blocks_preserve_extended_results_flags_and_precise_fallbacks() {
    let mut cache = FloatBlockCache::default();
    let mut random = 0x1357_2468_abcdef01u64;
    for format in [F::Binary32, F::Binary64] {
        let width = usize::from(format.bytes());
        let load_offset = (256 - width) as u8;
        let convert = |bits| match format {
            F::Binary32 => from_f32_bits(bits as u32),
            F::Binary64 => from_f64_bits(bits),
        };
        let accepted = |bits: u64| {
            let (fraction, exp) = match format {
                F::Binary32 => (23, 8),
                F::Binary64 => (52, 11),
            };
            let exponent = (bits >> fraction) & ((1 << exp) - 1);
            let payload = bits & ((1u64 << (fraction + exp)) - 1);
            payload == 0 || exponent != 0 && exponent != (1 << exp) - 1
        };
        let one = match format {
            F::Binary32 => 0x3f80_0000u64,
            F::Binary64 => 0x3ff0_0000_0000_0000,
        };
        for (operation, reference) in [
            (FloatOperation::Add, BinaryOp::Add),
            (FloatOperation::Subtract, BinaryOp::Sub),
            (FloatOperation::Multiply, BinaryOp::Mul),
            (FloatOperation::Divide, BinaryOp::Div),
        ] {
            for reverse in [false, true] {
                let block = FloatBlock::new(vec![
                    I::LoadMemory {
                        format,
                        offset: load_offset,
                    },
                    I::BinaryMemory {
                        format,
                        offset: 1,
                        operation,
                        reverse,
                    },
                ])
                .unwrap();
                for pc in [0, 2, 3] {
                    for rc in 0..4 {
                        let initial = FloatRegisters {
                            values: [Float80 {
                                significand: 0x1357,
                                sign_exponent: 0xabcd,
                            }; 8],
                            tags: 0xffff,
                            status: 0xc780,
                            control: 0x7f | pc << 8 | rc << 10,
                        };
                        let mut bytes = [0xa5; 256];
                        bytes[usize::from(load_offset)..]
                            .copy_from_slice(&one.to_le_bytes()[..width]);
                        bytes[1..1 + width].copy_from_slice(&one.to_le_bytes()[..width]);
                        for _ in 0..8 {
                            cache.execute(&block, &mut initial.clone(), &mut bytes, 2);
                        }
                        for index in 0..264 {
                            random ^= random << 13;
                            random ^= random >> 7;
                            random ^= random << 17;
                            let left = if index < 8 {
                                [
                                    0,
                                    1,
                                    one,
                                    one | (1 << (width * 8 - 1)),
                                    (one - 1),
                                    (one * 2 - 1),
                                    (1u64 << (width * 8 - 1)),
                                    u64::MAX,
                                ][index]
                            } else {
                                random
                            };
                            random = random.rotate_left(23).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                            let right = if index < 8 {
                                [
                                    one,
                                    one,
                                    0,
                                    1,
                                    u64::MAX,
                                    one,
                                    (1u64 << (width * 8 - 1)),
                                    one,
                                ][index]
                            } else {
                                random
                            };
                            bytes[usize::from(load_offset)..]
                                .copy_from_slice(&left.to_le_bytes()[..width]);
                            bytes[1..1 + width].copy_from_slice(&right.to_le_bytes()[..width]);
                            for budget in [1, 2, 32] {
                                let mut actual = initial;
                                let mut ram = bytes;
                                let retired = cache
                                    .execute(&block, &mut actual, &mut ram, budget)
                                    .unwrap();
                                let mut expected = initial;
                                let mut count = 0;
                                if accepted(left) {
                                    let loaded = convert(left).value;
                                    let mut value = loaded;
                                    count = 1;
                                    expected.status =
                                        (expected.status & !(0x8080 | 0x3800 | 0x200)) | (7 << 11);
                                    if budget > 1 && accepted(right) {
                                        let other = convert(right).value;
                                        if reference != BinaryOp::Div
                                            || (if reverse { loaded } else { other }).significand
                                                != 0
                                        {
                                            let result = if reverse {
                                                binary(reference, other, loaded, initial.control)
                                            } else {
                                                binary(reference, loaded, other, initial.control)
                                            };
                                            assert!(result.range.is_none());
                                            value = result.value;
                                            expected.status |= result.exceptions
                                                | if result.c1 { 0x200 } else { 0 };
                                            count = 2;
                                        }
                                    }
                                    expected.values[7] = Float80 {
                                        significand: value.significand,
                                        sign_exponent: value.sign_exponent,
                                    };
                                    expected.tags = (expected.tags & !(3 << 14))
                                        | if value.significand == 0 { 1 << 14 } else { 0 };
                                }
                                assert_eq!(
                                    retired, count,
                                    "{format:?} {operation:?} reverse={reverse} pc={pc} rc={rc} left={left:x} right={right:x}"
                                );
                                assert_eq!(actual, expected);
                                assert_eq!(ram, bytes);
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cache.statistics().failures, 0);
}

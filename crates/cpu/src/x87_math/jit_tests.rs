//! The portable integer JIT is checked against the existing APFloat adapter
//! on every development host, independently of the CPU's host enablement.
use super::*;
use compat16_jit::{Float80, FloatCache, FloatOperation};
fn raw(significand: u64, sign_exponent: u16) -> Ext80 {
    Ext80 {
        significand,
        sign_exponent,
    }
}
#[test]
fn all_jit_binary_operations_match_precision_rounding_cancellation_and_division() {
    let mut cache = FloatCache::default();
    let mut random = 0x1357_2468_abcdu64;
    let mut accepted = [0usize; 4];
    for (index, (operation, jit)) in [
        (BinaryOp::Add, FloatOperation::Add),
        (BinaryOp::Sub, FloatOperation::Subtract),
        (BinaryOp::Mul, FloatOperation::Multiply),
        (BinaryOp::Div, FloatOperation::Divide),
    ]
    .into_iter()
    .enumerate()
    {
        for pc in 0..4 {
            for rc in 0..4 {
                let control = 0x7f | pc << 8 | rc << 10;
                let convert = |v: Ext80| Float80 {
                    significand: v.significand,
                    sign_exponent: v.sign_exponent,
                };
                for _ in 0..32 {
                    cache.binary(
                        jit,
                        convert(raw(1 << 63, 0x3fff)),
                        convert(raw(1 << 63, 0x3fff)),
                        control,
                    );
                }
                assert_eq!(cache.statistics().failures, 0, "{jit:?} pc={pc} rc={rc}");
                let mut check = |left, right, control| {
                    if let Some(result) = cache.binary(jit, convert(left), convert(right), control)
                    {
                        let expected = binary(operation, left, right, control);
                        assert_eq!(
                            (
                                raw(result.value.significand, result.value.sign_exponent),
                                result.exceptions,
                                result.c1
                            ),
                            (expected.value, expected.exceptions, expected.c1),
                            "{jit:?} pc={pc} rc={rc} cw={control:x} left={left:?} right={right:?}"
                        );
                        assert!(expected.range.is_none());
                        accepted[index] += 1;
                    }
                };
                for _ in 0..8192 {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    let left = raw(
                        random | (1 << 63),
                        ((random >> 17) as u16 % 0x7ffe + 1) | (random as u16 & 0x8000),
                    );
                    random = random.rotate_left(23).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                    let right = raw(
                        random | (1 << 63),
                        ((random >> 17) as u16 % 0x7ffe + 1) | (random as u16 & 0x8000),
                    );
                    check(left, right, control);
                }
                for exp in [1u16, 64, 0x3fff, 0x7ffe] {
                    for distance in [
                        0u16, 1, 2, 23, 24, 25, 52, 53, 54, 63, 64, 65, 126, 127, 128, 129,
                    ] {
                        if exp <= distance {
                            continue;
                        }
                        for ls in [
                            1u64 << 63,
                            (1 << 63) + 1,
                            0xc000_0000_0000_0000,
                            u64::MAX - 1,
                            u64::MAX,
                        ] {
                            for rs in [
                                1u64 << 63,
                                (1 << 63) + 1,
                                0x8000_0001_ffff_ffff,
                                0xc000_0000_0000_0000,
                                u64::MAX,
                            ] {
                                for sign in [0, 0x8000] {
                                    for masks in
                                        [control, control & !8, control & !16, control & !32]
                                    {
                                        check(
                                            raw(ls, exp),
                                            raw(rs, (exp - distance) | sign),
                                            masks,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                for sign in [0u16, 0x8000] {
                    for other in [
                        raw(0, 0),
                        raw(0, 0x8000),
                        raw((1 << 63) + 1, 0x3fff),
                        raw(u64::MAX, 0xffff - 1),
                    ] {
                        check(raw(0, sign), other, control);
                        check(other, raw(0, sign), control);
                    }
                }
            }
        }
    }
    assert!(
        accepted.into_iter().all(|count| count > 140_000),
        "{accepted:?}"
    );
    assert_eq!(cache.statistics().float_compiled, 48);
    assert_eq!(cache.statistics().failures, 0);
}

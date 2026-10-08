use crate::x87_state::Ext80;

use super::{
    BinaryOp, Classification, RegisterRangeKind, X87_DE, X87_IE, X87_OE, X87_PE, X87_UE, binary,
    classify, from_f32_bits, from_f64_bits, from_i128, remainder, scale, sqrt, to_f32_bits,
    to_f64_bits, to_i128,
};

const DEFAULT_CW: u16 = 0x037f;
const PC24_NEAREST: u16 = 0x007f;
const PC24_UP: u16 = 0x087f;
const PC24_DOWN: u16 = 0x047f;
const PC24_TOWARD_ZERO: u16 = 0x0c7f;

fn normal(significand: u64, exponent: u16) -> Ext80 {
    Ext80 {
        significand,
        sign_exponent: exponent,
    }
}

fn one() -> Ext80 {
    normal(1 << 63, 0x3fff)
}

fn pow2(exponent: i32) -> Ext80 {
    normal(1 << 63, (exponent + 16_383) as u16)
}

fn exact_power_of_two(exponent: i32) -> Ext80 {
    if exponent >= -16_382 {
        pow2(exponent)
    } else {
        Ext80 {
            significand: 1_u64 << (exponent + 16_445),
            sign_exponent: 0,
        }
    }
}

#[test]
fn arithmetic_uses_control_word_precision_without_double_rounding() {
    let half_ulp = pow2(-24);
    let nearest = binary(BinaryOp::Add, one(), half_ulp, PC24_NEAREST);
    assert_eq!(nearest.value, one());
    assert_ne!(nearest.exceptions & X87_PE, 0);
    assert!(!nearest.c1);

    let upward = binary(BinaryOp::Add, one(), half_ulp, PC24_UP);
    assert_eq!(upward.value, normal(0x8000_0100_0000_0000, 0x3fff));
    assert!(upward.c1);

    let downward = binary(BinaryOp::Add, one(), half_ulp, PC24_DOWN);
    assert_eq!(downward.value, one());
    assert!(!downward.c1);
}

#[test]
fn arithmetic_reports_minimum_subnormal_rounding_and_underflow() {
    let minimum_subnormal = Ext80 {
        significand: 1,
        sign_exponent: 0,
    };
    let half = binary(
        BinaryOp::Div,
        minimum_subnormal,
        normal(1 << 63, 0x4000),
        DEFAULT_CW,
    );
    assert_eq!(half.value, Ext80::default());
    assert_eq!(half.exceptions & (X87_UE | X87_PE), X87_UE | X87_PE);

    let upward = binary(
        BinaryOp::Div,
        minimum_subnormal,
        normal(1 << 63, 0x4000),
        0x0b7f,
    );
    assert_eq!(upward.value, minimum_subnormal);
    assert_eq!(upward.exceptions & (X87_UE | X87_PE), X87_UE | X87_PE);
    assert!(upward.c1);
}

#[test]
fn reduced_precision_uses_its_own_fixed_subnormal_grid() {
    let minimum_normal = Ext80 {
        significand: 1 << 63,
        sign_exponent: 1,
    };
    let two_to_24 = pow2(24);
    let half_minimum_pc24_subnormal =
        binary(BinaryOp::Div, minimum_normal, two_to_24, PC24_NEAREST);
    assert_eq!(half_minimum_pc24_subnormal.value, Ext80::default());
    assert_eq!(
        half_minimum_pc24_subnormal.exceptions & (X87_UE | X87_PE),
        X87_UE | X87_PE
    );

    let upward = binary(BinaryOp::Div, minimum_normal, two_to_24, PC24_UP);
    assert_eq!(
        upward.value,
        Ext80 {
            significand: 1 << 40,
            sign_exponent: 0
        }
    );
    assert_eq!(upward.exceptions & (X87_UE | X87_PE), X87_UE | X87_PE);
}

#[test]
fn exact_cancellation_obeys_round_toward_negative_zero_sign() {
    let negative_one = Ext80 {
        significand: 1 << 63,
        sign_exponent: 0xbfff,
    };
    let result = binary(BinaryOp::Add, one(), negative_one, 0x047f);
    assert_eq!(
        result.value,
        Ext80 {
            significand: 0,
            sign_exponent: 0x8000
        }
    );
    assert_eq!(result.exceptions, 0);
}

#[test]
fn arithmetic_overflow_obeys_directed_rounding() {
    let largest = normal(u64::MAX, 0x7ffe);
    let nearest = binary(
        BinaryOp::Mul,
        largest,
        normal(1 << 63, 0x4000),
        PC24_NEAREST,
    );
    assert_eq!(nearest.value.sign_exponent & 0x7fff, 0x7fff);
    assert_ne!(nearest.exceptions & X87_OE, 0);

    let toward_zero = binary(
        BinaryOp::Mul,
        largest,
        normal(1 << 63, 0x4000),
        PC24_TOWARD_ZERO,
    );
    assert_eq!(toward_zero.value, normal(0xffff_ff00_0000_0000, 0x7ffe));
    assert_ne!(toward_zero.exceptions & X87_OE, 0);
}

#[test]
fn unmasked_binary_range_traps_return_biased_register_payloads() {
    let largest = normal(u64::MAX, 0x7ffe);
    let two = normal(1 << 63, 0x4000);
    let overflow_cw = DEFAULT_CW & !(1 << 3);
    let overflow = binary(BinaryOp::Mul, largest, two, overflow_cw);
    let overflow_range = overflow.range.expect("unmasked OE payload");
    assert_eq!(overflow_range.kind, RegisterRangeKind::Overflow);
    assert_eq!(overflow_range.biased_value, normal(u64::MAX, 0x1fff));
    assert!(!overflow_range.precision_lost);
    assert!(!overflow_range.biased_c1);
    assert_eq!(overflow.exceptions & (X87_OE | X87_PE), X87_OE);

    let minimum_normal = normal(1 << 63, 1);
    let half = normal(1 << 63, 0x3ffe);
    let underflow_cw = DEFAULT_CW & !(1 << 4);
    let underflow = binary(BinaryOp::Mul, minimum_normal, half, underflow_cw);
    let underflow_range = underflow.range.expect("unmasked UE payload");
    assert_eq!(underflow_range.kind, RegisterRangeKind::Underflow);
    assert_eq!(underflow_range.biased_value, normal(1 << 63, 0x6000));
    assert!(!underflow_range.precision_lost);
    assert_eq!(underflow.exceptions & (X87_UE | X87_PE), X87_UE);
}

#[test]
fn unmasked_underflow_uses_the_precision_rounded_unbounded_exponent() {
    let minimum_normal = normal(1 << 63, 1);
    let quarter_pc24_ulp = exact_power_of_two(-16_407);
    let unmasked_um = !(1 << 4);

    let nearest = binary(
        BinaryOp::Sub,
        minimum_normal,
        quarter_pc24_ulp,
        PC24_NEAREST & unmasked_um,
    );
    assert!(nearest.range.is_none());
    assert_eq!(nearest.value, minimum_normal);
    assert_eq!(nearest.exceptions & X87_UE, 0);

    let downward = binary(
        BinaryOp::Sub,
        minimum_normal,
        quarter_pc24_ulp,
        PC24_DOWN & unmasked_um,
    );
    assert_eq!(downward.range.unwrap().kind, RegisterRangeKind::Underflow);

    let negative_minimum = Ext80 {
        sign_exponent: 0x8001,
        ..minimum_normal
    };
    let upward_negative = binary(
        BinaryOp::Add,
        negative_minimum,
        quarter_pc24_ulp,
        PC24_UP & unmasked_um,
    );
    assert_eq!(
        upward_negative.range.unwrap().kind,
        RegisterRangeKind::Underflow
    );
}

#[test]
fn unmasked_fscale_extreme_finite_exponents_apply_bias_before_massive_range() {
    let one = one();
    let positive_exponent = from_i128(50_000).value;
    let negative_exponent = from_i128(-50_000).value;

    let overflow = scale(one, positive_exponent, DEFAULT_CW & !(1 << 3));
    let overflow_range = overflow.range.unwrap();
    assert_eq!(overflow_range.kind, RegisterRangeKind::Overflow);
    assert_eq!(classify(overflow_range.biased_value), Classification::Infinity);
    assert_eq!(overflow.exceptions & (X87_OE | X87_PE), X87_OE);

    let underflow = scale(one, negative_exponent, DEFAULT_CW & !(1 << 4));
    let underflow_range = underflow.range.unwrap();
    assert_eq!(underflow_range.kind, RegisterRangeKind::Underflow);
    assert_eq!(classify(underflow_range.biased_value), Classification::Zero);
    assert_eq!(underflow.exceptions & (X87_UE | X87_PE), X87_UE);
}

#[test]
fn values_just_above_max_finite_only_overflow_if_rounding_crosses_the_boundary() {
    let largest_pc24 = normal(0xffff_ff00_0000_0000, 0x7ffe);
    let one_ext_ulp_below_half_pc24_ulp = pow2(16_320);
    let result = binary(
        BinaryOp::Add,
        largest_pc24,
        one_ext_ulp_below_half_pc24_ulp,
        PC24_NEAREST,
    );
    assert_eq!(result.value, largest_pc24);
    assert_eq!(result.exceptions & X87_OE, 0);
    assert_ne!(result.exceptions & X87_PE, 0);
    assert!(!result.c1);
}

#[test]
fn fscale_matches_all_49_signed_classification_combinations() {
    #[derive(Clone, Copy)]
    enum Kind {
        NaN,
        NegativeZero,
        PositiveZero,
        NegativeFinite,
        PositiveFinite,
        NegativeInfinity,
        PositiveInfinity,
    }

    let values = [
        normal(1 << 63, 0xffff),
        normal(1 << 63, 0xbfff),
        Ext80 {
            significand: 0,
            sign_exponent: 0x8000,
        },
        Ext80 {
            significand: 0,
            sign_exponent: 0,
        },
        one(),
        normal(1 << 63, 0x7fff),
        normal(0xc000_0000_0000_0000, 0x7fff),
    ];
    let expected = [
        [
            Kind::NaN,
            Kind::NegativeInfinity,
            Kind::NegativeInfinity,
            Kind::NegativeInfinity,
            Kind::NegativeInfinity,
            Kind::NegativeInfinity,
            Kind::NaN,
        ],
        [
            Kind::NegativeZero,
            Kind::NegativeFinite,
            Kind::NegativeFinite,
            Kind::NegativeFinite,
            Kind::NegativeFinite,
            Kind::NegativeInfinity,
            Kind::NaN,
        ],
        [
            Kind::NegativeZero,
            Kind::NegativeZero,
            Kind::NegativeZero,
            Kind::NegativeZero,
            Kind::NegativeZero,
            Kind::NaN,
            Kind::NaN,
        ],
        [
            Kind::PositiveZero,
            Kind::PositiveZero,
            Kind::PositiveZero,
            Kind::PositiveZero,
            Kind::PositiveZero,
            Kind::NaN,
            Kind::NaN,
        ],
        [
            Kind::PositiveZero,
            Kind::PositiveFinite,
            Kind::PositiveFinite,
            Kind::PositiveFinite,
            Kind::PositiveFinite,
            Kind::PositiveInfinity,
            Kind::NaN,
        ],
        [
            Kind::NaN,
            Kind::PositiveInfinity,
            Kind::PositiveInfinity,
            Kind::PositiveInfinity,
            Kind::PositiveInfinity,
            Kind::PositiveInfinity,
            Kind::NaN,
        ],
        [
            Kind::NaN,
            Kind::NaN,
            Kind::NaN,
            Kind::NaN,
            Kind::NaN,
            Kind::NaN,
            Kind::NaN,
        ],
    ];

    for (row, lhs) in values.into_iter().enumerate() {
        for (column, rhs) in values.into_iter().enumerate() {
            let result = scale(lhs, rhs, DEFAULT_CW);
            match expected[row][column] {
                Kind::NaN => assert_eq!(
                    classify(result.value),
                    Classification::QuietNaN,
                    "row={row} column={column}"
                ),
                Kind::NegativeZero => {
                    assert_eq!(
                        classify(result.value),
                        Classification::Zero,
                        "row={row} column={column}"
                    );
                    assert_ne!(
                        result.value.sign_exponent & 0x8000,
                        0,
                        "row={row} column={column}"
                    );
                }
                Kind::PositiveZero => {
                    assert_eq!(
                        classify(result.value),
                        Classification::Zero,
                        "row={row} column={column}"
                    );
                    assert_eq!(
                        result.value.sign_exponent & 0x8000,
                        0,
                        "row={row} column={column}"
                    );
                }
                Kind::NegativeFinite => {
                    assert_eq!(
                        classify(result.value),
                        Classification::Finite,
                        "row={row} column={column}"
                    );
                    assert_ne!(
                        result.value.sign_exponent & 0x8000,
                        0,
                        "row={row} column={column}"
                    );
                }
                Kind::PositiveFinite => {
                    assert_eq!(
                        classify(result.value),
                        Classification::Finite,
                        "row={row} column={column}"
                    );
                    assert_eq!(
                        result.value.sign_exponent & 0x8000,
                        0,
                        "row={row} column={column}"
                    );
                }
                Kind::NegativeInfinity => {
                    assert_eq!(
                        classify(result.value),
                        Classification::Infinity,
                        "row={row} column={column}"
                    );
                    assert_ne!(
                        result.value.sign_exponent & 0x8000,
                        0,
                        "row={row} column={column}"
                    );
                }
                Kind::PositiveInfinity => {
                    assert_eq!(
                        classify(result.value),
                        Classification::Infinity,
                        "row={row} column={column}"
                    );
                    assert_eq!(
                        result.value.sign_exponent & 0x8000,
                        0,
                        "row={row} column={column}"
                    );
                }
            }

            let expected_flags = match (row, column) {
                (0, 0) | (2, 5) | (3, 5) | (5, 0) => X87_IE,
                _ => 0,
            };
            assert_eq!(
                result.exceptions, expected_flags,
                "flags row={row} column={column}"
            );
        }
    }
}

#[test]
fn infinite_fscale_exponent_uses_exact_class_result_for_all_rc_and_masks() {
    for rc in 0..4 {
        for negative_value in [false, true] {
            for negative_scale in [false, true] {
                for mask_pattern in 0..4 {
                    let mut control_word = (DEFAULT_CW & !0x0c00) | (rc << 10);
                    if mask_pattern & 1 == 0 {
                        control_word &= !(1 << 3);
                    }
                    if mask_pattern & 2 == 0 {
                        control_word &= !(1 << 4);
                    }
                    let input = normal(
                        1 << 63,
                        if negative_value { 0xbfff } else { 0x3fff },
                    );
                    let infinite_scale = normal(
                        1 << 63,
                        if negative_scale { 0xffff } else { 0x7fff },
                    );
                    let result = scale(input, infinite_scale, control_word);
                    let sign = if negative_value { 0x8000 } else { 0 };
                    let expected = if negative_scale {
                        Ext80 {
                            significand: 0,
                            sign_exponent: sign,
                        }
                    } else {
                        Ext80 {
                            significand: 1 << 63,
                            sign_exponent: sign | 0x7fff,
                        }
                    };
                    assert_eq!(result.value, expected);
                    assert_eq!(result.exceptions, 0);
                    assert!(result.range.is_none());
                }
            }
        }
    }
}

#[test]
fn fscale_quiets_signaling_nan_and_reports_denormal_operands() {
    let one = one();
    let signaling_nan = normal(0x8000_0000_0000_0001, 0x7fff);
    let quieted = scale(one, signaling_nan, DEFAULT_CW);
    assert_eq!(classify(quieted.value), Classification::QuietNaN);
    assert_ne!(quieted.exceptions & X87_IE, 0);

    let minimum_subnormal = Ext80 {
        significand: 1,
        sign_exponent: 0,
    };
    let scaled = scale(minimum_subnormal, one, DEFAULT_CW);
    assert_ne!(scaled.exceptions & X87_DE, 0);
    assert_eq!(
        scaled.value,
        Ext80 {
            significand: 2,
            sign_exponent: 0
        }
    );

    let denormal_scale = scale(one, minimum_subnormal, DEFAULT_CW);
    assert_ne!(denormal_scale.exceptions & X87_DE, 0);
    assert_eq!(denormal_scale.value, one);
}

#[test]
fn fscale_reports_directed_overflow_for_both_signs() {
    let cases = [
        (DEFAULT_CW, false, true),
        (DEFAULT_CW | 0x0400, false, false),
        (DEFAULT_CW | 0x0800, false, true),
        (DEFAULT_CW | 0x0c00, false, false),
        (DEFAULT_CW, true, true),
        (DEFAULT_CW | 0x0400, true, true),
        (DEFAULT_CW | 0x0800, true, false),
        (DEFAULT_CW | 0x0c00, true, false),
    ];
    for (control_word, negative, infinity) in cases {
        let largest = normal(
            u64::MAX,
            if negative { 0xfffe } else { 0x7ffe },
        );
        let result = scale(largest, normal(1 << 63, 0x4000), control_word);
        assert_eq!(result.exceptions & (X87_OE | X87_PE), X87_OE | X87_PE);
        assert_eq!(classify(result.value), if infinity { Classification::Infinity } else { Classification::Finite });
        assert_eq!(result.value.sign_exponent & 0x8000, if negative { 0x8000 } else { 0 });
    }
}

#[test]
fn binary32_and_binary64_stores_report_directed_overflow_for_both_signs() {
    let cases = [
        (DEFAULT_CW, 0x7f80_0000, 0xff80_0000, 0x7ff0_0000_0000_0000, 0xfff0_0000_0000_0000),
        (DEFAULT_CW | 0x0400, 0x7f7f_ffff, 0xff80_0000, 0x7fef_ffff_ffff_ffff, 0xfff0_0000_0000_0000),
        (DEFAULT_CW | 0x0800, 0x7f80_0000, 0xff7f_ffff, 0x7ff0_0000_0000_0000, 0xffef_ffff_ffff_ffff),
        (DEFAULT_CW | 0x0c00, 0x7f7f_ffff, 0xff7f_ffff, 0x7fef_ffff_ffff_ffff, 0xffef_ffff_ffff_ffff),
    ];
    let positive_f32_overflow = normal(1 << 63, 0x407f); // 2^128
    let negative_f32_overflow = Ext80 { sign_exponent: 0xc07f, ..positive_f32_overflow };
    let positive_f64_overflow = normal(1 << 63, 0x43ff); // 2^1024
    let negative_f64_overflow = Ext80 { sign_exponent: 0xc3ff, ..positive_f64_overflow };

    for (control_word, pos32, neg32, pos64, neg64) in cases {
        let single_positive = to_f32_bits(positive_f32_overflow, control_word);
        assert_eq!(single_positive.bits as u32, pos32);
        assert_eq!(single_positive.exceptions & (X87_OE | X87_PE), X87_OE | X87_PE);
        let single_negative = to_f32_bits(negative_f32_overflow, control_word);
        assert_eq!(single_negative.bits as u32, neg32);
        assert_eq!(single_negative.exceptions & (X87_OE | X87_PE), X87_OE | X87_PE);

        let double_positive_exact = to_f64_bits(positive_f32_overflow, control_word);
        assert_eq!(double_positive_exact.bits, 0x47f0_0000_0000_0000);
        assert_eq!(double_positive_exact.exceptions & (X87_OE | X87_PE), 0);
        let double_negative_exact = to_f64_bits(negative_f32_overflow, control_word);
        assert_eq!(double_negative_exact.bits, 0xc7f0_0000_0000_0000);
        assert_eq!(double_negative_exact.exceptions & (X87_OE | X87_PE), 0);

        let single_positive_huge = to_f32_bits(positive_f64_overflow, control_word);
        assert_eq!(single_positive_huge.bits as u32, pos32);
        assert_eq!(single_positive_huge.exceptions & (X87_OE | X87_PE), X87_OE | X87_PE);
        let single_negative_huge = to_f32_bits(negative_f64_overflow, control_word);
        assert_eq!(single_negative_huge.bits as u32, neg32);
        assert_eq!(single_negative_huge.exceptions & (X87_OE | X87_PE), X87_OE | X87_PE);

        let double_positive = to_f64_bits(positive_f64_overflow, control_word);
        assert_eq!(double_positive.bits, pos64);
        assert_eq!(double_positive.exceptions & (X87_OE | X87_PE), X87_OE | X87_PE);
        let double_negative = to_f64_bits(negative_f64_overflow, control_word);
        assert_eq!(double_negative.bits, neg64);
        assert_eq!(double_negative.exceptions & (X87_OE | X87_PE), X87_OE | X87_PE);
    }
}

#[test]
fn pseudo_denormals_are_supported_but_report_denormal_operand() {
    let pseudo = Ext80 {
        significand: 1 << 63,
        sign_exponent: 0,
    };
    assert_eq!(classify(pseudo), Classification::Finite);
    let result = binary(BinaryOp::Add, pseudo, one(), DEFAULT_CW);
    assert_ne!(result.exceptions & X87_DE, 0);
    assert_eq!(result.value, one());
}

#[test]
fn unsupported_ext80_encodings_raise_invalid_and_return_indefinite() {
    let unsupported = Ext80 {
        significand: 1 << 62,
        sign_exponent: 0x4000,
    };
    assert_eq!(classify(unsupported), Classification::Unsupported);
    let result = binary(BinaryOp::Add, unsupported, one(), DEFAULT_CW);
    assert_ne!(result.exceptions & X87_IE, 0);
    assert_eq!(
        result.value,
        Ext80 {
            significand: 0xc000_0000_0000_0000,
            sign_exponent: 0xffff
        }
    );
}

#[test]
fn integer_and_binary_conversions_are_bit_exact_and_round_by_control_word() {
    let three = from_i128(3);
    assert_eq!(three.value, normal(0xc000_0000_0000_0000, 0x4000));
    assert_eq!(to_i128(three.value, 64, DEFAULT_CW, false).value, 3);

    let one_f32 = from_f32_bits(0x3f80_0000);
    assert_eq!(one_f32.value, one());
    assert_eq!(to_f32_bits(one(), DEFAULT_CW).bits as u32, 0x3f80_0000);
    assert_eq!(to_f64_bits(one(), DEFAULT_CW).bits, 0x3ff0_0000_0000_0000);

    let source = from_f64_bits(0x3ff0_0000_0000_0001);
    let rounded_down = to_f32_bits(source.value, DEFAULT_CW);
    assert_eq!(rounded_down.bits as u32, 0x3f80_0000);
    assert_ne!(rounded_down.exceptions & X87_PE, 0);
}

#[test]
fn sqrt_uses_exact_integer_square_root_and_x87_precision_control() {
    let four = normal(1 << 63, 0x4001);
    let exact = sqrt(four, DEFAULT_CW);
    assert_eq!(exact.value, normal(1 << 63, 0x4000));
    assert_eq!(exact.exceptions, 0);

    let two = normal(1 << 63, 0x4000);
    let root = sqrt(two, DEFAULT_CW);
    assert_eq!(root.value.significand, 0xb504_f333_f9de_6484);
    assert_ne!(root.exceptions & X87_PE, 0);

    let root_single = sqrt(two, PC24_NEAREST);
    assert_eq!(root_single.value.significand, 0xb504_f300_0000_0000);
}

#[test]
fn remainder_quotient_low_bits_use_exact_modular_powers() {
    let cases = [
        (4, 0x9000_0000_0000_0000, 0x8000_0000_0000_0000, 2),
        (5, 0x9000_0000_0000_0000, 0x8000_0000_0000_0000, 4),
        (8, 0x9000_0000_0000_0000, 0x8000_0000_0000_0000, 0),
        (31, 0x9000_0000_0000_0000, 0x8000_0000_0000_0000, 0),
        (63, 0x8000_0000_0000_0001, 0xc000_0000_0000_0001, 5),
    ];
    for (difference, lhs_significand, rhs_significand, quotient_low3) in cases {
        let lhs = Ext80 {
            significand: lhs_significand,
            sign_exponent: 0x3fff + difference,
        };
        let rhs = Ext80 {
            significand: rhs_significand,
            sign_exponent: 0x3fff,
        };
        let result = remainder(lhs, rhs, false);
        assert_eq!(result.quotient_low3, quotient_low3, "D={difference}");
        assert!(!result.partial, "D={difference}");

        let negative = Ext80 {
            sign_exponent: lhs.sign_exponent | 0x8000,
            ..lhs
        };
        let negative_result = remainder(negative, rhs, false);
        assert_eq!(
            negative_result.quotient_low3,
            0_u8.wrapping_sub(quotient_low3) & 7,
            "negative D={difference}"
        );
    }
}

//! Independent normal-result arithmetic vectors from exact rational numbers.

mod data;

#[test]
fn exponent_boundary_obeys_selected_precision_rounding_and_sign() {
    use crate::x87_math::{binary, BinaryOp};
    use crate::x87_state::Ext80;
    for (precision, pc) in [(24_u32, 0_u16), (53, 2), (64, 3)] {
        let max_sig = (((1_u128 << precision) - 1) << (64 - precision)) as u64;
        for mode in 0..4_u16 {
            for negative in [false, true] {
                let sign = if negative { 0x8000 } else { 0 };
                let cw = 0x7f | (pc << 8) | (mode << 10);
                let maximum = Ext80 { significand: max_sig, sign_exponent: sign | 0x7ffe };
                let away = (mode == 1 && negative) || (mode == 2 && !negative);
                // At the maximum retained significand, add 1/4 or 3/4 ULP.
                // The unbounded rounded exponent, not the exact discarded
                // tail alone, decides whether overflow has occurred.
                for above_half in [false, true] {
                    let addend = Ext80 {
                        significand: if above_half { 0xc000_0000_0000_0000 } else { 1 << 63 },
                        sign_exponent: sign | (0x7ffe - precision as u16 - u16::from(!above_half)),
                    };
                    let overflow = away || (mode == 0 && above_half);
                    let expected = if overflow {
                        Ext80 { significand: 1 << 63, sign_exponent: sign | 0x7fff }
                    } else { maximum };
                    let result = binary(BinaryOp::Add, maximum, addend, cw);
                    assert_eq!(result.value, expected, "PC {precision}, RC {mode}, sign {negative}, high tail {above_half}");
                    assert_eq!(result.exceptions, 0x20 | if overflow { 8 } else { 0 });
                    let unmasked = binary(BinaryOp::Add, maximum, addend, cw & !8);
                    if overflow {
                        let range = unmasked.range.expect("PC rounding across the maximum exponent must trap");
                        assert_eq!(range.biased_value, Ext80 { significand: 1 << 63, sign_exponent: sign | 0x1fff });
                        assert!(range.precision_lost);
                        assert!(range.biased_c1);
                    } else {
                        assert!(unmasked.range.is_none());
                        assert_eq!(unmasked.value, maximum);
                    }
                    assert_eq!(unmasked.exceptions, 0x20 | if overflow { 8 } else { 0 });
                }
                // Doubling max finite exceeds the exponent range even when
                // the selected rounding mode saturates to a finite value.
                let twice = binary(BinaryOp::Mul, maximum,
                    Ext80 { significand: 1 << 63, sign_exponent: 0x4000 }, cw);
                let expected = if mode == 0 || away {
                    Ext80 { significand: 1 << 63, sign_exponent: sign | 0x7fff }
                } else { maximum };
                assert_eq!(twice.value, expected, "doubling PC {precision}, RC {mode}, sign {negative}");
                assert_eq!(twice.exceptions, 0x28);
            }
        }
    }
}

use crate::x87_math::{BinaryOp, binary};
use crate::x87_state::Ext80;

#[test]
fn unmasked_range_results_match_independent_power_and_fraction_expectations() {
    use crate::x87_math::RegisterRangeKind;
    for (precision, pc) in [(24_u32, 0_u16), (53, 2), (64, 3)] {
        for mode in 0..4_u16 {
            for negative in [false, true] {
                let sign = if negative { 0x8000 } else { 0 };
                let cw = 0x7f | (pc << 8) | (mode << 10);
                let retained_max = (((1_u128 << precision) - 1) << (64 - precision)) as u64;
                let overflow = binary(BinaryOp::Mul,
                    Ext80 { significand: retained_max, sign_exponent: sign | 0x7ffe },
                    Ext80 { significand: 1 << 63, sign_exponent: 0x4000 }, cw & !8);
                let range = overflow.range.expect("exact overflow needs a register payload");
                assert_eq!(range.kind, RegisterRangeKind::Overflow);
                assert_eq!(range.biased_value, Ext80 { significand: retained_max, sign_exponent: sign | 0x1fff });
                assert!(!range.precision_lost);
                assert!(!range.biased_c1);
                assert_eq!(overflow.exceptions, 8);

                let tiny = binary(BinaryOp::Mul,
                    Ext80 { significand: 1 << 63, sign_exponent: sign | 1 },
                    Ext80 { significand: 1 << 63, sign_exponent: 0x3ffe }, cw & !16);
                let range = tiny.range.expect("exact tiny nonzero result traps with UM clear");
                assert_eq!(range.kind, RegisterRangeKind::Underflow);
                assert_eq!(range.biased_value, Ext80 { significand: 1 << 63, sign_exponent: sign | 0x6000 });
                assert!(!range.precision_lost);
                assert!(!range.biased_c1);
                assert_eq!(tiny.exceptions, 16);

                // minsub / 3 = (4/3) * 2^-16447. Round the normalized
                // significand using integer division, before applying bias.
                let numerator = 1_u128 << (precision + 1);
                let quotient = numerator / 3;
                let remainder = numerator % 3;
                let increment = match mode {
                    0 => remainder * 2 > 3,
                    1 => negative,
                    2 => !negative,
                    _ => false,
                };
                let expected_sig = ((quotient + u128::from(increment)) << (64 - precision)) as u64;
                let divided = binary(BinaryOp::Div,
                    Ext80 { significand: 1, sign_exponent: sign },
                    Ext80 { significand: 0xc000_0000_0000_0000, sign_exponent: 0x4000 }, cw & !16);
                let range = divided.range.expect("inexact tiny division needs a register payload");
                assert_eq!(range.kind, RegisterRangeKind::Underflow);
                assert_eq!(range.biased_value, Ext80 { significand: expected_sig, sign_exponent: sign | 0x5fc0 },
                    "PC {precision}, RC {mode}, negative {negative}");
                assert!(range.precision_lost);
                assert_eq!(range.biased_c1, increment);
                assert_eq!(divided.exceptions, 0x32); // DE from source, UE and PE from result.
            }
        }
    }
}

#[test]
fn normal_arithmetic_matches_independent_exact_rational_vectors() {
    for (index, &(operation, ls, le, rs, re, control, es, ee, flags, c1)) in data::CASES.iter().enumerate() {
        let operation = [BinaryOp::Add, BinaryOp::Sub, BinaryOp::Mul, BinaryOp::Div][operation as usize];
        let result = binary(operation,
            Ext80 { significand: ls, sign_exponent: le },
            Ext80 { significand: rs, sign_exponent: re }, control);
        assert_eq!(result.value, Ext80 { significand: es, sign_exponent: ee }, "case {index}, control={control:04x}");
        assert_eq!(result.exceptions, flags, "case {index} exception flags");
        assert_eq!(result.c1, c1, "case {index} C1");
    }
}

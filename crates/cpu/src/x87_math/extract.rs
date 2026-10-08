use rustc_apfloat::{Float, Round};

use crate::x87_state::Ext80;

use super::rounding::X87_ZE;
use super::{decode, from_apfloat, ExtractResult, X87_IE};
use rustc_apfloat::ieee::X87DoubleExtended as ApX87;

pub(crate) fn extract(value: Ext80) -> ExtractResult {
    let (input, flags) = match decode(value) {
        Ok(value) => value,
        Err(exceptions) => {
            return ExtractResult {
                significand: super::indefinite(),
                exponent: super::indefinite(),
                exceptions,
            };
        }
    };
    if input.is_zero() {
        return ExtractResult {
            significand: from_apfloat(input),
            exponent: from_apfloat(
                ApX87::INFINITY.copy_sign(ApX87::from_bits(1_u128 << 79)),
            ),
            exceptions: flags | X87_ZE,
        };
    }
    if input.is_infinite() {
        return ExtractResult {
            significand: from_apfloat(input),
            exponent: from_apfloat(ApX87::INFINITY),
            exceptions: flags,
        };
    }
    if input.is_nan() {
        let mut exceptions = flags;
        if input.is_signaling() {
            exceptions |= X87_IE;
        }
        let quiet = input + ApX87::ZERO;
        return ExtractResult {
            significand: from_apfloat(quiet.value),
            exponent: from_apfloat(quiet.value),
            exceptions,
        };
    }
    let exponent = input.ilogb();
    let significand = input.scalbn_r(-exponent, Round::TowardZero);
    let encoded_exponent = ApX87::from_i128(exponent.into()).value;
    ExtractResult {
        significand: from_apfloat(significand),
        exponent: from_apfloat(encoded_exponent),
        exceptions: flags,
    }
}

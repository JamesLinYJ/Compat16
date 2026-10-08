use rustc_apfloat::{Float, Status};

use crate::x87_state::Ext80;

use super::{
    decode, from_apfloat, indefinite, map_status, raw_bits, RemainderResult,
    X87_EXCEPTION_MASK,
};
use rustc_apfloat::ieee::X87DoubleExtended as ApX87;

pub(crate) fn remainder(lhs: Ext80, rhs: Ext80, nearest_even: bool) -> RemainderResult {
    let (left, left_flags) = match decode(lhs) {
        Ok(value) => value,
        Err(flags) => return remainder_indefinite(flags),
    };
    let (right, right_flags) = match decode(rhs) {
        Ok(value) => value,
        Err(flags) => return remainder_indefinite(flags),
    };

    if left.is_finite_non_zero() && right.is_finite_non_zero() {
        let (left_sig, left_exp) = normalized_parts(left);
        let (right_sig, right_exp) = normalized_parts(right);
        let difference = left_exp - right_exp;
        let quotient_low3 = quotient_low3(
            left_sig,
            right_sig,
            difference,
            left.is_negative() ^ right.is_negative(),
            nearest_even,
        );
        if difference >= 64 {
            // Intel permits reducing 32–63 exponent bits per partial step.
            // N=63 is a valid implementation choice and exposes C2 to the
            // frontend so it can preserve the architectural partial state.
            let numerator = u128::from(left_sig) << 63;
            let partial_remainder = (numerator % u128::from(right_sig)) as u64;
            let exponent2 = right_exp + difference - 126;
            let value = encode_dyadic(left.is_negative(), partial_remainder, exponent2);
            return RemainderResult {
                value,
                exceptions: left_flags | right_flags,
                c1: false,
                quotient_low3: 0,
                partial: true,
            };
        }

        let result = if nearest_even {
            left.ieee_rem(right)
        } else {
            left.c_fmod(right)
        };
        let mut exceptions = left_flags | right_flags | map_status(result.status);
        let mut value = result.value;
        if result.status.contains(Status::INVALID_OP)
            && !left.is_signaling()
            && !right.is_signaling()
            && value.is_nan()
        {
            value = ApX87::from_bits(raw_bits(indefinite()));
        }
        exceptions = super::prioritize_operand_exceptions(&[lhs, rhs], exceptions)
            & X87_EXCEPTION_MASK;
        return RemainderResult {
            value: from_apfloat(value),
            exceptions,
            c1: false,
            quotient_low3,
            partial: false,
        };
    }

    let result = if nearest_even {
        left.ieee_rem(right)
    } else {
        left.c_fmod(right)
    };
    let mut exceptions = left_flags | right_flags | map_status(result.status);
    let mut value = result.value;
    if result.status.contains(Status::INVALID_OP)
        && !left.is_signaling()
        && !right.is_signaling()
        && value.is_nan()
    {
        value = ApX87::from_bits(raw_bits(indefinite()));
    }
    exceptions = super::prioritize_operand_exceptions(&[lhs, rhs], exceptions)
        & X87_EXCEPTION_MASK;
    RemainderResult {
        value: from_apfloat(value),
        exceptions,
        c1: false,
        quotient_low3: 0,
        partial: false,
    }
}

fn remainder_indefinite(exceptions: u16) -> RemainderResult {
    RemainderResult {
        value: indefinite(),
        exceptions,
        c1: false,
        quotient_low3: 0,
        partial: false,
    }
}

fn normalized_parts(value: ApX87) -> (u64, i32) {
    let bits = value.to_bits();
    let exponent_field = ((bits >> 64) & 0x7fff) as i32;
    let significand = bits as u64;
    if exponent_field == 0 {
        let highest = 63 - significand.leading_zeros() as i32;
        let shift = (63 - highest) as u32;
        (significand << shift, -16_382 - shift as i32)
    } else {
        (significand, exponent_field - 16_383)
    }
}

fn quotient_low3(
    lhs_sig: u64,
    rhs_sig: u64,
    exponent_difference: i32,
    negative: bool,
    nearest_even: bool,
) -> u8 {
    let (mut quotient, remainder, divisor) = if exponent_difference < 0 {
        let nearest_one = nearest_even
            && exponent_difference == -1
            && lhs_sig > rhs_sig;
        (u128::from(u8::from(nearest_one)), 0_u128, 1_u128)
    } else {
        let modulus = u128::from(rhs_sig) * 8;
        let factor = pow2_mod(exponent_difference as u32, modulus);
        let scaled = mul_mod(u128::from(lhs_sig), factor, modulus);
        let quotient = scaled / u128::from(rhs_sig);
        let remainder = scaled % u128::from(rhs_sig);
        (quotient, remainder, u128::from(rhs_sig))
    };
    if nearest_even && divisor != 1 {
        let twice = remainder * 2;
        if twice > divisor || (twice == divisor && quotient & 1 != 0) {
            quotient += 1;
        }
    }
    let magnitude = (quotient & 7) as u8;
    if negative {
        0_u8.wrapping_sub(magnitude) & 7
    } else {
        magnitude
    }
}

fn pow2_mod(mut exponent: u32, modulus: u128) -> u128 {
    let mut result = 1_u128 % modulus;
    let mut factor = 2_u128 % modulus;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = mul_mod(result, factor, modulus);
        }
        exponent >>= 1;
        if exponent != 0 {
            factor = mul_mod(factor, factor, modulus);
        }
    }
    result
}

fn mul_mod(mut lhs: u128, mut rhs: u128, modulus: u128) -> u128 {
    lhs %= modulus;
    let mut result = 0_u128;
    while rhs != 0 {
        if rhs & 1 != 0 {
            result = add_mod(result, lhs, modulus);
        }
        lhs = add_mod(lhs, lhs, modulus);
        rhs >>= 1;
    }
    result
}

fn add_mod(lhs: u128, rhs: u128, modulus: u128) -> u128 {
    let sum = lhs + rhs;
    if sum >= modulus { sum - modulus } else { sum }
}

fn encode_dyadic(negative: bool, significand: u64, exponent2: i32) -> Ext80 {
    let sign = if negative { 0x8000 } else { 0 };
    if significand == 0 {
        return Ext80 { significand: 0, sign_exponent: sign };
    }
    let highest = 63 - significand.leading_zeros() as i32;
    let result_exponent = exponent2 + highest;
    if result_exponent >= -16_382 {
        return Ext80 {
            significand: significand << (63 - highest) as u32,
            sign_exponent: sign | (result_exponent + 16_383) as u16,
        };
    }
    let shift = exponent2 + 16_445;
    let denormal = if shift >= 0 {
        u128::from(significand) << shift as u32
    } else {
        u128::from(significand) >> (-shift) as u32
    };
    Ext80 { significand: denormal as u64, sign_exponent: sign }
}

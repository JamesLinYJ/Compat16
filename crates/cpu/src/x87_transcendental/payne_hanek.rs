//! Fixed-point Payne-Hanek reduction for the full architectural FSIN/FCOS
//! range. The 256-bit constant is floor((2/pi) * 2^256); retaining the low
//! product bits matters because an in-range argument can be almost 2^63.

use rustc_apfloat::ieee::Quad;
use rustc_apfloat::Float;

use crate::x87_state::Ext80;

use super::kernel;

const TWO_OVER_PI_256_LE: [u64; 4] = [
    0xfe51_63ab_debb_c561,
    0xdb62_9599_3c43_9041,
    0xfc27_57d1_f534_ddc0,
    0xa2f9_836e_4e44_1529,
];

pub(crate) fn reduce(magnitude: Ext80) -> (u8, Quad) {
    let exponent = i32::from(magnitude.sign_exponent & 0x7fff);
    let binary_exponent = exponent - 16_383 - 63;
    let denominator_bits = usize::try_from(256 - binary_exponent).unwrap_or(320);
    let product = multiply_significand(magnitude.significand);

    let floor_mod_four = (bit(&product, denominator_bits) as u8)
        | ((bit(&product, denominator_bits + 1) as u8) << 1);
    let half_bit = bit(&product, denominator_bits - 1);
    let below_half_bit = any_low_bits(&product, denominator_bits - 1);
    let floor_is_odd = floor_mod_four & 1 != 0;
    let round_up = half_bit && (below_half_bit || floor_is_odd);
    let quadrant = floor_mod_four.wrapping_add(u8::from(round_up)) & 3;

    let fraction_numerator = if round_up {
        complement_fraction(&product, denominator_bits)
    } else {
        low_fraction(&product, denominator_bits)
    };
    let fraction = fraction_to_quad(&fraction_numerator, denominator_bits);
    let fraction = if round_up { -fraction } else { fraction };
    let reduced = (fraction * kernel::pi().scalbn(-1)).value;
    (quadrant, reduced)
}

fn multiply_significand(significand: u64) -> [u64; 5] {
    let mut product = [0_u64; 5];
    let mut carry = 0_u128;
    for index in 0..4 {
        let partial = u128::from(TWO_OVER_PI_256_LE[index]) * u128::from(significand) + carry;
        product[index] = partial as u64;
        carry = partial >> 64;
    }
    product[4] = carry as u64;
    product
}

fn bit(words: &[u64], index: usize) -> bool {
    words.get(index / 64).is_some_and(|word| word & (1_u64 << (index % 64)) != 0)
}

fn any_low_bits(words: &[u64], count: usize) -> bool {
    let full_words = count / 64;
    if words.iter().take(full_words).any(|word| *word != 0) {
        return true;
    }
    let partial_bits = count % 64;
    partial_bits != 0
        && words
            .get(full_words)
            .is_some_and(|word| word & ((1_u64 << partial_bits) - 1) != 0)
}

fn low_fraction(product: &[u64; 5], denominator_bits: usize) -> [u64; 6] {
    let mut numerator = [0_u64; 6];
    numerator[..5].copy_from_slice(product);
    mask_bits(&mut numerator, denominator_bits);
    numerator
}

fn complement_fraction(product: &[u64; 5], denominator_bits: usize) -> [u64; 6] {
    let numerator = low_fraction(product, denominator_bits);
    let mut complement = [0_u64; 6];
    complement[denominator_bits / 64] = 1_u64 << (denominator_bits % 64);
    let mut borrow = 0_u128;
    for index in 0..6 {
        let subtrahend = u128::from(numerator[index]) + borrow;
        let minuend = u128::from(complement[index]);
        if minuend >= subtrahend {
            complement[index] = (minuend - subtrahend) as u64;
            borrow = 0;
        } else {
            complement[index] = ((1_u128 << 64) + minuend - subtrahend) as u64;
            borrow = 1;
        }
    }
    complement
}

fn mask_bits(words: &mut [u64; 6], bit_count: usize) {
    let full_words = bit_count / 64;
    let partial_bits = bit_count % 64;
    if partial_bits != 0 {
        words[full_words] &= (1_u64 << partial_bits) - 1;
        for word in words.iter_mut().skip(full_words + 1) {
            *word = 0;
        }
    } else {
        for word in words.iter_mut().skip(full_words) {
            *word = 0;
        }
    }
}

/// Round an unsigned fixed-point fraction to Quad, including guard and sticky
/// bits. This preserves very small remainders instead of cancelling `1-f` in
/// Quad after an almost-integer quotient.
fn fraction_to_quad(numerator: &[u64; 6], denominator_bits: usize) -> Quad {
    let Some(highest) = (0..denominator_bits).rev().find(|index| bit(numerator, *index)) else {
        return Quad::ZERO;
    };
    let significant_bits = highest + 1;
    let drop = significant_bits.saturating_sub(Quad::PRECISION);
    let mut significand = extract_bits(numerator, drop, significant_bits - drop) as u128;
    if drop != 0 {
        let guard = bit(numerator, drop - 1);
        let sticky = any_low_bits(numerator, drop - 1);
        if guard && (sticky || significand & 1 != 0) {
            significand += 1;
        }
    }
    let rounded_integer = Quad::from_u128(significand).value;
    rounded_integer.scalbn(i32::try_from(drop).unwrap_or(i32::MAX) - denominator_bits as i32)
}

fn extract_bits(words: &[u64; 6], start: usize, count: usize) -> u128 {
    let mut result = 0_u128;
    for offset in 0..count {
        if bit(words, start + offset) {
            result |= 1_u128 << offset;
        }
    }
    result
}

//! Normalized 128/64 division using two radix-2^32 quotient digits. A 64-bit
//! host divide estimates each digit; at most two exact corrections suffice.
//! The integer remainder drives rounding, so no float approximation is used.
use super::*;
fn digit(
    b: &mut FunctionBuilder<'_>,
    high: Value,
    next: Value,
    divisor_high: Value,
    divisor_low: Value,
) -> Value {
    let mut q = b.ins().udiv(high, divisor_high);
    let product = b.ins().imul(q, divisor_high);
    let mut remainder = b.ins().isub(high, product);
    for _ in 0..2 {
        let large = b
            .ins()
            .icmp_imm_s(IntCC::UnsignedGreaterThanOrEqual, q, 1i64 << 32);
        let small_remainder = b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, remainder, 1i64 << 32);
        let product = b.ins().imul(q, divisor_low);
        let shifted = b.ins().ishl_imm_u(remainder, 32);
        let rhs = b.ins().bor(shifted, next);
        let exceeds = b.ins().icmp(IntCC::UnsignedGreaterThan, product, rhs);
        let exceeds = b.ins().band(small_remainder, exceeds);
        let correct = b.ins().bor(large, exceeds);
        let reduced = b.ins().iadd_imm_s(q, -1);
        q = b.ins().select(correct, reduced, q);
        let added = b.ins().iadd(remainder, divisor_high);
        remainder = b.ins().select(correct, added, remainder);
    }
    q
}
pub(super) fn emit(
    b: &mut FunctionBuilder<'_>,
    left: Value,
    right: Value,
    lexp: Value,
    rexp: Value,
) -> (Value, Value, Value) {
    let exponent = b.ins().isub(lexp, rexp);
    let exponent = b.ins().iadd_imm_s(exponent, 16383);
    let unit = b.ins().icmp_imm_s(IntCC::Equal, right, i64::MIN);
    let fast = b.create_block();
    let divide = b.create_block();
    let join = b.create_block();
    for _ in 0..3 {
        b.append_block_param(join, types::I64);
    }
    let zero = b.ins().iconst(types::I64, 0);
    b.ins().brif(unit, fast, &[], divide, &[]);
    b.switch_to_block(fast);
    b.ins()
        .jump(join, &[left.into(), zero.into(), exponent.into()]);
    b.switch_to_block(divide);
    // Defensive nonzero divisor makes every generated udiv nontrapping even
    // before the caller's input-class guard rejects malformed encodings.
    let nonzero = b.ins().bor_imm_u(right, i64::MIN);
    let big = b.ins().icmp(IntCC::UnsignedGreaterThanOrEqual, left, right);
    let half = b.ins().ushr_imm_u(left, 1);
    let high = b.ins().select(big, half, left);
    let low = b.ins().ishl_imm_u(left, 63);
    let low = b.ins().select(big, low, zero);
    let d1 = b.ins().ushr_imm_u(nonzero, 32);
    let d0 = b.ins().band_imm_u(nonzero, 0xffff_ffff);
    let n1 = b.ins().ushr_imm_u(low, 32);
    let n0 = b.ins().band_imm_u(low, 0xffff_ffff);
    let q1 = digit(b, high, n1, d1, d0);
    let shifted = b.ins().ishl_imm_u(high, 32);
    let next = b.ins().bor(shifted, n1);
    let product = b.ins().imul(q1, nonzero);
    let middle = b.ins().isub(next, product);
    let q0 = digit(b, middle, n0, d1, d0);
    let shifted = b.ins().ishl_imm_u(middle, 32);
    let next = b.ins().bor(shifted, n0);
    let product = b.ins().imul(q0, nonzero);
    let remainder = b.ins().isub(next, product);
    let q1 = b.ins().ishl_imm_u(q1, 32);
    let sig = b.ins().iadd(q1, q0);
    let complement = b.ins().isub(nonzero, remainder);
    let above = b
        .ins()
        .icmp(IntCC::UnsignedGreaterThan, remainder, complement);
    let halfway = b.ins().icmp(IntCC::Equal, remainder, complement);
    let high_bit = b.ins().bor(above, halfway);
    let high_bit = b.ins().uextend(types::I64, high_bit);
    let high_bit = b.ins().ishl_imm_u(high_bit, 63);
    let inexact = b.ins().icmp_imm_s(IntCC::NotEqual, remainder, 0);
    let not_half = b.ins().icmp(IntCC::NotEqual, remainder, complement);
    let sticky = b.ins().band(inexact, not_half);
    let sticky = b.ins().uextend(types::I64, sticky);
    let tail = b.ins().bor(high_bit, sticky);
    let adjustment = b.ins().uextend(types::I64, big);
    let exponent = b.ins().iadd(exponent, adjustment);
    let exponent = b.ins().iadd_imm_s(exponent, -1);
    let is_zero = b.ins().icmp_imm_s(IntCC::Equal, left, 0);
    let exponent = b.ins().select(is_zero, zero, exponent);
    b.ins()
        .jump(join, &[sig.into(), tail.into(), exponent.into()]);
    b.switch_to_block(join);
    let values = b.block_params(join);
    (values[0], values[1], values[2])
}

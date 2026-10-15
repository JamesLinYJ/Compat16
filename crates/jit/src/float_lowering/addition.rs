//! Align with a jammed 128-bit tail before adding or cancelling. The extra
//! word preserves exact deep cancellation; discarded distant bits are sticky.
use super::*;
pub(super) fn emit(
    b: &mut FunctionBuilder<'_>,
    plan: FloatPlan,
    left: Value,
    right: Value,
    (lexp, rexp): (Value, Value),
    lfield: Value,
    rfield: Value,
) -> (Value, Value, Value, Value) {
    let rfield = if plan.operation == FloatOperation::Subtract {
        b.ins().bxor_imm_u(rfield, 0x8000)
    } else {
        rfield
    };
    let greater_exp = b.ins().icmp(IntCC::UnsignedGreaterThan, lexp, rexp);
    let same_exp = b.ins().icmp(IntCC::Equal, lexp, rexp);
    let greater_sig = b.ins().icmp(IntCC::UnsignedGreaterThanOrEqual, left, right);
    let same_greater = b.ins().band(same_exp, greater_sig);
    let choose_left = b.ins().bor(greater_exp, same_greater);
    let big = b.ins().select(choose_left, left, right);
    let small = b.ins().select(choose_left, right, left);
    let exponent = b.ins().select(choose_left, lexp, rexp);
    let small_exp = b.ins().select(choose_left, rexp, lexp);
    let sign = b.ins().select(choose_left, lfield, rfield);
    let sign = b.ins().band_imm_u(sign, 0x8000);
    let signs = b.ins().bxor(lfield, rfield);
    let signs = b.ins().band_imm_u(signs, 0x8000);
    let add = b.ins().icmp_imm_s(IntCC::Equal, signs, 0);
    let distance = b.ins().isub(exponent, small_exp);
    let zero = b.ins().iconst(types::I64, 0);
    let below64 = b.ins().icmp_imm_s(IntCC::UnsignedLessThan, distance, 64);
    let below128 = b.ins().icmp_imm_s(IntCC::UnsignedLessThan, distance, 128);
    let same = b.ins().icmp_imm_s(IntCC::Equal, distance, 0);
    let negative_distance = b.ins().ineg(distance);
    let high = b.ins().ushr(small, distance);
    let high = b.ins().select(below64, high, zero);
    let low_near = b.ins().ishl(small, negative_distance);
    let low_near = b.ins().select(same, zero, low_near);
    // Shift counts in CLIF are modulo the word width. For distances >=64
    // distance mod64 is exactly the second word's shift count.
    let low_far = b.ins().ushr(small, distance);
    let restored = b.ins().ishl(low_far, distance);
    let lost = b.ins().icmp(IntCC::NotEqual, restored, small);
    let lost = b.ins().uextend(types::I64, lost);
    let low_far = b.ins().bor(low_far, lost);
    let sticky = b.ins().icmp_imm_s(IntCC::NotEqual, small, 0);
    let sticky = b.ins().uextend(types::I64, sticky);
    let low_far = b.ins().select(below128, low_far, sticky);
    let low = b.ins().select(below64, low_near, low_far);
    // Only one sign path can contribute to this result. In particular the
    // same-sign hot path needs no cancellation CLZ/variable shifts.
    let sum_path = b.create_block();
    let difference_path = b.create_block();
    let join = b.create_block();
    for _ in 0..3 {
        b.append_block_param(join, types::I64);
    }
    b.ins().brif(add, sum_path, &[], difference_path, &[]);
    b.switch_to_block(sum_path);
    let sum = b.ins().iadd(big, high);
    let carry = b.ins().icmp(IntCC::UnsignedLessThan, sum, big);
    let carry_bit = b.ins().iconst(types::I64, i64::MIN);
    let sum_high = b.ins().ushr_imm_u(sum, 1);
    let sum_high = b.ins().bor(sum_high, carry_bit);
    let spilled = b.ins().ishl_imm_u(sum, 63);
    let sum_low = b.ins().ushr_imm_u(low, 1);
    let sum_low = b.ins().bor(sum_low, spilled);
    let lost = b.ins().band_imm_u(low, 1);
    let sum_low = b.ins().bor(sum_low, lost);
    let sum = b.ins().select(carry, sum_high, sum);
    let sum_low = b.ins().select(carry, sum_low, low);
    let carry_word = b.ins().uextend(types::I64, carry);
    let sum_exp = b.ins().iadd(exponent, carry_word);
    b.ins()
        .jump(join, &[sum.into(), sum_low.into(), sum_exp.into()]);
    b.switch_to_block(difference_path);
    let borrow = b.ins().icmp_imm_s(IntCC::NotEqual, low, 0);
    let borrow = b.ins().uextend(types::I64, borrow);
    let difference = b.ins().isub(big, high);
    let difference = b.ins().isub(difference, borrow);
    let low_difference = b.ins().ineg(low);
    let high_zero = b.ins().icmp_imm_s(IntCC::Equal, difference, 0);
    let high_count = b.ins().clz(difference);
    let low_count = b.ins().clz(low_difference);
    let low_shift = b.ins().iadd_imm_s(low_count, 64);
    let shift = b.ins().select(high_zero, low_shift, high_count);
    let high_shifted = b.ins().ishl(difference, shift);
    let negative_shift = b.ins().ineg(shift);
    let spill = b.ins().ushr(low_difference, negative_shift);
    let shift_zero = b.ins().icmp_imm_s(IntCC::Equal, shift, 0);
    let spill = b.ins().select(shift_zero, zero, spill);
    let high_shifted = b.ins().bor(high_shifted, spill);
    let low_as_high = b.ins().ishl(low_difference, shift);
    let difference = b.ins().select(high_zero, low_as_high, high_shifted);
    let shifted_low = b.ins().ishl(low_difference, shift);
    let shifted_low = b.ins().select(high_zero, zero, shifted_low);
    let difference_exp = b.ins().isub(exponent, shift);
    b.ins().jump(
        join,
        &[difference.into(), shifted_low.into(), difference_exp.into()],
    );
    b.switch_to_block(join);
    let output = b.block_params(join);
    let (sig, tail, exponent) = (output[0], output[1], output[2]);
    let residue = b.ins().bor(sig, tail);
    let exact_zero = b.ins().icmp_imm_s(IntCC::Equal, residue, 0);
    let zero_sign = b
        .ins()
        .iconst(types::I64, if plan.rounding == 1 { 0x8000 } else { 0 });
    let zero_sign = b.ins().select(add, sign, zero_sign);
    let sign = b.ins().select(exact_zero, zero_sign, sign);
    let exponent = b.ins().select(exact_zero, zero, exponent);
    // Keep these values explicit: no implicit host rounding or contraction.
    (sig, tail, exponent, sign)
}

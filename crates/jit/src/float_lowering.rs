//! Integer lowering of raw extended arithmetic. The pair (significand, tail)
//! retains 64 explicit bits plus guard/sticky information through PC/RC.
//! Host float types cannot express x87's precision and exponent combination.
mod addition;
mod division;
use crate::floating::{FloatOperation, FloatPlan};
use cranelift_codegen::ir::{InstBuilder, MemFlagsData, Value, condcodes::IntCC, types};
use cranelift_frontend::FunctionBuilder;

pub(super) struct ResultValues {
    pub significand: Value,
    pub field: Value,
    pub flags: Value,
    pub valid: Value,
}
pub(super) fn supported(b: &mut FunctionBuilder<'_>, significand: Value, field: Value) -> Value {
    let exponent = b.ins().band_imm_u(field, 0x7fff);
    let nonzero = b.ins().icmp_imm_s(IntCC::NotEqual, exponent, 0);
    let finite = b
        .ins()
        .icmp_imm_s(IntCC::UnsignedLessThan, exponent, 0x7fff);
    let explicit = b.ins().icmp_imm_s(IntCC::SignedLessThan, significand, 0);
    let normal = b.ins().band(nonzero, finite);
    let normal = b.ins().band(normal, explicit);
    let combined = b.ins().bor(significand, exponent);
    let zero = b.ins().icmp_imm_s(IntCC::Equal, combined, 0);
    b.ins().bor(normal, zero)
}
pub(super) fn arithmetic(
    b: &mut FunctionBuilder<'_>,
    plan: FloatPlan,
    left: Value,
    right: Value,
    lfield: Value,
    rfield: Value,
) -> ResultValues {
    arithmetic_with_known_inputs(b, plan, left, right, lfield, rfield, [false; 2])
}
/// Only a dominating successful class guard or a checked result can certify
/// an operand. Block-local SSA facts never survive a generated function call.
pub(super) fn arithmetic_with_known_inputs(
    b: &mut FunctionBuilder<'_>,
    plan: FloatPlan,
    left: Value,
    right: Value,
    lfield: Value,
    rfield: Value,
    known: [bool; 2],
) -> ResultValues {
    let lexp = b.ins().band_imm_u(lfield, 0x7fff);
    let rexp = b.ins().band_imm_u(rfield, 0x7fff);
    let sign = b.ins().bxor(lfield, rfield);
    let sign = b.ins().band_imm_u(sign, 0x8000);
    let (sig, tail, exponent, sign) = match plan.operation {
        FloatOperation::Add | FloatOperation::Subtract => {
            addition::emit(b, plan, left, right, (lexp, rexp), lfield, rfield)
        }
        FloatOperation::Multiply => {
            let exponent = b.ins().iadd(lexp, rexp);
            let exponent = b.ins().iadd_imm_s(exponent, -16383);
            let low = b.ins().imul(left, right);
            let high = b.ins().umulhi(left, right);
            let top = b.ins().ushr_imm_u(high, 63);
            let twice = b.ins().icmp_imm_s(IntCC::NotEqual, top, 0);
            let shifted = b.ins().ishl_imm_u(high, 1);
            let spill = b.ins().ushr_imm_u(low, 63);
            let shifted = b.ins().bor(shifted, spill);
            let sig = b.ins().select(twice, high, shifted);
            let shifted_low = b.ins().ishl_imm_u(low, 1);
            let tail = b.ins().select(twice, low, shifted_low);
            let exponent = b.ins().iadd(exponent, top);
            // A zero operand gives an exact signed zero at every precision.
            let is_zero = b.ins().icmp_imm_s(IntCC::Equal, sig, 0);
            let zero = b.ins().iconst(types::I64, 0);
            let exponent = b.ins().select(is_zero, zero, exponent);
            (sig, tail, exponent, sign)
        }
        FloatOperation::Divide => {
            let (sig, tail, exponent) = division::emit(b, left, right, lexp, rexp);
            (sig, tail, exponent, sign)
        }
    };
    let mut result = round(b, plan, sig, tail, exponent, sign);
    for (index, (sig, field)) in [(left, lfield), (right, rfield)].into_iter().enumerate() {
        if !known[index] {
            let input = supported(b, sig, field);
            result.valid = b.ins().band(result.valid, input);
        }
    }
    if plan.operation == FloatOperation::Divide {
        let nonzero = b.ins().icmp_imm_s(IntCC::NotEqual, right, 0);
        result.valid = b.ins().band(result.valid, nonzero);
    }
    result
}
fn round(
    b: &mut FunctionBuilder<'_>,
    plan: FloatPlan,
    significand: Value,
    remainder: Value,
    exponent: Value,
    sign: Value,
) -> ResultValues {
    let nonzero_exp = b.ins().icmp_imm_s(IntCC::SignedGreaterThan, exponent, 0);
    let below_max = b.ins().icmp_imm_s(IntCC::SignedLessThan, exponent, 0x7fff);
    let in_range = b.ins().band(nonzero_exp, below_max);
    let combined = b.ins().bor(significand, remainder);
    let exact_zero = b.ins().icmp_imm_s(IntCC::Equal, combined, 0);
    let in_range = b.ins().bor(in_range, exact_zero);
    let drop = 64 - plan.precision;
    let mask = (1u64 << drop) - 1;
    let discarded = b.ins().band_imm_u(significand, mask as i64);
    let residue = b.ins().bor(discarded, remainder);
    let inexact = b.ins().icmp_imm_s(IntCC::NotEqual, residue, 0);
    let truncation = b.ins().band_imm_u(significand, !mask as i64);
    let negative = b.ins().icmp_imm_s(IntCC::NotEqual, sign, 0);
    let up = match plan.rounding {
        0 => {
            let tail = if drop == 0 { remainder } else { discarded };
            let half = if drop == 0 {
                1u64 << 63
            } else {
                1u64 << (drop - 1)
            };
            let above = b
                .ins()
                .icmp_imm_s(IntCC::UnsignedGreaterThan, tail, half as i64);
            let halfway = b.ins().icmp_imm_s(IntCC::Equal, tail, half as i64);
            let last = b.ins().ushr_imm_u(significand, i64::from(drop));
            let last = b.ins().band_imm_u(last, 1);
            let odd = b.ins().icmp_imm_s(IntCC::NotEqual, last, 0);
            let tie_up = if drop == 0 {
                odd
            } else {
                let sticky = b.ins().icmp_imm_s(IntCC::NotEqual, remainder, 0);
                b.ins().bor(sticky, odd)
            };
            let tie_up = b.ins().band(halfway, tie_up);
            b.ins().bor(above, tie_up)
        }
        1 => b.ins().band(negative, inexact),
        2 => {
            let positive = b.ins().icmp_imm_s(IntCC::Equal, sign, 0);
            b.ins().band(positive, inexact)
        }
        _ => b.ins().iconst(types::I8, 0),
    };
    let increment = b.ins().uextend(types::I64, up);
    let increment = b.ins().ishl_imm_u(increment, i64::from(drop));
    let rounded = b.ins().iadd(truncation, increment);
    let carry = b.ins().icmp(IntCC::UnsignedLessThan, rounded, truncation);
    let integer_bit = b.ins().iconst(types::I64, i64::MIN);
    let rounded = b.ins().select(carry, integer_bit, rounded);
    let carry = b.ins().uextend(types::I64, carry);
    let exponent = b.ins().iadd(exponent, carry);
    let zero = b.ins().iconst(types::I64, 0);
    let exponent = b.ins().select(exact_zero, zero, exponent);
    let final_in_range = b.ins().icmp_imm_s(IntCC::SignedLessThan, exponent, 0x7fff);
    let valid = b.ins().band(in_range, final_in_range);
    let field = b.ins().bor(sign, exponent);
    let flags = b.ins().uextend(types::I64, inexact);
    let flags = b.ins().ishl_imm_u(flags, 5);
    let c1 = b.ins().uextend(types::I64, up);
    let c1 = b.ins().ishl_imm_u(c1, 16);
    let flags = b.ins().bor(flags, c1);
    ResultValues {
        significand: rounded,
        field,
        flags,
        valid,
    }
}
pub(super) fn emit(b: &mut FunctionBuilder<'_>, plan: FloatPlan) {
    let entry = b.current_block().expect("float entry");
    let pointer = b.block_params(entry)[0];
    let left = b
        .ins()
        .load(types::I64, MemFlagsData::trusted(), pointer, 0);
    let right = b
        .ins()
        .load(types::I64, MemFlagsData::trusted(), pointer, 8);
    let fields = b
        .ins()
        .load(types::I64, MemFlagsData::trusted(), pointer, 16);
    let rfield = b.ins().ushr_imm_u(fields, 16);
    let result = arithmetic(b, plan, left, right, fields, rfield);
    let success = b.create_block();
    let fallback = b.create_block();
    b.set_cold_block(fallback);
    b.ins().brif(result.valid, success, &[], fallback, &[]);
    b.switch_to_block(success);
    b.ins()
        .store(MemFlagsData::trusted(), result.significand, pointer, 24);
    b.ins()
        .store(MemFlagsData::trusted(), result.field, pointer, 32);
    b.ins()
        .store(MemFlagsData::trusted(), result.flags, pointer, 40);
    let one = b.ins().iconst(types::I32, 1);
    b.ins().return_(&[one]);
    b.switch_to_block(fallback);
    let zero = b.ins().iconst(types::I32, 0);
    b.ins().return_(&[zero]);
    b.seal_all_blocks();
}

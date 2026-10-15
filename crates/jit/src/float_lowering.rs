//! An exact 64x64 -> 128-bit significand product, using host integer multiply
//! high/low operations. Explicit discarded bits drive all x87 PC/RC modes.
use crate::floating::FloatPlan;
use cranelift_codegen::ir::{InstBuilder, MemFlagsData, condcodes::IntCC, types};
use cranelift_frontend::FunctionBuilder;

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
    let lexp = b.ins().band_imm_u(fields, 0x7fff);
    let rexp = b.ins().ushr_imm_u(fields, 16);
    let rexp = b.ins().band_imm_u(rexp, 0x7fff);
    let exponent = b.ins().iadd(lexp, rexp);
    let exponent = b.ins().iadd_imm_s(exponent, -16383);
    let low = b.ins().imul(left, right);
    let high = b.ins().umulhi(left, right);
    let top = b.ins().ushr_imm_u(high, 63);
    let twice = b.ins().icmp_imm_s(IntCC::NotEqual, top, 0);
    let shifted = b.ins().ishl_imm_u(high, 1);
    let spill = b.ins().ushr_imm_u(low, 63);
    let shifted = b.ins().bor(shifted, spill);
    let significand = b.ins().select(twice, high, shifted);
    let shifted_low = b.ins().ishl_imm_u(low, 1);
    let remainder = b.ins().select(twice, low, shifted_low);
    let exponent = b.ins().iadd(exponent, top);
    let in_range = b.ins().icmp_imm_s(IntCC::SignedGreaterThan, exponent, 0);
    let below_max = b.ins().icmp_imm_s(IntCC::SignedLessThan, exponent, 0x7fff);
    let in_range = b.ins().band(in_range, below_max);
    let drop = 64 - plan.precision;
    let discarded = b.ins().band_imm_u(significand, ((1u64 << drop) - 1) as i64);
    let residue = b.ins().bor(discarded, remainder);
    let inexact = b.ins().icmp_imm_s(IntCC::NotEqual, residue, 0);
    let truncation = b
        .ins()
        .band_imm_u(significand, !((1u64 << drop) - 1) as i64);
    let rsign = b.ins().ushr_imm_u(fields, 16);
    let sign = b.ins().bxor(fields, rsign);
    let sign = b.ins().band_imm_u(sign, 0x8000);
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
    let final_in_range = b.ins().icmp_imm_s(IntCC::SignedLessThan, exponent, 0x7fff);
    let mut valid = b.ins().band(in_range, final_in_range);
    // Defensive validation of raw inputs also occurs inside the generated
    // function; safe callers already exclude zero, NaN and pseudo encodings.
    for (exponent, significand) in [(lexp, left), (rexp, right)] {
        let normal = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, exponent, 0);
        let finite = b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, exponent, 0x7fff);
        let explicit = b.ins().icmp_imm_s(IntCC::SignedLessThan, significand, 0);
        let normal = b.ins().band(normal, finite);
        let normal = b.ins().band(normal, explicit);
        valid = b.ins().band(valid, normal);
    }
    let success = b.create_block();
    let fallback = b.create_block();
    b.set_cold_block(fallback);
    b.ins().brif(valid, success, &[], fallback, &[]);
    b.switch_to_block(success);
    let sign_exponent = b.ins().bor(sign, exponent);
    let flags = b.ins().uextend(types::I64, inexact);
    let flags = b.ins().ishl_imm_u(flags, 5);
    let c1 = b.ins().uextend(types::I64, up);
    let c1 = b.ins().ishl_imm_u(c1, 16);
    let flags = b.ins().bor(flags, c1);
    b.ins().store(MemFlagsData::trusted(), rounded, pointer, 24);
    b.ins()
        .store(MemFlagsData::trusted(), sign_exponent, pointer, 32);
    b.ins().store(MemFlagsData::trusted(), flags, pointer, 40);
    let one = b.ins().iconst(types::I32, 1);
    b.ins().return_(&[one]);
    b.switch_to_block(fallback);
    let zero = b.ins().iconst(types::I32, 0);
    b.ins().return_(&[zero]);
    b.seal_all_blocks();
}

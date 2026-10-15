//! Exact IEEE input expansion using integer fields. Normals and signed zeros
//! fit in Ext80 without rounding; other classes exit before any guest effect.
use crate::FloatMemoryFormat;
use cranelift_codegen::ir::{InstBuilder, MemFlagsData, Value, condcodes::IntCC, types};
use cranelift_frontend::FunctionBuilder;

pub(super) fn load(
    b: &mut FunctionBuilder<'_>,
    memory: Value,
    offset: u8,
    format: FloatMemoryFormat,
) -> (Value, Value, Value) {
    let (ty, fraction_bits, exponent_bits, bias, sign_shift) = match format {
        FloatMemoryFormat::Binary32 => (types::I32, 23, 8, 127, 16),
        FloatMemoryFormat::Binary64 => (types::I64, 52, 11, 1023, 48),
    };
    let bits = b.ins().load(
        ty,
        MemFlagsData::new().with_notrap(),
        memory,
        i32::from(offset),
    );
    let bits = if ty == types::I32 {
        b.ins().uextend(types::I64, bits)
    } else {
        bits
    };
    let exponent = b.ins().ushr_imm_u(bits, fraction_bits);
    let exponent_mask = (1i64 << exponent_bits) - 1;
    let exponent = b.ins().band_imm_u(exponent, exponent_mask);
    let fraction = b.ins().band_imm_u(bits, (1i64 << fraction_bits) - 1);
    let payload = b.ins().bor(exponent, fraction);
    let is_zero = b.ins().icmp_imm_s(IntCC::Equal, payload, 0);
    let nonzero_exp = b.ins().icmp_imm_s(IntCC::NotEqual, exponent, 0);
    let finite = b
        .ins()
        .icmp_imm_s(IntCC::UnsignedLessThan, exponent, exponent_mask);
    let normal = b.ins().band(nonzero_exp, finite);
    let valid = b.ins().bor(normal, is_zero);
    let sig = b.ins().bor_imm_u(fraction, 1i64 << fraction_bits);
    let sig = b.ins().ishl_imm_u(sig, 63 - fraction_bits);
    let zero = b.ins().iconst(types::I64, 0);
    let sig = b.ins().select(is_zero, zero, sig);
    let exponent = b.ins().iadd_imm_s(exponent, 16383 - bias);
    let exponent = b.ins().select(is_zero, zero, exponent);
    let sign = b.ins().ushr_imm_u(bits, sign_shift);
    let sign = b.ins().band_imm_u(sign, 0x8000);
    let field = b.ins().bor(sign, exponent);
    (sig, field, valid)
}

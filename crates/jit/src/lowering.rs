//! Cranelift lowering for 8/16/32-bit register arithmetic and x86 status flags.

use crate::{Condition, Instruction, Operand, Operation as Op, Register};
use cranelift_codegen::ir::{InstBuilder, MemFlagsData, Value, condcodes::IntCC, types};
use cranelift_frontend::FunctionBuilder;

fn load(b: &mut FunctionBuilder<'_>, pointer: Value, register: Register) -> Value {
    let value = b.ins().load(
        types::I32,
        MemFlagsData::trusted(),
        pointer,
        i32::from(register.index) * 4,
    );
    let value = if register.high8 {
        b.ins().ushr_imm_u(value, 8)
    } else {
        value
    };
    b.ins().band_imm_u(value, i64::from(register.mask()))
}
fn store(b: &mut FunctionBuilder<'_>, pointer: Value, register: Register, value: Value) {
    let offset = i32::from(register.index) * 4;
    let value = b.ins().band_imm_u(value, i64::from(register.mask()));
    let value = if register.bytes == 4 {
        value
    } else {
        let old = b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), pointer, offset);
        let shift = if register.high8 { 8 } else { 0 };
        let unchanged = b
            .ins()
            .band_imm_u(old, i64::from(!(register.mask() << shift)));
        let changed = b.ins().ishl_imm_u(value, i64::from(shift));
        b.ins().bor(unchanged, changed)
    };
    b.ins()
        .store(MemFlagsData::trusted(), value, pointer, offset);
}
fn flag(b: &mut FunctionBuilder<'_>, value: Value, shift: i64) -> Value {
    let bit = b.ins().uextend(types::I32, value);
    b.ins().ishl_imm_u(bit, shift)
}
fn signed(b: &mut FunctionBuilder<'_>, value: Value, bytes: u8) -> Value {
    let value = match bytes {
        1 => b.ins().ireduce(types::I8, value),
        2 => b.ins().ireduce(types::I16, value),
        _ => value,
    };
    b.ins().sextend(types::I64, value)
}

pub(super) fn emit(b: &mut FunctionBuilder<'_>, pointer: Value, instruction: Instruction) {
    let register = instruction.destination;
    let original = load(b, pointer, register);
    let source = match instruction.source {
        Operand::Register(source) => load(b, pointer, source),
        Operand::Immediate(value) => b
            .ins()
            .iconst(types::I32, i64::from(value & register.mask())),
    };
    let old_flags = b
        .ins()
        .load(types::I32, MemFlagsData::trusted(), pointer, 32);
    match instruction.operation {
        Op::ZeroExtend => {
            store(b, pointer, register, source);
            return;
        }
        Op::SignExtend => {
            let bytes = match instruction.source {
                Operand::Register(source) => source.bytes,
                _ => register.bytes,
            };
            let value = signed(b, source, bytes);
            let value = b.ins().ireduce(types::I32, value);
            store(b, pointer, register, value);
            return;
        }
        Op::ByteSwap => {
            let value = b.ins().bswap(original);
            store(b, pointer, register, value);
            return;
        }
        Op::SetCondition(condition) => {
            let value = condition_value(b, old_flags, condition);
            let value = b.ins().uextend(types::I32, value);
            store(b, pointer, register, value);
            return;
        }
        Op::ConditionalMove(condition) => {
            let condition = condition_value(b, old_flags, condition);
            let value = b.ins().select(condition, source, original);
            store(b, pointer, register, value);
            return;
        }
        Op::Move => {
            store(b, pointer, register, source);
            return;
        }
        Op::Not => {
            let value = b.ins().bnot(original);
            store(b, pointer, register, value);
            return;
        }
        Op::Exchange => {
            store(b, pointer, register, source);
            if let Operand::Register(source) = instruction.source {
                store(b, pointer, source, original);
            }
            return;
        }
        _ => {}
    }
    let zero = b.ins().iconst(types::I32, 0);
    let one = b.ins().iconst(types::I32, 1);
    let (left, right) = match instruction.operation {
        Op::Negate => (zero, original),
        Op::Increment | Op::Decrement => (original, one),
        _ => (original, source),
    };
    let logical = matches!(instruction.operation, Op::And | Op::Or | Op::Xor | Op::Test);
    let mut new_flags = zero;
    let result = if logical {
        match instruction.operation {
            Op::And | Op::Test => b.ins().band(left, right),
            Op::Or => b.ins().bor(left, right),
            _ => b.ins().bxor(left, right),
        }
    } else {
        let borrow = matches!(
            instruction.operation,
            Op::Subtract | Op::SubtractBorrow | Op::Compare | Op::Decrement | Op::Negate
        );
        let carry = if matches!(instruction.operation, Op::AddCarry | Op::SubtractBorrow) {
            b.ins().band_imm_u(old_flags, 1)
        } else {
            zero
        };
        let l = b.ins().uextend(types::I64, left);
        let r = b.ins().uextend(types::I64, right);
        let c = b.ins().uextend(types::I64, carry);
        let rc = b.ins().iadd(r, c);
        let wide = if borrow {
            b.ins().isub(l, rc)
        } else {
            b.ins().iadd(l, rc)
        };
        let carry_bit = if borrow {
            b.ins().icmp(IntCC::UnsignedLessThan, l, rc)
        } else {
            b.ins()
                .icmp_imm_s(IntCC::UnsignedGreaterThan, wide, i64::from(register.mask()))
        };
        new_flags = flag(b, carry_bit, 0);
        let sl = signed(b, left, register.bytes);
        let sr = signed(b, right, register.bytes);
        let sr = b.ins().iadd(sr, c);
        let sum = if borrow {
            b.ins().isub(sl, sr)
        } else {
            b.ins().iadd(sl, sr)
        };
        let minimum = -(1_i64 << (register.bytes * 8 - 1));
        let low = b.ins().icmp_imm_s(IntCC::SignedLessThan, sum, minimum);
        let high = b
            .ins()
            .icmp_imm_s(IntCC::SignedGreaterThan, sum, -minimum - 1);
        let overflow = b.ins().bor(low, high);
        let overflow = flag(b, overflow, 11);
        new_flags = b.ins().bor(new_flags, overflow);
        let result = b.ins().ireduce(types::I32, wide);
        let result = b.ins().band_imm_u(result, i64::from(register.mask()));
        let aux = b.ins().bxor(left, right);
        let aux = b.ins().bxor(aux, result);
        let aux = b.ins().band_imm_u(aux, 0x10);
        new_flags = b.ins().bor(new_flags, aux);
        result
    };
    let result = b.ins().band_imm_u(result, i64::from(register.mask()));
    let zf = b.ins().icmp_imm_s(IntCC::Equal, result, 0);
    let zf = flag(b, zf, 6);
    new_flags = b.ins().bor(new_flags, zf);
    let sign = b
        .ins()
        .ushr_imm_u(result, i64::from(register.bytes * 8 - 1));
    let sign = b.ins().ishl_imm_u(sign, 7);
    new_flags = b.ins().bor(new_flags, sign);
    let low = b.ins().band_imm_u(result, 0xff);
    let parity = b.ins().popcnt(low);
    let parity = b.ins().band_imm_u(parity, 1);
    let parity = b.ins().icmp_imm_s(IntCC::Equal, parity, 0);
    let parity = flag(b, parity, 2);
    new_flags = b.ins().bor(new_flags, parity);
    let mask = if logical {
        0x8c5
    } else if matches!(instruction.operation, Op::Increment | Op::Decrement) {
        0x8d4
    } else {
        0x8d5
    };
    let previous = b.ins().band_imm_u(old_flags, i64::from(!mask as u32));
    let new_flags = b.ins().band_imm_u(new_flags, i64::from(mask));
    let flags = b.ins().bor(previous, new_flags);
    let flags = b.ins().bor_imm_u(flags, 2);
    b.ins().store(MemFlagsData::trusted(), flags, pointer, 32);
    if !matches!(instruction.operation, Op::Compare | Op::Test) {
        store(b, pointer, register, result);
    }
}

fn condition_value(b: &mut FunctionBuilder<'_>, flags: Value, condition: Condition) -> Value {
    use Condition::*;
    let mask = match condition {
        Overflow | NotOverflow => 1 << 11,
        Below | AboveEqual => 1,
        Equal | NotEqual => 1 << 6,
        BelowEqual | Above => (1 << 6) | 1,
        Sign | NotSign => 1 << 7,
        Parity | NotParity => 1 << 2,
        _ => 0,
    };
    let selected = if mask != 0 {
        b.ins().band_imm_u(flags, i64::from(mask))
    } else {
        let sign = b.ins().ushr_imm_u(flags, 7);
        let overflow = b.ins().ushr_imm_u(flags, 11);
        let different = b.ins().bxor(sign, overflow);
        let different = b.ins().band_imm_u(different, 1);
        if matches!(condition, LessEqual | Greater) {
            let zero = b.ins().band_imm_u(flags, 1 << 6);
            b.ins().bor(different, zero)
        } else {
            different
        }
    };
    let inverse = matches!(
        condition,
        NotOverflow | AboveEqual | NotEqual | Above | NotSign | NotParity | GreaterEqual | Greater
    );
    b.ins().icmp_imm_s(
        if inverse {
            IntCC::Equal
        } else {
            IntCC::NotEqual
        },
        selected,
        0,
    )
}

pub(crate) const CF: u32 = 1 << 0;
pub(crate) const PF: u32 = 1 << 2;
pub(crate) const AF: u32 = 1 << 4;
pub(crate) const ZF: u32 = 1 << 6;
pub(crate) const SF: u32 = 1 << 7;
pub(crate) const TF: u32 = 1 << 8;
pub(crate) const IF: u32 = 1 << 9;
pub(crate) const DF: u32 = 1 << 10;
pub(crate) const OF: u32 = 1 << 11;
const STATUS_FLAGS: u32 = CF | PF | AF | ZF | SF | OF;
const LOGIC_FLAGS: u32 = CF | PF | ZF | SF | OF;

pub(crate) fn width_mask(width: u8) -> u32 {
    match width { 1 => 0xff, 2 => 0xffff, _ => u32::MAX }
}
pub(crate) fn sign_bit(width: u8) -> u32 { 1_u32 << (u32::from(width) * 8 - 1) }
pub(crate) fn parity_even(value: u8) -> bool { value.count_ones() & 1 == 0 }

pub(crate) fn update_szp(regs: &mut Registers, result: u32, width: u8) {
    let value = result & width_mask(width);
    let mut flags = 0;
    if value == 0 { flags |= ZF; }
    if value & sign_bit(width) != 0 { flags |= SF; }
    if parity_even(value as u8) { flags |= PF; }
    regs.eflags = (regs.eflags & !(ZF | SF | PF)) | flags;
}

#[derive(Clone, Copy)]
pub(crate) enum AluOp { Add, Or, Adc, Sbb, And, Sub, Xor, Cmp, Test }

pub(crate) fn signed_value(value: u32, width: u8) -> i64 {
    let bits = i64::from(width) * 8;
    let sign = 1_i64 << (bits - 1);
    let value = i64::from(value & width_mask(width));
    if value & sign != 0 { value - (1_i64 << bits) } else { value }
}

fn arithmetic_flags(result: u32, width: u8, carry: bool, auxiliary: bool, overflow: bool) -> u32 {
    let mut flags = 0;
    if carry { flags |= CF; }
    if auxiliary { flags |= AF; }
    if overflow { flags |= OF; }
    if result & width_mask(width) == 0 { flags |= ZF; }
    if result & sign_bit(width) != 0 { flags |= SF; }
    if parity_even(result as u8) { flags |= PF; }
    flags
}

pub(crate) fn alu_compute(regs: &Registers, op: AluOp, lhs: u32, rhs: u32, width: u8) -> (u32, u32, u32) {
    let mask = width_mask(width);
    let lhs = lhs & mask;
    let rhs = rhs & mask;
    let carry_in = u32::from(regs.eflags & CF != 0);
    let (result, flag_mask, new_flags) = match op {
        AluOp::Add | AluOp::Adc => {
            let c = if matches!(op, AluOp::Adc) { carry_in } else { 0 };
            let wide = u64::from(lhs) + u64::from(rhs) + u64::from(c);
            let result = (wide as u32) & mask;
            let min = -(1_i64 << (i64::from(width) * 8 - 1));
            let max = -min - 1;
            let signed_sum = signed_value(lhs, width) + signed_value(rhs, width) + i64::from(c);
            let flags = arithmetic_flags(
                result, width, wide > u64::from(mask), (lhs ^ rhs ^ result) & 0x10 != 0,
                signed_sum < min || signed_sum > max,
            );
            (result, STATUS_FLAGS, flags)
        }
        AluOp::Sub | AluOp::Sbb | AluOp::Cmp => {
            let c = if matches!(op, AluOp::Sbb) { carry_in } else { 0 };
            let subtrahend = u64::from(rhs) + u64::from(c);
            let result = lhs.wrapping_sub(rhs).wrapping_sub(c) & mask;
            let min = -(1_i64 << (i64::from(width) * 8 - 1));
            let max = -min - 1;
            let signed_diff = signed_value(lhs, width) - signed_value(rhs, width) - i64::from(c);
            let flags = arithmetic_flags(
                result, width, u64::from(lhs) < subtrahend,
                (lhs ^ rhs ^ result) & 0x10 != 0,
                signed_diff < min || signed_diff > max,
            );
            (result, STATUS_FLAGS, flags)
        }
        AluOp::Or | AluOp::And | AluOp::Test | AluOp::Xor => {
            let result = match op {
                AluOp::Or => lhs | rhs, AluOp::And | AluOp::Test => lhs & rhs,
                _ => lhs ^ rhs,
            } & mask;
            let mut flags = 0;
            if result == 0 { flags |= ZF; }
            if result & sign_bit(width) != 0 { flags |= SF; }
            if parity_even(result as u8) { flags |= PF; }
            // AF is architecturally undefined for these operations and is
            // retained, while CF and OF are architecturally cleared.
            (result, LOGIC_FLAGS, flags)
        }
    };
    (result, flag_mask, new_flags)
}

pub(crate) fn apply_flags(regs: &mut Registers, mask: u32, values: u32) {
    regs.eflags = (regs.eflags & !mask) | (values & mask) | 2;
}

pub(crate) fn condition(regs: &Registers, code: u8) -> bool {
    let cf = regs.eflags & CF != 0;
    let pf = regs.eflags & PF != 0;
    let zf = regs.eflags & ZF != 0;
    let sf = regs.eflags & SF != 0;
    let of = regs.eflags & OF != 0;
    match code & 0xf {
        0 => of, 1 => !of, 2 => cf, 3 => !cf, 4 => zf, 5 => !zf,
        6 => cf || zf, 7 => !cf && !zf, 8 => sf, 9 => !sf, 10 => pf,
        11 => !pf, 12 => sf != of, 13 => sf == of,
        14 => zf || sf != of, _ => !zf && sf == of,
    }
}
use guest_core::Registers;

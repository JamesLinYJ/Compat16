use guest_core::Registers;

use crate::flags::{
    apply_flags, parity_even, sign_bit, signed_value, width_mask, AF, CF, OF, PF, SF, ZF,
};
use crate::CpuError;

pub(crate) fn execute_shift(regs: &mut Registers, value: u32, width: u8, extension: u8, count: u8) -> (u32, u32, u32) {
    let mask = width_mask(width);
    let bits = width * 8;
    let masked_count = count & 0x1f;
    if masked_count == 0 { return (value & mask, 0, regs.eflags); }
    let mut result = value & mask;
    let mut carry = regs.eflags & CF != 0;
    let mut overflow = regs.eflags & OF != 0;
    let kind = if extension == 6 { 4 } else { extension };
    // Single-operand shifts apply the full masked count, including counts
    // greater than the operand width. SHLD/SHRD have separate undefined-
    // destination rules and do not use this executor.
    let effective_count = match kind {
        0 | 1 => masked_count % bits,
        2 | 3 => masked_count % (bits + 1),
        _ => masked_count,
    };
    if effective_count == 0 {
        // ROL/ROR still define CF for nonzero masked counts that make one or
        // more complete operand turns. RCL/RCR reduce over the operand plus
        // CF ring, so an effective zero preserves every flag.
        if matches!(kind, 0 | 1) {
            carry = if kind == 0 {
                result & 1 != 0
            } else {
                result & sign_bit(width) != 0
            };
            return (result, CF, if carry { CF } else { 0 });
        }
        return (result, 0, regs.eflags);
    }
    for _ in 0..effective_count {
        match kind {
            0 => { // ROL
                let out = result & sign_bit(width) != 0;
                result = ((result << 1) | u32::from(out)) & mask;
                carry = out;
            }
            1 => { // ROR
                let out = result & 1 != 0;
                result = (result >> 1) | if out { sign_bit(width) } else { 0 };
                carry = out;
            }
            2 => { // RCL
                let out = result & sign_bit(width) != 0;
                result = ((result << 1) | u32::from(carry)) & mask;
                carry = out;
            }
            3 => { // RCR
                let out = result & 1 != 0;
                result = (result >> 1) | if carry { sign_bit(width) } else { 0 };
                carry = out;
            }
            4 => { carry = result & sign_bit(width) != 0; result = result.wrapping_shl(1) & mask; }
            5 => { carry = result & 1 != 0; result >>= 1; }
            _ => {
                carry = result & 1 != 0;
                result = (signed_value(result, width) >> 1) as u32 & mask;
            }
        }
    }
    let mut flags_mask = CF;
    let mut flags = if carry { CF } else { 0 };
    if masked_count == 1 {
        flags_mask |= OF;
        overflow = match kind {
            0 | 2 | 4 => (result & sign_bit(width) != 0) ^ carry,
            1 | 3 => (result & sign_bit(width) != 0) ^ (result & (sign_bit(width) >> 1) != 0),
            5 => value & sign_bit(width) != 0,
            7 => false,
            _ => overflow,
        };
        if overflow { flags |= OF; }
    }
    if kind >= 4 {
        flags_mask |= PF | ZF | SF;
        if result == 0 { flags |= ZF; }
        if result & sign_bit(width) != 0 { flags |= SF; }
        if parity_even(result as u8) { flags |= PF; }
    }
    (result, flags_mask, flags)
}

pub(crate) fn execute_multiply(regs: &mut Registers, operand: u32, width: u8, signed: bool) {
    let (low, high, overflow) = match (width, signed) {
        (1, false) => {
            let product = u32::from(regs.al()) * (operand & 0xff);
            (product & 0xffff, 0, product > 0xff)
        }
        (2, false) => {
            let product = u64::from(regs.ax()) * u64::from(operand & 0xffff);
            (product as u32 & 0xffff, (product >> 16) as u32 & 0xffff, product >> 16 != 0)
        }
        (4, false) => {
            let product = u64::from(regs.eax) * u64::from(operand);
            (product as u32, (product >> 32) as u32, product >> 32 != 0)
        }
        (1, true) => {
            let product = (regs.al() as i8 as i16 as i32) * (operand as u8 as i8 as i32);
            let packed = product as u16;
            (u32::from(packed), 0, product < i32::from(i8::MIN) || product > i32::from(i8::MAX))
        }
        (2, true) => {
            let product = (regs.ax() as i16 as i32) * (operand as u16 as i16 as i32);
            let packed = product as u32;
            (packed & 0xffff, (packed >> 16) & 0xffff,
             product < i32::from(i16::MIN) || product > i32::from(i16::MAX))
        }
        _ => {
            let product = (regs.eax as i32 as i64) * (operand as i32 as i64);
            let packed = product as u64;
            (packed as u32, (packed >> 32) as u32,
             product < i64::from(i32::MIN) || product > i64::from(i32::MAX))
        }
    };
    match width {
        1 => regs.set_ax(low as u16),
        2 => { regs.set_ax(low as u16); regs.set_dx(high as u16); }
        _ => { regs.eax = low; regs.edx = high; }
    }
    apply_flags(regs, CF | OF, if overflow { CF | OF } else { 0 });
}

pub(crate) fn execute_divide(regs: &mut Registers, divisor: u32, width: u8, signed: bool) -> Result<(), CpuError> {
    if divisor & width_mask(width) == 0 { return Err(CpuError::DivideError); }
    if !signed {
        let dividend = match width {
            1 => u64::from(regs.ax()),
            2 => (u64::from(regs.dx()) << 16) | u64::from(regs.ax()),
            _ => (u64::from(regs.edx) << 32) | u64::from(regs.eax),
        };
        let quotient = dividend / u64::from(divisor & width_mask(width));
        let remainder = dividend % u64::from(divisor & width_mask(width));
        if quotient > u64::from(width_mask(width)) { return Err(CpuError::DivideError); }
        match width {
            1 => { regs.set_al(quotient as u8); regs.set_ah(remainder as u8); }
            2 => { regs.set_ax(quotient as u16); regs.set_dx(remainder as u16); }
            _ => { regs.eax = quotient as u32; regs.edx = remainder as u32; }
        }
    } else {
        let (dividend, divisor_signed, min, max) = match width {
            1 => (i64::from(regs.ax() as i16), i64::from(divisor as u8 as i8), i64::from(i8::MIN), i64::from(i8::MAX)),
            2 => {
                let raw = (u32::from(regs.dx()) << 16) | u32::from(regs.ax());
                (i64::from(raw as i32), i64::from(divisor as u16 as i16), i64::from(i16::MIN), i64::from(i16::MAX))
            }
            _ => {
                let raw = (u64::from(regs.edx) << 32) | u64::from(regs.eax);
                (raw as i64, i64::from(divisor as i32), i64::from(i32::MIN), i64::from(i32::MAX))
            }
        };
        if dividend == i64::MIN && divisor_signed == -1 { return Err(CpuError::DivideError); }
        let quotient = dividend / divisor_signed;
        let remainder = dividend % divisor_signed;
        if quotient < min || quotient > max { return Err(CpuError::DivideError); }
        match width {
            1 => { regs.set_al(quotient as i8 as u8); regs.set_ah(remainder as i8 as u8); }
            2 => { regs.set_ax(quotient as i16 as u16); regs.set_dx(remainder as i16 as u16); }
            _ => { regs.eax = quotient as i32 as u32; regs.edx = remainder as i32 as u32; }
        }
    }
    Ok(())
}

pub(crate) fn decimal_adjust(regs: &mut Registers, subtract: bool) {
    let original = regs.al();
    let old_carry = regs.eflags & CF != 0;
    let mut value = original;
    let low_adjust = original & 0x0f > 9 || regs.eflags & AF != 0;
    let low_borrow = subtract && low_adjust && original < 6;
    let low_carry = !subtract && low_adjust && u16::from(original) + 6 > 0xff;
    let auxiliary = low_adjust;
    if low_adjust {
        value = if subtract { value.wrapping_sub(6) } else { value.wrapping_add(6) };
    }
    let high_adjust = original > 0x99 || old_carry || low_carry;
    if high_adjust {
        value = if subtract { value.wrapping_sub(0x60) } else { value.wrapping_add(0x60) };
    }
    // DAS propagates a borrow from its low-digit correction. DAA propagates
    // the corresponding carry; either direction also retains an old carry.
    let carry = old_carry || high_adjust || low_borrow;
    regs.set_al(value);
    let mut flag_values = 0;
    if auxiliary { flag_values |= AF; }
    if carry { flag_values |= CF; }
    if value == 0 { flag_values |= ZF; }
    if value & 0x80 != 0 { flag_values |= SF; }
    if parity_even(value) { flag_values |= PF; }
    apply_flags(regs, CF | AF | ZF | SF | PF, flag_values);
}

pub(crate) fn ascii_adjust(regs: &mut Registers, subtract: bool) {
    let al = regs.al();
    let adjust = al & 0x0f > 9 || regs.eflags & AF != 0;
    if adjust {
        let ax = if subtract { regs.ax().wrapping_sub(0x0106) }
            else { regs.ax().wrapping_add(0x0106) };
        regs.set_ax(ax);
        apply_flags(regs, AF | CF, AF | CF);
    } else { apply_flags(regs, AF | CF, 0); }
    regs.set_al(regs.al() & 0x0f);
}

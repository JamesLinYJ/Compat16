//! Independent decimal-reference vectors through actual x87 instruction bytes.
mod data;

use super::*;
use crate::x87_state::Ext80;

fn raw(pair: (u64, u16)) -> Ext80 {
    Ext80 { significand: pair.0, sign_exponent: pair.1 }
}

#[test]
fn transcendental_results_match_independent_decimal_reference_vectors() {
    for (index, &(opcode, left, right, mode, first, second)) in data::CASES.iter().enumerate() {
        let (mut cpu, mut ram) = cpu_with(&[0xd9, opcode], 0x3000);
        cpu.x87.control_word = 0x037f | (mode << 10);
        cpu.x87.write_st(0, raw(left));
        cpu.x87.write_st(1, raw(right));
        assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
        assert_eq!(cpu.x87.read_st(0), Some(raw(first)), "vector {index}: opcode {opcode:02x}, RC {mode}, ST0");
        if let Some(value) = second {
            assert_eq!(cpu.x87.read_st(1), Some(raw(value)), "vector {index}: opcode {opcode:02x}, RC {mode}, ST1");
        }
        assert_eq!(cpu.x87.status_word & 0x041f, 0, "vector {index}: unexpected fault or range failure");
    }
}

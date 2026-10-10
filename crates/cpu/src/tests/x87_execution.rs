//! Full decode/execute x87 tests through Cpu, independent of helper dispatch.

use super::*;
use crate::x87_state::{Ext80, X87_C1};

fn native_x87_cpu_with(code: &[u8], ram_size: usize) -> (Cpu, Ram) {
    let (mut cpu, ram) = cpu_with(code, ram_size);
    // Intel486 CR0.NE selects native #MF delivery rather than the external
    // FERR#/IRQ13 compatibility path selected by the reset value NE=0.
    cpu.system.write_cr0(cpu.system.cr0 | crate::system::CR0_NE).unwrap();
    (cpu, ram)
}

fn assert_pending_mf(cpu: &mut Cpu, ram: &mut Ram, waiting_ip: u32) {
    let registers = cpu.regs.clone();
    let state = cpu.x87.clone();
    let outcome = cpu.step_with_context_observing_events(
        ram, &mut guest_core::io::NoPorts, &crate::RealModeSegments,
    ).unwrap();
    let crate::CpuObservedStepOutcome::EventDeferred(event) = outcome else {
        panic!("expected a pending native x87 fault, got {outcome:?}");
    };
    let observation = event.observation();
    assert_eq!(observation.vector, 16);
    assert_eq!(observation.source, crate::CpuEventSource::Fault);
    assert_eq!(observation.saved_cs, registers.cs);
    assert_eq!(observation.saved_ip, waiting_ip);
    assert_eq!(observation.error_code, None);
    assert_eq!(cpu.regs, registers);
    assert_eq!(cpu.x87, state);
    assert!(!cpu.take_pending_x87_irq13());
}

#[test]
fn basic_x87_sequence_decodes_executes_stores_and_pops() {
    let (mut cpu, mut ram) = cpu_with(&[
        0xdb, 0xe3, // fninit
        0xd9, 0xe8, // fld1
        0xd9, 0xe8, // fld1
        0xde, 0xc1, // faddp st1,st0
        0xd9, 0x1e, 0x00, 0x02, // fstp dword [0200]
        0xdf, 0xe0, // fnstsw ax
        0xf4,
    ], 0x3000);
    for _ in 0..6 { assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); }
    assert_eq!(&ram.bytes[0x200..0x204], &0x4000_0000u32.to_le_bytes());
    assert_eq!(cpu.regs.ax() & 0x3fff, 0);
    assert_eq!(cpu.x87.tag_word, 0xffff);
}

#[test]
fn x87_bcd_round_trip_uses_bit_79_for_sign() {
    for sign in [0, 0x80] {
        let (mut cpu, mut ram) = cpu_with(&[
            0xdf, 0x26, 0x00, 0x02, // fbld [0200]
            0xdf, 0x36, 0x10, 0x02, // fbstp [0210]
        ], 0x3000);
        let bytes = [0x89, 0x67, 0x45, 0x23, 0x01, 0x89, 0x67, 0x45, 0x23, sign];
        ram.put(0x200, &bytes);
        cpu.step(&mut ram).unwrap();
        cpu.step(&mut ram).unwrap();
        assert_eq!(&ram.bytes[0x210..0x21a], &bytes);
        assert_eq!(cpu.x87.tag_word, 0xffff);
    }
}

#[test]
fn fst_register_can_fill_an_empty_destination() {
    let (mut cpu, mut ram) = cpu_with(&[0xd9, 0xe8, 0xdd, 0xd3], 0x3000);
    cpu.x87.control_word &= !1;
    cpu.step(&mut ram).unwrap();
    cpu.step(&mut ram).unwrap();
    assert_eq!(cpu.x87.read_st(3), cpu.x87.read_st(0));
    assert_eq!(cpu.x87.status_word & 0x41, 0);
}

#[test]
fn fninit_clears_saved_instruction_state() {
    let (mut cpu, mut ram) = cpu_with(&[0xd9, 0xe8, 0xdb, 0xe3], 0x3000);
    cpu.step(&mut ram).unwrap();
    assert_eq!(cpu.x87.opcode, 0x1e8);
    cpu.step(&mut ram).unwrap();
    assert_eq!(cpu.x87.opcode, 0);
    assert_eq!(cpu.x87.instruction_pointer, 0);
    assert_eq!(cpu.x87.instruction_segment, 0);
    assert_eq!(cpu.x87.status_word, 0);
    assert_eq!(cpu.x87.tag_word, 0xffff);
}

#[test]
fn pending_x87_exception_allows_integer_execution_but_faults_waiting_fnop() {
    let (mut cpu, mut ram) = native_x87_cpu_with(&[0x90, 0xd9, 0xd0], 0x3000);
    cpu.x87.control_word &= !1;
    cpu.x87.record_exceptions(1, false, None);
    cpu.step(&mut ram).unwrap();
    assert_eq!(cpu.regs.eip, 1);
    assert_pending_mf(&mut cpu, &mut ram, 1);
    assert_eq!(cpu.regs.eip, 1);
}

#[test]
fn legacy_x87_interrupt_and_protected_mode_controls_are_i486_noops() {
    for code in [
        &[0xdb, 0xe0][..], // FNENI
        &[0xdb, 0xe1][..], // FNDISI
        &[0xdb, 0xe4][..], // FNSETPM
    ] {
        let (mut cpu, mut ram) = cpu_with(code, 0x3000);
        cpu.x87.instruction_pointer = 0x1234_5678;
        cpu.x87.instruction_segment = 0x2468;
        cpu.x87.data_pointer = 0x9abc_def0;
        cpu.x87.data_segment = 0x1357;
        cpu.x87.opcode = 0x05aa;
        cpu.x87.status_word = 0x4500;
        let before = cpu.x87.clone();

        assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
        assert_eq!(cpu.x87, before);
    }
}

#[test]
fn fndisi_is_nonwaiting_but_a_following_fwait_checks_pending_exception() {
    for code in [
        &[0xdb, 0xe0, 0x9b][..], // FNENI; FWAIT
        &[0xdb, 0xe1, 0x9b][..], // FNDISI; FWAIT
        &[0xdb, 0xe4, 0x9b][..], // FNSETPM; FWAIT
    ] {
        let (mut cpu, mut ram) = native_x87_cpu_with(code, 0x3000);
        cpu.x87.control_word &= !1; // Unmask invalid-operation exception.
        cpu.x87.record_exceptions(1, false, None);
        let before = cpu.x87.clone();

        assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
        assert_eq!(cpu.regs.ip(), 2);
        assert_eq!(cpu.x87, before);
        assert_pending_mf(&mut cpu, &mut ram, 2);
        assert_eq!(cpu.regs.ip(), 2);
    }
}

#[test]
fn faulting_x87_store_keeps_stack_registers_and_memory_unchanged() {
    let (mut cpu, mut ram) = cpu_with(&[0xdb, 0x3e, 0x00, 0x02], 0x3000); // fstp tbyte [0200]
    cpu.x87.write_st(0, Ext80 { significand: 1 << 63, sign_exponent: 0x3fff });
    cpu.x87.status_word |= X87_C1;
    ram.put(0x200, &[0xa5; 10]);
    ram.reject_write_at(0x209);
    let old_state = cpu.x87.clone();
    let old_regs = cpu.regs.clone();
    assert!(matches!(cpu.step(&mut ram), Err(CpuError::Memory(_))));
    assert_eq!(cpu.x87, old_state);
    assert_eq!(cpu.regs, old_regs);
    assert_eq!(&ram.bytes[0x200..0x20a], &[0xa5; 10]);
}

#[test]
fn square_root_is_reached_through_instruction_dispatch() {
    let (mut cpu, mut ram) = cpu_with(&[0xd9, 0xfa], 0x3000);
    cpu.x87.write_st(0, Ext80 { significand: 1 << 63, sign_exponent: 0x4001 });
    cpu.step(&mut ram).unwrap();
    assert_eq!(cpu.x87.read_st(0), Some(Ext80 { significand: 1 << 63, sign_exponent: 0x4000 }));
}

#[test]
fn constant_loads_obey_rc_and_clear_c1_without_precision_exception() {
    let constants = [
        (0xe9, 0xd49a_784b_cd1b_8afe, 0x4000, false),
        (0xea, 0xb8aa_3b29_5c17_f0bb, 0x3fff, true),
        (0xeb, 0xc90f_daa2_2168_c234, 0x4000, true),
        (0xec, 0x9a20_9a84_fbcf_f798, 0x3ffd, true),
        (0xed, 0xb172_17f7_d1cf_79ab, 0x3ffe, true),
    ];
    for (opcode, lower, sign_exponent, nearest_up) in constants {
        for mode in 0..4 {
            let (mut cpu, mut ram) = cpu_with(&[0xd9, opcode], 0x3000);
            cpu.x87.control_word = 0x007f | (mode << 10); // PC24 must be ignored.
            cpu.x87.status_word |= X87_C1;
            cpu.step(&mut ram).unwrap();
            let increment = mode == 2 || (mode == 0 && nearest_up);
            assert_eq!(cpu.x87.read_st(0), Some(Ext80 {
                significand: lower + u64::from(increment), sign_exponent,
            }), "opcode {opcode:02x}, RC {mode}");
            assert_eq!(cpu.x87.status_word & (X87_C1 | 0x3f), 0);
        }
    }
}

#[test]
fn unmasked_precision_commits_register_result_then_faults_on_wait() {
    let (mut cpu, mut ram) = native_x87_cpu_with(&[0xd8, 0xc1, 0x9b], 0x3000);
    cpu.x87.control_word &= !(1 << 5);
    cpu.x87.write_st(0, Ext80 { significand: 1 << 63, sign_exponent: 0x3fff });
    cpu.x87.write_st(1, Ext80 { significand: 0xc000_0000_0000_0000, sign_exponent: 0x3fc0 });
    cpu.step(&mut ram).unwrap(); // 1 + 1.5 ULP rounds to the even 1 + 2 ULP.
    assert_eq!(cpu.x87.read_st(0), Some(Ext80 { significand: (1 << 63) + 2, sign_exponent: 0x3fff }));
    assert_ne!(cpu.x87.status_word & 0x20, 0);
    assert_pending_mf(&mut cpu, &mut ram, 2);
    assert_eq!(cpu.regs.eip, 2);
}

#[test]
fn unmasked_precision_on_fstp_stores_and_pops_before_wait() {
    let (mut cpu, mut ram) = native_x87_cpu_with(&[0xd9, 0x1e, 0x00, 0x02, 0x9b], 0x3000);
    cpu.x87.control_word &= !(1 << 5);
    cpu.x87.write_st(0, Ext80 { significand: 0x8000_0000_0000_0001, sign_exponent: 0x3fff });
    cpu.step(&mut ram).unwrap();
    assert_eq!(&ram.bytes[0x200..0x204], &0x3f80_0000u32.to_le_bytes());
    assert_eq!(cpu.x87.tag_word, 0xffff);
    assert_ne!(cpu.x87.status_word & 0x20, 0);
    assert_pending_mf(&mut cpu, &mut ram, 4);
    assert_eq!(cpu.regs.eip, 4);
}

#[test]
fn transcendental_stack_pairs_commit_before_unmasked_precision_waits() {
    for opcode in [0xfb, 0xf2] { // FSINCOS and FPTAN
        let code = [0xd9, opcode, 0x9b];
        let (mut masked, mut masked_ram) = native_x87_cpu_with(&code, 0x3000);
        let (mut unmasked, mut unmasked_ram) = native_x87_cpu_with(&code, 0x3000);
        let half = Ext80 { significand: 1 << 63, sign_exponent: 0x3ffe };
        masked.x87.write_st(0, half);
        unmasked.x87.write_st(0, half);
        unmasked.x87.control_word &= !0x20;
        masked.step(&mut masked_ram).unwrap();
        unmasked.step(&mut unmasked_ram).unwrap();
        assert_eq!(unmasked.x87.top(), 7);
        assert_eq!(unmasked.x87.registers, masked.x87.registers);
        assert_eq!(unmasked.x87.tag_word, masked.x87.tag_word);
        assert_eq!(unmasked.x87.pending_unmasked_exceptions(), 0x20);
        assert_pending_mf(&mut unmasked, &mut unmasked_ram, 2);
    }
}

#[test]
fn unmasked_range_traps_commit_biased_multiply_results_and_normal_pop() {
    let two = Ext80 { significand: 1 << 63, sign_exponent: 0x4000 };
    let half = Ext80 { significand: 1 << 63, sign_exponent: 0x3ffe };
    for (value, factor, expected, flag) in [
        (Ext80 { significand: u64::MAX, sign_exponent: 0x7ffe }, two,
         Ext80 { significand: u64::MAX, sign_exponent: 0x1fff }, 0x08),
        (Ext80 { significand: 1 << 63, sign_exponent: 0x0001 }, half,
         Ext80 { significand: 1 << 63, sign_exponent: 0x6000 }, 0x10),
    ] {
        for negative in [false, true] {
            for pop in [false, true] {
                let code = [if pop { 0xde } else { 0xd8 }, 0xc9, 0x9b];
                let (mut cpu, mut ram) = native_x87_cpu_with(&code, 0x3000);
                let sign = if negative { 0x8000 } else { 0 };
                let value = Ext80 { sign_exponent: value.sign_exponent | sign, ..value };
                let expected = Ext80 { sign_exponent: expected.sign_exponent | sign, ..expected };
                cpu.x87.control_word &= !flag;
                cpu.x87.status_word |= X87_C1;
                cpu.x87.write_st(u8::from(pop), value);
                cpu.x87.write_st(u8::from(!pop), factor);
                cpu.step(&mut ram).unwrap();
                assert_eq!(cpu.x87.top(), u8::from(pop));
                assert_eq!(cpu.x87.read_st(0), Some(expected));
                assert_eq!(cpu.x87.status_word & (0x3f | X87_C1), flag);
                assert_eq!(cpu.x87.pending_unmasked_exceptions(), flag);
                assert_pending_mf(&mut cpu, &mut ram, 2);
                assert_eq!(cpu.regs.eip, 2);
            }
        }
    }
}

#[test]
fn unmasked_fscale_preserves_stack_and_commits_adjusted_or_massive_results() {
    for scale in [20_000_i32, -20_000, 50_000, -50_000] {
        for negative in [false, true] {
            let (mut cpu, mut ram) = native_x87_cpu_with(&[0xd9, 0xfd, 0x9b], 0x3000);
            let sign = if negative { 0x8000 } else { 0 };
            let flag = if scale > 0 { 8 } else { 16 };
            let magnitude = scale.unsigned_abs();
            let exponent = 31 - magnitude.leading_zeros();
            let amount = Ext80 {
                significand: u64::from(magnitude) << (63 - exponent),
                sign_exponent: (16383 + exponent) as u16 | if scale < 0 { 0x8000 } else { 0 },
            };
            cpu.x87.control_word &= !flag;
            cpu.x87.write_st(0, Ext80 { significand: 1 << 63, sign_exponent: sign | 0x3fff });
            cpu.x87.write_st(1, amount);
            let biased = scale + if scale > 0 { -24576 } else { 24576 };
            let expected = if biased > 16383 {
                Ext80 { significand: 1 << 63, sign_exponent: sign | 0x7fff }
            } else if biased < -16445 {
                Ext80 { significand: 0, sign_exponent: sign }
            } else {
                Ext80 { significand: 1 << 63, sign_exponent: sign | (biased + 16383) as u16 }
            };
            cpu.step(&mut ram).unwrap();
            assert_eq!(cpu.x87.top(), 0);
            assert_eq!(cpu.x87.read_st(0), Some(expected), "scale {scale}, sign {negative}");
            assert_eq!(cpu.x87.read_st(1), Some(amount));
            assert_eq!(cpu.x87.pending_unmasked_exceptions(), flag);
            assert_pending_mf(&mut cpu, &mut ram, 2);
        }
    }
}

#[test]
fn external_x87_error_requests_irq13_and_stalls_wait_without_native_fault() {
    let (mut cpu, mut ram) = cpu_with(&[0xd8, 0xc1, 0x90, 0x9b], 0x3000);
    assert_eq!(cpu.system.cr0 & crate::system::CR0_NE, 0);
    cpu.x87.control_word &= !0x20;
    cpu.x87.write_st(0, Ext80 { significand: 1 << 63, sign_exponent: 0x3fff });
    cpu.x87.write_st(1, Ext80 { significand: 0xc000_0000_0000_0000, sign_exponent: 0x3fc0 });

    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert_eq!(cpu.regs.eip, 2);
    assert_eq!(cpu.x87.read_st(0), Some(Ext80 { significand: (1 << 63) + 2, sign_exponent: 0x3fff }));
    assert_eq!(cpu.x87.pending_unmasked_exceptions(), 0x20);
    assert!(cpu.take_pending_x87_irq13());
    assert!(!cpu.take_pending_x87_irq13());

    // Integer instructions still retire, but WAIT cannot pass the pending
    // exception until the external interrupt handler clears its cause.
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert_eq!(cpu.regs.eip, 3);
    let registers = cpu.regs.clone();
    let state = cpu.x87.clone();
    for _ in 0..2 {
        let outcome = cpu.step_with_context_observing_events(
            &mut ram, &mut guest_core::io::NoPorts, &crate::RealModeSegments,
        ).unwrap();
        assert!(matches!(outcome, crate::CpuObservedStepOutcome::Executed(StepOutcome::Continue)));
        assert_eq!(cpu.regs, registers);
        assert_eq!(cpu.x87, state);
        assert!(cpu.take_pending_x87_irq13());
    }
}

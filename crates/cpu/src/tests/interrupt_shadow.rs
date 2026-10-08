use super::{cpu_with, StepOutcome};
use super::super::IF;

#[test]
fn sti_blocks_irq_until_one_following_instruction_retires() {
    let (mut cpu, mut ram) = cpu_with(&[0xfb, 0x90, 0x90], 0x10000);
    assert!(!cpu.can_accept_maskable_interrupt());

    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // STI
    assert_ne!(cpu.regs.eflags & IF, 0);
    assert!(!cpu.can_accept_maskable_interrupt());

    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // NOP
    assert!(cpu.can_accept_maskable_interrupt());
}

#[test]
fn consecutive_sti_does_not_extend_the_first_delay() {
    let (mut cpu, mut ram) = cpu_with(&[0xfb, 0xfb, 0x90], 0x10000);

    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert!(!cpu.can_accept_maskable_interrupt());
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert!(cpu.can_accept_maskable_interrupt());
}

#[test]
fn mov_ss_and_pop_ss_block_irq_after_loading_stack_segment() {
    let (mut cpu, mut ram) = cpu_with(&[0x8e, 0xd0, 0x90, 0x17, 0x90], 0x30000);
    cpu.regs.set_ax(0x0200);
    cpu.regs.eflags |= IF;
    ram.put(0x2000 + 0xfffe, &[0x00, 0x03]);

    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // MOV SS,AX
    assert_eq!(cpu.regs.ss, 0x0200);
    assert!(!cpu.can_accept_maskable_interrupt());
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // NOP
    assert!(cpu.can_accept_maskable_interrupt());

    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // POP SS
    assert_eq!((cpu.regs.ss, cpu.regs.sp()), (0x0300, 0));
    assert!(!cpu.can_accept_maskable_interrupt());
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // NOP
    assert!(cpu.can_accept_maskable_interrupt());
}

#[test]
fn lss_loads_stack_atomically_without_an_interrupt_shadow() {
    let (mut cpu, mut ram) = cpu_with(&[0x0f, 0xb2, 0x06, 0x00, 0x02, 0x90], 0x30000);
    cpu.regs.eflags |= IF;
    ram.put(0x0200, &[0x34, 0x12, 0x00, 0x03]);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // LSS AX,[0200]
    assert_eq!((cpu.regs.ax(), cpu.regs.ss), (0x1234, 0x0300));
    assert!(cpu.can_accept_maskable_interrupt());
}

#[test]
fn consecutive_stack_segment_loads_do_not_extend_the_first_delay() {
    let (mut cpu, mut ram) = cpu_with(&[0x8e, 0xd0, 0x8e, 0xd0, 0x90], 0x10000);
    cpu.regs.set_ax(0x0200);
    cpu.regs.eflags |= IF;

    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // first MOV SS,AX
    assert!(!cpu.can_accept_maskable_interrupt());
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // second MOV SS,AX
    assert!(cpu.can_accept_maskable_interrupt());
}

#[test]
fn pending_irq_can_wake_hlt_after_sti_shadow_expires() {
    let (mut cpu, mut ram) = cpu_with(&[0xfb, 0xf4], 0x30000);
    ram.put(0x08 * 4, &[0x34, 0x12, 0x00, 0x20]);
    ram.put(0x20000 + 0x1234, &[0x90]);

    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue); // STI
    assert!(!cpu.can_accept_maskable_interrupt());
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Halt); // HLT retires the shadowed instruction
    assert!(cpu.can_accept_maskable_interrupt());

    // Runtime checks can_accept before ACKing the PIC, then enters the vector.
    cpu.enter_real_mode_interrupt(0x08, &mut ram).unwrap();
    assert_eq!((cpu.regs.cs, cpu.regs.ip()), (0x2000, 0x1234));
    assert_eq!(cpu.regs.eflags & IF, 0);
    assert!(!cpu.can_accept_maskable_interrupt());
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
}

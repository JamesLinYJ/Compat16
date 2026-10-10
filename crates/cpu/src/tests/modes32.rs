//! Execution-context tests; a flat resolver exercises sizes without claiming
//! that GDT loading, privilege transitions or paging are integrated yet.

use super::{cpu_with, Ram};
use crate::memory_access::{AccessSite, CpuMemoryAccess};
use crate::system::CpuSystem;
use crate::{Cpu, CpuError, RealModeSegments, SegmentResolver, StepOutcome};
use guest_core::io::NoPorts;
use guest_core::PhysAddr;

struct FlatSegments { stack32: bool }

impl SegmentResolver for FlatSegments {
    fn code_bits(&self) -> u32 { 32 }
    fn stack32(&self) -> bool { self.stack32 }
    fn resolve(&self, _segment: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
        Ok(PhysAddr(if address32 { offset } else { u32::from(offset as u16) }))
    }
}

fn step(cpu: &mut Cpu, ram: &mut Ram, stack32: bool) -> StepOutcome {
    cpu.step_with_context(ram, &mut NoPorts, &FlatSegments { stack32 }).unwrap()
}

#[test]
fn default_32_bit_fetch_and_register_width_cross_64k() {
    let (mut cpu, mut ram) = cpu_with(&[], 0x30000);
    cpu.regs.eip = 0xfffe;
    ram.put(0xfffe, &[0xb8, 0x78, 0x56, 0x34, 0x12, 0x66, 0x05, 0x01, 0x00]);
    assert_eq!(step(&mut cpu, &mut ram, true), StepOutcome::Continue);
    assert_eq!(cpu.regs.eax, 0x1234_5678);
    assert_eq!(cpu.regs.eip, 0x10003);
    step(&mut cpu, &mut ram, true);
    assert_eq!(cpu.regs.eax, 0x1234_5679);
    assert_eq!(cpu.regs.eip, 0x10007);
}

#[test]
fn call_and_return_keep_full_eip_and_esp() {
    let (mut cpu, mut ram) = cpu_with(&[], 0x30000);
    cpu.regs.eip = 0x10000;
    cpu.regs.esp = 0x20004;
    ram.put(0x10000, &[0xe8, 0x0b, 0, 0, 0]);
    ram.put(0x10010, &[0xc3]);
    step(&mut cpu, &mut ram, true);
    assert_eq!((cpu.regs.eip, cpu.regs.esp), (0x10010, 0x20000));
    assert_eq!(&ram.bytes[0x20000..0x20004], &0x10005u32.to_le_bytes());
    step(&mut cpu, &mut ram, true);
    assert_eq!((cpu.regs.eip, cpu.regs.esp), (0x10005, 0x20004));
}

#[test]
fn stack_address_size_is_independent_of_operand_size() {
    let (mut cpu, mut ram) = cpu_with(&[], 0x30000);
    cpu.regs.eip = 0x18000;
    ram.put(0x18000, &[0x50, 0x5b, 0x66, 0x50, 0x66, 0x59]);
    cpu.regs.eax = 0x1234_5678;
    cpu.regs.esp = 0xaabb_0002;
    step(&mut cpu, &mut ram, false);
    assert_eq!(cpu.regs.esp, 0xaabb_fffe);
    assert_eq!(&ram.bytes[0xfffe..0x10000], &[0x78, 0x56]);
    // SP arithmetic wraps at 16 bits, but bytes within one operand stay
    // contiguous in this flat, unconstrained segment.
    assert_eq!(&ram.bytes[0x10000..0x10002], &[0x34, 0x12]);
    assert_eq!(&ram.bytes[0..2], &[0, 0]);
    step(&mut cpu, &mut ram, false);
    assert_eq!((cpu.regs.ebx, cpu.regs.esp), (0x1234_5678, 0xaabb_0002));
    cpu.regs.esp = 0x20002;
    step(&mut cpu, &mut ram, true);
    assert_eq!(cpu.regs.esp, 0x20000);
    assert_eq!(&ram.bytes[0x20000..0x20002], &[0x78, 0x56]);
    step(&mut cpu, &mut ram, true);
    assert_eq!((cpu.regs.cx(), cpu.regs.esp), (0x5678, 0x20002));
}

#[test]
fn operand_16_near_jump_clears_upper_eip() {
    let (mut cpu, mut ram) = cpu_with(&[], 0x30000);
    cpu.regs.eip = 0x10000;
    ram.put(0x10000, &[0x66, 0xe9, 0x1c, 0x00]);
    step(&mut cpu, &mut ram, true);
    assert_eq!(cpu.regs.eip, 0x20);
}

#[test]
fn address_override_uses_16_bit_data_offsets_in_32_bit_code() {
    let (mut cpu, mut ram) = cpu_with(&[0x67, 0xa1, 0x00, 0x20], 0x30000);
    ram.put(0x2000, &[0x78, 0x56, 0x34, 0x12]);
    step(&mut cpu, &mut ram, true);
    assert_eq!(cpu.regs.eax, 0x1234_5678);
    assert_eq!(cpu.regs.eip, 4);
}

#[test]
fn rep_in_32_bit_code_updates_full_count_and_indices() {
    let (mut cpu, mut ram) = cpu_with(&[0xf3, 0xa5], 0x40000);
    cpu.regs.esi = 0x10000;
    cpu.regs.edi = 0x20000;
    cpu.regs.ecx = 2;
    ram.put(0x10000, &[1, 2, 3, 4, 5, 6, 7, 8]);
    step(&mut cpu, &mut ram, true);
    assert_eq!((cpu.regs.esi, cpu.regs.edi, cpu.regs.ecx), (0x10008, 0x20008, 0));
    assert_eq!(&ram.bytes[0x20000..0x20008], &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn decoder_keeps_x87_fop_separate_from_prefixes() {
    let (_, mut ram) = cpu_with(&[0x66, 0x2e, 0xd9, 0xc3], 0x100);
    let mut system = CpuSystem::reset();
    let resolver = RealModeSegments;
    let mut bus = CpuMemoryAccess::new(
        &mut ram,
        &resolver,
        &mut system,
        AccessSite { opcode: 0, ip: 0, eflags: 2 },
    );
    let decoded = crate::x86_decode::decode(&mut bus, 0, 0).unwrap();
    assert_eq!(decoded.x87_opcode, Some(0x1c3));
    assert_eq!(decoded.next_ip, 4);
}

#[test]
fn pop_memory_uses_incremented_esp_and_rejected_write_does_not_commit_it() {
    let (mut cpu, mut ram) = cpu_with(&[0x8f, 0x04, 0x24], 0x30000); // pop [esp]
    cpu.regs.esp = 0x20000;
    ram.put(0x20000, &[0x78, 0x56, 0x34, 0x12]);
    let before = cpu.regs.clone();
    ram.reject_write_at(0x20007);
    assert!(matches!(cpu.step_with_context(&mut ram, &mut NoPorts, &FlatSegments { stack32: true }), Err(CpuError::Memory(_))));
    assert_eq!(cpu.regs, before);
    assert_eq!(&ram.bytes[0x20004..0x20008], &[0; 4]);
    ram.rejected_write = None;
    step(&mut cpu, &mut ram, true);
    assert_eq!(cpu.regs.esp, 0x20004);
    assert_eq!(&ram.bytes[0x20004..0x20008], &[0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn incomplete_far_return_or_iret_frame_preserves_all_registers() {
    for opcode in [0xcb, 0xcf] {
        let (mut cpu, mut ram) = cpu_with(&[opcode], 0x30000);
        cpu.regs.esp = 0x2fffc;
        ram.put(0x2fffc, &0x12345u32.to_le_bytes());
        let before = cpu.regs.clone();
        assert!(matches!(cpu.step_with_context(&mut ram, &mut NoPorts, &FlatSegments { stack32: true }), Err(CpuError::Memory(_))));
        assert_eq!(cpu.regs, before);
    }
}

#[test]
fn failed_leave_read_keeps_original_stack_and_frame_pointers() {
    let (mut cpu, mut ram) = cpu_with(&[0xc9], 0x30000);
    cpu.regs.esp = 0x20000;
    cpu.regs.ebp = 0x30000;
    let before = cpu.regs.clone();
    assert!(matches!(cpu.step_with_context(&mut ram, &mut NoPorts, &FlatSegments { stack32: true }), Err(CpuError::Memory(_))));
    assert_eq!(cpu.regs, before);
}

use super::*;

#[test]
fn firmware_vectors_resolve_to_registered_iret_entries() {
    let mut memory = Memory::new().unwrap();
    install_service_entries(&mut memory).unwrap();
    for &vector in SERVICE_VECTORS {
        let base = PhysAddr(u32::from(vector) * 4);
        let offset = memory.read_u16(base).unwrap();
        let segment = memory.read_u16(PhysAddr(base.0 + 2)).unwrap();
        assert_eq!(service_vector(segment, offset), Some(vector));
        assert_eq!(service_vector(segment + 1, offset - 16), Some(vector));
        assert_eq!(memory.read_u8(real_address(segment, offset)).unwrap(), 0xcf);
    }
    assert_eq!(memory.read_u32(PhysAddr(0x1d * 4)).unwrap(), 0);
    assert_eq!(service_vector(0x1000, entry_offset(0x21)), None);
    assert_eq!(service_vector(ROM_SEGMENT, entry_offset(0x21) + 1), None);
}

#[test]
fn return_status_preserves_interrupt_and_trap_flags_across_stack_wrap() {
    let mut memory = Memory::new().unwrap();
    let mut regs = Registers::default();
    regs.ss = 0x1000;
    regs.set_sp(0xfffb);
    memory.write_u8(stack_address(&regs, 4), 0x02).unwrap();
    memory.write_u8(stack_address(&regs, 5), 0x03).unwrap();
    regs.eflags = 0x0043;
    store_service_return_flags(&mut memory, &regs).unwrap();
    assert_eq!(memory.read_u8(real_address(0x1000, 0xffff)).unwrap(), 0x43);
    assert_eq!(memory.read_u8(real_address(0x1000, 0)).unwrap(), 0x03);
}

#[test]
fn guest_replaced_ivt_entry_is_used_by_interrupt_entry() {
    let mut memory = Memory::new().unwrap();
    install_service_entries(&mut memory).unwrap();
    memory.write(PhysAddr(0x21 * 4), &[0x34, 0x12, 0x00, 0x20]).unwrap();
    let mut regs = Registers::default();
    regs.ss = 0x1000;
    regs.set_sp(0x100);
    let mut cpu = Cpu::new(regs);
    enter_interrupt(&mut cpu, &mut memory, 0x21).unwrap();
    assert_eq!((cpu.regs.cs, cpu.regs.ip()), (0x2000, 0x1234));
    assert_eq!(service_vector(cpu.regs.cs, cpu.regs.ip()), None);
}

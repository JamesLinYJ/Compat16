use super::{execute_bit, execute_bit_scan, execute_double_shift};
use crate::x86_decode::{NormalizedInstruction, decode};
use crate::memory_access::{AccessSite, CpuMemoryAccess};
use crate::system::CpuSystem;
use crate::{CF, CpuError, OF, PF, RealModeSegments, ZF};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

struct Ram {
    bytes: Vec<u8>,
    rejected_write: Option<u32>,
}

impl Ram {
    fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
            rejected_write: None,
        }
    }

    fn put(&mut self, address: usize, bytes: &[u8]) {
        self.bytes[address..address + bytes.len()].copy_from_slice(bytes);
    }
}

impl GuestMemory for Ram {
    fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.validate_read(address, length)?;
        let end = address
            .0
            .checked_add(length as u32)
            .ok_or(MemoryError::AddressOverflow)?;
        if let Some(rejected) = self.rejected_write {
            if address.0 <= rejected && rejected < end {
                return Err(MemoryError::ReadOnly {
                    address: rejected,
                    length: 1,
                });
            }
        }
        Ok(())
    }

    fn read(&self, address: PhysAddr, output: &mut [u8]) -> Result<(), MemoryError> {
        self.validate_read(address, output.len())?;
        let start = address.0 as usize;
        output.copy_from_slice(&self.bytes[start..start + output.len()]);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, input: &[u8]) -> Result<(), MemoryError> {
        self.validate_write(address, input.len())?;
        let start = address.0 as usize;
        self.bytes[start..start + input.len()].copy_from_slice(input);
        Ok(())
    }
}

fn instruction(code: &[u8], ram: &mut Ram) -> NormalizedInstruction {
    ram.put(0, code);
    let decoded = with_bus(ram, 2, 0, |bus| decode(bus, 0, 0).unwrap());
    NormalizedInstruction::new(decoded)
}

fn with_bus<T>(
    memory: &mut Ram,
    eflags: u32,
    ip: u32,
    operation: impl FnOnce(&mut CpuMemoryAccess<'_, Ram, RealModeSegments>) -> T,
) -> T {
    let mut system = CpuSystem::reset();
    let resolver = RealModeSegments;
    let mut bus = CpuMemoryAccess::new(
        memory,
        &resolver,
        &mut system,
        AccessSite { opcode: 0, ip, eflags },
    );
    operation(&mut bus)
}

fn run_bit(regs: &mut Registers, ram: &mut Ram, instruction: &NormalizedInstruction) -> Result<(), CpuError> {
    with_bus(ram, regs.eflags, instruction.decoded.start_ip, |bus| {
        execute_bit(regs, bus, instruction)
    })
}

fn run_bit_scan(regs: &mut Registers, ram: &mut Ram, instruction: &NormalizedInstruction) -> Result<(), CpuError> {
    with_bus(ram, regs.eflags, instruction.decoded.start_ip, |bus| {
        execute_bit_scan(regs, bus, instruction)
    })
}

fn run_double_shift(regs: &mut Registers, ram: &mut Ram, instruction: &NormalizedInstruction) -> Result<(), CpuError> {
    with_bus(ram, regs.eflags, instruction.decoded.start_ip, |bus| {
        execute_double_shift(regs, bus, instruction)
    })
}

#[test]
fn register_bit_offset_wraps_modulo_register_width_and_only_changes_cf() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_ax(0x0001);
    regs.set_cx(16);
    regs.eflags = 2 | CF | PF | OF;
    let decoded = instruction(&[0x0f, 0xa3, 0xc8], &mut ram); // BT AX,CX

    run_bit(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.eflags & (CF | PF | OF), CF | PF | OF);
}

#[test]
fn negative_register_bit_offset_selects_the_previous_memory_element() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_bx(0x20);
    regs.set_cx(u16::MAX); // Signed -1 selects bit 15 in the preceding word.
    ram.put(0x1e, &0x8001_u16.to_le_bytes());
    let decoded = instruction(&[0x0f, 0xb3, 0x0f], &mut ram); // BTR word [BX],CX

    run_bit(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(u16::from_le_bytes([ram.bytes[0x1e], ram.bytes[0x1f]]), 1);
    assert_ne!(regs.eflags & CF, 0);
}

#[test]
fn negative_register_bit_offset_uses_address_size_override_for_32_bit_memory() {
    let mut ram = Ram::new(0x20000);
    let mut regs = Registers::default();
    regs.ebx = 0x1_0000;
    regs.ecx = u32::MAX;
    // The signed bit displacement selects the preceding dword, within 64 KiB.
    ram.put(0xfffc, &0x8000_0001_u32.to_le_bytes());
    let decoded = instruction(&[0x66, 0x67, 0x0f, 0xb3, 0x0b], &mut ram); // BTR dword [EBX],ECX

    run_bit(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(
        u32::from_le_bytes(ram.bytes[0xfffc..0x1_0000].try_into().unwrap()),
        1
    );
    assert_ne!(regs.eflags & CF, 0);
}

#[test]
fn immediate_bit_modify_uses_element_width_and_preserves_other_flags() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_bx(0x20);
    regs.eflags = 2 | CF | PF | OF;
    ram.put(0x20, &1_u16.to_le_bytes());
    let decoded = instruction(&[0x0f, 0xba, 0x2f, 7], &mut ram); // BTS word [BX],7

    run_bit(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(u16::from_le_bytes([ram.bytes[0x20], ram.bytes[0x21]]), 0x81);
    assert_eq!(regs.eflags & (CF | PF | OF), PF | OF);
}

#[test]
fn rejected_bit_modify_write_leaves_flags_registers_and_memory_unchanged() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_bx(0x20);
    regs.set_cx(0);
    regs.eflags = 2 | CF | PF;
    ram.put(0x20, &0x1234_u16.to_le_bytes());
    ram.rejected_write = Some(0x21);
    let before_regs = regs.clone();
    let decoded = instruction(&[0x0f, 0xab, 0x0f], &mut ram); // BTS word [BX],CX

    assert!(run_bit(&mut regs, &mut ram, &decoded).is_err());

    assert_eq!(regs, before_regs);
    assert_eq!(&ram.bytes[0x20..0x22], &0x1234_u16.to_le_bytes());
}

#[test]
fn bit_scans_leave_destination_undefined_value_untouched_for_zero_source() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_ax(0x4567);
    regs.set_cx(0);
    regs.eflags = 2 | CF | OF;
    let decoded = instruction(&[0x0f, 0xbc, 0xc1], &mut ram); // BSF AX,CX

    run_bit_scan(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(regs.ax(), 0x4567);
    assert_ne!(regs.eflags & ZF, 0);
    assert_eq!(regs.eflags & (CF | OF), CF | OF);
}

#[test]
fn bsr_with_operand_size_override_writes_a_32_bit_index() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.ecx = 0x8000_0000;
    let decoded = instruction(&[0x66, 0x0f, 0xbd, 0xc1], &mut ram); // BSR EAX,ECX

    run_bit_scan(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(regs.eax, 31);
    assert_eq!(regs.eflags & ZF, 0);
}

#[test]
fn shld_uses_the_source_word_and_preserves_undefined_overflow_for_multi_bit_count() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_ax(0x1234);
    regs.set_cx(0xabcd);
    regs.eflags = 2 | OF;
    let decoded = instruction(&[0x0f, 0xa4, 0xc8, 4], &mut ram); // SHLD AX,CX,4

    run_double_shift(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(regs.ax(), 0x234a);
    assert_ne!(regs.eflags & CF, 0);
    assert_ne!(regs.eflags & OF, 0);
}

#[test]
fn zero_count_double_shift_changes_neither_destination_nor_flags() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_ax(0x1234);
    regs.set_cx(0xabcd);
    regs.eflags = 2 | CF | OF | ZF;
    let decoded = instruction(&[0x0f, 0xa4, 0xc8, 0], &mut ram); // SHLD AX,CX,0
    let before_flags = regs.eflags;

    run_double_shift(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(regs.ax(), 0x1234);
    assert_eq!(regs.eflags, before_flags);
}

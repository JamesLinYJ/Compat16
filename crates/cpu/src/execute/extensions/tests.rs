use super::{execute_cmov, execute_cmpxchg8b, execute_xadd, execute_xlat};
use crate::x86_decode::{NormalizedInstruction, decode};
use crate::memory_access::{AccessSite, CpuMemoryAccess};
use crate::system::CpuSystem;
use crate::{CF, CpuError, OF, RealModeSegments, ZF};
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

fn run_cmov(regs: &mut Registers, ram: &mut Ram, instruction: &NormalizedInstruction) -> Result<(), CpuError> {
    with_bus(ram, regs.eflags, instruction.decoded.start_ip, |bus| {
        execute_cmov(regs, bus, instruction)
    })
}

fn run_xadd(regs: &mut Registers, ram: &mut Ram, instruction: &NormalizedInstruction) -> Result<(), CpuError> {
    with_bus(ram, regs.eflags, instruction.decoded.start_ip, |bus| {
        execute_xadd(regs, bus, instruction)
    })
}

fn run_xlat(regs: &mut Registers, ram: &mut Ram, instruction: &NormalizedInstruction) -> Result<(), CpuError> {
    with_bus(ram, regs.eflags, instruction.decoded.start_ip, |bus| {
        execute_xlat(regs, bus, instruction)
    })
}

fn run_cmpxchg8b(regs: &mut Registers, ram: &mut Ram, instruction: &NormalizedInstruction) -> Result<(), CpuError> {
    with_bus(ram, regs.eflags, instruction.decoded.start_ip, |bus| {
        execute_cmpxchg8b(regs, bus, instruction)
    })
}

#[test]
fn xadd_exchanges_the_old_destination_and_sets_add_flags() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_ax(0xffff);
    regs.set_cx(1);
    regs.eflags = 2 | OF;
    let decoded = instruction(&[0x0f, 0xc1, 0xc8], &mut ram); // XADD AX,CX

    run_xadd(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!((regs.ax(), regs.cx()), (0, 0xffff));
    assert_eq!(regs.eflags & (CF | ZF | OF), CF | ZF);
}

#[test]
fn xadd_same_register_retains_the_sum() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_ax(0x1234);
    let decoded = instruction(&[0x0f, 0xc1, 0xc0], &mut ram); // XADD AX,AX

    run_xadd(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(regs.ax(), 0x2468);
}

#[test]
fn xlat_uses_segment_override_and_does_not_change_flags() {
    let mut ram = Ram::new(0x20000);
    let mut regs = Registers::default();
    regs.fs = 0x200;
    regs.set_bx(0x20);
    regs.set_al(3);
    regs.eflags = 2 | CF | OF;
    ram.bytes[0x2023] = 0xa7;
    let decoded = instruction(&[0x64, 0xd7], &mut ram); // XLAT using FS override

    run_xlat(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(regs.al(), 0xa7);
    assert_eq!(regs.eflags, 2 | CF | OF);
}

#[test]
fn address_size_override_xlat_uses_ebx_and_wraps_at_32_bits() {
    let mut ram = Ram::new(0x30000);
    let mut regs = Registers::default();
    regs.ebx = 0x1_0020;
    regs.set_al(3);
    ram.bytes[0x1_0023] = 0x5c;
    let decoded = instruction(&[0x67, 0xd7], &mut ram); // XLAT with 32-bit address size

    run_xlat(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(regs.al(), 0x5c);
}

#[test]
fn cmov_moves_only_when_true_and_preserves_flags() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.set_ax(0x1111);
    regs.set_cx(0x2222);
    regs.eflags = 2 | ZF | CF;
    let decoded = instruction(&[0x0f, 0x44, 0xc1], &mut ram); // CMOVE AX,CX

    run_cmov(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(regs.ax(), 0x2222);
    assert_eq!(regs.eflags, 2 | ZF | CF);
}

#[test]
fn cmov_reads_memory_even_when_condition_is_false() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    regs.ds = 0x1000;
    regs.set_ax(0x1111);
    regs.eflags = 2 | ZF;
    let before = regs.clone();
    let decoded = instruction(&[0x0f, 0x45, 0x06, 0x00, 0x00], &mut ram); // CMOVNE AX,[0000]

    assert!(run_cmov(&mut regs, &mut ram, &decoded).is_err());

    assert_eq!(regs, before);
}

fn cmpxchg8b_instruction(ram: &mut Ram) -> NormalizedInstruction {
    instruction(&[0x0f, 0xc7, 0x0e, 0x40, 0x00], ram) // CMPXCHG8B [0040]
}

#[test]
fn cmpxchg8b_success_stores_ecx_ebx_pair_and_sets_zf() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    let old = 0x5566_7788_1122_3344_u64;
    ram.put(0x40, &old.to_le_bytes());
    regs.eax = old as u32;
    regs.edx = (old >> 32) as u32;
    regs.ebx = 0xaabb_ccdd;
    regs.ecx = 0xeeff_0011;
    regs.eflags = 2 | CF | OF;
    let decoded = cmpxchg8b_instruction(&mut ram);

    run_cmpxchg8b(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!(
        u64::from_le_bytes(ram.bytes[0x40..0x48].try_into().unwrap()),
        0xeeff_0011_aabb_ccdd
    );
    assert_eq!(regs.eflags, 2 | CF | OF | ZF);
}

#[test]
fn cmpxchg8b_failure_loads_memory_pair_and_clears_zf() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    let old = 0x0102_0304_0506_0708_u64;
    ram.put(0x40, &old.to_le_bytes());
    regs.eax = 0;
    regs.edx = 0;
    regs.eflags = 2 | ZF | CF;
    let decoded = cmpxchg8b_instruction(&mut ram);

    run_cmpxchg8b(&mut regs, &mut ram, &decoded).unwrap();

    assert_eq!((regs.edx, regs.eax), ((old >> 32) as u32, old as u32));
    assert_eq!(
        u64::from_le_bytes(ram.bytes[0x40..0x48].try_into().unwrap()),
        old
    );
    assert_eq!(regs.eflags & (ZF | CF), CF);
}

#[test]
fn cmpxchg8b_write_fault_leaves_memory_registers_and_flags_unchanged() {
    let mut ram = Ram::new(0x10000);
    let mut regs = Registers::default();
    let old = 0x5566_7788_1122_3344_u64;
    ram.put(0x40, &old.to_le_bytes());
    regs.eax = old as u32;
    regs.edx = (old >> 32) as u32;
    regs.ebx = 0xaabb_ccdd;
    regs.ecx = 0xeeff_0011;
    regs.eflags = 2 | CF;
    ram.rejected_write = Some(0x46);
    let before = regs.clone();
    let decoded = cmpxchg8b_instruction(&mut ram);

    assert!(run_cmpxchg8b(&mut regs, &mut ram, &decoded).is_err());

    assert_eq!(regs, before);
    assert_eq!(&ram.bytes[0x40..0x48], &old.to_le_bytes());
}

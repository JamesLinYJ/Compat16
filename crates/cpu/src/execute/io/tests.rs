use super::execute;
use crate::memory_access::{AccessSite, CpuMemoryAccess};
use crate::system::CpuSystem;
use crate::{CpuError, DF, RealModeSegments, x86_decode};
use guest_core::io::{PortError, PortIo, PortWidth};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

struct Ram(Vec<u8>);
impl GuestMemory for Ram {
    fn len(&self) -> u32 { self.0.len() as u32 }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.validate_read(address, bytes.len())?;
        bytes.copy_from_slice(&self.0[address.0 as usize..address.0 as usize + bytes.len()]);
        Ok(())
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.validate_write(address, bytes.len())?;
        self.0[address.0 as usize..address.0 as usize + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Default)]
struct Bus { reads: Vec<(u16, PortWidth)>, writes: Vec<(u16, PortWidth, u32)>, reject: bool }
impl PortIo for Bus {
    fn read(&mut self, port: u16, width: PortWidth) -> Result<u32, PortError> {
        if self.reject { return Err(PortError::Unsupported { port, width, write: false }); }
        self.reads.push((port, width));
        Ok(0x8765_4321)
    }
    fn write(&mut self, port: u16, width: PortWidth, value: u32) -> Result<(), PortError> {
        if self.reject { return Err(PortError::Unsupported { port, width, write: true }); }
        self.writes.push((port, width, value));
        Ok(())
    }
}

fn run(code: &[u8], regs: &mut Registers, memory: &mut Ram, ports: &mut Bus) -> Result<Option<u32>, CpuError> {
    memory.0[..code.len()].copy_from_slice(code);
    let mut system = CpuSystem::reset();
    let resolver = RealModeSegments;
    let mut memory_bus = CpuMemoryAccess::new(
        memory,
        &resolver,
        &mut system,
        AccessSite { opcode: 0, ip: 0, eflags: regs.eflags },
    );
    let decoded = x86_decode::decode(&mut memory_bus, 0, 0)?;
    execute(regs, &mut memory_bus, ports, decoded)
}

#[test]
fn scalar_in_out_preserve_width_port_and_flags() {
    let mut memory = Ram(vec![0; 0x20000]);
    let mut regs = Registers::default();
    let mut ports = Bus::default();
    regs.eflags = 0x8d7;
    regs.eax = 0xaabb_ccdd;
    run(&[0xe4, 0x80], &mut regs, &mut memory, &mut ports).unwrap();
    assert_eq!(regs.eax, 0xaabb_cc21);
    assert_eq!(ports.reads, [(0x80, PortWidth::Byte)]);
    regs.set_dx(0x3f8);
    run(&[0x66, 0xed], &mut regs, &mut memory, &mut ports).unwrap();
    assert_eq!(regs.eax, 0x8765_4321);
    run(&[0xe7, 0x40], &mut regs, &mut memory, &mut ports).unwrap();
    run(&[0x66, 0xef], &mut regs, &mut memory, &mut ports).unwrap();
    assert_eq!(ports.writes, [(0x40, PortWidth::Word, 0x4321), (0x3f8, PortWidth::Dword, 0x8765_4321)]);
    assert_eq!(regs.eflags, 0x8d7);
}

#[test]
fn rep_insw_segment_limit_faults_without_io_and_zero_count_has_no_bus_transaction() {
    let mut memory = Ram(vec![0; 0x20000]);
    let mut regs = Registers::default();
    let mut ports = Bus::default();
    regs.es = 0x1000;
    regs.set_di(0xffff);
    regs.set_cx(2);
    regs.set_dx(0x40);
    let before = regs.clone();

    // Intel Vol. 2B's real-address memory-operand limit requires this full
    // word span to fit below 10000h; INS faults before consuming device input.
    assert_eq!(
        run(&[0xf3, 0x6d], &mut regs, &mut memory, &mut ports).unwrap_err(),
        CpuError::GeneralProtectionFault { error_code: 0, ip: 0 },
    );
    assert_eq!(regs, before);
    assert!(ports.reads.is_empty());

    regs.set_cx(0);
    let zero_count_regs = regs.clone();
    assert_eq!(run(&[0xf3, 0x6d], &mut regs, &mut memory, &mut ports).unwrap(), Some(2));
    assert_eq!(regs, zero_count_regs);
    assert!(ports.reads.is_empty());
}

#[test]
fn outs_uses_segment_override_address32_and_direction() {
    let mut memory = Ram(vec![0; 0x20000]);
    let mut regs = Registers::default();
    let mut ports = Bus::default();
    regs.fs = 0x100;
    regs.esi = 0x20;
    regs.ecx = 2;
    regs.set_dx(0x80);
    regs.eflags = DF;
    memory.0[0x1020] = 0xaa;
    memory.0[0x101f] = 0xbb;
    run(&[0x64, 0x67, 0xf3, 0x6e], &mut regs, &mut memory, &mut ports).unwrap();
    assert_eq!(ports.writes, [(0x80, PortWidth::Byte, 0xaa), (0x80, PortWidth::Byte, 0xbb)]);
    assert_eq!((regs.esi, regs.ecx), (0x1e, 0));
}

#[test]
fn invalid_ins_buffer_and_failed_bus_leave_registers_unchanged() {
    let mut memory = Ram(vec![0; 0x100]);
    let mut regs = Registers::default();
    let mut ports = Bus::default();
    regs.set_di(0xff);
    regs.set_cx(1);
    let before = regs.clone();
    assert!(matches!(run(&[0xf3, 0x6d], &mut regs, &mut memory, &mut ports), Err(CpuError::Memory(_))));
    assert_eq!(regs, before);
    assert!(ports.reads.is_empty());
    ports.reject = true;
    assert!(matches!(run(&[0xe4, 0x80], &mut regs, &mut memory, &mut ports), Err(CpuError::Io(_))));
    assert_eq!(regs, before);
}

#[test]
fn long_rep_yields_and_retains_remaining_count() {
    let mut memory = Ram(vec![0; 0x20000]);
    let mut regs = Registers::default();
    let mut ports = Bus::default();
    regs.es = 0x1000;
    regs.set_cx(4097);
    assert_eq!(run(&[0xf3, 0x6c], &mut regs, &mut memory, &mut ports).unwrap(), Some(0));
    assert_eq!((regs.cx(), regs.di()), (1, 4096));
    assert_eq!(ports.reads.len(), 4096);
    assert_eq!(run(&[0xf3, 0x6c], &mut regs, &mut memory, &mut ports).unwrap(), Some(2));
    assert_eq!((regs.cx(), regs.di()), (0, 4097));
}

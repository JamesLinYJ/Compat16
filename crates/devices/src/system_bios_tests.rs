use super::dispatch;
use crate::BiosDevices;
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

struct Memory(Vec<u8>);

impl Memory {
    fn new() -> Self { Self(vec![0; 0x12_0000]) }
}

impl GuestMemory for Memory {
    fn len(&self) -> u32 { self.0.len() as u32 }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let source = self.0.get(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        bytes.copy_from_slice(source);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let target = self.0.get_mut(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        target.copy_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn e801_absence_returns_unsupported_status_without_memory_sizes() {
    let devices = BiosDevices::new();
    let memory = Memory::new();
    let mut regs = Registers::default();
    regs.set_ax(0xe801);
    regs.set_cx(0x1234);
    regs.set_dx(0x5678);

    dispatch(&devices, 0x15, &mut regs, &memory).unwrap();

    assert_eq!(regs.ah(), 0x86);
    assert!(regs.carry());
    assert_eq!(regs.cx(), 0x1234);
    assert_eq!(regs.dx(), 0x5678);
}

#[test]
fn e820_absence_returns_failure_without_smap_or_guest_buffer_write() {
    let devices = BiosDevices::new();
    let mut memory = Memory::new();
    let entry_address = 0x50000;
    memory.0[entry_address..entry_address + 24].fill(0xa5);
    let mut regs = Registers::default();
    regs.eax = 0xe820;
    regs.edx = 0x534d_4150;
    regs.ecx = 24;
    regs.es = 0x5000;
    regs.edi = 0;

    dispatch(&devices, 0x15, &mut regs, &memory).unwrap();

    assert_eq!(regs.ah(), 0x86);
    assert!(regs.carry());
    assert_ne!(regs.eax, 0x534d_4150);
    assert_eq!(&memory.0[entry_address..entry_address + 24], &[0xa5; 24]);
}

#[test]
fn ah88_remains_a_supported_extended_memory_size_query() {
    let devices = BiosDevices::new();
    let memory = Memory::new();
    let mut regs = Registers::default();
    regs.set_ah(0x88);

    dispatch(&devices, 0x15, &mut regs, &memory).unwrap();

    assert_eq!(regs.ax(), 0x0080);
    assert!(!regs.carry());
}

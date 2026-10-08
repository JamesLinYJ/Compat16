use std::convert::TryFrom;

use crate::{XmsConfig, XmsService};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

pub(super) use crate::model::KIB;
pub(super) use guest_core::real_address;

pub(super) struct TestMemory {
    pub(super) bytes: Vec<u8>,
    pub(super) fail_writes: bool,
}

impl TestMemory {
    pub(super) fn new() -> Self {
        Self::with_len(0x0020_0000)
    }

    pub(super) fn with_len(length: usize) -> Self {
        Self {
            bytes: vec![0xcc; length],
            fail_writes: false,
        }
    }
}

impl GuestMemory for TestMemory {
    fn len(&self) -> u32 {
        u32::try_from(self.bytes.len()).expect("test memory length fits u32")
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        let len = u32::try_from(bytes.len()).map_err(|_| MemoryError::AddressOverflow)?;
        let end = address
            .0
            .checked_add(len)
            .ok_or(MemoryError::AddressOverflow)?;
        if end > self.len() {
            return Err(MemoryError::OutOfBounds {
                address: address.0,
                length: bytes.len(),
            });
        }
        bytes.copy_from_slice(&self.bytes[address.0 as usize..end as usize]);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        let len = u32::try_from(bytes.len()).map_err(|_| MemoryError::AddressOverflow)?;
        let end = address
            .0
            .checked_add(len)
            .ok_or(MemoryError::AddressOverflow)?;
        if end > self.len() {
            return Err(MemoryError::OutOfBounds {
                address: address.0,
                length: bytes.len(),
            });
        }
        if self.fail_writes {
            return Err(MemoryError::ReadOnly {
                address: address.0,
                length: bytes.len(),
            });
        }
        self.bytes[address.0 as usize..end as usize].copy_from_slice(bytes);
        Ok(())
    }
}

pub(super) fn fixture() -> (XmsService, TestMemory) {
    let config = XmsConfig {
        arena_start: PhysAddr(0x0011_0000),
        arena_end: PhysAddr(0x0011_1000),
    };
    (XmsService::with_config(config).unwrap(), TestMemory::new())
}

pub(super) fn far_pointer(segment: u16, offset: u16) -> u32 {
    (u32::from(segment) << 16) | u32::from(offset)
}

pub(super) fn call_registers(function: u8) -> Registers {
    let mut regs = Registers::default();
    regs.set_ah(function);
    regs
}

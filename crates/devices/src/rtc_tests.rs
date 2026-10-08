use super::RtcState;
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

struct Memory(Vec<u8>);

impl Memory {
    fn new() -> Self { Self(vec![0; 0x10_0000]) }
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
fn absent_pci_bios_returns_pci_not_supported_status_without_a_signature() {
    let bda_ticks = 0x0400 + 0x6c;
    for ax in [0xb101, 0xb102] {
        let mut rtc = RtcState::new();
        let mut memory = Memory::new();
        memory.0[bda_ticks..bda_ticks + 5].fill(0xa5);
        let mut regs = Registers::default();
        regs.set_ax(ax);
        regs.edx = 0xdead_beef;

        rtc.dispatch_int1a(&mut regs, &mut memory, 86_400).unwrap();

        assert_eq!(regs.ah(), 0x81);
        assert!(regs.carry());
        assert_eq!(regs.edx, 0xdead_beef);
        assert_eq!(&memory.0[bda_ticks..bda_ticks + 5], &[0xa5; 5]);
        assert_eq!(rtc.last_day, None);
    }
}

#[test]
fn unsupported_clock_function_returns_bios_failure_without_clock_side_effects() {
    let bda_ticks = 0x0400 + 0x6c;
    let mut rtc = RtcState::new();
    let mut memory = Memory::new();
    memory.0[bda_ticks..bda_ticks + 5].fill(0xa5);
    let mut regs = Registers::default();
    regs.set_ah(0x01);

    rtc.dispatch_int1a(&mut regs, &mut memory, 86_400).unwrap();

    assert_eq!(regs.ah(), 0x86);
    assert!(regs.carry());
    assert_eq!(&memory.0[bda_ticks..bda_ticks + 5], &[0xa5; 5]);
    assert_eq!(rtc.last_day, None);
}

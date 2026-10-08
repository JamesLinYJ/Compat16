use super::{BiosKeyboard, KeyStroke};
use crate::{DeviceError, DispatchOutcome};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

struct Memory(Vec<u8>);

impl GuestMemory for Memory {
    fn len(&self) -> u32 { self.0.len() as u32 }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        let start = address.0 as usize;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let source = self.0.get(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        bytes.copy_from_slice(source);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        let start = address.0 as usize;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let destination = self.0.get_mut(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        destination.copy_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn extended_shift_status_combines_tracked_and_bda_flags() {
    let mut keyboard = BiosKeyboard::new();
    keyboard.set_shift_flags(0b1010_0101);
    let mut memory = Memory(vec![0; 0x100000]);
    memory.0[0x418] = 0b1000_1101; // SysRq, left Ctrl, plus ignored/reserved bits.
    memory.0[0x496] = 0b0000_0100; // Right Ctrl.
    let mut regs = Registers::default();
    regs.set_ah(0x12);

    keyboard.dispatch_int16(&mut regs, &mut memory, &mut DispatchOutcome::default()).unwrap();

    assert_eq!(regs.ax(), 0b1000_0101_1010_0101);
    assert_eq!(memory.0[0x417], 0b1010_0101);
}

#[test]
fn keyboard_functionality_query_reports_no_typematic_controls() {
    let mut keyboard = BiosKeyboard::new();
    let mut memory = Memory(vec![0; 0x100000]);
    let mut regs = Registers::default();
    regs.set_ah(0x09);

    keyboard.dispatch_int16(&mut regs, &mut memory, &mut DispatchOutcome::default()).unwrap();

    assert_eq!(regs.al(), 0x20);
}

#[test]
fn unsupported_keyboard_id_query_leaves_registers_unchanged() {
    let mut keyboard = BiosKeyboard::new();
    let mut memory = Memory(vec![0; 0x100000]);
    let mut regs = Registers::default();
    regs.set_ah(0x0a);
    regs.set_bx(0x8383);
    regs.eflags = 1;
    let before = regs.clone();

    keyboard.dispatch_int16(&mut regs, &mut memory, &mut DispatchOutcome::default()).unwrap();

    assert_eq!(regs, before);
}

#[test]
fn extended_shift_status_propagates_a_real_guest_memory_error() {
    let mut keyboard = BiosKeyboard::new();
    let mut memory = Memory(vec![0; 0x496]);
    let mut regs = Registers::default();
    regs.set_ah(0x12);

    let result = keyboard.dispatch_int16(&mut regs, &mut memory, &mut DispatchOutcome::default());

    assert!(matches!(
        result,
        Err(DeviceError::Memory(MemoryError::OutOfBounds { address: 0x496, length: 1 }))
    ));
}

#[test]
fn syncing_keyboard_state_mirrors_the_standard_shift_byte() {
    let mut keyboard = BiosKeyboard::new();
    keyboard.set_shift_flags(0x5a);
    assert!(keyboard.push(KeyStroke { ascii: b'Q', scan: 0x10 }));
    let mut memory = Memory(vec![0; 0x100000]);

    keyboard.sync_bda(&mut memory).unwrap();

    assert_eq!(memory.0[0x417], 0x5a);
}

#[test]
fn unclaimed_keyboard_extensions_preserve_registers_and_memory() {
    let mut keyboard = BiosKeyboard::new();
    let mut memory = Memory(vec![0xa5; 0x500]);
    for ax in [0x0300, 0x55fe, 0x5500, 0xabcd, 0xff00] {
        let mut regs = Registers::default();
        regs.set_ax(ax);
        regs.ebx = 0x1234_5678;
        regs.eflags = 0x0fd7;
        let before = regs.clone();
        let mut outcome = DispatchOutcome::default();
        keyboard.dispatch_int16(&mut regs, &mut memory, &mut outcome).unwrap();
        assert_eq!(regs, before);
        assert!(outcome.actions.is_empty());
        assert!(memory.0.iter().all(|&byte| byte == 0xa5));
    }
}

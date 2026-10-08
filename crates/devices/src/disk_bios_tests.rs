use super::dispatch;
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
fn absent_floppy_geometry_uses_zero_values_and_clear_carry() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut regs = Registers::default();
    regs.set_ah(0x08);
    regs.set_dl(0);
    regs.set_bx(0x1234);
    regs.es = 0x5678;
    regs.set_di(0x9abc);

    dispatch(&mut regs, &mut memory).unwrap();

    assert_eq!((regs.ax(), regs.bx(), regs.cx(), regs.dx()), (0, 0, 0, 0));
    assert_eq!((regs.es, regs.di()), (0, 0));
    assert!(!regs.carry());
}

#[test]
fn absent_fixed_disk_geometry_reports_failure_and_zero_geometry() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut regs = Registers::default();
    regs.set_ah(0x08);
    regs.set_dl(0x80);
    regs.set_cx(0xffff);
    regs.set_dx(0xffff);

    dispatch(&mut regs, &mut memory).unwrap();

    assert_eq!(regs.ah(), 0x01);
    assert_eq!((regs.cx(), regs.dx()), (0, 0));
    assert!(regs.carry());
}

#[test]
fn drive_type_reports_absence_without_fabricating_capacity() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut regs = Registers::default();
    regs.set_ah(0x15);
    regs.set_dl(0x80);
    regs.set_cx(0xffff);
    regs.set_dx(0xffff);

    dispatch(&mut regs, &mut memory).unwrap();

    assert_eq!((regs.ah(), regs.cx(), regs.dx()), (0, 0, 0));
    assert!(!regs.carry());
}

#[test]
fn failed_io_preserves_guest_buffer_and_reports_not_ready() {
    let mut memory = Memory(vec![0; 0x100000]);
    memory.0[0x5000..0x5200].fill(0xa5);
    let mut regs = Registers::default();
    regs.set_ah(0x02);
    regs.set_al(1);
    regs.set_dl(0);
    regs.es = 0x0500;
    regs.set_bx(0);

    dispatch(&mut regs, &mut memory).unwrap();

    assert_eq!((regs.ah(), regs.al()), (0x80, 0));
    assert!(regs.carry());
    assert_eq!(&memory.0[0x5000..0x5200], &[0xa5; 0x200]);
}

#[test]
fn absent_edd_check_keeps_input_signature_and_reports_unsupported() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut regs = Registers::default();
    regs.set_ah(0x41);
    regs.set_bx(0x55aa);
    regs.set_dl(0x80);

    dispatch(&mut regs, &mut memory).unwrap();

    assert_eq!((regs.ah(), regs.bx()), (0x01, 0x55aa));
    assert!(regs.carry());
}

#[test]
fn absent_reset_is_a_recoverable_not_ready_result() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut regs = Registers::default();
    regs.set_ah(0);
    regs.set_dl(0);

    dispatch(&mut regs, &mut memory).unwrap();

    assert_eq!(regs.ah(), 0x80);
    assert!(regs.carry());
}

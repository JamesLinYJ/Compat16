use super::*;
use crate::vga::VgaDevice;
use crate::DeviceError;
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

struct Memory(Vec<u8>);

impl Memory {
    fn new(size: usize) -> Self {
        Self(vec![0; size])
    }
}

impl GuestMemory for Memory {
    fn len(&self) -> u32 {
        self.0.len() as u32
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(MemoryError::AddressOverflow)?;
        let source = self.0.get(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        bytes.copy_from_slice(source);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(MemoryError::AddressOverflow)?;
        let target = self.0.get_mut(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        target.copy_from_slice(bytes);
        Ok(())
    }
}

fn controller_regs() -> Registers {
    let mut regs = Registers::default();
    regs.set_ax(0x4f00);
    regs.es = 0x2000;
    regs.set_di(0x0100);
    regs
}

fn mode_info_regs(mode: u16) -> Registers {
    let mut regs = Registers::default();
    regs.set_ax(0x4f01);
    regs.set_cx(mode);
    regs.es = 0x2000;
    regs.set_di(0x0100);
    regs
}

fn invoke(
    vga: &VgaDevice,
    regs: &mut Registers,
    memory: &mut Memory,
) -> Result<bool, DeviceError> {
    dispatch(vga, regs, memory)
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

#[test]
fn runtime_controller_info_exposes_only_the_six_implemented_modes() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    let mut regs = controller_regs();
    regs.eax = 0x1234_4f00;

    assert_eq!(invoke(&vga, &mut regs, &mut memory).unwrap(), true);
    assert_eq!(regs.ax(), 0x004f);
    assert_eq!(regs.eax >> 16, 0x1234);

    let block = &memory.0[0x20100..0x20200];
    assert_eq!(&block[0..4], b"VESA");
    assert_eq!(word(block, 4), 0x0102);
    assert_eq!((word(block, 8), word(block, 6)), (0x2014, 0));
    assert_eq!((word(block, 16), word(block, 14)), (0x2016, 0));
    assert_eq!(word(block, 18), 64);
    assert_eq!(&memory.0[0x20140..0x2014d], b"Emulated VGA\0");
    let expected_modes = [0x0101, 0x0103, 0x0105, 0x0111, 0x0114, 0x0117, 0xffff];
    for (index, expected) in expected_modes.into_iter().enumerate() {
        assert_eq!(word(&memory.0[0x20160..0x2016e], index * 2), expected);
    }
}

#[test]
fn runtime_controller_info_rejects_unrepresentable_embedded_far_pointers_atomically() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x12_0000);
    let mut regs = Registers::default();
    regs.set_ax(0x4f00);
    regs.es = 0xffff;
    regs.set_di(0xfff0);
    let before = memory.0.clone();

    invoke(&vga, &mut regs, &mut memory).unwrap();

    assert_eq!(regs.ax(), 0x014f);
    assert_eq!(memory.0, before);
}

#[test]
fn runtime_controller_info_memory_fault_is_not_converted_to_vbe_failure() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x201ff);
    let mut regs = controller_regs();

    assert!(matches!(invoke(&vga, &mut regs, &mut memory), Err(DeviceError::Memory(_))));
    assert_eq!(regs.ax(), 0x4f00);
}

#[test]
fn runtime_mode_info_reports_banked_8_bit_and_rgb565_layouts() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    let mut regs = mode_info_regs(0x0101);
    memory.0[0x20100..0x20200].fill(0xcc);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    let indexed = &memory.0[0x20100..0x20200];
    assert_eq!(regs.ax(), 0x004f);
    assert_eq!(word(indexed, 0), 0x001b);
    assert_eq!(indexed[2], 0x07);
    assert_eq!(indexed[3], 0);
    assert_eq!(word(indexed, 4), 64);
    assert_eq!(word(indexed, 6), 64);
    assert_eq!(word(indexed, 8), 0xa000);
    assert_eq!(word(indexed, 10), 0);
    assert_eq!(indexed[12..16], [0; 4]);
    assert_eq!(word(indexed, 16), 640);
    assert_eq!((word(indexed, 18), word(indexed, 20)), (640, 480));
    assert_eq!((indexed[24], indexed[25], indexed[26], indexed[27]), (1, 8, 1, 4));
    assert_eq!(indexed[29], 12);
    assert_eq!(indexed[30], 1);
    assert_eq!(indexed[31..40], [0; 9]);
    assert_eq!(indexed[40..].iter().filter(|byte| **byte != 0).count(), 0);

    let mut regs = mode_info_regs(0x0111);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    let direct = &memory.0[0x20100..0x20200];
    assert_eq!(regs.ax(), 0x004f);
    assert_eq!(word(direct, 0), 0x001b);
    assert_eq!(word(direct, 16), 1280);
    assert_eq!((word(direct, 18), word(direct, 20)), (640, 480));
    assert_eq!((direct[24], direct[25], direct[26], direct[27]), (1, 16, 1, 6));
    assert_eq!(direct[29], 5);
    assert_eq!(&direct[31..40], &[5, 11, 6, 5, 5, 0, 0, 0, 0]);
    assert_eq!(direct[40..].iter().filter(|byte| **byte != 0).count(), 0);
}

#[test]
fn runtime_unsupported_mode_info_preserves_the_buffer() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    memory.0[0x20100..0x20200].fill(0xa5);
    let mut regs = mode_info_regs(0x0118);

    invoke(&vga, &mut regs, &mut memory).unwrap();

    assert_eq!(regs.ax(), 0x014f);
    assert_eq!(&memory.0[0x20100..0x20200], &[0xa5; 256]);
}

#[test]
fn runtime_mode_set_query_and_invalid_flags_are_atomic() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    let mut regs = Registers::default();
    regs.set_ax(0x4f02);
    regs.set_bx(0x8101); // VBE no-clear request.
    {
        let mut state = vga.borrow_mut();
        state.vram[0x20_0000] = 0x6d;
    }
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x004f);
    assert_eq!(vga.borrow().svga.as_ref().unwrap().mode, 0x0101);
    assert!(vga.borrow().svga.as_ref().unwrap().preserve_memory);
    assert_eq!(vga.borrow().vram[0x20_0000], 0x6d);

    regs.set_ax(0x4f03);
    regs.set_bx(0);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x004f);
    assert_eq!(regs.bx(), 0x8101);

    let before_state = vga.borrow().clone();
    regs.set_ax(0x4f02);
    regs.set_bx(0x4101); // Unsupported linear-framebuffer flag.
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x014f);
    assert_eq!(vga.borrow().svga, before_state.svga);
    assert_eq!(vga.borrow().vram, before_state.vram);
}

#[test]
fn runtime_bank_window_and_scanline_services_validate_before_state_changes() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    let mut regs = Registers::default();
    regs.set_ax(0x4f02);
    regs.set_bx(0x0101);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x004f);

    regs.set_ax(0x4f05);
    regs.set_bh(0);
    regs.set_bl(0);
    regs.set_dx(3);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x004f);
    regs.set_ax(0x4f05);
    regs.set_bh(1);
    regs.set_dx(0);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!((regs.ax(), regs.dx()), (0x004f, 3));
    regs.set_ax(0x4f05);
    regs.set_bh(0);
    regs.set_dx(64);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x014f);
    assert_eq!(vga.borrow().svga.as_ref().unwrap().bank, 3);
    regs.set_ax(0x4f05);
    regs.set_bl(1); // Window B is not implemented.
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x014f);
    assert_eq!(vga.borrow().svga.as_ref().unwrap().bank, 3);

    regs.set_ax(0x4f06);
    regs.set_bx(0);
    regs.set_cx(800);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!((regs.ax(), regs.bx(), regs.cx(), regs.dx()), (0x004f, 800, 800, 5242));
    assert_eq!(vga.borrow().svga.as_ref().unwrap().stride, 800);

    regs.set_ax(0x4f06);
    regs.set_bx(0x0001);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!((regs.ax(), regs.bx(), regs.cx(), regs.dx()), (0x004f, 800, 800, 5242));

    regs.set_ax(0x4f06);
    regs.set_bl(0);
    regs.set_cx(639);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x014f);
    assert_eq!(vga.borrow().svga.as_ref().unwrap().stride, 800);

    // BH is not specified for 4F06 and does not invalidate the request.
    regs.set_ax(0x4f06);
    regs.set_bl(0);
    regs.set_bh(0x5a);
    regs.set_cx(800);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x004f);
}

#[test]
fn runtime_display_start_and_fixed_dac_width_follow_reported_hardware() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    let mut regs = Registers::default();
    regs.set_ax(0x4f02);
    regs.set_bx(0x0101);
    invoke(&vga, &mut regs, &mut memory).unwrap();

    regs.set_ax(0x4f06);
    regs.set_bx(0);
    regs.set_cx(800);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    regs.set_ax(0x4f07);
    regs.set_bx(0);
    regs.set_cx(160);
    regs.set_dx(2);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x004f);
    regs.set_ax(0x4f07);
    regs.set_bl(1);
    regs.set_bh(0);
    regs.set_cx(0);
    regs.set_dx(0);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!((regs.ax(), regs.cx(), regs.dx()), (0x004f, 160, 2));

    regs.set_ax(0x4f07);
    regs.set_bx(0);
    regs.set_cx(161); // Visible width no longer fits an 800-pixel stride.
    regs.set_dx(2);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x014f);
    assert_eq!(vga.borrow().svga.as_ref().unwrap().display_x, 160);

    // BL=80h requests the same start update during retrace; this software
    // adapter applies it immediately because it has no scan timing model.
    regs.set_ax(0x4f07);
    regs.set_bx(0x0080);
    regs.set_cx(0);
    regs.set_dx(3);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x004f);
    assert_eq!(vga.borrow().svga.as_ref().unwrap().display_y, 3);

    regs.set_ax(0x4f08);
    regs.set_bl(1);
    regs.set_bh(0);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!((regs.ax(), regs.bh()), (0x004f, 6));
    regs.set_ax(0x4f08);
    regs.set_bl(0);
    regs.set_bh(8);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.ax(), 0x014f);
}

#[test]
fn runtime_unknown_vbe_function_uses_the_standard_failure_status() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    let mut regs = Registers::default();
    regs.eax = 0x1234_4ffe;
    regs.ebx = 0x5678_9abc;
    let before = regs.clone();

    assert!(invoke(&vga, &mut regs, &mut memory).unwrap());

    let mut expected = before;
    expected.set_ax(0x014f);
    assert_eq!(regs, expected);
}

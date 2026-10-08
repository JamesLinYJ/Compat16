use super::{dispatch_state, FAILURE, SUCCESS};
use super::codec::*;
use crate::{bios::BDA_BASE, vga::VgaDevice, DeviceError};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers, real_address};

#[derive(Clone)]
struct TestMemory(Vec<u8>);

impl TestMemory {
    fn new() -> Self {
        let mut memory = Self(vec![0; 0x12_0000]);
        memory.0[(BDA_BASE as usize) + BDA_MODE] = 3;
        write_test_word(&mut memory.0, BDA_BASE as usize + BDA_COLUMNS, 80);
        write_test_word(&mut memory.0, BDA_BASE as usize + BDA_PAGE_BYTES, 0x1000);
        write_test_word(&mut memory.0, BDA_BASE as usize + BDA_CRTC_BASE, 0x03d4);
        memory.0[(BDA_BASE as usize) + BDA_ROWS] = 25;
        memory.0[(BDA_BASE as usize) + BDA_CHAR_HEIGHT] = 16;
        memory
    }
}

impl GuestMemory for TestMemory {
    fn len(&self) -> u32 { self.0.len() as u32 }

    fn read(&self, address: PhysAddr, output: &mut [u8]) -> Result<(), MemoryError> {
        self.validate_read(address, output.len())?;
        let start = address.0 as usize;
        output.copy_from_slice(&self.0[start..start + output.len()]);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, input: &[u8]) -> Result<(), MemoryError> {
        self.validate_write(address, input.len())?;
        let start = address.0 as usize;
        self.0[start..start + input.len()].copy_from_slice(input);
        Ok(())
    }
}

fn write_test_word(memory: &mut [u8], address: usize, value: u16) {
    memory[address..address + 2].copy_from_slice(&value.to_le_bytes());
}

fn run(
    vga: &VgaDevice,
    memory: &mut impl GuestMemory,
    function: u8,
    mask: u16,
    segment: u16,
    offset: u16,
) -> Result<Registers, DeviceError> {
    let mut regs = Registers::default();
    regs.set_ax(0x4f04);
    regs.set_bx(offset);
    regs.set_cx(mask);
    regs.set_dx(0xa500);
    regs.set_dl(function);
    regs.es = segment;
    dispatch_state(vga, &mut regs, memory)?;
    Ok(regs)
}

#[test]
fn query_sizes_follow_the_selected_vbe_state_groups() {
    let vga = VgaDevice::new();
    let mut memory = TestMemory::new();
    for (mask, expected) in [
        (0, 0),
        (STATE_HARDWARE, 2),
        (STATE_BIOS_DATA, 1),
        (STATE_DAC, 13),
        (STATE_SVGA, 1),
        (SUPPORTED_STATE_MASK, 15),
    ] {
        let regs = run(&vga, &mut memory, 0, mask, 0, 0).unwrap();
        assert_eq!(regs.ax(), SUCCESS);
        assert_eq!(regs.bx(), expected, "mask {mask:#06x}");
        assert_eq!(regs.dh(), 0xa5);
        assert_eq!(regs.dl(), 0);
    }

    let regs = run(&vga, &mut memory, 0, 0x0010, 0, 0).unwrap();
    assert_eq!(regs.ax(), FAILURE);
    assert_eq!(regs.bx(), 0);
}

#[test]
fn full_restore_recovers_selected_state_and_never_restores_vram() {
    let vga = VgaDevice::new();
    let mut memory = TestMemory::new();
    {
        let mut state = vga.borrow_mut();
        state.sequencer[2] = 0x0f;
        state.graphics[5] = 0x40;
        state.attribute[3] = 0x22;
        state.latches = [0x11, 0x22, 0x33, 0x44];
        state.palette[42] = [1, 2, 3];
        state.pel_mask = 0x3f;
        state.vram[1234] = 0x17;
    }
    memory.0[BDA_BASE as usize + BDA_CURSOR_POSITIONS..BDA_BASE as usize + BDA_CURSOR_POSITIONS + 4]
        .copy_from_slice(&[1, 2, 3, 4]);
    write_test_word(&mut memory.0, BDA_BASE as usize + BDA_CURSOR_SHAPE, 0x0610);
    memory.0[BDA_BASE as usize + BDA_ACTIVE_PAGE] = 2;

    // Starting at the final 16 bytes of a segment exercises real-mode offset
    // wrapping while retaining a single portable state buffer.
    let save = run(&vga, &mut memory, 1, SUPPORTED_STATE_MASK, 0x1000, 0xfff0).unwrap();
    assert_eq!(save.ax(), SUCCESS);
    let saved_bda = memory.0[BDA_BASE as usize..BDA_BASE as usize + crate::bios::BDA_SIZE].to_vec();
    {
        let mut state = vga.borrow_mut();
        state.sequencer[2] = 0;
        state.graphics[5] = 0;
        state.attribute[3] = 0;
        state.latches = [0; 4];
        state.palette[42] = [9, 9, 9];
        state.pel_mask = 0xff;
        state.bios_mode = 0x12;
        state.vram[1234] = 0xa5;
    }
    memory.0[BDA_BASE as usize + BDA_CURSOR_POSITIONS..BDA_BASE as usize + BDA_CURSOR_POSITIONS + 4]
        .fill(0);
    memory.0[BDA_BASE as usize + BDA_ACTIVE_PAGE] = 0;

    let restore = run(&vga, &mut memory, 2, SUPPORTED_STATE_MASK, 0x1000, 0xfff0).unwrap();
    assert_eq!(restore.ax(), SUCCESS);
    let state = vga.borrow();
    assert_eq!(state.bios_mode, 3);
    assert_eq!(state.sequencer[2], 0x0f);
    assert_eq!(state.graphics[5], 0x40);
    assert_eq!(state.attribute[3], 0x22);
    assert_eq!(state.latches, [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(state.palette[42], [1, 2, 3]);
    assert_eq!(state.pel_mask, 0x3f);
    assert_eq!(state.vram[1234], 0xa5, "VBE 4F04 excludes framebuffer memory");
    assert_eq!(
        &memory.0[BDA_BASE as usize..BDA_BASE as usize + crate::bios::BDA_SIZE],
        saved_bda.as_slice()
    );
}

#[test]
fn partial_restore_changes_only_requested_state() {
    let vga = VgaDevice::new();
    let mut memory = TestMemory::new();
    {
        let mut state = vga.borrow_mut();
        state.sequencer[1] = 0x0c;
        state.palette[8] = [4, 5, 6];
    }
    assert_eq!(run(&vga, &mut memory, 1, STATE_HARDWARE, 0x2000, 0).unwrap().ax(), SUCCESS);
    {
        let mut state = vga.borrow_mut();
        state.sequencer[1] = 0x03;
        state.palette[8] = [9, 9, 9];
    }
    let restored = run(&vga, &mut memory, 2, STATE_HARDWARE, 0x2000, 0).unwrap();
    assert_eq!(restored.ax(), SUCCESS);
    let state = vga.borrow();
    assert_eq!(state.sequencer[1], 0x0c);
    assert_eq!(state.palette[8], [9, 9, 9]);

    let unsupported = run(&vga, &mut memory, 2, STATE_DAC, 0x2000, 0).unwrap();
    assert_eq!(unsupported.ax(), FAILURE);
    assert_eq!(vga.borrow().palette[8], [9, 9, 9]);
}

#[test]
fn invalid_snapshot_is_rejected_without_changing_adapter_or_bda() {
    let vga = VgaDevice::new();
    let mut memory = TestMemory::new();
    assert_eq!(run(&vga, &mut memory, 1, STATE_HARDWARE, 0x3000, 0).unwrap().ax(), SUCCESS);
    let start = real_address(0x3000, 0).0 as usize;
    memory.0[start + 4] = FORMAT_VERSION.wrapping_add(1);

    {
        let mut state = vga.borrow_mut();
        state.sequencer[0] = 0x5a;
    }
    let before_generation = vga.generation();
    let before_bda = memory.0[BDA_BASE as usize..BDA_BASE as usize + crate::bios::BDA_SIZE].to_vec();
    let regs = run(&vga, &mut memory, 2, STATE_HARDWARE, 0x3000, 0).unwrap();
    assert_eq!(regs.ax(), FAILURE);
    assert_eq!(vga.borrow().sequencer[0], 0x5a);
    assert_eq!(vga.generation(), before_generation);
    assert_eq!(
        &memory.0[BDA_BASE as usize..BDA_BASE as usize + crate::bios::BDA_SIZE],
        before_bda.as_slice()
    );
}

#[test]
fn svga_state_roundtrips_without_copying_framebuffer_memory() {
    let vga = VgaDevice::new();
    let mut memory = TestMemory::new();
    {
        let mut state = vga.borrow_mut();
        assert!(state.set_svga_mode(0x101, false));
        state.vram[0x30000] = 0x34;
    }
    memory.0[BDA_BASE as usize + BDA_MODE] = 0xff;
    assert_eq!(run(&vga, &mut memory, 1, STATE_SVGA, 0x4000, 0).unwrap().ax(), SUCCESS);
    {
        let mut state = vga.borrow_mut();
        let svga = state.svga.as_mut().unwrap();
        svga.bank = 4;
        state.vram[0x30000] = 0x78;
    }
    let regs = run(&vga, &mut memory, 2, STATE_SVGA, 0x4000, 0).unwrap();
    assert_eq!(regs.ax(), SUCCESS);
    let state = vga.borrow();
    assert_eq!(state.svga.as_ref().unwrap().bank, 0);
    assert_eq!(state.vram[0x30000], 0x78);
}

#[test]
fn guest_buffer_fault_keeps_adapter_state_unchanged_and_preserves_error() {
    let vga = VgaDevice::new();
    let mut memory = TestMemory(vec![0; 0x500]);
    let before = vga.borrow().clone();
    let error = run(&vga, &mut memory, 2, STATE_HARDWARE, 0xffff, 0xfff0).unwrap_err();
    assert!(matches!(error, DeviceError::Memory(MemoryError::OutOfBounds { .. })));
    assert_eq!(vga.borrow().sequencer, before.sequencer);
    assert_eq!(vga.generation(), before.generation);
}

use super::*;
use crate::{BiosDevices, DeviceError};
use guest_core::{GuestMemory, MemoryError, PhysAddr};

struct Memory(Vec<u8>);

impl Memory {
    fn new(size: usize) -> Self { Self(vec![0; size]) }

    fn put(&mut self, address: u32, bytes: &[u8]) {
        let start = address as usize;
        self.0[start..start + bytes.len()].copy_from_slice(bytes);
    }
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

fn invoke(vga: &VgaDevice, regs: &mut Registers, memory: &mut Memory) -> Result<bool, DeviceError> {
    dispatch(vga, regs, memory)
}

fn write_word(memory: &mut Memory, offset: usize, value: u16) {
    memory.put((BDA_BASE as usize + offset) as u32, &value.to_le_bytes());
}

#[test]
fn overscan_is_distinct_from_attribute_mode_control() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    let mode_control = vga.borrow().attribute[ATTRIBUTE_MODE_CONTROL];
    let mut regs = Registers::default();
    regs.set_ah(0x10);
    regs.set_al(0x01);
    regs.set_bh(0xc5);
    invoke(&vga, &mut regs, &mut memory).unwrap();

    assert_eq!(vga.borrow().attribute[ATTRIBUTE_OVERSCAN], 0x05);
    assert_eq!(vga.borrow().attribute[ATTRIBUTE_MODE_CONTROL], mode_control);

    regs.set_al(0x08);
    regs.set_bh(0xaa);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.bh(), 0x05);

    let palette: Vec<u8> = (0..17).map(|value| 0x80 | value).collect();
    memory.put(0x300, &palette);
    regs.es = 0;
    regs.set_dx(0x300);
    regs.set_al(0x02);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(&vga.borrow().attribute[..16], &(0..16).collect::<Vec<_>>());
    assert_eq!(vga.borrow().attribute[ATTRIBUTE_OVERSCAN], 16);
    assert_eq!(vga.borrow().attribute[ATTRIBUTE_MODE_CONTROL], mode_control);

    regs.set_al(0x09);
    regs.set_dx(0x400);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(&memory.0[0x400..0x411], &(0..17).collect::<Vec<_>>());
}

#[test]
fn dac_blocks_wrap_index_and_keep_six_bit_components() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    memory.put(0x300, &[0xff, 0x42, 0x81, 0x01, 0xc0, 0x7f]);

    let mut regs = Registers::default();
    regs.set_ah(0x10);
    regs.set_al(0x12);
    regs.set_bx(0x00ff);
    regs.set_cx(2);
    regs.set_dx(0x300);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(vga.borrow().palette[255], [0x3f, 0x02, 0x01]);
    assert_eq!(vga.borrow().palette[0], [0x01, 0x00, 0x3f]);

    regs.set_al(0x17);
    regs.set_dx(0x400);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(&memory.0[0x400..0x406], &[0x3f, 0x02, 0x01, 0x01, 0x00, 0x3f]);

    let before = vga.borrow().palette;
    regs.set_bx(0x0101);
    regs.set_dx(0x300);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(vga.borrow().palette, before, "out-of-range DAC index is ignored");
}

#[test]
fn pel_mask_and_grayscale_services_update_the_modeled_dac() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    {
        let mut state = vga.borrow_mut();
        state.palette[7] = [63, 0, 0];
        state.palette[8] = [0, 63, 0];
        state.palette[9] = [0, 0, 63];
    }
    let mut regs = Registers::default();
    regs.set_ah(0x10);
    regs.set_al(0x1b);
    regs.set_bx(7);
    regs.set_cx(3);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(vga.borrow().palette[7], [18; 3]);
    assert_eq!(vga.borrow().palette[8], [37; 3]);
    assert_eq!(vga.borrow().palette[9], [6; 3]);

    regs.set_al(0x18);
    regs.set_bl(0x5a);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    regs.set_al(0x19);
    regs.set_bl(0);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.bl(), 0x5a);
}

#[test]
fn far_buffer_offsets_wrap_at_sixteen_bits() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    let payload: Vec<u8> = (0..17).collect();
    memory.put(0x1_fff8, &payload[..8]);
    memory.put(0x1_0000, &payload[8..]);
    let mut regs = Registers::default();
    regs.set_ah(0x10);
    regs.set_al(0x02);
    regs.es = 0x1000;
    regs.set_dx(0xfff8);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(&vga.borrow().attribute[..16], &(0..16).collect::<Vec<_>>());
    assert_eq!(vga.borrow().attribute[ATTRIBUTE_OVERSCAN], 16);
}

#[test]
fn vga_presence_memory_and_functionality_queries_report_modeled_state() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);

    let mut regs = Registers::default();
    regs.set_ah(0x1a);
    regs.set_al(0);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.al(), 0x1a);
    assert_eq!(regs.bl(), 8);
    assert_eq!(regs.bh(), 0);

    regs.set_ah(0x12);
    regs.set_bl(0x10);
    regs.set_cx(0xffff);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.bh(), 0);
    assert_eq!(regs.bl(), 3);
    assert_eq!(regs.cx(), 0);

    memory.put((BDA_BASE + 0x49) as u32, &[3]);
    write_word(&mut memory, 0x4c, 0x1000);
    write_word(&mut memory, 0x4e, 0x2000);
    memory.put((BDA_BASE + 0x50) as u32, &[1, 2, 3, 4]);
    write_word(&mut memory, 0x60, 0x0607);
    memory.put((BDA_BASE + 0x62) as u32, &[0]);
    write_word(&mut memory, 0x63, 0x03d4);
    {
        let mut state = vga.borrow_mut();
        state.cga_mode_control = 0x49;
        state.cga_color_control = 0x0f;
        state.attribute[ATTRIBUTE_MODE_CONTROL] |= 0x08;
    }

    regs.set_ah(0x1b);
    regs.set_bx(0);
    regs.es = 0x2000;
    regs.set_di(0x0100);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.al(), 0x1b);
    let mut state = [0; STATE_BYTES];
    memory.read(real_address(0x2000, 0x0100), &mut state).unwrap();
    assert_eq!(&state[0..4], &[0x00, 0x30, 0x00, 0xf0]);
    assert_eq!(state[4], 3);
    assert_eq!(u16::from_le_bytes([state[5], state[6]]), 80);
    assert_eq!(u16::from_le_bytes([state[7], state[8]]), 0x1000);
    assert_eq!(&state[11..15], &[1, 2, 3, 4]);
    assert_eq!(u16::from_le_bytes([state[27], state[28]]), 0x0607);
    assert_eq!(&state[30..34], &[0xd4, 0x03, 0x49, 0x0f]);
    assert_eq!(&state[34..37], &[25, 16, 0]);
    assert_eq!(&state[37..39], &[8, 0]);
    assert_eq!(u16::from_le_bytes([state[39], state[40]]), 16);
    assert_eq!(state[41], 8);
    assert_eq!(state[42], 2);
    assert_eq!(state[45], 0x20);
    assert_eq!(state[49], 3);

    let before = memory.0[0x20100..0x20140].to_vec();
    regs.set_bx(1);
    regs.set_al(0x6d);
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs.al(), 0);
    assert_eq!(&memory.0[0x20100..0x20140], &before);
}

#[test]
fn static_functionality_table_and_mode_metadata_are_truthful() {
    let table = functionality_table();
    assert_eq!(table[0] & (1 << 3), 1 << 3, "mode 03h is implemented");
    assert_eq!(table[1] & (1 << 0), 0, "mode 08h is not advertised");
    assert_eq!(table[7], 1 << 2, "implemented VGA text modes use 400-line cells");
    assert_eq!(table[0x0a] & 0x80, 0, "color paging is not implemented");
    assert_eq!(table[0x0a] & (1 << 1), 0, "persistent summing is not implemented");

    assert_eq!(mode_color_count(modes::mode_info(0x0f).unwrap()), 2);
    assert_eq!(mode_color_count(modes::mode_info(0x11).unwrap()), 2);
    assert_eq!(mode_page_count(modes::mode_info(0x0d).unwrap()), 8);
    assert_eq!(mode_page_count(modes::mode_info(0x0e).unwrap()), 4);
    assert_eq!(mode_page_count(modes::mode_info(0x0f).unwrap()), 2);
    assert_eq!(mode_page_count(modes::mode_info(0x13).unwrap()), 1);
}

#[test]
fn unsupported_ah10_subfunctions_leave_registers_and_state_unchanged() {
    let vga = VgaDevice::new();
    let mut memory = Memory::new(0x10_0000);
    let mut regs = Registers::default();
    regs.eax = 0x1234_10fe;
    regs.ebx = 0x5678_9abc;
    let before_regs = regs.clone();
    let before_generation = vga.generation();
    let before_state = vga.borrow().clone();
    invoke(&vga, &mut regs, &mut memory).unwrap();
    assert_eq!(regs, before_regs);
    assert_eq!(vga.borrow().generation, before_generation);
    assert_eq!(vga.borrow().attribute, before_state.attribute);
    assert_eq!(vga.borrow().palette, before_state.palette);
}

#[test]
fn runtime_unknown_vbe_function_returns_failure_without_reading_or_writing_the_buffer() {
    let mut memory = Memory::new(0x10_0000);
    let mut bios = BiosDevices::new();
    bios.initialize(&mut memory).unwrap();

    // Deliberately invalid VBE output address proves this absent extension
    // returns its failure status without attempting an information-block write.
    let mut regs = Registers::default();
    regs.eax = 0x4321_4ffe;
    regs.ebx = 0x8765_4321;
    regs.ecx = 0x1357_2468;
    regs.edx = 0x2468_1357;
    regs.esi = 0xdead_beef;
    regs.edi = 0xbeef_dead;
    regs.es = 0xffff;
    regs.eflags = 0x0000_0ad7;
    let mut expected_regs = regs.clone();
    expected_regs.set_ax(0x014f);
    let before_memory = memory.0.clone();

    bios.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();

    assert_eq!(regs, expected_regs);
    assert_eq!(memory.0, before_memory);
}

#[test]
fn runtime_unimplemented_int10_probe_preserves_registers_and_guest_memory() {
    let mut memory = Memory::new(0x10_0000);
    let mut bios = BiosDevices::new();
    bios.initialize(&mut memory).unwrap();

    let mut regs = Registers::default();
    regs.eax = 0xcafe_6b77;
    regs.ebx = 0x1234_5678;
    regs.ecx = 0x8765_4321;
    regs.edx = 0x1357_2468;
    regs.esi = 0xabcd_ef01;
    regs.edi = 0x1020_3040;
    regs.eflags = 0x0000_0ad7;
    let before_regs = regs.clone();
    let before_memory = memory.0.clone();

    bios.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();

    assert_eq!(regs, before_regs);
    assert_eq!(memory.0, before_memory);
}

#[test]
fn runtime_invalid_video_mode_is_ignored_without_changing_vga_or_memory() {
    let mut memory = Memory::new(0x10_0000);
    let mut bios = BiosDevices::new();
    bios.initialize(&mut memory).unwrap();
    let before_vga = bios.video.vga().borrow().clone();

    let mut regs = Registers::default();
    regs.eax = 0x9876_007f;
    regs.ebx = 0x1234_5678;
    regs.eflags = 0x0000_0ad7;
    let before_regs = regs.clone();
    let before_memory = memory.0.clone();

    bios.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();

    assert_eq!(regs, before_regs);
    assert_eq!(memory.0, before_memory);
    let current_vga = bios.video.vga().borrow();
    assert_eq!(current_vga.bios_mode, before_vga.bios_mode);
    assert_eq!(current_vga.generation, before_vga.generation);
    assert_eq!(current_vga.vram, before_vga.vram);
    drop(current_vga);

    // The normal current-mode query still exposes the unchanged real mode.
    regs.set_ah(0x0f);
    bios.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.al(), 3);
}

#[test]
fn runtime_existing_palette_service_still_executes_through_bios_dispatch() {
    let mut memory = Memory::new(0x10_0000);
    let mut bios = BiosDevices::new();
    bios.initialize(&mut memory).unwrap();
    let mut regs = Registers::default();
    regs.set_ah(0x10);
    regs.set_al(0x18);
    regs.set_bl(0x5a);

    bios.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(bios.video.vga().borrow().pel_mask, 0x5a);

    regs.set_al(0x19);
    regs.set_bl(0);
    bios.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.bl(), 0x5a);
}

#[test]
fn runtime_real_palette_buffer_memory_fault_is_still_reported() {
    let mut memory = Memory::new(0x10_0000);
    let mut bios = BiosDevices::new();
    bios.initialize(&mut memory).unwrap();
    let before_memory = memory.0.clone();
    let before_attribute = bios.video.vga().borrow().attribute;

    let mut regs = Registers::default();
    regs.set_ah(0x10);
    regs.set_al(0x02);
    regs.es = 0xffff;
    regs.set_dx(0xfff8);

    let result = bios.dispatch_interrupt(0x10, &mut regs, &mut memory, 0);

    assert!(matches!(result, Err(DeviceError::Memory(_))));
    assert_eq!(memory.0, before_memory);
    assert_eq!(bios.video.vga().borrow().attribute, before_attribute);
}

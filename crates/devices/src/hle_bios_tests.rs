use super::Memory;
use crate::{BiosDevices, DeviceAction};
use guest_core::Registers;

fn machine() -> (BiosDevices, Memory) {
    let mut memory = Memory(vec![0; 0x12_0000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    (devices, memory)
}

#[test]
fn int10_services_cover_mode_cursor_scroll_text_palette_and_font() {
    let (mut devices, mut memory) = machine();
    let mut regs = Registers::default();
    regs.set_ah(0x0f);
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.al(), 0x03);
    assert_eq!(regs.ah(), 80);

    regs.set_ax(0x0200);
    regs.set_dx(0x0102);
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    regs.set_ah(0x03);
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.dx() & 0xffff, 0x0102);
    assert_eq!(memory.0[0x450], 2);
    assert_eq!(memory.0[0x451], 1);

    regs.set_ax(0x0900 | u16::from(b'Z'));
    regs.set_bx(0x001f);
    regs.set_cx(1);
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(&memory.0[0xb8000 + (1 * 80 + 2) * 2..0xb8000 + (1 * 80 + 2) * 2 + 2], b"Z\x1f");

    regs.set_ax(0x0e41);
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();

    regs.set_ax(0x0601);
    regs.set_bx(0x0700);
    regs.set_cx(0);
    regs.set_dx(0x184f);
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();

    regs.set_ax(0x0b00);
    regs.set_bx(0x0004);
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    regs.set_ax(0x0b01);
    regs.set_bx(0x0101);
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();

    regs.set_ax(0x1130);
    regs.set_bh(6);
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    assert_eq!((regs.es, regs.bp()), (0xf000, 0x6000));
    assert_eq!(regs.cx(), 16);
    assert_eq!(regs.dl(), 24);

    regs.set_ah(0xfe);
    let before = regs.eax;
    devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.eax, before);
}

#[test]
fn int16_extended_keyboard_reads_shift_flags() {
    let (mut devices, mut memory) = machine();
    devices.keyboard.set_shift_flags(0x02);
    assert!(devices.push_key(crate::keyboard::KeyStroke { ascii: 0, scan: 0x3b }));
    let mut regs = Registers::default();
    regs.set_ah(0x11);
    devices.dispatch_interrupt(0x16, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.ax(), 0x3b00);
    assert_eq!(regs.eflags & (1 << 6), 0);
    regs.set_ah(0x12);
    devices.dispatch_interrupt(0x16, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.al(), 0x02);
    assert_eq!(memory.0[0x417], 0x02);
    assert_eq!(u16::from_le_bytes([memory.0[0x41a], memory.0[0x41b]]), 0x001e);
}

#[test]
fn int1a_sets_and_reads_the_cmos_clock_and_alarm() {
    let (mut devices, mut memory) = machine();
    let mut regs = Registers::default();
    regs.set_ah(0x03);
    regs.set_cx(0x2359);
    regs.set_dx(0x5800);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 0).unwrap();
    assert!(!regs.carry());
    regs.set_ah(0x02);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 86_400).unwrap();
    assert!(!regs.carry());
    assert_eq!(regs.cx(), 0x2359);
    assert_eq!(regs.dx() >> 8, 0x58);

    regs.set_ah(0x05);
    regs.set_cx(0x2000);
    regs.set_dx(0x0229);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 0).unwrap();
    assert!(!regs.carry());
    regs.set_ah(0x04);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.cx(), 0x2000);
    assert_eq!(regs.dx(), 0x0229);

    regs.set_ah(0x05);
    regs.set_dx(0x0230);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 0).unwrap();
    assert!(regs.carry());

    regs.set_ah(0x06);
    regs.set_cx(0x0000);
    regs.set_dx(0x0100);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 0).unwrap();
    assert!(!regs.carry());
    regs.set_ah(0x06);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 0).unwrap();
    assert!(regs.carry());
    regs.set_ah(0x07);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 0).unwrap();
    assert!(!devices.cmos().alarm_enabled());

    regs.set_ah(0x01);
    regs.set_cx(0x0001);
    regs.set_dx(0x0002);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(u32::from_le_bytes(memory.0[0x46c..0x470].try_into().unwrap()), 0x0001_0002);
    assert_eq!(memory.0[0x470], 0);
}

#[test]
fn equipment_memory_wait_a20_and_extended_memory_use_cmos() {
    let (mut devices, mut memory) = machine();
    let mut regs = Registers::default();
    devices.dispatch_interrupt(0x11, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.ax(), 0x0020);
    devices.dispatch_interrupt(0x12, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.ax(), 640);
    assert_eq!(u16::from_le_bytes([memory.0[0x413], memory.0[0x414]]), 640);

    regs.set_ah(0x88);
    devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.ax(), 128);
    assert!(!regs.carry());

    regs.set_ax(0x8300);
    regs.set_cx(0);
    regs.set_dx(0);
    regs.es = 0x40;
    regs.set_bx(0x50);
    devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    assert!(!regs.carry());
    let flag = devices.cmos().take_completed_waits();
    assert_eq!(flag, vec![(0x40, 0x50)]);

    regs.set_ax(0x8300);
    regs.set_cx(1);
    regs.set_dx(0);
    devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    regs.set_ax(0x8600);
    devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ah(), 0x80);
    regs.set_ax(0x8301);
    devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    assert!(!devices.cmos().user_wait_active());

    regs.set_ax(0x2400);
    let outcome = devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(outcome.actions, vec![DeviceAction::SetA20Gate { enabled: false }]);
    assert!(!devices.a20_enabled());
    regs.set_ax(0x2402);
    devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.bh(), 0);
    regs.set_ax(0x2403);
    devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.bx(), 0x0003);

    regs.set_ah(0xc0);
    devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ah(), 0x86);
}

#[test]
fn disk_serial_printer_and_rtc_irq_do_not_abort() {
    let (mut devices, mut memory) = machine();
    let mut regs = Registers::default();
    regs.set_ah(0x00);
    regs.set_dl(0);
    devices.dispatch_interrupt(0x13, &mut regs, &mut memory, 0).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ah(), 0x80);

    regs.set_ah(0x03);
    regs.set_dx(0);
    devices.dispatch_interrupt(0x14, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.ax(), 0x8000);

    regs.set_ah(0x02);
    devices.dispatch_interrupt(0x17, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.ah() & 0x09, 0x09);

    devices.cmos().write_index(0x0c);
    devices.cmos().write_data(0xff);
    devices.cmos().write_index(0x0a);
    devices.cmos().write_data(0x2f);
    devices.cmos().write_index(0x0b);
    devices.cmos().write_data(0x42);
    assert!(devices.cmos().advance_pit_ticks((1_193_182 + 1) / 2));
    devices.dispatch_interrupt(0x70, &mut regs, &mut memory, 0).unwrap();
    devices.cmos().write_index(0x0c);
    assert_eq!(devices.cmos().read_data(), 0);
}

#[test]
fn bda_tracks_video_keyboard_and_ticks() {
    let (mut devices, mut memory) = machine();
    assert_eq!(memory.0[0x449], 3);
    assert_eq!(u16::from_le_bytes([memory.0[0x44a], memory.0[0x44b]]), 80);
    devices.update_clock(&mut memory, 3_600).unwrap();
    assert!(u32::from_le_bytes(memory.0[0x46c..0x470].try_into().unwrap()) > 0);
}

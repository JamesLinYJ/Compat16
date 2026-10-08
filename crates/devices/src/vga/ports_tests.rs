use crate::ports::MachinePorts;
use guest_core::io::{PortIo, PortWidth};

#[test]
fn word_port_transaction_splits_vga_index_and_data_bytes() {
    let mut ports = MachinePorts::new();

    ports.write(0x03d4, PortWidth::Word, 0x3410).unwrap();

    assert_eq!(ports.vga().borrow().crtc[0x10], 0x34);
    assert_eq!(ports.read(0x03d4, PortWidth::Word).unwrap(), 0x3410);
}

#[test]
fn misc_output_selects_mono_or_color_crtc_ports() {
    let mut ports = MachinePorts::new();
    ports.write(0x03c2, PortWidth::Byte, 0x00).unwrap();
    ports.write(0x03b4, PortWidth::Word, 0x5610).unwrap();

    assert_eq!(ports.vga().borrow().crtc[0x10], 0x56);
    assert_eq!(ports.read(0x03d4, PortWidth::Word).unwrap(), 0xffff);

    ports.write(0x03c2, PortWidth::Byte, 0x01).unwrap();
    ports.write(0x03d4, PortWidth::Word, 0x7810).unwrap();
    assert_eq!(ports.vga().borrow().crtc[0x10], 0x78);
}

#[test]
fn input_status_read_resets_attribute_controller_write_phase() {
    let mut ports = MachinePorts::new();
    ports.write(0x03c0, PortWidth::Byte, 0x12).unwrap();
    ports.write(0x03c0, PortWidth::Byte, 0x34).unwrap();
    assert_eq!(ports.vga().borrow().attribute[0x12], 0x34);

    let _ = ports.read(0x03da, PortWidth::Byte).unwrap();
    ports.write(0x03c0, PortWidth::Byte, 0x05).unwrap();
    ports.write(0x03c0, PortWidth::Byte, 0x67).unwrap();
    assert_eq!(ports.vga().borrow().attribute[0x05], 0x67);
}

#[test]
fn vertical_retrace_is_derived_from_guest_clock_phase() {
    let mut ports = MachinePorts::new();
    assert_eq!(ports.read(0x03da, PortWidth::Byte).unwrap() & 0x08, 0);

    ports.advance_ticks(18_500);

    assert_ne!(ports.read(0x03da, PortWidth::Byte).unwrap() & 0x08, 0);
    assert_ne!(ports.read(0x03da, PortWidth::Byte).unwrap() & 0x08, 0);
}

#[test]
fn wide_vga_transaction_crossing_aperture_is_rejected_before_writing() {
    let mut ports = MachinePorts::new();
    let before = ports.vga().borrow().misc_output;

    assert!(ports.write(0x03df, PortWidth::Word, 0x1234).is_err());
    assert_eq!(ports.vga().borrow().misc_output, before);
}

#[test]
fn dac_state_port_reports_read_and_write_modes() {
    let mut ports = MachinePorts::new();

    ports.write(0x03c7, PortWidth::Byte, 7).unwrap();
    assert_eq!(ports.read(0x03c7, PortWidth::Byte).unwrap(), 0x03);

    ports.write(0x03c8, PortWidth::Byte, 9).unwrap();
    assert_eq!(ports.read(0x03c7, PortWidth::Byte).unwrap(), 0x00);
}

#[test]
fn protected_crtc_overflow_register_only_allows_line_compare_bit() {
    let mut ports = MachinePorts::new();
    ports.write(0x03d4, PortWidth::Byte, 0x11).unwrap();
    ports.write(0x03d5, PortWidth::Byte, 0x80).unwrap();

    let before = ports.vga().borrow().crtc[7];
    ports.write(0x03d4, PortWidth::Byte, 7).unwrap();
    ports.write(0x03d5, PortWidth::Byte, 0xff).unwrap();

    assert_eq!(ports.vga().borrow().crtc[7], (before & !0x10) | 0x10);
}

#[test]
fn legacy_cga_mode_port_does_not_reprogram_vga_mode_or_vram() {
    let mut ports = MachinePorts::new();
    assert!(ports.vga().set_mode(0x13, false));
    ports.vga().borrow_mut().vram[0] = 0x5a;

    ports.write(0x03d8, PortWidth::Byte, 0x42).unwrap();

    let state = ports.vga().borrow();
    assert_eq!(state.bios_mode, 0x13);
    assert_eq!(state.vram[0], 0x5a);
    assert_eq!(state.cga_mode_control, 0x42);
}

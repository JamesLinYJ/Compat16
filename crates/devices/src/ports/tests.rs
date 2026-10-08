use guest_core::io::{PortError, PortIo, PortWidth};

use super::MachinePorts;

fn write_byte(ports: &mut MachinePorts, port: u16, value: u8) {
    ports.write(port, PortWidth::Byte, u32::from(value)).unwrap();
}

fn initialize_pic(ports: &mut MachinePorts) {
    write_byte(ports, 0x20, 0x11);
    write_byte(ports, 0x21, 0x20);
    write_byte(ports, 0x21, 0x04);
    write_byte(ports, 0x21, 0x01);
    write_byte(ports, 0xa0, 0x11);
    write_byte(ports, 0xa1, 0x28);
    write_byte(ports, 0xa1, 0x02);
    write_byte(ports, 0xa1, 0x01);
    write_byte(ports, 0x21, 0x00);
    write_byte(ports, 0xa1, 0x00);
}

#[test]
fn pit_modes_0_through_5_drive_the_documented_output_sequences() {
    let mut pit = super::Pit8254::new();

    // Mode 0 loads on one clock, counts N further clocks, then raises OUT.
    pit.write_control(0x10).unwrap();
    pit.write_counter(0, 3).unwrap();
    assert!(!pit.output(0).unwrap());
    pit.advance_ticks(1);
    assert!(!pit.output(0).unwrap());
    pit.advance_ticks(2);
    assert!(!pit.output(0).unwrap());
    pit.advance_ticks(1);
    assert!(pit.output(0).unwrap());

    // Mode 1 waits for a rising GATE trigger and emits an N-clock low pulse.
    pit.write_control(0x12).unwrap();
    pit.write_counter(0, 3).unwrap();
    pit.set_gate(0, false).unwrap();
    pit.set_gate(0, true).unwrap();
    pit.advance_ticks(1);
    assert!(!pit.output(0).unwrap());
    pit.advance_ticks(2);
    assert!(!pit.output(0).unwrap());
    pit.advance_ticks(1);
    assert!(pit.output(0).unwrap());

    // Mode 2 produces a one-clock low pulse every N clocks.
    pit.write_control(0x14).unwrap();
    pit.write_counter(0, 3).unwrap();
    pit.advance_ticks(1);
    assert!(pit.output(0).unwrap());
    pit.advance_ticks(2);
    assert!(!pit.output(0).unwrap());
    assert!(pit.advance_ticks(1));
    assert!(pit.output(0).unwrap());

    // Mode 3 uses the longer high half for odd reload counts.
    pit.write_control(0x16).unwrap();
    pit.write_counter(0, 5).unwrap();
    pit.advance_ticks(1);
    pit.advance_ticks(2);
    assert!(pit.output(0).unwrap());
    pit.advance_ticks(1);
    assert!(!pit.output(0).unwrap());
    assert!(pit.advance_ticks(2));
    assert!(pit.output(0).unwrap());

    // Mode 4 is software loaded and emits one low clock at terminal count.
    pit.write_control(0x18).unwrap();
    pit.write_counter(0, 2).unwrap();
    pit.advance_ticks(1);
    pit.advance_ticks(2);
    assert!(!pit.output(0).unwrap());
    pit.advance_ticks(1);
    assert!(pit.output(0).unwrap());

    // Mode 5 waits for a hardware trigger, then emits a one-clock strobe.
    pit.write_control(0x1a).unwrap();
    pit.write_counter(0, 2).unwrap();
    pit.set_gate(0, false).unwrap();
    pit.set_gate(0, true).unwrap();
    pit.advance_ticks(1);
    pit.advance_ticks(2);
    assert!(!pit.output(0).unwrap());
    pit.advance_ticks(1);
    assert!(pit.output(0).unwrap());
}

#[test]
fn pit_count_latches_readback_and_byte_sequencing_are_independent() {
    let mut ports = MachinePorts::new();
    write_byte(&mut ports, 0x43, 0x30); // Counter 0, LSB/MSB, mode 0.
    write_byte(&mut ports, 0x40, 3);
    write_byte(&mut ports, 0x40, 0);
    ports.advance_ticks(1);

    write_byte(&mut ports, 0x43, 0x00); // Latch the current count.
    ports.advance_ticks(1);
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 3);
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 0);

    write_byte(&mut ports, 0x43, 0xe2); // Latch counter 0 status only.
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 0x30);
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 2);
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 0);
}

#[test]
fn pit_mode_two_count_updates_wait_for_the_current_period_boundary() {
    let mut ports = MachinePorts::new();
    write_byte(&mut ports, 0x43, 0x14); // Counter 0, LSB, mode 2.
    write_byte(&mut ports, 0x40, 4);
    ports.advance_ticks(1); // Load count 4.
    ports.advance_ticks(1); // Count is now 3.
    write_byte(&mut ports, 0x40, 6); // New count is deferred while running.
    ports.advance_ticks(4); // Finish the old period, reload 6, then count once.
    write_byte(&mut ports, 0x43, 0xe2); // Read back status, no count latch.
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 0x94);
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 5);
}

#[test]
fn pit_bcd_count_uses_four_digit_decimal_counting() {
    let mut ports = MachinePorts::new();
    write_byte(&mut ports, 0x43, 0x31); // Counter 0, LSB/MSB, mode 0, BCD.
    write_byte(&mut ports, 0x40, 0x12);
    write_byte(&mut ports, 0x40, 0x00);
    ports.advance_ticks(2); // Load 12, then count down to 11.
    write_byte(&mut ports, 0x43, 0x00); // Latch current count.
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 0x11);
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 0x00);
}

#[test]
fn paired_pic_resolves_priority_cascade_masks_and_eoi() {
    let mut ports = MachinePorts::new();
    initialize_pic(&mut ports);
    ports.request_irq(3).unwrap();
    ports.request_irq(1).unwrap();
    assert_eq!(ports.acknowledge_interrupt(), Some(0x21));
    assert_eq!(ports.pic().master_isr(), 1 << 1);

    ports.request_irq(0).unwrap();
    assert_eq!(ports.acknowledge_interrupt(), Some(0x20)); // Higher priority nests.
    assert_eq!(ports.pic().master_isr(), (1 << 0) | (1 << 1));
    write_byte(&mut ports, 0x20, 0x20); // Non-specific EOI clears IRQ0 first.
    assert_eq!(ports.acknowledge_interrupt(), None); // IRQ1 still blocks IRQ3.
    write_byte(&mut ports, 0x20, 0x20);
    assert_eq!(ports.acknowledge_interrupt(), Some(0x23));

    write_byte(&mut ports, 0xa0, 0x20);
    write_byte(&mut ports, 0x20, 0x20);
    ports.request_irq(10).unwrap();
    assert_eq!(ports.acknowledge_interrupt(), Some(0x2a));
    assert_eq!(ports.pic().master_isr(), 1 << 2);
    assert_eq!(ports.pic().slave_isr(), 1 << 2);
    write_byte(&mut ports, 0xa0, 0x20);
    write_byte(&mut ports, 0x20, 0x20);
    assert_eq!(ports.pic().master_isr(), 0);
    assert_eq!(ports.pic().slave_isr(), 0);
}

#[test]
fn masked_high_priority_irq_does_not_hide_unmasked_lower_priority_irq() {
    let mut ports = MachinePorts::new();
    initialize_pic(&mut ports);
    write_byte(&mut ports, 0x21, 0x01); // Mask IRQ0, leave IRQ1 enabled.
    ports.request_irq(0).unwrap();
    ports.request_irq(1).unwrap();
    assert_eq!(ports.acknowledge_interrupt(), Some(0x21));
    assert_eq!(ports.pic().master_irr() & 1, 1);
}

#[test]
fn pic_ports_select_irr_and_isr_and_read_the_mask_register() {
    let mut ports = MachinePorts::new();
    initialize_pic(&mut ports);
    ports.request_irq(1).unwrap();
    write_byte(&mut ports, 0x20, 0x0a); // Select IRR for command-port reads.
    assert_eq!(ports.read(0x20, PortWidth::Byte).unwrap(), 1 << 1);
    write_byte(&mut ports, 0x21, 1 << 1); // Mask IRQ1.
    assert_eq!(ports.read(0x21, PortWidth::Byte).unwrap(), 1 << 1);
    assert_eq!(ports.acknowledge_interrupt(), None);
    write_byte(&mut ports, 0x21, 0);
    assert_eq!(ports.acknowledge_interrupt(), Some(0x21));
    write_byte(&mut ports, 0x20, 0x0b); // Select ISR for command-port reads.
    assert_eq!(ports.read(0x20, PortWidth::Byte).unwrap(), 1 << 1);
}

#[test]
fn unsupported_pic_modes_are_reported_without_completing_initialization() {
    let mut ports = MachinePorts::new();
    write_byte(&mut ports, 0x20, 0x11);
    write_byte(&mut ports, 0x21, 0x20);
    write_byte(&mut ports, 0x21, 0x04);

    assert!(matches!(
        ports.write(0x21, PortWidth::Byte, 0x09), // 8086 mode plus unsupported SFNM.
        Err(PortError::Unsupported { port: 0x21, width: PortWidth::Byte, write: true })
    ));
    assert_eq!(ports.pic().master_mask(), 0);
    write_byte(&mut ports, 0x21, 0x01); // Retry ICW4 in supported 8086 mode.
    assert_eq!(ports.pic().master_mask(), 0);

    assert!(matches!(
        ports.write(0x20, PortWidth::Byte, 0x0c), // OCW3 poll request.
        Err(PortError::Unsupported { port: 0x20, width: PortWidth::Byte, write: true })
    ));
}

#[test]
fn unsupported_pic_8080_initialization_is_a_byte_write_gap_without_side_effects() {
    let mut ports = MachinePorts::new();
    assert!(matches!(
        ports.write(0x20, PortWidth::Byte, 0x10), // ICW1 selects unsupported 8080 mode.
        Err(PortError::Unsupported { port: 0x20, width: PortWidth::Byte, write: true })
    ));
    assert_eq!(ports.pic().master_mask(), 0xff);
}

#[test]
fn invalid_host_device_indices_are_internal_invariants() {
    let mut ports = MachinePorts::new();
    assert!(matches!(
        ports.request_irq(16),
        Err(PortError::InternalInvariant { port: 0x20, .. })
    ));
    assert!(matches!(
        ports.set_irq_level(16, true),
        Err(PortError::InternalInvariant { port: 0x20, .. })
    ));
    assert!(matches!(
        ports.set_pit_gate(3, true),
        Err(PortError::InternalInvariant { port: 0x43, .. })
    ));
}

#[test]
fn channel_two_gate_output_is_not_wired_to_irq_zero() {
    let mut ports = MachinePorts::new();
    write_byte(&mut ports, 0x43, 0x94); // Counter 2, LSB, mode 2.
    write_byte(&mut ports, 0x42, 2);
    ports.advance_ticks(1); // Load while channel 2 GATE is initially low.
    ports.set_pit_gate(2, true).unwrap();
    ports.advance_ticks(2); // Reload, then move OUT low.
    assert_eq!(ports.pit().output(2), Some(false));
    ports.set_pit_gate(2, false).unwrap(); // Mode 2 forces channel 2 OUT high.
    assert_eq!(ports.pic().master_irr() & 1, 0);
}

#[test]
fn unsupported_width_to_a_connected_device_fails_without_side_effects() {
    let mut ports = MachinePorts::new();
    assert!(matches!(
        ports.write(0x40, PortWidth::Word, 0x1234),
        Err(PortError::Unsupported { port: 0x40, width: PortWidth::Word, write: true })
    ));
    assert_eq!(ports.pic().master_mask(), 0xff);
}

#[test]
fn unconnected_machine_ports_return_open_bus_and_ignore_writes() {
    let mut ports = MachinePorts::new();

    assert_eq!(ports.read(0x56e0, PortWidth::Byte).unwrap(), 0xff);
    assert_eq!(ports.read(0x56e0, PortWidth::Word).unwrap(), 0xffff);
    assert_eq!(ports.read(0x56e0, PortWidth::Dword).unwrap(), 0xffff_ffff);
    ports.write(0x56e0, PortWidth::Byte, 0x12).unwrap();
    ports.write(0x56e0, PortWidth::Word, 0x3456).unwrap();
    ports.write(0x56e0, PortWidth::Dword, 0x789a_bcde).unwrap();

    assert_eq!(ports.pic().master_mask(), 0xff);
    assert!(!ports.interrupt_pending());
}

#[test]
fn byte_accesses_to_connected_pic_and_pit_still_dispatch() {
    let mut ports = MachinePorts::new();

    ports.write(0x21, PortWidth::Byte, 0x34).unwrap();
    assert_eq!(ports.read(0x21, PortWidth::Byte).unwrap(), 0x34);
    ports.write(0x43, PortWidth::Byte, 0x10).unwrap(); // Channel 0, LSB, mode 0.
    ports.write(0x40, PortWidth::Byte, 0x4a).unwrap();
    ports.advance_ticks(1);
    assert_eq!(ports.read(0x40, PortWidth::Byte).unwrap(), 0x4a);
}

#[test]
fn wide_transaction_overlapping_a_connected_port_fails_as_a_whole() {
    let mut ports = MachinePorts::new();
    assert!(matches!(
        ports.write(0x003f, PortWidth::Word, 0x1234),
        Err(PortError::Unsupported { port: 0x003f, width: PortWidth::Word, write: true })
    ));
    assert_eq!(ports.pit().output(0), Some(false));

    assert!(matches!(
        ports.read(0xffff, PortWidth::Word),
        Err(PortError::Unsupported { port: 0xffff, width: PortWidth::Word, write: false })
    ));
}

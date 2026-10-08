use super::*;

#[test]
fn dos_system_data_has_its_own_reservation_outside_the_program_arena() {
    let runtime = Runtime::load(&[0xcd, 0x20], &[], b"C:\\LAYOUT.COM").unwrap();
    let region = runtime.arenas.regions()
        .find(|region| region.kind() == RegionKind::DosSystem).unwrap();
    assert_eq!(region.base(), real_address(dos_kernel::SYSTEM_SEGMENT, 0));
    assert!(region.end_exclusive().0 <= real_address(ENV_SEGMENT, 0).0);
    let first = runtime.memory.read_u16(real_address(dos_kernel::SYSTEM_SEGMENT, 0x16)).unwrap();
    assert_eq!(first, ENV_SEGMENT - 1);
    assert!(real_address(first, 0).0 >= region.end_exclusive().0);
    assert_eq!(runtime.memory.read_u8(real_address(first, 0)).unwrap(), b'M');
    assert_eq!(runtime.memory.read_u16(real_address(first, 1)).unwrap(), MINIMUM_PSP_SEGMENT);
    assert_eq!(runtime.memory.read_u16(real_address(first, 3)).unwrap(), 2);
    let mut environment = [0; 18];
    runtime.memory.read(real_address(ENV_SEGMENT, 0), &mut environment).unwrap();
    assert_eq!(&environment, b"\0\0\x01\0C:\\LAYOUT.COM\0");
}

#[test]
fn bios_ports_and_memory_share_one_vga_adapter() {
    use guest_core::io::{PortIo, PortWidth};
    let mut runtime = Runtime::load(&[0xcd, 0x20], &[], b"C:\\VGABUS.COM").unwrap();
    let mut regs = guest_core::Registers::default();
    regs.set_ax(0x0012);
    runtime.devices.dispatch_interrupt(0x10, &mut regs, &mut runtime.memory.bus(), 0).unwrap();
    // Sequencer map mask: write only plane 1. One OUTW writes index then data.
    runtime.ports.write(0x3c4, PortWidth::Word, 0x0202).unwrap();
    runtime.memory.bus().write_u8(PhysAddr(0xa0000), 0x80).unwrap();
    // Graphics controller read-map selection observes the same VRAM written
    // through the CPU memory aperture, including raw physical reads.
    runtime.ports.write(0x3ce, PortWidth::Word, 0x0104).unwrap();
    assert_eq!(runtime.memory.read_u8(PhysAddr(0xa0000)).unwrap(), 0x80);
    runtime.ports.write(0x3ce, PortWidth::Word, 0x0004).unwrap();
    assert_eq!(runtime.memory.bus().read_u8(PhysAddr(0xa0000)).unwrap(), 0);
    regs.set_ax(0x0d00);
    regs.set_bx(0);
    regs.set_cx(0);
    regs.set_dx(0);
    runtime.devices.dispatch_interrupt(0x10, &mut regs, &mut runtime.memory.bus(), 0).unwrap();
    assert_eq!(regs.al(), 2);
}

#[test]
fn vga_functionality_pointer_refers_to_installed_guest_rom() {
    let runtime = Runtime::load(&[0xcd, 0x20], &[], b"C:\\VGAROM.COM").unwrap();
    let mut actual = [0; 16];
    let address = real_address(
        devices::vga::bios::FUNCTIONALITY_SEGMENT,
        devices::vga::bios::FUNCTIONALITY_OFFSET,
    );
    runtime.memory.read(address, &mut actual).unwrap();
    assert_eq!(actual, devices::vga::bios::functionality_table());
    assert!(runtime.memory.validate_write(address, 1).is_err());
}

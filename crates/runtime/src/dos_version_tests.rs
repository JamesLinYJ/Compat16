use super::*;

#[test]
fn reported_dos_version_initializes_and_updates_the_actual_psp() {
    let mut runtime = Runtime::load(&[0xcd, 0x20], &[], b"C:\\VERSION.COM").unwrap();
    let address = real_address(runtime.dos.psp_segment(), 0x40);
    let mut bytes = [0; 2];
    runtime.memory.read(address, &mut bytes).unwrap();
    assert_eq!(
        u16::from_le_bytes(bytes),
        dos_kernel::DEFAULT_DOS_REPORTED_VERSION
    );
    for version in [0x0007_u16, 0x1606, 0, 0xffff] {
        runtime.set_dos_reported_version(version).unwrap();
        runtime.memory.read(address, &mut bytes).unwrap();
        assert_eq!(u16::from_le_bytes(bytes), version);
    }
}

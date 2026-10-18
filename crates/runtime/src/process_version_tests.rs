use super::*;

#[test]
fn reported_dos_version_child_psp_does_not_copy_parent_override() {
    let mut runtime = Runtime::load(&[0xcd, 0x20], &[], b"C:\\PARENT.COM").unwrap();
    runtime.set_dos_reported_version(7).unwrap();
    let parent = runtime.dos.psp_segment();
    let mut tail = [0; 128];
    tail[1] = 0x0d;
    let request = DosExecRequest {
        program_path: b"CHILD.COM".to_vec(),
        environment_segment: 0,
        command_tail: tail,
        first_fcb: [0; 16],
        second_fcb: [0; 16],
    };
    install_child_psp(&mut runtime.memory, 0x2000, parent, 0x100, 0x3000, &request).unwrap();
    let mut bytes = [0; 2];
    runtime
        .memory
        .read(real_address(parent, 0x40), &mut bytes)
        .unwrap();
    assert_eq!(u16::from_le_bytes(bytes), 7);
    runtime
        .memory
        .read(real_address(0x2000, 0x40), &mut bytes)
        .unwrap();
    assert_eq!(
        u16::from_le_bytes(bytes),
        dos_kernel::DEFAULT_DOS_REPORTED_VERSION
    );
}

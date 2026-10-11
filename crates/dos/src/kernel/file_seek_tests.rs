use super::*;

fn registers(handle: u16, method: u8, offset: u32) -> Registers {
    Registers {
        eax: 0xaaaa_4200 | u32::from(method),
        ebx: 0xbbbb_0000 | u32::from(handle),
        ecx: 0xcccc_0000 | (offset >> 16),
        edx: 0xdddd_0000 | (offset & 0xffff),
        esi: 0xeeee_5678,
        edi: 0xffff_9abc,
        eflags: 0xad7,
        ds: 0x1000,
        es: 0x4321,
        ..Default::default()
    }
}

fn seek(
    dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory,
    handle: u16, method: u8, offset: u32, position: u32,
) {
    let mut regs = registers(handle, method, offset);
    let mut expected = regs.clone();
    expected.set_ax(position as u16);
    expected.set_dx((position >> 16) as u16);
    expected.set_carry(false);
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    assert_eq!(regs, expected);
}

#[test]
fn file_seek_unsigned_start_round_trips_cx_dx_and_shared_position_in_dx_ax() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"SEEK.DAT\0");
    let mut create = Registers::default();
    create.set_ah(0x3c);
    create.ds = 0x1000;
    create.set_dx(0x0100);
    dos.interrupt(0x21, &mut create, &mut memory, &mut host).unwrap();
    assert!(!create.carry());
    let handle = create.ax();
    let Handle::File(file) = dos.handles[&handle] else { panic!("expected file"); };
    let mut duplicate = Registers::default();
    duplicate.set_ah(0x45);
    duplicate.set_bx(handle);
    dos.interrupt(0x21, &mut duplicate, &mut memory, &mut host).unwrap();
    assert!(!duplicate.carry());
    let copy = duplicate.ax();

    for position in [0x7fff_ffff_u32, 0x8000_0000, 0xffff_ffff] {
        seek(&mut dos, &mut host, &mut memory, handle, 0, position, position);
        seek(&mut dos, &mut host, &mut memory, copy, 1, 0, position);
        seek(&mut dos, &mut host, &mut memory, copy, 1, u32::MAX, position - 1);
        seek(&mut dos, &mut host, &mut memory, handle, 1, 0, position - 1);
        assert!(host.file_for(file).unwrap().bytes.is_empty());
    }
    seek(&mut dos, &mut host, &mut memory, copy, 1, 0x8000_0000, 0x7fff_fffe);
    assert!(host.file_for(file).unwrap().bytes.is_empty());
}

#[test]
fn file_seek_signed_relative_offsets_and_failure_carry_preserve_frame() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let file = host.file_create(b"SEEK.DAT", 0).unwrap();
    host.file_write(file, b"abcd").unwrap();
    dos.handles.insert(5, Handle::File(file));
    seek(&mut dos, &mut host, &mut memory, 5, 2, (-1_i32) as u32, 3);
    seek(&mut dos, &mut host, &mut memory, 5, 1, (-2_i32) as u32, 1);
    seek(&mut dos, &mut host, &mut memory, 5, 2, (-4_i32) as u32, 0);

    for (handle, method, offset, error) in [
        (5, 1, u32::MAX, DosErrorCode::InvalidData),
        (5, 2, (-5_i32) as u32, DosErrorCode::InvalidData),
        (5, 3, 0, DosErrorCode::InvalidFunction),
        (99, 0, 0, DosErrorCode::InvalidHandle),
    ] {
        let mut regs = registers(handle, method, offset);
        regs.set_carry(false);
        let mut expected = regs.clone();
        expected.set_ax(error as u16);
        expected.set_carry(true);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert_eq!(regs, expected);
        assert_eq!(host.file_for(file).unwrap().cursor, 0);
    }
    assert_eq!(host.file_for(file).unwrap().bytes, b"abcd");
}

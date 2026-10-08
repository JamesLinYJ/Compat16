use super::state::Handle;
use super::tests::{TestHost, TestMemory};
use super::DosKernel;
use crate::{DosAction, DosHostFile};
use guest_core::Registers;

fn invoke(
    dos: &mut DosKernel,
    regs: &mut Registers,
    memory: &mut TestMemory,
    host: &mut TestHost,
) -> DosAction {
    dos.interrupt(0x21, regs, memory, host).unwrap()
}

fn query(
    dos: &mut DosKernel,
    handle: u16,
    regs: &mut Registers,
    memory: &mut TestMemory,
    host: &mut TestHost,
) -> DosAction {
    regs.set_ax(0x4400);
    regs.set_bx(handle);
    invoke(dos, regs, memory, host)
}

#[test]
fn ioctl_4400_reports_only_the_supported_standard_device_bits() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();

    for (handle, expected) in [(0, 0x00e1), (1, 0x00e2), (2, 0x00e2)] {
        regs.eflags = 0x0000_0042;
        assert_eq!(query(&mut dos, handle, &mut regs, &mut memory, &mut host), DosAction::Continue);
        assert_eq!(regs.dx(), expected);
        assert_eq!(regs.bx(), handle);
        assert_eq!(regs.eflags & 1, 0);
        assert_ne!(regs.eflags & 0x40, 0, "ZF must be preserved");
    }

    host.set_standard_input_eof(true);
    query(&mut dos, 0, &mut regs, &mut memory, &mut host);
    assert_eq!(regs.dx(), 0x00a1, "device-info bit 6 is clear on input EOF");
    assert!(!regs.carry());
}

#[test]
fn ioctl_4400_file_drive_written_state_and_duplicates_follow_host_identity() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    memory.put(0x2500, b"STATUS.TXT\0");
    regs.ds = 0x0250;
    regs.set_dx(0);
    regs.set_ax(0x3c00);
    invoke(&mut dos, &mut regs, &mut memory, &mut host);
    assert!(!regs.carry());
    let file_handle = regs.ax();

    query(&mut dos, file_handle, &mut regs, &mut memory, &mut host);
    assert_eq!(regs.dx(), 0x0042, "C: and not-yet-written bits");

    regs.set_ax(0x4500);
    regs.set_bx(file_handle);
    invoke(&mut dos, &mut regs, &mut memory, &mut host);
    assert!(!regs.carry());
    let duplicate = regs.ax();

    memory.put(0x2600, b"X");
    regs.ds = 0x0260;
    regs.set_dx(0);
    regs.set_cx(1);
    regs.set_ax(0x4000);
    regs.set_bx(file_handle);
    invoke(&mut dos, &mut regs, &mut memory, &mut host);
    assert!(!regs.carry());

    query(&mut dos, duplicate, &mut regs, &mut memory, &mut host);
    assert_eq!(regs.dx(), 0x0002, "write state is shared through a duplicate");

    regs.set_ax(0x3e00);
    regs.set_bx(file_handle);
    invoke(&mut dos, &mut regs, &mut memory, &mut host);
    assert!(!regs.carry());
    assert_eq!(query(&mut dos, file_handle, &mut regs, &mut memory, &mut host), DosAction::Continue);
    assert!(regs.carry());
    assert_eq!(regs.ax(), 6, "closed DOS handle reports InvalidHandle");

    query(&mut dos, duplicate, &mut regs, &mut memory, &mut host);
    assert!(!regs.carry(), "closing one duplicate leaves the other valid");
    assert_eq!(regs.dx(), 0x0002);
}

#[test]
fn ioctl_4400_rejects_invalid_guest_and_stale_host_handles() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.set_dx(0x1357);

    query(&mut dos, 0xffff, &mut regs, &mut memory, &mut host);
    assert!(regs.carry());
    assert_eq!(regs.ax(), 6);
    assert_eq!(regs.dx(), 0x1357, "error must not overwrite the result register");

    dos.handles.insert(7, Handle::File(DosHostFile(0xdead)));
    query(&mut dos, 7, &mut regs, &mut memory, &mut host);
    assert!(regs.carry());
    assert_eq!(regs.ax(), 6, "stale host token reports InvalidHandle");
}

#[test]
fn ioctl_4400_does_not_misreport_redirected_streams_as_devices() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    host.redirect_standard_streams();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();

    query(&mut dos, 0, &mut regs, &mut memory, &mut host);
    assert!(regs.carry());
    assert_eq!(regs.ax(), 1, "host without a DOS mapping reports InvalidFunction");
}

#[test]
fn ioctl_unimplemented_subfunctions_return_invalid_function() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();

    for subfunction in [0x01, 0x02, 0x06, 0x07, 0x08, 0xff] {
        regs.set_ax(0x4400 | subfunction);
        regs.set_bx(0);
        assert_eq!(invoke(&mut dos, &mut regs, &mut memory, &mut host), DosAction::Continue);
        assert!(regs.carry());
        assert_eq!(regs.ax(), 1, "AL={subfunction:02x} must not fall through as unhandled");
    }
}

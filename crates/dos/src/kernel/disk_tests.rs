use crate::{DosAction, DosDiskSpace, DosKernel};
use guest_core::Registers;

use super::tests::{TestHost, TestMemory};

fn call_disk_space(drive: u8, host: &mut TestHost) -> Registers {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.set_ax(0x3600);
    regs.set_dx(u16::from(drive));
    assert_eq!(dos.interrupt(0x21, &mut regs, &mut memory, host).unwrap(), DosAction::Continue);
    regs
}

#[test]
fn ah36_reports_dos_allocation_geometry_for_mapped_c_drive() {
    let mut host = TestHost::default();
    host.set_disk_space(DosDiskSpace {
        total_bytes: 100 * 1024 * 1024,
        available_bytes: 50 * 1024 * 1024,
    });

    let regs = call_disk_space(3, &mut host);
    assert_eq!(regs.ax(), 4); // 2 KiB clusters keep the count within 16 bits.
    assert_eq!(regs.cx(), 512);
    assert_eq!(regs.dx(), 51_200);
    assert_eq!(regs.bx(), 25_600);
    assert!(!regs.carry());
}

#[test]
fn ah36_resolves_drive_zero_through_the_host_current_drive() {
    let mut host = TestHost::default();
    host.set_current_drive(2);
    host.set_disk_space(DosDiskSpace { total_bytes: 64 * 1024, available_bytes: 32 * 1024 });

    let regs = call_disk_space(0, &mut host);
    assert_eq!(regs.cx(), 512);
    assert_eq!(regs.dx(), 128);
    assert!(!regs.carry());
}

#[test]
fn ah36_returns_ffff_for_unmapped_invalid_or_empty_drives() {
    let mut host = TestHost::default();
    let missing_a = call_disk_space(1, &mut host);
    assert_eq!(missing_a.ax(), u16::MAX);
    assert!(!missing_a.carry());

    let invalid_drive = call_disk_space(27, &mut host);
    assert_eq!(invalid_drive.ax(), u16::MAX);
    assert!(!invalid_drive.carry());

    host.set_disk_space(DosDiskSpace { total_bytes: 0, available_bytes: 0 });
    let empty = call_disk_space(3, &mut host);
    assert_eq!(empty.ax(), u16::MAX);
    assert!(!empty.carry());
}

#[test]
fn ah36_saturates_at_dos5_limit_and_caps_free_clusters_to_total() {
    let mut host = TestHost::default();
    host.set_disk_space(DosDiskSpace {
        total_bytes: 4 * 1024 * 1024 * 1024,
        available_bytes: u64::MAX,
    });

    let regs = call_disk_space(3, &mut host);
    assert_eq!(regs.ax(), 64);
    assert_eq!(regs.cx(), 512);
    assert_eq!(regs.dx(), u16::MAX);
    assert_eq!(regs.bx(), regs.dx());
    assert!(!regs.carry());
}

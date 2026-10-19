//! Native file information through capability-rooted KERNEL opens.

use super::*;
use dos_kernel::{DosErrorCode, DosIoctlObjectInfo, DosSeekOrigin};

fn info(files: &Win16Files, file: runtime::Win16HostFile, written: bool) {
    let drive = fixture_filesystem().drive();
    assert_eq!(files.ioctl_info(file).unwrap(), DosIoctlObjectInfo::File { drive, written });
}

#[test]
fn file_ioctl_native_query_preserves_cursor_bytes_and_timestamp() {
    let fixture = TestFile::new();
    let mut files = Win16Files::new();
    let file = open(&mut files, codec(), &fixture.path(), 0, vec![0; OFSTRUCT_BYTES]).unwrap().file.unwrap();
    let bytes = std::fs::read(&fixture.0).unwrap();
    let stamp = files.write_time(file).unwrap();
    files.seek(file, 7, 0).unwrap();
    for _ in 0..3 { info(&files, file, false); }
    assert_eq!(files.seek(file, 0, 1).unwrap(), Some(7));
    files.commit(file).unwrap();
    info(&files, file, false);
    assert_eq!(files.write_time(file).unwrap(), stamp);
    assert_eq!(std::fs::read(&fixture.0).unwrap(), bytes);
    files.close_checked(file).unwrap();
    assert_eq!(files.ioctl_info(file).unwrap_err().code, DosErrorCode::InvalidHandle);
    fixture.assert_unowned();
}

#[test]
fn file_ioctl_native_tracks_kernel_dos_truncate_timestamp_and_lz_writes() {
    for operation in 0..6 {
        let fixture = TestFile::new();
        let source = TestFile::new();
        let mut files = Win16Files::new();
        let file = open(&mut files, codec(), &fixture.path(), 2, vec![0; OFSTRUCT_BYTES]).unwrap().file.unwrap();
        info(&files, file, false);
        files.read(file, 1).unwrap();
        files.seek(file, 2, 0).unwrap();
        info(&files, file, false);
        match operation {
            0 => { assert_eq!(files.write(file, b"K").unwrap(), Some(1)); }
            1 => { assert_eq!(files.dos_write(file, b"D").unwrap(), 1); }
            2 => { assert_eq!(files.write(file, b"").unwrap(), Some(0)); }
            3 => { assert_eq!(files.dos_write(file, b"").unwrap(), 0); }
            4 => {
                let (time, date) = files.write_time(file).unwrap();
                files.set_write_time(file, time, date).unwrap();
            }
            5 => {
                let input = open(&mut files, codec(), &source.path(), 0, vec![0; OFSTRUCT_BYTES]).unwrap().file.unwrap();
                assert!(crate::windows::win16_compat_calls_lzexpand::copy(&mut files, input, file).unwrap().unwrap() > 0);
                info(&files, input, false);
                files.close_checked(input).unwrap();
            }
            _ => unreachable!(),
        }
        info(&files, file, true);
        files.commit(file).unwrap();
        info(&files, file, true);
        files.close_checked(file).unwrap();
        fixture.assert_unowned(); source.assert_unowned();
    }
}

#[test]
fn file_ioctl_native_failed_write_and_time_update_leave_readonly_open_clean() {
    let fixture = TestFile::new();
    let mut files = Win16Files::new();
    let file = open(&mut files, codec(), &fixture.path(), 0, vec![0; OFSTRUCT_BYTES]).unwrap().file.unwrap();
    assert_eq!(files.write(file, b"X").unwrap(), None);
    assert!(files.dos_write(file, b"X").is_err());
    assert!(files.dos_write(file, b"").is_err());
    let (time, date) = files.write_time(file).unwrap();
    assert!(files.set_write_time(file, time, date).is_err());
    info(&files, file, false);
    assert_eq!(files.dos_seek(file, 0, DosSeekOrigin::Current).unwrap(), 0);
    files.close_checked(file).unwrap();
    fixture.assert_unowned();
}

#[test]
fn file_ioctl_native_rejects_unmapped_imports_devices_and_lz_streams() {
    let fixture = TestFile::new();
    let mut files = Win16Files::new();
    // Direct imports have no proven DOS mount mapping, even if they are disks.
    let imported = files.open(codec(), &fixture.path(), 0).unwrap().unwrap();
    assert_eq!(files.ioctl_info(imported).unwrap_err().code, DosErrorCode::InvalidFunction);
    files.close_checked(imported).unwrap();
    let device = files.open(codec(), b"NUL", 0).unwrap().unwrap();
    assert_eq!(files.ioctl_info(device).unwrap_err().code, DosErrorCode::InvalidFunction);
    files.close_checked(device).unwrap();
    let file = open(&mut files, codec(), &fixture.path(), 0, vec![0; OFSTRUCT_BYTES]).unwrap().file.unwrap();
    let runtime::Win16HostLzInit::File(stream) =
        crate::windows::win16_compat_calls_lzexpand::init(&mut files, file, true).unwrap() else { panic!("LZInit failed"); };
    assert_eq!(files.ioctl_info(stream).unwrap_err().code, DosErrorCode::InvalidFunction);
    files.close_checked(stream).unwrap();
    assert_eq!(files.ioctl_info(file).unwrap_err().code, DosErrorCode::InvalidHandle);
    fixture.assert_unowned();
}

use dos_kernel::{DosErrorCode, DosFileAccess, DosFileSharing, DosSeekOrigin};

use super::{Filesystem, TestDirectory};

#[test]
fn file_seek_start_uses_unsigned_dword_and_shares_cursor_without_extending_file() {
    let directory = TestDirectory::new();
    let path = directory.0.join("SEEK.DAT");
    std::fs::write(&path, b"").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs
        .file_open(b"SEEK.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone)
        .unwrap();
    let copy = fs.file_duplicate(file).unwrap();

    // Read-only seeks change only the cursor, never file size or allocation.
    for position in [0x7fff_ffff_u32, 0x8000_0000, 0xffff_ffff] {
        assert_eq!(
            fs.file_seek(file, position as i32, DosSeekOrigin::Start).unwrap(),
            position,
        );
        for handle in [file, copy] {
            assert_eq!(fs.file_seek(handle, 0, DosSeekOrigin::Current).unwrap(), position);
            let status = fs.file_status(handle).unwrap();
            assert_eq!((status.position, status.size), (position, 0));
        }
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert_eq!(fs.file_seek(copy, -1, DosSeekOrigin::Current).unwrap(), position - 1);
        assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), position - 1);
    }
    assert_eq!(fs.file_seek(copy, i32::MIN, DosSeekOrigin::Current).unwrap(), 0x7fff_fffe);
    assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 0x7fff_fffe);
    fs.file_close(file).unwrap();
    assert_eq!(fs.file_seek(copy, 0, DosSeekOrigin::Current).unwrap(), 0x7fff_fffe);
    fs.file_close(copy).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
}

#[test]
fn file_seek_relative_offsets_stay_signed_and_rejected_targets_preserve_cursor() {
    let directory = TestDirectory::new();
    let path = directory.0.join("SEEK.DAT");
    std::fs::write(&path, b"abcd").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs
        .file_open(b"SEEK.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone)
        .unwrap();
    assert_eq!(fs.file_seek(file, -1, DosSeekOrigin::End).unwrap(), 3);
    assert_eq!(fs.file_seek(file, -2, DosSeekOrigin::Current).unwrap(), 1);
    assert_eq!(fs.file_seek(file, -4, DosSeekOrigin::End).unwrap(), 0);

    // Preserve the existing host range policy; before-start DOS semantics are
    // a separate compatibility question from unsigned absolute positions.
    for (offset, origin) in [(-1, DosSeekOrigin::Current), (-5, DosSeekOrigin::End)] {
        assert_eq!(fs.file_seek(file, offset, origin).unwrap_err().code, DosErrorCode::InvalidData);
        assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 0);
    }
    assert_eq!(fs.file_seek(file, -1, DosSeekOrigin::Start).unwrap(), u32::MAX);
    assert_eq!(fs.file_seek(file, 1, DosSeekOrigin::Current).unwrap_err().code, DosErrorCode::InvalidData);
    assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), u32::MAX);
    assert_eq!(fs.file_seek(file, -1, DosSeekOrigin::End).unwrap(), 3);
    let mut last = [0];
    assert_eq!(fs.file_read(file, &mut last).unwrap(), 1);
    assert_eq!(&last, b"d");
    fs.file_close(file).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"abcd");
}

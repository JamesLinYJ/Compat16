use std::io::{Seek, SeekFrom};

use dos_kernel::{DosErrorCode, DosFileAccess, DosFileSharing, DosSeekOrigin};

use super::super::files::file_has_unread_bytes;
use super::{Filesystem, TestDirectory};

#[test]
fn file_input_status_preserves_data_and_shared_cursor() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("INPUT.DAT"), b"abc").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs
        .file_open(b"INPUT.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone)
        .unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    let independent = fs
        .file_open(b"INPUT.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone)
        .unwrap();
    let info = fs.file_ioctl_info(file).unwrap();

    for _ in 0..3 {
        assert!(fs.file_input_status(file).unwrap());
        assert!(fs.file_input_status(copy).unwrap());
        assert_eq!(fs.file_seek(copy, 0, DosSeekOrigin::Current).unwrap(), 0);
        assert_eq!(fs.file_ioctl_info(file).unwrap(), info);
    }
    let mut first = [0; 2];
    assert_eq!(fs.file_read(file, &mut first).unwrap(), first.len());
    assert_eq!(&first, b"ab");
    assert!(fs.file_input_status(copy).unwrap());
    assert_eq!(fs.file_seek(copy, 0, DosSeekOrigin::Current).unwrap(), 2);
    let mut last = [0];
    assert_eq!(fs.file_read(copy, &mut last).unwrap(), 1);
    assert_eq!(&last, b"c");
    for _ in 0..3 {
        assert!(!fs.file_input_status(file).unwrap());
        assert!(!fs.file_input_status(copy).unwrap());
        assert!(fs.file_input_status(independent).unwrap());
        assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 3);
        assert_eq!(fs.file_ioctl_info(copy).unwrap(), info);
    }

    fs.file_close(file).unwrap();
    assert_eq!(
        fs.file_input_status(file).unwrap_err().code,
        DosErrorCode::InvalidHandle,
    );
    assert!(!fs.file_input_status(copy).unwrap());
    fs.file_seek(copy, 0, DosSeekOrigin::Start).unwrap();
    assert!(fs.file_input_status(copy).unwrap());
    assert_eq!(fs.file_read(copy, &mut last).unwrap(), 1);
    assert_eq!(&last, b"a");
    fs.file_close(copy).unwrap();
    assert_eq!(
        fs.file_input_status(copy).unwrap_err().code,
        DosErrorCode::InvalidHandle,
    );
    fs.file_close(independent).unwrap();
    assert_eq!(std::fs::read(directory.0.join("INPUT.DAT")).unwrap(), b"abc");
}

#[test]
fn file_input_status_uses_live_size_at_empty_eof_and_beyond_eof() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create(b"INPUT.DAT", 0).unwrap();
    assert!(!fs.file_input_status(file).unwrap());
    fs.file_write(file, b"abc").unwrap();
    assert!(!fs.file_input_status(file).unwrap());
    fs.file_seek(file, 4, DosSeekOrigin::Start).unwrap();
    assert!(!fs.file_input_status(file).unwrap());
    assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 4);
    fs.file_seek(file, 1, DosSeekOrigin::Start).unwrap();
    assert!(fs.file_input_status(file).unwrap());
    fs.file_set_len(file, 1).unwrap();
    assert!(!fs.file_input_status(file).unwrap());
    fs.file_set_len(file, 0).unwrap();
    assert!(!fs.file_input_status(file).unwrap());
    fs.file_set_len(file, 3).unwrap();
    assert!(fs.file_input_status(file).unwrap());
    assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 1);
    fs.file_close(file).unwrap();
}

#[test]
fn file_input_status_keeps_native_cursor_high_bits_without_extending_file() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("INPUT.DAT"), b"abc").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs
        .file_open(b"INPUT.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone)
        .unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    let shared = fs.files.get(&file).unwrap().clone();
    let position = (1_u64 << 32) + 1;
    // Seeking a read-only handle past EOF changes only the native cursor. It
    // does not extend the three-byte fixture or allocate a multi-GiB file.
    shared
        .lock()
        .unwrap()
        .file
        .seek(SeekFrom::Start(position))
        .unwrap();
    let status = fs.file_status(file).unwrap();
    assert_eq!((status.position, status.size), (1, 3));
    for _ in 0..3 {
        assert!(!fs.file_input_status(file).unwrap());
        assert!(!fs.file_input_status(copy).unwrap());
        let mut handle = shared.lock().unwrap();
        assert_eq!(handle.file.stream_position().unwrap(), position);
        assert_eq!(handle.file.metadata().unwrap().len(), 3);
    }
    drop(shared);
    fs.file_close(file).unwrap();
    fs.file_close(copy).unwrap();
    assert_eq!(std::fs::read(directory.0.join("INPUT.DAT")).unwrap(), b"abc");
}

#[test]
fn file_input_status_compares_full_native_width() {
    let dword = 1_u64 << 32;
    for (position, length, ready) in [
        (0, 0, false),
        (0, 1, true),
        (1, 1, false),
        (2, 1, false),
        (1, dword, true),
        (dword - 1, dword, true),
        (dword, dword, false),
        (dword + 1, 3, false),
        (dword + 16, dword + 17, true),
        (dword + 17, dword + 17, false),
        (dword + 18, dword + 17, false),
        (u64::MAX - 1, u64::MAX, true),
        (u64::MAX, u64::MAX, false),
    ] {
        assert_eq!(
            file_has_unread_bytes(position, length),
            ready,
            "position={position}, length={length}",
        );
    }
}

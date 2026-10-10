//! Native commit tests observe file contents and open-description state.
//! They do not establish persistence across a crash or loss of power.

use std::io::{Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use dos_kernel::{
    DosErrorCode, DosFileAccess, DosFileDisposition, DosFileOpenRequest, DosFileSharing,
    DosHostFile, DosIoctlObjectInfo, DosSeekOrigin,
};

use super::super::OpenFile;
use super::{Filesystem, TestDirectory};

fn request(disposition: DosFileDisposition, access: DosFileAccess) -> DosFileOpenRequest {
    DosFileOpenRequest {
        access,
        sharing: DosFileSharing::DenyNone,
        disposition,
        attributes: 0,
    }
}

#[test]
fn file_commit_preserves_contents_shared_cursor_and_written_fact() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create(b"COMMIT.DAT", 0).unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    assert_eq!(fs.file_write(file, b"abcdef").unwrap(), 6);
    fs.file_seek(copy, 2, DosSeekOrigin::Start).unwrap();
    let status = fs.file_status(file).unwrap();
    let written = DosIoctlObjectInfo::File {
        drive: fs.drive(),
        written: true,
    };
    let shared = Arc::clone(fs.files.get(&file).unwrap());
    let next_file = fs.next_file;

    for token in [file, copy, file] {
        fs.file_commit(token).unwrap();
        assert_eq!(fs.file_status(file).unwrap(), status);
        assert_eq!(fs.file_status(copy).unwrap(), status);
        assert_eq!(fs.file_ioctl_info(token).unwrap(), written);
        assert_eq!(fs.files.len(), 2);
        assert_eq!(fs.next_file, next_file);
        assert!(Arc::ptr_eq(&shared, fs.files.get(&token).unwrap()));
    }
    assert_eq!(std::fs::read(directory.0.join("COMMIT.DAT")).unwrap(), b"abcdef");
    let mut bytes = [0; 2];
    assert_eq!(fs.file_read(copy, &mut bytes).unwrap(), 2);
    assert_eq!(&bytes, b"cd");
    assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 4);

    fs.file_close(file).unwrap();
    assert_eq!(fs.file_commit(file).unwrap_err().code, DosErrorCode::InvalidHandle);
    assert_eq!(fs.file_write(copy, b"XY").unwrap(), 2);
    fs.file_commit(copy).unwrap();
    assert_eq!(fs.file_seek(copy, 0, DosSeekOrigin::Current).unwrap(), 6);
    assert_eq!(fs.file_ioctl_info(copy).unwrap(), written);
    drop(shared);
    fs.file_close(copy).unwrap();
    assert_eq!(std::fs::read(directory.0.join("COMMIT.DAT")).unwrap(), b"abcdXY");
}

#[test]
fn file_commit_accepts_clean_read_only_normal_and_extended_access() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("READONLY.DAT"), b"unchanged").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.file_set_attributes(b"READONLY.DAT", 0x01).unwrap();
    for extended in [false, true] {
        let file = if extended {
            fs.file_extended_open(
                b"READONLY.DAT",
                request(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadOnly),
            )
            .unwrap()
            .file
        } else {
            fs.file_open(b"READONLY.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone)
                .unwrap()
        };
        let copy = fs.file_duplicate(file).unwrap();
        let clean = DosIoctlObjectInfo::File {
            drive: fs.drive(),
            written: false,
        };
        assert_eq!(fs.files.get(&file).unwrap().lock().unwrap().access, DosFileAccess::ReadOnly);
        assert_eq!(fs.file_write(file, b"bad").unwrap_err().code, DosErrorCode::AccessDenied);
        fs.file_seek(file, 3, DosSeekOrigin::Start).unwrap();
        let status = fs.file_status(file).unwrap();
        for token in [file, copy] {
            fs.file_commit(token).unwrap();
            assert_eq!(fs.file_status(token).unwrap(), status);
            assert_eq!(fs.file_ioctl_info(token).unwrap(), clean);
        }
        fs.file_close(file).unwrap();
        fs.file_commit(copy).unwrap();
        let mut bytes = [0; 6];
        assert_eq!(fs.file_read(copy, &mut bytes).unwrap(), 6);
        assert_eq!(&bytes, b"hanged");
        fs.file_close(copy).unwrap();
    }
    assert_eq!(std::fs::read(directory.0.join("READONLY.DAT")).unwrap(), b"unchanged");
    fs.file_set_attributes(b"READONLY.DAT", 0).unwrap();
}

#[test]
fn file_commit_handles_creation_before_any_write() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let files = [
        (
            b"CREATE.DAT".as_slice(),
            fs.file_create(b"CREATE.DAT", 0).unwrap(),
            DosFileAccess::ReadWrite,
        ),
        (
            b"NEW.DAT".as_slice(),
            fs.file_create_new(b"NEW.DAT", 0).unwrap(),
            DosFileAccess::ReadWrite,
        ),
        (
            b"EXTNEW.DAT".as_slice(),
            fs.file_extended_open(
                b"EXTNEW.DAT",
                request(DosFileDisposition::CreateNew, DosFileAccess::WriteOnly),
            )
            .unwrap()
            .file,
            DosFileAccess::WriteOnly,
        ),
        (
            b"EXTOPEN.DAT".as_slice(),
            fs.file_extended_open(
                b"EXTOPEN.DAT",
                request(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadWrite),
            )
            .unwrap()
            .file,
            DosFileAccess::ReadWrite,
        ),
    ];
    let clean = DosIoctlObjectInfo::File {
        drive: fs.drive(),
        written: false,
    };
    for (path, file, access) in files {
        assert_eq!(fs.files.get(&file).unwrap().lock().unwrap().access, access);
        assert_eq!(fs.file_ioctl_info(file).unwrap(), clean);
        fs.file_commit(file).unwrap();
        let status = fs.file_status(file).unwrap();
        assert_eq!((status.size, status.position), (0, 0));
        assert_eq!(fs.file_ioctl_info(file).unwrap(), clean);
        assert_eq!(fs.file_write(file, b"after commit").unwrap(), 12);
        fs.file_commit(file).unwrap();
        fs.file_close(file).unwrap();
        assert_eq!(
            std::fs::read(directory.0.join(std::str::from_utf8(path).unwrap())).unwrap(),
            b"after commit",
        );
    }
}

#[test]
fn file_commit_uses_handle_access_instead_of_read_only_file_attributes() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create_new(b"READATTR.DAT", 0x01).unwrap();
    assert_eq!(fs.files.get(&file).unwrap().lock().unwrap().access, DosFileAccess::ReadWrite);
    assert_ne!(fs.file_get_attributes(b"READATTR.DAT").unwrap() & 1, 0);
    fs.file_commit(file).unwrap();
    assert_eq!(fs.file_write(file, b"initial write").unwrap(), 13);
    fs.file_commit(file).unwrap();
    fs.file_close(file).unwrap();
    assert_eq!(std::fs::read(directory.0.join("READATTR.DAT")).unwrap(), b"initial write");
    assert_ne!(fs.file_get_attributes(b"READATTR.DAT").unwrap() & 1, 0);
    fs.file_set_attributes(b"READATTR.DAT", 0).unwrap();
}

#[test]
fn file_commit_handles_truncation_and_length_changes_without_moving_cursor() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("TRUNCATE.DAT"), b"old contents").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create(b"TRUNCATE.DAT", 0).unwrap();
    let clean = DosIoctlObjectInfo::File {
        drive: fs.drive(),
        written: false,
    };
    assert_eq!(fs.file_ioctl_info(file).unwrap(), clean);
    fs.file_commit(file).unwrap();
    assert_eq!(fs.file_ioctl_info(file).unwrap(), clean);
    assert_eq!(std::fs::metadata(directory.0.join("TRUNCATE.DAT")).unwrap().len(), 0);

    fs.file_set_len(file, 5).unwrap();
    fs.file_seek(file, 9, DosSeekOrigin::Start).unwrap();
    fs.file_commit(file).unwrap();
    let status = fs.file_status(file).unwrap();
    assert_eq!((status.size, status.position), (5, 9));
    assert_eq!(
        fs.file_ioctl_info(file).unwrap(),
        DosIoctlObjectInfo::File {
            drive: fs.drive(),
            written: true,
        },
    );
    assert_eq!(std::fs::metadata(directory.0.join("TRUNCATE.DAT")).unwrap().len(), 5);
    fs.file_close(file).unwrap();
}

#[test]
fn file_commit_preserves_requested_access_and_exclusive_sharing() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("EXCLUSIVE.DAT"), b"abc").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    for extended in [false, true] {
        for access in [DosFileAccess::WriteOnly, DosFileAccess::ReadWrite] {
            let file = if extended {
                let mut open = request(DosFileDisposition::OpenExisting, access);
                open.sharing = DosFileSharing::DenyAll;
                fs.file_extended_open(b"EXCLUSIVE.DAT", open).unwrap().file
            } else {
                fs.file_open(b"EXCLUSIVE.DAT", access, DosFileSharing::DenyAll).unwrap()
            };
            assert_eq!(fs.files.get(&file).unwrap().lock().unwrap().access, access);
            let copy = fs.file_duplicate(file).unwrap();
            fs.file_commit(file).unwrap();
            assert_eq!(fs.file_write(file, b"x").unwrap(), 1);
            fs.file_close(file).unwrap();
            fs.file_commit(copy).unwrap();
            assert_eq!(fs.file_seek(copy, 0, DosSeekOrigin::Current).unwrap(), 1);
            assert_eq!(fs.file_open(
                b"EXCLUSIVE.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone,
            ).unwrap_err().code, DosErrorCode::SharingViolation);
            if access == DosFileAccess::WriteOnly {
                assert_eq!(
                    fs.file_read(copy, &mut [0]).unwrap_err().code,
                    DosErrorCode::AccessDenied,
                );
            }
            fs.file_close(copy).unwrap();
            assert_eq!(std::fs::read(directory.0.join("EXCLUSIVE.DAT")).unwrap(), b"xbc");
        }
    }
}

#[test]
fn file_commit_uses_the_exact_owned_token_and_rejects_closed_tokens() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.next_file = (1_u64 << 32) + 7;
    let file = fs.file_create(b"TOKEN.DAT", 0).unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    for invalid in [
        DosHostFile(0),
        DosHostFile(7),
        DosHostFile(file.0 + (1_u64 << 32)),
        DosHostFile(u64::MAX),
    ] {
        assert_eq!(fs.file_commit(invalid).unwrap_err().code, DosErrorCode::InvalidHandle);
        assert_eq!(fs.files.len(), 2);
    }
    fs.file_commit(file).unwrap();
    fs.file_close(file).unwrap();
    assert_eq!(fs.file_commit(file).unwrap_err().code, DosErrorCode::InvalidHandle);
    fs.file_commit(copy).unwrap();
    fs.file_close(copy).unwrap();
    assert_eq!(fs.file_commit(copy).unwrap_err().code, DosErrorCode::InvalidHandle);
    assert!(fs.files.is_empty());
}

#[test]
fn file_commit_keeps_the_full_native_cursor() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create(b"CURSOR.DAT", 0).unwrap();
    fs.file_write(file, b"abc").unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    let shared = Arc::clone(fs.files.get(&file).unwrap());
    let position = (1_u64 << 32) + 2;
    shared
        .lock()
        .unwrap()
        .file
        .seek(SeekFrom::Start(position))
        .unwrap();
    for token in [file, copy] {
        fs.file_commit(token).unwrap();
        let mut handle = shared.lock().unwrap();
        assert_eq!(handle.file.stream_position().unwrap(), position);
        assert_eq!(handle.file.metadata().unwrap().len(), 3);
    }
    drop(shared);
    fs.file_close(file).unwrap();
    fs.file_close(copy).unwrap();
    assert_eq!(std::fs::read(directory.0.join("CURSOR.DAT")).unwrap(), b"abc");
}

#[test]
fn file_commit_propagates_native_sync_errors_even_without_a_written_fact() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("FAIL.DAT"), b"unchanged").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let path = fs.resolve_path(b"FAIL.DAT", false).unwrap();
    for written in [false, true] {
        // Test-only fault injection: Windows rejects sync_all on a read-only
        // native handle. Label it writable to reach the real sync failure
        // path without invalidating an owned OS handle or adding a mock layer.
        let mut state = OpenFile::new(
            fs.root.open(&path).unwrap(),
            DosFileAccess::ReadWrite,
            *b"FAIL    DAT",
        );
        state.written = written;
        let shared = Arc::new(Mutex::new(state));
        let file = fs.insert_file(Arc::clone(&shared)).unwrap();
        let copy = fs.file_duplicate(file).unwrap();
        fs.file_seek(file, 2, DosSeekOrigin::Start).unwrap();
        for token in [file, copy, file] {
            let error = fs.file_commit(token).unwrap_err();
            assert_eq!(error.code, DosErrorCode::AccessDenied);
            let source = std::error::Error::source(&error).unwrap();
            assert_eq!(
                source.downcast_ref::<std::io::Error>().unwrap().raw_os_error(),
                Some(5),
            );
            assert_eq!(fs.file_seek(token, 0, DosSeekOrigin::Current).unwrap(), 2);
            assert_eq!(
                fs.file_ioctl_info(token).unwrap(),
                DosIoctlObjectInfo::File { drive: fs.drive(), written },
            );
            assert!(Arc::ptr_eq(&shared, fs.files.get(&token).unwrap()));
        }
        drop(shared);
        fs.file_close(file).unwrap();
        fs.file_close(copy).unwrap();
    }
    assert_eq!(std::fs::read(directory.0.join("FAIL.DAT")).unwrap(), b"unchanged");
}

//! Native last-write-time updates retain the existing open description.

use std::io::{Seek, SeekFrom};
use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, Mutex};

use cap_std::fs::MetadataExt;
use dos_kernel::{
    DosErrorCode, DosFileAccess, DosFileDisposition, DosFileOpenRequest, DosFileSharing,
    DosHostError, DosHostFile, DosIoctlObjectInfo, DosSeekOrigin,
};

use super::super::OpenFile;
use super::{Filesystem, TestDirectory};

// Ordinary local midday avoids a seasonal clock transition in the runner's
// selected zone. Conversion-specific boundary and DST cases have unit tests.
const WRITE_TIME: u16 = (12 << 11) | (34 << 5) | (56 / 2);
const WRITE_DATE: u16 = ((2004 - 1980) << 9) | (6 << 5) | 15;
const OTHER_TIME: u16 = (13 << 11) | (47 << 5) | (58 / 2);

fn request(disposition: DosFileDisposition, access: DosFileAccess) -> DosFileOpenRequest {
    DosFileOpenRequest {
        access,
        sharing: DosFileSharing::DenyNone,
        disposition,
        attributes: 0,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct NativeMetadata {
    length: u64,
    attributes: u32,
    creation: u64,
    access: u64,
    write: u64,
}

fn native_metadata(fs: &Filesystem, file: DosHostFile) -> NativeMetadata {
    let shared = fs.files.get(&file).unwrap().lock().unwrap();
    let metadata = shared.file.metadata().unwrap();
    NativeMetadata {
        length: metadata.len(),
        attributes: metadata.file_attributes(),
        creation: metadata.creation_time(),
        access: metadata.last_access_time(),
        write: metadata.last_write_time(),
    }
}

fn assert_written(fs: &Filesystem, file: DosHostFile, written: bool) {
    assert_eq!(
        fs.file_ioctl_info(file).unwrap(),
        DosIoctlObjectInfo::File { drive: fs.drive(), written },
    );
}

fn assert_native_access_denied(error: DosHostError) {
    assert_eq!(error.code, DosErrorCode::AccessDenied);
    let cause = std::error::Error::source(&error).unwrap();
    assert_eq!(cause.downcast_ref::<std::io::Error>().unwrap().raw_os_error(), Some(5));
}

#[test]
fn file_set_write_time_changes_only_last_write_for_writable_open_modes() {
    let directory = TestDirectory::new();
    let path = directory.0.join("STAMP.DAT");
    // Close the seed writer before measuring metadata; pending data-write
    // timestamps must not race the explicit setter.
    std::fs::write(&path, b"unchanged bytes").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.file_set_attributes(b"STAMP.DAT", 0x26).unwrap();
    for extended in [false, true] {
        for access in [DosFileAccess::WriteOnly, DosFileAccess::ReadWrite] {
            let time = if access == DosFileAccess::WriteOnly { WRITE_TIME } else { OTHER_TIME };
            let file = if extended {
                fs.file_extended_open(
                    b"STAMP.DAT", request(DosFileDisposition::OpenExisting, access),
                ).unwrap().file
            } else {
                fs.file_open(b"STAMP.DAT", access, DosFileSharing::DenyNone).unwrap()
            };
            fs.file_seek(file, 3, DosSeekOrigin::Start).unwrap();
            let before = native_metadata(&fs, file);
            let mut status = fs.file_status(file).unwrap();
            assert_written(&fs, file, false);
            fs.file_set_write_time(file, time, WRITE_DATE).unwrap();
            let after = native_metadata(&fs, file);
            assert_ne!(after.write, before.write);
            assert_eq!(after, NativeMetadata { write: after.write, ..before });
            status.write_time = time;
            status.write_date = WRITE_DATE;
            assert_eq!(fs.file_status(file).unwrap(), status);
            assert_eq!(fs.files.get(&file).unwrap().lock().unwrap().access, access);
            assert_written(&fs, file, true);
            fs.file_close(file).unwrap();

            let reopened = fs.file_open(
                b"STAMP.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone,
            ).unwrap();
            let status = fs.file_status(reopened).unwrap();
            assert_eq!((status.write_time, status.write_date), (time, WRITE_DATE));
            assert_written(&fs, reopened, false);
            fs.file_close(reopened).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"unchanged bytes");
        }
    }
}

#[test]
fn file_set_write_time_handles_created_and_extended_descriptions() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let files = [
        fs.file_create(b"CREATE.DAT", 0).unwrap(),
        fs.file_create_new(b"NEW.DAT", 0).unwrap(),
        fs.file_extended_open(
            b"EXTNEW.DAT", request(DosFileDisposition::CreateNew, DosFileAccess::WriteOnly),
        ).unwrap().file,
        fs.file_extended_open(
            b"EXTMAKE.DAT", request(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadWrite),
        ).unwrap().file,
    ];
    for file in files {
        assert_written(&fs, file, false);
        fs.file_set_write_time(file, WRITE_TIME, WRITE_DATE).unwrap();
        let status = fs.file_status(file).unwrap();
        assert_eq!((status.size, status.position), (0, 0));
        assert_eq!((status.write_time, status.write_date), (WRITE_TIME, WRITE_DATE));
        assert_written(&fs, file, true);
        fs.file_close(file).unwrap();
    }
    for access in [DosFileAccess::WriteOnly, DosFileAccess::ReadWrite] {
        let file = fs.file_extended_open(
            b"EXTMAKE.DAT", request(DosFileDisposition::OpenOrCreate, access),
        ).unwrap().file;
        assert_written(&fs, file, false);
        fs.file_set_write_time(file, OTHER_TIME, WRITE_DATE).unwrap();
        let status = fs.file_status(file).unwrap();
        assert_eq!((status.write_time, status.write_date), (OTHER_TIME, WRITE_DATE));
        assert_written(&fs, file, true);
        fs.file_close(file).unwrap();
    }
}

#[test]
fn file_set_write_time_uses_existing_handle_rights_on_read_only_attributes() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create_new(b"READATTR.DAT", 0x01).unwrap();
    assert_written(&fs, file, false);
    fs.file_set_write_time(file, WRITE_TIME, WRITE_DATE).unwrap();
    let status = fs.file_status(file).unwrap();
    assert_ne!(status.attributes & 1, 0);
    assert_eq!((status.write_time, status.write_date), (WRITE_TIME, WRITE_DATE));
    assert_written(&fs, file, true);
    fs.file_close(file).unwrap();
    fs.file_set_attributes(b"READATTR.DAT", 0).unwrap();
}

#[test]
fn file_set_write_time_retains_exclusive_identity_and_survives_original_close() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("EXCLUSIVE.DAT"), b"abcdef").unwrap();
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
            let copy = fs.file_duplicate(file).unwrap();
            let shared = Arc::clone(fs.files.get(&file).unwrap());
            let native_handle = shared.lock().unwrap().file.as_raw_handle();
            let next_file = fs.next_file;
            fs.file_seek(copy, 2, DosSeekOrigin::Start).unwrap();
            fs.file_set_write_time(file, WRITE_TIME, WRITE_DATE).unwrap();
            assert_written(&fs, copy, true);
            assert_eq!(fs.files.len(), 2);
            fs.file_close(file).unwrap();
            fs.file_set_write_time(copy, OTHER_TIME, WRITE_DATE).unwrap();
            assert_eq!(fs.files.len(), 1);
            assert_eq!(fs.next_file, next_file);
            assert!(Arc::ptr_eq(&shared, fs.files.get(&copy).unwrap()));
            assert_eq!(shared.lock().unwrap().file.as_raw_handle(), native_handle);
            assert_eq!(shared.lock().unwrap().access, access);
            let status = fs.file_status(copy).unwrap();
            assert_eq!((status.size, status.position), (6, 2));
            assert_eq!((status.write_time, status.write_date), (OTHER_TIME, WRITE_DATE));
            assert_written(&fs, copy, true);
            assert_eq!(fs.file_open(
                b"EXCLUSIVE.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone,
            ).unwrap_err().code, DosErrorCode::SharingViolation);
            if access == DosFileAccess::WriteOnly {
                assert_eq!(fs.file_read(copy, &mut [0]).unwrap_err().code, DosErrorCode::AccessDenied);
            }
            drop(shared);
            fs.file_close(copy).unwrap();
            assert_eq!(std::fs::read(directory.0.join("EXCLUSIVE.DAT")).unwrap(), b"abcdef");
        }
    }
}

#[test]
fn file_set_write_time_preserves_the_full_native_shared_cursor() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("CURSOR.DAT"), b"abc").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_open(b"CURSOR.DAT", DosFileAccess::ReadWrite, DosFileSharing::DenyNone).unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    let shared = Arc::clone(fs.files.get(&file).unwrap());
    let position = (1_u64 << 32) + 2;
    shared.lock().unwrap().file.seek(SeekFrom::Start(position)).unwrap();
    for token in [file, copy] {
        fs.file_set_write_time(token, WRITE_TIME, WRITE_DATE).unwrap();
        let mut state = shared.lock().unwrap();
        assert_eq!(state.file.stream_position().unwrap(), position);
        assert_eq!(state.file.metadata().unwrap().len(), 3);
    }
    drop(shared);
    fs.file_close(file).unwrap();
    fs.file_close(copy).unwrap();
    assert_eq!(std::fs::read(directory.0.join("CURSOR.DAT")).unwrap(), b"abc");
}

#[test]
fn file_set_write_time_rejects_actual_read_only_normal_and_extended_handles() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("READ.DAT"), b"unchanged").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    for extended in [false, true] {
        let file = if extended {
            fs.file_extended_open(
                b"READ.DAT", request(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadOnly),
            ).unwrap().file
        } else {
            fs.file_open(b"READ.DAT", DosFileAccess::ReadOnly, DosFileSharing::DenyNone).unwrap()
        };
        let copy = fs.file_duplicate(file).unwrap();
        fs.file_seek(file, 2, DosSeekOrigin::Start).unwrap();
        let before = native_metadata(&fs, file);
        let status = fs.file_status(file).unwrap();
        for token in [file, copy] {
            assert_native_access_denied(fs.file_set_write_time(token, WRITE_TIME, WRITE_DATE).unwrap_err());
            assert_eq!(native_metadata(&fs, token), before);
            assert_eq!(fs.file_status(token).unwrap(), status);
            assert_written(&fs, token, false);
        }
        fs.file_close(file).unwrap();
        assert_native_access_denied(fs.file_set_write_time(copy, WRITE_TIME, WRITE_DATE).unwrap_err());
        fs.file_close(copy).unwrap();
    }
    assert_eq!(std::fs::read(directory.0.join("READ.DAT")).unwrap(), b"unchanged");
}

#[test]
fn file_set_write_time_preserves_written_fact_after_native_failure() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("FAIL.DAT"), b"unchanged").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let path = fs.resolve_path(b"FAIL.DAT", false).unwrap();
    for written in [false, true] {
        // Use a real, owned read-only OS handle with writable bookkeeping to
        // exercise native SetFileTime denial without closing an owned handle.
        let mut state = OpenFile::new(
            fs.root.open(&path).unwrap(), DosFileAccess::ReadWrite, *b"FAIL    DAT",
        );
        state.written = written;
        let shared = Arc::new(Mutex::new(state));
        let file = fs.insert_file(Arc::clone(&shared)).unwrap();
        let copy = fs.file_duplicate(file).unwrap();
        fs.file_seek(file, 2, DosSeekOrigin::Start).unwrap();
        let before = native_metadata(&fs, file);
        for token in [file, copy, file] {
            assert_native_access_denied(fs.file_set_write_time(token, WRITE_TIME, WRITE_DATE).unwrap_err());
            assert_eq!(native_metadata(&fs, token), before);
            assert_eq!(fs.file_seek(token, 0, DosSeekOrigin::Current).unwrap(), 2);
            assert_written(&fs, token, written);
            assert!(Arc::ptr_eq(&shared, fs.files.get(&token).unwrap()));
        }
        drop(shared);
        fs.file_close(file).unwrap();
        fs.file_close(copy).unwrap();
    }
}

#[test]
fn file_set_write_time_rejects_invalid_fields_without_mutation() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create(b"INVALID.DAT", 0).unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    for written in [false, true] {
        if written {
            fs.file_set_write_time(file, WRITE_TIME, WRITE_DATE).unwrap();
        }
        let before = native_metadata(&fs, file);
        let status = fs.file_status(file).unwrap();
        for (time, date) in [
            (24 << 11, WRITE_DATE),
            ((12 << 11) | (60 << 5), WRITE_DATE),
            ((12 << 11) | 30, WRITE_DATE),
            (WRITE_TIME, 0),
            (WRITE_TIME, ((2004 - 1980) << 9) | 15),
            (WRITE_TIME, ((2004 - 1980) << 9) | (13 << 5) | 15),
            (WRITE_TIME, ((2004 - 1980) << 9) | (6 << 5)),
            (WRITE_TIME, ((2004 - 1980) << 9) | (4 << 5) | 31),
            (WRITE_TIME, ((2003 - 1980) << 9) | (2 << 5) | 29),
        ] {
            assert_eq!(fs.file_set_write_time(copy, time, date).unwrap_err().code, DosErrorCode::InvalidData);
            assert_eq!(native_metadata(&fs, file), before);
            assert_eq!(fs.file_status(copy).unwrap(), status);
            assert_written(&fs, file, written);
            assert_written(&fs, copy, written);
        }
    }
    fs.file_close(file).unwrap();
    fs.file_close(copy).unwrap();
}

#[test]
fn file_set_write_time_uses_exact_owned_tokens_and_rejects_closed_tokens() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.next_file = (1_u64 << 32) + 7;
    let file = fs.file_create(b"TOKEN.DAT", 0).unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    let before = native_metadata(&fs, file);
    for invalid in [
        DosHostFile(0), DosHostFile(7), DosHostFile(file.0 + (1_u64 << 32)), DosHostFile(u64::MAX),
    ] {
        assert_eq!(fs.file_set_write_time(invalid, WRITE_TIME, WRITE_DATE).unwrap_err().code, DosErrorCode::InvalidHandle);
        assert_eq!(native_metadata(&fs, file), before);
        assert_written(&fs, file, false);
        assert_eq!(fs.files.len(), 2);
    }
    fs.file_set_write_time(file, WRITE_TIME, WRITE_DATE).unwrap();
    fs.file_close(file).unwrap();
    assert_eq!(fs.file_set_write_time(file, WRITE_TIME, WRITE_DATE).unwrap_err().code, DosErrorCode::InvalidHandle);
    fs.file_set_write_time(copy, OTHER_TIME, WRITE_DATE).unwrap();
    fs.file_close(copy).unwrap();
    assert_eq!(fs.file_set_write_time(copy, WRITE_TIME, WRITE_DATE).unwrap_err().code, DosErrorCode::InvalidHandle);
    assert!(fs.files.is_empty());
}

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dos_kernel::{DosErrorCode, DosFileAccess, DosFileSharing, DosIoctlObjectInfo, DosSeekOrigin};

use super::Filesystem;
use super::files::dos_dword;

mod commit;
mod extended_open;
mod directory_errors;
mod input_status;
mod seek;
mod write_time;

struct TestDirectory(PathBuf);

#[test]
fn volume_root_current_directory_has_no_dot_component() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.directory_set_current(b"\\", false).unwrap();
    let mut output = [0xCC; 63];
    assert_eq!(
        fs.directory_get_current(fs.drive(), &mut output).unwrap(),
        0
    );
    assert_eq!(output, [0xCC; 63]);
}

#[test]
fn directory_search_lists_native_entries_without_opening_their_targets() {
    let directory = TestDirectory::new();
    std::fs::create_dir(directory.0.join("SUBDIR")).unwrap();
    std::fs::write(directory.0.join("SMALL.DAT"), b"abc").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let search = fs.directory_search_open(b".").unwrap();
    let mut found = Vec::new();
    while let Some(entry) = fs.directory_search_next(search).unwrap() {
        found.push(entry);
    }
    fs.directory_search_close(search).unwrap();
    assert!(
        found
            .iter()
            .any(|entry| entry.short_name == b"SUBDIR" && entry.attributes & 0x10 != 0)
    );
    assert!(
        found
            .iter()
            .any(|entry| entry.short_name == b"SMALL.DAT" && entry.size == 3)
    );
    // A real drive root includes protected files and directory junctions.
    // Enumeration must use their entry metadata, without dereferencing them.
    fs.directory_set_current(b"\\", false).unwrap();
    let root = fs.directory_search_open(b".").unwrap();
    assert!(fs.directory_search_next(root).unwrap().is_some());
    fs.directory_search_close(root).unwrap();
}

#[test]
fn native_volume_keeps_program_directory_separate_from_drive_root() {
    let directory = TestDirectory::new();
    let native_file = directory.0.join("SELF.DAT");
    std::fs::write(&native_file, b"self contents").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    assert!(!fs.current_directory.as_os_str().is_empty());
    assert_ne!(
        fs.canonical_root,
        std::fs::canonicalize(&directory.0).unwrap()
    );
    let absolute = fs.guest_path_for_host_path(&native_file).unwrap().unwrap();
    assert_eq!(absolute[0], b'A' + fs.drive());
    assert!(absolute.len() > b"C:\\SELF.DAT".len());
    for path in [absolute.as_slice(), b"SELF.DAT".as_slice()] {
        let handle = fs
            .file_open(path, DosFileAccess::ReadOnly, DosFileSharing::DenyNone)
            .unwrap();
        let mut contents = [0; 13];
        assert_eq!(fs.file_read(handle, &mut contents).unwrap(), 13);
        assert_eq!(&contents, b"self contents");
        fs.file_close(handle).unwrap();
    }
}

impl TestDirectory {
    fn new() -> Self {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for _ in 0..100 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "filesystem-ioctl-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            // Clock ticks can coincide across parallel tests. Claim a fresh
            // directory atomically; never adopt or remove an existing path.
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create test directory: {error}"),
            }
        }
        panic!("cannot reserve a unique test directory");
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn ioctl_file_information_tracks_shared_writes_and_independent_opens() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create(b"INFO.DAT", 0).unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    let clean = DosIoctlObjectInfo::File {
        drive: fs.drive(),
        written: false,
    };
    let dirty = DosIoctlObjectInfo::File {
        drive: fs.drive(),
        written: true,
    };
    assert_eq!(fs.file_ioctl_info(file).unwrap(), clean);
    assert_eq!(fs.file_ioctl_info(copy).unwrap(), clean);
    assert_eq!(fs.file_write(copy, b"abc").unwrap(), 3);
    assert_eq!(fs.file_ioctl_info(file).unwrap(), dirty);
    assert_eq!(fs.file_ioctl_info(copy).unwrap(), dirty);
    assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 3);
    fs.file_close(copy).unwrap();
    assert_eq!(
        fs.file_ioctl_info(copy).unwrap_err().code,
        DosErrorCode::InvalidHandle
    );
    fs.file_close(file).unwrap();

    let reopened = fs
        .file_open(
            b"INFO.DAT",
            DosFileAccess::ReadWrite,
            DosFileSharing::DenyNone,
        )
        .unwrap();
    assert_eq!(fs.file_ioctl_info(reopened).unwrap(), clean);
    let mut bytes = [0; 3];
    assert_eq!(fs.file_read(reopened, &mut bytes).unwrap(), 3);
    assert_eq!(&bytes, b"abc");
    assert_eq!(fs.file_ioctl_info(reopened).unwrap(), clean);
    fs.file_set_len(reopened, 1).unwrap();
    assert_eq!(fs.file_ioctl_info(reopened).unwrap(), dirty);
    fs.file_close(reopened).unwrap();
}

#[test]
fn file_status_uses_the_shared_cursor_and_current_file_size() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create(b"STATUS.DAT", 0).unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    fs.file_write(copy, b"abc").unwrap();
    let status = fs.file_status(file).unwrap();
    assert_eq!((status.size, status.position), (3, 3));
    assert_eq!(&status.short_name, b"STATUS  DAT");
    assert_eq!(status.attributes & 0x20, 0x20);
    assert_ne!(status.write_date, 0);
    fs.file_seek(file, 1, DosSeekOrigin::Start).unwrap();
    assert_eq!(fs.file_status(copy).unwrap().position, 1);
    fs.file_set_len(copy, 2).unwrap();
    let status = fs.file_status(file).unwrap();
    assert_eq!((status.size, status.position), (2, 1));
    fs.file_close(copy).unwrap();
    assert_eq!(
        fs.file_status(copy).unwrap_err().code,
        DosErrorCode::InvalidHandle
    );
    fs.file_close(file).unwrap();
}

#[test]
fn dos_file_status_dword_conversion_keeps_the_low_32_bits() {
    assert_eq!(dos_dword(0), 0);
    assert_eq!(dos_dword(u64::from(u32::MAX)), u32::MAX);
    assert_eq!(dos_dword(1_u64 << 32), 0);
    assert_eq!(dos_dword((1_u64 << 32) + 17), 17);
}

#[test]
fn disk_space_reports_the_mounted_native_volume() {
    let directory = TestDirectory::new();
    let fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let space = fs.disk_space(fs.drive()).unwrap();
    assert!(space.total_bytes > 0);
    assert!(space.available_bytes <= space.total_bytes);
    assert_eq!(
        fs.disk_space((fs.drive() + 1) % 26).unwrap_err().code,
        DosErrorCode::UnknownUnit
    );
}

#[test]
fn create_new_native_preserves_existing_contents_and_attributes() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let original = fs.file_create_new(b"KEEP.DAT", 0x02).unwrap();
    fs.file_write(original, b"preserved contents").unwrap();
    let attributes = fs.file_get_attributes(b"KEEP.DAT").unwrap();
    for spelling in [b"KEEP.DAT".as_slice(), b"keep.dat".as_slice()] {
        assert_eq!(fs.file_create_new(spelling, 0).unwrap_err().code, DosErrorCode::FileExists);
        assert_eq!(fs.file_get_attributes(spelling).unwrap(), attributes);
    }
    assert_eq!(fs.file_seek(original, 0, DosSeekOrigin::Current).unwrap(), 18);
    fs.file_seek(original, 0, DosSeekOrigin::Start).unwrap();
    let mut bytes = [0; 18];
    assert_eq!(fs.file_read(original, &mut bytes).unwrap(), bytes.len());
    assert_eq!(&bytes, b"preserved contents");
    fs.file_close(original).unwrap();
}

#[test]
fn create_new_native_uses_existing_short_alias_identity() {
    let directory = TestDirectory::new();
    let native = directory.0.join("Long existing filename.dat");
    std::fs::write(&native, b"keep").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let search = fs.directory_search_open(b".").unwrap();
    let mut files = Vec::new();
    while let Some(entry) = fs.directory_search_next(search).unwrap() {
        // DOS subdirectory searches include synthetic '.' and '..' entries.
        // Select the fixture's file by type, never by enumeration position.
        if entry.attributes & 0x10 == 0 {
            files.push(entry);
        }
    }
    fs.directory_search_close(search).unwrap();
    assert_eq!(files.len(), 1, "fixture must expose exactly one regular file");
    let entry = files.pop().unwrap();
    assert_eq!(entry.size, 4);
    // Prove this enumerated alias names the long file before testing the
    // collision. Close the read handle to exclude sharing as a failure cause.
    let opened = fs.file_open(&entry.short_name, DosFileAccess::ReadOnly, DosFileSharing::DenyNone).unwrap();
    let mut contents = [0; 4];
    assert_eq!(fs.file_read(opened, &mut contents).unwrap(), 4);
    assert_eq!(&contents, b"keep");
    fs.file_close(opened).unwrap();
    assert_eq!(fs.file_create_new(&entry.short_name, 0).unwrap_err().code, DosErrorCode::FileExists);
    assert_eq!(std::fs::read(&native).unwrap(), b"keep");
    assert!(fs.files.is_empty());
}

#[test]
fn create_new_native_has_shared_cursor_and_compatibility_sharing() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create_new(b"SHARED.DAT", 0).unwrap();
    let copy = fs.file_duplicate(file).unwrap();
    fs.file_write(copy, b"abc").unwrap();
    assert_eq!(fs.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 3);
    let independent = fs.file_open(
        b"SHARED.DAT", DosFileAccess::ReadWrite, DosFileSharing::Compatibility,
    ).unwrap();
    assert_eq!(fs.file_seek(independent, 0, DosSeekOrigin::Current).unwrap(), 0);
    fs.file_close(independent).unwrap();
    fs.file_close(file).unwrap();
    fs.file_write(copy, b"def").unwrap();
    assert_eq!(fs.file_status(copy).unwrap().size, 6);
    fs.file_close(copy).unwrap();
    assert_eq!(std::fs::read(directory.0.join("SHARED.DAT")).unwrap(), b"abcdef");
}

#[test]
fn create_new_native_concurrent_creators_have_exactly_one_winner() {
    let directory = TestDirectory::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2).map(|_| {
        let path = directory.0.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            let mut fs = Filesystem::new_native_directory(&path, 437).unwrap();
            barrier.wait();
            match fs.file_create_new(b"ATOMIC.DAT", 0) {
                Ok(file) => {
                    fs.file_write(file, b"winner").unwrap();
                    fs.file_close(file).unwrap();
                    Ok(())
                }
                Err(error) => Err(error.code),
            }
        })
    }).collect();
    let outcomes: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(outcomes.iter().filter(|result| **result == Err(DosErrorCode::FileExists)).count(), 1);
    assert_eq!(std::fs::read(directory.0.join("ATOMIC.DAT")).unwrap(), b"winner");
}

#[test]
fn create_new_native_exhausted_tokens_and_invalid_attributes_do_not_create() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    assert_eq!(fs.file_create_new(b"INVALID.DAT", 0x10).unwrap_err().code, DosErrorCode::InvalidAccess);
    assert!(!directory.0.join("INVALID.DAT").exists());
    fs.next_file = u64::MAX;
    assert_eq!(fs.file_create_new(b"EXHAUST.DAT", 0).unwrap_err().code, DosErrorCode::TooManyOpenFiles);
    assert!(!directory.0.join("EXHAUST.DAT").exists());
}

#[test]
fn create_new_native_existing_directory_is_preserved() {
    let directory = TestDirectory::new();
    let existing = directory.0.join("EXISTING");
    std::fs::create_dir(&existing).unwrap();
    std::fs::write(existing.join("KEEP.DAT"), b"directory contents").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let error = fs.file_create_new(b"EXISTING", 0).unwrap_err();
    assert!(matches!(error.code, DosErrorCode::AccessDenied | DosErrorCode::FileExists));
    assert!(existing.is_dir());
    assert_eq!(std::fs::read(existing.join("KEEP.DAT")).unwrap(), b"directory contents");
    assert!(fs.files.is_empty());
}

#[test]
fn temporary_create_new_native_keeps_readonly_attribute_and_initial_write_handle() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create_new(b".\\0C22384E", 0x01).unwrap();
    assert_eq!(fs.file_write(file, b"initial write").unwrap(), 13);
    fs.file_close(file).unwrap();
    assert_ne!(fs.file_get_attributes(b".\\0C22384E").unwrap() & 1, 0);
    assert_eq!(fs.file_open(b".\\0C22384E", DosFileAccess::ReadWrite,
        DosFileSharing::Compatibility).unwrap_err().code, DosErrorCode::AccessDenied);
    let read = fs.file_open(b".\\0C22384E", DosFileAccess::ReadOnly,
        DosFileSharing::Compatibility).unwrap();
    let mut contents = [0; 13];
    assert_eq!(fs.file_read(read, &mut contents).unwrap(), contents.len());
    assert_eq!(&contents, b"initial write");
    fs.file_close(read).unwrap();
    // DOS does not delete AH=5Ah files on close. Clear readonly for explicit
    // cleanup, rather than relying on the test directory destructor.
    assert!(directory.0.join("0C22384E").is_file());
    fs.file_set_attributes(b".\\0C22384E", 0).unwrap();
    fs.file_delete(b".\\0C22384E").unwrap();
}

#[test]
fn temporary_create_new_native_uses_supplied_subdirectory_and_rejects_unmounted_drive() {
    let directory = TestDirectory::new();
    std::fs::create_dir(directory.0.join("SPOOL")).unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let file = fs.file_create_new(b"SPOOL\\0C22384E", 0).unwrap();
    fs.file_close(file).unwrap();
    assert!(directory.0.join("SPOOL").join("0C22384E").is_file());
    assert!(!directory.0.join("0C22384E").exists());
    let mut wrong_drive = b"C:\\0C22384E".to_vec();
    wrong_drive[0] = b'A' + ((fs.drive() + 1) % 26);
    assert_eq!(fs.file_create_new(&wrong_drive, 0).unwrap_err().code, DosErrorCode::UnknownUnit);
    assert_eq!(fs.file_create_new(b"MISSING\\0C22384E", 0).unwrap_err().code, DosErrorCode::PathNotFound);
    for namespace in [br"\\server\share\0C22384E".as_slice(),
        br"\\?\C:\0C22384E".as_slice(), br"\\.\NUL\0C22384E".as_slice()] {
        assert_eq!(fs.file_create_new(namespace, 0).unwrap_err().code, DosErrorCode::InvalidData);
    }
}

#[test]
fn create_new_native_distinguishes_missing_parents_from_missing_final_leaf() {
    let directory = TestDirectory::new();
    std::fs::create_dir(directory.0.join("EXISTS")).unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    for path in [b"MISSING\\NEW.DAT".as_slice(),
        b"EXISTS\\MISSING\\NEW.DAT".as_slice(), b"MISSING\\NESTED\\NEW.DAT".as_slice()] {
        assert_eq!(fs.file_create_new(path, 0).unwrap_err().code, DosErrorCode::PathNotFound);
        assert!(fs.files.is_empty());
    }
    assert!(!directory.0.join("MISSING").exists());
    assert!(!directory.0.join("EXISTS/MISSING").exists());
    // Missing final leaves remain ordinary lookup failures for existing-only
    // operations. Only exclusive creation gets the path-error classification.
    assert_eq!(fs.file_open(b"EXISTS\\NEW.DAT", DosFileAccess::ReadOnly,
        DosFileSharing::Compatibility).unwrap_err().code, DosErrorCode::FileNotFound);
    let file = fs.file_create_new(b"EXISTS\\NEW.DAT", 0).unwrap();
    fs.file_close(file).unwrap();
    assert!(directory.0.join("EXISTS/NEW.DAT").is_file());
}

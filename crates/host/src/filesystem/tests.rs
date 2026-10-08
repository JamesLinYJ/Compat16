use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use dos_kernel::{DosErrorCode, DosFileAccess, DosFileSharing, DosIoctlObjectInfo, DosSeekOrigin};

use super::Filesystem;
use super::files::dos_dword;

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
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("filesystem-ioctl-{}-{nanos}", std::process::id()));
        // Fail on collisions; only this newly created directory is removed.
        std::fs::create_dir(&path).unwrap();
        Self(path)
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

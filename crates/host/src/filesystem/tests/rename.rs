use super::{Filesystem, TestDirectory};
use dos_kernel::{DosErrorCode, DosFileAccess, DosFileSharing};

#[test]
fn rename_moves_ascii_and_oem_readonly_files_relative_to_the_owned_destination() {
    for page in [437, 936] {
        let directory = TestDirectory::new();
        std::fs::create_dir(directory.0.join("FROM")).unwrap();
        std::fs::create_dir(directory.0.join("TO")).unwrap();
        let mut fs = Filesystem::new_native_directory(&directory.0, page).unwrap();
        for name in [
            b"ASCII.OLD".as_slice(),
            if page == 936 {
                b"\x81\\A.OLD"
            } else {
                b"\x81A.OLD"
            },
        ] {
            let mut old = b"FROM\\".to_vec();
            old.extend_from_slice(name);
            let mut new = b"TO\\".to_vec();
            new.extend_from_slice(&name[..name.len() - 3]);
            new.extend_from_slice(b"NEW");
            let file = fs.file_create(&old, 0x20).unwrap();
            fs.file_write(file, b"preserve").unwrap();
            fs.file_close(file).unwrap();
            fs.file_set_attributes(&old, 0x21).unwrap();
            fs.file_rename(&old, &new).unwrap();
            assert_eq!(
                fs.file_get_attributes(&old).unwrap_err().code,
                DosErrorCode::FileNotFound
            );
            assert_eq!(fs.file_get_attributes(&new).unwrap() & 1, 1);
            let handle = fs
                .file_open(&new, DosFileAccess::ReadOnly, DosFileSharing::DenyNone)
                .unwrap();
            let mut bytes = [0; 8];
            assert_eq!(fs.file_read(handle, &mut bytes).unwrap(), 8);
            assert_eq!(&bytes, b"preserve");
            fs.file_close(handle).unwrap();
            fs.file_set_attributes(&new, 0x20).unwrap();
            fs.file_delete(&new).unwrap();
        }
    }
}

#[test]
fn rename_directory_retains_descendants_and_rebases_the_owned_current_directory() {
    let directory = TestDirectory::new();
    std::fs::create_dir_all(directory.0.join("OLD/SUB")).unwrap();
    std::fs::write(directory.0.join("OLD/SUB/KEEP.TXT"), b"preserve").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.directory_set_current(b"OLD\\SUB", false).unwrap();
    let mut before = [0; 63];
    let count = fs.directory_get_current(fs.drive(), &mut before).unwrap();
    assert!(before[..count].ends_with(b"OLD\\SUB"));
    let mut expected = before[..count].to_vec();
    expected[count - 7..].copy_from_slice(b"NEW\\SUB");
    fs.file_rename(b"..", b"..\\..\\NEW").unwrap();
    assert!(!directory.0.join("OLD").exists());
    assert_eq!(
        std::fs::read(directory.0.join("NEW/SUB/KEEP.TXT")).unwrap(),
        b"preserve"
    );
    let mut current = [0; 63];
    let count = fs.directory_get_current(fs.drive(), &mut current).unwrap();
    assert_eq!(&current[..count], expected);
}

#[test]
fn rename_rejects_existing_targets_and_open_sources_without_changing_either_file() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("OLD.TXT"), b"source").unwrap();
    std::fs::write(directory.0.join("KEEP.TXT"), b"target").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    assert_eq!(
        fs.file_rename(b"OLD.TXT", b"KEEP.TXT").unwrap_err().code,
        DosErrorCode::AccessDenied
    );
    let handle = fs
        .file_open(
            b"OLD.TXT",
            DosFileAccess::ReadOnly,
            DosFileSharing::DenyNone,
        )
        .unwrap();
    assert_eq!(
        fs.file_rename(b"OLD.TXT", b"NEW.TXT").unwrap_err().code,
        DosErrorCode::SharingViolation
    );
    assert_eq!(
        std::fs::read(directory.0.join("OLD.TXT")).unwrap(),
        b"source"
    );
    assert_eq!(
        std::fs::read(directory.0.join("KEEP.TXT")).unwrap(),
        b"target"
    );
    assert!(!directory.0.join("NEW.TXT").exists());
    fs.file_close(handle).unwrap();
    fs.file_rename(b"OLD.TXT", b"NEW.TXT").unwrap();
    assert!(!directory.0.join("OLD.TXT").exists());
    assert_eq!(
        std::fs::read(directory.0.join("NEW.TXT")).unwrap(),
        b"source"
    );
}

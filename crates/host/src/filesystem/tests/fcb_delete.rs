use super::{Filesystem, TestDirectory};
use dos_kernel::{DosErrorCode, DosFileAccess, DosFileSharing};

#[test]
fn fcb_readonly_delete_requires_the_extended_capability_and_removes_the_actual_entry() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("READONLY.TMP"), b"preserve").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.file_set_attributes(b"READONLY.TMP", 0x21).unwrap();
    assert_eq!(
        fs.file_delete(b"READONLY.TMP").unwrap_err().code,
        DosErrorCode::AccessDenied
    );
    let rejected = fs.file_delete_fcb(b"READONLY.TMP", false).unwrap_err();
    assert_eq!(rejected.code, DosErrorCode::AccessDenied);
    assert_eq!(fs.file_get_attributes(b"READONLY.TMP").unwrap() & 1, 1);
    fs.file_delete_fcb(b"READONLY.TMP", true).unwrap();
    assert!(!directory.0.join("READONLY.TMP").exists());
}

#[test]
fn fcb_readonly_delete_sharing_failure_does_not_clear_any_attributes_or_change_data() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("LOCKED.TMP"), b"preserve").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.file_set_attributes(b"LOCKED.TMP", 0x27).unwrap();
    let file = fs
        .file_open(
            b"LOCKED.TMP",
            DosFileAccess::ReadOnly,
            DosFileSharing::DenyNone,
        )
        .unwrap();
    let before = fs.file_get_attributes(b"LOCKED.TMP").unwrap();
    assert_eq!(
        fs.file_delete(b"LOCKED.TMP").unwrap_err().code,
        DosErrorCode::SharingViolation
    );
    assert_eq!(
        fs.file_delete_fcb(b"LOCKED.TMP", true).unwrap_err().code,
        DosErrorCode::SharingViolation
    );
    assert_eq!(fs.file_get_attributes(b"LOCKED.TMP").unwrap(), before);
    assert_eq!(
        std::fs::read(directory.0.join("LOCKED.TMP")).unwrap(),
        b"preserve"
    );
    fs.file_close(file).unwrap();
    fs.file_delete_fcb(b"LOCKED.TMP", true).unwrap();
    assert!(!directory.0.join("LOCKED.TMP").exists());
}

#[test]
fn fcb_readonly_delete_does_not_remove_a_directory() {
    let directory = TestDirectory::new();
    std::fs::create_dir(directory.0.join("KEEPDIR")).unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    assert_eq!(
        fs.file_delete(b"KEEPDIR").unwrap_err().code,
        DosErrorCode::AccessDenied
    );
    assert_eq!(
        fs.file_delete_fcb(b"KEEPDIR", true).unwrap_err().code,
        DosErrorCode::AccessDenied
    );
    assert!(directory.0.join("KEEPDIR").is_dir());
}

use super::{Filesystem, TestDirectory};

#[test]
fn canonical_component_uses_published_alias_and_original_unicode_entry() {
    for page in [437, 936] {
        let directory = TestDirectory::new();
        let name = "A long file name.txt";
        std::fs::write(directory.0.join(name), b"original").unwrap();
        let mut fs = Filesystem::new_native_directory(&directory.0, page).unwrap();
        let mut cwd = [0; 63];
        let drive = fs.drive();
        let count = fs.directory_get_current(drive, &mut cwd).unwrap();
        let mut parent = vec![b'A' + drive, b':', b'\\'];
        parent.extend_from_slice(&cwd[..count]);
        parent.push(b'\\');
        let alias = fs
            .project_short_component(&parent, name.as_bytes())
            .unwrap()
            .unwrap();
        let search = fs.directory_search_open(b"").unwrap();
        let mut found = false;
        while let Some(entry) = fs.directory_search_next(search).unwrap() {
            found |= entry.short_name == alias;
        }
        fs.directory_search_close(search).unwrap();
        assert!(found);
        let file = fs
            .file_open(
                &alias,
                dos_kernel::DosFileAccess::ReadOnly,
                dos_kernel::DosFileSharing::DenyNone,
            )
            .unwrap();
        let mut bytes = [0; 8];
        assert_eq!(fs.file_read(file, &mut bytes).unwrap(), 8);
        assert_eq!(&bytes, b"original");
        fs.file_close(file).unwrap();
    }
}

#[test]
fn canonical_component_missing_parent_and_final_entry_return_none_without_creation() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let mut cwd = [0; 63];
    let drive = fs.drive();
    let count = fs.directory_get_current(drive, &mut cwd).unwrap();
    let mut parent = vec![b'A' + drive, b':', b'\\'];
    parent.extend_from_slice(&cwd[..count]);
    parent.push(b'\\');
    assert_eq!(
        fs.project_short_component(&parent, b"absentlongname.txt")
            .unwrap(),
        None
    );
    parent.extend_from_slice(b"MISSING\\");
    assert_eq!(
        fs.project_short_component(&parent, b"absentlongname.txt")
            .unwrap(),
        None
    );
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
}

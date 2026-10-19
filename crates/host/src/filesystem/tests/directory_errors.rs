//! A regular file in a directory position is a DOS path error.
use super::{Filesystem, TestDirectory};
use dos_kernel::DosErrorCode;

#[test]
fn non_directory_paths_report_path_not_found_without_changing_current_directory() {
    for page in [437, 936] {
        let directory = TestDirectory::new();
        std::fs::write(directory.0.join("PLAIN.DAT"), b"preserve").unwrap();
        let mut fs = Filesystem::new_native_directory(&directory.0, page).unwrap();
        let initial = fs.current_directory.clone();
        for path in [b"PLAIN.DAT".as_slice(), b"PLAIN.DAT\\CHILD"] {
            let error = fs.directory_set_current(path, false).unwrap_err();
            assert_eq!(
                error.code,
                DosErrorCode::PathNotFound,
                "path={path:?}: {error:?}"
            );
            assert_eq!(fs.current_directory, initial);
        }
        assert_eq!(
            std::fs::read(directory.0.join("PLAIN.DAT")).unwrap(),
            b"preserve"
        );
    }
}

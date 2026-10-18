//! An external native OEM 8.3 name must have the same DOS enumeration spelling.
use super::{Filesystem, TestDirectory};
use dos_kernel::{DosFileAccess, DosFileSharing};

#[test]
fn oem_short_names_enumerate_and_reopen_with_their_dos_case_mapping() {
    for (page, name) in [
        (text_codec::CodePage::Cp437, b"\x81a.txt".as_slice()),
        (text_codec::CodePage::Cp936, b"\x81\\a.txt"),
    ] {
        let directory = TestDirectory::new();
        let native = text_codec::decode(name, page).unwrap();
        std::fs::write(directory.0.join(&native), b"preserve").unwrap();
        let mut fs =
            Filesystem::new_native_directory(&directory.0, u32::from(page.number())).unwrap();
        let expected = text_codec::uppercase_oem_name(name, page).unwrap();
        let search = fs.directory_search_open(b"").unwrap();
        let mut found = false;
        while let Some(entry) = fs.directory_search_next(search).unwrap() {
            if entry.short_name == expected {
                found = true;
            }
        }
        fs.directory_search_close(search).unwrap();
        assert!(found, "native OEM short name was replaced: {page:?}");
        let file = fs
            .file_open(&expected, DosFileAccess::ReadOnly, DosFileSharing::DenyNone)
            .unwrap();
        let mut bytes = [0; 8];
        assert_eq!(fs.file_read(file, &mut bytes).unwrap(), 8);
        assert_eq!(&bytes, b"preserve");
        fs.file_close(file).unwrap();
        assert_eq!(
            std::fs::read(directory.0.join(native)).unwrap(),
            b"preserve"
        );
    }
}

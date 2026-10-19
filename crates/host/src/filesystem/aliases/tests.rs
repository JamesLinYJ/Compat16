use super::{AliasTable, DirectoryCaseSensitivity, make_alias_table};
use std::collections::BTreeMap;
use std::ffi::OsString;
use text_codec::CodePage;

#[test]
fn legal_oem_names_keep_their_spelling_with_native_alternate_names() {
    for (page, bytes) in [
        (CodePage::Cp437, b"\x81a.txt".as_slice()),
        (CodePage::Cp936, b"\x81\\a.txt".as_slice()),
    ] {
        let name = OsString::from(text_codec::decode(bytes, page).unwrap());
        let expected =
            text_codec::decode(&text_codec::uppercase_oem_name(bytes, page).unwrap(), page)
                .unwrap();
        let table = make_alias_table(
            vec![name.clone()],
            AliasTable::default(),
            BTreeMap::from([(name.clone(), "A~1.TXT".into())]),
            DirectoryCaseSensitivity::Insensitive,
            page,
        )
        .unwrap();
        assert_eq!(table.by_real_name[&name], expected);
        assert_eq!(table.by_alias[&expected], name);
    }
}

#[test]
fn long_names_keep_available_native_aliases_and_active_assignments() {
    let name = OsString::from("a long filename.txt");
    let native = BTreeMap::from([(name.clone(), "ALONGF~1.TXT".into())]);
    let previous = make_alias_table(
        vec![name.clone()],
        AliasTable::default(),
        native,
        DirectoryCaseSensitivity::Insensitive,
        CodePage::Cp437,
    )
    .unwrap();
    assert_eq!(previous.by_real_name[&name], "ALONGF~1.TXT");
    let newcomer = OsString::from("ALONGF~1.TXT");
    let table = make_alias_table(
        vec![name.clone(), newcomer.clone()],
        previous,
        BTreeMap::new(),
        DirectoryCaseSensitivity::Insensitive,
        CodePage::Cp437,
    )
    .unwrap();
    assert_eq!(table.by_alias["ALONGF~1.TXT"], name);
    assert_ne!(table.by_real_name[&newcomer], "ALONGF~1.TXT");
}

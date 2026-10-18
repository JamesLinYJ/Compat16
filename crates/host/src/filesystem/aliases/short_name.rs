//! DOS 8.3 limits count OEM bytes, not UTF-8 bytes or Unicode characters.
use std::ffi::OsStr;
use text_codec::CodePage;

pub(in super::super) fn canonical_83(name: &OsStr, page: CodePage) -> Option<String> {
    let text = name.to_str()?;
    if text.is_empty()
        || text.ends_with('.')
        || text.ends_with(' ')
        || super::super::is_reserved_device_name(text)
    {
        return None;
    }
    let mut parts = text.split('.');
    let stem = parts.next()?;
    let extension = parts.next();
    if parts.next().is_some()
        || stem.is_empty()
        || !component_fits(stem, 8, page)
        || extension.is_some_and(|ext| ext.is_empty() || !component_fits(ext, 3, page))
    {
        return None;
    }
    let bytes = text_codec::encode(text, page).ok()?;
    // Keep the selected DOS case table, including opaque DBCS trail bytes.
    let uppercase = text_codec::uppercase_oem_name(&bytes, page).ok()?;
    text_codec::decode(&uppercase, page).ok()
}

fn component_fits(text: &str, limit: usize, page: CodePage) -> bool {
    let Ok(bytes) = text_codec::encode(text, page) else {
        return false;
    };
    if bytes.len() > limit || text_codec::decode(&bytes, page).ok().as_deref() != Some(text) {
        return false;
    }
    text_codec::encoded_characters(&bytes, page).all(|character| {
        character.is_ok_and(|character| {
            character.byte_range.len() == 2
                || bytes[character.byte_range.start] >= 0x80
                || super::allowed_short_byte(bytes[character.byte_range.start])
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name_oem_limits_and_case_are_byte_exact() {
        assert_eq!(
            canonical_83(OsStr::new("üabcdefg.txt"), CodePage::Cp437).as_deref(),
            Some("ÜABCDEFG.TXT")
        );
        assert!(canonical_83(OsStr::new("üabcdefgh.txt"), CodePage::Cp437).is_none());
        let name = text_codec::decode(b"\x81\\abcdef.txt", CodePage::Cp936).unwrap();
        let expected = text_codec::decode(b"\x81\\ABCDEF.TXT", CodePage::Cp936).unwrap();
        assert_eq!(
            canonical_83(OsStr::new(&name), CodePage::Cp936),
            Some(expected)
        );
        let long = text_codec::decode(b"\x81\\abcdefg.txt", CodePage::Cp936).unwrap();
        assert!(canonical_83(OsStr::new(&long), CodePage::Cp936).is_none());
    }

    #[test]
    fn short_name_dbcs_extension_limits_do_not_split_pairs() {
        let name = text_codec::decode(b"a.\x81\\z", CodePage::Cp936).unwrap();
        let expected = text_codec::decode(b"A.\x81\\Z", CodePage::Cp936).unwrap();
        assert_eq!(
            canonical_83(OsStr::new(&name), CodePage::Cp936),
            Some(expected)
        );
        let long = text_codec::decode(b"a.\x81\\zz", CodePage::Cp936).unwrap();
        assert!(canonical_83(OsStr::new(&long), CodePage::Cp936).is_none());
    }

    #[test]
    fn short_name_rejects_lossy_names_devices_and_ascii_separators() {
        for page in [CodePage::Cp437, CodePage::Cp936] {
            for name in [
                "a?.txt", "a b.txt", "a/b.txt", "a\\b.txt", "a:b.txt", "a..txt", "CON.txt", "a.",
                "a.txt ", "🍣.txt",
            ] {
                assert!(
                    canonical_83(OsStr::new(name), page).is_none(),
                    "{page:?}: {name}"
                );
            }
        }
    }
}

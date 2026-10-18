use runtime::{DiagnosticKind, RuntimeError};

pub(super) fn parse(text: &str) -> Result<u16, RuntimeError> {
    let invalid = || {
        RuntimeError::new(
            DiagnosticKind::InvalidInput,
            "DOS version requires decimal MAJOR.MINOR bytes, for example 7.00",
        )
    };
    let (major, minor) = text.split_once('.').ok_or_else(invalid)?;
    let component = |value: &str| {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        value.parse::<u8>().map_err(|_| invalid())
    };
    Ok(u16::from(component(major)?) | (u16::from(component(minor)?) << 8))
}

#[cfg(test)]
mod tests {
    use super::parse;
    #[test]
    fn reported_dos_version_preserves_decimal_components() {
        for (text, expected) in [
            ("5.00", 0x0005),
            ("5.50", 0x3205),
            ("6.22", 0x1606),
            ("7.00", 0x0007),
            ("0.0", 0),
            ("255.255", 0xffff),
        ] {
            assert_eq!(parse(text).unwrap(), expected);
        }
    }
    #[test]
    fn reported_dos_version_rejects_missing_or_non_byte_components() {
        for text in [
            "", "7", "7.", ".0", "7.0.0", "-1.0", "7.+0", " 7.0", "256.0", "7.256",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }
}

//! Win16 profile-integer conversion.
//!
//! `GetProfileInt` and `GetPrivateProfileInt` return a 16-bit `WORD`. The
//! Windows 3.0 Programmer's Reference says a missing key returns `nDefault`,
//! a value that is not an integer returns zero, a negative integer returns
//! zero, and digits followed by other characters return the digit value
//! (`102abc` is 102). A magnitude above 65,535 does not fit that word. The
//! pre-Windows 9x limit saturates there instead of keeping the low 16 bits.

/// Convert stored profile text into the Win16 integer result.
///
/// `stored == None` means the key is absent. A present value is the exact
/// bytes copied for that key, without a trailing NUL.
pub fn win16_profile_integer(stored: Option<&[u8]>, default: i32) -> u32 {
    let Some(text) = stored else {
        return u32::from(default as u16);
    };
    let mut index = 0;
    while index < text.len() && matches!(text[index], b' ' | b'\t') {
        index += 1;
    }
    if index >= text.len() || text[index] == b'-' || !text[index].is_ascii_digit() {
        return 0;
    }
    let mut value = 0_u32;
    while index < text.len() && text[index].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add(u32::from(text[index] - b'0'));
        if value > u32::from(u16::MAX) {
            return u32::from(u16::MAX);
        }
        index += 1;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::win16_profile_integer;

    #[test]
    fn missing_key_keeps_the_default_bit_pattern() {
        assert_eq!(win16_profile_integer(None, 7), 7);
        assert_eq!(win16_profile_integer(None, -1), 0xffff);
        assert_eq!(win16_profile_integer(None, -32_768), 0x8000);
    }

    #[test]
    fn empty_negative_and_non_integer_text_returns_zero() {
        for text in ["", "   ", "\t", "abc", "  -4", "-1", "+", "0x10"] {
            assert_eq!(win16_profile_integer(Some(text.as_bytes()), 9), 0, "{text}");
        }
    }

    #[test]
    fn decimal_prefix_fits_a_word_and_a_larger_magnitude_saturates() {
        assert_eq!(win16_profile_integer(Some(b"0"), 9), 0);
        assert_eq!(win16_profile_integer(Some(b"  \t102abc"), 9), 102);
        assert_eq!(win16_profile_integer(Some(b"32767"), 9), 32_767);
        assert_eq!(win16_profile_integer(Some(b"32768"), 9), 32_768);
        assert_eq!(win16_profile_integer(Some(b"40000"), 9), 40_000);
        assert_eq!(win16_profile_integer(Some(b"65535"), 9), 65_535);
        assert_eq!(win16_profile_integer(Some(b"65536"), 9), 65_535);
        assert_eq!(win16_profile_integer(Some(b"70000"), 9), 65_535);
        assert_eq!(
            win16_profile_integer(Some(b"00000000000000000000999999999"), 9),
            65_535
        );
    }
}

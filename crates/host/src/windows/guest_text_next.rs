//! Bounded Win16 character probes using the fixed guest encoding.

use super::{GuestTextBuffer, GuestTextCodec};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16AnsiNextProbe as Probe};
use windows_sys::Win32::Globalization::{CP_UTF8, IsDBCSLeadByteEx};

impl GuestTextCodec {
    pub(in crate::windows) fn next_character_probe(
        self,
        source: &[u8],
    ) -> Result<Probe, RuntimeError> {
        let Some(&first) = source.first() else {
            return Ok(Probe::NeedMore);
        };
        if first == 0 {
            return Ok(Probe::Complete(0));
        }
        let length = if self.code_page() == CP_UTF8 {
            // Preserve the existing UTF-8 scalar extension. CharNextW has
            // different combining-character semantics and cannot supply this
            // byte boundary. Validate only this scalar, never the suffix.
            let length = match first {
                0x01..=0x7f => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Err(invalid_utf8()),
            };
            match std::str::from_utf8(&source[..source.len().min(length)]) {
                Ok(_) => length,
                Err(error) if error.error_len().is_none() && source.len() < length => {
                    return Ok(Probe::NeedMore);
                }
                Err(_) => return Err(invalid_utf8()),
            }
        } else {
            // MaxCharSize alone is not enough: this also rejects known
            // stateful encodings whose boundaries depend on earlier bytes.
            self.require_single_or_double_byte_ranges()?;
            // SAFETY: Only the concrete guest code page and scalar byte are
            // passed; Windows neither reads nor retains a guest pointer.
            if unsafe { IsDBCSLeadByteEx(self.code_page(), first) } != 0 {
                let Some(&trail) = source.get(1) else {
                    return Ok(Probe::NeedMore);
                };
                // AnsiNext returns the terminal NUL, including after a lone
                // lead byte. Absence of the next byte is never a terminator.
                if trail == 0 {
                    return Ok(Probe::Complete(1));
                }
                2
            } else {
                1
            }
        };
        let mut wide = GuestTextBuffer::acquire();
        self.to_wide_into(&source[..length], &mut wide)?;
        if wide.is_empty() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 first character decoded to no UTF-16 units",
            ));
        }
        Ok(Probe::Complete(length))
    }
}

fn invalid_utf8() -> RuntimeError {
    RuntimeError::new(
        Kind::InvalidInput,
        "Win16 first character is not a complete UTF-8 scalar",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::CharNextExA;

    #[test]
    fn ansi_next_dbcs_probe_needs_a_real_trail_or_terminator() {
        for page in [932, 936] {
            let codec = GuestTextCodec::new(page).unwrap();
            assert_eq!(codec.next_character_probe(&[]).unwrap(), Probe::NeedMore);
            assert_eq!(
                codec.next_character_probe(&[0]).unwrap(),
                Probe::Complete(0)
            );
            assert_eq!(
                codec.next_character_probe(&[0x81]).unwrap(),
                Probe::NeedMore
            );
            assert_eq!(
                codec.next_character_probe(&[0x81, 0]).unwrap(),
                Probe::Complete(1)
            );
            for trail in [0x40, b'A', 0x81] {
                assert_eq!(
                    codec.next_character_probe(&[0x81, trail]).unwrap(),
                    Probe::Complete(2)
                );
            }
        }
    }

    #[test]
    fn ansi_next_dbcs_offsets_match_native_charnextexa() {
        for page in [932, 936] {
            let codec = GuestTextCodec::new(page).unwrap();
            for source in [
                [0, 0, 0, 0],
                [b'A', 0, 0, 0],
                [0x81, 0, 0xa5, 0],
                [0x81, 0x40, 0, 0],
                [0x81, b'A', 0, 0],
                [0x81, 0x81, 0, 0],
                [0x81, 0xff, 0, 0],
            ] {
                // Native differential only: every source is owned and NUL
                // terminated. Production never passes guest ANSI pointers to
                // host APIs. This tests DBCS, not the UTF-8 scalar extension.
                // SAFETY: `CharNextExA` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                let native = unsafe { CharNextExA(page as u16, source.as_ptr(), 0) };
                let offset = (native as usize)
                    .checked_sub(source.as_ptr() as usize)
                    .unwrap();
                assert!(offset < source.len());
                assert_eq!(
                    codec.next_character_probe(&source).unwrap(),
                    Probe::Complete(offset),
                    "code page {page}, source {source:?}"
                );
            }
        }
    }

    #[test]
    fn ansi_next_utf8_ignores_invalid_later_characters() {
        let codec = GuestTextCodec::new(65001).unwrap();
        assert_eq!(
            codec.next_character_probe(&[b'A', 0xff, 0]).unwrap(),
            Probe::Complete(1)
        );
        assert_eq!(
            codec.next_character_probe(&[0xc2, 0xa2, 0xff]).unwrap(),
            Probe::Complete(2)
        );
        assert_eq!(
            codec.next_character_probe(&[b'A', 0xcc, 0x81, 0]).unwrap(),
            Probe::Complete(1)
        );
        assert_eq!(
            codec.next_character_probe(&[0xcc, 0x81, 0]).unwrap(),
            Probe::Complete(2)
        );
        for character in ["\u{a2}", "\u{20ac}", "\u{1f642}"] {
            let bytes = character.as_bytes();
            for length in 1..bytes.len() {
                assert_eq!(
                    codec.next_character_probe(&bytes[..length]).unwrap(),
                    Probe::NeedMore
                );
            }
            assert_eq!(
                codec.next_character_probe(bytes).unwrap(),
                Probe::Complete(bytes.len())
            );
        }
    }

    #[test]
    fn ansi_next_utf8_rejects_malformed_first_scalar() {
        let codec = GuestTextCodec::new(65001).unwrap();
        for source in [
            &[0xff][..],
            &[0x80],
            &[0xc0, 0x80],
            &[0xc2, 0],
            &[0xe0, 0x80],
            &[0xed, 0xa0, 0x80],
            &[0xf4, 0x90, 0x80, 0x80],
            &[0xf5],
        ] {
            assert_eq!(
                codec.next_character_probe(source).unwrap_err().kind(),
                Kind::InvalidInput
            );
        }
    }

    #[test]
    fn ansi_next_rejects_stateful_and_wider_code_pages() {
        for page in [65000, 50220, 54936] {
            let codec = GuestTextCodec::new(page).unwrap();
            assert_eq!(
                codec.next_character_probe(b"A").unwrap_err().kind(),
                Kind::CompatibilityGap,
                "code page {page}"
            );
        }
        let sbcs = GuestTextCodec::new(1252).unwrap();
        assert_eq!(
            sbcs.next_character_probe(&[0x81, 0]).unwrap(),
            Probe::Complete(1)
        );
    }
}

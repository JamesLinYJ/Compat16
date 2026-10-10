//! Win16 byte-string operations bridged through the runtime's fixed guest codec.

use super::guest_text::{GuestTextBuffer, GuestTextCodec};
use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Globalization::{lstrcmpW, lstrcmpiW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CharLowerBuffW, CharLowerW, CharUpperBuffW, CharUpperW,
};
use windows_sys::Win32::Globalization::IsDBCSLeadByteEx;

pub(super) fn ansi_lower_char(codec: GuestTextCodec, value: u16) -> Result<u16, RuntimeError> {
    ansi_case_char(codec, value, false)
}

pub(super) fn ansi_upper_char(codec: GuestTextCodec, value: u16) -> Result<u16, RuntimeError> {
    ansi_case_char(codec, value, true)
}

fn ansi_case_char(codec: GuestTextCodec, value: u16, upper: bool) -> Result<u16, RuntimeError> {
    // Win16 character form consumes the low byte. Decode it with the selected
    // guest codec, then call the W pointer-as-character form.
    let mut wide = GuestTextBuffer::acquire();
    codec.to_wide_into(&[value as u8], &mut wide)?;
    let character = *wide.first().ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "guest character decoded to no UTF-16 units"))?;
    if wide.len() != 1 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "one-byte Win16 character decoded to multiple UTF-16 units",
        ));
    }
    let pointer = usize::from(character) as *mut u16;
    // SAFETY: The W scalar form treats a low-valued pointer as a UTF-16
    // character value and does not dereference it.
    let returned = unsafe {
        if upper { CharUpperW(pointer) } else { CharLowerW(pointer) }
    };
    let encoded = codec.from_wide(&[returned as usize as u16])?;
    encoded.bytes.first().copied().map(u16::from).ok_or_else(|| {
        RuntimeError::new(Kind::InternalInvariant,
            "guest character case conversion encoded to no bytes")
    })
}

pub(super) fn ansi_lower_string(
    codec: GuestTextCodec,
    source: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    ansi_case_string(codec, source, false)
}

pub(super) fn ansi_upper_string(
    codec: GuestTextCodec,
    source: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    ansi_case_string(codec, source, true)
}

fn ansi_case_string(
    codec: GuestTextCodec,
    source: &[u8],
    upper: bool,
) -> Result<Vec<u8>, RuntimeError> {
    let mut buffer = GuestTextBuffer::acquire();
    codec.to_wide_z_into(source, &mut buffer)?;
    let base = buffer.as_mut_ptr();
    // SAFETY: The W API receives an owned, writable, terminated UTF-16 string.
    let returned = unsafe {
        if upper { CharUpperW(base) } else { CharLowerW(base) }
    };
    if returned != base {
        return Err(RuntimeError::new(Kind::HostFailure,
            "Windows UTF-16 string case conversion returned a different buffer"));
    }
    let end = buffer.iter().position(|&unit| unit == 0).ok_or_else(|| {
        RuntimeError::new(Kind::HostFailure,
            "Windows UTF-16 string case conversion lost its terminator")
    })?;
    Ok(codec.from_wide(&buffer[..end])?.bytes)
}

/// Apply USER's in-place string casing without allowing any original guest
/// character span to grow. Atom and class key normalization continues to use
/// `ansi_case_string`, whose result may expand because those callers do not
/// write back into the original guest buffer.
pub(super) fn ansi_case_string_in_place(
    codec: GuestTextCodec,
    source: &[u8],
    upper: bool,
) -> Result<Vec<u8>, RuntimeError> {
    let end = source.iter().position(|&byte| byte == 0).unwrap_or(source.len());
    let source = &source[..end];
    if source.is_empty() {
        return Ok(Vec::new());
    }

    let mut wide = GuestTextBuffer::acquire();
    let spans = codec.to_wide_with_ranges_into(source, &mut wide)?;
    let mut output = Vec::new();
    output.try_reserve_exact(source.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 in-place case result", error))?;
    let mut encoded_character = Vec::new();

    for span in spans {
        let guest_bytes = &source[span.guest_bytes.clone()];
        let character = &mut wide[span.utf16_units.clone()];
        let original = codec.from_wide_in_buffer(character, encoded_character)?;
        encoded_character = original.bytes;
        if encoded_character.as_slice() != guest_bytes || original.used_default_char == Some(true) {
            output.extend_from_slice(guest_bytes);
            continue;
        }
        let length = u32::try_from(character.len()).map_err(|error| RuntimeError::with_source(
            Kind::InvalidInput, "Win16 case character exceeds the Windows API length", error))?;
        // SAFETY: `character` owns exactly the UTF-16 units for this guest
        // byte span and remains writable for the synchronous W call.
        let converted = unsafe {
            if upper {
                CharUpperBuffW(character.as_mut_ptr(), length)
            } else {
                CharLowerBuffW(character.as_mut_ptr(), length)
            }
        };
        if converted > length {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Windows UTF-16 character case conversion exceeded its requested length"));
        }
        if converted == length {
            let bounded = codec.from_wide_bounded_in_buffer(
                character, guest_bytes.len(), encoded_character,
            )?;
            encoded_character = bounded.bytes;
            if !bounded.truncated && bounded.source_utf16_units == character.len() {
                output.extend_from_slice(&encoded_character);
                continue;
            }
        }
        // A casing result may need more guest bytes than the original
        // character. Keep that character unchanged and continue transforming
        // later spans; never truncate the whole string or split one encoding.
        output.extend_from_slice(guest_bytes);
    }
    Ok(output)
}

/// Transform exactly the guest byte count, including embedded NUL bytes.
/// The W service counts UTF-16 units, so writeback is accepted only when the
/// converted guest representation still occupies the original byte span.
pub(super) fn ansi_case_buffer(
    codec: GuestTextCodec,
    source: &[u8],
    upper: bool,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    if source.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let mut buffer = GuestTextBuffer::acquire();
    codec.to_wide_into(source, &mut buffer)?;
    let length = u32::try_from(buffer.len()).map_err(|error| RuntimeError::with_source(
        Kind::InvalidInput, "Win16 UTF-16 case buffer exceeds the Windows API length", error))?;
    // SAFETY: The vector owns all requested writable UTF-16 units for this
    // synchronous bounded native operation.
    let converted = unsafe {
        if upper {
            CharUpperBuffW(buffer.as_mut_ptr(), length)
        } else {
            CharLowerBuffW(buffer.as_mut_ptr(), length)
        }
    };
    if converted > length {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "Windows UTF-16 buffer case conversion exceeded its requested length"));
    }
    if converted == 0 || converted < length {
        return Ok(None);
    }
    let bytes = codec.from_wide(&buffer)?.bytes;
    if bytes.len() == source.len() {
        Ok(Some(bytes))
    } else {
        Ok(None)
    }
}

pub(super) fn ansi_compare(
    codec: GuestTextCodec,
    left: &[u8],
    right: &[u8],
    ignore_case: bool,
) -> Result<i16, RuntimeError> {
    let mut wide_left = GuestTextBuffer::acquire();
    codec.to_wide_z_into(left, &mut wide_left)?;
    let mut wide_right = GuestTextBuffer::acquire();
    codec.to_wide_z_into(right, &mut wide_right)?;
    // SAFETY: Both arguments are separate owned NUL-terminated UTF-16 strings.
    let result = unsafe {
        if ignore_case { lstrcmpiW(wide_left.as_ptr(), wide_right.as_ptr()) }
        else { lstrcmpW(wide_left.as_ptr(), wide_right.as_ptr()) }
    };
    Ok(result.signum() as i16)
}

/// Return the guest-byte offset of the next character. Valid text is mapped
/// through the codec's per-character spans. An isolated DBCS lead uses only
/// the explicit code-page lead-byte query to preserve its historical offset
/// past the NUL when that position has real guest backing.
pub(super) fn ansi_next_offset(
    codec: GuestTextCodec,
    source: &[u8],
) -> Result<usize, RuntimeError> {
    if source.is_empty() || source[0] == 0 {
        return Ok(0);
    }
    if is_dangling_dbcs_next(codec, source) {
        return next_damaged_dbcs_offset(codec, source);
    }
    let mut wide = GuestTextBuffer::acquire();
    let spans = codec.to_wide_with_ranges_into(source, &mut wide)?;
    spans.first().map(|span| span.guest_bytes.end).ok_or_else(|| {
        RuntimeError::new(Kind::InternalInvariant,
            "decoded guest text has no character boundary")
    })
}

fn next_damaged_dbcs_offset(
    _codec: GuestTextCodec,
    _source: &[u8],
) -> Result<usize, RuntimeError> {
    // A damaged DBCS lead is followed by the owned string terminator. The
    // Win16 byte boundary advances over the lead and that terminator; this
    // arithmetic preserves the old offset without passing guest bytes to an
    // ANSI host API.
    Ok(2)
}

/// Return the guest-byte offset of the previous character before current.
/// A current offset splitting a DBCS sequence uses its checked range or the
/// explicit guest-page lead-byte query to preserve the Win16 byte offset.
pub(super) fn ansi_prev_offset(
    codec: GuestTextCodec,
    source: &[u8],
    current: usize,
) -> Result<usize, RuntimeError> {
    if current > source.len() {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 previous-character offset exceeds its source"));
    }
    if current == 0 {
        return Ok(0);
    }
    let prefix = &source[..current];
    // A DBCS trail byte can also be a valid lead byte. Determine the previous
    // boundary by scanning from the start, never by classifying the last byte.
    let mut wide = GuestTextBuffer::acquire();
    let spans = match codec.to_wide_with_ranges_into(prefix, &mut wide) {
        Ok(spans) => spans,
        Err(prefix_error) => {
            let spans = codec.to_wide_with_ranges_into(source, &mut wide)
                .map_err(|_| prefix_error)?;
            spans
        }
    };
    spans.iter().rev()
        .find(|span| span.guest_bytes.start < current)
        .map(|span| span.guest_bytes.start)
        .ok_or_else(|| {
        RuntimeError::new(Kind::InternalInvariant,
            "decoded guest prefix has no previous-character boundary")
    })
}

fn is_dangling_dbcs_next(codec: GuestTextCodec, source: &[u8]) -> bool {
    let Some(&first) = source.first() else { return false; };
    let followed_by_nul = source.get(1).copied().unwrap_or(0) == 0;
    // SAFETY: This API reads only the selected explicit code page and byte.
    followed_by_nul && unsafe { IsDBCSLeadByteEx(codec.code_page(), first) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp936() -> GuestTextCodec {
        GuestTextCodec::new(936).expect("Windows should provide code page 936")
    }

    #[test]
    fn w_case_and_compare_keep_guest_bytes_and_counted_nuls() {
        let codec = cp936();
        assert_eq!(ansi_lower_char(codec, b'A' as u16).unwrap(), b'a' as u16);
        assert_eq!(ansi_upper_char(codec, b'a' as u16).unwrap(), b'A' as u16);
        assert_eq!(ansi_lower_string(codec, b"A").unwrap(), b"a");
        assert_eq!(ansi_upper_string(codec, b"a").unwrap(), b"A");
        assert_eq!(
            ansi_case_buffer(codec, b"a\0b", true).unwrap(),
            Some(b"A\0B".to_vec()),
        );
        assert_eq!(ansi_compare(codec, b"A", b"b", false).unwrap(), -1);
    }

    #[test]
    fn local_atom_case_keys_preserve_dbcs_trail_bytes() {
        for page in [932, 936] {
            let codec = GuestTextCodec::new(page).expect("Windows DBCS code page");
            // The second byte belongs to a two-byte character. Treating it
            // as ASCII would turn two distinct atom names into the same key.
            let upper_trail = [0x81, b'A', b'Z'];
            let lower_trail = [0x81, b'a', b'Z'];
            let first = ansi_lower_string(codec, &upper_trail).unwrap();
            let second = ansi_lower_string(codec, &lower_trail).unwrap();
            assert_eq!(first, [0x81, b'A', b'z'], "code page {page}");
            assert_eq!(second, [0x81, b'a', b'z'], "code page {page}");
            assert_ne!(first, second, "code page {page}");
            assert_eq!(ansi_lower_string(codec, &[0x81, b'A', b'z']).unwrap(), first);
        }
    }

    #[test]
    fn in_place_case_preserves_only_the_guest_character_that_would_expand() {
        let utf8 = GuestTextCodec::new(65001).expect("Windows should provide code page 65001");
        // U+023A lowercases to U+2C65, which needs three UTF-8 bytes instead
        // of the source character's two. The following ASCII character still
        // lowercases normally.
        assert_eq!(ansi_case_string_in_place(utf8, &[0xc6, 0xba, b'A'], false).unwrap(),
            [0xc6, 0xba, b'a']);
    }

    #[test]
    fn dbcs_offsets_use_ranges_and_preserve_damaged_lead_contract() {
        let codec = cp936();
        let valid = [0xd6, 0xd0, b'A']; // GBK for the first character is two bytes.
        assert_eq!(ansi_next_offset(codec, &valid).unwrap(), 2);
        assert_eq!(ansi_prev_offset(codec, &valid, 1).unwrap(), 0);
        assert_eq!(ansi_prev_offset(codec, &valid, 2).unwrap(), 0);
        assert_eq!(ansi_prev_offset(codec, &valid, 3).unwrap(), 2);

        assert_eq!(ansi_next_offset(codec, &[0x81]).unwrap(), 2);
        assert_eq!(ansi_prev_offset(codec, &[b'A', 0x81], 2).unwrap(), 1);
    }
}

//! Legacy LZ filename transforms over explicit guest character boundaries.
//! Only standalone bytes participate in separators, dots and underscores.

use super::{GuestTextCodec, Kind, RuntimeError};
use crate::windows::guest_text::GuestTextSpan;

fn extension(bytes: &[u8], spans: &[GuestTextSpan]) -> Option<usize> {
    let mut dot = None;
    for span in spans.iter().filter(|span| span.guest_bytes.len() == 1) {
        match bytes[span.guest_bytes.start] {
            b'\\' | b'/' | b':' => dot = None,
            b'.' => dot = Some(span.guest_bytes.start),
            _ => {}
        }
    }
    dot
}

pub(super) fn compressed_leaf(
    codec: GuestTextCodec,
    leaf: &str,
) -> Result<Option<String>, RuntimeError> {
    let encoded = codec.from_wide(&leaf.encode_utf16().collect::<Vec<_>>())?;
    if encoded.used_default_char == Some(true) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "LZ filename is not representable in its guest code page",
        ));
    }
    let mut bytes = encoded.bytes;
    let (_, spans) = codec.to_wide_with_ranges(&bytes)?;
    let original = bytes.clone();
    match extension(&bytes, &spans) {
        None => bytes.extend_from_slice(b"._"),
        Some(dot) if bytes.len() - dot - 1 < 3 => bytes.push(b'_'),
        Some(dot) => {
            // SZDD stores one replaced byte. Never split a DBCS/UTF-8
            // character. Use the reversible final-byte or leading-SBCS
            // form; other long extensions append an underscore instead.
            let ext: Vec<_> = spans
                .iter()
                .filter(|span| span.guest_bytes.start > dot)
                .collect();
            let replacement = match ext.last() {
                Some(last) if last.guest_bytes.len() == 1 => Some(last.guest_bytes.start),
                _ => match ext.as_slice() {
                    [first, second, ..]
                        if first.guest_bytes.len() == 1 && second.guest_bytes.len() > 1 =>
                    {
                        Some(first.guest_bytes.start)
                    }
                    _ => None,
                },
            };
            match replacement {
                Some(index) => bytes[index] = b'_',
                None => bytes.push(b'_'),
            }
        }
    }
    if bytes == original {
        return Ok(None);
    }
    let wide = codec.to_wide(&bytes)?;
    String::from_utf16(&wide).map(Some).map_err(|error| {
        RuntimeError::with_source(Kind::InvalidInput, "decode compressed LZ filename", error)
    })
}

pub(super) fn expanded(
    codec: GuestTextCodec,
    source: &[u8],
    last: Option<u8>,
) -> Result<Vec<u8>, RuntimeError> {
    let (_, spans) = codec.to_wide_with_ranges(source)?;
    let mut output = source.to_vec();
    let Some(mut last) = last else {
        return Ok(output);
    };
    let Some(dot) = extension(source, &spans) else {
        return Ok(output);
    };
    if last.is_ascii_alphabetic() {
        if let Some(first) = spans
            .iter()
            .filter(|span| span.guest_bytes.len() == 1)
            .map(|span| source[span.guest_bytes.start])
            .find(u8::is_ascii_alphabetic)
        {
            last = if first.is_ascii_lowercase() {
                last.to_ascii_lowercase()
            } else {
                last.to_ascii_uppercase()
            };
        }
    }
    let ext: Vec<_> = spans
        .iter()
        .filter(|span| span.guest_bytes.start > dot)
        .collect();
    let replacement = match ext.as_slice() {
        [first, second, ..]
            if first.guest_bytes.len() == 1
                && source[first.guest_bytes.start] == b'_'
                && second.guest_bytes.len() > 1 =>
        {
            Some(first.guest_bytes.start)
        }
        _ => ext
            .last()
            .filter(|span| span.guest_bytes.len() == 1 && source[span.guest_bytes.start] == b'_')
            .map(|span| span.guest_bytes.start),
    };
    if let Some(index) = replacement {
        if last == 0 {
            output.truncate(index);
            if output.len() == dot + 1 {
                output.truncate(dot);
            }
        } else {
            output[index] = last;
        }
    }
    // Validate the restored byte sequence without silently substituting a
    // malformed header character in the fixed guest code page.
    codec.to_wide(&output)?;
    Ok(output)
}

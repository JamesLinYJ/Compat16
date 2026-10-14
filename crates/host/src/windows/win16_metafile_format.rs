//! Bounded framing for the fixed Windows 3.1 METAHEADER/METARECORD layout.
//!
//! GDI interprets drawing records. This small codec only checks byte extents
//! and locates Escape records whose payload needs a separate ABI translator.

pub(super) const HEADER_BYTES: usize = 18;
const HEADER_WORDS: u16 = 9;
const META_ESCAPE: u16 = 0x0626;

pub(super) fn byte_length(header: &[u8]) -> Option<usize> {
    if header.len() < HEADER_BYTES
        || !matches!(word(header, 0)?, 1 | 2)
        || word(header, 2)? != HEADER_WORDS
        || !matches!(word(header, 4)?, 0x0100 | 0x0300)
    {
        return None;
    }
    let length = usize::try_from(dword(header, 6)?).ok()?.checked_mul(2)?;
    (length >= HEADER_BYTES + 6).then_some(length)
}

pub(super) struct MetafileBits<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) has_escape: bool,
}

pub(super) fn validate(bytes: &[u8]) -> Option<MetafileBits<'_>> {
    let length = byte_length(bytes)?;
    let bytes = bytes.get(..length)?;
    let mut offset = HEADER_BYTES;
    let mut has_escape = false;
    while offset < length {
        let record_words = usize::try_from(dword(bytes, offset)?).ok()?;
        if record_words < 3 { return None; }
        let next = offset.checked_add(record_words.checked_mul(2)?)?;
        if next > length { return None; }
        let function = word(bytes, offset.checked_add(4)?)?;
        if function == 0 {
            return (record_words == 3 && next == length)
                .then_some(MetafileBits { bytes, has_escape });
        }
        // Historical native playback dispatches on the low byte, even when
        // an untrusted record supplies a noncanonical high-byte argument count.
        has_escape |= function & 0x00ff == META_ESCAPE & 0x00ff;
        offset = next;
    }
    None
}

fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}

fn dword(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}

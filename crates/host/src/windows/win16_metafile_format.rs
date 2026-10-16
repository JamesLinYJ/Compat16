//! Bounded framing for the fixed Windows 3.1 METAHEADER/METARECORD layout.
//!
//! GDI interprets drawing records. This small codec only checks byte extents
//! and locates Escape records whose payload needs a separate ABI translator.

pub(super) const HEADER_BYTES: usize = formats::WMF_HEADER_BYTES;

pub(super) fn byte_length(header: &[u8]) -> Option<usize> {
    formats::parse_wmf_header(header).ok().map(|header| header.byte_length())
}

pub(super) struct MetafileBits<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) has_escape: bool,
}

pub(super) fn validate(bytes: &[u8]) -> Option<MetafileBits<'_>> {
    let parsed = formats::parse_wmf(bytes).ok()?;
    Some(MetafileBits { bytes: parsed.bytes(), has_escape: parsed.has_escape() })
}

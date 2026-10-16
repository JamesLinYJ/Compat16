//! Checked Windows 3.x METAHEADER and METARECORD framing.
//!
//! These fixed 18-byte and 6-byte wire layouts follow WINDOWS.H and MS-WMF.
//! This reader checks byte extents and exposes immutable record slices; native
//! GDI remains responsible for interpreting drawing operations. In particular,
//! framing alone does not make a record safe for standalone native playback.

mod playback;
pub use playback::{WmfPlaybackError, WmfPlaybackRecord, validate_wmf_record_playback};

use std::fmt;

pub const WMF_HEADER_BYTES: usize = 18;
pub const WMF_RECORD_HEADER_BYTES: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WmfError {
    TruncatedHeader,
    InvalidHeader,
    InvalidLength,
    InvalidRecord { offset: usize },
    InvalidEndRecord { offset: usize },
    MissingEndRecord,
}

impl fmt::Display for WmfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("truncated WMF header"),
            Self::InvalidHeader => f.write_str("unsupported WMF header layout"),
            Self::InvalidLength => f.write_str("WMF size exceeds its backing bytes"),
            Self::InvalidRecord { offset } => write!(f, "invalid WMF record at byte {offset}"),
            Self::InvalidEndRecord { offset } => {
                write!(f, "invalid WMF end record at byte {offset}")
            }
            Self::MissingEndRecord => f.write_str("WMF has no end record"),
        }
    }
}

impl std::error::Error for WmfError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WmfHeader {
    pub kind: u16,
    pub version: u16,
    pub total_words: u32,
    pub object_count: u16,
    /// The file's claim, distinct from the checked largest record below.
    pub declared_maximum_record_words: u32,
    pub parameter_count: u16,
    byte_length: usize,
}

impl WmfHeader {
    pub fn byte_length(self) -> usize {
        self.byte_length
    }
}

/// Read just the fixed header, before a file reader allocates the stream.
pub fn parse_wmf_header(bytes: &[u8]) -> Result<WmfHeader, WmfError> {
    let bytes = bytes
        .get(..WMF_HEADER_BYTES)
        .ok_or(WmfError::TruncatedHeader)?;
    let kind = word(bytes, 0).ok_or(WmfError::TruncatedHeader)?;
    let version = word(bytes, 4).ok_or(WmfError::TruncatedHeader)?;
    if !matches!(kind, 1 | 2) || word(bytes, 2) != Some(9) || !matches!(version, 0x0100 | 0x0300) {
        return Err(WmfError::InvalidHeader);
    }
    let total_words = dword(bytes, 6).ok_or(WmfError::TruncatedHeader)?;
    let byte_length = usize::try_from(total_words)
        .ok()
        .and_then(|words| words.checked_mul(2))
        .ok_or(WmfError::InvalidLength)?;
    if byte_length < WMF_HEADER_BYTES + WMF_RECORD_HEADER_BYTES {
        return Err(WmfError::InvalidLength);
    }
    Ok(WmfHeader {
        kind,
        version,
        total_words,
        byte_length,
        object_count: word(bytes, 10).ok_or(WmfError::TruncatedHeader)?,
        declared_maximum_record_words: dword(bytes, 12).ok_or(WmfError::TruncatedHeader)?,
        parameter_count: word(bytes, 16).ok_or(WmfError::TruncatedHeader)?,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct WmfRecord<'a> {
    bytes: &'a [u8],
    offset: usize,
    words: u32,
    function: u16,
}

impl<'a> WmfRecord<'a> {
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    pub fn parameters(self) -> &'a [u8] {
        &self.bytes[WMF_RECORD_HEADER_BYTES..]
    }
    pub fn offset(self) -> usize {
        self.offset
    }
    pub fn words(self) -> u32 {
        self.words
    }
    pub fn function(self) -> u16 {
        self.function
    }
    pub fn is_end(self) -> bool {
        self.function == 0
    }
    // Native classic playback dispatches Escape by its low byte, even when
    // a record supplies a noncanonical high-byte parameter count.
    pub fn is_escape(self) -> bool {
        self.function & 0xff == 0x26
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WmfMetafile<'a> {
    bytes: &'a [u8],
    header: WmfHeader,
    record_count: usize,
    maximum_record_words: u32,
    has_escape: bool,
}

impl<'a> WmfMetafile<'a> {
    /// Logical stream only. A Win16 HGLOBAL can also contain allocation padding.
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    pub fn header(self) -> WmfHeader {
        self.header
    }
    /// Includes the terminating META_EOF record.
    pub fn record_count(self) -> usize {
        self.record_count
    }
    pub fn maximum_record_words(self) -> u32 {
        self.maximum_record_words
    }
    pub fn has_escape(self) -> bool {
        self.has_escape
    }
    /// The immutable, checked record sequence, including META_EOF.
    pub fn records(self) -> WmfRecords<'a> {
        WmfRecords {
            bytes: self.bytes,
            offset: WMF_HEADER_BYTES,
            remaining: self.record_count,
        }
    }
}

/// Validate the full record chain without allocating or interpreting GDI data.
pub fn parse_wmf(bytes: &[u8]) -> Result<WmfMetafile<'_>, WmfError> {
    let header = parse_wmf_header(bytes)?;
    let bytes = bytes
        .get(..header.byte_length)
        .ok_or(WmfError::InvalidLength)?;
    let mut offset = WMF_HEADER_BYTES;
    let mut count = 0;
    let mut maximum_record_words = 0;
    let mut has_escape = false;
    while offset < bytes.len() {
        let record = read_record(bytes, offset)?;
        count += 1; // Every record consumes at least six backing bytes.
        maximum_record_words = maximum_record_words.max(record.words);
        has_escape |= record.is_escape();
        let next = offset + record.bytes.len(); // read_record checked this sum.
        if record.is_end() {
            if record.words != 3 || next != bytes.len() {
                return Err(WmfError::InvalidEndRecord { offset });
            }
            return Ok(WmfMetafile {
                bytes,
                header,
                record_count: count,
                maximum_record_words,
                has_escape,
            });
        }
        offset = next;
    }
    Err(WmfError::MissingEndRecord)
}

pub struct WmfRecords<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: usize,
}

impl<'a> Iterator for WmfRecords<'a> {
    type Item = WmfRecord<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        // Only parse_wmf constructs this iterator, over the same immutable
        // bytes it already checked. No guest or native pointer is retained.
        let record = read_record(self.bytes, self.offset).ok()?;
        self.offset += record.bytes.len();
        self.remaining -= 1;
        Some(record)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for WmfRecords<'_> {}
impl std::iter::FusedIterator for WmfRecords<'_> {}

/// Check a standalone record against its complete owned extent.
pub fn parse_wmf_record(bytes: &[u8]) -> Result<WmfRecord<'_>, WmfError> {
    let record = read_record(bytes, 0)?;
    if record.bytes.len() != bytes.len() {
        return Err(WmfError::InvalidRecord { offset: 0 });
    }
    Ok(record)
}

fn read_record(bytes: &[u8], offset: usize) -> Result<WmfRecord<'_>, WmfError> {
    let error = WmfError::InvalidRecord { offset };
    let words = dword(bytes, offset).ok_or(error)?;
    if words < 3 {
        return Err(error);
    }
    let length = usize::try_from(words)
        .ok()
        .and_then(|words| words.checked_mul(2))
        .ok_or(error)?;
    let end = offset.checked_add(length).ok_or(error)?;
    let record = bytes.get(offset..end).ok_or(error)?;
    let function = word(record, 4).ok_or(error)?;
    Ok(WmfRecord {
        bytes: record,
        offset,
        words,
        function,
    })
}

fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn dword(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests;

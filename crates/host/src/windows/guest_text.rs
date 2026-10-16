//! Checked conversion between an explicit guest code page and host UTF-16.

#[path = "guest_text_next.rs"]
mod next;

#[path = "guest_text_buffer.rs"]
mod buffer;
pub(in crate::windows) use buffer::GuestTextBuffer;

use std::error::Error;
use std::fmt;
use std::ops::Range;
use std::ptr;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_UNICODE_TRANSLATION};
use windows_sys::Win32::Globalization::{
    CP_ACP, CP_MACCP, CP_OEMCP, CP_SYMBOL, CP_THREAD_ACP, CP_UTF7, CP_UTF8, CPINFO,
    GetCPInfo, IsDBCSLeadByteEx, IsValidCodePage, MB_ERR_INVALID_CHARS, MultiByteToWideChar,
    WC_ERR_INVALID_CHARS, WC_NO_BEST_FIT_CHARS, WideCharToMultiByte,
};

// Windows requires zero flags for these legacy/stateful pages. UTF-8 and
// GB18030 accept only zero or WC_ERR_INVALID_CHARS. Keep these exceptions here
// because the Win32 conversion API, rather than a Rust codec, defines them.
const CP_GB18030: u32 = 54_936;
const CP_HZ_GB2312: u32 = 52_936;
const CP_WINDOWS_50220: u32 = 50_220;
const CP_WINDOWS_50221: u32 = 50_221;
const CP_WINDOWS_50222: u32 = 50_222;
const CP_WINDOWS_50225: u32 = 50_225;
const CP_WINDOWS_50227: u32 = 50_227;
const CP_WINDOWS_50229: u32 = 50_229;
const CP_WINDOWS_50930: u32 = 50_930;
const CP_WINDOWS_50939: u32 = 50_939;
const CP_WINDOWS_57002: u32 = 57_002;
const CP_WINDOWS_57011: u32 = 57_011;

/// A fixed guest encoding selected by the executable/runtime, independent of
/// the host's current ANSI or OEM locale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) struct GuestTextCodec {
    code_page: u32,
}

/// Result of converting host UTF-16 to guest bytes.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::windows) struct GuestTextEncoding {
    pub(in crate::windows) bytes: Vec<u8>,
    /// `Some(true)` means Windows used its default replacement character.
    /// `Some(false)` means it did not. Windows requires this output pointer to
    /// be null for UTF-7 and UTF-8, so those pages report `None`.
    pub(in crate::windows) used_default_char: Option<bool>,
}

/// A guest-byte encoding clipped at a Unicode scalar boundary.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::windows) struct BoundedGuestTextEncoding {
    pub(in crate::windows) bytes: Vec<u8>,
    /// Number of source UTF-16 code units represented in `bytes`.
    pub(in crate::windows) source_utf16_units: usize,
    pub(in crate::windows) truncated: bool,
    pub(in crate::windows) used_default_char: Option<bool>,
}

/// Corresponding source-byte and host UTF-16 ranges for one decoded guest
/// character. Both ranges are half-open and relative to their input/output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::windows) struct GuestTextSpan {
    pub(in crate::windows) guest_bytes: Range<usize>,
    pub(in crate::windows) utf16_units: Range<usize>,
}

impl GuestTextCodec {
    /// Create a codec for one installed numeric Windows code page.
    ///
    /// The symbolic process/thread locale selectors are rejected so callers
    /// cannot accidentally let ACP/OEM changes alter the guest's text ABI.
    pub(in crate::windows) fn new(code_page: u32) -> Result<Self, RuntimeError> {
        if matches!(code_page, CP_ACP | CP_OEMCP | CP_MACCP | CP_THREAD_ACP) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "guest text codec requires a concrete Windows code page",
            ));
        }

        // SAFETY: IsValidCodePage accepts a scalar code-page identifier and
        // retains no pointer or caller-owned memory.
        if unsafe { IsValidCodePage(code_page) } == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                format!("Windows does not report code page {code_page} as valid"),
            ));
        }
        Ok(Self { code_page })
    }

    pub(in crate::windows) const fn code_page(self) -> u32 {
        self.code_page
    }

    /// Convert exactly these guest bytes; no implicit terminator is consumed
    /// or appended. Empty input is handled without passing a zero length to
    /// the Windows API.
    pub(in crate::windows) fn to_wide(&self, source: &[u8]) -> Result<Vec<u16>, RuntimeError> {
        let mut wide = Vec::new();
        self.to_wide_into(source, &mut wide)?;
        Ok(wide)
    }

    /// Replace an owned scratch buffer with the exact conversion. A failed
    /// conversion leaves it empty, and its capacity remains reusable.
    pub(in crate::windows) fn to_wide_into(
        &self, source: &[u8], wide: &mut Vec<u16>,
    ) -> Result<(), RuntimeError> {
        self.to_wide_buffer(source, wide, false)
    }

    fn to_wide_buffer(
        &self, source: &[u8], wide: &mut Vec<u16>, terminated: bool,
    ) -> Result<(), RuntimeError> {
        wide.clear();
        if source.is_empty() {
            if terminated {
                wide.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted, "terminate guest text", error,
                ))?;
                wide.push(0);
            }
            return Ok(());
        }

        let source_length = checked_i32(source.len(), "size guest text input")?;
        let flags = multibyte_flags(self.code_page);
        // SAFETY: `source` is a live immutable slice for the synchronous call;
        // the null destination and zero capacity request the exact UTF-16 size.
        let required = unsafe {
            MultiByteToWideChar(
                self.code_page,
                flags,
                source.as_ptr(),
                source_length,
                ptr::null_mut(),
                0,
            )
        };
        if required <= 0 {
            return Err(windows_failure(
                "size guest text conversion",
                self.code_page,
                unsafe { GetLastError() },
            ));
        }

        let length = checked_usize(required, "size guest UTF-16 output")?
            .checked_add(usize::from(terminated))
            .ok_or_else(|| resource_limit("size terminated guest UTF-16 output"))?;
        wide.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate guest UTF-16 output", error,
        ))?;
        wide.resize(length, 0);
        // SAFETY: both slices remain alive for the synchronous call. The
        // destination covers the sizing result plus any separate terminator.
        let written = unsafe {
            MultiByteToWideChar(
                self.code_page,
                flags,
                source.as_ptr(),
                source_length,
                wide.as_mut_ptr(),
                required,
            )
        };
        if written <= 0 {
            let last_error = unsafe { GetLastError() };
            wide.clear();
            return Err(windows_failure(
                "convert guest text to UTF-16",
                self.code_page,
                last_error,
            ));
        }
        if written != required {
            wide.clear();
            return Err(conversion_invariant("guest text conversion size changed"));
        }
        Ok(())
    }

    /// Decode guest bytes once and report exact source-byte / UTF-16 ranges.
    /// UTF-8 uses Rust's validated scalar boundaries; ordinary SBCS/DBCS pages
    /// use Windows lead-byte metadata with checked source-byte ranges.
    /// A mapping that Windows cannot describe as independent characters is a
    /// compatibility gap; plain `to_wide` still supports that code page.
    pub(in crate::windows) fn to_wide_with_ranges(
        &self,
        source: &[u8],
    ) -> Result<(Vec<u16>, Vec<GuestTextSpan>), RuntimeError> {
        let mut wide = Vec::new();
        let spans = self.to_wide_with_ranges_into(source, &mut wide)?;
        Ok((wide, spans))
    }

    pub(in crate::windows) fn to_wide_with_ranges_into(
        &self, source: &[u8], wide: &mut Vec<u16>,
    ) -> Result<Vec<GuestTextSpan>, RuntimeError> {
        self.to_wide_into(source, wide)?;
        if source.is_empty() {
            return Ok(Vec::new());
        }
        if self.code_page == CP_UTF8 {
            return utf8_spans(source, wide);
        }

        self.require_single_or_double_byte_ranges()?;
        sbcs_dbcs_spans(self, source, wide)
    }

    fn require_single_or_double_byte_ranges(&self) -> Result<(), RuntimeError> {
        if is_stateful_mapping_page(self.code_page) {
            return Err(mapping_gap(
                self.code_page,
                "stateful guest code-page character ranges are not supported",
            ));
        }
        // Only the maximum byte width is needed. GetCPInfo supplies that
        // contract without requesting GetCPInfoExW's unused localized name
        // and extended fields; a failed basic query still fails closed.
        let mut info = CPINFO::default();
        // SAFETY: `info` is an initialized, writable CPINFO owned by this
        // call; Windows writes only the documented structure synchronously.
        if unsafe { GetCPInfo(self.code_page, &mut info) } == 0 {
            let last_error = unsafe { GetLastError() };
            #[cfg(test)]
            eprintln!("GetCPInfo failed: page={}, error={last_error}, maximum={}, \
                default={:?}, lead={:?}, thread={:?}", self.code_page,
                info.MaxCharSize, info.DefaultChar, info.LeadByte, std::thread::current().id());
            return Err(mapping_gap_with_windows_error(
                self.code_page,
                "Windows code-page metadata is unavailable for character mapping",
                last_error,
            ));
        }
        if !(1..=2).contains(&info.MaxCharSize) {
            return Err(mapping_gap(
                self.code_page,
                "character mapping currently requires an SBCS or DBCS code page",
            ));
        }
        Ok(())
    }

    /// Convert a present guest string and append one host UTF-16 NUL. Pass
    /// `None` through the caller's `Option::map` to keep absent distinct from
    /// `Some(&[])`, which becomes a one-unit empty C string.
    pub(in crate::windows) fn to_wide_z(&self, source: &[u8]) -> Result<Vec<u16>, RuntimeError> {
        let mut wide = Vec::new();
        self.to_wide_z_into(source, &mut wide)?;
        Ok(wide)
    }

    pub(in crate::windows) fn to_wide_z_into(
        &self, source: &[u8], wide: &mut Vec<u16>,
    ) -> Result<(), RuntimeError> {
        self.to_wide_buffer(source, wide, true)
    }

    /// Convert the exact UTF-16 input to guest bytes without adding a NUL.
    /// Windows' documented default-character replacement is retained for code
    /// pages that expose it; `used_default_char` reports only the API's single
    /// aggregate flag, not which characters changed or whether best-fit
    /// mappings occurred on pages that require zero flags.
    pub(in crate::windows) fn from_wide(
        &self,
        source: &[u16],
    ) -> Result<GuestTextEncoding, RuntimeError> {
        self.from_wide_in_buffer(source, Vec::new())
    }

    /// Reuse an owned guest output allocation while preserving its exact byte
    /// count and the converter's default-character indication.
    pub(in crate::windows) fn from_wide_in_buffer(
        &self, source: &[u16], bytes: Vec<u8>,
    ) -> Result<GuestTextEncoding, RuntimeError> {
        let required = self.wide_length(source)?;
        self.encode_wide_in_buffer(source, required, bytes)
    }

    /// Convert as much UTF-16 as fits in a guest byte capacity, ending only at
    /// complete UTF-16 scalar boundaries. Each candidate size is measured by
    /// the same Windows code-page converter that emits the final bytes, so
    /// DBCS/UTF-8 sequences are never cut at an assumed byte width.
    pub(in crate::windows) fn from_wide_bounded(
        &self,
        source: &[u16],
        byte_capacity: usize,
    ) -> Result<BoundedGuestTextEncoding, RuntimeError> {
        self.from_wide_bounded_in_buffer(source, byte_capacity, Vec::new())
    }

    pub(in crate::windows) fn from_wide_bounded_in_buffer(
        &self, source: &[u16], byte_capacity: usize, bytes: Vec<u8>,
    ) -> Result<BoundedGuestTextEncoding, RuntimeError> {
        let full_length = self.wide_length(source)?;
        if full_length <= byte_capacity {
            let encoded = self.encode_wide_in_buffer(source, full_length, bytes)?;
            return Ok(BoundedGuestTextEncoding {
                bytes: encoded.bytes,
                source_utf16_units: source.len(),
                truncated: false,
                used_default_char: encoded.used_default_char,
            });
        }

        let boundaries = utf16_prefix_boundaries(source)?;
        // The full input is known not to fit. Encoded byte length is
        // non-decreasing as complete source scalars are appended; binary
        // search avoids repeatedly converting every earlier prefix.
        let mut fitting = 0_usize;
        let mut non_fitting = boundaries.len() - 1;
        while fitting + 1 < non_fitting {
            let middle = fitting + (non_fitting - fitting) / 2;
            let prefix_length = self.wide_length(&source[..boundaries[middle]])?;
            if prefix_length <= byte_capacity {
                fitting = middle;
            } else {
                non_fitting = middle;
            }
        }

        let source_utf16_units = boundaries[fitting];
        let prefix = &source[..source_utf16_units];
        let prefix_length = self.wide_length(prefix)?;
        let encoded = self.encode_wide_in_buffer(prefix, prefix_length, bytes)?;
        Ok(BoundedGuestTextEncoding {
            bytes: encoded.bytes,
            source_utf16_units,
            truncated: source_utf16_units != source.len(),
            used_default_char: encoded.used_default_char,
        })
    }

    fn wide_length(&self, source: &[u16]) -> Result<usize, RuntimeError> {
        if source.is_empty() {
            return Ok(0);
        }
        let source_length = checked_i32(source.len(), "size host UTF-16 text")?;
        let flags = wide_flags(self.code_page);
        // SAFETY: `source` is a live immutable slice for the synchronous call;
        // a null destination asks Windows for the exact guest-byte count.
        let required = unsafe {
            WideCharToMultiByte(
                self.code_page,
                flags,
                source.as_ptr(),
                source_length,
                ptr::null_mut(),
                0,
                ptr::null(),
                ptr::null_mut(),
            )
        };
        if required <= 0 {
            return Err(windows_failure(
                "size guest text output",
                self.code_page,
                unsafe { GetLastError() },
            ));
        }
        checked_usize(required, "size guest text output")
    }

    fn encode_wide_in_buffer(
        &self,
        source: &[u16],
        required: usize,
        mut bytes: Vec<u8>,
    ) -> Result<GuestTextEncoding, RuntimeError> {
        bytes.clear();
        let used_default_char = if has_default_char_indicator(self.code_page) {
            Some(false)
        } else {
            None
        };
        if source.is_empty() {
            return Ok(GuestTextEncoding {
                bytes,
                used_default_char,
            });
        }
        if required == 0 {
            return Err(conversion_invariant(
                "nonempty guest text has zero encoded size",
            ));
        }

        let source_length = checked_i32(source.len(), "size host UTF-16 text")?;
        let capacity = checked_i32(required, "size guest text output")?;
        bytes.try_reserve_exact(required).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate guest text output", error,
        ))?;
        bytes.resize(required, 0);
        let flags = wide_flags(self.code_page);
        let mut used_default = 0;
        let used_default_ptr = if has_default_char_indicator(self.code_page) {
            &mut used_default
        } else {
            ptr::null_mut()
        };
        // SAFETY: the UTF-16 source and owned byte destination are live for
        // the synchronous call; `capacity` is the exact size queried above.
        let written = unsafe {
            WideCharToMultiByte(
                self.code_page,
                flags,
                source.as_ptr(),
                source_length,
                bytes.as_mut_ptr(),
                capacity,
                ptr::null(),
                used_default_ptr,
            )
        };
        if written <= 0 {
            return Err(windows_failure(
                "convert host UTF-16 text to guest bytes",
                self.code_page,
                unsafe { GetLastError() },
            ));
        }
        if written != capacity {
            return Err(conversion_invariant("guest text output size changed"));
        }
        Ok(GuestTextEncoding {
            bytes,
            used_default_char: if has_default_char_indicator(self.code_page) {
                Some(used_default != 0)
            } else {
                None
            },
        })
    }
}

fn multibyte_flags(code_page: u32) -> u32 {
    if matches!(code_page, CP_UTF8 | CP_GB18030) {
        MB_ERR_INVALID_CHARS
    } else {
        0
    }
}

fn wide_flags(code_page: u32) -> u32 {
    if matches!(code_page, CP_UTF8 | CP_GB18030) {
        WC_ERR_INVALID_CHARS
    } else if needs_zero_wide_flags(code_page) {
        0
    } else {
        WC_NO_BEST_FIT_CHARS
    }
}

fn needs_zero_wide_flags(code_page: u32) -> bool {
    matches!(
        code_page,
        CP_UTF7
            | CP_SYMBOL
            | CP_WINDOWS_50220
            | CP_WINDOWS_50221
            | CP_WINDOWS_50222
            | CP_WINDOWS_50225
            | CP_WINDOWS_50227
            | CP_WINDOWS_50229
    ) || (CP_WINDOWS_57002..=CP_WINDOWS_57011).contains(&code_page)
}

fn has_default_char_indicator(code_page: u32) -> bool {
    !matches!(code_page, CP_UTF7 | CP_UTF8)
}

fn utf16_prefix_boundaries(source: &[u16]) -> Result<Vec<usize>, RuntimeError> {
    let capacity = source
        .len()
        .checked_add(1)
        .ok_or_else(|| resource_limit("reserve UTF-16 scalar boundaries"))?;
    let mut boundaries = Vec::new();
    boundaries.try_reserve_exact(capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve UTF-16 scalar boundaries",
            error,
        )
    })?;
    boundaries.push(0);
    let mut units = 0_usize;
    for scalar in char::decode_utf16(source.iter().copied()) {
        units += scalar.map_or(1, char::len_utf16);
        boundaries.push(units);
    }
    Ok(boundaries)
}

fn utf8_spans(source: &[u8], wide: &[u16]) -> Result<Vec<GuestTextSpan>, RuntimeError> {
    let text = std::str::from_utf8(source)
        .map_err(|_| conversion_invariant("Windows accepted invalid UTF-8 input"))?;
    let mut spans = Vec::new();
    spans
        .try_reserve_exact(text.chars().count())
        .map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve UTF-8 text ranges", error)
        })?;
    let mut wide_start = 0_usize;
    for (guest_start, scalar) in text.char_indices() {
        let guest_end = guest_start + scalar.len_utf8();
        let wide_end = wide_start
            .checked_add(scalar.len_utf16())
            .ok_or_else(|| resource_limit("size UTF-8 text ranges"))?;
        let mut expected = [0_u16; 2];
        let encoded: &[u16] = scalar.encode_utf16(&mut expected);
        if wide.get(wide_start..wide_end) != Some(encoded) {
            return Err(mapping_gap(
                CP_UTF8,
                "Windows UTF-8 output does not match validated scalar boundaries",
            ));
        }
        spans.push(GuestTextSpan {
            guest_bytes: guest_start..guest_end,
            utf16_units: wide_start..wide_end,
        });
        wide_start = wide_end;
    }
    if wide_start != wide.len() {
        return Err(mapping_gap(
            CP_UTF8,
            "UTF-8 scalar ranges do not cover the Windows conversion output",
        ));
    }
    Ok(spans)
}

fn sbcs_dbcs_spans(
    codec: &GuestTextCodec,
    source: &[u8],
    wide: &[u16],
) -> Result<Vec<GuestTextSpan>, RuntimeError> {
    let mut spans = Vec::new();
    spans
        .try_reserve_exact(source.len().min(wide.len()))
        .map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve guest text ranges", error)
        })?;
    let mut guest_start = 0_usize;
    let mut wide_cursor = 0_usize;
    let mut span_wide = GuestTextBuffer::acquire();
    while guest_start < source.len() {
        if source[guest_start] == 0 {
            let guest_end = guest_start + 1;
            append_verified_span(
                codec,
                source,
                guest_start,
                guest_end,
                wide,
                &mut wide_cursor,
                &mut spans,
                &mut span_wide,
            )?;
            guest_start = guest_end;
            continue;
        }

        let run_end = source[guest_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map_or(source.len(), |length| guest_start + length);
        while guest_start < run_end {
            // Windows conversion APIs do not return source-byte ranges. For
            // installed SBCS/DBCS pages, reuse the explicit-page lead-byte
            // classifier and verify each proposed span against the complete
            // UTF-16 result below; no host ACP or ANSI string API is involved.
            // A trailing lead byte consumes one byte; conversion validation
            // decides whether that byte is representable in this code page.
            let has_trail = guest_start + 1 < run_end;
            let is_lead = unsafe { IsDBCSLeadByteEx(codec.code_page, source[guest_start]) != 0 };
            let next_offset = guest_start + if is_lead && has_trail { 2 } else { 1 };
            append_verified_span(
                codec,
                source,
                guest_start,
                next_offset,
                wide,
                &mut wide_cursor,
                &mut spans,
                &mut span_wide,
            )?;
            guest_start = next_offset;
        }
    }
    if wide_cursor != wide.len() {
        return Err(mapping_gap(
            codec.code_page,
            "guest character ranges do not cover the Windows conversion output",
        ));
    }
    Ok(spans)
}

fn append_verified_span(
    codec: &GuestTextCodec,
    source: &[u8],
    guest_start: usize,
    guest_end: usize,
    wide: &[u16],
    wide_cursor: &mut usize,
    spans: &mut Vec<GuestTextSpan>,
    span_wide: &mut Vec<u16>,
) -> Result<(), RuntimeError> {
    codec.to_wide_into(&source[guest_start..guest_end], span_wide)?;
    if span_wide.is_empty() {
        return Err(mapping_gap(
            codec.code_page,
            "one guest character produced no UTF-16 units",
        ));
    }
    let wide_end = (*wide_cursor)
        .checked_add(span_wide.len())
        .ok_or_else(|| resource_limit("size guest text ranges"))?;
    if wide.get(*wide_cursor..wide_end) != Some(span_wide.as_slice()) {
        return Err(mapping_gap(
            codec.code_page,
            "per-character Windows conversions do not reproduce the full conversion",
        ));
    }
    spans.push(GuestTextSpan {
        guest_bytes: guest_start..guest_end,
        utf16_units: *wide_cursor..wide_end,
    });
    *wide_cursor = wide_end;
    Ok(())
}

fn is_stateful_mapping_page(code_page: u32) -> bool {
    // Lead-byte metadata provides SBCS/DBCS boundaries, not state transitions for
    // ISO-2022, HZ, EBCDIC extension, ISCII, or UTF-7 streams.
    matches!(code_page, CP_UTF7 | CP_HZ_GB2312)
        || (CP_WINDOWS_50220..=CP_WINDOWS_50229).contains(&code_page)
        || (CP_WINDOWS_50930..=CP_WINDOWS_50939).contains(&code_page)
        || (CP_WINDOWS_57002..=CP_WINDOWS_57011).contains(&code_page)
}

fn checked_i32(length: usize, operation: &'static str) -> Result<i32, RuntimeError> {
    i32::try_from(length).map_err(|_| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            format!("{operation}: input exceeds the Windows API length range"),
        )
    })
}

fn checked_usize(length: i32, operation: &'static str) -> Result<usize, RuntimeError> {
    usize::try_from(length).map_err(|_| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            format!("{operation}: Windows returned an invalid size"),
        )
    })
}

fn windows_failure(operation: &'static str, code_page: u32, last_error: u32) -> RuntimeError {
    // An invalid text sequence is caller input, not a failed host service.
    // Preserve other Windows failures so API adapters can report real causes.
    let kind = if last_error == ERROR_NO_UNICODE_TRANSLATION {
        Kind::InvalidInput
    } else {
        Kind::HostFailure
    };
    RuntimeError::with_source(
        kind,
        operation,
        GuestTextWindowsError {
            code_page,
            last_error,
        },
    )
}

fn mapping_gap(code_page: u32, message: &'static str) -> RuntimeError {
    RuntimeError::new(
        Kind::CompatibilityGap,
        format!("guest code page {code_page}: {message}"),
    )
}

fn mapping_gap_with_windows_error(
    code_page: u32,
    message: &'static str,
    last_error: u32,
) -> RuntimeError {
    RuntimeError::with_source(
        Kind::CompatibilityGap,
        format!("guest code page {code_page}: {message}"),
        GuestTextMappingError {
            code_page,
            last_error,
        },
    )
}

fn conversion_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn resource_limit(operation: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, operation)
}

#[derive(Debug)]
struct GuestTextWindowsError {
    code_page: u32,
    last_error: u32,
}

impl fmt::Display for GuestTextWindowsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "code page {} conversion failed with Windows error {}",
            self.code_page, self.last_error
        )
    }
}

impl Error for GuestTextWindowsError {}

#[derive(Debug)]
struct GuestTextMappingError {
    code_page: u32,
    last_error: u32,
}

impl fmt::Display for GuestTextMappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Windows error {} while reading code page {} mapping metadata",
            self.last_error, self.code_page
        )
    }
}

impl Error for GuestTextMappingError {}

#[cfg(test)]
#[path = "guest_text_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "guest_text_metadata_tests.rs"]
mod metadata_tests;

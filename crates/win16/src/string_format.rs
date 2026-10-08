//! Guest-side formatter for Win16 USER's ANSI `wsprintf` family.
//!
//! The Windows 3.1 SDK declares a 16-bit word-oriented argument list. Host
//! `printf`/`va_list` implementations use the host ABI and cannot interpret
//! those words, FAR pointers, or guest address-space bounds. This parser and
//! renderer therefore operate on checked guest values and never borrow a host
//! varargs list or expose a guest pointer as a host pointer.
//!
//! Windows 3.1 documents `c/C`, `s/S`, `d/i`, `u`, and `x/X` with Win16 word
//! or long arguments, field width, precision, and `%%`. The local Win16
//! compatibility reference additionally implements `%p` as uppercase,
//! zero-padded hexadecimal in an eight-character field (a WORD unless marked
//! long); that extension is not claimed as a Windows 3.1 SDK guarantee. FAR
//! `s/S` values are copied from checked guest memory. The output body is
//! clipped to 1023 bytes before its final NUL.
//!
//! The older Win16 formatter in the local development reference also
//! treats an unrecognized conversion byte as ordinary text after consuming
//! the percent marker and parsed modifiers, and drops an incomplete trailing
//! conversion. That compatibility behavior is not a Windows 3.1 SDK promise;
//! it avoids inventing a fatal API result for inputs the manual leaves
//! unspecified. The same reference omits a NUL produced by %c because it
//! cannot be part of the returned C string.

use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

/// USER's documented formatter output area is 1024 bytes including NUL.
pub(crate) const USER_FORMAT_OUTPUT_CAPACITY: usize = 1024;
const USER_FORMAT_MAX_CONTENT: usize = USER_FORMAT_OUTPUT_CAPACITY - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FormatArgumentKind {
    Word,
    Dword,
    FarString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawFormatArgument {
    Word(u16),
    Dword(u32),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FormatFlags {
    left: bool,
    alternate_hex: bool,
    zero: bool,
    long: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FormatValueKind {
    Character,
    String,
    Signed,
    Unsigned,
    HexLower,
    HexUpper,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Conversion {
    flags: FormatFlags,
    width: usize,
    precision: Option<usize>,
    value_kind: FormatValueKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FormatOperation {
    Text { start: usize, end: usize },
    Percent,
    Conversion(Conversion),
}

/// Parsed format and the Win16 slot width required for each conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FormatPlan {
    operations: Vec<FormatOperation>,
    arguments: Vec<FormatArgumentKind>,
}

impl FormatPlan {
    pub(crate) fn parse(format: &[u8]) -> Result<Self, Win16Error> {
        let mut operations = Vec::new();
        let mut arguments = Vec::new();
        operations.try_reserve(format.len().min(256)).map_err(|_| Win16Error::OutOfMemory)?;
        arguments.try_reserve(format.len().min(64)).map_err(|_| Win16Error::OutOfMemory)?;

        let mut index = 0;
        let mut text_start = 0;
        while index < format.len() {
            if format[index] != b'%' {
                index += 1;
                continue;
            }
            if text_start < index {
                operations.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
                operations.push(FormatOperation::Text { start: text_start, end: index });
            }
            index += 1;
            if index == format.len() {
                text_start = format.len();
                break;
            }
            if format[index] == b'%' {
                operations.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
                operations.push(FormatOperation::Percent);
                index += 1;
                text_start = index;
                continue;
            }

            let mut flags = FormatFlags::default();
            if format.get(index) == Some(&b'-') { flags.left = true; index += 1; }
            if format.get(index) == Some(&b'#') { flags.alternate_hex = true; index += 1; }
            if format.get(index) == Some(&b'0') { flags.zero = true; index += 1; }
            let (mut width, next) = parse_decimal(format, index);
            index = next;
            let precision = if format.get(index) == Some(&b'.') {
                index += 1;
                let (value, next) = parse_decimal(format, index);
                index = next;
                Some(value)
            } else {
                None
            };
            match format.get(index).copied() {
                Some(b'l') => { flags.long = true; index += 1; }
                Some(b'h') => { index += 1; }
                _ => {}
            }
            let Some(specifier) = format.get(index).copied() else {
                // The historical formatter consumes a terminal percent
                // sequence without output and without consuming an argument.
                text_start = format.len();
                break;
            };
            let value_kind = match specifier {
                b'c' | b'C' => FormatValueKind::Character,
                b's' | b'S' => FormatValueKind::String,
                b'd' | b'i' => FormatValueKind::Signed,
                b'u' => FormatValueKind::Unsigned,
                b'x' => FormatValueKind::HexLower,
                b'X' => FormatValueKind::HexUpper,
                b'p' => {
                    // This is a documented local Win16 compatibility
                    // extension; the SDK's wsprintf table does not list it.
                    width = 8;
                    flags.zero = true;
                    FormatValueKind::HexUpper
                }
                // The historical fallback emits an unrecognized conversion
                // byte as ordinary text and consumes no vararg.
                _ => {
                    operations.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
                    operations.push(FormatOperation::Text { start: index, end: index + 1 });
                    index += 1;
                    text_start = index;
                    continue;
                }
            };
            index += 1;
            let argument = match value_kind {
                FormatValueKind::Character => FormatArgumentKind::Word,
                FormatValueKind::String => FormatArgumentKind::FarString,
                _ if flags.long => FormatArgumentKind::Dword,
                _ => FormatArgumentKind::Word,
            };
            arguments.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
            arguments.push(argument);
            operations.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
            operations.push(FormatOperation::Conversion(Conversion {
                flags,
                width,
                precision,
                value_kind,
            }));
            text_start = index;
        }
        if text_start < format.len() {
            operations.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
            operations.push(FormatOperation::Text { start: text_start, end: format.len() });
        }
        Ok(Self { operations, arguments })
    }

    pub(crate) fn arguments(&self) -> &[FormatArgumentKind] {
        &self.arguments
    }

    /// Render from decoded Win16 scalar slots. FAR `%s` inputs are copied
    /// before output writeback, so input/output aliasing cannot invalidate them.
    pub(crate) fn render(
        &self,
        format: &[u8],
        arguments: &[RawFormatArgument],
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
    ) -> Result<Vec<u8>, Win16Error> {
        if arguments.len() != self.arguments.len() {
            return Err(Win16Error::InvalidRange);
        }
        let mut output = Vec::new();
        output.try_reserve_exact(USER_FORMAT_MAX_CONTENT).map_err(|_| Win16Error::OutOfMemory)?;
        let mut argument_index = 0;
        for operation in &self.operations {
            match *operation {
                FormatOperation::Text { start, end } => {
                    append_limited(&mut output, &format[start..end]);
                }
                FormatOperation::Percent => append_limited(&mut output, b"%"),
                FormatOperation::Conversion(conversion) => {
                    let argument = *arguments.get(argument_index).ok_or(Win16Error::InvalidRange)?;
                    argument_index += 1;
                    match conversion.value_kind {
                        FormatValueKind::Character => {
                            let RawFormatArgument::Word(value) = argument else {
                                return Err(Win16Error::InvalidRange);
                            };
                            render_character(&mut output, value as u8, conversion);
                        }
                        FormatValueKind::String => {
                            let RawFormatArgument::Dword(pointer) = argument else {
                                return Err(Win16Error::InvalidRange);
                            };
                            render_string(
                                &mut output, pointer, conversion, selectors, memory,
                            )?;
                        }
                        kind => {
                            let raw = match argument {
                                RawFormatArgument::Word(value) => u32::from(value),
                                RawFormatArgument::Dword(value) => value,
                            };
                            render_number(&mut output, raw, kind, conversion);
                        }
                    }
                }
            }
        }
        Ok(output)
    }
}

fn parse_decimal(bytes: &[u8], mut index: usize) -> (usize, usize) {
    let mut value = 0_usize;
    while let Some(digit @ b'0'..=b'9') = bytes.get(index).copied() {
        value = value
            .saturating_mul(10)
            .saturating_add(usize::from(digit - b'0'));
        index += 1;
    }
    (value, index)
}

fn append_limited(output: &mut Vec<u8>, bytes: &[u8]) {
    let remaining = USER_FORMAT_MAX_CONTENT.saturating_sub(output.len());
    output.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
}

fn append_repeated(output: &mut Vec<u8>, byte: u8, count: usize) {
    let remaining = USER_FORMAT_MAX_CONTENT.saturating_sub(output.len());
    output.resize(output.len() + count.min(remaining), byte);
}

fn render_character(output: &mut Vec<u8>, value: u8, conversion: Conversion) {
    let padding = conversion.width.saturating_sub(1);
    if !conversion.flags.left { append_repeated(output, b' ', padding); }
    if value != 0 {
        append_limited(output, &[value]);
    } else if conversion.width > 1 {
        append_limited(output, b" ");
    }
    if conversion.flags.left { append_repeated(output, b' ', padding); }
}

fn render_string(
    output: &mut Vec<u8>,
    far_pointer: u32,
    conversion: Conversion,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<(), Win16Error> {
    let remaining = USER_FORMAT_MAX_CONTENT.saturating_sub(output.len());
    if remaining == 0 { return Ok(()); }
    // Measure the whole string when it controls field padding. A cap based
    // only on output space would misplace text for a wide field whose source
    // string is longer than the output buffer. Positive precision below the
    // shared string limit bounds the copy without requiring a NUL in-prefix.
    let text_limit = conversion.precision.filter(|limit| *limit != 0);
    let text = match text_limit {
        Some(limit) if limit < crate::MAX_WIN16_STRING_BYTES => {
            read_string_prefix(far_pointer, limit, selectors, memory)?
        }
        _ => crate::strings::read_ansi_z(
            selectors,
            memory,
            far_pointer,
            crate::MAX_WIN16_STRING_BYTES,
        )?,
    };
    let padding = conversion.width.saturating_sub(text.len());
    if !conversion.flags.left { append_repeated(output, b' ', padding); }
    append_limited(output, &text);
    if conversion.flags.left { append_repeated(output, b' ', padding); }
    Ok(())
}

fn read_string_prefix(
    far_pointer: u32,
    maximum: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(maximum).map_err(|_| Win16Error::OutOfMemory)?;
    if maximum == 0 { return Ok(bytes); }
    let start = selectors.pointer_from_far(far_pointer)?;
    for index in 0..maximum {
        let pointer = selectors.add_bytes(
            start,
            u32::try_from(index).map_err(|_| Win16Error::InvalidRange)?,
        )?;
        let mut byte = [0_u8; 1];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 { break; }
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

fn render_number(output: &mut Vec<u8>, raw: u32, kind: FormatValueKind, conversion: Conversion) {
    let (value, negative, radix, uppercase) = match kind {
        FormatValueKind::Signed if conversion.flags.long => {
            let signed = raw as i32;
            (signed.unsigned_abs(), signed < 0, 10, false)
        }
        FormatValueKind::Signed => {
            let signed = raw as u16 as i16;
            (u32::from(signed.unsigned_abs()), signed < 0, 10, false)
        }
        FormatValueKind::Unsigned => (raw, false, 10, false),
        FormatValueKind::HexLower => (raw, false, 16, false),
        FormatValueKind::HexUpper => (raw, false, 16, true),
        _ => return,
    };
    let mut reverse = [0_u8; 32];
    let mut digit_count = 0;
    if value != 0 {
        let mut remainder = value;
        loop {
            let digit = (remainder % radix) as u8;
            reverse[digit_count] = if digit < 10 {
                b'0' + digit
            } else if uppercase {
                b'A' + (digit - 10)
            } else {
                b'a' + (digit - 10)
            };
            digit_count += 1;
            remainder /= radix;
            if remainder == 0 { break; }
        }
    } else {
        reverse[0] = b'0';
        digit_count = 1;
    }
    let digits = digit_count.max(conversion.precision.unwrap_or(0));
    let prefix = radix == 16 && conversion.flags.alternate_hex;
    let sign = negative;
    let prefix_length: usize = if prefix { 2 } else { 0 };
    let sign_length: usize = if sign { 1 } else { 0 };
    let core = prefix_length.saturating_add(sign_length).saturating_add(digits);
    let padding = conversion.width.saturating_sub(core);
    let zero_width = conversion.flags.zero
        && !conversion.flags.left;
    if !conversion.flags.left && !zero_width { append_repeated(output, b' ', padding); }
    if sign { append_limited(output, b"-"); }
    if prefix {
        append_limited(output, if uppercase { b"0X" } else { b"0x" });
    }
    // Precision zeros establish the minimum digit count; zero-filled field
    // width adds any remaining width zeros after the sign and hex prefix.
    let precision_zeros = digits - digit_count;
    let width_zeros = if zero_width { padding } else { 0 };
    let zeros = precision_zeros.saturating_add(width_zeros);
    append_repeated(output, b'0', zeros);
    for index in (0..digit_count).rev() {
        append_limited(output, &reverse[index..=index]);
    }
    if conversion.flags.left { append_repeated(output, b' ', padding); }
}

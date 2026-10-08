//! SZDD decompression used by LZEXPAND.
//!
//! The decoder supports the `A` compression method and the 14-byte SZDD
//! header. `SzddStream` eagerly validates and expands the bounded payload,
//! then provides LZRead-like partial reads and checked seeking. File handles,
//! path mangling, timestamps, and the exported Win16/Win32 ABI remain outside
//! this module.

use std::io::SeekFrom;

pub const SZDD_MAGIC: [u8; 8] = [b'S', b'Z', b'D', b'D', 0x88, 0xf0, 0x27, 0x33];
pub const SZDD_HEADER_LEN: usize = 14;
const LZ_TABLE_SIZE: usize = 4096;
const INITIAL_TABLE_OFFSET: usize = 0x0ff0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SzddHeader {
    pub compression_type: u8,
    /// The final character used by LZEXPAND's filename restoration helper.
    pub last_character: u8,
    pub uncompressed_size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LzSeekOrigin {
    Start,
    Current,
    End,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LzError {
    TruncatedHeader,
    UnknownCompressionType(u8),
    OutputTooLarge { declared: u32, limit: usize },
    OutputSizeNotRepresentable(u32),
    AllocationFailed,
    TruncatedStream { output_offset: u32 },
    InvalidSeek,
}

impl std::fmt::Display for LzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("truncated SZDD header"),
            Self::UnknownCompressionType(kind) => {
                write!(f, "unsupported SZDD compression type 0x{kind:02x}")
            }
            Self::OutputTooLarge { declared, limit } => {
                write!(f, "SZDD output size {declared} exceeds limit {limit}")
            }
            Self::OutputSizeNotRepresentable(size) => {
                write!(f, "SZDD output size {size} cannot be represented on this host")
            }
            Self::AllocationFailed => f.write_str("could not reserve SZDD output buffer"),
            Self::TruncatedStream { output_offset } => write!(
                f,
                "truncated SZDD stream after {output_offset} decompressed bytes"
            ),
            Self::InvalidSeek => f.write_str("seek position is outside the expanded file"),
        }
    }
}

impl std::error::Error for LzError {}

/// Inspect an SZDD header. A non-SZDD file returns `Ok(None)`; a file with a
/// complete SZDD signature but an incomplete header is reported as truncated.
pub fn inspect_szdd(input: &[u8]) -> Result<Option<SzddHeader>, LzError> {
    if input.len() < SZDD_MAGIC.len() || input[..SZDD_MAGIC.len()] != SZDD_MAGIC[..] {
        return Ok(None);
    }
    if input.len() < SZDD_HEADER_LEN {
        return Err(LzError::TruncatedHeader);
    }

    let compression_type = input[8];
    if compression_type != b'A' {
        return Err(LzError::UnknownCompressionType(compression_type));
    }
    let uncompressed_size = u32::from_le_bytes([input[10], input[11], input[12], input[13]]);
    Ok(Some(SzddHeader {
        compression_type,
        last_character: input[9],
        uncompressed_size,
    }))
}

/// Decompress an SZDD file, enforcing `max_output_size` before allocating.
///
/// Returns `Ok(None)` when the input is not an SZDD file. Only the SZDD `A`
/// method is supported. Trailing compressed bytes are ignored once the size
/// declared in the header has been produced.
pub fn decode_szdd(
    input: &[u8],
    max_output_size: usize,
) -> Result<Option<(SzddHeader, Vec<u8>)>, LzError> {
    let Some(header) = inspect_szdd(input)? else {
        return Ok(None);
    };
    let output_size = usize::try_from(header.uncompressed_size)
        .map_err(|_| LzError::OutputSizeNotRepresentable(header.uncompressed_size))?;
    if output_size > max_output_size {
        return Err(LzError::OutputTooLarge {
            declared: header.uncompressed_size,
            limit: max_output_size,
        });
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(output_size)
        .map_err(|_| LzError::AllocationFailed)?;

    let mut decoder = Decoder::new(&input[SZDD_HEADER_LEN..], output_size);
    while output.len() < output_size {
        decoder.decode_next(&mut output)?;
    }

    Ok(Some((header, output)))
}

struct Decoder<'a> {
    compressed: &'a [u8],
    input_offset: usize,
    output_limit: usize,
    table: [u8; LZ_TABLE_SIZE],
    table_offset: usize,
    control: u8,
    control_bits_remaining: u8,
}

impl<'a> Decoder<'a> {
    fn new(compressed: &'a [u8], output_limit: usize) -> Self {
        Self {
            compressed,
            input_offset: 0,
            output_limit,
            table: [b' '; LZ_TABLE_SIZE],
            table_offset: INITIAL_TABLE_OFFSET,
            control: 0,
            control_bits_remaining: 0,
        }
    }

    fn take_compressed_byte(&mut self, output_offset: usize) -> Result<u8, LzError> {
        let Some(byte) = self.compressed.get(self.input_offset).copied() else {
            // The declared output size is a u32 and decoding never advances
            // beyond it, so this conversion cannot truncate.
            let output_offset = output_offset as u32;
            return Err(LzError::TruncatedStream { output_offset });
        };
        self.input_offset += 1;
        Ok(byte)
    }

    fn decode_next(&mut self, output: &mut Vec<u8>) -> Result<(), LzError> {
        let output_offset = output.len();
        if self.control_bits_remaining == 0 {
            self.control = self.take_compressed_byte(output_offset)?;
            self.control_bits_remaining = 8;
        }
        let literal = self.control & 1 != 0;
        self.control >>= 1;
        self.control_bits_remaining -= 1;

        if literal {
            let byte = self.take_compressed_byte(output_offset)?;
            self.emit(byte, output);
        } else {
            let low = self.take_compressed_byte(output_offset)?;
            let high = self.take_compressed_byte(output_offset)?;
            let position = usize::from(low) | (usize::from(high & 0xf0) << 4);
            let length = usize::from(high & 0x0f) + 3;
            let count = length.min(self.output_limit - output.len());
            let mut table_position = position;
            for _ in 0..count {
                let byte = self.table[table_position];
                table_position = (table_position + 1) & (LZ_TABLE_SIZE - 1);
                self.emit(byte, output);
            }
        }
        Ok(())
    }

    fn emit(&mut self, byte: u8, output: &mut Vec<u8>) {
        self.table[self.table_offset] = byte;
        self.table_offset = (self.table_offset + 1) & (LZ_TABLE_SIZE - 1);
        output.push(byte);
    }
}

/// A seekable LZEXPAND view over an expanded SZDD payload.
///
/// Construction performs full bounded decompression so every subsequent read
/// and seek has deterministic stream behavior and cannot discover corruption
/// after partially changing caller-visible buffers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SzddStream {
    header: SzddHeader,
    expanded: Vec<u8>,
    position: usize,
}

impl SzddStream {
    pub fn open(input: &[u8], max_output_size: usize) -> Result<Option<Self>, LzError> {
        let Some((header, expanded)) = decode_szdd(input, max_output_size)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            header,
            expanded,
            position: 0,
        }))
    }

    pub fn header(&self) -> SzddHeader {
        self.header
    }

    pub fn len(&self) -> u64 {
        self.expanded.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.expanded.is_empty()
    }

    pub fn position(&self) -> u64 {
        self.position as u64
    }

    /// Read up to `buffer.len()` bytes and advance the stream position.
    /// Returns zero at end of file or for an empty destination buffer.
    pub fn read(&mut self, buffer: &mut [u8]) -> usize {
        let available = self.expanded.len() - self.position;
        let count = available.min(buffer.len());
        buffer[..count].copy_from_slice(&self.expanded[self.position..self.position + count]);
        self.position += count;
        count
    }

    /// Seek using conventional `std::io::SeekFrom` offsets. Positions outside
    /// `[0, len]` are rejected, matching LZEXPAND's bounded logical file.
    pub fn seek(&mut self, from: SeekFrom) -> Result<u64, LzError> {
        let base = match from {
            SeekFrom::Start(position) => {
                let target = usize::try_from(position).map_err(|_| LzError::InvalidSeek)?;
                if target > self.expanded.len() {
                    return Err(LzError::InvalidSeek);
                }
                self.position = target;
                return Ok(self.position as u64);
            }
            SeekFrom::Current(_) => self.position as i128,
            SeekFrom::End(_) => self.expanded.len() as i128,
        };
        let delta = match from {
            SeekFrom::Current(delta) | SeekFrom::End(delta) => i128::from(delta),
            SeekFrom::Start(_) => unreachable!(),
        };
        let target = base.checked_add(delta).ok_or(LzError::InvalidSeek)?;
        if target < 0 || target > self.expanded.len() as i128 {
            return Err(LzError::InvalidSeek);
        }
        self.position = target as usize;
        Ok(self.position as u64)
    }

    /// Seek using the legacy LZSeek origin convention from the reference
    /// implementation. `End` treats a positive offset as bytes before EOF
    /// (`len - offset`); use [`seek`](Self::seek) for conventional Rust
    /// `SeekFrom` semantics.
    pub fn seek_lz(&mut self, offset: i32, origin: LzSeekOrigin) -> Result<u64, LzError> {
        let length = self.expanded.len() as i128;
        let target = match origin {
            LzSeekOrigin::Start => i128::from(offset),
            LzSeekOrigin::Current => self.position as i128 + i128::from(offset),
            LzSeekOrigin::End => length - i128::from(offset),
        };
        if target < 0 || target > length {
            return Err(LzError::InvalidSeek);
        }
        self.position = target as usize;
        Ok(self.position as u64)
    }
}

#[cfg(test)]
mod tests;

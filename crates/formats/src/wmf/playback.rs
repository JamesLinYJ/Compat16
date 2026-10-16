//! Bounds required before the pointer-only PlayMetaFileRecord API is called.
//!
//! Unlike whole-stream GDI entry points, that API receives no backing length.
//! These Win3.x fixed layouts and variable arrays therefore need an explicit
//! check. Complex bitmap/region and driver records stay unsupported until their
//! nested payloads have a complete codec; they must never reach native GDI.

use super::{WmfRecord, parse_wmf_record};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WmfPlaybackError {
    Invalid,
    Unsupported(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WmfPlaybackRecord {
    pub creates_object: bool,
    /// Unknown functions are ignored under the documented WMF playback contract.
    pub ignored: bool,
}

pub fn validate_wmf_record_playback(
    bytes: &[u8],
    object_count: usize,
) -> Result<WmfPlaybackRecord, WmfPlaybackError> {
    let record = parse_wmf_record(bytes).map_err(|_| WmfPlaybackError::Invalid)?;
    let function = record.function();
    let p = record.parameters();
    let mut creates_object = false;
    let mut ignored = false;
    let words = match function & 0xff {
        0x00 => {
            if function != 0 || p.len() != 0 {
                return invalid();
            }
            0
        }
        0x01 => fixed(function, 0x0201, 2)?,
        0x02..=0x08 => fixed(function, 0x0100 | (function & 0xff), 1)?,
        0x09..=0x0f | 0x11 | 0x13 | 0x14 | 0x20 => fixed(function, 0x0200 | (function & 0xff), 2)?,
        0x10 | 0x12 | 0x15 | 0x16 | 0x18 | 0x19 | 0x1b | 0x1f => {
            fixed(function, 0x0400 | (function & 0xff), 4)?
        }
        0x17 | 0x1a | 0x30 => fixed(function, 0x0800 | (function & 0xff), 8)?,
        0x1c | 0x1d => fixed(function, 0x0600 | (function & 0xff), 6)?,
        0x1e | 0x35 => fixed(function, function & 0xff, 0)?,
        0x27 | 0x2e | 0x39 => fixed(function, 0x0100 | (function & 0xff), 1)?,
        0x31 => fixed(function, 0x0231, 2)?,
        0x48 => fixed(function, 0x0548, 5)?,
        0x21 => {
            fixed(function, 0x0521, 0)?;
            let count = word(p, 0)?;
            // WORD byte count, padded ANSI bytes, y and x. Coordinates are
            // at the record's tail, so do not accept an ambiguous extra tail.
            exact(p, 2 + padded(count)? + 4)?;
            0
        }
        0x24 | 0x25 => {
            fixed(function, 0x0300 | (function & 0xff), 0)?;
            let count = word(p, 0)?;
            need(p, 2 + count * 4)?;
            0
        }
        0x32 => {
            fixed(function, 0x0a32, 0)?;
            let count = word(p, 4)?;
            let options = word(p, 6)?;
            // Glyph-index and PDY layouts are not Win16 ANSI ExtTextOut.
            if options & (0x0010 | 0x2000) != 0 {
                return unsupported(record);
            }
            let start = 8 + if options & 6 != 0 { 8 } else { 0 };
            let end = start + padded(count)?;
            need(p, end)?;
            if p.len() != end {
                exact(p, end + count * 2)?;
            }
            0
        }
        0x38 => {
            fixed(function, 0x0538, 0)?;
            let count = word(p, 0)?;
            need(p, 2 + count * 2)?;
            let mut points = 0usize;
            for i in 0..count {
                points += word(p, 2 + i * 2)?;
            }
            need(p, 2 + count * 2 + points * 4)?;
            0
        }
        0x28 | 0x29 => {
            let n = if function & 0xff == 0x28 { 2 } else { 4 };
            fixed(function, ((n as u16) << 8) | (function & 0xff), n)?;
            index(p, 0, object_count, false)?;
            index(p, 2, object_count, false)?;
            n
        }
        0x2a..=0x2d | 0xf0 => {
            fixed(function, 0x0100 | (function & 0xff), 1)?;
            index(p, 0, object_count, function == 0x012d)?;
            1
        }
        0x34 => {
            fixed(function, 0x0234, 2)?;
            index(p, 0, object_count, false)?;
            2
        }
        0xf7 => {
            fixed(function, 0x00f7, 0)?;
            if word(p, 0)? != 0x0300 {
                return invalid();
            }
            need(p, 4 + word(p, 2)? * 4)?;
            creates_object = true;
            0
        }
        0xfa => {
            fixed(function, 0x02fa, 5)?;
            creates_object = true;
            5
        }
        0xfb => {
            fixed(function, 0x02fb, 25)?;
            need(p, 50)?;
            if !p[18..50].contains(&0) {
                return invalid();
            }
            creates_object = true;
            25
        }
        0xfc => {
            fixed(function, 0x02fc, 4)?;
            // LOGBRUSH16.hatch is data only for solid/null/hatched brushes.
            // Pattern variants contain a Win16 handle or nested DIB contract.
            if word(p, 0)? > 2 {
                return unsupported(record);
            }
            creates_object = true;
            4
        }
        0x22
        | 0x23
        | 0x26
        | 0x2f
        | 0x33
        | 0x36
        | 0x37
        | 0x40..=0x43
        | 0x49
        | 0x4c
        | 0x4d
        | 0x4f
        | 0x50
        | 0x52
        | 0x5e
        | 0xf8
        | 0xf9
        | 0xfd..=0xff => {
            return unsupported(record);
        }
        _ => {
            ignored = true;
            0
        }
    };
    need(p, words * 2)?;
    Ok(WmfPlaybackRecord {
        creates_object,
        ignored,
    })
}
fn fixed(actual: u16, expected: u16, words: usize) -> Result<usize, WmfPlaybackError> {
    if actual != expected {
        return invalid();
    }
    Ok(words)
}
fn need(bytes: &[u8], count: usize) -> Result<(), WmfPlaybackError> {
    if bytes.len() < count {
        return invalid();
    }
    Ok(())
}
fn exact(bytes: &[u8], count: usize) -> Result<(), WmfPlaybackError> {
    if bytes.len() != count {
        return invalid();
    }
    Ok(())
}
fn word(bytes: &[u8], offset: usize) -> Result<usize, WmfPlaybackError> {
    let b = bytes
        .get(offset..offset + 2)
        .ok_or(WmfPlaybackError::Invalid)?;
    Ok(usize::from(u16::from_le_bytes([b[0], b[1]])))
}
fn padded(n: usize) -> Result<usize, WmfPlaybackError> {
    n.checked_add(1)
        .map(|n| n & !1)
        .ok_or(WmfPlaybackError::Invalid)
}
fn index(bytes: &[u8], offset: usize, count: usize, stock: bool) -> Result<(), WmfPlaybackError> {
    let n = word(bytes, offset)?;
    if n >= count && !(stock && n & 0x8000 != 0 && n & 0x7fff <= 19) {
        return invalid();
    }
    Ok(())
}
fn invalid<T>() -> Result<T, WmfPlaybackError> {
    Err(WmfPlaybackError::Invalid)
}
fn unsupported<T>(record: WmfRecord<'_>) -> Result<T, WmfPlaybackError> {
    Err(WmfPlaybackError::Unsupported(record.function()))
}

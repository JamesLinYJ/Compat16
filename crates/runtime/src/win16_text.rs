//! Win16 string operations with checked guest addresses and native ANSI rules.

use guest_core::memory::Memory;
use win16_abi::{Access, MAX_WIN16_STRING_BYTES, Win16AnsiCaseTarget};
use win16_abi::exports::Win16StringComparison;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16AnsiNextProbe};

impl Win16State {
    pub(super) fn ansi_case(
        &self,
        target: Win16AnsiCaseTarget,
        upper: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match target {
            Win16AnsiCaseTarget::Char(value) => {
                Ok(u32::from(if upper { host.win16_ansi_upper_char(value)? }
                    else { host.win16_ansi_lower_char(value)? }))
            }
            Win16AnsiCaseTarget::String { pointer, bytes } => {
                let mut converted = host.win16_ansi_case_string_in_place(&bytes, upper)?;
                if converted.len() > bytes.len() || converted.contains(&0) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 ANSI case conversion exceeded its input or returned an embedded NUL"));
                }
                converted.try_reserve(1).map_err(|_| RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 ANSI result cannot reserve a terminator"))?;
                converted.push(0);
                let destination = self.selectors.pointer_from_far(pointer)
                    .map_err(crate::runtime_error)?;
                self.write_text_bytes(memory, destination, &converted)?;
                Ok(pointer)
            }
        }
    }

    pub(super) fn string_copy(
        &self,
        destination: u32,
        source: Option<Vec<u8>>,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let Some(mut bytes) = source.filter(|_| destination != 0) else { return Ok(0) };
        append_terminator(&mut bytes)?;
        let pointer = self.selectors.pointer_from_far(destination).map_err(crate::runtime_error)?;
        self.write_text_bytes(memory, pointer, &bytes)?;
        Ok(destination)
    }

    pub(super) fn string_concat(
        &self,
        destination: u32,
        source: &[u8],
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let mut bytes = win16_abi::strings::read_ansi_z(
            &self.selectors, memory, destination, MAX_WIN16_STRING_BYTES,
        ).map_err(crate::runtime_error)?;
        bytes.try_reserve(source.len().checked_add(1).ok_or_else(||
            RuntimeError::new(Kind::ResourceExhausted, "Win16 concatenated text is too large"))?)
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve Win16 concatenated text", error))?;
        bytes.extend_from_slice(source);
        bytes.push(0);
        let pointer = self.selectors.pointer_from_far(destination).map_err(crate::runtime_error)?;
        self.write_text_bytes(memory, pointer, &bytes)?;
        Ok(destination)
    }

    pub(super) fn string_compare(
        &self,
        left: &[u8],
        right: &[u8],
        comparison: Win16StringComparison,
        host: &mut impl RuntimeHost,
    ) -> Result<i16, RuntimeError> {
        match comparison {
            // KERNEL.Reserved5 is the internal ordinal comparison entry.
            Win16StringComparison::Binary => Ok(match left.cmp(right) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }),
            Win16StringComparison::Linguistic => host.win16_ansi_compare(left, right, false),
            Win16StringComparison::LinguisticIgnoreCase => host.win16_ansi_compare(left, right, true),
        }
    }

    pub(super) fn ansi_case_buffer(
        &self,
        pointer: u32,
        length: u16,
        upper: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        // The original Win16 WORD count encodes 64 KiB as zero. It counts
        // bytes, and embedded NULs do not terminate this buffer operation.
        let count = if length == 0 { 0x1_0000 } else { usize::from(length) };
        let destination = self.selectors.pointer_from_far(pointer).map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, destination, count)?;
        let Some(converted) = host.win16_ansi_case_buffer(&bytes, upper)? else {
            // Native conversion can fail normally. Do not commit partial
            // output or terminate the guest for a documented API failure.
            return Ok(0);
        };
        if converted.len() != count {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 ANSI buffer conversion changed the byte count"));
        }
        self.write_text_bytes(memory, destination, &converted)?;
        Ok(length)
    }

    pub(super) fn ansi_next(
        &self,
        pointer: u32,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let start = self.selectors.pointer_from_far(pointer).map_err(crate::runtime_error)?;
        let delta = probe_next_character(|offset| {
            let current = self.selectors.add_bytes(start, offset as u32)
                .map_err(crate::runtime_error)?;
            let mut byte = [0];
            self.selectors.read(memory, current, &mut byte).map_err(crate::runtime_error)?;
            Ok(byte[0])
        }, |source| host.win16_ansi_next_probe(source))?;
        if delta == 0 { return Ok(pointer); }
        let next = self.selectors.add_bytes(start, delta as u32).map_err(crate::runtime_error)?;
        self.selectors.translate(next, Access::Read, 1, memory).map_err(crate::runtime_error)?;
        // Checked selector references canonicalize TI/RPL bits. Retain the
        // caller's exact high word when movement stays in its descriptor.
        if next.selector() == start.selector() {
            Ok((pointer & 0xffff_0000) | u32::from(next.offset()))
        } else {
            Ok(next.far_value())
        }
    }

    pub(super) fn ansi_prev(
        &self,
        start: u32,
        current: u32,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if start == current { return Ok(current); }
        let first = self.selectors.pointer_from_far(start).map_err(crate::runtime_error)?;
        let last = self.selectors.pointer_from_far(current).map_err(crate::runtime_error)?;
        let prefix = self.text_prefix(memory, first, last)?;
        if prefix.is_empty() { return Ok(current); }
        let offset = host.win16_ansi_prev_offset(&prefix, prefix.len())?;
        if offset >= prefix.len() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Windows ANSI previous-character result did not precede its current position"));
        }
        let previous = self.selectors.add_bytes(first, offset as u32).map_err(crate::runtime_error)?;
        let address = self.selectors.translate(previous, Access::Read, 1, memory)
            .map_err(crate::runtime_error)?;
        let back = prefix.len() - offset;
        // Preserve the caller's selector alias whenever the near subtraction
        // stays in that selector. Crossing a selector uses the owned block's
        // checked descriptor, never arithmetic on raw selector values.
        if let Some(near) = usize::from(last.offset()).checked_sub(back) {
            let alias = win16_abi::SegmentedPointer::new(last.selector(), near as u16);
            if self.selectors.translate(alias, Access::Read, 1, memory)
                .map_err(crate::runtime_error)? == address
            {
                return Ok(alias.far_value());
            }
        }
        Ok(previous.far_value())
    }
}

fn append_terminator(bytes: &mut Vec<u8>) -> Result<(), RuntimeError> {
    bytes.try_reserve(1).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 text terminator", error))?;
    bytes.push(0);
    Ok(())
}

/// Each requested byte is read once. Keeping this loop independent of the
/// selector reader also lets tests count actual reads without timing claims.
fn probe_next_character(
    mut read: impl FnMut(usize) -> Result<u8, RuntimeError>,
    mut probe: impl FnMut(&[u8]) -> Result<Win16AnsiNextProbe, RuntimeError>,
) -> Result<usize, RuntimeError> {
    let mut source = [0; 4];
    for index in 0..source.len() {
        source[index] = read(index)?;
        if index == 0 && source[0] == 0 { return Ok(0); }
        let prefix = &source[..=index];
        match probe(prefix)? {
            Win16AnsiNextProbe::Complete(delta) => {
                let end = prefix.iter().position(|&byte| byte == 0).unwrap_or(prefix.len());
                if delta == 0 || delta > end {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 ANSI next-character result exceeds its checked prefix"));
                }
                return Ok(delta);
            }
            Win16AnsiNextProbe::NeedMore if source[index] != 0 && index + 1 < source.len() => {}
            Win16AnsiNextProbe::NeedMore => {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 ANSI character probe exceeded its terminator or four-byte bound"));
            }
        }
    }
    unreachable!("a four-byte probe must complete or fail")
}

#[cfg(test)]
#[path = "win16_text_tests.rs"]
mod tests;

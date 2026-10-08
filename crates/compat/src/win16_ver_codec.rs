//! Bounded codec for Win16 version-information resources.
//!
//! Windows' `VerQueryValueA` has no input-length parameter and may use scratch
//! storage prepared by `GetFileVersionInfoA`. This codec handles the ANSI
//! Win16 resource layout without passing caller-owned bytes to that API. It
//! also converts a checked Win32 UTF-16 version tree into the ANSI layout used
//! by Win16 callers.
//!
//! A raw Win32 VERSION resource fetched with GetFileResource is not a
//! GetFileVersionInfo buffer: VerQueryValueA may require conversion scratch
//! space that only the latter API prepares. Direct queries on such raw blocks
//! therefore fail safely for now; the block is never rewritten in place.

use std::ops::Range;

const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 16_384;
const MAX_BLOCK_LENGTH: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionQueryValue {
    pub offset: usize,
    pub length: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionBlockError {
    TruncatedHeader,
    InvalidLength(u16),
    ExceedsParent,
    UnterminatedKey,
    InvalidType(u16),
    InvalidValueRange,
    InvalidChildRange,
    TooDeep,
    TooManyNodes,
    NotWin16VersionBlock,
    LengthOverflow,
    AllocationFailed,
}

impl std::fmt::Display for VersionBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("version-information node header is truncated"),
            Self::InvalidLength(length) => write!(f, "version-information node length {length} is invalid"),
            Self::ExceedsParent => f.write_str("version-information node exceeds its parent range"),
            Self::UnterminatedKey => f.write_str("version-information key has no terminator"),
            Self::InvalidType(value) => write!(f, "version-information node type {value} is invalid"),
            Self::InvalidValueRange => f.write_str("version-information value exceeds its node"),
            Self::InvalidChildRange => f.write_str("version-information child range is malformed"),
            Self::TooDeep => f.write_str("version-information tree exceeds the nesting limit"),
            Self::TooManyNodes => f.write_str("version-information tree exceeds the node limit"),
            Self::NotWin16VersionBlock => f.write_str("block is not a Win16 ANSI version-information block"),
            Self::LengthOverflow => f.write_str("version-information result exceeds its WORD length field"),
            Self::AllocationFailed => f.write_str("could not allocate version-information storage"),
        }
    }
}

impl std::error::Error for VersionBlockError {}

#[derive(Debug)]
pub enum TranscodeError<E> {
    Block(VersionBlockError),
    Text(E),
}

#[derive(Clone, Copy)]
enum Encoding {
    Ansi,
    Utf16,
}

struct Node {
    end: usize,
    key: Range<usize>,
    value: Range<usize>,
    kind: u16,
    children: Vec<Node>,
}

/// Find a value in a structurally valid Win16 ANSI `VS_VERSION_INFO` block.
/// The returned byte range is relative to the start of the block.
pub fn query_win16_ansi(
    block: &[u8],
    sub_block: &[u8],
) -> Result<Option<VersionQueryValue>, VersionBlockError> {
    let root = parse_root(block, Encoding::Ansi)?;
    if block.get(root.key.clone()) != Some(b"VS_VERSION_INFO".as_slice()) {
        return Err(VersionBlockError::NotWin16VersionBlock);
    }

    let mut parts = sub_block.split(|byte| *byte == b'\\').filter(|part| !part.is_empty());
    let first = parts.next();
    let mut current = &root;
    let skip_root = first.is_some_and(|part| part.eq_ignore_ascii_case(b"VS_VERSION_INFO"));
    if let Some(first) = first {
        if !skip_root {
            let Some(child) = find_child(block, current, first) else { return Ok(None); };
            current = child;
        }
    }
    for part in parts {
        let Some(child) = find_child(block, current, part) else { return Ok(None); };
        current = child;
    }
    Ok(Some(query_value(current)?))
}

/// Convert a bounded Win32 UTF-16 version-information block into the ANSI
/// structure used by Win16. `encode_ansi` receives UTF-16 code units without
/// key terminators and with value terminators preserved. Windows hosts should
/// implement it with `WideCharToMultiByte(CP_ACP, ...)`.
pub fn transcode_win32_to_win16_ansi<E>(
    block: &[u8],
    mut encode_ansi: impl FnMut(&[u16]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, TranscodeError<E>> {
    let root = parse_root(block, Encoding::Utf16).map_err(TranscodeError::Block)?;
    let root_key = utf16_string(block, root.key.clone()).map_err(TranscodeError::Block)?;
    if !root_key.iter().copied().eq("VS_VERSION_INFO".encode_utf16()) {
        return Err(TranscodeError::Block(VersionBlockError::NotWin16VersionBlock));
    }
    let mut output = Vec::new();
    serialize_node(block, &root, &mut output, &mut encode_ansi)
        .map_err(|error| match error {
            SerializeError::Block(error) => TranscodeError::Block(error),
            SerializeError::Text(error) => TranscodeError::Text(error),
        })?;
    Ok(output)
}

fn parse_root(block: &[u8], encoding: Encoding) -> Result<Node, VersionBlockError> {
    let header_length = match encoding {
        Encoding::Ansi => 4,
        Encoding::Utf16 => 6,
    };
    if block.len() < header_length { return Err(VersionBlockError::TruncatedHeader); }
    let root_length = read_u16(block, 0)?;
    if usize::from(root_length) < header_length {
        return Err(VersionBlockError::InvalidLength(root_length));
    }
    let end = usize::from(root_length);
    if end > block.len() { return Err(VersionBlockError::ExceedsParent); }
    let mut nodes = 0usize;
    parse_node(block, 0, end, encoding, 0, &mut nodes)
}

fn parse_node(
    block: &[u8],
    start: usize,
    parent_end: usize,
    encoding: Encoding,
    depth: usize,
    node_count: &mut usize,
) -> Result<Node, VersionBlockError> {
    if depth > MAX_DEPTH { return Err(VersionBlockError::TooDeep); }
    *node_count = (*node_count).checked_add(1).ok_or(VersionBlockError::TooManyNodes)?;
    if *node_count > MAX_NODES { return Err(VersionBlockError::TooManyNodes); }
    let header_length = match encoding {
        Encoding::Ansi => 4,
        Encoding::Utf16 => 6,
    };
    let header_end = start.checked_add(header_length).ok_or(VersionBlockError::TruncatedHeader)?;
    if header_end > parent_end || header_end > block.len() {
        return Err(VersionBlockError::TruncatedHeader);
    }
    let length = read_u16(block, start)?;
    if usize::from(length) < header_length {
        return Err(VersionBlockError::InvalidLength(length));
    }
    let end = start.checked_add(usize::from(length)).ok_or(VersionBlockError::ExceedsParent)?;
    if end > parent_end || end > block.len() { return Err(VersionBlockError::ExceedsParent); }
    let value_length = read_u16(block, start + 2)?;
    let kind = match encoding {
        Encoding::Ansi => 0,
        Encoding::Utf16 => {
            let kind = read_u16(block, start + 4)?;
            if kind > 1 { return Err(VersionBlockError::InvalidType(kind)); }
            kind
        }
    };

    let key_start = header_end;
    let (key_end, terminated_at) = match encoding {
        Encoding::Ansi => {
            let Some(relative) = block.get(key_start..end)
                .and_then(|key| key.iter().position(|byte| *byte == 0)) else {
                return Err(VersionBlockError::UnterminatedKey);
            };
            (key_start + relative, key_start + relative + 1)
        }
        Encoding::Utf16 => {
            let mut cursor = key_start;
            loop {
                let next = cursor.checked_add(2).ok_or(VersionBlockError::UnterminatedKey)?;
                if next > end { return Err(VersionBlockError::UnterminatedKey); }
                if read_u16(block, cursor)? == 0 { break (cursor, next); }
                cursor = next;
            }
        }
    };
    let value_start = align4(terminated_at).ok_or(VersionBlockError::InvalidValueRange)?;
    let value_bytes = match (encoding, kind) {
        (Encoding::Utf16, 1) => usize::from(value_length).checked_mul(2),
        _ => Some(usize::from(value_length)),
    }.ok_or(VersionBlockError::InvalidValueRange)?;
    let value_end = value_start.checked_add(value_bytes).ok_or(VersionBlockError::InvalidValueRange)?;
    if value_start > end || value_end > end { return Err(VersionBlockError::InvalidValueRange); }
    let mut node = Node {
        end,
        key: key_start..key_end,
        value: value_start..value_end,
        kind,
        children: Vec::new(),
    };

    let mut cursor = align4(value_end).ok_or(VersionBlockError::InvalidChildRange)?;
    if cursor < end && !block[cursor..end].iter().all(|byte| *byte == 0) {
        loop {
            if cursor >= end { break; }
            let remaining = end - cursor;
            let child_header_length = match encoding {
                Encoding::Ansi => 4,
                Encoding::Utf16 => 6,
            };
            if remaining < child_header_length {
                if block[cursor..end].iter().all(|byte| *byte == 0) { break; }
                return Err(VersionBlockError::InvalidChildRange);
            }
            if block[cursor..end].iter().all(|byte| *byte == 0) { break; }
            node.children.try_reserve(1).map_err(|_| VersionBlockError::AllocationFailed)?;
            let child = parse_node(block, cursor, end, encoding, depth + 1, node_count)?;
            let child_end = child.end;
            node.children.push(child);
            if child_end == end { break; }
            cursor = align4(child_end).ok_or(VersionBlockError::InvalidChildRange)?;
            if cursor > end { return Err(VersionBlockError::InvalidChildRange); }
        }
    }
    Ok(node)
}

fn find_child<'a>(block: &[u8], node: &'a Node, key: &[u8]) -> Option<&'a Node> {
    node.children.iter().find(|child| {
        block.get(child.key.clone()).is_some_and(|candidate| candidate.eq_ignore_ascii_case(key))
    })
}

fn query_value(node: &Node) -> Result<VersionQueryValue, VersionBlockError> {
    let length = u32::try_from(node.value.len()).map_err(|_| VersionBlockError::LengthOverflow)?;
    Ok(VersionQueryValue { offset: node.value.start, length })
}

enum SerializeError<E> {
    Block(VersionBlockError),
    Text(E),
}

fn serialize_node<E>(
    source: &[u8],
    node: &Node,
    output: &mut Vec<u8>,
    encode_ansi: &mut impl FnMut(&[u16]) -> Result<Vec<u8>, E>,
) -> Result<(), SerializeError<E>> {
    let start = output.len();
    append(output, &[0, 0, 0, 0]).map_err(SerializeError::Block)?;
    let key = utf16_string(source, node.key.clone()).map_err(SerializeError::Block)?;
    let key_bytes = encode_ansi(&key).map_err(SerializeError::Text)?;
    if key_bytes.contains(&0) { return Err(SerializeError::Block(VersionBlockError::UnterminatedKey)); }
    append(output, &key_bytes).map_err(SerializeError::Block)?;
    append(output, &[0]).map_err(SerializeError::Block)?;
    pad4(output).map_err(SerializeError::Block)?;

    let value = if node.kind == 1 {
        let text = utf16_string(source, node.value.clone()).map_err(SerializeError::Block)?;
        encode_ansi(&text).map_err(SerializeError::Text)?
    } else {
        let source_value = source.get(node.value.clone())
            .ok_or_else(|| SerializeError::Block(VersionBlockError::InvalidValueRange))?;
        copy_bytes(source_value).map_err(SerializeError::Block)?
    };
    let value_length = u16::try_from(value.len())
        .map_err(|_| SerializeError::Block(VersionBlockError::LengthOverflow))?;
    append(output, &value).map_err(SerializeError::Block)?;
    if !node.children.is_empty() {
        for child in &node.children {
            pad4(output).map_err(SerializeError::Block)?;
            serialize_node(source, child, output, encode_ansi)?;
        }
    }
    let length = output.len().checked_sub(start)
        .ok_or_else(|| SerializeError::Block(VersionBlockError::LengthOverflow))?;
    let length_word = u16::try_from(length)
        .map_err(|_| SerializeError::Block(VersionBlockError::LengthOverflow))?;
    write_u16(output, start, length_word).map_err(SerializeError::Block)?;
    write_u16(output, start + 2, value_length).map_err(SerializeError::Block)?;
    if output.len() > MAX_BLOCK_LENGTH {
        return Err(SerializeError::Block(VersionBlockError::LengthOverflow));
    }
    Ok(())
}

fn utf16_string(block: &[u8], range: Range<usize>) -> Result<Vec<u16>, VersionBlockError> {
    if range.start > range.end || range.end > block.len() || range.len() % 2 != 0 {
        return Err(VersionBlockError::InvalidValueRange);
    }
    let mut output = Vec::new();
    output.try_reserve_exact(range.len() / 2).map_err(|_| VersionBlockError::AllocationFailed)?;
    for pair in block[range].chunks_exact(2) {
        output.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    Ok(output)
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, VersionBlockError> {
    let mut output = Vec::new();
    output.try_reserve_exact(bytes.len()).map_err(|_| VersionBlockError::AllocationFailed)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, VersionBlockError> {
    let end = offset.checked_add(2).ok_or(VersionBlockError::TruncatedHeader)?;
    let pair = bytes.get(offset..end).ok_or(VersionBlockError::TruncatedHeader)?;
    Ok(u16::from_le_bytes([pair[0], pair[1]]))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), VersionBlockError> {
    let end = offset.checked_add(2).ok_or(VersionBlockError::LengthOverflow)?;
    let target = bytes.get_mut(offset..end).ok_or(VersionBlockError::LengthOverflow)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VersionBlockError> {
    output.try_reserve(bytes.len()).map_err(|_| VersionBlockError::AllocationFailed)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn pad4(output: &mut Vec<u8>) -> Result<(), VersionBlockError> {
    let aligned = align4(output.len()).ok_or(VersionBlockError::LengthOverflow)?;
    let padding = aligned - output.len();
    output.try_reserve(padding).map_err(|_| VersionBlockError::AllocationFailed)?;
    output.resize(aligned, 0);
    Ok(())
}

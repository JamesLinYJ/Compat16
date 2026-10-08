use std::ops::Range;

use super::LocalHeapError;

// LocalHeap's fixed Win16 near-pointer layout stays in a byte slice, but the
// runtime needs the exact write set to merge a transaction into external-backed
// guest RAM. No general byte-slice API exposes write intent (especially stores
// that preserve the same value), so these helpers record it at each write site.
pub(super) fn write_word(
    bytes: &mut [u8],
    spans: &mut Vec<Range<usize>>,
    offset: usize,
    value: u16,
) -> Result<(), LocalHeapError> {
    write_bytes(bytes, spans, offset, &value.to_le_bytes())
}

pub(super) fn write_byte(
    bytes: &mut [u8],
    spans: &mut Vec<Range<usize>>,
    offset: usize,
    value: u8,
) -> Result<(), LocalHeapError> {
    write_bytes(bytes, spans, offset, &[value])
}

fn write_bytes(
    bytes: &mut [u8],
    spans: &mut Vec<Range<usize>>,
    offset: usize,
    value: &[u8],
) -> Result<(), LocalHeapError> {
    let end = offset.checked_add(value.len())
        .ok_or(LocalHeapError::CorruptArenaChain { offset })?;
    let destination = bytes.get_mut(offset..end)
        .ok_or(LocalHeapError::CorruptArenaChain { offset })?;
    record_write_span(spans, offset..end)?;
    destination.copy_from_slice(value);
    Ok(())
}

pub(super) fn fill_range(
    bytes: &mut [u8],
    spans: &mut Vec<Range<usize>>,
    range: Range<usize>,
    value: u8,
) -> Result<(), LocalHeapError> {
    let destination = bytes.get_mut(range.clone())
        .ok_or(LocalHeapError::CorruptArenaChain { offset: range.start })?;
    record_write_span(spans, range)?;
    destination.fill(value);
    Ok(())
}

pub(super) fn copy_within_range(
    bytes: &mut [u8],
    spans: &mut Vec<Range<usize>>,
    source: Range<usize>,
    destination: usize,
) -> Result<(), LocalHeapError> {
    let length = source.end.checked_sub(source.start)
        .ok_or(LocalHeapError::CorruptArenaChain { offset: source.start })?;
    let destination_end = destination.checked_add(length)
        .ok_or(LocalHeapError::CorruptArenaChain { offset: destination })?;
    if source.end > bytes.len() || destination_end > bytes.len() {
        return Err(LocalHeapError::CorruptArenaChain { offset: destination });
    }
    record_write_span(spans, destination..destination_end)?;
    bytes.copy_within(source, destination);
    Ok(())
}

pub(super) fn record_write_span(
    spans: &mut Vec<Range<usize>>,
    range: Range<usize>,
) -> Result<(), LocalHeapError> {
    if range.start > range.end {
        return Err(LocalHeapError::CorruptArenaChain { offset: range.start });
    }
    if range.start == range.end {
        return Ok(());
    }
    let merges = spans.iter().any(|span| span.end >= range.start && span.start <= range.end);
    if !merges {
        spans.try_reserve(1).map_err(|_| LocalHeapError::OutOfMemory)?;
    }
    merge_write_span(spans, range);
    Ok(())
}

/// Inserts into an already-reserved, sorted range set, merging overlaps and
/// adjacent writes without allocating.
pub(super) fn merge_write_span(spans: &mut Vec<Range<usize>>, range: Range<usize>) {
    if range.start == range.end {
        return;
    }
    let first = spans.iter().position(|span| span.end >= range.start)
        .unwrap_or(spans.len());
    let mut start = range.start;
    let mut end = range.end;
    let mut after = first;
    while after < spans.len() && spans[after].start <= end {
        start = start.min(spans[after].start);
        end = end.max(spans[after].end);
        after += 1;
    }
    if first == after {
        spans.insert(first, start..end);
    } else {
        spans[first] = start..end;
        spans.drain(first + 1..after);
    }
}

use crate::FormatError;

pub(super) fn checked_file_range<'a>(
    bytes: &'a [u8],
    start: usize,
    length: usize,
    context: &'static str,
) -> Result<&'a [u8], FormatError> {
    let end = start.checked_add(length).ok_or(FormatError::ArithmeticOverflow)?;
    bytes.get(start..end).ok_or(FormatError::Truncated { context, offset: start, needed: length })
}

pub(super) fn read_u8(bytes: &[u8], offset: usize, context: &'static str) -> Result<u8, FormatError> {
    bytes.get(offset).copied().ok_or(FormatError::Truncated { context, offset, needed: 1 })
}

pub(super) fn read_u16(bytes: &[u8], offset: usize, context: &'static str) -> Result<u16, FormatError> {
    let field = checked_file_range(bytes, offset, 2, context)?;
    let low = *field.get(0).ok_or(FormatError::Truncated { context, offset, needed: 2 })?;
    let high = *field.get(1).ok_or(FormatError::Truncated { context, offset, needed: 2 })?;
    Ok(u16::from_le_bytes([low, high]))
}

pub(super) fn write_stage(
    bytes: &mut [u8],
    offset: usize,
    value: &[u8],
    context: &'static str,
) -> Result<(), FormatError> {
    let end = offset.checked_add(value.len()).ok_or(FormatError::ArithmeticOverflow)?;
    let target = bytes.get_mut(offset..end).ok_or(FormatError::InvalidNeLoad(context))?;
    target.copy_from_slice(value);
    Ok(())
}

pub(super) fn zeroed_buffer(length: usize) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| FormatError::AllocationFailed)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

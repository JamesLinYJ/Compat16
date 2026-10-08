use crate::ne_checked::{checked_file_range, read_u16, zeroed_buffer};
use crate::{FormatError, NeModule};

const MAX_NE_SEGMENT_SIZE: u32 = 0x1_0000;

pub(super) fn allocation_size(
    module: &NeModule,
    segment_number: u16,
    declared_size: u32,
) -> Result<u32, FormatError> {
    if declared_size == 0 || declared_size > MAX_NE_SEGMENT_SIZE {
        return Err(FormatError::InvalidNeLoad("segment allocation size is outside the NE limit"));
    }
    let mut size = declared_size;
    if module.header.automatic_data_segment == segment_number {
        let extra = u32::from(module.header.stack_size)
            .checked_add(u32::from(module.header.heap_size))
            .and_then(|value| value.checked_add(2))
            .ok_or(FormatError::ArithmeticOverflow)?;
        size = size.checked_add(extra).ok_or(FormatError::ArithmeticOverflow)?.min(MAX_NE_SEGMENT_SIZE);
    }
    if size == 0 || size > MAX_NE_SEGMENT_SIZE {
        return Err(FormatError::InvalidNeLoad("segment allocation size is outside the NE limit"));
    }
    Ok(size)
}

pub(super) fn expand_segment(
    source: &[u8],
    size: u32,
    iterated: bool,
) -> Result<Vec<u8>, FormatError> {
    if iterated {
        expand_iterated_segment(source, size)
    } else {
        expand_plain_segment(source, size)
    }
}

fn expand_plain_segment(source: &[u8], size: u32) -> Result<Vec<u8>, FormatError> {
    let size = usize::try_from(size).map_err(|_| FormatError::ArithmeticOverflow)?;
    if source.len() > size {
        return Err(FormatError::InvalidNeLoad("segment file image exceeds its allocation"));
    }
    let mut image = zeroed_buffer(size)?;
    let destination = image.get_mut(0..source.len())
        .ok_or(FormatError::InvalidNeLoad("segment image does not fit its allocation"))?;
    destination.copy_from_slice(source);
    Ok(image)
}

fn expand_iterated_segment(source: &[u8], size: u32) -> Result<Vec<u8>, FormatError> {
    let mut image = zeroed_buffer(usize::try_from(size).map_err(|_| FormatError::ArithmeticOverflow)?)?;
    let mut source_offset = 0_usize;
    let mut output_offset = 0_usize;
    while source_offset < source.len() {
        let record_header = checked_file_range(source, source_offset, 4, "NE iterated-segment record header")?;
        let repeat_count = usize::from(read_u16(record_header, 0, "NE iterated repeat count")?);
        let data_length = usize::from(read_u16(record_header, 2, "NE iterated data length")?);
        source_offset = source_offset.checked_add(4).ok_or(FormatError::ArithmeticOverflow)?;
        let data = checked_file_range(source, source_offset, data_length, "NE iterated-segment record data")?;
        let expanded_length = repeat_count.checked_mul(data_length).ok_or(FormatError::ArithmeticOverflow)?;
        let end_output = output_offset.checked_add(expanded_length).ok_or(FormatError::ArithmeticOverflow)?;
        if end_output > image.len() {
            return Err(FormatError::InvalidNeLoad("iterated segment expands past its allocation"));
        }
        for _ in 0..repeat_count {
            let end = output_offset.checked_add(data_length).ok_or(FormatError::ArithmeticOverflow)?;
            let destination = image.get_mut(output_offset..end)
                .ok_or(FormatError::InvalidNeLoad("iterated output is outside its allocation"))?;
            destination.copy_from_slice(data);
            output_offset = end;
        }
        source_offset = source_offset.checked_add(data_length).ok_or(FormatError::ArithmeticOverflow)?;
    }
    Ok(image)
}

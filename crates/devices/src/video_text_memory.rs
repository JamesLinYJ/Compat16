use guest_core::{GuestMemory, MemoryError, PhysAddr};

const APERTURE_BYTES: usize = 0x8000;

fn chunks(base: u32, offset: usize, length: usize) -> Result<Vec<(PhysAddr, usize, usize)>, MemoryError> {
    let mut spans = Vec::new();
    let mut aperture_offset = offset % APERTURE_BYTES;
    let mut buffer_offset = 0;
    let mut remaining = length;
    while remaining != 0 {
        let span_length = remaining.min(APERTURE_BYTES - aperture_offset);
        let address_offset = u32::try_from(aperture_offset).map_err(|_| MemoryError::AddressOverflow)?;
        let address = base.checked_add(address_offset).ok_or(MemoryError::AddressOverflow)?;
        spans.push((PhysAddr(address), buffer_offset, span_length));
        remaining -= span_length;
        buffer_offset += span_length;
        aperture_offset = 0;
    }
    Ok(spans)
}

pub(super) fn read_wrapped(
    memory: &impl GuestMemory,
    base: u32,
    offset: usize,
    bytes: &mut [u8],
) -> Result<(), MemoryError> {
    let spans = chunks(base, offset, bytes.len())?;
    for (address, _, length) in &spans { memory.validate_read(*address, *length)?; }
    for (address, buffer_offset, length) in spans {
        memory.read(address, &mut bytes[buffer_offset..buffer_offset + length])?;
    }
    Ok(())
}

pub(super) fn write_wrapped(
    memory: &mut impl GuestMemory,
    base: u32,
    offset: usize,
    bytes: &[u8],
) -> Result<(), MemoryError> {
    let spans = chunks(base, offset, bytes.len())?;
    for (address, _, length) in &spans { memory.validate_write(*address, *length)?; }
    for (address, buffer_offset, length) in spans {
        memory.write(address, &bytes[buffer_offset..buffer_offset + length])?;
    }
    Ok(())
}

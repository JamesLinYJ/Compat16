//! Owned requests for the Win16 WINSPOOL entry points.

use guest_core::GuestMemory;

use crate::{
    SelectorTable, Win16Argument, Win16Error,
    gdi_abi::{
        DEVMODE16_DRIVER_EXTRA_OFFSET, DEVMODE16_HEADER_SIZE, DEVMODE16_SIZE_OFFSET, DevMode16,
        DevMode16Error, decode_devmode16,
    },
};

use crate::exports::call::call_helpers::{dword_argument, read_nullable_far_string, word_argument};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16PrinterRequest {
    DeviceCapabilities {
        device: Option<Vec<u8>>,
        port: Option<Vec<u8>>,
        index: u16,
        output: u32,
        devmode: Option<DevMode16>,
    },
}

/// Decodes the already-sized Pascal argument frame for DeviceCapabilities:
/// device FAR, port FAR, index WORD, output FAR, and DEVMODE FAR.
pub fn decode_device_capabilities(
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16PrinterRequest, Win16Error> {
    if arguments.len() != 5 {
        return Err(Win16Error::InvalidRange);
    }
    let device_far = dword_argument(arguments, 0)?;
    let port_far = dword_argument(arguments, 1)?;
    let index = word_argument(arguments, 2)?;
    let output = dword_argument(arguments, 3)?;
    let devmode_far = dword_argument(arguments, 4)?;

    let device = read_nullable_far_string(device_far, selectors, memory)?;
    let port = read_nullable_far_string(port_far, selectors, memory)?;
    let devmode = if devmode_far == 0 {
        None
    } else {
        Some(read_devmode(devmode_far, selectors, memory)?)
    };

    Ok(Win16PrinterRequest::DeviceCapabilities {
        device,
        port,
        index,
        output,
        devmode,
    })
}

fn read_devmode(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<DevMode16, Win16Error> {
    let pointer = selectors.pointer_from_far(far)?;
    let header = read_guest_range(pointer, DEVMODE16_HEADER_SIZE, selectors, memory)?;
    let public_size = u16::from_le_bytes([
        header[DEVMODE16_SIZE_OFFSET],
        header[DEVMODE16_SIZE_OFFSET + 1],
    ]);
    let driver_extra = u16::from_le_bytes([
        header[DEVMODE16_DRIVER_EXTRA_OFFSET],
        header[DEVMODE16_DRIVER_EXTRA_OFFSET + 1],
    ]);
    let total_size = usize::from(public_size)
        .checked_add(usize::from(driver_extra))
        .filter(|_| usize::from(public_size) >= DEVMODE16_HEADER_SIZE)
        .ok_or(Win16Error::InvalidRange)?;
    // The checked DEVMODE codec requires exactly dmSize + dmDriverExtra bytes;
    // the 40-byte prefix is only enough to discover that full declared length.
    let bytes = read_guest_range(pointer, total_size, selectors, memory)?;
    decode_devmode16(&bytes).map_err(|error| match error {
        DevMode16Error::AllocationFailed => Win16Error::OutOfMemory,
        DevMode16Error::InvalidPublicSize | DevMode16Error::IncompleteBytes => {
            Win16Error::InvalidRange
        }
    })
}

fn read_guest_range(
    mut pointer: crate::SegmentedPointer,
    count: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count)
        .map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(count, 0);
    let mut offset = 0usize;
    while offset < count {
        let descriptor = selectors.describe(pointer.selector())?;
        let available = descriptor
            .limit
            .checked_sub(u32::from(pointer.offset()))
            .and_then(|remaining| remaining.checked_add(1))
            .and_then(|remaining| usize::try_from(remaining).ok())
            .ok_or(Win16Error::InvalidRange)?;
        let chunk = (count - offset).min(available);
        if chunk == 0 {
            return Err(Win16Error::InvalidRange);
        }
        let end = offset.checked_add(chunk).ok_or(Win16Error::InvalidRange)?;
        selectors.read(memory, pointer, &mut bytes[offset..end])?;
        offset = end;
        if offset < count {
            // SelectorTable::add_bytes resolves only within this selector's
            // owning block and segment run; adjacent independent selectors
            // are never treated as continuation bytes.
            pointer = selectors.add_bytes(
                pointer,
                u32::try_from(chunk).map_err(|_| Win16Error::InvalidRange)?,
            )?;
        }
    }
    Ok(bytes)
}

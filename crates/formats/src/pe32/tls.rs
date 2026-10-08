use object::endian::LittleEndian as LE;
use object::pe::ImageTlsDirectory32;
use object::read::pe::DataDirectories;

use super::pe32_rva::Pe32RvaReader;
use super::pe32_types::{Pe32Error, Pe32TlsMetadata};

const TLS_DIRECTORY_SIZE: u32 = core::mem::size_of::<ImageTlsDirectory32>() as u32;

pub(super) fn parse_tls(
    reader: &Pe32RvaReader<'_>,
    directories: DataDirectories<'_>,
    preferred_base: u32,
) -> Result<Option<Pe32TlsMetadata>, Pe32Error> {
    let Some(directory) = directories.get(object::pe::IMAGE_DIRECTORY_ENTRY_TLS) else {
        return Ok(None);
    };
    let (directory_rva, directory_size) = directory.address_range();
    if directory_size < TLS_DIRECTORY_SIZE {
        return Err(Pe32Error::InvalidImage("truncated TLS directory"));
    }
    let raw = reader.read_record::<ImageTlsDirectory32>(directory_rva)?;
    let start_va = raw.start_address_of_raw_data.get(LE);
    let end_va = raw.end_address_of_raw_data.get(LE);
    let index_va = raw.address_of_index.get(LE);
    let callbacks_va = raw.address_of_call_backs.get(LE);

    let (template_rva, template_size) = match (start_va, end_va) {
        (0, 0) => (None, 0),
        (0, _) | (_, 0) => {
            return Err(Pe32Error::InvalidImage(
                "TLS template start and end must both be null or non-null",
            ));
        }
        (start, end) => {
            let start_rva = va_to_rva(
                start,
                preferred_base,
                reader.image_size,
                "TLS template start",
            )?;
            let end_rva =
                va_to_end_rva(end, preferred_base, reader.image_size, "TLS template end")?;
            if end_rva < start_rva {
                return Err(Pe32Error::InvalidImage("TLS template end precedes start"));
            }
            let length = end_rva - start_rva;
            reader.read_raw(start_rva, length)?;
            (Some(start_rva), length)
        }
    };

    let index_rva = if index_va == 0 {
        None
    } else {
        let rva = va_to_rva(
            index_va,
            preferred_base,
            reader.image_size,
            "TLS index address",
        )?;
        if rva % 4 != 0 {
            return Err(Pe32Error::InvalidImage("TLS index address is unaligned"));
        }
        reader.validate_mapped_range(rva, 4)?;
        Some(rva)
    };

    let (callback_table_rva, callback_rvas) = if callbacks_va == 0 {
        (None, Vec::new())
    } else {
        let table_rva = va_to_rva(
            callbacks_va,
            preferred_base,
            reader.image_size,
            "TLS callback table",
        )?;
        if table_rva % 4 != 0 {
            return Err(Pe32Error::InvalidImage("TLS callback table is unaligned"));
        }
        let max_entries = reader.image_size / 4;
        let mut callbacks = Vec::new();
        let mut terminated = false;
        for index in 0..max_entries {
            let offset = index
                .checked_mul(4)
                .ok_or(Pe32Error::InvalidImage("TLS callback offset overflows"))?;
            let slot = table_rva
                .checked_add(offset)
                .ok_or(Pe32Error::InvalidImage("TLS callback table RVA overflows"))?;
            let callback_va = reader.read_u32(slot)?;
            if callback_va == 0 {
                terminated = true;
                break;
            }
            let callback_rva = va_to_rva(
                callback_va,
                preferred_base,
                reader.image_size,
                "TLS callback address",
            )?;
            reader.validate_mapped_range(callback_rva, 1)?;
            if !reader.is_executable_rva(callback_rva) {
                return Err(Pe32Error::InvalidImage(
                    "TLS callback does not lie in an executable section",
                ));
            }
            callbacks
                .try_reserve(1)
                .map_err(|_| Pe32Error::OutOfMemory("recording TLS callback metadata"))?;
            callbacks.push(callback_rva);
        }
        if !terminated {
            return Err(Pe32Error::InvalidImage(
                "TLS callback array has no null terminator within the image",
            ));
        }
        (Some(table_rva), callbacks)
    };

    Ok(Some(Pe32TlsMetadata {
        directory_rva,
        start_address_of_raw_data_va: start_va,
        end_address_of_raw_data_va: end_va,
        address_of_index_va: index_va,
        address_of_callbacks_va: callbacks_va,
        template_rva,
        template_size,
        index_rva,
        callback_table_rva,
        callback_rvas,
        size_of_zero_fill: raw.size_of_zero_fill.get(LE),
        characteristics: raw.characteristics.get(LE),
    }))
}

fn va_to_rva(
    address: u32,
    preferred_base: u32,
    image_size: u32,
    context: &'static str,
) -> Result<u32, Pe32Error> {
    let rva = address
        .checked_sub(preferred_base)
        .ok_or(Pe32Error::InvalidImage(context))?;
    if rva >= image_size {
        return Err(Pe32Error::InvalidImage(context));
    }
    Ok(rva)
}

fn va_to_end_rva(
    address: u32,
    preferred_base: u32,
    image_size: u32,
    context: &'static str,
) -> Result<u32, Pe32Error> {
    let rva = address
        .checked_sub(preferred_base)
        .ok_or(Pe32Error::InvalidImage(context))?;
    if rva > image_size {
        return Err(Pe32Error::InvalidImage(context));
    }
    Ok(rva)
}

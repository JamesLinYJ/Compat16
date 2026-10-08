use object::endian::LittleEndian as LE;
use object::pe::{
    IMAGE_DELAYLOAD_RVA_BASED, ImageDelayloadDescriptor, ImageImportDescriptor, ImageThunkData32,
};
use object::read::pe::{DataDirectories, ImageThunkData};

use super::pe32_rva::Pe32RvaReader;
use super::pe32_types::{
    Pe32DelayImportMetadata, Pe32Error, Pe32ImportKind, Pe32ImportModule, Pe32ImportSymbol,
    Pe32ImportTarget,
};

const IMPORT_DESCRIPTOR_SIZE: u32 = core::mem::size_of::<ImageImportDescriptor>() as u32;
const DELAY_DESCRIPTOR_SIZE: u32 = core::mem::size_of::<ImageDelayloadDescriptor>() as u32;
const THUNK_SIZE: u32 = core::mem::size_of::<ImageThunkData32>() as u32;

pub(super) fn parse_imports(
    reader: &Pe32RvaReader<'_>,
    directories: DataDirectories<'_>,
    preferred_base: u32,
) -> Result<Vec<Pe32ImportModule>, Pe32Error> {
    // `object::ImportTable` follows the null sentinel without bounding regular
    // descriptors by the declared directory size and only remaps the first
    // descriptor's name section. Read its typed records here so every RVA and
    // the terminator stay inside this image's checked guest ranges.
    let mut modules = Vec::new();
    if let Some(directory) = directories.get(object::pe::IMAGE_DIRECTORY_ENTRY_IMPORT) {
        let (rva, size) = directory.address_range();
        parse_normal_directory(reader, rva, size, &mut modules)?;
    }
    if let Some(directory) = directories.get(object::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
        let (rva, size) = directory.address_range();
        parse_delay_directory(reader, rva, size, preferred_base, &mut modules)?;
    }
    Ok(modules)
}

fn parse_normal_directory(
    reader: &Pe32RvaReader<'_>,
    directory_rva: u32,
    directory_size: u32,
    modules: &mut Vec<Pe32ImportModule>,
) -> Result<(), Pe32Error> {
    if directory_size == 0 {
        return Err(Pe32Error::InvalidImage("empty import directory"));
    }
    reader.read_raw(directory_rva, directory_size)?;
    let end = directory_rva
        .checked_add(directory_size)
        .ok_or(Pe32Error::InvalidImage("import directory range overflows"))?;
    let mut cursor = directory_rva;
    let mut found_terminator = false;
    while cursor < end {
        if end - cursor < IMPORT_DESCRIPTOR_SIZE {
            return Err(Pe32Error::InvalidImage(
                "import directory ends inside a descriptor",
            ));
        }
        let descriptor = reader.read_record::<ImageImportDescriptor>(cursor)?;
        cursor = cursor
            .checked_add(IMPORT_DESCRIPTOR_SIZE)
            .ok_or(Pe32Error::InvalidImage(
                "import descriptor cursor overflows",
            ))?;
        if descriptor.is_null() {
            found_terminator = true;
            break;
        }
        let name_rva = descriptor.name.get(LE);
        let first_thunk = descriptor.first_thunk.get(LE);
        let original_first_thunk = descriptor.original_first_thunk.get(LE);
        let timestamp = descriptor.time_date_stamp.get(LE);
        if name_rva == 0 || first_thunk == 0 {
            return Err(Pe32Error::InvalidImage(
                "import descriptor lacks a module name or IAT",
            ));
        }
        let lookup_rva = if original_first_thunk == 0 {
            // Microsoft SDK winnt.h defines a zero timestamp as unbound and
            // ForwarderChain == -1 as “no forwarders”; zero is not its sentinel.
            if timestamp != 0 {
                return Err(Pe32Error::Unsupported(
                    "bound imports without an original lookup table",
                ));
            }
            first_thunk
        } else {
            original_first_thunk
        };
        let name = reader.read_c_string(name_rva, "unterminated import module name")?;
        let symbols = parse_thunks(reader, lookup_rva, first_thunk)?;
        modules
            .try_reserve(1)
            .map_err(|_| Pe32Error::OutOfMemory("recording PE imports"))?;
        modules.push(Pe32ImportModule {
            kind: Pe32ImportKind::Normal,
            name,
            symbols,
        });
    }
    if !found_terminator {
        return Err(Pe32Error::InvalidImage(
            "import directory has no null descriptor within its declared size",
        ));
    }
    Ok(())
}

fn parse_delay_directory(
    reader: &Pe32RvaReader<'_>,
    directory_rva: u32,
    directory_size: u32,
    preferred_base: u32,
    modules: &mut Vec<Pe32ImportModule>,
) -> Result<(), Pe32Error> {
    if directory_size == 0 {
        return Err(Pe32Error::InvalidImage("empty delay-import directory"));
    }
    reader.read_raw(directory_rva, directory_size)?;
    let end = directory_rva
        .checked_add(directory_size)
        .ok_or(Pe32Error::InvalidImage("delay-import directory overflows"))?;
    let mut cursor = directory_rva;
    let mut found_terminator = false;
    while cursor < end {
        if end - cursor < DELAY_DESCRIPTOR_SIZE {
            return Err(Pe32Error::InvalidImage(
                "delay-import directory ends inside a descriptor",
            ));
        }
        let descriptor = reader.read_record::<ImageDelayloadDescriptor>(cursor)?;
        cursor = cursor
            .checked_add(DELAY_DESCRIPTOR_SIZE)
            .ok_or(Pe32Error::InvalidImage(
                "delay-import descriptor cursor overflows",
            ))?;
        if descriptor.is_null() {
            found_terminator = true;
            break;
        }
        let attributes = descriptor.attributes.get(LE);
        if attributes & !IMAGE_DELAYLOAD_RVA_BASED != 0 {
            return Err(Pe32Error::Unsupported(
                "unknown delay-import descriptor attribute bits",
            ));
        }
        let is_rva = attributes & IMAGE_DELAYLOAD_RVA_BASED != 0;
        let name_rva = normalize_pointer(
            descriptor.dll_name_rva.get(LE),
            is_rva,
            preferred_base,
            reader.image_size,
            "delay-import module name",
        )?
        .ok_or(Pe32Error::InvalidImage(
            "delay-import descriptor has no module name",
        ))?;
        let iat_rva = normalize_pointer(
            descriptor.import_address_table_rva.get(LE),
            is_rva,
            preferred_base,
            reader.image_size,
            "delay-import IAT",
        )?
        .ok_or(Pe32Error::InvalidImage(
            "delay-import descriptor has no IAT",
        ))?;
        let lookup_rva = normalize_pointer(
            descriptor.import_name_table_rva.get(LE),
            is_rva,
            preferred_base,
            reader.image_size,
            "delay-import name table",
        )?
        .ok_or(Pe32Error::Unsupported(
            "delay-import descriptor has no name lookup table",
        ))?;
        let name = reader.read_c_string(name_rva, "unterminated delay-import module name")?;
        let symbols = parse_thunks(reader, lookup_rva, iat_rva)?;
        let lookup_slots = u32::try_from(symbols.len())
            .map_err(|_| Pe32Error::InvalidImage("delay-import count exceeds PE32"))?
            .checked_add(1)
            .and_then(|count| count.checked_mul(THUNK_SIZE))
            .ok_or(Pe32Error::InvalidImage("delay-import table size overflows"))?;
        let module_handle_rva = normalize_pointer(
            descriptor.module_handle_rva.get(LE),
            is_rva,
            preferred_base,
            reader.image_size,
            "delay-import module handle",
        )?;
        if let Some(handle_rva) = module_handle_rva {
            reader.validate_mapped_range(handle_rva, 4)?;
        }
        let bound_iat_rva = normalize_pointer(
            descriptor.bound_import_address_table_rva.get(LE),
            is_rva,
            preferred_base,
            reader.image_size,
            "delay-import bound IAT",
        )?;
        if let Some(bound_rva) = bound_iat_rva {
            reader.validate_mapped_range(bound_rva, lookup_slots)?;
        }
        let unload_iat_rva = normalize_pointer(
            descriptor.unload_information_table_rva.get(LE),
            is_rva,
            preferred_base,
            reader.image_size,
            "delay-import unload IAT",
        )?;
        if let Some(unload_rva) = unload_iat_rva {
            reader.validate_mapped_range(unload_rva, lookup_slots)?;
        }
        let metadata = Pe32DelayImportMetadata {
            attributes,
            module_handle_rva,
            bound_iat_rva,
            unload_iat_rva,
            timestamp: descriptor.time_date_stamp.get(LE),
        };
        modules
            .try_reserve(1)
            .map_err(|_| Pe32Error::OutOfMemory("recording delay imports"))?;
        modules.push(Pe32ImportModule {
            kind: Pe32ImportKind::Delay(metadata),
            name,
            symbols,
        });
    }
    if !found_terminator {
        return Err(Pe32Error::InvalidImage(
            "delay-import directory has no null descriptor within its declared size",
        ));
    }
    Ok(())
}

fn parse_thunks(
    reader: &Pe32RvaReader<'_>,
    lookup_rva: u32,
    iat_rva: u32,
) -> Result<Vec<Pe32ImportSymbol>, Pe32Error> {
    let max_entries = reader.image_size / THUNK_SIZE;
    let mut symbols = Vec::new();
    for index in 0..max_entries {
        let offset = index
            .checked_mul(THUNK_SIZE)
            .ok_or(Pe32Error::InvalidImage("import thunk offset overflows"))?;
        let lookup_slot = lookup_rva
            .checked_add(offset)
            .ok_or(Pe32Error::InvalidImage("import lookup RVA overflows"))?;
        let iat_slot = iat_rva
            .checked_add(offset)
            .ok_or(Pe32Error::InvalidImage("IAT RVA overflows"))?;
        let lookup = reader.read_record::<ImageThunkData32>(lookup_slot)?;
        reader.validate_mapped_range(iat_slot, THUNK_SIZE)?;
        let raw = u32::try_from(lookup.raw())
            .map_err(|_| Pe32Error::InvalidImage("PE32 import thunk exceeds DWORD"))?;
        if raw == 0 {
            return Ok(symbols);
        }
        let target = if lookup.is_ordinal() {
            if raw & 0x7fff_0000 != 0 {
                return Err(Pe32Error::InvalidImage(
                    "ordinal import thunk has reserved bits set",
                ));
            }
            Pe32ImportTarget::Ordinal(lookup.ordinal())
        } else {
            let name_rva = lookup.address();
            if name_rva == 0 {
                return Err(Pe32Error::InvalidImage("import-by-name RVA is zero"));
            }
            let hint = reader.read_raw(name_rva, 2)?;
            let hint = u16::from_le_bytes([hint[0], hint[1]]);
            let string_rva = name_rva
                .checked_add(2)
                .ok_or(Pe32Error::InvalidImage("import name RVA overflows"))?;
            let name = reader.read_c_string(string_rva, "unterminated import symbol name")?;
            Pe32ImportTarget::Name { hint, name }
        };
        symbols
            .try_reserve(1)
            .map_err(|_| Pe32Error::OutOfMemory("recording imported symbols"))?;
        symbols.push(Pe32ImportSymbol {
            iat_rva: iat_slot,
            target,
        });
    }
    Err(Pe32Error::InvalidImage(
        "import thunk table has no null entry within SizeOfImage",
    ))
}

fn normalize_pointer(
    value: u32,
    is_rva: bool,
    preferred_base: u32,
    image_size: u32,
    context: &'static str,
) -> Result<Option<u32>, Pe32Error> {
    if value == 0 {
        return Ok(None);
    }
    let rva = if is_rva {
        value
    } else {
        value
            .checked_sub(preferred_base)
            .ok_or(Pe32Error::InvalidImage(context))?
    };
    if rva >= image_size {
        return Err(Pe32Error::InvalidImage(context));
    }
    Ok(Some(rva))
}

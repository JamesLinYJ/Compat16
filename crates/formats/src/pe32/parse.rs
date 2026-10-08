use object::endian::LittleEndian as LE;
use object::pe;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile32};

use super::pe32_exports::parse_exports;
use super::pe32_imports::parse_imports;
use super::pe32_relocations::parse_relocations;
use super::pe32_rva::Pe32RvaReader;
use super::pe32_sections::copy_and_validate_sections;
use super::pe32_tls::parse_tls;
use super::pe32_types::{
    Pe32DataDirectory, Pe32DataDirectoryKind, Pe32DirectoryAddressKind, Pe32Error, Pe32Image,
};

/// Parse an owned I386 PE32 image without loading or executing host code.
pub fn parse_pe32(file_bytes: &[u8]) -> Result<Pe32Image, Pe32Error> {
    let file = PeFile32::parse(file_bytes)
        .map_err(|_| Pe32Error::InvalidImage("object PE32 reader rejected the file"))?;
    let nt_headers = file.nt_headers();
    let file_header = nt_headers.file_header();
    let machine = file_header.machine.get(LE).0;
    if machine != pe::IMAGE_FILE_MACHINE_I386.0 {
        return Err(Pe32Error::UnsupportedMachine(machine));
    }
    let optional = nt_headers.optional_header();
    let preferred_base = u32::try_from(optional.image_base())
        .map_err(|_| Pe32Error::InvalidImage("PE32 image base exceeds DWORD"))?;
    // Microsoft PE/COFF “Optional Header Windows-Specific Fields” requires
    // ImageBase to be a multiple of 64 KiB.
    if preferred_base % 0x1_0000 != 0 {
        return Err(Pe32Error::InvalidImage(
            "ImageBase is not aligned to 64 KiB",
        ));
    }
    let image_size = optional.size_of_image();
    let header_size = optional.size_of_headers();
    let section_alignment = optional.section_alignment();
    let file_alignment = optional.file_alignment();
    let entry_rva = match optional.address_of_entry_point() {
        0 => None,
        rva => Some(rva),
    };
    let characteristics = file_header.characteristics.get(LE).0;
    let section_count = usize::from(file_header.number_of_sections.get(LE));
    let optional_size = u64::from(file_header.size_of_optional_header.get(LE));
    let nt_offset = u64::from(file.dos_header().nt_headers_offset());
    let file_header_size = u64::try_from(pe::IMAGE_SIZEOF_FILE_HEADER)
        .map_err(|_| Pe32Error::InvalidImage("COFF header size does not fit u64"))?;
    let section_header_size = u64::try_from(pe::IMAGE_SIZEOF_SECTION_HEADER)
        .map_err(|_| Pe32Error::InvalidImage("section header size does not fit u64"))?;
    let header_end = nt_offset
        .checked_add(4)
        .and_then(|end| end.checked_add(file_header_size))
        .and_then(|end| end.checked_add(optional_size))
        .and_then(|end| {
            end.checked_add(
                u64::try_from(section_count)
                    .ok()?
                    .checked_mul(section_header_size)?,
            )
        })
        .ok_or(Pe32Error::InvalidImage("PE header extent overflows"))?;
    let header_size_usize = usize::try_from(header_size)
        .map_err(|_| Pe32Error::InvalidImage("SizeOfHeaders does not fit host size"))?;
    let header_bytes_slice = file_bytes
        .get(..header_size_usize)
        .ok_or(Pe32Error::InvalidImage("SizeOfHeaders exceeds file length"))?;
    let mut header_bytes = Vec::new();
    header_bytes
        .try_reserve_exact(header_bytes_slice.len())
        .map_err(|_| Pe32Error::OutOfMemory("owning PE headers"))?;
    header_bytes.extend_from_slice(header_bytes_slice);

    let sections = copy_and_validate_sections(
        file_bytes,
        file.section_table(),
        header_end,
        header_size,
        image_size,
        file_alignment,
        section_alignment,
    )?;
    let reader = Pe32RvaReader {
        image_size,
        header_bytes: &header_bytes,
        sections: &sections,
    };
    let directories = file.data_directories();
    let data_directories = validate_data_directories(file_bytes, &reader, directories)?;
    if let Some(rva) = entry_rva {
        reader.validate_mapped_range(rva, 1)?;
        if !reader.is_executable_rva(rva) {
            return Err(Pe32Error::InvalidImage(
                "entry point does not lie in an executable section",
            ));
        }
    }

    let imports = parse_imports(&reader, directories, preferred_base)?;
    let exports = parse_exports(&reader, directories)?;
    let (relocations, has_relocation_directory) = parse_relocations(&reader, directories)?;
    let tls = parse_tls(&reader, directories, preferred_base)?;

    Ok(Pe32Image {
        machine,
        preferred_base,
        image_size,
        header_size,
        section_alignment,
        entry_rva,
        is_dll: characteristics & pe::IMAGE_FILE_DLL.0 != 0,
        subsystem: optional.subsystem().0,
        sections,
        header_bytes,
        imports,
        exports,
        data_directories,
        relocations,
        has_relocation_directory,
        relocations_stripped: characteristics & pe::IMAGE_FILE_RELOCS_STRIPPED.0 != 0,
        tls,
    })
}

fn validate_data_directories(
    file_bytes: &[u8],
    reader: &Pe32RvaReader<'_>,
    directories: object::read::pe::DataDirectories<'_>,
) -> Result<Vec<Pe32DataDirectory>, Pe32Error> {
    let mut populated = Vec::new();
    for (index, directory) in directories.iter().enumerate() {
        let (address, size) = directory.address_range();
        if address == 0 && size == 0 {
            continue;
        }
        let global_pointer = index == pe::IMAGE_DIRECTORY_ENTRY_GLOBALPTR;
        if address == 0 || (global_pointer && size != 0) || (size == 0 && !global_pointer) {
            return Err(Pe32Error::InvalidImage(
                "data-directory address and size are invalid",
            ));
        }
        let address_kind = if index == pe::IMAGE_DIRECTORY_ENTRY_SECURITY {
            let end = address
                .checked_add(size)
                .ok_or(Pe32Error::InvalidImage("certificate file range overflows"))?;
            if end as u64 > file_bytes.len() as u64 {
                return Err(Pe32Error::InvalidImage(
                    "certificate directory file range exceeds input",
                ));
            }
            Pe32DirectoryAddressKind::FileOffset
        } else {
            // Security is the one PE directory whose address is a file offset;
            // every other populated entry is checked as an RVA-backed image range.
            if global_pointer {
                // Microsoft PE/COFF's data-directory table assigns GlobalPtr
                // a zero size; validate its address without inventing a range.
                reader.validate_mapped_range(address, 1)?;
            } else {
                reader.read_raw(address, size)?;
            }
            Pe32DirectoryAddressKind::Rva
        };
        populated
            .try_reserve(1)
            .map_err(|_| Pe32Error::OutOfMemory("retaining PE data-directory metadata"))?;
        populated.push(Pe32DataDirectory {
            kind: directory_kind(index)?,
            address_kind,
            address,
            size,
        });
    }
    Ok(populated)
}

fn directory_kind(index: usize) -> Result<Pe32DataDirectoryKind, Pe32Error> {
    Ok(match index {
        pe::IMAGE_DIRECTORY_ENTRY_EXPORT => Pe32DataDirectoryKind::Export,
        pe::IMAGE_DIRECTORY_ENTRY_IMPORT => Pe32DataDirectoryKind::Import,
        pe::IMAGE_DIRECTORY_ENTRY_RESOURCE => Pe32DataDirectoryKind::Resource,
        pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION => Pe32DataDirectoryKind::Exception,
        pe::IMAGE_DIRECTORY_ENTRY_SECURITY => Pe32DataDirectoryKind::Security,
        pe::IMAGE_DIRECTORY_ENTRY_BASERELOC => Pe32DataDirectoryKind::BaseRelocation,
        pe::IMAGE_DIRECTORY_ENTRY_DEBUG => Pe32DataDirectoryKind::Debug,
        pe::IMAGE_DIRECTORY_ENTRY_ARCHITECTURE => Pe32DataDirectoryKind::Architecture,
        pe::IMAGE_DIRECTORY_ENTRY_GLOBALPTR => Pe32DataDirectoryKind::GlobalPointer,
        pe::IMAGE_DIRECTORY_ENTRY_TLS => Pe32DataDirectoryKind::Tls,
        pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG => Pe32DataDirectoryKind::LoadConfig,
        pe::IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT => Pe32DataDirectoryKind::BoundImport,
        pe::IMAGE_DIRECTORY_ENTRY_IAT => Pe32DataDirectoryKind::Iat,
        pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT => Pe32DataDirectoryKind::DelayImport,
        pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR => Pe32DataDirectoryKind::ClrRuntimeHeader,
        15 => Pe32DataDirectoryKind::Reserved,
        other => Pe32DataDirectoryKind::Other(u32::try_from(other).map_err(|_| {
            Pe32Error::InvalidImage("data-directory index does not fit public metadata")
        })?),
    })
}

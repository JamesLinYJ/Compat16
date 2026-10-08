use object::read::pe::{DataDirectories, ExportTable, ExportTarget};

use super::pe32_rva::Pe32RvaReader;
use super::pe32_types::{Pe32Error, Pe32Export, Pe32ExportTarget, Pe32ForwardTarget};

pub(super) fn parse_exports(
    reader: &Pe32RvaReader<'_>,
    directories: DataDirectories<'_>,
) -> Result<Vec<Pe32Export>, Pe32Error> {
    let Some(directory) = directories.get(object::pe::IMAGE_DIRECTORY_ENTRY_EXPORT) else {
        return Ok(Vec::new());
    };
    let (directory_rva, directory_size) = directory.address_range();
    if directory_size == 0 {
        return Err(Pe32Error::InvalidImage("empty export directory"));
    }
    let bytes = reader.read_raw(directory_rva, directory_size)?;
    let table = ExportTable::parse(bytes, directory_rva)
        .map_err(|_| Pe32Error::InvalidImage("object PE export table parse failed"))?;

    // `ExportTable::exports()` stores only the last name seen for an ordinal.
    // This adapter groups every name-table alias by its address-table index.
    let address_count = table.addresses().len();
    let mut indexed: Vec<Option<Pe32Export>> = Vec::new();
    indexed
        .try_reserve_exact(address_count)
        .map_err(|_| Pe32Error::OutOfMemory("allocating PE export entries"))?;
    indexed.resize_with(address_count, || None);

    for (index, ordinal, address) in table.address_iter() {
        if address == 0 {
            continue;
        }
        let target = match table
            .target_by_index(index)
            .map_err(|_| Pe32Error::InvalidImage("invalid export target"))?
        {
            ExportTarget::Address(rva) => {
                if rva >= reader.image_size {
                    return Err(Pe32Error::InvalidImage(
                        "export target RVA exceeds SizeOfImage",
                    ));
                }
                reader.validate_mapped_range(rva, 1)?;
                Pe32ExportTarget::ImageRva(rva)
            }
            ExportTarget::ForwardByName(module, name) => {
                let module = own_nonempty(module, "empty forwarded module name")?;
                let name = own_nonempty(name, "empty forwarded export name")?;
                Pe32ExportTarget::Forwarder {
                    module,
                    target: Pe32ForwardTarget::Name(name),
                }
            }
            ExportTarget::ForwardByOrdinal(module, target_ordinal) => {
                let module = own_nonempty(module, "empty forwarded module name")?;
                Pe32ExportTarget::Forwarder {
                    module,
                    target: Pe32ForwardTarget::Ordinal(target_ordinal.0),
                }
            }
        };
        let slot = indexed
            .get_mut(usize::from(index.0))
            .ok_or(Pe32Error::InvalidImage("export address index is invalid"))?;
        *slot = Some(Pe32Export {
            ordinal: ordinal.0,
            names: Vec::new(),
            target,
        });
    }

    for (name_pointer, index) in table.name_iter() {
        let name = table
            .name_from_pointer(name_pointer)
            .map_err(|_| Pe32Error::InvalidImage("invalid or unterminated export name"))?;
        if name.is_empty() {
            return Err(Pe32Error::InvalidImage("empty export name"));
        }
        let export = indexed
            .get_mut(usize::from(index.0))
            .and_then(Option::as_mut)
            .ok_or(Pe32Error::InvalidImage(
                "export name points to a hole or invalid ordinal",
            ))?;
        export
            .names
            .try_reserve(1)
            .map_err(|_| Pe32Error::OutOfMemory("recording export name aliases"))?;
        export
            .names
            .push(own_bytes(name, "copying an export name")?);
    }

    let export_count = indexed.iter().filter(|entry| entry.is_some()).count();
    let mut exports = Vec::new();
    exports
        .try_reserve_exact(export_count)
        .map_err(|_| Pe32Error::OutOfMemory("finishing PE export entries"))?;
    exports.extend(indexed.into_iter().flatten());
    Ok(exports)
}

fn own_nonempty(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, Pe32Error> {
    if bytes.is_empty() {
        return Err(Pe32Error::InvalidImage(context));
    }
    own_bytes(bytes, context)
}

fn own_bytes(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, Pe32Error> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| Pe32Error::OutOfMemory(context))?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

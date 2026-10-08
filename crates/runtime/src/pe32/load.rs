//! Convert a formats-owned validated load plan into runtime ownership metadata.

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::types::{
    Pe32ExportRecord, Pe32ExportTarget, Pe32GuestImage, Pe32ImportSite, Pe32ImportSymbol,
    Pe32LoaderDirectory, Pe32LoaderDirectoryAddressKind, Pe32LoaderDirectoryKind, Pe32ModuleSpec,
    Pe32RvaRange, Pe32SectionProtection,
};

// These documented PE IMAGE_SCN_MEM_* bits are kept here rather than adding
// object as a runtime dependency; the formats crate owns PE header decoding.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Build registry metadata from the same checked plan whose mapped bytes the
/// caller writes through `Memory`; matching base and size prevent split views.
pub(crate) fn module_spec_from_plan(
    name: &[u8],
    image: Pe32GuestImage,
    plan: &formats::Pe32LoadPlan,
) -> Result<Pe32ModuleSpec, RuntimeError> {
    if image.base.0 != plan.load_base() || image.size != plan.image_size() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "PE32 guest reservation does not match its validated load plan",
        ));
    }
    if name.is_empty() || name.contains(&0) || !plan.is_dll() {
        return Err(loader_failure("PE32 load plan is not a named DLL image"));
    }

    let loader_directories = loader_directories_from_formats(plan.data_directories())?;
    let mut executable_ranges = Vec::new();
    let mut sections = Vec::new();
    executable_ranges
        .try_reserve_exact(plan.sections().len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 executable section ranges",
                error,
            )
        })?;
    sections
        .try_reserve_exact(plan.sections().len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 section protection metadata",
                error,
            )
        })?;
    for section in plan.sections().iter() {
        let characteristics = section.characteristics();
        let execute = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        sections.push(Pe32SectionProtection {
            rva: section.rva(),
            size: section.virtual_size(),
            characteristics,
            read: characteristics & IMAGE_SCN_MEM_READ != 0,
            write: characteristics & IMAGE_SCN_MEM_WRITE != 0,
            execute,
        });
        if !execute {
            continue;
        }
        if section.virtual_size() != 0 {
            executable_ranges.push(Pe32RvaRange {
                start: section.rva(),
                size: section.virtual_size(),
                executable: true,
            });
        }
    }

    let import_count = plan
        .imports()
        .iter()
        .try_fold(0_usize, |count, module| {
            count.checked_add(module.symbols().len())
        })
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "PE32 import count overflows host size",
            )
        })?;
    let mut imports = Vec::new();
    imports.try_reserve_exact(import_count).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "reserve PE32 import sites", error)
    })?;
    for module in plan.imports() {
        let delayed = matches!(module.kind(), formats::Pe32ImportKind::Delay(_));
        for symbol in module.symbols() {
            let target = match symbol.target() {
                formats::Pe32ImportTarget::Name { hint, name } => Pe32ImportSymbol::Name {
                    hint: *hint,
                    name: copy_bytes(name, "copy PE32 import name")?,
                },
                formats::Pe32ImportTarget::Ordinal(ordinal) => Pe32ImportSymbol::Ordinal(*ordinal),
            };
            imports.push(Pe32ImportSite {
                iat_rva: symbol.iat_rva(),
                module: copy_bytes(module.name(), "copy PE32 import module name")?,
                symbol: target,
                delayed,
            });
        }
    }

    let mut exports = Vec::new();
    exports
        .try_reserve_exact(plan.exports().len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 export records",
                error,
            )
        })?;
    for export in plan.exports() {
        let mut names = Vec::new();
        names
            .try_reserve_exact(export.names().len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve PE32 export aliases",
                    error,
                )
            })?;
        for name in export.names() {
            names.push(copy_bytes(name, "copy PE32 export name")?);
        }
        let target = match export.target() {
            formats::Pe32ExportTarget::ImageRva(rva) => Pe32ExportTarget::Rva(*rva),
            formats::Pe32ExportTarget::Forwarder { module, target } => {
                let symbol = match target {
                    formats::Pe32ForwardTarget::Name(name) => Pe32ImportSymbol::Name {
                        hint: 0,
                        name: copy_bytes(name, "copy PE32 forwarder name")?,
                    },
                    formats::Pe32ForwardTarget::Ordinal(ordinal) => {
                        Pe32ImportSymbol::Ordinal(*ordinal)
                    }
                };
                Pe32ExportTarget::Forwarder {
                    module: copy_bytes(module, "copy PE32 forwarder module")?,
                    symbol,
                }
            }
        };
        exports.push(Pe32ExportRecord {
            ordinal: u32::from(export.ordinal()),
            names,
            target,
        });
    }

    Ok(Pe32ModuleSpec {
        name: copy_bytes(name, "copy PE32 module name")?,
        image,
        is_dll: plan.is_dll(),
        entry_rva: plan.entry_rva(),
        has_tls: plan.tls().is_some(),
        loader_directories,
        sections,
        executable_ranges,
        imports,
        exports,
    })
}

pub(super) fn loader_directories_from_formats(
    directories: &[formats::Pe32DataDirectory],
) -> Result<Vec<Pe32LoaderDirectory>, RuntimeError> {
    let mut loader_directories = Vec::new();
    loader_directories
        .try_reserve_exact(directories.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 loader directory metadata",
                error,
            )
        })?;
    for directory in directories {
        let kind = match directory.kind() {
            formats::Pe32DataDirectoryKind::Export => Pe32LoaderDirectoryKind::Export,
            formats::Pe32DataDirectoryKind::Import => Pe32LoaderDirectoryKind::Import,
            formats::Pe32DataDirectoryKind::Resource => Pe32LoaderDirectoryKind::Resource,
            formats::Pe32DataDirectoryKind::Exception => Pe32LoaderDirectoryKind::Exception,
            formats::Pe32DataDirectoryKind::Security => Pe32LoaderDirectoryKind::Security,
            formats::Pe32DataDirectoryKind::BaseRelocation => {
                Pe32LoaderDirectoryKind::BaseRelocation
            }
            formats::Pe32DataDirectoryKind::Debug => Pe32LoaderDirectoryKind::Debug,
            formats::Pe32DataDirectoryKind::Architecture => Pe32LoaderDirectoryKind::Architecture,
            formats::Pe32DataDirectoryKind::GlobalPointer => Pe32LoaderDirectoryKind::GlobalPointer,
            formats::Pe32DataDirectoryKind::Tls => Pe32LoaderDirectoryKind::Tls,
            formats::Pe32DataDirectoryKind::LoadConfig => Pe32LoaderDirectoryKind::LoadConfig,
            formats::Pe32DataDirectoryKind::BoundImport => Pe32LoaderDirectoryKind::BoundImport,
            formats::Pe32DataDirectoryKind::Iat => Pe32LoaderDirectoryKind::Iat,
            formats::Pe32DataDirectoryKind::DelayImport => Pe32LoaderDirectoryKind::DelayImport,
            formats::Pe32DataDirectoryKind::ClrRuntimeHeader => {
                Pe32LoaderDirectoryKind::ClrRuntimeHeader
            }
            formats::Pe32DataDirectoryKind::Reserved => Pe32LoaderDirectoryKind::Reserved,
            formats::Pe32DataDirectoryKind::Other(index) => Pe32LoaderDirectoryKind::Other(index),
        };
        let address_kind = match directory.address_kind() {
            formats::Pe32DirectoryAddressKind::Rva => Pe32LoaderDirectoryAddressKind::ImageRva,
            formats::Pe32DirectoryAddressKind::FileOffset => {
                Pe32LoaderDirectoryAddressKind::FileOffset
            }
        };
        // The certificate directory is a file offset, so it must not be
        // treated as an RVA while validating or relocating guest memory.
        loader_directories.push(Pe32LoaderDirectory {
            kind,
            address_kind,
            address: directory.address(),
            size: directory.size(),
        });
    }

    Ok(loader_directories)
}

fn copy_bytes(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, context, error))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn loader_failure(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::CompatibilityGap, message)
}

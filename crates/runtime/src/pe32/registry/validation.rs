//! Checked metadata validation and address helpers shared by the registry.

use super::*;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub(super) fn validate_module_spec(spec: &Pe32ModuleSpec) -> Result<(), RuntimeError> {
    if spec.name.is_empty()
        || spec.name.contains(&0)
        || !spec.is_dll
        || spec.image.size == 0
        || spec.image.base.0 == 0
        || spec.image.arena_id == 0
        || spec.image.allocation_id == 0
        || spec.image.generation == 0
    {
        return Err(loader_failure(
            "PE32 module name or guest image range is invalid",
        ));
    }
    let end = u64::from(spec.image.base.0) + u64::from(spec.image.size);
    if end > u64::from(u32::MAX) + 1 {
        return Err(loader_failure(
            "PE32 guest image range overflows the 32-bit address space",
        ));
    }
    if spec.entry_rva.is_some_and(|entry| {
        entry >= spec.image.size
            || !spec
                .executable_ranges
                .iter()
                .any(|range| range_contains(*range, entry))
    }) {
        return Err(loader_failure(
            "PE32 entrypoint is outside an executable image section",
        ));
    }
    for range in &spec.executable_ranges {
        if !range.executable
            || range.size == 0
            || u64::from(range.start) + u64::from(range.size) > u64::from(spec.image.size)
        {
            return Err(loader_failure("PE32 executable section range is invalid"));
        }
    }
    for (index, section) in spec.sections.iter().enumerate() {
        if section.execute != (section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            || section.read != (section.characteristics & IMAGE_SCN_MEM_READ != 0)
            || section.write != (section.characteristics & IMAGE_SCN_MEM_WRITE != 0)
        {
            return Err(invariant(
                "PE32 section protection flags disagree with section characteristics",
            ));
        }
        if section.size != 0
            && u64::from(section.rva) + u64::from(section.size) > u64::from(spec.image.size)
        {
            return Err(loader_failure(
                "PE32 section range extends beyond its image",
            ));
        }
        if section.execute
            && section.size != 0
            && !spec.executable_ranges.iter().any(|range| {
                range.start == section.rva && range.size == section.size && range.executable
            })
        {
            return Err(invariant(
                "PE32 executable section metadata disagrees with fetch ranges",
            ));
        }
        if spec.sections[..index].iter().any(|previous| {
            section.size != 0
                && previous.size != 0
                && u64::from(section.rva) < u64::from(previous.rva) + u64::from(previous.size)
                && u64::from(previous.rva) < u64::from(section.rva) + u64::from(section.size)
        }) {
            return Err(loader_failure("PE32 section ranges overlap"));
        }
    }
    if spec
        .sections
        .iter()
        .filter(|section| section.execute && section.size != 0)
        .count()
        != spec.executable_ranges.len()
    {
        return Err(invariant(
            "PE32 fetch ranges do not match section permissions",
        ));
    }
    let mut iats = Vec::new();
    iats.try_reserve_exact(spec.imports.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 IAT validation ranges",
                error,
            )
        })?;
    for import in &spec.imports {
        if import.module.is_empty()
            || import.module.contains(&0)
            || import
                .iat_rva
                .checked_add(4)
                .map_or(true, |end| end > spec.image.size)
            || matches!(&import.symbol,
                Pe32ImportSymbol::Name { name, .. } if name.is_empty() || name.contains(&0))
        {
            return Err(loader_failure(
                "PE32 import table contains an invalid symbol or IAT slot",
            ));
        }
        iats.push(import.iat_rva);
    }
    iats.sort_unstable();
    if iats
        .windows(2)
        .any(|pair| pair[0].checked_add(4).map_or(true, |end| end > pair[1]))
    {
        return Err(loader_failure("PE32 IAT contains overlapping DWORD slots"));
    }

    let mut directories = BTreeSet::new();
    let mut has_tls_directory = false;
    for directory in &spec.loader_directories {
        if directory.address == 0 || directory.size == 0 || !directories.insert(directory.kind) {
            return Err(loader_failure(
                "PE32 data directories contain an empty or duplicate entry",
            ));
        }
        match directory.address_kind {
            Pe32LoaderDirectoryAddressKind::ImageRva => {
                if u64::from(directory.address) + u64::from(directory.size)
                    > u64::from(spec.image.size)
                {
                    return Err(loader_failure(
                        "PE32 data directory extends beyond its mapped image",
                    ));
                }
                if directory.kind == Pe32LoaderDirectoryKind::Security {
                    return Err(loader_failure(
                        "PE32 security directory has an invalid RVA address",
                    ));
                }
            }
            Pe32LoaderDirectoryAddressKind::FileOffset => {
                if directory.kind != Pe32LoaderDirectoryKind::Security {
                    return Err(loader_failure(
                        "only the PE32 security directory may use a file offset",
                    ));
                }
            }
        }
        has_tls_directory |= directory.kind == Pe32LoaderDirectoryKind::Tls;
    }
    if has_tls_directory != spec.has_tls {
        return Err(invariant(
            "PE32 TLS directory metadata disagrees with parsed TLS data",
        ));
    }

    let mut ordinals = BTreeSet::new();
    let mut names = BTreeSet::new();
    for export in &spec.exports {
        if !ordinals.insert(export.ordinal) {
            return Err(loader_failure(
                "PE32 export table contains a duplicate ordinal",
            ));
        }
        for name in &export.names {
            if name.is_empty() || name.contains(&0) || !names.insert(name.as_slice()) {
                return Err(loader_failure(
                    "PE32 export table contains an invalid or ambiguous name",
                ));
            }
        }
        match &export.target {
            Pe32ExportTarget::Rva(rva) if *rva >= spec.image.size => {
                return Err(loader_failure(
                    "PE32 export RVA is outside the loaded image",
                ));
            }
            Pe32ExportTarget::Forwarder { module, symbol } => {
                if module.is_empty()
                    || module.contains(&0)
                    || matches!(symbol, Pe32ImportSymbol::Name { name, .. } if name.is_empty() || name.contains(&0))
                {
                    return Err(loader_failure("PE32 forwarder contains an invalid target"));
                }
            }
            Pe32ExportTarget::Rva(_) => {}
        }
    }
    Ok(())
}

/// A populated directory may carry loader work even when its table was parsed.
/// Gate it before DllMain so unknown runtime requirements never become ready.
pub(super) fn check_loader_requirements(spec: &Pe32ModuleSpec) -> Result<(), RuntimeError> {
    check_loader_directories(&spec.loader_directories)
}

/// Share the same unsupported-directory gate with the file-image preflight,
/// which must run before the PE32 arena reserves or writes guest RAM.
pub(super) fn check_loader_directories(
    directories: &[Pe32LoaderDirectory],
) -> Result<(), RuntimeError> {
    for directory in directories {
        match directory.kind {
            Pe32LoaderDirectoryKind::Tls => {
                return Err(loader_failure(
                    "PE32 TLS storage and callbacks are not implemented",
                ));
            }
            Pe32LoaderDirectoryKind::DelayImport => {
                return Err(loader_failure(
                    "PE32 delay-import activation is not implemented",
                ));
            }
            Pe32LoaderDirectoryKind::ClrRuntimeHeader => {
                return Err(loader_failure(
                    "CLR-managed PE32 DLL loading is not implemented",
                ));
            }
            Pe32LoaderDirectoryKind::LoadConfig => {
                return Err(loader_failure(
                    "PE32 load-config, CFG, and security-cookie setup are not implemented",
                ));
            }
            Pe32LoaderDirectoryKind::Exception => {
                return Err(loader_failure(
                    "PE32 exception and SEH registration are not implemented",
                ));
            }
            Pe32LoaderDirectoryKind::Architecture
            | Pe32LoaderDirectoryKind::GlobalPointer
            | Pe32LoaderDirectoryKind::Reserved
            | Pe32LoaderDirectoryKind::Other(_) => {
                return Err(loader_failure(
                    "PE32 image has an unsupported data-directory requirement",
                ));
            }
            Pe32LoaderDirectoryKind::Export
            | Pe32LoaderDirectoryKind::Import
            | Pe32LoaderDirectoryKind::Resource
            | Pe32LoaderDirectoryKind::Security
            | Pe32LoaderDirectoryKind::BaseRelocation
            | Pe32LoaderDirectoryKind::Debug
            | Pe32LoaderDirectoryKind::BoundImport
            | Pe32LoaderDirectoryKind::Iat => {}
        }
    }
    Ok(())
}

pub(super) fn entrypoint_can_retire(entrypoint: Pe32EntryPointLifecycle) -> bool {
    matches!(
        entrypoint,
        Pe32EntryPointLifecycle::NotRequired
            | Pe32EntryPointLifecycle::AttachAborted
            | Pe32EntryPointLifecycle::Detached
            | Pe32EntryPointLifecycle::AttachFaulted
    )
}

pub(super) fn export_matches_key(export: &Pe32ExportRecord, key: &Pe32ExportKey) -> bool {
    match key {
        Pe32ExportKey::Ordinal(ordinal) => export.ordinal == *ordinal,
        Pe32ExportKey::Name(name) => export.names.iter().any(|candidate| candidate == name),
    }
}

/// A PE import descriptor contains a loader query, while `spec.name` is the
/// actual published image path. Keep the default-extension query rule in a
/// distinct type so resolution and prepared procedure/data checks cannot
/// compare the raw descriptor against a resolved file leaf.
pub(super) struct Pe32ImportModuleQueryKey(Vec<u8>);

impl Pe32ImportModuleQueryKey {
    pub(super) fn from_import_name(module: &[u8]) -> Result<Self, RuntimeError> {
        if module.is_empty() || module.contains(&0) {
            return Err(loader_failure("PE32 import module name is invalid"));
        }
        let leaf = module_basename(module);
        if leaf.is_empty() {
            return Err(loader_failure("PE32 import module name has no basename"));
        }

        let trailing_period = leaf.last() == Some(&b'.');
        let remove_query_marker = trailing_period && module.is_ascii();
        let key_leaf = if remove_query_marker {
            &leaf[..leaf.len() - 1]
        } else {
            leaf
        };
        if key_leaf.is_empty() {
            return Err(loader_failure(
                "PE32 import module name has no basename after query normalization",
            ));
        }
        let append_extension = !trailing_period
            && !leaf
                .iter()
                .rposition(|byte| *byte == b'.')
                .is_some_and(|dot| dot != 0);
        let capacity = key_leaf
            .len()
            .checked_add(if append_extension { 4 } else { 0 })
            .ok_or_else(|| loader_failure("PE32 import module query length overflowed"))?;
        let mut key = Vec::new();
        key.try_reserve_exact(capacity).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 import module query key",
                error,
            )
        })?;
        key.extend(key_leaf.iter().map(u8::to_ascii_lowercase));
        if append_extension {
            key.extend_from_slice(b".dll");
        }
        Ok(Self(key))
    }
}

pub(super) fn provider_matches(
    record: &ModuleRecord,
    requested: &Pe32ImportModuleQueryKey,
) -> bool {
    let provider = module_basename(&record.spec.name);
    !provider.is_empty() && provider.eq_ignore_ascii_case(&requested.0)
}

fn module_basename(module: &[u8]) -> &[u8] {
    module
        // Match the discovery query leaf rule for accepted drive-relative
        // descriptors such as `C:dep.dll`; this remains a lookup key only.
        .rsplit(|byte| matches!(*byte, b'/' | b'\\' | b':'))
        .next()
        .unwrap_or(module)
}

pub(super) fn direct_export<'a>(
    record: &'a ModuleRecord,
    symbol: &Pe32ImportSymbol,
) -> Option<&'a Pe32ExportRecord> {
    record.spec.exports.iter().find(|export| match symbol {
        Pe32ImportSymbol::Name { name, .. } => {
            export.names.iter().any(|candidate| candidate == name)
        }
        Pe32ImportSymbol::Ordinal(ordinal) => export.ordinal == u32::from(*ordinal),
    })
}

pub(super) fn direct_export_matches(
    record: &ModuleRecord,
    ordinal: Option<u32>,
    symbol: &Pe32ImportSymbol,
) -> bool {
    let Some(ordinal) = ordinal else {
        return false;
    };
    direct_export(record, symbol).is_some_and(|export| {
        export.ordinal == ordinal
            && matches!(&export.target, Pe32ExportTarget::Rva(rva)
                if record.spec.executable_ranges.iter().any(|range| range_contains(*range, *rva)))
    })
}

pub(super) fn range_contains(range: Pe32RvaRange, rva: u32) -> bool {
    range.start <= rva && u64::from(rva) < u64::from(range.start) + u64::from(range.size)
}

pub(super) fn rva_in_image(size: u32, rva: u32) -> bool {
    rva < size
}

pub(super) fn address_in_image(image: Pe32GuestImage, address: Pe32GuestAddress) -> bool {
    address.0 >= image.base.0
        && u64::from(address.0) < u64::from(image.base.0) + u64::from(image.size)
}

pub(super) fn guest_address(
    image: Pe32GuestImage,
    rva: u32,
) -> Result<Pe32GuestAddress, RuntimeError> {
    if !rva_in_image(image.size, rva) {
        return Err(invariant("PE32 guest RVA is outside its retained image"));
    }
    image
        .base
        .0
        .checked_add(rva)
        .map(Pe32GuestAddress)
        .ok_or_else(|| invariant("PE32 guest entry address overflows after image mapping"))
}

pub(super) fn loader_failure(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::CompatibilityGap, message)
}

pub(super) fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

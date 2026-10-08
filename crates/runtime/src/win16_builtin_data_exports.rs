//! Guest data images for declared variable exports from builtin Win16 modules.
//!
//! The caller owns the returned image and its selector for the builtin
//! module's lifetime. No host pointer is exposed to the guest.

use std::collections::{BTreeMap, BTreeSet};

use formats::{FarAddress, FormatError, NeDataImportIssue, NeImportTarget, NeImportValue};
use guest_core::{GuestMemory, PhysAddr, memory::{ROM_END, ROM_START}};
use devices::{BDA_BASE, BDA_SIZE, vga::{VGA_APERTURE_SIZE, VGA_APERTURE_START}};
use win16_abi::{AccessRights, SelectorRef, SelectorTable};
use win16_abi::exports::{
    ExportArchitecture, ExportEntryKind, ExportMetadata, WIN16_EXPORTS, Win16DataExportSource,
    Win16EquateValueSource, Win16RuntimeSelectorEquate, Win16VariableRuntimeState,
    lookup_data_export_source,
};
use win16_abi::version::{WIN16_MACHINE_FEATURES, WINDOWS_COMPATIBILITY_PROFILE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BuiltinDataExport {
    pub(crate) ordinal: u16,
    pub(crate) offset: u16,
    pub(crate) byte_length: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BuiltinDataImage {
    pub(crate) bytes: Vec<u8>,
    pub(crate) exports: Vec<BuiltinDataExport>,
    pub(crate) unsupported_runtime_state: Vec<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BootstrappedBuiltinData {
    pub(crate) image: BuiltinDataImage,
    pub(crate) selector: Option<SelectorRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectorAliasSpec {
    base: PhysAddr,
    size: u32,
    rights: AccessRights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectorAliasBinding {
    Live(SelectorRef),
    Unsupported(&'static str),
}

/// The one process-owned catalog used by initial NE relocation and every
/// later builtin-library relocation. It retains the runtime-owned identities
/// for the process-view lifetime. KERNEL.176/177 ownership checks prevent
/// guest APIs from freeing or repurposing these descriptors; dynamic lookups
/// still validate the live descriptor shape and retained identity.
#[derive(Debug, Default)]
pub(crate) struct RuntimeSelectorAliasCatalog {
    entries: BTreeMap<Win16RuntimeSelectorEquate, SelectorAliasBinding>,
}

impl RuntimeSelectorAliasCatalog {
    fn bootstrap(
        selectors: &mut SelectorTable,
        memory: &impl GuestMemory,
    ) -> Result<Self, crate::RuntimeError> {
        const ALL_EQUATES: [Win16RuntimeSelectorEquate; 12] = [
            Win16RuntimeSelectorEquate::RomBios,
            Win16RuntimeSelectorEquate::VideoA000,
            Win16RuntimeSelectorEquate::OptionRomC000,
            Win16RuntimeSelectorEquate::OptionRomD000,
            Win16RuntimeSelectorEquate::VideoB000,
            Win16RuntimeSelectorEquate::VideoB800,
            Win16RuntimeSelectorEquate::ConventionalZero,
            Win16RuntimeSelectorEquate::OptionRomE000,
            Win16RuntimeSelectorEquate::BiosData,
            Win16RuntimeSelectorEquate::BiosRomF000,
            Win16RuntimeSelectorEquate::FlatCode,
            Win16RuntimeSelectorEquate::FlatData,
        ];

        let mut entries = BTreeMap::new();
        let mut allocated = Vec::<(SelectorAliasSpec, SelectorRef)>::new();
        for equate in ALL_EQUATES {
            let binding = match selector_alias_spec(equate) {
                Some(spec) => {
                    // The BIOS ROM spellings identify the same physical
                    // segment and rights, so they deliberately share one
                    // descriptor identity rather than consuming two slots.
                    let existing = allocated.iter()
                        .find_map(|(candidate, reference)| (*candidate == spec).then_some(*reference));
                    let reference = match existing {
                        Some(reference) => reference,
                        None => {
                            allocated.try_reserve(1).map_err(|_| {
                                crate::RuntimeError::new(
                                    crate::DiagnosticKind::ResourceExhausted,
                                    "KERNEL selector alias catalog allocation failed",
                                )
                            })?;
                            let reference = selectors.alloc_block(
                                spec.base, spec.size, spec.rights, memory,
                            ).map_err(crate::runtime_error)?;
                            allocated.push((spec, reference));
                            reference
                        }
                    };
                    SelectorAliasBinding::Live(reference)
                }
                None => SelectorAliasBinding::Unsupported(selector_alias_gap(equate)),
            };
            entries.insert(equate, binding);
        }
        Ok(Self { entries })
    }

    fn resolve(
        &self,
        equate: Win16RuntimeSelectorEquate,
        selectors: Option<&SelectorTable>,
    ) -> Result<SelectorRef, &'static str> {
        match self.entries.get(&equate) {
            Some(SelectorAliasBinding::Live(reference)) => {
                if let Some(selectors) = selectors {
                    let spec = selector_alias_spec(equate)
                        .ok_or("the KERNEL selector alias has no live backing contract")?;
                    let descriptor = selectors.describe(*reference)
                        .map_err(|_| "the KERNEL selector alias identity is stale")?;
                    let expected_limit = spec.size.checked_sub(1)
                        .ok_or("the KERNEL selector alias has an empty backing contract")?;
                    if !descriptor.present
                        || descriptor.base != spec.base
                        || descriptor.limit != expected_limit
                        || descriptor.rights != spec.rights
                    {
                        return Err("the KERNEL selector alias descriptor was changed after bootstrap");
                    }
                }
                Ok(*reference)
            }
            Some(SelectorAliasBinding::Unsupported(detail)) => Err(detail),
            None => Err("the KERNEL selector alias catalog has been retired"),
        }
    }

    pub(crate) fn owns_selector(&self, selector: u16) -> bool {
        self.entries.values().any(|binding| match binding {
            SelectorAliasBinding::Live(reference) => reference.raw().0 == selector,
            SelectorAliasBinding::Unsupported(_) => false,
        })
    }

    /// Process-view teardown invalidates every descriptor generation at once;
    /// drop these identities immediately after that established retirement.
    pub(crate) fn retire(&mut self) {
        self.entries.clear();
    }
}

/// The Win16 SDK identifies selector equates and their segment bases, but the
/// consulted SDK pages do not specify descriptor limits or rights. These
/// candidate bindings therefore expose only the live guest backing range and
/// only the access that backing permits; they do not assert historical Windows
/// descriptor geometry.
fn selector_alias_spec(
    equate: Win16RuntimeSelectorEquate,
) -> Option<SelectorAliasSpec> {
    let spec = match equate {
        Win16RuntimeSelectorEquate::RomBios
        | Win16RuntimeSelectorEquate::BiosRomF000 => SelectorAliasSpec {
            base: PhysAddr(ROM_START),
            size: ROM_END.checked_sub(ROM_START)?,
            rights: AccessRights::read_only(),
        },
        Win16RuntimeSelectorEquate::VideoA000 => SelectorAliasSpec {
            base: PhysAddr(VGA_APERTURE_START),
            size: 0x1_0000,
            rights: AccessRights::read_write(),
        },
        Win16RuntimeSelectorEquate::VideoB000 => SelectorAliasSpec {
            base: PhysAddr(VGA_APERTURE_START.checked_add(0x1_0000)?),
            size: 0x1_0000,
            rights: AccessRights::read_write(),
        },
        Win16RuntimeSelectorEquate::VideoB800 => {
            let offset = 0x1_8000;
            SelectorAliasSpec {
                base: PhysAddr(VGA_APERTURE_START.checked_add(offset)?),
                size: VGA_APERTURE_SIZE.checked_sub(offset)?,
                rights: AccessRights::read_write(),
            }
        }
        Win16RuntimeSelectorEquate::ConventionalZero => SelectorAliasSpec {
            base: PhysAddr(0),
            size: 0x1_0000,
            rights: AccessRights::read_write(),
        },
        Win16RuntimeSelectorEquate::BiosData => SelectorAliasSpec {
            base: PhysAddr(BDA_BASE),
            size: u32::try_from(BDA_SIZE).ok()?,
            rights: AccessRights::read_write(),
        },
        Win16RuntimeSelectorEquate::OptionRomC000
        | Win16RuntimeSelectorEquate::OptionRomD000
        | Win16RuntimeSelectorEquate::OptionRomE000
        | Win16RuntimeSelectorEquate::FlatCode
        | Win16RuntimeSelectorEquate::FlatData => return None,
    };
    Some(spec)
}

fn selector_alias_gap(equate: Win16RuntimeSelectorEquate) -> &'static str {
    match equate {
        Win16RuntimeSelectorEquate::OptionRomC000
        | Win16RuntimeSelectorEquate::OptionRomD000
        | Win16RuntimeSelectorEquate::OptionRomE000 =>
            "the guest bus has no ROM or mapped-device backing for this option-ROM window; exposing ordinary RAM would misstate its source",
        Win16RuntimeSelectorEquate::FlatCode | Win16RuntimeSelectorEquate::FlatData =>
            "the Win16 path has no USE32 descriptor attribute and narrows segment offsets to 16 bits",
        _ => "this equate has no selector alias specification",
    }
}

/// Creates pinned builtin variable segments before the main NE image is
/// relocated, so both the executable and later DLLs resolve the same selector.
pub(crate) fn bootstrap_builtin_data_exports(
    selectors: &mut SelectorTable,
    memory: &mut guest_core::memory::Memory,
    arena_base: u32,
    arena_end: u32,
) -> Result<(
    BTreeMap<&'static str, BootstrappedBuiltinData>,
    u32,
    RuntimeSelectorAliasCatalog,
), crate::RuntimeError> {
    let aliases = RuntimeSelectorAliasCatalog::bootstrap(selectors, memory)?;
    let mut modules = BTreeSet::new();
    for declaration in WIN16_EXPORTS.iter().flat_map(|chunk| chunk.iter()) {
        if declaration.architecture == ExportArchitecture::Win16 {
            modules.insert(declaration.module);
        }
    }

    let mut next_base = arena_base;
    let mut prepared = BTreeMap::new();
    for module in modules {
        let Some(image) = build_builtin_data_image(
            module.as_bytes(),
            WIN16_EXPORTS.iter().flat_map(|chunk| chunk.iter()),
        ).map_err(crate::runtime_error)? else {
            continue;
        };
        let selector = if image.bytes.is_empty() {
            None
        } else {
            let base = next_base.checked_add(15).map(|value| value & !15)
                .ok_or_else(|| crate::RuntimeError::new(
                    crate::DiagnosticKind::ResourceExhausted,
                    "builtin Win16 data segment base overflowed",
                ))?;
            let size = u32::try_from(image.bytes.len()).map_err(|_| crate::RuntimeError::new(
                crate::DiagnosticKind::ResourceExhausted,
                "builtin Win16 data segment exceeds the address range",
            ))?;
            let end = base.checked_add(size).filter(|end| *end <= arena_end)
                .ok_or_else(|| crate::RuntimeError::new(
                    crate::DiagnosticKind::ResourceExhausted,
                    "builtin Win16 data exports exceed the guest arena",
                ))?;
            let reference = selectors.alloc_block(
                PhysAddr(base), size, AccessRights::read_write(), memory,
            ).map_err(crate::runtime_error)?;
            memory.write(PhysAddr(base), &image.bytes).map_err(crate::runtime_error)?;
            next_base = end;
            Some(reference)
        };
        prepared.insert(module, BootstrappedBuiltinData { image, selector });
    }
    Ok((prepared, next_base, aliases))
}

/// `selectors` is absent only while resolving the initial image, before guest
/// code can mutate descriptors; subsequent module imports provide the live
/// table so stale or changed alias descriptors are rejected.
pub(crate) fn lookup_builtin_data_export(
    declaration: &'static ExportMetadata,
    binding: Option<&BootstrappedBuiltinData>,
    aliases: &RuntimeSelectorAliasCatalog,
    selectors: Option<&SelectorTable>,
    import_module: &[u8],
    target: &NeImportTarget,
) -> Result<Option<NeImportValue>, FormatError> {
    match lookup_data_export_source(declaration) {
        Some(Win16DataExportSource::Equate(source)) => {
            let value = match source {
                Win16EquateValueSource::Literal(value) => value as u32,
                Win16EquateValueSource::CurrentWinFlags =>
                    WINDOWS_COMPATIBILITY_PROFILE.win_flags(WIN16_MACHINE_FEATURES),
                Win16EquateValueSource::RuntimeSelector(equate) => {
                    let selector = aliases.resolve(equate, selectors).map_err(|detail| {
                        data_import_failure(
                            declaration,
                            import_module,
                            target,
                            NeDataImportIssue::SelectorAliasUnavailable {
                                equate: declaration.declared_name,
                                detail,
                            },
                        )
                    })?;
                    return Ok(Some(NeImportValue::Selector(selector.raw())));
                }
            };
            let value = u16::try_from(value).map_err(|_| {
                FormatError::UnsupportedNeFeature("equate value exceeds the NE constant width")
            })?;
            Ok(Some(NeImportValue::Constant(value)))
        }
        Some(Win16DataExportSource::VariableWords { runtime_state, .. }) => {
            if runtime_state == Win16VariableRuntimeState::Unspecified {
                return Err(data_import_failure(
                    declaration,
                    import_module,
                    target,
                    NeDataImportIssue::RuntimeVariableStateUnspecified,
                ));
            }
            let binding = binding.ok_or(FormatError::InvalidNeLoad(
                "builtin variable export has no pinned data image",
            ))?;
            let export = binding.image.exports.iter()
                .find(|export| export.ordinal == declaration.ordinal)
                .ok_or(FormatError::InvalidNeLoad(
                    "builtin variable export is missing from its data image",
                ))?;
            let selector = binding.selector.ok_or(FormatError::InvalidNeLoad(
                "builtin variable export has no data selector",
            ))?;
            Ok(Some(NeImportValue::Address(FarAddress {
                selector: selector.raw(),
                offset: export.offset,
            })))
        }
        None if matches!(declaration.kind,
            ExportEntryKind::Extern | ExportEntryKind::Forward | ExportEntryKind::Unknown) =>
        {
            Err(data_import_failure(
                declaration,
                import_module,
                target,
                NeDataImportIssue::UnsupportedDeclarationKind,
            ))
        }
        None => Ok(None),
    }
}

fn data_import_failure(
    declaration: &'static ExportMetadata,
    import_module: &[u8],
    target: &NeImportTarget,
    issue: NeDataImportIssue,
) -> FormatError {
    FormatError::NeDataImportFailure {
        module: import_module.to_vec(),
        declared_name: declaration.declared_name,
        ordinal: declaration.ordinal,
        target: target.clone(),
        issue,
    }
}

/// Packs declaration initial values into one ordinary Win16 data segment.
/// Every variable begins at a four-byte boundary, and all offsets and the
/// complete segment must fit the 64-KiB Win16 offset space.
pub(crate) fn build_builtin_data_image(
    module: &[u8],
    declarations: impl IntoIterator<Item = &'static ExportMetadata>,
) -> Result<Option<BuiltinDataImage>, FormatError> {
    let mut bytes = Vec::new();
    let mut exports = Vec::new();
    let mut unsupported_runtime_state = Vec::new();

    for declaration in declarations {
        if !declaration.module.as_bytes().eq_ignore_ascii_case(module) {
            continue;
        }
        let Some(Win16DataExportSource::VariableWords {
            words,
            runtime_state,
        }) = lookup_data_export_source(declaration)
        else {
            continue;
        };
        if runtime_state == Win16VariableRuntimeState::Unspecified {
            unsupported_runtime_state
                .try_reserve(1)
                .map_err(|_| FormatError::AllocationFailed)?;
            unsupported_runtime_state.push(declaration.ordinal);
            continue;
        }
        if words.is_empty() {
            return Err(FormatError::InvalidNeLoad(
                "variable export has no declared initial data",
            ));
        }

        let aligned = bytes
            .len()
            .checked_add(3)
            .ok_or(FormatError::ArithmeticOverflow)?
            & !3;
        let byte_length = words
            .len()
            .checked_mul(4)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let end = aligned
            .checked_add(byte_length)
            .ok_or(FormatError::ArithmeticOverflow)?;
        if aligned > usize::from(u16::MAX) || end > 0x1_0000 {
            return Err(FormatError::InvalidNeLoad(
                "builtin variable exports exceed one Win16 data segment",
            ));
        }

        bytes
            .try_reserve(end.saturating_sub(bytes.len()))
            .map_err(|_| FormatError::AllocationFailed)?;
        exports
            .try_reserve(1)
            .map_err(|_| FormatError::AllocationFailed)?;
        bytes.resize(aligned, 0);
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        exports.push(BuiltinDataExport {
            ordinal: declaration.ordinal,
            offset: u16::try_from(aligned)
                .map_err(|_| FormatError::InvalidNeLoad("variable offset exceeds 16 bits"))?,
            byte_length: u32::try_from(byte_length).map_err(|_| FormatError::ArithmeticOverflow)?,
        });
    }

    if exports.is_empty() && unsupported_runtime_state.is_empty() {
        Ok(None)
    } else {
        Ok(Some(BuiltinDataImage {
            bytes,
            exports,
            unsupported_runtime_state,
        }))
    }
}

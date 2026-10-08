use crate::ne_checked::{read_u16, read_u8, write_stage};
use crate::ne_entrypoints::segment_allocation;
use crate::{
    FormatError, NeFixup, NeFixupAddressType, NeFixupTarget, NeImportModule, NeModule,
    NeRelocationKind,
};
use crate::ne_load::{FarAddress, NeImportTarget, NeImportValue, NeLoadResolver};
use std::collections::HashSet;

const SEGMENT_FLAG_HAS_FIXUPS: u16 = 0x0100;
// Microsoft Windows 3.1 Programmer's Reference, vol. 1, section 13.1.2
// (https://www.bitsavers.org/pdf/microsoft/windows_3.1/Microsoft_Windows_3.1_SDK_1992/PC28915-0492_Programmers_Reference_Volume_1_199204.pdf)
// defines OS fixup types 1-6 for 80x87 instructions and WIN87EM.DLL. The
// guest CPU executes the original x87/FWAIT instructions, so this NE loader
// selects the coprocessor path and keeps those bytes intact.
const FIRST_X87_OS_FIXUP: u16 = 1;
const LAST_X87_OS_FIXUP: u16 = 6;

#[derive(Clone)]
pub(super) struct ResolvedFixup {
    address_type: NeFixupAddressType,
    additive: bool,
    target: NeImportValue,
    sites: Vec<u16>,
}

pub(super) fn resolve_fixups(
    module: &NeModule,
    selectors: &[guest_core::Selector],
    allocation_sizes: &[u32],
    entry_points: &[Option<NeImportValue>],
    resolver: &mut impl NeLoadResolver,
    pristine_images: &[Vec<u8>],
) -> Result<Vec<Vec<ResolvedFixup>>, FormatError> {
    if pristine_images.len() != module.segments.len() {
        return Err(FormatError::InvalidNeLoad("staged image count disagrees with segment table"));
    }
    let mut all = Vec::new();
    all.try_reserve_exact(module.segments.len()).map_err(|_| FormatError::AllocationFailed)?;
    for (segment_index, segment) in module.segments.iter().enumerate() {
        let image = pristine_images.get(segment_index)
            .ok_or(FormatError::InvalidNeLoad("missing unrelocated segment image"))?;
        if !segment.fixups.is_empty() && segment.flags & SEGMENT_FLAG_HAS_FIXUPS == 0 {
            return Err(FormatError::InvalidNeLoad("fixup records are present without the segment fixup flag"));
        }
        let mut resolved = Vec::new();
        resolved.try_reserve_exact(segment.fixups.len()).map_err(|_| FormatError::AllocationFailed)?;
        for fixup in &segment.fixups {
            let width = fixup.address_type.width()
                .ok_or(FormatError::UnsupportedNeFixup("unknown NE source address type"))?;
            let source_end = u32::from(fixup.source_offset).checked_add(width)
                .ok_or(FormatError::ArithmeticOverflow)?;
            if usize::try_from(source_end).map_err(|_| FormatError::ArithmeticOverflow)? > image.len() {
                return Err(FormatError::InvalidNeLoad("fixup source extends past its allocated segment"));
            }
            if let (NeRelocationKind::OsFixup, NeFixupTarget::OsFixup { target1, target2 }) =
                (&fixup.relocation_kind, &fixup.target)
            {
                if fixup.address_type == NeFixupAddressType::Offset16
                    && (FIRST_X87_OS_FIXUP..=LAST_X87_OS_FIXUP).contains(target1)
                    && *target2 == 0
                {
                    continue;
                }
                return Err(FormatError::UnsupportedNeFixup("unknown OS fixup relocation"));
            }
            let target = resolve_fixup_target(module, fixup, selectors, allocation_sizes, entry_points, resolver)?;
            let sites = if fixup.additive {
                vec![fixup.source_offset]
            } else {
                chain_sites(image, fixup.source_offset, width)?
            };
            resolved.push(ResolvedFixup { address_type: fixup.address_type, additive: fixup.additive, target, sites });
        }
        all.push(resolved);
    }
    Ok(all)
}

pub(super) fn apply_fixups(
    images: &mut [Vec<u8>],
    fixups: &[Vec<ResolvedFixup>],
) -> Result<(), FormatError> {
    if images.len() != fixups.len() {
        return Err(FormatError::InvalidNeLoad("fixup groups disagree with the staged image count"));
    }
    for (segment_index, segment_fixups) in fixups.iter().enumerate() {
        let image = images.get_mut(segment_index)
            .ok_or(FormatError::InvalidNeLoad("missing staged segment image"))?;
        for fixup in segment_fixups {
            for site in &fixup.sites {
                apply_fixup(image, *site, fixup.address_type, fixup.additive, fixup.target)?;
            }
        }
    }
    Ok(())
}

fn resolve_fixup_target(
    module: &NeModule,
    fixup: &NeFixup,
    selectors: &[guest_core::Selector],
    allocation_sizes: &[u32],
    entry_points: &[Option<NeImportValue>],
    resolver: &mut impl NeLoadResolver,
) -> Result<NeImportValue, FormatError> {
    let target = match (&fixup.relocation_kind, &fixup.target) {
        (NeRelocationKind::Internal, NeFixupTarget::InternalSegment { segment, offset }) => {
            let (selector, allocation_size) = segment_allocation(selectors, allocation_sizes, *segment)?;
            if u32::from(*offset) >= allocation_size {
                return Err(FormatError::InvalidNeLoad("internal relocation offset is outside its allocated segment"));
            }
            NeImportValue::Address(FarAddress { selector, offset: *offset })
        }
        (NeRelocationKind::Internal, NeFixupTarget::InternalEntry { ordinal }) => {
            let zero_based = usize::from(ordinal.checked_sub(1)
                .ok_or(FormatError::InvalidNeLoad("internal entry ordinal zero is invalid"))?);
            entry_points.get(zero_based).copied().flatten()
                .ok_or(FormatError::InvalidNeLoad("internal relocation references an unused entry"))?
        }
        (NeRelocationKind::ImportByOrdinal, NeFixupTarget::ImportOrdinal { module_index, ordinal }) => {
            let import = import_module(&module.imported_modules, *module_index)?;
            resolver.resolve_import(&import.name, &NeImportTarget::Ordinal(*ordinal))?
        }
        (NeRelocationKind::ImportByName, NeFixupTarget::ImportName { module_index, name }) => {
            let import = import_module(&module.imported_modules, *module_index)?;
            resolver.resolve_import(&import.name, &NeImportTarget::Name(name.clone()))?
        }
        (NeRelocationKind::OsFixup, _) | (_, NeFixupTarget::OsFixup { .. }) => {
            return Err(FormatError::UnsupportedNeFixup("OS fixup relocation"));
        }
        _ => return Err(FormatError::InvalidNeLoad("fixup relocation kind and target disagree")),
    };
    let target_selector = match target {
        NeImportValue::Address(address) => Some(address.selector),
        NeImportValue::Selector(selector) => Some(selector),
        NeImportValue::Constant(_) => None,
    };
    if target_selector.is_some_and(|selector| selector.0 == 0) {
        return Err(FormatError::InvalidNeLoad("fixup resolved to the null selector"));
    }
    Ok(target)
}

fn import_module(imports: &[NeImportModule], module_index: u16) -> Result<&NeImportModule, FormatError> {
    let zero_based = usize::from(module_index.checked_sub(1)
        .ok_or(FormatError::InvalidNeLoad("import module index zero is invalid"))?);
    imports.get(zero_based).ok_or(FormatError::InvalidNeLoad("fixup references a missing import module"))
}

fn chain_sites(image: &[u8], first: u16, width: u32) -> Result<Vec<u16>, FormatError> {
    let mut sites = Vec::new();
    let mut visited = HashSet::new();
    let mut current = u32::from(first);
    loop {
        let site_end = current.checked_add(width).ok_or(FormatError::ArithmeticOverflow)?;
        if usize::try_from(site_end).map_err(|_| FormatError::ArithmeticOverflow)? > image.len() {
            return Err(FormatError::InvalidNeLoad("fixup chain site extends past its segment"));
        }
        visited.try_reserve(1).map_err(|_| FormatError::AllocationFailed)?;
        if !visited.insert(current) {
            return Err(FormatError::InvalidNeLoad("fixup chain contains a cycle"));
        }
        sites.try_reserve(1).map_err(|_| FormatError::AllocationFailed)?;
        sites.push(u16::try_from(current).map_err(|_| FormatError::InvalidNeLoad("fixup site exceeds 16 bits"))?);
        let next_field_end = current.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
        if usize::try_from(next_field_end).map_err(|_| FormatError::ArithmeticOverflow)? > image.len() {
            return Err(FormatError::InvalidNeLoad("fixup chain link is truncated"));
        }
        let next = read_u16(
            image,
            usize::try_from(current).map_err(|_| FormatError::ArithmeticOverflow)?,
            "NE fixup chain link",
        )?;
        if next == 0xffff || u32::from(next) == current {
            break;
        }
        current = u32::from(next);
    }
    Ok(sites)
}

fn apply_fixup(
    image: &mut [u8],
    site: u16,
    address_type: NeFixupAddressType,
    additive: bool,
    target: NeImportValue,
) -> Result<(), FormatError> {
    let base = usize::from(site);
    if let NeImportValue::Constant(value) = target {
        match address_type {
            // The NE source address type defines the scalar width. A byte
            // relocation therefore uses the low byte of this 16-bit value.
            NeFixupAddressType::LowByte => {
                let existing = read_u8(image, base, "NE byte constant-fixup source")?;
                let value = if additive { existing.wrapping_add(value as u8) } else { value as u8 };
                write_stage(image, base, &[value], "NE byte constant-fixup source")?;
            }
            NeFixupAddressType::Offset16 => {
                let existing = read_u16(image, base, "NE constant-fixup source")?;
                let value = if additive { existing.wrapping_add(value) } else { value };
                write_stage(image, base, &value.to_le_bytes(), "NE constant-fixup source")?;
            }
            NeFixupAddressType::Selector | NeFixupAddressType::FarPointer32 => {
                return Err(FormatError::UnsupportedNeFixup(
                    "constant target used as a selector or far pointer",
                ));
            }
            NeFixupAddressType::FarPointer48 => {
                return Err(FormatError::UnsupportedNeFixup("48-bit far pointer relocation"));
            }
            NeFixupAddressType::Offset32 => {
                return Err(FormatError::UnsupportedNeFixup("32-bit offset relocation"));
            }
            NeFixupAddressType::Unknown(_) => {
                return Err(FormatError::UnsupportedNeFixup("unknown NE source address type"));
            }
        }
        return Ok(());
    }
    let (target, scalar_value) = match target {
        NeImportValue::Address(target) => (target, target.offset),
        NeImportValue::Selector(selector) => (
            FarAddress { selector, offset: 0 },
            selector.0,
        ),
        NeImportValue::Constant(_) => {
            return Err(FormatError::InvalidNeLoad("NE import value kind is invalid"));
        }
    };
    match address_type {
        NeFixupAddressType::LowByte => {
            let existing = read_u8(image, base, "NE byte fixup source")?;
            let value = if additive {
                existing.wrapping_add(scalar_value as u8)
            } else {
                scalar_value as u8
            };
            write_stage(image, base, &[value], "NE byte fixup source")?;
        }
        NeFixupAddressType::Offset16 => {
            let existing = read_u16(image, base, "NE offset fixup source")?;
            let value = if additive { existing.wrapping_add(scalar_value) } else { scalar_value };
            write_stage(image, base, &value.to_le_bytes(), "NE offset fixup source")?;
        }
        NeFixupAddressType::Selector => {
            let existing = read_u16(image, base, "NE selector fixup source")?;
            if additive && existing != 0 {
                return Err(FormatError::InvalidNeLoad("additive selector fixup source is not zero"));
            }
            write_stage(image, base, &target.selector.0.to_le_bytes(), "NE selector fixup source")?;
        }
        NeFixupAddressType::FarPointer32 => {
            let existing_offset = read_u16(image, base, "NE far-pointer fixup offset")?;
            let fixed_offset = if additive { existing_offset.wrapping_add(target.offset) } else { target.offset };
            write_stage(image, base, &fixed_offset.to_le_bytes(), "NE far-pointer fixup offset")?;
            let selector_offset = base.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
            write_stage(image, selector_offset, &target.selector.0.to_le_bytes(), "NE far-pointer fixup selector")?;
        }
        NeFixupAddressType::FarPointer48 => {
            return Err(FormatError::UnsupportedNeFixup("48-bit far pointer relocation"));
        }
        NeFixupAddressType::Offset32 => {
            return Err(FormatError::UnsupportedNeFixup("32-bit offset relocation"));
        }
        NeFixupAddressType::Unknown(_) => {
            return Err(FormatError::UnsupportedNeFixup("unknown NE source address type"));
        }
    }
    Ok(())
}

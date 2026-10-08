use crate::ne_load::{FarAddress, NeImportValue, NeLoadedModule, NeLoadedSegment};
use crate::{FormatError, NeEntryKind, NeModule};
use guest_core::Selector;

pub(super) fn build_entry_points(
    module: &NeModule,
    selectors: &[Selector],
    allocation_sizes: &[u32],
) -> Result<Vec<Option<NeImportValue>>, FormatError> {
    let mut points = Vec::new();
    points.try_reserve_exact(module.entries.len()).map_err(|_| FormatError::AllocationFailed)?;
    points.resize(module.entries.len(), None);
    for (entry_index, entry) in module.entries.iter().enumerate() {
        let expected_ordinal = u16::try_from(entry_index.checked_add(1).ok_or(FormatError::ArithmeticOverflow)?)
            .map_err(|_| FormatError::InvalidNeLoad("entry table exceeds the ordinal limit"))?;
        if entry.ordinal != expected_ordinal {
            return Err(FormatError::InvalidNeLoad("entry ordinals are not unique and contiguous"));
        }
        let ordinal_index = usize::from(entry.ordinal.checked_sub(1)
            .ok_or(FormatError::InvalidNeLoad("entry ordinal zero is invalid"))?);
        let slot = points.get_mut(ordinal_index)
            .ok_or(FormatError::InvalidNeLoad("entry ordinal is outside the parsed entry table"))?;
        let value = match entry.kind {
            NeEntryKind::Unused => None,
            NeEntryKind::Fixed { segment, offset } | NeEntryKind::Movable { segment, offset } => {
                let (selector, allocation_size) = segment_allocation(selectors, allocation_sizes, segment)?;
                if u32::from(offset) >= allocation_size {
                    return Err(FormatError::InvalidNeLoad("entry offset is outside its allocated segment"));
                }
                Some(NeImportValue::Address(FarAddress { selector, offset }))
            }
            NeEntryKind::Constant(value) => Some(NeImportValue::Constant(value)),
        };
        *slot = value;
    }
    Ok(points)
}

pub(super) fn segment_allocation(
    selectors: &[Selector],
    sizes: &[u32],
    segment_number: u16,
) -> Result<(Selector, u32), FormatError> {
    let zero_based = usize::from(segment_number.checked_sub(1)
        .ok_or(FormatError::InvalidNeLoad("segment reference zero is invalid"))?);
    let selector = *selectors.get(zero_based)
        .ok_or(FormatError::InvalidNeLoad("segment reference is outside the module"))?;
    let size = *sizes.get(zero_based)
        .ok_or(FormatError::InvalidNeLoad("segment allocation is missing"))?;
    Ok((selector, size))
}

pub(super) fn build_loaded_module(
    module: &NeModule,
    selectors: &[Selector],
    allocation_sizes: &[u32],
    entry_points: Vec<Option<NeImportValue>>,
) -> Result<NeLoadedModule, FormatError> {
    let mut segments = Vec::new();
    segments.try_reserve_exact(module.segments.len()).map_err(|_| FormatError::AllocationFailed)?;
    for segment in &module.segments {
        let (selector, memory_size) = segment_allocation(selectors, allocation_sizes, segment.number)?;
        segments.push(NeLoadedSegment { number: segment.number, selector, memory_size });
    }
    let code_entry = if module.header.initial_cs == 0 {
        None
    } else {
        let (selector, size) = segment_allocation(selectors, allocation_sizes, module.header.initial_cs)?;
        if u32::from(module.header.initial_ip) >= size {
            return Err(FormatError::InvalidNeLoad("initial IP is outside its allocated segment"));
        }
        Some(FarAddress { selector, offset: module.header.initial_ip })
    };
    let stack = if module.header.initial_ss == 0 {
        None
    } else {
        let (selector, size) = segment_allocation(selectors, allocation_sizes, module.header.initial_ss)?;
        let stack_offset = if module.header.initial_sp == 0
            && module.header.initial_ss == module.header.automatic_data_segment
        {
            // Windows 3.1 Programmer's Reference, Volume 4, NE header offset
            // 0x18: when SS names the automatic data segment and SP is zero,
            // set SP to the automatic data segment size plus the stack size.
            let automatic_data_index =
                usize::from(module.header.automatic_data_segment.checked_sub(1).ok_or(
                    FormatError::InvalidNeLoad("automatic data segment reference zero is invalid"),
                )?);
            let data_size = module
                .segments
                .get(automatic_data_index)
                .ok_or(FormatError::InvalidNeLoad(
                    "automatic data segment is outside the module",
                ))?
                .memory_size;
            data_size
                .checked_add(u32::from(module.header.stack_size))
                .ok_or(FormatError::ArithmeticOverflow)?
        } else {
            u32::from(module.header.initial_sp)
        };
        // A 64-KiB segment's one-past-end stack top is represented by the
        // 16-bit SP value zero; all other calculated positions must fit SP.
        if stack_offset > size || stack_offset > 0x1_0000 {
            return Err(FormatError::InvalidNeLoad(
                "initial SP is outside its allocated segment",
            ));
        }
        let offset = if stack_offset == 0x1_0000 {
            0
        } else {
            u16::try_from(stack_offset).map_err(|_| {
                FormatError::InvalidNeLoad("initial SP exceeds the 16-bit segment limit")
            })?
        };
        Some(FarAddress { selector, offset })
    };
    Ok(NeLoadedModule { segments, entry_points, code_entry, stack })
}

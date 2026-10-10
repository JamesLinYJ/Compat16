use crate::ne_checked::{checked_file_range, zeroed_buffer};
use crate::ne_entrypoints::{build_entry_points, build_loaded_module};
use crate::ne_prologs::patch_windows_prologs;
use crate::ne_reloc::{apply_fixups, resolve_fixups};
use crate::ne_segments::{allocation_size, expand_segment};
use crate::{FormatError, GuestMemoryRollbackFailure, NeModule, NeResource};
use std::collections::HashSet;
use guest_core::{GuestMemory, PhysAddr, Selector};

const SEGMENT_FLAG_ITERATED: u16 = 0x0008;
const SEGMENT_FLAG_32BIT: u16 = 0x2000;
const MODULE_FLAG_SELF_LOADING: u16 = 0x0800;

/// A selector:offset address in the 16-bit NE address space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FarAddress {
    pub selector: Selector,
    pub offset: u16,
}

/// A typed NE export value. Selector equates are distinct from both callable
/// addresses and ordinary scalar constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeImportValue {
    Address(FarAddress),
    /// A typed protected-mode selector value. It can satisfy selector and
    /// scalar-word fixups without becoming a callable address or a literal.
    Selector(Selector),
    Constant(u16),
}

/// An imported NE procedure requested by name or ordinal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NeImportTarget {
    Ordinal(u16),
    Name(Vec<u8>),
}

/// Operations needed by the generic NE loader.
///
/// An allocation error must leave no allocation behind. Every selector
/// returned by allocate_segment is released if loading fails. selector_range
/// must validate the complete requested interval within that selector.
/// Import resolution must return a typed address, selector, or constant, or an
/// error; the loader never synthesizes a placeholder address.
pub trait NeLoadResolver {
    fn allocate_segment(
        &mut self,
        module: &NeModule,
        segment_number: u16,
        size: u32,
        flags: u16,
    ) -> Result<Selector, FormatError>;

    fn selector_range(
        &self,
        selector: Selector,
        offset: u32,
        length: usize,
    ) -> Result<PhysAddr, FormatError>;

    fn release_segment(&mut self, selector: Selector);

    fn resolve_import(
        &mut self,
        module_name: &[u8],
        target: &NeImportTarget,
    ) -> Result<NeImportValue, FormatError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeLoadedSegment {
    pub number: u16,
    pub selector: Selector,
    pub memory_size: u32,
}

/// Loaded NE selector assignments and typed exported values.
///
/// `entry_value` uses NE's one-based ordinal numbering. `entrypoint` returns
/// only address-valued exports; selectors and constants never become callable
/// addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeLoadedModule {
    pub segments: Vec<NeLoadedSegment>,
    pub(super) entry_points: Vec<Option<NeImportValue>>,
    pub code_entry: Option<FarAddress>,
    pub stack: Option<FarAddress>,
}

impl NeLoadedModule {
    pub fn entrypoint(&self, ordinal: u16) -> Option<FarAddress> {
        match self.entry_value(ordinal)? {
            NeImportValue::Address(address) => Some(address),
            NeImportValue::Selector(_) | NeImportValue::Constant(_) => None,
        }
    }

    pub fn entry_value(&self, ordinal: u16) -> Option<NeImportValue> {
        let zero_based = usize::from(ordinal.checked_sub(1)?);
        self.entry_points.get(zero_based).copied().flatten()
    }

    pub fn segment_selector(&self, segment_number: u16) -> Option<Selector> {
        let zero_based = usize::from(segment_number.checked_sub(1)?);
        self.segments.get(zero_based).map(|segment| segment.selector)
    }
}

/// Build NE selector and entrypoint metadata for caller-provided segment
/// selectors without expanding segments, resolving imports, or writing guest
/// memory.
///
/// `selectors` must contain exactly one unique, non-null selector per NE
/// segment, in the module's one-based segment order. The same segment-count,
/// numbering, allocation-size, 32-bit-segment, self-loading-module, entrypoint,
/// and initial CPU-state rules used by [`load_ne_segments`] are applied. This
/// plan lets a caller reserve selectors for a whole dependency graph before it
/// resolves cross-module imports and invokes the transactional loader.
pub fn plan_ne_segments(
    module: &NeModule,
    selectors: &[Selector],
) -> Result<NeLoadedModule, FormatError> {
    let allocation_sizes = validated_segment_allocation_sizes(module)?;
    if selectors.len() != allocation_sizes.len() {
        return Err(FormatError::InvalidNeLoad(
            "selector count disagrees with the NE segment table",
        ));
    }

    let mut selector_validator = SelectorValidator::with_capacity(selectors.len())?;
    for selector in selectors {
        selector_validator.accept(*selector)?;
    }

    let entry_points = build_entry_points(module, selectors, &allocation_sizes)?;
    build_loaded_module(module, selectors, &allocation_sizes, entry_points)
}

/// Return the loader's validated allocation size for one one-based NE segment.
///
/// This applies the same module-wide segment validation and automatic-data
/// segment stack/heap expansion used by [`load_ne_segments`], so callers can
/// reserve shared heap selectors before loading a dependency graph.
pub fn ne_segment_allocation_size(
    module: &NeModule,
    segment_number: u16,
) -> Result<u32, FormatError> {
    let allocation_sizes = validated_segment_allocation_sizes(module)?;
    let index = usize::from(segment_number.checked_sub(1).ok_or(
        FormatError::InvalidNeLoad("segment reference zero is invalid"),
    )?);
    allocation_sizes
        .get(index)
        .copied()
        .ok_or(FormatError::InvalidNeLoad(
            "segment reference is outside the module",
        ))
}

/// Allocate, expand, relocate, and copy all NE segments transactionally.
///
/// Segment data and relocation chains are fully staged before guest memory is
/// changed. Chain sites are read from the unrelocated expanded segment image.
/// Recognized Windows-target entry prologs are adapted to the assigned data
/// selector or instance-callback AX contract before relocation writes.
/// Fixup records are applied in file order: repeated additive fixups accumulate,
/// and later overlapping non-additive fixups overwrite earlier values.
pub fn load_ne_segments(
    bytes: &[u8],
    module: &NeModule,
    resolver: &mut impl NeLoadResolver,
    memory: &mut impl GuestMemory,
) -> Result<NeLoadedModule, FormatError> {
    let mut allocated = Vec::<Selector>::new();
    let result = load_ne_segments_inner(bytes, module, resolver, memory, &mut allocated);
    if result.is_err() {
        for selector in allocated.iter().rev().copied() {
            resolver.release_segment(selector);
        }
    }
    result
}

/// Return a resource's exact stored bytes after rechecking its file range.
pub fn extract_ne_resource(
    bytes: &[u8],
    resource: &NeResource,
) -> Result<Vec<u8>, FormatError> {
    let stored = checked_file_range(bytes, resource.file_offset, resource.byte_length, "NE resource data")?;
    let mut result = Vec::new();
    result.try_reserve_exact(stored.len()).map_err(|_| FormatError::AllocationFailed)?;
    result.extend_from_slice(stored);
    Ok(result)
}

struct StagedSegment {
    address: PhysAddr,
    bytes: Vec<u8>,
}

fn validated_segment_allocation_sizes(module: &NeModule) -> Result<Vec<u32>, FormatError> {
    if module.segments.is_empty() {
        return Err(FormatError::InvalidNeLoad("module has no segments"));
    }
    if module.header.flags & MODULE_FLAG_SELF_LOADING != 0 {
        return Err(FormatError::UnsupportedNeFeature("self-loading NE module"));
    }
    if module.header.segment_count > 255 {
        return Err(FormatError::InvalidNeLoad("segment count exceeds the NE reference limit"));
    }
    if module.segments.len() != usize::from(module.header.segment_count) {
        return Err(FormatError::InvalidNeLoad("segment count disagrees with the NE header"));
    }

    let mut allocation_sizes = Vec::new();
    allocation_sizes
        .try_reserve_exact(module.segments.len())
        .map_err(|_| FormatError::AllocationFailed)?;
    for (index, segment) in module.segments.iter().enumerate() {
        if segment.flags & SEGMENT_FLAG_32BIT != 0 {
            return Err(FormatError::UnsupportedNeFeature("32-bit NE segment"));
        }
        let expected_number = u16::try_from(
            index
                .checked_add(1)
                .ok_or(FormatError::ArithmeticOverflow)?,
        )
        .map_err(|_| FormatError::InvalidNeLoad("segment number exceeds the NE limit"))?;
        if segment.number != expected_number {
            return Err(FormatError::InvalidNeLoad(
                "segment numbers are not contiguous and one-based",
            ));
        }
        allocation_sizes.push(allocation_size(
            module,
            segment.number,
            segment.memory_size,
        )?);
    }
    Ok(allocation_sizes)
}

struct SelectorValidator {
    seen: HashSet<Selector>,
}

impl SelectorValidator {
    fn with_capacity(capacity: usize) -> Result<Self, FormatError> {
        let mut seen = HashSet::new();
        seen.try_reserve(capacity)
            .map_err(|_| FormatError::AllocationFailed)?;
        Ok(Self { seen })
    }

    fn accept(&mut self, selector: Selector) -> Result<(), FormatError> {
        if selector.0 == 0 {
            return Err(FormatError::InvalidNeLoad(
                "segment selector is zero",
            ));
        }
        if !self.seen.insert(selector) {
            return Err(FormatError::InvalidNeLoad(
                "segment selectors are not unique",
            ));
        }
        Ok(())
    }
}

fn load_ne_segments_inner(
    bytes: &[u8],
    module: &NeModule,
    resolver: &mut impl NeLoadResolver,
    memory: &mut impl GuestMemory,
    allocated: &mut Vec<Selector>,
) -> Result<NeLoadedModule, FormatError> {
    let allocation_sizes = validated_segment_allocation_sizes(module)?;
    let mut selectors = Vec::new();
    selectors.try_reserve_exact(module.segments.len()).map_err(|_| FormatError::AllocationFailed)?;
    allocated.try_reserve(module.segments.len()).map_err(|_| FormatError::AllocationFailed)?;
    let mut selector_validator = SelectorValidator::with_capacity(module.segments.len())?;

    for (index, segment) in module.segments.iter().enumerate() {
        let segment_size = *allocation_sizes
            .get(index)
            .ok_or(FormatError::InvalidNeLoad("missing segment allocation size"))?;
        let selector = resolver.allocate_segment(module, segment.number, segment_size, segment.flags)?;
        selector_validator.accept(selector)?;
        allocated.push(selector);
        selectors.push(selector);
    }

    let mut images = Vec::new();
    images.try_reserve_exact(module.segments.len()).map_err(|_| FormatError::AllocationFailed)?;
    for (index, segment) in module.segments.iter().enumerate() {
        let size = allocation_sizes.get(index).copied()
            .ok_or(FormatError::InvalidNeLoad("missing segment allocation size"))?;
        let source = match segment.file_offset {
            Some(offset) => {
                let file_size = usize::try_from(segment.file_size).map_err(|_| FormatError::ArithmeticOverflow)?;
                checked_file_range(bytes, offset, file_size, "NE segment image")?
            }
            None if segment.file_size == 0 => &[][..],
            None => return Err(FormatError::InvalidNeLoad("segment has a file size but no file offset")),
        };
        let image = expand_segment(source, size, segment.flags & SEGMENT_FLAG_ITERATED != 0)?;
        images.push(image);
    }

    let entry_points = build_entry_points(module, &selectors, &allocation_sizes)?;
    let resolved_fixups = resolve_fixups(module, &selectors, &allocation_sizes, &entry_points, resolver, &images)?;
    // Keep chain links pristine during resolution. As in the Windows NE
    // loading sequence implemented by Wine's NE_LoadSegment, prolog patches
    // precede relocation writes, so an overlapping relocation still wins.
    patch_windows_prologs(module, &selectors, &mut images)?;
    apply_fixups(&mut images, &resolved_fixups)?;

    let mut staged = Vec::new();
    staged.try_reserve_exact(module.segments.len()).map_err(|_| FormatError::AllocationFailed)?;
    for (index, image) in images.into_iter().enumerate() {
        let selector = *selectors.get(index).ok_or(FormatError::InvalidNeLoad("missing segment selector"))?;
        let address = resolver.selector_range(selector, 0, image.len())?;
        memory.validate_write(address, image.len())?;
        staged.push(StagedSegment { address, bytes: image });
    }
    validate_non_overlapping_writes(&staged)?;
    let loaded = build_loaded_module(module, &selectors, &allocation_sizes, entry_points)?;
    commit_staged_segments(memory, &staged)?;
    Ok(loaded)
}

fn validate_non_overlapping_writes(staged: &[StagedSegment]) -> Result<(), FormatError> {
    for (index, current) in staged.iter().enumerate() {
        let current_len = u32::try_from(current.bytes.len()).map_err(|_| FormatError::ArithmeticOverflow)?;
        let current_end = current.address.0.checked_add(current_len).ok_or(FormatError::ArithmeticOverflow)?;
        for previous in staged.iter().take(index) {
            let previous_len = u32::try_from(previous.bytes.len()).map_err(|_| FormatError::ArithmeticOverflow)?;
            let previous_end = previous.address.0.checked_add(previous_len).ok_or(FormatError::ArithmeticOverflow)?;
            if current.address.0 < previous_end && previous.address.0 < current_end {
                return Err(FormatError::InvalidNeLoad("selector mappings overlap in guest memory"));
            }
        }
    }
    Ok(())
}

fn commit_staged_segments(
    memory: &mut impl GuestMemory,
    staged: &[StagedSegment],
) -> Result<(), FormatError> {
    let mut previous_images = Vec::new();
    previous_images.try_reserve_exact(staged.len()).map_err(|_| FormatError::AllocationFailed)?;
    let mut rollback_failures = Vec::new();
    // Reserve before the first write so reporting a failed rollback does not
    // itself allocate after guest memory has changed.
    rollback_failures.try_reserve_exact(staged.len()).map_err(|_| FormatError::AllocationFailed)?;
    for segment in staged {
        let mut previous = zeroed_buffer(segment.bytes.len())?;
        memory.read(segment.address, &mut previous)?;
        previous_images.push(previous);
    }
    for (index, segment) in staged.iter().enumerate() {
        if let Err(error) = memory.write(segment.address, &segment.bytes) {
            // GuestMemory guarantees a failed write changes no bytes, so only
            // ranges from earlier successful writes need to be restored.
            for (committed, previous) in staged
                .iter()
                .zip(previous_images.iter())
                .take(index)
                .rev()
            {
                if let Err(rollback_error) = memory.write(committed.address, previous) {
                    rollback_failures.push(GuestMemoryRollbackFailure {
                        address: committed.address,
                        error: rollback_error,
                    });
                }
            }
            if rollback_failures.is_empty() {
                return Err(FormatError::GuestMemory(error));
            }
            return Err(FormatError::GuestMemoryRollback {
                failed_address: segment.address,
                primary_error: error,
                rollback_failures,
            });
        }
    }
    Ok(())
}

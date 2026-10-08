//! ToolHelp global-heap queries over the runtime's guest-owned Win16 state.
//!
//! Entries are built from live allocator, selector, module, resource and task
//! records. `dwAddress` is always a linear address in simulated guest memory;
//! allocator-private handle slots are never returned as Win16 HGLOBALs.

use guest_core::{memory::Memory, Selector};
use win16_abi::{
    toolhelp_abi::{
        GlobalEntry16, GlobalInfo16, GF_PDB_OWNER, GLOBAL_ALL, GLOBAL_FREE,
        GLOBAL_LRU, GT_CODE, GT_DATA, GT_DGROUP, GT_FREE, GT_INTERNAL, GT_MODULE, GT_RESOURCE,
        GT_TASK,
    },
    GlobalBlockInfo, GlobalHandle, GlobalHeapRegion, SegmentedPointer, SelectorRef,
    TaskState, TASK_DATABASE_PREFIX_SIZE,
};

use super::{module_registry::ModuleState, Win16State};
use crate::{DiagnosticKind as Kind, RuntimeError};

// GLOBALENTRY.wFlags low-byte bit from the Win16 global-arena flag contract.
// The current heap records whether an allocation is movable; other arena
// flags are not synthesized when the runtime does not retain their state.
const GA_MOVEABLE: u16 = 0x0002;
// NE segment-table flag: movable segment handles are selector minus one.
const NE_SEGMENT_MOVEABLE: u16 = 0x0010;
const NE_SEGMENT_DATA: u16 = 0x0001;

#[derive(Clone, Copy)]
struct SnapshotEntry {
    abi: GlobalEntry16,
    // Private opaque cursor used only to continue GlobalNext. It is never
    // dereferenced, and can differ from the public address for discarded or
    // otherwise zero-sized records.
    cursor: u32,
    selector: Option<u16>,
    module: Option<u16>,
    segment: Option<u16>,
    // Allocator identity is private and distinct from ABI HGLOBAL words.
    // Keep it solely for cross-referencing the heap's LRU order.
    heap_identity: Option<GlobalHandle>,
}

impl SnapshotEntry {
    fn free(base: u32, size: u32) -> Self {
        Self {
            abi: GlobalEntry16 {
                address: base,
                block_size: size,
                block_type: GT_FREE,
                ..GlobalEntry16::default()
            },
            cursor: base,
            selector: None,
            module: None,
            segment: None,
            heap_identity: None,
        }
    }

    fn matches_handle(self, handle: u16) -> bool {
        handle != 0 && (self.abi.block_handle == handle || self.selector == Some(handle))
    }
}

impl Win16State {
    /// Resolve a live guest HGLOBAL/module/task handle to its guest selector.
    /// The ABI result cannot carry an error, so stale or unknown identities
    /// return the documented null selector.
    pub(super) fn toolhelp_global_handle_to_sel(&self, handle: u16) -> u16 {
        if handle == 0 {
            return 0;
        }

        if self.dos_global_blocks.contains_key(&handle) {
            return self.global_selectors.get(&handle).copied()
                .and_then(|selector| self.selectors.describe(selector).ok()
                    .filter(|descriptor| descriptor.present)
                    .map(|_| selector.raw().0))
                .unwrap_or(0);
        }

        if let Some(identity) = self.global_handles.get(&handle).copied() {
            if let (Ok(info), Some(selector)) = (
                self.heap.info(identity), self.global_selectors.get(&handle).copied(),
            ) {
                if info.discarded && self.selectors.describe(selector).is_ok() {
                    return selector.raw().0;
                }
                if self.selector_matches_block(selector, info) {
                    return selector.raw().0;
                }
            }
            return 0;
        }

        // Fixed objects use selector == HGLOBAL. Movable objects use
        // selector - 1 as HGLOBAL, but selector-form queries are also valid.
        for (&guest_handle, &selector) in &self.global_selectors {
            if selector.raw().0 != handle { continue; }
            let Some(identity) = self.global_handles.get(&guest_handle).copied() else { continue; };
            if self.heap.info(identity).ok()
                .is_some_and(|info| self.selector_matches_block(selector, info))
            {
                return handle;
            }
        }

        if self.psp_selector.raw().0 == handle
            && self.selectors.describe(self.psp_selector).is_ok()
        {
            return handle;
        }
        if self.task_handles.values().any(|&task| task == handle)
            && self.selectors.reference(Selector(handle))
                .ok().is_some_and(|selector| self.selectors.describe(selector).is_ok())
        {
            return handle;
        }

        for record in self.modules.records.values() {
            if record.state == ModuleState::Retired {
                continue;
            }
            if record.handle == handle {
                if let Some(header) = record.allocations.first() {
                    if self.heap.info(header.handle).ok()
                        .is_some_and(|info| self.selector_matches_block(header.selector, info))
                    {
                        return header.selector.raw().0;
                    }
                }
            }
            if let Some(loaded) = record.loaded.as_ref() {
                for segment in &loaded.segments {
                    let selector = segment.selector.0;
                    let guest_handle = self.loaded_segment_handles.get(&selector)
                        .copied().unwrap_or(selector);
                    if handle != selector && handle != guest_handle {
                        continue;
                    }
                    let Ok(reference) = self.selectors.reference(Selector(selector)) else {
                        continue;
                    };
                    let Some(allocation) = record.allocations.iter()
                        .find(|allocation| allocation.selector.raw().0 == selector)
                    else {
                        // The main image's NE segments are resident in the
                        // reserved guest arena rather than GlobalHeap.
                        if record.handle == self.modules.main
                            && self.loaded.segments.iter().any(|main| main.selector.0 == selector)
                            && self.selectors.describe(reference).is_ok()
                        {
                            return selector;
                        }
                        continue;
                    };
                    if self.heap.info(allocation.handle).ok()
                        .is_some_and(|info| self.selector_matches_block(reference, info))
                    {
                        return selector;
                    }
                }
            }
        }

        for (selector, identity, _) in self.proc_global_blocks() {
            if selector != handle {
                continue;
            }
            if self.heap.info(identity).ok().is_some_and(|info| {
                self.selectors.reference(Selector(selector)).ok()
                    .is_some_and(|reference| self.selector_matches_block(reference, info))
            }) {
                return selector;
            }
        }

        for (&raw, &reference) in &self.allocated_selector_aliases {
            if raw == handle && self.selectors.describe(reference).is_ok() {
                return raw;
            }
        }
        for (&raw, &reference) in &self.api_allocated_selectors {
            if raw == handle && self.selectors.describe(reference).is_ok() {
                return raw;
            }
        }

        // Some runtime-owned fixed heap blocks have only a selector identity.
        // Returning that actual, currently installed selector is valid; the
        // internal GlobalHandle raw slot is never used as a guest handle.
        self.heap.snapshot_regions().ok().and_then(|regions| {
            regions.into_iter().find_map(|region| match region {
                GlobalHeapRegion::Allocated { info, selector: Some(selector), .. }
                    if selector.raw().0 == handle
                        && self.selector_matches_block(selector, info) => Some(handle),
                _ => None,
            })
        }).unwrap_or(0)
    }

    pub(super) fn toolhelp_global_first(
        &self, output: u32, flags: u16, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.global_entry_output(output, memory)? else {
            return Ok(0);
        };
        let Some(entries) = self.entries_for_flags(flags, memory)? else {
            return Ok(0);
        };
        let Some(first) = entries.first().copied() else { return Ok(0); };
        self.write_entry(pointer, dw_size, first, entries.get(1).copied(), memory)?;
        Ok(1)
    }

    pub(super) fn toolhelp_global_next(
        &self, output: u32, flags: u16, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size, previous)) = self.global_entry_input(output, memory)? else {
            return Ok(0);
        };
        let Some(entries) = self.entries_for_flags(flags, memory)? else {
            return Ok(0);
        };
        // dwNext is an opaque continuation value. Match it in a fresh
        // same-filter snapshot; it is never dereferenced as a pointer.
        let cursor = previous.next;
        if cursor == 0 { return Ok(0); }
        let Some(index) = entries.iter().position(|entry| entry.cursor == cursor) else {
            return Ok(0);
        };
        let current = entries[index];
        self.write_entry(pointer, dw_size, current, entries.get(index + 1).copied(), memory)?;
        Ok(1)
    }

    pub(super) fn toolhelp_global_info(
        &self, output: u32, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.global_info_output(output, memory)? else {
            return Ok(0);
        };
        let entries = self.snapshot_entries(memory)?;
        let items = u16::try_from(entries.len()).map_err(|_| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 ToolHelp GLOBALINFO item count exceeds WORD",
        ))?;
        let free_items = u16::try_from(entries.iter()
            .filter(|entry| entry.abi.block_type == GT_FREE).count())
            .map_err(|_| RuntimeError::new(Kind::ResourceExhausted,
                "Win16 ToolHelp GLOBALINFO free-item count exceeds WORD"))?;
        let lru_items = self.heap.lru_item_count().map_err(crate::runtime_error)?;
        let value = GlobalInfo16 { items, free_items, lru_items };
        self.selectors.write(memory, pointer, &value.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    pub(super) fn toolhelp_global_entry_handle(
        &self, output: u32, handle: u16, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.global_entry_output(output, memory)? else {
            return Ok(0);
        };
        let entries = self.snapshot_entries(memory)?;
        let Some(index) = entries.iter().position(|entry| entry.matches_handle(handle)) else {
            return Ok(0);
        };
        let current = entries[index];
        self.write_entry(pointer, dw_size, current, entries.get(index + 1).copied(), memory)?;
        Ok(1)
    }

    pub(super) fn toolhelp_global_entry_module(
        &self, output: u32, module: u16, segment: u16, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.global_entry_output(output, memory)? else {
            return Ok(0);
        };
        if module == 0 || segment == 0
            || !self.modules.records.get(&module)
                .is_some_and(|record| record.state != ModuleState::Retired && record.handle == module)
        {
            return Ok(0);
        }
        let entries = self.snapshot_entries(memory)?;
        let Some(index) = entries.iter().position(|entry| {
            entry.module == Some(module) && entry.segment == Some(segment)
        }) else {
            return Ok(0);
        };
        let current = entries[index];
        self.write_entry(pointer, dw_size, current, entries.get(index + 1).copied(), memory)?;
        Ok(1)
    }

    fn selector_matches_block(&self, selector: SelectorRef, info: GlobalBlockInfo) -> bool {
        self.selectors.describe(selector).ok().is_some_and(|descriptor| {
            descriptor.base == info.base
                && self.selectors.allocation_size(selector).ok()
                    .is_some_and(|size| size >= info.size)
        })
    }

    fn global_entry_output(
        &self, output: u32, memory: &Memory,
    ) -> Result<Option<(SegmentedPointer, u32)>, RuntimeError> {
        let pointer = self.output_pointer(output)?;
        let dw_size = self.read_dw_size(pointer, memory)?;
        Ok((dw_size >= GlobalEntry16::SIZE as u32).then_some((pointer, dw_size)))
    }

    fn global_entry_input(
        &self, output: u32, memory: &Memory,
    ) -> Result<Option<(SegmentedPointer, u32, GlobalEntry16)>, RuntimeError> {
        let pointer = self.output_pointer(output)?;
        let dw_size = self.read_dw_size(pointer, memory)?;
        if dw_size < GlobalEntry16::SIZE as u32 { return Ok(None); }
        let mut bytes = [0_u8; GlobalEntry16::SIZE];
        self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
        Ok(Some((pointer, dw_size, GlobalEntry16::decode(&bytes))))
    }

    fn global_info_output(
        &self, output: u32, memory: &Memory,
    ) -> Result<Option<(SegmentedPointer, u32)>, RuntimeError> {
        let pointer = self.output_pointer(output)?;
        let dw_size = self.read_dw_size(pointer, memory)?;
        Ok((dw_size >= GlobalInfo16::SIZE as u32).then_some((pointer, dw_size)))
    }

    fn output_pointer(&self, output: u32) -> Result<SegmentedPointer, RuntimeError> {
        self.selectors.pointer_from_far(output).map_err(|error|
            crate::runtime_error(error).with_context("validating Win16 ToolHelp output FAR pointer"))
    }

    fn read_dw_size(
        &self, pointer: SegmentedPointer, memory: &Memory,
    ) -> Result<u32, RuntimeError> {
        let mut bytes = [0_u8; 4];
        self.selectors.read(memory, pointer, &mut bytes).map_err(|error|
            crate::runtime_error(error).with_context("reading Win16 ToolHelp structure dwSize"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn write_entry(
        &self, pointer: SegmentedPointer, dw_size: u32, mut current: SnapshotEntry,
        following: Option<SnapshotEntry>, memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        current.abi.next = following.map_or(0, |entry| entry.cursor);
        current.abi.next_alt = 0;
        self.selectors.write(memory, pointer, &current.abi.encode_with_size(dw_size))
            .map_err(crate::runtime_error)
    }

    fn entries_for_flags(
        &self, flags: u16, memory: &Memory,
    ) -> Result<Option<Vec<SnapshotEntry>>, RuntimeError> {
        match flags {
            GLOBAL_LRU => {
                let order = self.heap.lru_handles().map_err(crate::runtime_error)?;
                let snapshot = self.snapshot_entries(memory)?;
                let mut entries = Vec::new();
                entries.try_reserve_exact(order.len()).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted, "allocate Win16 ToolHelp LRU order", error,
                ))?;
                for handle in order {
                    let Some(entry) = snapshot.iter().find(|entry| entry.heap_identity == Some(handle))
                        .copied() else {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "Win16 discardable HGLOBAL is missing from ToolHelp snapshot"));
                    };
                    entries.push(entry);
                }
                Ok(Some(entries))
            }
            GLOBAL_ALL | GLOBAL_FREE => {
                let snapshot = self.snapshot_entries(memory)?;
                let mut filtered = Vec::new();
                filtered.try_reserve_exact(snapshot.len()).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted, "allocate Win16 ToolHelp entry filter", error,
                ))?;
                for entry in snapshot {
                    if flags == GLOBAL_ALL || entry.abi.block_type == GT_FREE {
                        filtered.push(entry);
                    }
                }
                Ok(Some(filtered))
            }
            _ => Ok(None),
        }
    }

    fn snapshot_entries(&self, memory: &Memory) -> Result<Vec<SnapshotEntry>, RuntimeError> {
        let regions = self.heap.snapshot_regions().map_err(crate::runtime_error)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(regions.len().saturating_add(self.dos_global_blocks.len())
            .saturating_add(self.loaded.segments.len())
            .saturating_add(self.task_handles.len()).saturating_add(1))
            .map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "allocate Win16 ToolHelp global snapshot", error,
            ))?;

        for region in regions {
            match region {
                GlobalHeapRegion::Free { base, size } => {
                    entries.push(SnapshotEntry::free(base.0, size));
                }
                GlobalHeapRegion::Allocated { identity, info, selector } => {
                    if let Some(entry) = self.module_allocation_entry(identity, info, memory)? {
                        entries.push(entry);
                    } else if let Some(entry) = self.global_allocation_entry(identity, info, memory)? {
                        entries.push(entry);
                    } else if let Some((guest_selector, _identity, _owner_ds)) =
                        self.proc_global_blocks().find(|(_, candidate, _)| *candidate == identity)
                    {
                        let reference = self.selectors.reference(Selector(guest_selector))
                            .map_err(crate::runtime_error)?;
                        self.validate_snapshot_selector(reference, info, "procedure thunk")?;
                        let (owner, owner_flag) = self.pdb_owner(info.owner, memory)?;
                        let mut flags = if info.movable { GA_MOVEABLE } else { 0 };
                        if owner_flag { flags |= GF_PDB_OWNER; }
                        entries.push(SnapshotEntry {
                            abi: GlobalEntry16 {
                                address: info.base.0, block_size: info.size,
                                block_handle: guest_selector,
                                lock_count: info.lock_count,
                                page_lock_count: info.page_lock_count, flags, owner,
                                block_type: GT_INTERNAL,
                                heap_present: self.toolhelp_local_heap_present(guest_selector, memory)?,
                                ..GlobalEntry16::default()
                            },
                            cursor: info.base.0,
                            selector: Some(guest_selector), module: None, segment: None,
                            heap_identity: Some(identity),
                        });
                    } else {
                        let reference = selector.ok_or_else(|| RuntimeError::new(
                            Kind::InternalInvariant,
                            "live Win16 global allocation has no guest HGLOBAL or selector mapping",
                        ))?;
                        self.validate_snapshot_selector(reference, info, "runtime-owned heap block")?;
                        let raw = reference.raw().0;
                        let (owner, owner_flag) = self.pdb_owner(info.owner, memory)?;
                        let flags = (if info.movable { GA_MOVEABLE } else { 0 })
                            | (if owner_flag { GF_PDB_OWNER } else { 0 });
                        let address = info.base.0;
                        let block_size = info.size;
                        entries.push(SnapshotEntry {
                            abi: GlobalEntry16 {
                                address, block_size, block_handle: raw,
                                lock_count: info.lock_count,
                                page_lock_count: info.page_lock_count, flags, owner,
                                block_type: GT_INTERNAL,
                                heap_present: self.toolhelp_local_heap_present(raw, memory)?,
                                ..GlobalEntry16::default()
                            },
                            cursor: info.base.0,
                            selector: Some(raw), module: None, segment: None,
                            heap_identity: Some(identity),
                        });
                    }
                }
            }
        }

        for (&handle, block) in &self.dos_global_blocks {
            if block.mcb_released { continue; }
            let base = block.extent.guest_base().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 DOS global MCB has no linear address",
            ))?;
            let size = block.extent.byte_length().and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DOS global MCB byte length exceeds the guest range"))?;
            let selector = self.global_selectors.get(&handle).copied().ok_or_else(||
                RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DOS global block has no selector mapping"))?;
            let descriptor = self.selectors.describe(selector).map_err(crate::runtime_error)?;
            if !descriptor.present || descriptor.base != base
                || self.selectors.allocation_size(selector).map_err(crate::runtime_error)? < size
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DOS global selector disagrees with its exact MCB extent"));
            }
            let owner = block.guest_owner.raw();
            let owner_is_pdb = self.guest_owner_is_pdb(owner, memory)?;
            let flags = if owner_is_pdb { GF_PDB_OWNER } else { 0 };
            entries.push(SnapshotEntry {
                abi: GlobalEntry16 {
                    address: base.0,
                    block_size: size,
                    block_handle: handle,
                    lock_count: block.fix_count.saturating_add(block.wire_count),
                    page_lock_count: block.page_lock_count,
                    flags,
                    owner,
                    block_type: GT_DATA,
                    ..GlobalEntry16::default()
                },
                cursor: base.0,
                selector: Some(selector.raw().0),
                module: None,
                segment: None,
                heap_identity: None,
            });
        }

        self.append_main_segments(&mut entries, memory)?;
        self.append_task_blocks(&mut entries, memory)?;
        entries.sort_by_key(|entry| (entry.cursor, entry.abi.address, entry.abi.block_size,
            entry.abi.block_type, entry.abi.block_handle));
        // `dwNext` is an opaque continuation value, not an address to read.
        // Give zero-sized discarded blocks and any same-address aliases a
        // unique private cursor so each snapshot entry remains reachable.
        let mut used = std::collections::BTreeSet::new();
        let mut next_private = u32::MAX;
        for entry in &mut entries {
            if entry.cursor != 0 && used.insert(entry.cursor) { continue; }
            loop {
                if next_private != 0 && used.insert(next_private) {
                    entry.cursor = next_private;
                    next_private = next_private.wrapping_sub(1);
                    break;
                }
                next_private = next_private.wrapping_sub(1);
                if next_private == u32::MAX {
                    return Err(RuntimeError::new(Kind::ResourceExhausted,
                        "Win16 ToolHelp cursor space is exhausted"));
                }
            }
        }
        Ok(entries)
    }

    fn module_allocation_entry(
        &self, identity: GlobalHandle, info: GlobalBlockInfo, memory: &Memory,
    ) -> Result<Option<SnapshotEntry>, RuntimeError> {
        for (&module, record) in &self.modules.records {
            if record.state == ModuleState::Retired { continue; }
            let Some((index, allocation)) = record.allocations.iter().enumerate()
                .find(|(_, allocation)| allocation.handle == identity)
            else { continue; };
            let selector = allocation.selector.raw().0;
            self.validate_snapshot_selector(allocation.selector, info, "NE module allocation")?;
            if index == 0 {
                return Ok(Some(SnapshotEntry {
                            abi: GlobalEntry16 {
                                address: info.base.0, block_size: info.size,
                                block_handle: record.handle, lock_count: info.lock_count,
                                page_lock_count: info.page_lock_count,
                                owner: record.handle, block_type: GT_MODULE,
                        heap_present: self.toolhelp_local_heap_present(selector, memory)?,
                        ..GlobalEntry16::default()
                    },
                    cursor: info.base.0,
                    selector: Some(selector), module: Some(module), segment: None,
                    heap_identity: Some(identity),
                }));
            }

            let definition = record.definition.as_ref().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 module segment has no NE definition",
            ))?;
            let loaded = record.loaded.as_ref().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 module segment has no loaded selector metadata",
            ))?;
            let segment = loaded.segments.iter().find(|segment| segment.selector.0 == selector)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "Win16 module allocation is not associated with a loaded NE segment"))?;
            let segment_definition = definition.segments.iter()
                .find(|segment_definition| segment_definition.number == segment.number)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "Win16 loaded module segment has no NE segment-table entry"))?;
            let guest_handle = self.loaded_segment_handles.get(&selector).copied()
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "Win16 module segment has no guest handle mapping"))?;
            let expected_handle = (if segment_definition.flags & NE_SEGMENT_MOVEABLE != 0 {
                selector.checked_sub(1)
            } else {
                Some(selector)
            }).ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 movable module segment has no handle word"))?;
            if guest_handle != expected_handle {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 module segment handle disagrees with its NE flags"));
            }
            let block_type = if segment.number == definition.header.automatic_data_segment {
                GT_DGROUP
            } else if segment_definition.flags & NE_SEGMENT_DATA != 0 {
                GT_DATA
            } else {
                GT_CODE
            };
            let flags = if segment_definition.flags & NE_SEGMENT_MOVEABLE != 0 {
                GA_MOVEABLE
            } else { 0 };
            return Ok(Some(SnapshotEntry {
                abi: GlobalEntry16 {
                    address: info.base.0, block_size: info.size,
                    block_handle: guest_handle, lock_count: info.lock_count,
                    page_lock_count: info.page_lock_count,
                    flags, owner: record.handle, block_type,
                    data: if block_type == GT_CODE { segment.number } else { 0 },
                    heap_present: self.toolhelp_local_heap_present(selector, memory)?,
                    ..GlobalEntry16::default()
                },
                cursor: info.base.0,
                selector: Some(selector), module: Some(module), segment: Some(segment.number),
                heap_identity: Some(identity),
            }));
        }
        Ok(None)
    }

    fn global_allocation_entry(
        &self, identity: GlobalHandle, info: GlobalBlockInfo, memory: &Memory,
    ) -> Result<Option<SnapshotEntry>, RuntimeError> {
        let Some(handle) = self.global_handles.iter()
            .find_map(|(&handle, &candidate)| (candidate == identity).then_some(handle))
        else { return Ok(None); };
        let selector = self.global_selectors.get(&handle).copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 HGLOBAL is missing its stable guest selector",
        ))?;
        if !info.discarded {
            self.validate_snapshot_selector(selector, info, "Win16 HGLOBAL")?;
        } else {
            self.selectors.describe(selector).map_err(crate::runtime_error)?;
        }
        let resource = self.toolhelp_resource_info(handle, identity);
        let (owner, owner_is_pdb, block_type, data) = match resource {
            Some((module, resource_type)) => (module, false, GT_RESOURCE, resource_type),
            None => {
                let (pdb, internal_pdb_owner) = self.pdb_owner(info.owner, memory)?;
                let (owner, is_pdb) = match info.guest_owner {
                    Some(guest_owner) => {
                        let raw = guest_owner.raw();
                        (raw, self.guest_owner_is_pdb(raw, memory)?)
                    }
                    None => (pdb, internal_pdb_owner),
                };
                (owner, is_pdb, GT_DATA, 0)
            }
        };
        let mut flags = if info.movable { GA_MOVEABLE } else { 0 };
        if owner_is_pdb { flags |= GF_PDB_OWNER; }
        let discarded = info.discarded;
        Ok(Some(SnapshotEntry {
            abi: GlobalEntry16 {
                address: if discarded { 0 } else { info.base.0 },
                block_size: if discarded { 0 } else { info.size },
                block_handle: handle, lock_count: info.lock_count,
                page_lock_count: info.page_lock_count, flags, owner,
                block_type, data,
                heap_present: !discarded
                    && self.toolhelp_local_heap_present(selector.raw().0, memory)?,
                ..GlobalEntry16::default()
            },
            cursor: info.base.0,
            selector: Some(selector.raw().0), module: None, segment: None,
            heap_identity: Some(identity),
        }))
    }

    fn append_main_segments(
        &self, entries: &mut Vec<SnapshotEntry>, memory: &Memory,
    ) -> Result<(), RuntimeError> {
        let Some(record) = self.modules.records.get(&self.modules.main)
            .filter(|record| record.state != ModuleState::Retired)
        else { return Ok(()); };
        let Some(definition) = record.definition.as_ref() else { return Ok(()); };
        for segment in &self.loaded.segments {
            let segment_definition = definition.segments.iter()
                .find(|definition| definition.number == segment.number)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "main NE loaded segment has no segment-table entry"))?;
            let selector = segment.selector.0;
            let reference = self.selectors.reference(Selector(selector)).map_err(crate::runtime_error)?;
            let descriptor = self.selectors.describe(reference).map_err(crate::runtime_error)?;
            if u64::from(descriptor.limit) + 1 < u64::from(segment.memory_size) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "main NE segment exceeds its checked guest selector"));
            }
            let block_handle = self.loaded_segment_handles.get(&selector).copied()
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "main NE segment has no guest handle mapping"))?;
            let expected_handle = (if segment_definition.flags & NE_SEGMENT_MOVEABLE != 0 {
                selector.checked_sub(1)
            } else { Some(selector) }).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "main movable NE segment has no handle word",
            ))?;
            if block_handle != expected_handle {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "main NE segment handle disagrees with its NE flags"));
            }
            let block_type = if segment.number == definition.header.automatic_data_segment {
                GT_DGROUP
            } else if segment_definition.flags & NE_SEGMENT_DATA != 0 {
                GT_DATA
            } else {
                GT_CODE
            };
            let flags = if segment_definition.flags & NE_SEGMENT_MOVEABLE != 0 {
                GA_MOVEABLE
            } else { 0 };
            entries.push(SnapshotEntry {
                abi: GlobalEntry16 {
                    address: descriptor.base.0, block_size: segment.memory_size,
                    block_handle, flags, owner: record.handle, block_type,
                    data: if block_type == GT_CODE { segment.number } else { 0 },
                    heap_present: self.toolhelp_local_heap_present(selector, memory)?,
                    ..GlobalEntry16::default()
                },
                cursor: descriptor.base.0,
                selector: Some(selector), module: Some(record.handle), segment: Some(segment.number),
                heap_identity: None,
            });
        }
        Ok(())
    }

    fn append_task_blocks(
        &self, entries: &mut Vec<SnapshotEntry>, memory: &Memory,
    ) -> Result<(), RuntimeError> {
        for (&owner_id, &task_handle) in &self.task_handles {
            let task_info = match self.tasks.info(owner_id) {
                Ok(info) if !matches!(info.state, TaskState::Terminating | TaskState::Exited) => info,
                _ => continue,
            };
            let _ = task_info;
            let task_selector = self.selectors.reference(Selector(task_handle))
                .map_err(crate::runtime_error)?;
            let descriptor = self.selectors.describe(task_selector).map_err(crate::runtime_error)?;
            let (pdb, is_pdb) = self.pdb_owner(owner_id, memory)?;
            let mut flags = 0;
            if is_pdb { flags |= GF_PDB_OWNER; }
            entries.push(SnapshotEntry {
                abi: GlobalEntry16 {
                    address: descriptor.base.0,
                    block_size: descriptor.limit.saturating_add(1)
                        .min(TASK_DATABASE_PREFIX_SIZE as u32),
                    block_handle: task_handle, flags, owner: pdb,
                    block_type: GT_TASK,
                    heap_present: self.toolhelp_local_heap_present(task_handle, memory)?,
                    ..GlobalEntry16::default()
                },
                cursor: descriptor.base.0,
                selector: Some(task_handle), module: None, segment: None,
                heap_identity: None,
            });
        }

        let psp = self.selectors.describe(self.psp_selector).map_err(crate::runtime_error)?;
        entries.push(SnapshotEntry {
            abi: GlobalEntry16 {
                address: psp.base.0,
                block_size: psp.limit.saturating_add(1),
                block_handle: self.psp_selector.raw().0,
                block_type: GT_DATA,
                ..GlobalEntry16::default()
            },
            cursor: psp.base.0,
            selector: Some(self.psp_selector.raw().0), module: None, segment: None,
            heap_identity: None,
        });
        Ok(())
    }

    fn validate_snapshot_selector(
        &self, selector: SelectorRef, info: GlobalBlockInfo, object: &str,
    ) -> Result<(), RuntimeError> {
        let descriptor = self.selectors.describe(selector).map_err(crate::runtime_error)?;
        let allocation_size = self.selectors.allocation_size(selector)
            .map_err(crate::runtime_error)?;
        if !descriptor.present || descriptor.base != info.base || allocation_size < info.size
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                format!("Win16 {object} selector disagrees with its live heap allocation")));
        }
        Ok(())
    }
}

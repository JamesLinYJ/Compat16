//! Selector operations exposed by the Win16 KERNEL ABI.
//!
//! This module keeps the historical descriptor flags alongside the runtime's
//! capability permissions. The guest API can only express the ordinary
//! 16-bit present ring-3 data/code forms represented by this selector table.

use guest_core::{GuestMemory, PhysAddr};

use super::{
    AccessRights, AllocationResizePolicy, Descriptor, SelectorRef, SelectorTable,
    SELECTOR_SHIFT, Win16Error, selector_index,
};

/// Canonical access/flag bytes for descriptors created by runtime services.
/// LDT Flags1's high nibble is the present, ring-3 application descriptor
/// shape; the low nibble selects readable code or writable data.
pub(super) const fn canonical_access_flags(rights: AccessRights) -> u16 {
    let kind = if rights.executable() { 0x08 } else { 0x00 };
    let read_write = if rights.executable() {
        rights.readable()
    } else {
        rights.writable()
    };
    0x00f0 | kind | if read_write { 0x02 } else { 0x00 }
}

impl SelectorTable {
    /// Copy each 64-KiB descriptor in a source selector run into an
    /// independently owned guest selector.
    ///
    /// The selector table models checked guest ranges, not host LDT entries;
    /// this narrow copy keeps the source's base, effective 16-bit limit,
    /// access bits, and generation-independent identity without making a
    /// guest selector into an operating-system selector.
    pub fn alloc_selector_copy(
        &mut self,
        source: SelectorRef,
        memory: &impl GuestMemory,
    ) -> Result<Vec<SelectorRef>, Win16Error> {
        let source_descriptor = self.validate(source)?;
        if source_descriptor.segment_index == 0 {
            self.validate_all_segments(source_descriptor)?;
        }

        // AllocSelector copies the source LDT entry run. Each copied entry is
        // independently freed by FreeSelector, so model each copied slot as a
        // one-entry allocation instead of one indivisible selector block.
        // The guest ABI has no host LDT to copy, and source bytes stay in
        // checked GuestMemory; validate every present source entry first.
        let source_index = if source_descriptor.segment_index == 0 {
            source_descriptor.block_index
        } else {
            usize::from(source.raw().0 >> SELECTOR_SHIFT)
        };
        let count = if source_descriptor.segment_index == 0 {
            source_descriptor.segment_count
        } else {
            1
        };
        let mut source_entries = Vec::new();
        source_entries.try_reserve_exact(count).map_err(|_| Win16Error::OutOfMemory)?;
        for segment in 0..count {
            let descriptor = self.entries.get(source_index + segment)
                .and_then(Option::as_ref).copied()
                .ok_or(Win16Error::StaleSelector)?;
            if descriptor.present {
                let size = descriptor.limit.checked_add(1)
                    .ok_or(Win16Error::InvalidRange)?;
                self.check_range(descriptor.base, size, descriptor.rights, memory)?;
            }
            source_entries.push(descriptor);
        }

        let block_index = self.find_contiguous(count)
            .ok_or(Win16Error::SelectorTableFull)?;
        let generation_count = u64::try_from(count)
            .map_err(|_| Win16Error::GenerationExhausted)?;
        let next_generation = self.next_generation.checked_add(generation_count)
            .ok_or(Win16Error::GenerationExhausted)?;
        let mut references = Vec::new();
        references.try_reserve_exact(count).map_err(|_| Win16Error::OutOfMemory)?;
        for segment in 0..count {
            let index = block_index + segment;
            let generation = self.next_generation + u64::try_from(segment)
                .map_err(|_| Win16Error::GenerationExhausted)?;
            let mut descriptor = source_entries[segment];
            descriptor.generation = generation;
            descriptor.block_index = index;
            descriptor.segment_index = 0;
            descriptor.segment_count = 1;
            descriptor.block_size = if descriptor.present {
                descriptor.limit.checked_add(1).ok_or(Win16Error::InvalidRange)?
            } else {
                0
            };
            descriptor.resize_policy = AllocationResizePolicy::PreserveDescriptorShape;
            self.entries[index] = Some(descriptor);
            references.push(self.reference_for(index, 0).ok_or(Win16Error::StaleSelector)?);
        }
        self.next_generation = next_generation;
        Ok(references)
    }

    /// Allocate `count` adjacent, independently releasable, two-byte data
    /// descriptors, matching the historical KERNEL.206 table shape.
    pub fn alloc_selector_array(
        &mut self,
        count: u16,
        memory: &impl GuestMemory,
    ) -> Result<Vec<SelectorRef>, Win16Error> {
        let count = usize::from(count);
        if count == 0 { return Err(Win16Error::InvalidSize); }
        self.check_range(
            PhysAddr(0), 2, AccessRights::read_write(), memory,
        )?;
        let block_index = self.find_contiguous(count).ok_or(Win16Error::SelectorTableFull)?;
        let generation_count = u64::try_from(count)
            .map_err(|_| Win16Error::GenerationExhausted)?;
        let next_generation = self.next_generation.checked_add(generation_count)
            .ok_or(Win16Error::GenerationExhausted)?;
        let mut references = Vec::new();
        references.try_reserve_exact(count).map_err(|_| Win16Error::OutOfMemory)?;

        let flags = canonical_access_flags(AccessRights::read_write());
        for index in 0..count {
            let slot = block_index + index;
            let raw = u16::try_from(slot.checked_shl(SELECTOR_SHIFT as u32)
                .ok_or(Win16Error::IdentityExhausted)?)
                .map_err(|_| Win16Error::IdentityExhausted)?;
            let generation = self.next_generation + u64::try_from(index)
                .map_err(|_| Win16Error::GenerationExhausted)?;
            self.entries[slot] = Some(Descriptor {
                base: PhysAddr(0),
                limit: 1,
                rights: AccessRights::read_write(),
                access_flags: flags,
                resize_policy: AllocationResizePolicy::PreserveDescriptorShape,
                generation,
                block_index: slot,
                segment_index: 0,
                segment_count: 1,
                block_size: 2,
                present: true,
            });
            references.push(self.reference_for(slot, 0).ok_or(Win16Error::StaleSelector)?);
            debug_assert_eq!(references.last().map(|entry| entry.raw().0), Some(raw));
        }
        self.next_generation = next_generation;
        Ok(references)
    }

    /// Build KERNEL.171's executable alias of one data selector. The alias is
    /// independent and preserves the source's exact one-selector extent.
    pub fn alloc_ds_to_cs_alias(
        &mut self,
        source: SelectorRef,
        memory: &impl GuestMemory,
    ) -> Result<SelectorRef, Win16Error> {
        let descriptor = self.validate(source)?;
        if !descriptor.present { return Err(Win16Error::InvalidSelector); }
        let size = descriptor.limit.checked_add(1).ok_or(Win16Error::InvalidRange)?;
        // Toggling the descriptor type reinterprets the same R/W bit: a
        // writable data segment becomes readable code; read-only data becomes
        // execute-only code.
        let rights = AccessRights::new(descriptor.rights.writable(), false, true);
        let alias = self.alloc_fixed_selector_descriptor(
            descriptor.base, size, rights, memory,
        )?;
        let index = usize::from(alias.raw().0 >> SELECTOR_SHIFT);
        let target = self.entries.get_mut(index).and_then(Option::as_mut)
            .ok_or(Win16Error::StaleSelector)?;
        target.access_flags = descriptor.access_flags ^ 0x0008;
        Ok(alias)
    }

    /// Implements KERNEL.177 by copying the source descriptor's base and
    /// limit to a KERNEL.175-owned destination selector and toggling its
    /// code/data type. An uninitialized AllocSelector(NULL) destination becomes
    /// present here; the destination keeps its selector identity and generation.
    ///
    /// Win16's descriptor type bit also changes how its read/write bit is
    /// interpreted: code readability becomes data writability, and data
    /// writability becomes code readability. This keeps the resulting
    /// descriptor non-writable whenever it is executable.
    pub fn presto_chango_selector(
        &mut self,
        source: SelectorRef,
        destination: SelectorRef,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        let source_descriptor = self.validate(source)?;
        let destination_descriptor = self.validate(destination)?;
        if !source_descriptor.present
            || destination_descriptor.segment_index != 0
            || destination_descriptor.segment_count != 1
            || destination_descriptor.block_index != selector_index(destination.raw)
        {
            return Err(Win16Error::InvalidSelector);
        }
        let rights = if source_descriptor.rights.executable() {
            AccessRights::new(true, source_descriptor.rights.readable(), false)
        } else {
            AccessRights::new(source_descriptor.rights.writable(), false, true)
        };

        let size = source_descriptor.limit.checked_add(1).ok_or(Win16Error::InvalidRange)?;
        let length = usize::try_from(size).map_err(|_| Win16Error::InvalidRange)?;
        // Execute accesses ultimately read bytes from GuestMemory, including
        // execute-only code selectors; validate that backing range regardless
        // of the descriptor's guest-visible read bit.
        memory.validate_read(source_descriptor.base, length)?;
        self.check_range(source_descriptor.base, size, rights, memory)?;

        let destination_index = selector_index(destination.raw);
        let target = self.entries.get_mut(destination_index)
            .and_then(|entry| entry.as_mut())
            .ok_or(Win16Error::StaleSelector)?;
        *target = Descriptor {
            base: source_descriptor.base,
            limit: source_descriptor.limit,
            rights,
            access_flags: source_descriptor.access_flags ^ 0x0008,
            resize_policy: destination_descriptor.resize_policy,
            generation: destination_descriptor.generation,
            block_index: destination_descriptor.block_index,
            segment_index: 0,
            segment_count: 1,
            block_size: size,
            present: true,
        };
        Ok(())
    }

    /// Return the modeled historical Flags1/Flags2 access value.
    pub fn selector_access_rights(&self, reference: SelectorRef) -> Result<u16, Win16Error> {
        Ok(self.validate(reference)?.access_flags)
    }

    /// Set a supported 16-bit readable/writable data or executable code form.
    /// D/B, granularity, conforming, expand-down, and system descriptors are
    /// rejected because the guest selector model cannot preserve their x86
    /// descriptor semantics.
    pub fn set_selector_access_rights(
        &mut self,
        reference: SelectorRef,
        value: u16,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        let descriptor = self.validate(reference)?;
        require_independent_descriptor(descriptor)?;
        // Preserve the architecturally inert AVL bit. L, D/B, granularity,
        // upper descriptor, and system bits cannot be represented by this
        // 16-bit guest range model.
        if value & !0x01ff != 0 { return Err(Win16Error::InvalidRange); }

        let access_type = (value & 0x000f) as u8;
        if access_type & 0x0004 != 0 { return Err(Win16Error::InvalidRange); }
        let executable = access_type & 0x0008 != 0;
        let bit_one = access_type & 0x0002 != 0;
        let rights = if executable {
            AccessRights::new(bit_one, false, true)
        } else {
            AccessRights::new(true, bit_one, false)
        };
        let size = descriptor.limit.checked_add(1).ok_or(Win16Error::InvalidRange)?;
        self.check_range(descriptor.base, size, rights, memory)?;

        let index = usize::from(reference.raw().0 >> SELECTOR_SHIFT);
        let target = self.entries.get_mut(index).and_then(Option::as_mut)
            .ok_or(Win16Error::StaleSelector)?;
        target.rights = rights;
        target.access_flags = 0x00f0 | (value & 0x010f);
        target.present = true;
        target.block_size = size;
        Ok(())
    }

    pub fn set_selector_base(
        &mut self,
        reference: SelectorRef,
        base: PhysAddr,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        let descriptor = self.validate(reference)?;
        require_independent_descriptor(descriptor)?;
        let size = descriptor.limit.checked_add(1).ok_or(Win16Error::InvalidRange)?;
        if descriptor.present {
            self.check_range(base, size, descriptor.rights, memory)?;
        }
        let index = usize::from(reference.raw().0 >> SELECTOR_SHIFT);
        self.entries[index].as_mut().ok_or(Win16Error::StaleSelector)?.base = base;
        Ok(())
    }

    pub fn set_selector_limit(
        &mut self,
        reference: SelectorRef,
        limit: u32,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        let descriptor = self.validate(reference)?;
        require_independent_descriptor(descriptor)?;
        if limit > 0xffff { return Err(Win16Error::InvalidRange); }
        let size = limit.checked_add(1).ok_or(Win16Error::InvalidRange)?;
        if descriptor.present {
            self.check_range(descriptor.base, size, descriptor.rights, memory)?;
        }
        let index = usize::from(reference.raw().0 >> SELECTOR_SHIFT);
        let target = self.entries[index].as_mut().ok_or(Win16Error::StaleSelector)?;
        target.limit = limit;
        target.block_size = size;
        Ok(())
    }
}

fn require_independent_descriptor(descriptor: Descriptor) -> Result<(), Win16Error> {
    if descriptor.segment_index != 0 || descriptor.segment_count != 1 {
        return Err(Win16Error::SelectorBlockInterior);
    }
    Ok(())
}

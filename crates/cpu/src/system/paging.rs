use guest_core::{GuestMemory, LinearAddr, MemoryError, PhysAddr};

use super::{CR0_PG, CR0_WP, CpuFault, CpuSystem};

const ENTRY_PRESENT: u32 = 1 << 0;
const ENTRY_WRITABLE: u32 = 1 << 1;
const ENTRY_USER: u32 = 1 << 2;
const ENTRY_ACCESSED: u32 = 1 << 5;
const ENTRY_DIRTY: u32 = 1 << 6;
const PAGE_FRAME_MASK: u32 = 0xffff_f000;
const PAGE_OFFSET_MASK: u32 = 0x0000_0fff;

/// Access class is supplied by the caller for each linear memory access.
/// i486 32-bit paging has no execute-disable bit, so instruction fetches have
/// the same page permissions as reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageAccess {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TranslationError {
    Fault(CpuFault),
    Memory(MemoryError),
}

impl From<MemoryError> for TranslationError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

#[derive(Clone, Copy, Debug)]
struct EntryUpdate {
    address: PhysAddr,
    updated: u32,
}

impl CpuSystem {
    /// Translate one linear address through the Intel486 two-level 4-KiB
    /// paging format. The directory and table indices are 10 bits each and
    /// the low 12 bits select the byte within the resulting frame.
    /// The entry layout and permission rules follow Intel, *Embedded
    /// Intel486 Processor Family Developer's Manual*, order 273021-001,
    /// §§6.4.2–6.4.3. A general memory crate cannot own guest CR2, CPL/WP
    /// faults, or the read/modify/write side effects in this CPU's checked
    /// GuestMemory contract, so the architecture-specific walk stays here.
    ///
    /// This CPU target has no CR4/PSE or PAE path. Every call walks current
    /// guest tables, so edits become visible immediately. That deliberately
    /// omits hardware TLB stale-translation timing; INVLPG therefore has no
    /// software translation entry to remove.
    ///
    /// A multi-byte access must call this for every covered linear page before
    /// transferring operand bytes. Translation faults update CR2. A physical
    /// guest-memory failure while reading or updating paging structures stays
    /// a typed MemoryError and never masquerades as a guest #PF.
    pub(crate) fn translate_linear(
        &mut self,
        linear: LinearAddr,
        access: PageAccess,
        cpl: u8,
        memory: &mut impl GuestMemory,
    ) -> Result<PhysAddr, TranslationError> {
        let cr3 = self.cr3;
        self.translate_linear_with_cr3(cr3, linear, access, cpl, memory)
    }

    /// Walk a caller-selected i486 page directory while keeping the live
    /// architectural CR3 unchanged. Task-switch planning uses this only for
    /// accesses that occur after the incoming TSS CR3 becomes effective.
    pub(crate) fn translate_linear_with_cr3(
        &mut self,
        cr3: u32,
        linear: LinearAddr,
        access: PageAccess,
        cpl: u8,
        memory: &mut impl GuestMemory,
    ) -> Result<PhysAddr, TranslationError> {
        if cpl > 3 {
            return Err(TranslationError::Fault(CpuFault::general_protection(0)));
        }
        if self.cr0 & CR0_PG == 0 {
            return Ok(PhysAddr(linear.0));
        }

        let directory_index = (linear.0 >> 22) & 0x3ff;
        let directory_address = (cr3 & PAGE_FRAME_MASK)
            .checked_add(directory_index * 4)
            .ok_or(MemoryError::AddressOverflow)?;
        let directory_address = PhysAddr(directory_address);
        let directory_entry = memory.read_u32(directory_address)?;
        if directory_entry & ENTRY_PRESENT == 0 {
            return Err(self.page_fault(linear, access, cpl, false));
        }

        // A present directory entry is consumed before the leaf lookup. The
        // Intel486 walk description sets its accessed bit at this stage, and
        // the IA-32 SDM explicitly requires PDE.A on a protection fault. Keep
        // this physical update distinct so a backend failure remains a typed
        // MemoryError instead of being overwritten by a later guest #PF.
        let mut directory_updates = [None, None];
        let mut directory_update_count = 0;
        Self::queue_update(
            &mut directory_updates,
            &mut directory_update_count,
            directory_address,
            directory_entry,
            directory_entry | ENTRY_ACCESSED,
        );
        Self::commit_updates(memory, &directory_updates[..directory_update_count])?;

        let table_index = (linear.0 >> 12) & 0x3ff;
        let table_entry_address = (directory_entry & PAGE_FRAME_MASK)
            .checked_add(table_index * 4)
            .ok_or(MemoryError::AddressOverflow)?;
        let table_entry_address = PhysAddr(table_entry_address);
        let table_entry = memory.read_u32(table_entry_address)?;
        if table_entry & ENTRY_PRESENT == 0 {
            return Err(self.page_fault(linear, access, cpl, false));
        }

        self.check_permissions(linear, access, cpl, directory_entry, table_entry)?;

        let mut updates = [None, None];
        let mut update_count = 0;
        // Intel486 documents leaf A/D updates on permitted accesses, but does
        // not specify the leaf-A state after a protection fault. Do not claim
        // that model-specific edge: update the PTE only after permissions pass.
        let mut accessed_table_entry = table_entry | ENTRY_ACCESSED;
        if access == PageAccess::Write {
            accessed_table_entry |= ENTRY_DIRTY;
        }
        Self::queue_update(
            &mut updates,
            &mut update_count,
            table_entry_address,
            table_entry,
            accessed_table_entry,
        );
        Self::commit_updates(memory, &updates[..update_count])?;

        Ok(PhysAddr(
            (table_entry & PAGE_FRAME_MASK) | (linear.0 & PAGE_OFFSET_MASK),
        ))
    }

    fn check_permissions(
        &mut self,
        linear: LinearAddr,
        access: PageAccess,
        cpl: u8,
        directory_entry: u32,
        table_entry: u32,
    ) -> Result<(), TranslationError> {
        let user_page = directory_entry & ENTRY_USER != 0 && table_entry & ENTRY_USER != 0;
        let writable_page =
            directory_entry & ENTRY_WRITABLE != 0 && table_entry & ENTRY_WRITABLE != 0;
        let user_violation = cpl == 3 && !user_page;
        let supervisor_write_violation =
            access == PageAccess::Write && cpl < 3 && !writable_page && self.cr0 & CR0_WP != 0;
        let user_write_violation = access == PageAccess::Write && cpl == 3 && !writable_page;
        if user_violation || supervisor_write_violation || user_write_violation {
            return Err(self.page_fault(linear, access, cpl, true));
        }
        Ok(())
    }

    fn page_fault(
        &mut self,
        linear: LinearAddr,
        access: PageAccess,
        cpl: u8,
        protection_violation: bool,
    ) -> TranslationError {
        // Intel486 defines P, W/R and U/S. Bit 3's reserved-bit indicator is
        // a later paging extension and is intentionally not modeled here.
        const PF_PRESENT: u32 = 1 << 0;
        const PF_WRITE: u32 = 1 << 1;
        const PF_USER: u32 = 1 << 2;

        let mut error_code = 0;
        if protection_violation {
            error_code |= PF_PRESENT;
        }
        if access == PageAccess::Write {
            error_code |= PF_WRITE;
        }
        if cpl == 3 {
            error_code |= PF_USER;
        }
        self.cr2 = linear.0;
        TranslationError::Fault(CpuFault::page_fault(linear, error_code))
    }

    fn queue_update(
        updates: &mut [Option<EntryUpdate>; 2],
        update_count: &mut usize,
        address: PhysAddr,
        original: u32,
        updated: u32,
    ) {
        if let Some(existing) = updates[..*update_count]
            .iter_mut()
            .flatten()
            .find(|entry| entry.address == address)
        {
            // PDE/PTE aliases must merge hardware-maintained bits into one
            // update instead of writing twice from the same old word.
            existing.updated |= updated;
        } else if original != updated {
            updates[*update_count] = Some(EntryUpdate { address, updated });
            *update_count += 1;
        }
    }

    fn commit_updates(
        memory: &mut impl GuestMemory,
        updates: &[Option<EntryUpdate>],
    ) -> Result<(), TranslationError> {
        // Preflight the complete one-or-two-entry update set. If a physical
        // backend then fails a transfer, propagate that exact storage fault;
        // do not replace it with a synthetic guest page fault.
        for update in updates.iter().flatten() {
            memory.validate_write(update.address, 4)?;
        }
        for update in updates.iter().flatten() {
            memory.write_u32(update.address, update.updated)?;
        }
        Ok(())
    }
}

//! Real-mode DOS 3.3+ AH=67h: owned per-process handle capacity and storage.
//!
//! Microsoft DOS 4 HANDLE.ASM ($ExtHandle, lines 196–310) clamps to twenty,
//! rejects FFFFh, and allocates a replacement before retiring an old external
//! table, even on shrink. MISC.ASM (lines 346–485) inherits only twenty slots.
//! https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/HANDLE.ASM
//! https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/MISC.ASM

use crate::{DosAction, DosCallAddressSpace, DosCallerId, DosError, DosErrorCode, DosHostError};
use guest_core::{GuestMemory, Registers, real_address};

use super::DosKernel;
use super::sft::{DEFAULT_JFT_LEN, MAX_JFT_LEN, PSP_JFT_COUNT_OFFSET};

const PSP_JFT_INLINE_OFFSET: u16 = 0x18;

impl DosKernel {
    pub(super) fn handle_fits_jft(&self, handle: u16) -> bool {
        handle < self.jft_capacity
    }

    pub(super) fn first_free_handle(&self) -> Option<u16> {
        // Closed standard streams participate in the same lowest-free search.
        (0..self.jft_capacity).find(|handle| !self.handles.contains_key(handle))
    }

    pub(super) fn set_handle_count(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
    ) -> Result<DosAction, DosError> {
        self.block_leases.check_storage_state()?;
        // Windows' SetHandleCount requires its own protected PDB/HFILE owner
        // (SDK KB Q66640). A scalar DOS call must not detach the pinned Win16
        // PDB view or consume the HFILE numbers reserved by WNet. AH=50 also
        // does not install a foreign PSP's handle context in this kernel.
        // https://jeffpar.github.io/kbarchive/kb/066/Q66640/
        if memory.caller_id() != DosCallerId::REAL_MODE
            || self.psp_segment != self.jft_owner_psp
            || regs.bx() > MAX_JFT_LEN
        {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            return Ok(DosAction::Continue);
        }
        self.validate_jft_metadata(memory)?;
        let count = regs.bx().max(DEFAULT_JFT_LEN);
        if count == self.jft_capacity {
            // A prior call may have published this capacity before an
            // independent pin prevented old-table retirement. Retrying that
            // call can finish its owned cleanup without allocating or
            // republishing the current table. Ordinary no-ops write nothing.
            if !self.retired_jft_storage.is_empty() {
                self.release_retired_jft_storage(memory)?;
            }
            Self::success(regs);
            return Ok(DosAction::Continue);
        }
        if self.handles.keys().any(|handle| *handle >= count) {
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        self.validate_system_tables(memory)?;
        let _ = self.mcb_chain(memory)?;
        // Neither publication nor retirement may need host allocation after
        // the first DOS allocation side effect. One slot holds the prepared
        // lease, then the previous current lease after publication succeeds.
        let mut entries = Vec::new();
        if entries.try_reserve_exact(usize::from(count)).is_err()
            || self.retired_jft_storage.try_reserve(1).is_err()
        {
            self.failure(regs, DosHostError::new(DosErrorCode::InsufficientMemory));
            return Ok(DosAction::Continue);
        }
        entries.resize(usize::from(count), 0xff);
        for (handle, index) in self.file_table.live_handles() {
            let Some(slot) = entries.get_mut(usize::from(handle)) else {
                return Err(DosError::HostContractViolation("owned JFT mapping exceeds requested capacity"));
            };
            if !self.handles.contains_key(&handle) {
                return Err(DosError::HostContractViolation("JFT mapping has no live DOS handle"));
            }
            *slot = index;
        }
        if self.handles.len() != self.file_table.live_handles().len() {
            return Err(DosError::HostContractViolation("DOS handle has no SFT mapping"));
        }
        let header_address = real_address(self.jft_owner_psp, PSP_JFT_COUNT_OFFSET);
        memory.validate_write(header_address, 6)?;
        let prepared = count > DEFAULT_JFT_LEN;
        let (segment, offset) = if prepared {
            // Widen before adding fifteen: FFFEh requires 4096 paragraphs.
            let paragraphs = ((u32::from(count) + 15) / 16) as u16;
            let lease = match self.allocate_pinned_block(memory, self.jft_owner_psp, paragraphs) {
                Ok(lease) => lease,
                Err(DosError::HostOperation(error)) if error.code == DosErrorCode::InsufficientMemory => {
                    self.failure(regs, error);
                    return Ok(DosAction::Continue);
                }
                Err(error) => return Err(error),
            };
            let segment = lease.extent().data_segment();
            self.retired_jft_storage.push(lease);
            (segment, 0)
        } else {
            (self.jft_owner_psp, PSP_JFT_INLINE_OFFSET)
        };
        let mut header = [0; 6];
        header[..2].copy_from_slice(&count.to_le_bytes());
        header[2..4].copy_from_slice(&offset.to_le_bytes());
        header[4..6].copy_from_slice(&segment.to_le_bytes());
        let publication = (|| {
            let address = real_address(segment, offset);
            memory.validate_write(address, entries.len())?;
            memory.write(address, &entries)?;
            memory.write(header_address, &header)?;
            Ok::<_, DosError>(())
        })();
        if let Err(error) = publication {
            // The prepared lease stays recorded. A partial backing-store
            // transfer is terminal for every context sharing this DOS arena;
            // never restore a snapshot or turn it into recoverable DOS error 8.
            self.block_leases.poison_on_storage_failure(&error)?;
            return Err(error);
        }
        let replacement = if prepared { self.retired_jft_storage.pop() } else { None };
        if let Some(previous) = std::mem::replace(&mut self.jft_storage, replacement) {
            self.retired_jft_storage.push(previous);
        }
        self.jft_capacity = count;
        self.release_retired_jft_storage(memory)?;
        Self::success(regs);
        Ok(DosAction::Continue)
    }

    fn release_retired_jft_storage(&mut self, memory: &mut impl GuestMemory) -> Result<(), DosError> {
        self.block_leases.check_storage_state()?;
        while let Some(lease) = self.retired_jft_storage.pop() {
            if let Err(error) = self.release_block_lease(memory, &lease, true) {
                self.retired_jft_storage.push(lease);
                return Err(error);
            }
        }
        Ok(())
    }

    /// Retire only storage whose allocation provenance this DOS owner holds.
    /// Run after handles close and before freeing any process MCBs. A busy pin
    /// or non-mutating preflight error retains its lease for a later retry;
    /// uncertain partial storage mutations instead poison the shared arena.
    pub fn release_jft_storage(&mut self, memory: &mut impl GuestMemory) -> Result<(), DosError> {
        self.block_leases.check_storage_state()?;
        self.release_retired_jft_storage(memory)?;
        if let Some(lease) = self.jft_storage.take() {
            if let Err(error) = self.release_block_lease(memory, &lease, true) {
                self.jft_storage = Some(lease);
                return Err(error);
            }
        }
        Ok(())
    }
}

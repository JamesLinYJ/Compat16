use std::collections::BTreeMap;

use crate::{DosAction, DosError, DosErrorCode, DosHostError};
use guest_core::{GuestMemory, Registers, real_address};

use super::state::{DosKernel, Handle, Mcb};
use super::system::{SYSTEM_BYTES, SYSTEM_SEGMENT};

impl DosKernel {
    /// Install the initial process' environment and program blocks as a DOS
    /// MCB chain. The environment header is immediately before
    /// `environment_segment`; the final program block ends at `end_segment`.
    /// Call this after writing the environment and PSP, but before publishing
    /// the List of Lists.
    pub fn initialize_process_arena(
        &mut self,
        memory: &mut impl GuestMemory,
        environment_segment: u16,
        environment_paragraphs: u16,
        end_segment: u16,
    ) -> Result<(), DosError> {
        if self.mcb_head.is_some() || self.system_tables.is_some() {
            return Err(DosError::HostContractViolation(
                "initial DOS process arena was already initialized",
            ));
        }

        let memory_end = memory.len().min(0x000a_0000) / 16;
        let psp = u32::from(self.psp_segment);
        let end = u32::from(end_segment);
        let environment = u32::from(environment_segment);
        let paragraphs = u32::from(environment_paragraphs);
        let Some(environment_mcb) = environment.checked_sub(1) else {
            return Err(DosError::HostContractViolation(
                "environment segment has no preceding MCB",
            ));
        };
        let Some(environment_end) = environment.checked_add(paragraphs) else {
            return Err(DosError::HostContractViolation(
                "environment block segment range overflows",
            ));
        };
        let Some(program_mcb) = psp.checked_sub(1) else {
            return Err(DosError::HostContractViolation(
                "PSP segment has no preceding MCB",
            ));
        };
        let system_end = u32::from(SYSTEM_SEGMENT) + (SYSTEM_BYTES as u32 / 16);

        if environment_paragraphs == 0
            || environment_mcb < system_end
            || environment_end > program_mcb
            || psp >= end
            || end > memory_end
        {
            return Err(DosError::HostContractViolation(
                "initial DOS process arena overlaps reserved memory or exceeds conventional memory",
            ));
        }

        let environment_size = environment_paragraphs;
        let program_size = u16::try_from(end - psp).map_err(|_| {
            DosError::HostContractViolation("initial DOS program block size is not representable")
        })?;
        let mut headers = Vec::with_capacity(3);
        headers.push(Mcb::new(
            environment_mcb as u16,
            b'M',
            self.psp_segment,
            environment_size,
        ));

        if environment_end < program_mcb {
            let free_size = u16::try_from(program_mcb - environment_end - 1).map_err(|_| {
                DosError::HostContractViolation("initial DOS free block size is not representable")
            })?;
            headers.push(Mcb::new(environment_end as u16, b'M', 0, free_size));
        }

        headers.push(Mcb::new(
            program_mcb as u16,
            b'Z',
            self.psp_segment,
            program_size,
        ));

        // Preflight every live header before touching the guest arena. Only
        // publish the chain head after all header writes have succeeded.
        write_mcb_batch(memory, &headers)?;
        self.mcb_head = Some(environment_mcb as u16);
        Ok(())
    }

    pub(super) fn allocate_memory(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) -> Result<DosAction, DosError> {
        let chain = match self.mcb_chain(memory) {
            Ok(chain) => chain,
            Err(DosError::MalformedGuestInput(_) | DosError::InvalidMcbSignature { .. }) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::McbDestroyed));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        // DOS coalesces neighboring free blocks while searching, so an AH=48
        // request can use their combined paragraph count. Keep the guest MCB
        // chain in that canonical form before selecting a block.
        let chain = coalesce_free_mcb_chain(memory, chain)?;
        let requested = regs.bx();
        let largest = chain
            .iter()
            .filter(|mcb| mcb.owner() == 0)
            .map(|mcb| mcb.size())
            .max()
            .unwrap_or(0);
        let Some(index) = chain
            .iter()
            .position(|mcb| mcb.owner() == 0 && requested != 0 && mcb.size() >= requested)
        else {
            regs.set_bx(largest);
            Self::failure(regs, DosHostError::new(DosErrorCode::InsufficientMemory));
            return Ok(DosAction::Continue);
        };
        let mut allocated = chain[index];
        if allocated.size().saturating_sub(requested) >= 2 {
            let next_segment = allocated
                .segment
                .checked_add(requested)
                .and_then(|v| v.checked_add(1))
                .ok_or(DosError::MalformedGuestInput("MCB segment overflow"))?;
            let free = Mcb::new(
                next_segment,
                allocated.kind(),
                0,
                allocated.size() - requested - 1,
            );
            allocated.set_kind(b'M');
            allocated.set_owner(self.psp_segment);
            allocated.set_size(requested);
            write_mcb_pair(memory, allocated, free)?;
        } else {
            allocated.set_owner(self.psp_segment);
            write_mcb(memory, allocated)?;
        }
        regs.set_ax(allocated.segment + 1);
        // DOS returns the actual allocation size in BX only on failure.
        Self::success(regs);
        Ok(DosAction::Continue)
    }

    /// Return the largest currently free conventional-memory block, in
    /// paragraphs. Adjacent free blocks are coalesced first, matching DOS
    /// allocation behavior.
    pub fn largest_free_block(&mut self, memory: &mut impl GuestMemory) -> Result<u16, DosError> {
        let chain = self.mcb_chain(memory)?;
        let chain = coalesce_free_mcb_chain(memory, chain)?;
        Ok(chain
            .iter()
            .filter(|mcb| mcb.owner() == 0)
            .map(|mcb| mcb.size())
            .max()
            .unwrap_or(0))
    }

    /// Allocate a child process block from free conventional memory and mark
    /// its MCB owner as the PSP segment returned to the caller.
    pub fn allocate_child_process_block(
        &mut self,
        memory: &mut impl GuestMemory,
        paragraphs: u16,
    ) -> Result<u16, DosError> {
        if paragraphs == 0 {
            return Err(DosError::HostContractViolation(
                "DOS child process allocation requires a nonzero size",
            ));
        }
        let chain = self.mcb_chain(memory)?;
        let chain = coalesce_free_mcb_chain(memory, chain)?;
        allocate_block_for_owner(memory, &chain, None, paragraphs)?.ok_or_else(|| {
            DosError::HostOperation(DosHostError::new(DosErrorCode::InsufficientMemory))
        })
    }

    /// Allocate an MCB-backed block owned by `owner_psp_segment`, returning
    /// the segment of its first data paragraph. A zero owner or size is not a
    /// valid process allocation.
    pub fn allocate_owned_block(
        &mut self,
        memory: &mut impl GuestMemory,
        owner_psp_segment: u16,
        paragraphs: u16,
    ) -> Result<u16, DosError> {
        if owner_psp_segment == 0 || paragraphs == 0 {
            return Err(DosError::HostContractViolation(
                "DOS process allocation requires a nonzero owner and size",
            ));
        }
        let chain = self.mcb_chain(memory)?;
        let chain = coalesce_free_mcb_chain(memory, chain)?;
        allocate_block_for_owner(memory, &chain, Some(owner_psp_segment), paragraphs)?.ok_or_else(
            || DosError::HostOperation(DosHostError::new(DosErrorCode::InsufficientMemory)),
        )
    }

    /// Free every MCB owned by one DOS process and coalesce adjacent free
    /// blocks. This also releases separately allocated child environments.
    pub fn free_process_blocks(
        &mut self,
        memory: &mut impl GuestMemory,
        owner_psp_segment: u16,
    ) -> Result<(), DosError> {
        if owner_psp_segment == 0 {
            return Err(DosError::HostContractViolation(
                "cannot free DOS blocks owned by the free-memory marker",
            ));
        }
        let mut chain = self.mcb_chain(memory)?;
        let mut changed = Vec::new();
        for mcb in &mut chain {
            if mcb.owner() == owner_psp_segment {
                let data_segment = mcb
                    .segment
                    .checked_add(1)
                    .ok_or(DosError::MalformedGuestInput("MCB data segment overflows"))?;
                if self.block_leases.is_pinned(data_segment, mcb.owner())? {
                    return Err(DosError::HostContractViolation(
                        "process cleanup cannot retire a DOS block with active leases",
                    ));
                }
                mcb.set_owner(0);
                changed.push(*mcb);
            }
        }
        if !changed.is_empty() {
            write_mcb_batch(memory, &changed)?;
            let _ = coalesce_free_mcb_chain(memory, chain)?;
        }
        Ok(())
    }

    /// Free one MCB-backed allocation only when it is still owned by the
    /// requested DOS PSP and has no live DOS block leases. `data_segment` is
    /// the first paragraph returned by `allocate_owned_block`.
    pub fn free_owned_block(
        &mut self,
        memory: &mut impl GuestMemory,
        owner_psp_segment: u16,
        data_segment: u16,
    ) -> Result<bool, DosError> {
        if owner_psp_segment == 0 || data_segment == 0 {
            return Ok(false);
        }
        let Some(mcb_segment) = data_segment.checked_sub(1) else {
            return Ok(false);
        };
        let mut chain = self.mcb_chain(memory)?;
        let Some(index) = chain.iter().position(|mcb| mcb.segment == mcb_segment) else {
            return Ok(false);
        };
        let mcb = chain[index];
        if mcb.segment.checked_add(1) != Some(data_segment) || mcb.owner() != owner_psp_segment {
            return Ok(false);
        }
        if self.block_leases.is_pinned(data_segment, mcb.owner())? {
            return Ok(false);
        }
        chain[index].set_owner(0);
        write_mcb(memory, chain[index])?;
        let _ = coalesce_free_mcb_chain(memory, chain)?;
        Ok(true)
    }

    pub(super) fn free_memory(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) -> Result<DosAction, DosError> {
        let Some(mcb_segment) = regs.es.checked_sub(1) else {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidMemoryBlock));
            return Ok(DosAction::Continue);
        };
        let chain = match self.mcb_chain(memory) {
            Ok(chain) => chain,
            Err(DosError::MalformedGuestInput(_) | DosError::InvalidMcbSignature { .. }) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::McbDestroyed));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        let Some(mut mcb) = chain.iter().find(|mcb| mcb.segment == mcb_segment).copied() else {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidMemoryBlock));
            return Ok(DosAction::Continue);
        };
        if mcb.segment + 1 != regs.es || mcb.owner() != self.psp_segment {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidMemoryBlock));
            return Ok(DosAction::Continue);
        }
        if self.block_leases.is_pinned(regs.es, mcb.owner())? {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidMemoryBlock));
            return Ok(DosAction::Continue);
        }
        mcb.set_owner(0);
        write_mcb(memory, mcb)?;
        self.coalesce_free_mcbs(memory)?;
        Self::success(regs);
        Ok(DosAction::Continue)
    }

    pub(super) fn resize_memory(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) -> Result<DosAction, DosError> {
        let Some(mcb_segment) = regs.es.checked_sub(1) else {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidMemoryBlock));
            return Ok(DosAction::Continue);
        };
        let mut chain = match self.mcb_chain(memory) {
            Ok(chain) => chain,
            Err(DosError::MalformedGuestInput(_) | DosError::InvalidMcbSignature { .. }) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::McbDestroyed));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        let Some(mut index) = chain.iter().position(|mcb| mcb.segment == mcb_segment) else {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidMemoryBlock));
            return Ok(DosAction::Continue);
        };
        let mut block = chain[index];
        if block.segment.checked_add(1) != Some(regs.es) || block.owner() != self.psp_segment {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidMemoryBlock));
            return Ok(DosAction::Continue);
        }
        let requested = regs.bx();
        if !self.block_leases.allows_resize(
            regs.es,
            block.owner(),
            block.size(),
            requested,
        )? {
            regs.set_bx(block.size());
            Self::failure(regs, DosHostError::new(DosErrorCode::InsufficientMemory));
            return Ok(DosAction::Continue);
        }
        if requested == 0 {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidMemoryBlock));
            return Ok(DosAction::Continue);
        }
        if requested > block.size() {
            // DOS joins adjacent free MCBs before growing a block. This also
            // means an unsuccessful growth still enlarges the block to the
            // largest available size; callers receive that size in BX and may
            // legally use the partial extension. See FreeDOS memmgr.c's
            // DosMemChange/joinMCBs and the MS-DOS 4.0 Programmer's Reference,
            // INT 21h Function 4AH.
            chain = coalesce_free_mcb_chain(memory, chain)?;
            let Some(new_index) = chain.iter().position(|mcb| mcb.segment == mcb_segment) else {
                return Err(DosError::MalformedGuestInput(
                    "MCB disappeared while coalescing adjacent free blocks",
                ));
            };
            index = new_index;
            block = chain[index];
        }
        let old_size = block.size();
        if requested == old_size {
            Self::success(regs);
            return Ok(DosAction::Continue);
        }

        if requested < old_size {
            let free_segment = block
                .segment
                .checked_add(requested)
                .and_then(|v| v.checked_add(1))
                .ok_or(DosError::MalformedGuestInput("MCB segment overflow"))?;
            let free = Mcb::new(free_segment, block.kind(), 0, old_size - requested - 1);
            block.set_kind(b'M');
            block.set_size(requested);
            write_mcb_pair(memory, block, free)?;
            self.coalesce_free_mcbs(memory)?;
            Self::success(regs);
            return Ok(DosAction::Continue);
        }

        let adjacent = chain
            .get(index + 1)
            .copied()
            .filter(|next| block.kind() == b'M' && next.owner() == 0);
        let available = adjacent
            .map(|next| old_size.saturating_add(1).saturating_add(next.size()))
            .unwrap_or(old_size);
        if requested > available {
            if let Some(next) = adjacent {
                block.set_kind(next.kind());
                block.set_size(available);
                write_mcb(memory, block)?;
            }
            regs.set_bx(available);
            Self::failure(regs, DosHostError::new(DosErrorCode::InsufficientMemory));
            return Ok(DosAction::Continue);
        }
        let next = adjacent.ok_or(DosError::MalformedGuestInput(
            "missing adjacent MCB during resize",
        ))?;
        let remaining = available - requested;
        if remaining == 0 {
            block.set_kind(next.kind());
            block.set_size(available);
            write_mcb(memory, block)?;
        } else {
            let free_segment = block
                .segment
                .checked_add(requested)
                .and_then(|v| v.checked_add(1))
                .ok_or(DosError::MalformedGuestInput("MCB segment overflow"))?;
            let free = Mcb::new(free_segment, next.kind(), 0, remaining - 1);
            block.set_kind(b'M');
            block.set_size(requested);
            write_mcb_pair(memory, block, free)?;
            self.coalesce_free_mcbs(memory)?;
        }
        Self::success(regs);
        Ok(DosAction::Continue)
    }

    pub(super) fn mcb_chain(
        &mut self,
        memory: &mut impl GuestMemory,
    ) -> Result<Vec<Mcb>, DosError> {
        let head = if let Some(head) = self.mcb_head {
            head
        } else {
            let Some(head) = self.psp_segment.checked_sub(1) else {
                return Err(DosError::MalformedGuestInput(
                    "PSP segment has no preceding MCB",
                ));
            };
            let marker = memory.read_u8(real_address(head, 0))?;
            if marker == b'M' || marker == b'Z' {
                self.mcb_head = Some(head);
                head
            } else {
                self.initialize_initial_mcb(memory, head)?;
                self.mcb_head = Some(head);
                head
            }
        };
        let end_segment = (memory.len().min(0x000a_0000) / 16) as u16;
        let mut chain = Vec::new();
        let mut segment = head;
        let mut previous = None;
        for _ in 0..end_segment {
            if segment >= end_segment {
                return Err(DosError::MalformedGuestInput(
                    "MCB is outside conventional memory",
                ));
            }
            let mcb = read_mcb(memory, segment)?;
            if mcb.kind() != b'M' && mcb.kind() != b'Z' {
                return Err(DosError::InvalidMcbSignature {
                    segment,
                    chain_head: head,
                    psp_segment: self.psp_segment,
                    previous,
                    header: mcb.raw,
                });
            }
            let next = u32::from(segment) + 1 + u32::from(mcb.size());
            if next > u32::from(end_segment) {
                return Err(DosError::MalformedGuestInput(
                    "MCB size exceeds conventional memory",
                ));
            }
            chain.push(mcb);
            if mcb.kind() == b'Z' {
                // All callers pass through this point before allocating,
                // freeing, coalescing, or performing INT 21h side effects.
                self.block_leases.validate(&chain)?;
                return Ok(chain);
            }
            if next == u32::from(segment) {
                return Err(DosError::MalformedGuestInput("MCB chain did not advance"));
            }
            previous = Some((segment, mcb.size()));
            segment = next as u16;
        }
        Err(DosError::MalformedGuestInput("unterminated MCB chain"))
    }

    pub(super) fn initialize_initial_mcb(
        &mut self,
        memory: &mut impl GuestMemory,
        segment: u16,
    ) -> Result<(), DosError> {
        let psp = u32::from(self.psp_segment);
        let end = memory.len().min(0x000a_0000) / 16;
        if psp == 0 || psp >= end {
            return Err(DosError::MalformedGuestInput(
                "PSP is outside conventional memory",
            ));
        }
        let declared_top = memory.read_u16(real_address(self.psp_segment, 2))?;
        let top = if u32::from(declared_top) > psp && u32::from(declared_top) <= end {
            u32::from(declared_top)
        } else {
            end
        };
        let size = u16::try_from(top - psp)
            .map_err(|_| DosError::MalformedGuestInput("initial MCB size is invalid"))?;
        let mcb = Mcb::new(segment, b'Z', self.psp_segment, size);
        write_mcb(memory, mcb)
    }

    pub(super) fn coalesce_free_mcbs(
        &mut self,
        memory: &mut impl GuestMemory,
    ) -> Result<(), DosError> {
        let chain = self.mcb_chain(memory)?;
        let _ = coalesce_free_mcb_chain(memory, chain)?;
        Ok(())
    }
}

pub(super) fn coalesce_free_mcb_chain(
    memory: &mut impl GuestMemory,
    mut chain: Vec<Mcb>,
) -> Result<Vec<Mcb>, DosError> {
    // FreeDOS kernel/memmgr.c's DosMemAlloc joins adjacent free MCBs while
    // searching, before testing whether a request fits.
    let mut index = 0;
    while index + 1 < chain.len() {
        if chain[index].owner() == 0 && chain[index + 1].owner() == 0 {
            let next = chain[index + 1];
            let mut merged = chain[index];
            let merged_size = merged
                .size()
                .checked_add(1)
                .and_then(|size| size.checked_add(next.size()))
                .ok_or(DosError::MalformedGuestInput(
                    "MCB size overflow while coalescing free blocks",
                ))?;
            merged.set_kind(next.kind());
            merged.set_size(merged_size);
            // `next` is no longer a live chain node; its bytes are inside the
            // combined free block and need not be rewritten.
            write_mcb(memory, merged)?;
            chain[index] = merged;
            chain.remove(index + 1);
        } else {
            index += 1;
        }
    }
    Ok(chain)
}

pub(super) fn allocate_block_for_owner(
    memory: &mut impl GuestMemory,
    chain: &[Mcb],
    requested_owner: Option<u16>,
    requested: u16,
) -> Result<Option<u16>, DosError> {
    let Some(index) = chain
        .iter()
        .position(|mcb| mcb.owner() == 0 && mcb.size() >= requested)
    else {
        return Ok(None);
    };

    let mut allocated = chain[index];
    let psp_segment = allocated
        .segment
        .checked_add(1)
        .ok_or(DosError::MalformedGuestInput(
            "allocated DOS PSP segment overflows",
        ))?;
    let owner_psp_segment = requested_owner.unwrap_or(psp_segment);
    let remaining = allocated.size() - requested;
    if remaining >= 2 {
        let free_segment = allocated
            .segment
            .checked_add(requested)
            .and_then(|segment| segment.checked_add(1))
            .ok_or(DosError::MalformedGuestInput(
                "allocated DOS MCB segment overflows",
            ))?;
        let free = Mcb::new(free_segment, allocated.kind(), 0, remaining - 1);
        allocated.set_kind(b'M');
        allocated.set_owner(owner_psp_segment);
        allocated.set_size(requested);
        write_mcb_pair(memory, allocated, free)?;
    } else {
        allocated.set_owner(owner_psp_segment);
        write_mcb(memory, allocated)?;
    }
    Ok(Some(psp_segment))
}

pub(super) fn first_free_handle(handles: &BTreeMap<u16, Handle>) -> Option<u16> {
    // Scan the actual default JFT, including closed standard-stream slots.
    // FreeDOS kernel/dosfns.c get_free_hndl uses the same lowest-free rule.
    (0..super::sft::DEFAULT_JFT_LEN).find(|id| !handles.contains_key(id))
}

pub(super) fn read_mcb(memory: &impl GuestMemory, segment: u16) -> Result<Mcb, DosError> {
    let mut raw = [0; 16];
    memory.read(real_address(segment, 0), &mut raw)?;
    Ok(Mcb { segment, raw })
}

pub(super) fn write_mcb(memory: &mut impl GuestMemory, mcb: Mcb) -> Result<(), DosError> {
    let address = real_address(mcb.segment, 0);
    memory.validate_write(address, mcb.raw.len())?;
    memory.write(address, &mcb.raw)?;
    Ok(())
}

pub(super) fn write_mcb_pair(
    memory: &mut impl GuestMemory,
    first: Mcb,
    second: Mcb,
) -> Result<(), DosError> {
    write_mcb_batch(memory, &[first, second])
}

pub(super) fn write_mcb_batch(memory: &mut impl GuestMemory, mcbs: &[Mcb]) -> Result<(), DosError> {
    // Preflight every header before changing any so read-only/out-of-range
    // guest memory cannot leave a partially rewritten MCB chain.
    for mcb in mcbs {
        memory.validate_write(real_address(mcb.segment, 0), mcb.raw.len())?;
    }
    for mcb in mcbs {
        memory.write(real_address(mcb.segment, 0), &mcb.raw)?;
    }
    Ok(())
}

pub(super) fn read_dos_c_string(
    memory: &mut impl crate::DosCallAddressSpace,
    segment_or_selector: u16,
    offset: u16,
) -> Result<Vec<u8>, DosError> {
    let pointer = memory.resolve_caller_pointer(segment_or_selector, offset)?;
    memory.read_caller_terminated(pointer, 0, 260, crate::DosSpanPolicy::Linear)
}

//! Read-only DOS allocation provenance for protected-mode adapters.
//!
//! This view exposes an owned DOS block's paragraph extent. It never treats a
//! Win16 selector as a DOS paragraph or interprets selector values as DOS
//! addresses.

use crate::DosError;
use guest_core::{GuestMemory, PhysAddr};

use super::state::DosKernel;

/// The DOS-owned allocation extent beginning at a block's data segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DosBlockExtent {
    data_segment: u16,
    owner_psp_segment: u16,
    paragraphs: u16,
}

impl DosBlockExtent {
    /// Segment immediately after the allocation's MCB header.
    pub fn data_segment(self) -> u16 {
        self.data_segment
    }

    /// PSP segment recorded as the owner of this live allocation.
    pub fn owner_psp_segment(self) -> u16 {
        self.owner_psp_segment
    }

    /// Number of DOS paragraphs in the allocation.
    pub fn paragraphs(self) -> u16 {
        self.paragraphs
    }

    /// Checked real-mode guest base address of the allocation data.
    pub fn guest_base(self) -> Option<PhysAddr> {
        u32::from(self.data_segment)
            .checked_mul(16)
            .map(PhysAddr)
    }

    /// Checked byte length represented by the DOS paragraph count.
    pub fn byte_length(self) -> Option<usize> {
        usize::from(self.paragraphs).checked_mul(16)
    }
}

impl DosKernel {
    /// Find the live DOS allocation containing a complete guest byte range.
    ///
    /// The owner and paragraph extent come from the validated MCB chain. A
    /// numeric segment or an overlapping unowned block is not provenance.
    pub fn owned_block_containing_range(
        &mut self,
        memory: &mut impl GuestMemory,
        base: PhysAddr,
        byte_length: usize,
    ) -> Result<Option<DosBlockExtent>, DosError> {
        if self.mcb_head.is_none() {
            return Err(DosError::HostContractViolation(
                "DOS MCB chain has not been initialized",
            ));
        }
        let Some(length) = u32::try_from(byte_length).ok().filter(|length| *length != 0) else {
            return Ok(None);
        };
        let Some(end) = base.0.checked_add(length) else {
            return Ok(None);
        };
        let chain = self.mcb_chain(memory)?;
        Ok(chain.into_iter().find_map(|mcb| {
            let data_segment = mcb.segment.checked_add(1)?;
            let owner_psp_segment = mcb.owner();
            if owner_psp_segment == 0 {
                return None;
            }
            let extent = DosBlockExtent {
                data_segment,
                owner_psp_segment,
                paragraphs: mcb.size(),
            };
            let start = extent.guest_base()?.0;
            let length = u32::try_from(extent.byte_length()?).ok()?;
            let block_end = start.checked_add(length)?;
            (base.0 >= start && end <= block_end).then_some(extent)
        }))
    }

    /// Find a live DOS MCB allocation by its data segment and PSP owner.
    ///
    /// The complete existing MCB walker validates the chain before a match is
    /// returned. This query does not initialize or repair the chain and does
    /// not write guest memory.
    pub fn owned_block_extent(
        &mut self,
        memory: &mut impl GuestMemory,
        data_segment: u16,
        owner_psp_segment: u16,
    ) -> Result<Option<DosBlockExtent>, DosError> {
        if self.mcb_head.is_none() {
            return Err(DosError::HostContractViolation(
                "DOS MCB chain has not been initialized",
            ));
        }

        // With an initialized head, mcb_chain performs full structural
        // validation without entering its lazy initial-MCB path.
        let chain = self.mcb_chain(memory)?;
        if data_segment == 0 || owner_psp_segment == 0 {
            return Ok(None);
        }

        let extent = chain.into_iter().find_map(|mcb| {
            let live_data_segment = mcb.segment.checked_add(1)?;
            let owner = mcb.owner();
            (live_data_segment == data_segment && owner != 0 && owner == owner_psp_segment)
                .then_some(DosBlockExtent {
                    data_segment,
                    owner_psp_segment,
                    paragraphs: mcb.size(),
                })
        });
        Ok(extent)
    }
}

//! DOS 6300h returns a readable guest table, including for SBCS code pages.
use crate::caller_address_space::{DosCallAddressSpace, DosPointerAccess};
use crate::{DosAction, DosError, DosErrorCode, DosHost, DosHostError};
use guest_core::{GuestMemory, Registers, real_address};
use text_codec::CodePage;

use super::DosKernel;

/// Byte pairs, inclusive start/end, followed by a zero pair. Unlike the
/// extended-country table record, DS:SI points directly at the first pair.
pub fn dbcs_lead_byte_table(code_page: CodePage) -> Vec<u8> {
    let mut table = Vec::new();
    for &(first, last) in code_page.dbcs_lead_byte_ranges() {
        table.extend_from_slice(&[first, last]);
    }
    table.extend_from_slice(&[0, 0]);
    table
}

impl DosKernel {
    /// Runtime registers immutable, process-owned guest bytes. No caller or
    /// host address is accepted as the returned DOS pointer.
    pub fn set_dbcs_table_address(
        &mut self,
        code_page: CodePage,
        segment: u16,
        offset: u16,
    ) -> Result<(), DosError> {
        if usize::from(offset) + dbcs_lead_byte_table(code_page).len() > 0x1_0000 {
            return Err(DosError::HostContractViolation(
                "DOS DBCS table crosses its registered 64 KiB segment",
            ));
        }
        self.dbcs_table_addresses
            .insert(code_page.number(), (segment, offset));
        Ok(())
    }

    pub(super) fn extended_code_system(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &impl DosHost,
    ) -> Result<DosAction, DosError> {
        if regs.al() != 0 {
            // Interim console mode needs its own console/PSP contract. Keep
            // reporting unsupported selectors rather than inventing that state.
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            return Ok(DosAction::Continue);
        }
        let code_page = host.guest_code_page();
        let (segment, offset) = self
            .dbcs_table_addresses
            .get(&code_page.number())
            .copied()
            .ok_or(DosError::HostContractViolation(
                "INT 21h/6300h called before runtime installed its guest DBCS ROM",
            ))?;
        let expected = dbcs_lead_byte_table(code_page);
        let address = real_address(segment, offset);
        let table_error = |source| DosError::HostMemoryContractViolation {
            detail: "registered DOS DBCS ROM is inaccessible",
            source,
        };
        memory
            .validate_read(address, expected.len())
            .map_err(table_error)?;
        let mut actual = vec![0; expected.len()];
        memory.read(address, &mut actual).map_err(table_error)?;
        if actual != expected {
            return Err(DosError::HostContractViolation(
                "registered DOS DBCS ROM does not match the selected guest codec",
            ));
        }
        let pointer =
            memory.expose_dos_pointer(segment, offset, expected.len(), DosPointerAccess::Read)?;
        let (segment_or_selector, offset) = pointer.words();
        // MS-DOS GETSET.ASM $ECS_call/get_lbt preserves AX and returns DS:SI;
        // protected callers receive their owned read-only selector alias.
        regs.ds = segment_or_selector;
        regs.set_si(offset);
        Self::success(regs);
        Ok(DosAction::Continue)
    }
}

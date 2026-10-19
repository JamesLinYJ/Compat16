//! DOS extended country information services and their guest-visible tables.
use crate::caller_address_space::{DosCallAddressSpace, DosPointerAccess, DosSpanPolicy};
use crate::{DosAction, DosError, DosErrorCode, DosHost, DosHostError};
use guest_core::{GuestMemory, Registers, real_address};
use text_codec::CodePage;

use super::DosKernel;
mod country;
use country::CountryProfile;

const COLLATING_TABLE_LEN: usize = 258;
const UPPERCASE_TABLE_LEN: usize = 130;
const COUNTRY_CINFO_LEN: usize = 38;
const COUNTRY_INFO_LEN: usize = 41;
const LEGACY_COUNTRY_INFO_LEN: usize = 24;

/// DOS table records share their data with filename normalization.
/// The text layer selects the supported profile; DOS owns its guest pointers.
pub const fn collating_table(code_page: CodePage) -> Option<&'static [u8; COLLATING_TABLE_LEN]> {
    match text_codec::dos_code_page_tables(code_page) {
        Some(tables) => Some(tables.collation_record()),
        None => None,
    }
}

pub const fn upper_case_table(code_page: CodePage) -> Option<&'static [u8; UPPERCASE_TABLE_LEN]> {
    match text_codec::dos_code_page_tables(code_page) {
        Some(tables) => Some(tables.uppercase_record()),
        None => None,
    }
}

impl DosKernel {
    /// Register a guest far pointer to a collation table installed in guest ROM.
    /// The table is not copied here: runtime owns its ROM bytes, while this
    /// kernel stores only the guest segment:offset required by INT 21h/6506h.
    ///
    /// The offset plus the full 258-byte table must fit in one 64 KiB segment.
    pub fn set_collating_table_address(
        &mut self,
        code_page: CodePage,
        segment: u16,
        offset: u16,
    ) -> Result<(), DosError> {
        if collating_table(code_page).is_none() {
            return Err(DosError::HostContractViolation(
                "runtime registered a DOS collation table for an unsupported code page",
            ));
        }
        if usize::from(offset) + COLLATING_TABLE_LEN > 0x1_0000 {
            return Err(DosError::HostContractViolation(
                "DOS collation table crosses its registered 64 KiB segment",
            ));
        }
        self.collating_table_addresses
            .insert(code_page.number(), (segment, offset));
        Ok(())
    }

    /// Register a guest far pointer to the DOS uppercase table installed in
    /// guest ROM. Both INT 21h/6502h and /6504h use the selected profile.
    pub fn set_uppercase_table_address(
        &mut self,
        code_page: CodePage,
        segment: u16,
        offset: u16,
    ) -> Result<(), DosError> {
        if upper_case_table(code_page).is_none() {
            return Err(DosError::HostContractViolation(
                "runtime registered a DOS uppercase table for an unsupported code page",
            ));
        }
        if usize::from(offset) + UPPERCASE_TABLE_LEN > 0x1_0000 {
            return Err(DosError::HostContractViolation(
                "DOS uppercase table crosses its registered 64 KiB segment",
            ));
        }
        self.uppercase_table_addresses
            .insert(code_page.number(), (segment, offset));
        Ok(())
    }

    /// Register a guest far pointer to the real-mode case-mapping callback
    /// installed in guest ROM. The pointer is returned inside country info;
    /// it is never a host function pointer.
    pub fn set_case_map_address(
        &mut self,
        code_page: CodePage,
        segment: u16,
        offset: u16,
    ) -> Result<(), DosError> {
        if upper_case_table(code_page).is_none() {
            return Err(DosError::HostContractViolation(
                "runtime registered a DOS case-map callback for an unsupported code page",
            ));
        }
        self.case_map_addresses
            .insert(code_page.number(), (segment, offset));
        Ok(())
    }

    pub(super) fn extended_country_information(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        match regs.al() {
            0x01 => self.get_extended_country_record(regs, memory, host),
            0x02 => self.get_extended_country_table(regs, memory, host, 0x02),
            0x04 => self.get_extended_country_table(regs, memory, host, 0x04),
            0x06 => self.get_extended_country_table(regs, memory, host, 0x06),
            _ => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
                Ok(DosAction::Continue)
            }
        }
    }

    fn get_extended_country_record(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &impl DosHost,
    ) -> Result<DosAction, DosError> {
        let requested = usize::from(regs.cx());
        if requested < 5 {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            return Ok(DosAction::Continue);
        }
        let Some(profile) = Self::requested_profile(regs, host) else {
            return self.country_not_found(regs);
        };
        let code_page = profile.page;
        let returned = requested.min(COUNTRY_INFO_LEN);
        let destination = memory.resolve_caller_pointer(regs.es, regs.di())?;
        memory.validate_caller_range(
            destination,
            0,
            returned,
            DosPointerAccess::Write,
            DosSpanPolicy::OffsetWrap,
        )?;
        let (case_segment, case_offset) = self.case_map_address(code_page)?;
        self.validate_registered_case_map(memory, case_segment, case_offset)?;
        let (case_segment, case_offset) = if returned > 25 {
            // The one-byte span identifies the callback entry; success also
            // requires the runtime's real executable view or call gate.
            memory
                .expose_dos_pointer(case_segment, case_offset, 1, DosPointerAccess::Execute)?
                .words()
        } else {
            (case_segment, case_offset)
        };
        let cinfo = profile.cinfo(case_segment, case_offset);

        let size = (returned - 3).min(COUNTRY_CINFO_LEN);
        let mut record = [0; COUNTRY_INFO_LEN];
        record[0] = 0x01;
        record[1..3].copy_from_slice(&(size as u16).to_le_bytes());
        record[3..].copy_from_slice(&cinfo);
        Self::write_segmented(memory, regs.es, regs.di(), &record[..returned])?;

        regs.set_cx(returned as u16);
        regs.set_ax(code_page.number());
        Self::success(regs);
        Ok(DosAction::Continue)
    }

    fn get_extended_country_table(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &impl DosHost,
        info_id: u8,
    ) -> Result<DosAction, DosError> {
        if regs.cx() < 5 {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            return Ok(DosAction::Continue);
        }
        let Some(profile) = Self::requested_profile(regs, host) else {
            return self.country_not_found(regs);
        };
        let code_page = profile.page;
        let destination = memory.resolve_caller_pointer(regs.es, regs.di())?;
        memory.validate_caller_range(
            destination,
            0,
            5,
            DosPointerAccess::Write,
            DosSpanPolicy::OffsetWrap,
        )?;
        let (table_segment, table_offset) = match info_id {
            0x02 | 0x04 => self.uppercase_table_address(code_page)?,
            0x06 => self.collating_table_address(code_page)?,
            _ => unreachable!("only supported table IDs reach this helper"),
        };
        match info_id {
            0x02 | 0x04 => {
                self.validate_registered_uppercase_table(memory, table_segment, table_offset)?
            }
            0x06 => {
                self.validate_registered_collating_table(memory, table_segment, table_offset)?
            }
            _ => unreachable!("only supported table IDs reach this helper"),
        }

        let table_length = match info_id {
            0x02 | 0x04 => UPPERCASE_TABLE_LEN,
            0x06 => COLLATING_TABLE_LEN,
            _ => unreachable!("only supported table IDs reach this helper"),
        };
        let table = memory.expose_dos_pointer(
            table_segment,
            table_offset,
            table_length,
            DosPointerAccess::Read,
        )?;
        let (table_segment, table_offset) = table.words();

        let descriptor = [
            info_id,
            table_offset as u8,
            (table_offset >> 8) as u8,
            table_segment as u8,
            (table_segment >> 8) as u8,
        ];
        Self::write_segmented(memory, regs.es, regs.di(), &descriptor)?;
        regs.set_cx(5);
        regs.set_ax(code_page.number());
        Self::success(regs);
        Ok(DosAction::Continue)
    }

    pub(super) fn get_set_country_data(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &impl DosHost,
    ) -> Result<DosAction, DosError> {
        // MS-DOS uses DX=FFFFh to select the set-country operation. This DOS
        // core has no country-switch service, so report the documented invalid
        // country code and leave guest memory untouched.
        if regs.dx() == u16::MAX {
            return self.country_not_found(regs);
        }

        let current = CountryProfile::current(host.guest_code_page());
        let country = match regs.al() {
            0x00 => current.country,
            0x01..=0xfe => u16::from(regs.al()),
            0xff => regs.bx(),
        };
        let Some(profile) = CountryProfile::requested(country, current.page) else {
            return self.country_not_found(regs);
        };
        let (case_segment, case_offset) = self.case_map_address(profile.page)?;
        self.validate_registered_case_map(memory, case_segment, case_offset)?;
        let destination = memory.resolve_caller_pointer(regs.ds, regs.dx())?;
        memory.validate_caller_range(
            destination,
            0,
            LEGACY_COUNTRY_INFO_LEN,
            DosPointerAccess::Write,
            DosSpanPolicy::OffsetWrap,
        )?;
        // The one-byte span identifies the callback entry; success also
        // requires a real executable view or ABI-correct call gate.
        let case_map =
            memory.expose_dos_pointer(case_segment, case_offset, 1, DosPointerAccess::Execute)?;
        let (case_segment, case_offset) = case_map.words();
        let cinfo = profile.cinfo(case_segment, case_offset);
        // DOS 4's actual GETSET.ASM copies OLD_COUNTRY_SIZE = 24 bytes from
        // ccDFormat. The documented 32-byte caller buffer's final eight bytes
        // are therefore deliberately left unchanged.
        Self::write_segmented(
            memory,
            regs.ds,
            regs.dx(),
            &cinfo[4..4 + LEGACY_COUNTRY_INFO_LEN],
        )?;
        regs.set_ax(profile.country);
        regs.set_bx(profile.country);
        Self::success(regs);
        Ok(DosAction::Continue)
    }

    fn requested_profile(regs: &Registers, host: &impl DosHost) -> Option<CountryProfile> {
        let current = CountryProfile::current(host.guest_code_page());
        let country = if regs.dx() == u16::MAX { current.country } else { regs.dx() };
        let page = if regs.bx() == u16::MAX { current.page }
            else { CodePage::try_from(regs.bx()).ok()? };
        CountryProfile::requested(country, page)
    }

    fn collating_table_address(&self, code_page: CodePage) -> Result<(u16, u16), DosError> {
        self.collating_table_addresses
            .get(&code_page.number())
            .copied()
            .ok_or(DosError::HostContractViolation(
                "INT 21h/6506h called before the runtime installed its guest collation ROM",
            ))
    }

    fn uppercase_table_address(&self, code_page: CodePage) -> Result<(u16, u16), DosError> {
        self.uppercase_table_addresses.get(&code_page.number()).copied().ok_or(
            DosError::HostContractViolation(
                "INT 21h/6502h or /6504h called before the runtime installed its guest uppercase ROM",
            ),
        )
    }

    fn case_map_address(&self, code_page: CodePage) -> Result<(u16, u16), DosError> {
        self.case_map_addresses.get(&code_page.number()).copied().ok_or(
            DosError::HostContractViolation(
                "country information requested before the runtime installed its guest case-map routine",
            ),
        )
    }

    fn validate_registered_collating_table(
        &self,
        memory: &impl GuestMemory,
        segment: u16,
        offset: u16,
    ) -> Result<(), DosError> {
        let address = real_address(segment, offset);
        let table_error = |source| DosError::HostMemoryContractViolation {
            detail: "registered DOS collation ROM is inaccessible",
            source,
        };
        memory
            .validate_read(address, COLLATING_TABLE_LEN)
            .map_err(table_error)?;
        if memory.read_u16(address).map_err(table_error)? != 0x0100 {
            return Err(DosError::HostContractViolation(
                "registered DOS collation ROM has an unexpected table length",
            ));
        }
        Ok(())
    }

    fn validate_registered_uppercase_table(
        &self,
        memory: &impl GuestMemory,
        segment: u16,
        offset: u16,
    ) -> Result<(), DosError> {
        let address = real_address(segment, offset);
        let table_error = |source| DosError::HostMemoryContractViolation {
            detail: "registered DOS uppercase ROM is inaccessible",
            source,
        };
        memory
            .validate_read(address, UPPERCASE_TABLE_LEN)
            .map_err(table_error)?;
        if memory.read_u16(address).map_err(table_error)? != 0x0080 {
            return Err(DosError::HostContractViolation(
                "registered DOS uppercase ROM has an unexpected table length",
            ));
        }
        Ok(())
    }

    fn validate_registered_case_map(
        &self,
        memory: &impl GuestMemory,
        segment: u16,
        offset: u16,
    ) -> Result<(), DosError> {
        let address = real_address(segment, offset);
        memory
            .validate_read(address, 1)
            .map_err(|source| DosError::HostMemoryContractViolation {
                detail: "registered DOS case-map ROM is inaccessible",
                source,
            })
    }

    fn write_segmented(
        memory: &mut impl DosCallAddressSpace,
        segment: u16,
        offset: u16,
        bytes: &[u8],
    ) -> Result<(), DosError> {
        let pointer = memory.resolve_caller_pointer(segment, offset)?;
        memory.write_caller_range(pointer, 0, bytes, DosSpanPolicy::OffsetWrap)
    }

    fn country_not_found(&mut self, regs: &mut Registers) -> Result<DosAction, DosError> {
        // DOS documents AX=2 when no country/code-page table matches.
        self.failure(regs, DosHostError::new(DosErrorCode::FileNotFound));
        Ok(DosAction::Continue)
    }
}

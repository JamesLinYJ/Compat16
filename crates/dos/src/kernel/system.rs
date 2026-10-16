//! DOS List of Lists and the guest-resident system-table block.
//!
//! The block is kept in simulated low memory for the life of the DOS runtime.
//! Far pointers stored here always address that guest RAM; they are never Rust
//! pointers or host handles.

use crate::{DosAction, DosError, DosHost};
use guest_core::{GuestMemory, Registers, real_address};
use super::version::DOS_BOOT_DRIVE;

// These List-of-Lists field offsets follow the packed DOS_LISTOFLISTS in a
// read-only legacy reference (`krnl386/dosdev.c`, InitListOfLists) and were
// cross-checked against FreeDOS `hdr/lol.h`. They are DOS ABI layout,
// not offsets chosen by this runtime.
//
// In contrast, 0800:0000 (physical 8000h) and the 7000h-byte reservation are
// runtime placement policy. The runtime reserves physical 8000h..F000h in its
// guest RAM, outside IVT/BDA memory and before allocating environment/program
// state. DOS does not require the system block to live at this address.
pub const SYSTEM_SEGMENT: u16 = 0x0800;
pub const SYSTEM_BYTES: usize = 0x7000;
pub(super) const LOL_OFFSET: u16 = 0x0018;
pub(super) const SFT_OFFSET: u16 = 0x0200;
pub(super) const SFT_HEADER_BYTES: usize = 6;
// A JFT byte can index 0..254; FF is the closed-handle marker.
pub(super) const SFT_ENTRY_COUNT: usize = u8::MAX as usize;
// FreeDOS hdr/sft.h, matching the DOS 4+ SF.INC layout.
pub(super) const SFT_ENTRY_BYTES: usize = 59;
const SFT_TABLE_BYTES: usize = SFT_HEADER_BYTES + SFT_ENTRY_COUNT * SFT_ENTRY_BYTES;
pub(super) const CDS_OFFSET: u16 = 0x4000;
const CDS_ENTRY_COUNT: usize = 26;
const CDS_ENTRY_BYTES: usize = 88;
pub(super) const CON_HEADER_OFFSET: u16 = 0x0080;

const LOL_FIRST_MCB_OFFSET: u16 = LOL_OFFSET - 2;
const LOL_DPB_OFFSET: u16 = LOL_OFFSET;
const LOL_SFT_OFFSET: u16 = LOL_OFFSET + 0x04;
const LOL_CLOCK_OFFSET: u16 = LOL_OFFSET + 0x08;
const LOL_CON_OFFSET: u16 = LOL_OFFSET + 0x0c;
const LOL_MAX_SECTOR_OFFSET: u16 = LOL_OFFSET + 0x10;
const LOL_DISK_BUFFER_OFFSET: u16 = LOL_OFFSET + 0x12;
const LOL_CDS_OFFSET: u16 = LOL_OFFSET + 0x16;
const LOL_FCB_OFFSET: u16 = LOL_OFFSET + 0x1a;
const LOL_PROTECTED_FCBS_OFFSET: u16 = LOL_OFFSET + 0x1e;
const LOL_BLOCK_DEVICE_COUNT_OFFSET: u16 = LOL_OFFSET + 0x20;
const LOL_DRIVE_LETTER_COUNT_OFFSET: u16 = LOL_OFFSET + 0x21;
const LOL_JOINED_DRIVES_OFFSET: u16 = LOL_OFFSET + 0x34;
const LOL_SPECIAL_PROGRAMS_OFFSET: u16 = LOL_OFFSET + 0x35;
const LOL_SETVER_OFFSET: u16 = LOL_OFFSET + 0x37;
const LOL_HIGH_A20_OFFSET: u16 = LOL_OFFSET + 0x3b;
const LOL_LAST_EXEC_PSP_OFFSET: u16 = LOL_OFFSET + 0x3d;
const LOL_BUFFER_COUNT_OFFSET: u16 = LOL_OFFSET + 0x3f;
const LOL_LOOKAHEAD_COUNT_OFFSET: u16 = LOL_OFFSET + 0x41;
const LOL_BOOT_DRIVE_OFFSET: u16 = LOL_OFFSET + 0x43;
const LOL_DWORD_MOVES_OFFSET: u16 = LOL_OFFSET + 0x44;
const LOL_EXTENDED_MEMORY_KB_OFFSET: u16 = LOL_OFFSET + 0x45;

const _: () = assert!(CDS_OFFSET as usize + CDS_ENTRY_COUNT * CDS_ENTRY_BYTES <= SYSTEM_BYTES);
const _: () = assert!(SFT_OFFSET as usize + SFT_TABLE_BYTES <= CDS_OFFSET as usize);
const _: () = assert!(LOL_OFFSET as usize + 0x47 <= SYSTEM_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SystemTables {
    pub(super) segment: u16,
}

impl super::state::DosKernel {
    /// Initialize the persistent guest-resident DOS system block.
    ///
    /// Runtime load installs character-device headers after this call. SFT
    /// contents are populated by `refresh_sft`; this method only publishes its
    /// far pointer. Repeated calls preserve the already-installed device data.
    pub fn initialize_system_tables(
        &mut self,
        memory: &mut impl GuestMemory,
    ) -> Result<(), DosError> {
        self.block_leases.check_storage_state()?;
        if self.system_tables.is_some() {
            return Ok(());
        }

        let base = real_address(SYSTEM_SEGMENT, 0);
        memory.validate_write(base, SYSTEM_BYTES)?;
        let chain = self.mcb_chain(memory)?;
        let first_mcb = chain
            .first()
            .ok_or(DosError::MalformedGuestInput("DOS MCB chain is empty"))?
            .segment;

        let mut block = vec![0; SYSTEM_BYTES];
        write_u16(&mut block, usize::from(LOL_FIRST_MCB_OFFSET), first_mcb);

        // FreeDOS kernel/kernel.asm initializes the empty DPB chain to -1.
        // This makes a normal offset-FFFF chain walk stop without reading IVT
        // bytes as a disk record. Optional non-chain providers stay null.
        write_far_pointer(&mut block, usize::from(LOL_DPB_OFFSET), u16::MAX, u16::MAX);
        write_far_pointer(&mut block, usize::from(LOL_SFT_OFFSET), SFT_OFFSET, SYSTEM_SEGMENT);
        write_far_pointer(&mut block, usize::from(LOL_CLOCK_OFFSET), 0, 0);
        write_far_pointer(
            &mut block,
            usize::from(LOL_CON_OFFSET),
            CON_HEADER_OFFSET,
            SYSTEM_SEGMENT,
        );
        write_u16(&mut block, usize::from(LOL_MAX_SECTOR_OFFSET), 0);
        write_far_pointer(&mut block, usize::from(LOL_DISK_BUFFER_OFFSET), 0, 0);
        // CDS storage is reserved for a future real DOS drive provider. A host
        // path alone is not a DPB or an IFS/network device header.
        write_far_pointer(&mut block, usize::from(LOL_CDS_OFFSET), 0, 0);
        write_far_pointer(&mut block, usize::from(LOL_FCB_OFFSET), 0, 0);
        write_u16(&mut block, usize::from(LOL_PROTECTED_FCBS_OFFSET), 0);
        block[usize::from(LOL_BLOCK_DEVICE_COUNT_OFFSET)] = 0;
        block[usize::from(LOL_DRIVE_LETTER_COUNT_OFFSET)] = 0;
        block[usize::from(LOL_JOINED_DRIVES_OFFSET)] = 0;
        write_u16(&mut block, usize::from(LOL_SPECIAL_PROGRAMS_OFFSET), 0);
        write_far_pointer(&mut block, usize::from(LOL_SETVER_OFFSET), 0, 0);
        write_u16(&mut block, usize::from(LOL_HIGH_A20_OFFSET), 0);
        // DOS resides below the HMA, so this DOS 5-compatible extension stays
        // zero. Extended memory is likewise reported only when configured.
        write_u16(&mut block, usize::from(LOL_LAST_EXEC_PSP_OFFSET), 0);
        write_u16(&mut block, usize::from(LOL_BUFFER_COUNT_OFFSET), 0);
        write_u16(&mut block, usize::from(LOL_LOOKAHEAD_COUNT_OFFSET), 0);
        block[usize::from(LOL_BOOT_DRIVE_OFFSET)] = DOS_BOOT_DRIVE;
        block[usize::from(LOL_DWORD_MOVES_OFFSET)] = 1;
        let extended_memory_kb = memory.len().saturating_sub(0x10_0000) / 1024;
        let extended_memory_kb = u16::try_from(extended_memory_kb).unwrap_or(u16::MAX);
        write_u16(
            &mut block,
            usize::from(LOL_EXTENDED_MEMORY_KB_OFFSET),
            extended_memory_kb,
        );

        // The whole range was preflighted above. One write leaves no partially
        // initialized pointer graph if the guest-memory implementation rejects
        // the range.
        memory.write(base, &block)?;
        self.system_tables = Some(SystemTables {
            segment: SYSTEM_SEGMENT,
        });
        Ok(())
    }

    /// Preflight the guest system-table destination before a DOS call can
    /// consume input, change a host file, or update a guest handle table.
    pub(super) fn validate_system_tables(
        &self,
        memory: &impl GuestMemory,
    ) -> Result<(), DosError> {
        self.block_leases.check_storage_state()?;
        let Some(tables) = self.system_tables else {
            return Ok(());
        };
        if tables.segment != SYSTEM_SEGMENT {
            return Err(DosError::HostContractViolation(
                "DOS system-table segment changed after initialization",
            ));
        }
        memory.validate_write(real_address(tables.segment, 0), SYSTEM_BYTES)?;
        self.validate_jft(memory)?;
        Ok(())
    }

    /// Refresh the real guest MCB/SFT facts exposed by the List of Lists.
    ///
    /// A kernel used by a unit-level host mock may not have installed system
    /// tables; in that case refresh is intentionally a no-op.
    pub fn refresh_system_tables(
        &mut self,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        self.block_leases.check_storage_state()?;
        let Some(tables) = self.system_tables else {
            return Ok(());
        };
        if tables.segment != SYSTEM_SEGMENT {
            return Err(DosError::HostContractViolation(
                "DOS system-table segment changed after initialization",
            ));
        }
        self.validate_system_tables(memory)?;

        let drive_count = host.logical_drive_count();
        if usize::from(drive_count) > CDS_ENTRY_COUNT {
            return Err(DosError::HostContractViolation(
                "host reported more than 26 DOS drive letters",
            ));
        }
        let chain = self.mcb_chain(memory)?;
        let first_mcb = chain
            .first()
            .ok_or(DosError::MalformedGuestInput("DOS MCB chain is empty"))?
            .segment;

        self.refresh_sft(memory, host)?;

        // Keep absent disk geometry and CDS providers unpublished. The DOS
        // kernel's higher-level current-directory APIs continue to use `host`.
        memory.write_u16(
            real_address(tables.segment, LOL_FIRST_MCB_OFFSET),
            first_mcb,
        )?;
        memory.write_u8(
            real_address(tables.segment, LOL_DRIVE_LETTER_COUNT_OFFSET),
            drive_count,
        )?;
        memory.write_u16(
            real_address(tables.segment, LOL_LAST_EXEC_PSP_OFFSET),
            0,
        )?;
        Ok(())
    }

    /// INT 21h/AH=52h: return ES:BX at the `ptr_first_DPB` field and preserve
    /// every other register and flag.
    pub(super) fn list_of_lists(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        self.block_leases.check_storage_state()?;
        let Some(tables) = self.system_tables else {
            return Err(DosError::HostContractViolation(
                "AH=52h called before DOS system tables were initialized",
            ));
        };
        memory.validate_write(real_address(tables.segment, 0), SYSTEM_BYTES)?;
        let drive_count = host.logical_drive_count();
        if usize::from(drive_count) > CDS_ENTRY_COUNT {
            return Err(DosError::HostContractViolation(
                "host reported more than 26 DOS drive letters",
            ));
        }
        let chain = self.mcb_chain(memory)?;
        let first_mcb = chain
            .first()
            .ok_or(DosError::MalformedGuestInput("DOS MCB chain is empty"))?
            .segment;
        // DOSDEV_GetLOL refreshes this field immediately before returning the
        // pointer. The normal interrupt lifecycle refreshes SFT after return.
        memory.write_u16(
            real_address(tables.segment, LOL_FIRST_MCB_OFFSET),
            first_mcb,
        )?;
        memory.write_u8(
            real_address(tables.segment, LOL_DRIVE_LETTER_COUNT_OFFSET),
            drive_count,
        )?;
        regs.es = tables.segment;
        regs.set_bx(LOL_OFFSET);
        Ok(DosAction::Continue)
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_far_pointer(bytes: &mut [u8], offset: usize, pointer_offset: u16, segment: u16) {
    bytes[offset..offset + 2].copy_from_slice(&pointer_offset.to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&segment.to_le_bytes());
}

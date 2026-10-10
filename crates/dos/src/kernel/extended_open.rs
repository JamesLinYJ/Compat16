//! Bounded DOS 4 extended open (Microsoft KB Q39529; DOS 4 FILE.ASM,
//! Extended_Open). Replacement and commit-on-write need additional contracts.
//! https://www.betaarchive.com/wiki/index.php/Microsoft_KB_Archive/39529
//! https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/FILE.ASM

use crate::{
    DosAction, DosCallAddressSpace, DosError, DosErrorCode, DosFileAccess, DosFileDisposition,
    DosFileOpenOutcome, DosFileOpenRequest, DosFileSharing, DosHost, DosHostError,
};
use guest_core::Registers;

use super::DosKernel;
use super::memory::read_dos_c_string;
use super::state::Handle;

impl DosKernel {
    pub(super) fn extended_open_file(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let request = match extended_open_request(regs) {
            Ok(request) => request,
            Err(code) => {
                Self::failure(regs, DosHostError::new(code));
                return Ok(DosAction::Continue);
            }
        };
        let Some(handle) = self.first_free_handle() else {
            Self::failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        };
        if !self.file_table.has_free_slot() {
            Self::failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        // Unlike AH=3Dh/5Bh, the filename is DS:SI. Resolve it through the
        // caller's checked address space, including protected selectors.
        let path = match read_dos_c_string(memory, regs.ds, regs.si()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = self.reserve_file_cleanup_slot() {
            Self::failure(regs, error);
            return Ok(DosAction::Continue);
        }
        // Retain the full mode, including the SFT's no-inherit bit. Both
        // identities must be reserved before a host operation can create.
        if self.file_table.register_open(handle, regs.bx()).is_none() {
            Self::failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        let opened = match host.file_extended_open(&path, request) {
            Ok(opened) => opened,
            Err(error) => {
                self.file_table.remove_handle(handle);
                Self::failure(regs, error);
                return Ok(DosAction::Continue);
            }
        };
        if self.owns_file_token(opened.file) {
            self.file_table.remove_handle(handle);
            // An already-owned identity must never be closed as cleanup.
            return Err(DosError::HostContractViolation(
                "extended open returned an already owned file token",
            ));
        }
        let outcome_matches = matches!(
            (request.disposition, opened.outcome),
            (DosFileDisposition::OpenExisting, DosFileOpenOutcome::Opened)
                | (DosFileDisposition::CreateNew, DosFileOpenOutcome::Created)
                | (DosFileDisposition::OpenOrCreate, _)
        );
        if !outcome_matches {
            self.file_table.remove_handle(handle);
            if host.file_close(opened.file).is_err() {
                self.retain_unclosed_file(opened.file).map_err(|_| {
                    DosError::HostContractViolation("reserved file cleanup slot disappeared")
                })?;
            }
            return Err(DosError::HostContractViolation(
                "extended open returned an outcome outside its disposition",
            ));
        }
        self.handles.insert(handle, Handle::File(opened.file));
        regs.set_ax(handle);
        regs.set_cx(match opened.outcome {
            DosFileOpenOutcome::Opened => 1,
            DosFileOpenOutcome::Created => 2,
        });
        Self::success(regs);
        Ok(DosAction::Continue)
    }
}

fn extended_open_request(regs: &Registers) -> Result<DosFileOpenRequest, DosErrorCode> {
    if regs.al() != 0 {
        return Err(DosErrorCode::InvalidFunction);
    }
    let mode = regs.bx();
    // Bits 3, 8..12 and 15 are reserved. Validate the entire BX, not BL.
    if mode & !0x60f7 != 0 {
        return Err(DosErrorCode::InvalidAccess);
    }
    let access = match mode & 7 {
        0 => DosFileAccess::ReadOnly,
        1 => DosFileAccess::WriteOnly,
        2 => DosFileAccess::ReadWrite,
        _ => return Err(DosErrorCode::InvalidAccess),
    };
    let sharing = match (mode >> 4) & 7 {
        0 => DosFileSharing::Compatibility,
        1 => DosFileSharing::DenyAll,
        2 => DosFileSharing::DenyWrite,
        3 => DosFileSharing::DenyRead,
        4 => DosFileSharing::DenyNone,
        _ => return Err(DosErrorCode::InvalidAccess),
    };
    if mode & 0x4000 != 0 {
        return Err(DosErrorCode::InvalidFunction);
    }
    // Bit 13 requests returned critical errors. Both settings currently use
    // the runtime's existing returned-error policy; INT 24h is not emulated.
    let disposition = match regs.dx() {
        0x0001 => DosFileDisposition::OpenExisting,
        0x0010 => DosFileDisposition::CreateNew,
        0x0011 => DosFileDisposition::OpenOrCreate,
        // DOS 4 explicitly rejects 0000. Reserved bits/nibbles and the valid
        // but unsupported replace actions 0002/0012 also fail before mutation.
        _ => return Err(DosErrorCode::InvalidFunction),
    };
    let attributes = if disposition == DosFileDisposition::OpenExisting {
        0 // CX is ignored when creation is not requested.
    } else {
        // The mounted-file backend supports only ordinary DOS file flags;
        // volume labels and directories are not extended-open creations.
        if regs.cx() & !0x0027 != 0 {
            return Err(DosErrorCode::InvalidAccess);
        }
        regs.cx() as u8
    };
    Ok(DosFileOpenRequest { access, sharing, disposition, attributes })
}

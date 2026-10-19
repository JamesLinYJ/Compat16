//! Unopened FCB deletion and in-place rename; guest FCB/DTA bytes are inputs.
use super::{
    DosKernel, directory,
    state::{SearchKey, SearchKind},
};
use crate::{DosAction, DosCallAddressSpace, DosDirectoryEntry, DosError, DosErrorCode, DosHost};
use guest_core::Registers;
mod layout;
use layout::Request;

impl DosKernel {
    pub(super) fn fcb_mutation(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let rename = regs.ah() == 0x17;
        let request = Request::read(memory, regs.ds, regs.dx(), rename)?;
        let page = host.guest_code_page();
        let (pattern, destination) = match request.patterns(page) {
            Ok(patterns) => patterns,
            Err(code) => return Ok(self.fcb_failure(regs, code)),
        };
        let current = host.current_drive();
        if current > 25 {
            return Err(DosError::HostContractViolation("invalid FCB current drive"));
        }
        let drive = match request.drive {
            0 => current,
            1..=26 => request.drive - 1,
            _ => return Ok(self.fcb_failure(regs, DosErrorCode::PathNotFound)),
        };
        let prefix = if drive == current {
            Vec::new()
        } else {
            vec![b'A' + drive, b':']
        };
        let key = SearchKey {
            kind: SearchKind::FcbMutation,
            psp_segment: self.psp_segment,
            caller: memory.caller_id(),
            dta_segment: regs.ds,
            dta_offset: regs.dx(),
            dta_lease: 0,
        };
        let entries =
            match self.collect_fcb_matches(key, &prefix, pattern, request.attributes, host, Ok) {
                Ok(entries) => entries,
                Err(DosError::HostOperation(error)) => {
                    return Ok(self.fcb_failure(
                        regs,
                        match error.code {
                            DosErrorCode::NoMoreFiles => DosErrorCode::FileNotFound,
                            DosErrorCode::UnknownUnit => DosErrorCode::PathNotFound,
                            code => code,
                        },
                    ));
                }
                Err(error) => return Err(error),
            };
        if entries.is_empty() {
            return Ok(self.fcb_failure(regs, DosErrorCode::FileNotFound));
        }
        if let Some(destination) = destination {
            for entry in entries {
                if entry.attributes & 8 != 0 {
                    return Ok(self.fcb_failure(regs, DosErrorCode::InvalidFunction));
                }
                if entry.short_name == b"." || entry.short_name == b".." {
                    return Ok(self.fcb_failure(regs, DosErrorCode::AccessDenied));
                }
                let name = match layout::substitute(destination, &entry.short_name, page) {
                    Ok(name) => name,
                    Err(code) => return Ok(self.fcb_failure(regs, code)),
                };
                let old = path(&prefix, &entry.short_name);
                let new = path(&prefix, &name);
                // DOS rejects renaming to the same name; native rename APIs
                // may accept it. Compare in the DOS short-name case mapping.
                if directory::short_name_fields(&entry.short_name, page)
                    == directory::short_name_fields(&name, page)
                {
                    return Ok(self.fcb_failure(regs, DosErrorCode::AccessDenied));
                }
                if let Err(error) = host.file_rename(&old, &new) {
                    return Ok(self.fcb_failure(regs, error.code));
                }
            }
        } else {
            let mut deleted = false;
            let mut first_error = None;
            for entry in entries {
                let result = delete_entry(&entry, request.attributes, &prefix, host);
                match result {
                    Ok(()) => deleted = true,
                    Err(code)
                        if matches!(
                            code,
                            DosErrorCode::WriteProtected
                                | DosErrorCode::DriveNotReady
                                | DosErrorCode::GeneralFailure
                        ) =>
                    {
                        return Ok(self.fcb_failure(regs, code));
                    }
                    Err(code) => {
                        first_error.get_or_insert(code);
                    }
                }
            }
            // DOS DELETE.ASM skips readonly/sharing failures. A successful
            // deletion is sufficient; unlike rename this is not all-or-error.
            if !deleted {
                return Ok(
                    self.fcb_failure(regs, first_error.unwrap_or(DosErrorCode::FileNotFound))
                );
            }
        }
        regs.set_al(0);
        Ok(DosAction::Continue)
    }
}

fn path(prefix: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(prefix.len() + name.len());
    path.extend_from_slice(prefix);
    path.extend_from_slice(name);
    path
}

fn delete_entry(
    entry: &DosDirectoryEntry,
    attributes: u8,
    prefix: &[u8],
    host: &mut impl DosHost,
) -> Result<(), DosErrorCode> {
    // The documented FCB delete contract does not delete directories. Do not
    // reproduce the historical FORMAT-only raw-FAT directory corruption path.
    if entry.attributes & 0x10 != 0 {
        return Err(DosErrorCode::AccessDenied);
    }
    if entry.attributes & 8 != 0 {
        return Err(DosErrorCode::InvalidFunction);
    }
    let read_only = entry.attributes & 1 != 0;
    if read_only && attributes & 1 == 0 {
        return Err(DosErrorCode::AccessDenied);
    }
    host.file_delete_fcb(&path(prefix, &entry.short_name), read_only)
        .map_err(|error| match error.code {
            // Original DOS reports access denied when all found entries were
            // blocked by its exclusive-access check, including open files.
            DosErrorCode::SharingViolation | DosErrorCode::LockViolation => {
                DosErrorCode::AccessDenied
            }
            code => code,
        })
}

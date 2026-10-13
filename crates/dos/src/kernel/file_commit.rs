//! Commit an owned DOS open file without closing or changing its aliases.

use crate::{
    DosAction, DosError, DosErrorCode, DosHost, DosHostError, DosIoctlObjectInfo, DosIoctlStream,
};
use guest_core::Registers;

use super::DosKernel;
use super::state::{Handle, StandardHandle};

impl DosKernel {
    pub(super) fn commit_file(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        // AH=68h uses BX, not AL or any caller pointer. Look up the actual
        // object: AH=46h can replace even handles 0..2 with ordinary files.
        // DOS4 preserves SFT reference counts/sharing and skips clean files
        // and character devices rather than closing and reopening them.
        // https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/CLOSE.ASM#L325-L372
        let result = match self.handles.get(&regs.bx()).copied() {
            Some(Handle::File(file)) => host.file_commit(file),
            Some(Handle::Standard(standard)) => {
                let stream = match standard {
                    StandardHandle::Input => DosIoctlStream::Input,
                    StandardHandle::Output => DosIoctlStream::Output,
                    StandardHandle::Error => DosIoctlStream::Error,
                };
                match host.standard_ioctl_info(stream) {
                    Ok(DosIoctlObjectInfo::CharacterDevice { .. }) => Ok(()),
                    // A redirected stream has no owned-file commit contract
                    // here. A drive number alone cannot establish one.
                    Ok(DosIoctlObjectInfo::File { .. }) => {
                        Err(DosHostError::new(DosErrorCode::InvalidFunction))
                    }
                    Err(error) => Err(error),
                }
            }
            None => Err(DosHostError::new(DosErrorCode::InvalidHandle)),
        };
        match result {
            Ok(()) => self.success(regs),
            // MS-DOS 4 I21_MAP_E_TAB allows only error_invalid_handle on
            // Commit. Any other code stays available through AH=59h, and the
            // call itself returns 6.
            // https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/HANDLE.ASM#L157-L194
            Err(error) => self.fail_with_extended_cause(
                regs,
                error.code,
                DosErrorCode::InvalidHandle,
            ),
        }
        Ok(DosAction::Continue)
    }
}

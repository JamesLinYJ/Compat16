use crate::{
    DosAction, DosError, DosErrorCode, DosHost, DosHostError, DosIoctlStream,
};
use guest_core::Registers;

use super::state::{DosKernel, Handle, StandardHandle};

impl DosKernel {
    pub(super) fn ioctl(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        match regs.al() {
            0x00 => self.get_device_information(regs, host),
            _ => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
                Ok(DosAction::Continue)
            }
        }
    }

    fn get_device_information(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let Some(handle) = self.handles.get(&regs.bx()).copied() else {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidHandle));
            return Ok(DosAction::Continue);
        };

        let info = match handle {
            Handle::Standard(StandardHandle::Input) => {
                host.standard_ioctl_info(DosIoctlStream::Input)
            }
            Handle::Standard(StandardHandle::Output) => {
                host.standard_ioctl_info(DosIoctlStream::Output)
            }
            Handle::Standard(StandardHandle::Error) => {
                host.standard_ioctl_info(DosIoctlStream::Error)
            }
            Handle::File(file) => host.file_ioctl_info(file),
        };
        let info = match info {
            Ok(info) => info,
            Err(error) => {
                self.failure(regs, error);
                return Ok(DosAction::Continue);
            }
        };

        let word = info.device_information_word().ok_or(DosError::HostContractViolation(
            "host returned a drive number outside the DOS drive-letter range",
        ))?;

        regs.set_dx(word);
        Self::success(regs);
        Ok(DosAction::Continue)
    }
}

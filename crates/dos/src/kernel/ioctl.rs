use crate::{
    DosAction, DosError, DosErrorCode, DosHost, DosHostError, DosIoctlObjectInfo, DosIoctlStream,
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
        &self,
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

        let word = match info {
            DosIoctlObjectInfo::File { drive, written } => {
                if drive > 25 {
                    return Err(DosError::HostContractViolation(
                        "host returned a drive number outside the DOS drive-letter range",
                    ));
                }
                u16::from(drive) | (u16::from(!written) << 6)
            }
            DosIoctlObjectInfo::CharacterDevice {
                input_eof,
                raw_mode,
                standard_input,
                standard_output,
            } => {
                // MS-DOS uses a clear bit 6 to signal EOF on a character device.
                (1 << 7)
                    | (u16::from(!input_eof) << 6)
                    | (u16::from(raw_mode) << 5)
                    | u16::from(standard_input)
                    | (u16::from(standard_output) << 1)
            }
        };

        regs.set_dx(word);
        self.success(regs);
        Ok(DosAction::Continue)
    }
}

use crate::caller_address_space::{DosCallAddressSpace, DosPointerAccess, DosSpanPolicy};
use crate::{
    DosAction, DosError, DosErrorCode, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosSeekOrigin,
};
use guest_core::Registers;

use super::DosKernel;
use super::memory::read_dos_c_string;
use super::state::{Handle, StandardHandle};

const OPEN_ACCESS_MASK: u8 = 0x07;
const OPEN_RESERVED_MASK: u8 = 0x08;
const OPEN_SHARING_MASK: u8 = 0x70;

impl DosKernel {
    pub(super) fn create_file(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let Some(handle) = self.first_free_handle() else {
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        };
        if !self.file_table.has_free_slot() {
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        let path = match read_dos_c_string(memory, regs.ds, regs.dx()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        // Reserve the JFT/SFT identity before touching a host file. This makes
        // exhaustion side-effect free and leaves no post-create registration
        // failure that would require closing an untracked host token.
        if self.file_table.register_open(handle, 2).is_none() {
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        // MS-DOS 4 Programmer's Reference, Function 5Bh: unlike 3Ch, fail
        // with DOS error 80 if the name exists; never truncate that file.
        // https://www.pcjs.org/documents/books/mspl13/msdos/dosref40/
        let created = if regs.ah() == 0x5b {
            host.file_create_new(&path, regs.cx() as u8)
        } else {
            host.file_create(&path, regs.cx() as u8)
        };
        match created {
            Ok(file) => {
                if self.owns_file_token(file) {
                    self.file_table.remove_handle(handle);
                    return Err(DosError::HostContractViolation(
                        "file creation returned an already owned file token",
                    ));
                }
                self.handles.insert(handle, Handle::File(file));
                regs.set_ax(handle);
                self.success(regs);
                Ok(DosAction::Continue)
            }
            Err(error) => {
                self.file_table.remove_handle(handle);
                self.failure(regs, error);
                Ok(DosAction::Continue)
            }
        }
    }

    pub(super) fn open_file(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let Some(handle) = self.first_free_handle() else {
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        };
        if !self.file_table.has_free_slot() {
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        let mode = regs.al();
        let access = match mode & OPEN_ACCESS_MASK {
            0 => DosFileAccess::ReadOnly,
            1 => DosFileAccess::WriteOnly,
            2 => DosFileAccess::ReadWrite,
            _ => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidAccess));
                return Ok(DosAction::Continue);
            }
        };
        let sharing = match (mode & OPEN_SHARING_MASK) >> 4 {
            0 => DosFileSharing::Compatibility,
            1 => DosFileSharing::DenyAll,
            2 => DosFileSharing::DenyWrite,
            3 => DosFileSharing::DenyRead,
            4 => DosFileSharing::DenyNone,
            _ => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidAccess));
                return Ok(DosAction::Continue);
            }
        };
        if mode & OPEN_RESERVED_MASK != 0 {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidAccess));
            return Ok(DosAction::Continue);
        }
        let path = match read_dos_c_string(memory, regs.ds, regs.dx()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        match host.file_open_with_sharing(&path, access, sharing) {
            Ok(file) => {
                if self
                    .file_table
                    .register_open(handle, u16::from(mode))
                    .is_none()
                {
                    let _ = host.file_close(file);
                    self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
                    return Ok(DosAction::Continue);
                }
                self.handles.insert(handle, Handle::File(file));
                regs.set_ax(handle);
                self.success(regs);
                Ok(DosAction::Continue)
            }
            Err(error) => {
                self.failure(regs, error);
                Ok(DosAction::Continue)
            }
        }
    }

    pub(super) fn close_file(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let handle = regs.bx();
        let Some(target) = self.handles.get(&handle).copied() else {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidHandle));
            return Ok(DosAction::Continue);
        };
        if let Handle::File(file) = target {
            if let Err(error) = host.file_close(file) {
                self.failure(regs, error);
                return Ok(DosAction::Continue);
            }
        }
        self.handles.remove(&handle);
        self.file_table.remove_handle(handle);
        self.success(regs);
        Ok(DosAction::Continue)
    }

    pub(super) fn read_file(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let handle_id = regs.bx();
        let count = usize::from(regs.cx());
        let target = match self.handles.get(&handle_id).copied() {
            Some(handle) => handle,
            None => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidHandle));
                return Ok(DosAction::Continue);
            }
        };
        if let Handle::File(_) = target {
            // DOS 4 checks the SFT access mode before its zero-count shortcut.
            // https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/DISK.ASM#L153-L165
            // Use the owned mode, never the guest-writable SFT projection.
            let error = match self.file_table.file_open_mode(handle_id) {
                Some(mode) => match mode & u16::from(OPEN_ACCESS_MASK) {
                    0 | 2 => None,
                    1 => Some(DosErrorCode::AccessDenied),
                    _ => Some(DosErrorCode::InvalidAccess),
                },
                None => Some(DosErrorCode::InvalidHandle),
            };
            if let Some(error) = error {
                self.failure(regs, DosHostError::new(error));
                return Ok(DosAction::Continue);
            }
        }
        let pointer = if count == 0 {
            None
        } else {
            let pointer = memory.resolve_caller_pointer(regs.ds, regs.dx())?;
            memory.validate_caller_range(
                pointer,
                0,
                count,
                DosPointerAccess::Write,
                DosSpanPolicy::Linear,
            )?;
            Some(pointer)
        };
        let mut data = vec![0; count];
        let read = if count == 0 {
            Ok(0)
        } else {
            match target {
                Handle::Standard(StandardHandle::Input) => self.read_stdin_bytes(host, &mut data),
                Handle::Standard(_) => Err(DosHostError::new(DosErrorCode::InvalidHandle)),
                Handle::File(file) => host.file_read(file, &mut data),
            }
        };
        match read {
            Ok(read) if read <= count => {
                if read != 0 {
                    let pointer = pointer.ok_or(DosError::HostContractViolation(
                        "DOS read returned bytes for an empty caller buffer",
                    ))?;
                    memory.write_caller_range(pointer, 0, &data[..read], DosSpanPolicy::Linear)?;
                }
                regs.set_ax(read as u16);
                self.success(regs);
            }
            Ok(_) => {
                return Err(DosError::HostContractViolation(
                    "host read exceeded its output buffer",
                ));
            }
            Err(error) => self.failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn read_stdin_bytes(
        &mut self,
        host: &mut impl DosHost,
        output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        if output.is_empty() {
            return Ok(0);
        }
        if let Some(byte) = self.pending_input.take() {
            output[0] = byte;
            return Ok(1);
        }
        let count = host.read_stdin(output)?;
        if count > output.len() {
            return Err(DosHostError::new(DosErrorCode::GeneralFailure));
        }
        Ok(count)
    }

    pub(super) fn write_file(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let handle_id = regs.bx();
        let count = usize::from(regs.cx());
        let target = match self.handles.get(&handle_id).copied() {
            Some(handle) => handle,
            None => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidHandle));
                return Ok(DosAction::Continue);
            }
        };
        if let Handle::File(_) = target {
            // DOS 4 rejects read-only opens before SETUP, including CX=0.
            // https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/DISK.ASM#L433-L458
            // Use the owned mode, never the guest-writable SFT projection.
            let error = match self.file_table.file_open_mode(handle_id) {
                Some(mode) => match mode & u16::from(OPEN_ACCESS_MASK) {
                    1 | 2 => None,
                    0 => Some(DosErrorCode::AccessDenied),
                    _ => Some(DosErrorCode::InvalidAccess),
                },
                None => Some(DosErrorCode::InvalidHandle),
            };
            if let Some(error) = error {
                self.failure(regs, DosHostError::new(error));
                return Ok(DosAction::Continue);
            }
        }
        let mut data = vec![0; count];
        if count != 0 {
            let pointer = memory.resolve_caller_pointer(regs.ds, regs.dx())?;
            memory.read_caller_range(pointer, 0, &mut data, DosSpanPolicy::Linear)?;
        }
        let write = match target {
            Handle::Standard(StandardHandle::Output) => host.write_stdout(&data),
            Handle::Standard(StandardHandle::Error) => host.write_stderr(&data),
            _ if count == 0 => match target {
                Handle::File(file) => host
                    .file_seek(file, 0, DosSeekOrigin::Current)
                    .and_then(|position| host.file_set_len(file, position))
                    .map(|()| 0),
                Handle::Standard(_) => Err(DosHostError::new(DosErrorCode::InvalidHandle)),
            },
            Handle::Standard(StandardHandle::Input) => {
                Err(DosHostError::new(DosErrorCode::InvalidHandle))
            }
            Handle::File(file) => host.file_write(file, &data),
        };
        match write {
            Ok(written) if written <= count => {
                regs.set_ax(written as u16);
                self.success(regs);
            }
            Ok(_) => {
                return Err(DosError::HostContractViolation(
                    "host write exceeded its input buffer",
                ));
            }
            Err(error) => self.failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn delete_file(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let path = match read_dos_c_string(memory, regs.ds, regs.dx()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        match host.file_delete(&path) {
            Ok(()) => {
                self.success(regs);
            }
            Err(error) => self.failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn seek_file(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let file = match self.handles.get(&regs.bx()).copied() {
            Some(Handle::File(file)) => file,
            _ => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidHandle));
                return Ok(DosAction::Continue);
            }
        };
        let origin = match regs.al() {
            0 => DosSeekOrigin::Start,
            1 => DosSeekOrigin::Current,
            2 => DosSeekOrigin::End,
            _ => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
                return Ok(DosAction::Continue);
            }
        };
        let offset = ((u32::from(regs.cx()) << 16) | u32::from(regs.dx())) as i32;
        match host.file_seek(file, offset, origin) {
            Ok(position) => {
                regs.set_dx((position >> 16) as u16);
                regs.set_ax(position as u16);
                self.success(regs);
            }
            Err(error) => self.failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn duplicate_file(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        // DOS 4 $DUP checks JFNFree before CheckOwner, so a full JFT takes
        // precedence over an invalid source handle (HANDLE.ASM, lines 673–689).
        let new_id = self.first_free_handle();
        let Some(new_id) = new_id else {
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        };
        let source = match self.handles.get(&regs.bx()).copied() {
            Some(handle) => handle,
            None => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidHandle));
                return Ok(DosAction::Continue);
            }
        };
        if !self.file_table.can_duplicate_handle(regs.bx(), new_id) {
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        let target = match source {
            Handle::Standard(kind) => Handle::Standard(kind),
            Handle::File(file) => match host.file_duplicate(file) {
                Ok(copy) if !self.owns_file_token(copy) => Handle::File(copy),
                Ok(_) => {
                    return Err(DosError::HostContractViolation(
                        "file_duplicate returned an already owned file token",
                    ));
                }
                Err(error) => {
                    self.failure(regs, error);
                    return Ok(DosAction::Continue);
                }
            },
        };
        if !self.file_table.duplicate_handle(regs.bx(), new_id) {
            if let Handle::File(file) = target {
                let _ = host.file_close(file);
            }
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        self.handles.insert(new_id, target);
        regs.set_ax(new_id);
        self.success(regs);
        Ok(DosAction::Continue)
    }

    pub(super) fn force_duplicate_file(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let source_id = regs.bx();
        let target_id = regs.cx();
        let Some(source) = self.handles.get(&source_id).copied() else {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidHandle));
            return Ok(DosAction::Continue);
        };
        if !self.handle_fits_jft(target_id) {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidHandle));
            return Ok(DosAction::Continue);
        }
        if !self.file_table.can_duplicate_handle(source_id, target_id) {
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        if source_id == target_id {
            self.success(regs);
            return Ok(DosAction::Continue);
        }
        let replacement = match source {
            Handle::Standard(kind) => Handle::Standard(kind),
            Handle::File(file) => match host.file_duplicate(file) {
                Ok(copy) if !self.owns_file_token(copy) => Handle::File(copy),
                Ok(_) => {
                    return Err(DosError::HostContractViolation(
                        "file_duplicate returned an already owned file token",
                    ));
                }
                Err(error) => {
                    self.failure(regs, error);
                    return Ok(DosAction::Continue);
                }
            },
        };
        if let Some(Handle::File(old)) = self.handles.get(&target_id).copied() {
            if let Err(error) = host.file_close(old) {
                if let Handle::File(copy) = replacement {
                    let _ = host.file_close(copy);
                }
                self.failure(regs, error);
                return Ok(DosAction::Continue);
            }
        }
        if !self.file_table.duplicate_handle(source_id, target_id) {
            if let Handle::File(copy) = replacement {
                let _ = host.file_close(copy);
            }
            self.failure(regs, DosHostError::new(DosErrorCode::TooManyOpenFiles));
            return Ok(DosAction::Continue);
        }
        self.handles.insert(target_id, replacement);
        regs.set_ax(target_id);
        self.success(regs);
        Ok(DosAction::Continue)
    }
}

//! DOS AH=5Ah: append an eight-character name to the caller's directory.
//! Microsoft MS-DOS Encyclopedia, Function 5Ah, documents 13 bytes after
//! the directory's final separator, including the generated name's NUL.
//! DOS 4 FILE.ASM ($CreateTempFile) confirms separator insertion, hex names,
//! attribute validation, and writing each candidate before atomic CreateNew.
//! https://www.pcjs.org/documents/books/mspl13/msdos/encyclopedia/section5/
//! https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/FILE.ASM

use crate::{
    DosAction, DosCallAddressSpace, DosError, DosErrorCode, DosHost, DosHostError,
    DosPointerAccess, DosSpanPolicy,
};
use guest_core::{MemoryError, Registers};

use super::DosKernel;
use super::state::Handle;

const PATH_BUFFER_LIMIT: usize = 260;
const NAME_BUFFER_BYTES: usize = 13;
pub(super) const TEMPORARY_CREATE_ATTEMPTS: usize = 256;

impl DosKernel {
    pub(super) fn create_temporary_file(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        // DOS rejects volume/directory and reserved attribute bits before its
        // retry loop. Validate all of CX rather than silently discarding CH.
        if regs.cx() & !0x0027 != 0 {
            return Ok(self.temporary_file_failure(regs, DosErrorCode::AccessDenied));
        }
        let Some(handle) = self.first_free_handle() else {
            return Ok(self.temporary_file_failure(regs, DosErrorCode::TooManyOpenFiles));
        };
        if !self.file_table.has_free_slot() {
            return Ok(self.temporary_file_failure(regs, DosErrorCode::TooManyOpenFiles));
        }
        let pointer = memory.resolve_caller_pointer(regs.ds, regs.dx())?;
        let mut path = match memory.read_caller_terminated(
            pointer, 0, PATH_BUFFER_LIMIT, DosSpanPolicy::Linear,
        ) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                return Ok(self.temporary_file_failure(regs, DosErrorCode::PathNotFound));
            }
            Err(error) => return Err(error),
        };
        let mut trailing_separator = false;
        for character in text_codec::encoded_characters(&path, host.guest_code_page()) {
            let Ok(character) = character else {
                return Ok(self.temporary_file_failure(regs, DosErrorCode::PathNotFound));
            };
            trailing_separator = character.is_standalone_ascii(b'\\')
                || character.is_standalone_ascii(b'/');
        }
        // A DBCS trail byte equal to '\\' is not a separator. An empty path
        // gains '\\', matching DOS 5's documented root-directory behavior.
        let prefix_len = path.len() + usize::from(!trailing_separator);
        let capacity = prefix_len + NAME_BUFFER_BYTES;
        if capacity > PATH_BUFFER_LIMIT {
            return Ok(self.temporary_file_failure(regs, DosErrorCode::PathNotFound));
        }
        memory.validate_caller_range(
            pointer, 0, capacity, DosPointerAccess::Write, DosSpanPolicy::Linear,
        )?;
        path.try_reserve_exact(capacity - path.len())
            .map_err(|_| DosError::Memory(MemoryError::AllocationFailed))?;
        if !trailing_separator {
            path.push(b'\\');
        }
        path.resize(prefix_len + 9, 0);
        let time = match host.local_date_time() {
            Ok(time) => time,
            Err(error) => {
                self.failure(regs, error);
                return Ok(DosAction::Continue);
            }
        };
        let seed = u32::from_be_bytes([time.hour, time.minute, time.second, time.hundredth]);
        // Read/write, compatibility sharing, inheritable, cursor initially 0.
        // Both guest table identities are claimed before any host mutation.
        if self.file_table.register_open(handle, 2).is_none() {
            return Ok(self.temporary_file_failure(regs, DosErrorCode::TooManyOpenFiles));
        }
        for _ in 0..TEMPORARY_CREATE_ATTEMPTS {
            let value = seed.wrapping_add(self.next_temporary_name);
            self.next_temporary_name = self.next_temporary_name.wrapping_add(1);
            for index in 0..8 {
                path[prefix_len + index] = b"0123456789ABCDEF"
                    [((value >> ((7 - index) * 4)) & 0xf) as usize];
            }
            // Like DOS, publish the attempted name before creation. A failed
            // guest write cannot leave a newly created file or an open token.
            if let Err(error) = memory.write_caller_range(
                pointer, 0, &path, DosSpanPolicy::Linear,
            ) {
                self.file_table.remove_handle(handle);
                return Err(error);
            }
            // The seed/counter is only a candidate generator, never proof of
            // uniqueness. The capability-rooted host must atomically claim it.
            match host.file_create_new(&path[..path.len() - 1], regs.cx() as u8) {
                Ok(file) => {
                    if self.owns_file_token(file) {
                        self.file_table.remove_handle(handle);
                        return Err(DosError::HostContractViolation(
                            "temporary file creation returned an already owned file token",
                        ));
                    }
                    self.handles.insert(handle, Handle::File(file));
                    regs.set_ax(handle);
                    Self::success(regs);
                    return Ok(DosAction::Continue);
                }
                Err(error) if error.code == DosErrorCode::FileExists => {}
                Err(error) => {
                    self.file_table.remove_handle(handle);
                    self.failure(regs, error);
                    return Ok(DosAction::Continue);
                }
            }
        }
        // Bound retries even with a frozen clock or a hostile/full namespace.
        // Do not pretend a collision was a created file, or loop on genuine
        // AccessDenied as old DOS did. Error 5 is a documented 5Ah failure.
        self.file_table.remove_handle(handle);
        Ok(self.temporary_file_failure(regs, DosErrorCode::AccessDenied))
    }

    fn temporary_file_failure(&mut self, regs: &mut Registers, code: DosErrorCode) -> DosAction {
        self.failure(regs, DosHostError::new(code));
        DosAction::Continue
    }
}

//! KERNEL.406 and KERNEL.407. The Windows 3.1 SDK does not publish these
//! exports. Strings stay guest ANSI/DBCS. The structure is opaque bytes and
//! is stored by the host profile API, not by a second INI codec here.

use guest_core::memory::Memory;
use win16_abi::Access;

use super::{guest_ranges::{GuestOutputRange, commit_guest_writes}, Win16State};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn write_private_profile_struct(
        &self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        data: Option<&[u8]>,
        data_size: u16,
        filename: Option<&[u8]>,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if data.is_some_and(|bytes| bytes.len() != usize::from(data_size)) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 profile-struct payload length differs from its checked size"));
        }
        let filename = self.private_profile_path(filename, host)?;
        Ok(u32::from(host.win16_profile_struct_write(
            section, key, data, data_size, &filename,
        )?))
    }

    pub(super) fn get_private_profile_struct(
        &self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        output: u32,
        capacity: u16,
        filename: Option<&[u8]>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        // A null destination is FALSE and does not read the profile. COMMCTRL
        // uses the same null-output failure for this API pair.
        if output == 0 {
            return Ok(0);
        }
        let range = if capacity == 0 {
            None
        } else {
            let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
            self.selectors.translate(pointer, Access::Write, usize::from(capacity), memory)
                .map_err(crate::runtime_error)?;
            Some(GuestOutputRange::capture(self, memory, pointer, usize::from(capacity))?)
        };
        let filename = self.private_profile_path(filename, host)?;
        let (succeeded, data) = host.win16_profile_struct_read(
            section, key, capacity, &filename,
        )?;
        if !succeeded {
            return Ok(0);
        }
        if data.len() != usize::from(capacity) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "GetPrivateProfileStruct host returned a different byte count"));
        }
        if let Some(range) = range {
            commit_guest_writes(self, memory, vec![(range, data)])?;
        }
        Ok(1)
    }
}

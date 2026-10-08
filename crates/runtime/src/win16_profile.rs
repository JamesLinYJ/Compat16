//! Guest buffers for Win16 profile string APIs.

use guest_core::memory::Memory;
use win16_abi::Win16OutputBuffer;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn profile_string(
        &self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        default_value: Option<&[u8]>,
        filename: Option<&[u8]>,
        output: Win16OutputBuffer,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let (bytes, copied) = host.win16_profile_string(
            section, key, default_value, filename, output.capacity,
        )?;
        self.write_profile_result(section, key, output, &bytes, copied, memory)
    }

    pub(super) fn system_profile_string(
        &self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        default_value: Option<&[u8]>,
        output: Win16OutputBuffer,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let (bytes, copied) = host.win16_system_profile_string(
            section, key, default_value, output.capacity,
        )?;
        self.write_profile_result(section, key, output, &bytes, copied, memory)
    }

    fn write_profile_result(
        &self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        output: Win16OutputBuffer,
        bytes: &[u8],
        copied: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if bytes.len() > usize::from(output.capacity) || usize::from(copied) > bytes.len() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 profile host returned an oversized output buffer"));
        }
        // A successful enumeration count includes the last item's NUL, while
        // the truncation sentinel (capacity - 2) excludes both trailing NULs.
        // Copy the owned terminated span rather than infer it from that count.
        let written = if section.is_none() || key.is_none() {
            bytes.windows(2).position(|pair| pair == [0, 0])
                .map_or(bytes.len(), |end| end + 2)
        } else {
            bytes.iter().position(|byte| *byte == 0)
                .map_or(bytes.len(), |end| end + 1)
        };
        self.write_output(memory, output, &bytes[..written])?;
        Ok(u32::from(copied))
    }
}

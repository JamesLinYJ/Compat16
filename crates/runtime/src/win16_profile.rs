//! Guest buffers for Win16 profile string APIs.

use guest_core::memory::Memory;
use win16_abi::Win16OutputBuffer;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn private_profile_path(
        &self, filename: Option<&[u8]>, host: &impl RuntimeHost,
    ) -> Result<crate::Win16ProfilePath, RuntimeError> {
        use crate::Win16ProfilePath as Path;
        let Some(bytes) = filename else { return Ok(Path::System); };
        let text = match host.decode_win16_ansi(bytes) {
            Ok(text) => text,
            Err(error) if matches!(error.kind(), Kind::InvalidInput | Kind::GuestFault) =>
                return Ok(Path::Invalid),
            Err(error) => return Err(error),
        };
        if text.is_empty() { return Ok(Path::Invalid); }
        // The SDK places a bare INI filename in the Windows directory. An
        // explicit relative path (including .\) uses the task's DOS cwd.
        if !text.contains(['\\', '/', ':']) { return Ok(Path::WindowsDirectory(text)); }
        Ok(match self.legacy_file_path(bytes, host)? {
            Some(path) => Path::File(path), None => Path::Invalid,
        })
    }

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
        let filename = self.private_profile_path(filename, host)?;
        let (bytes, copied) = host.win16_profile_string(
            section, key, default_value, &filename, output.capacity,
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

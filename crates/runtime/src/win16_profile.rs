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
        // Programmer's Reference Volume 2: a name that is not a full path is
        // in the Windows directory, including a relative name such as
        // `dir\app.ini`. Drive, root, and UNC paths keep the DOS resolver.
        // Classification uses the decoded string, so a DBCS trail 0x5c is not
        // a path separator.
        if profile_path_is_outside_windows_directory(&text) {
            return Ok(match self.legacy_file_path(bytes, host)? {
                Some(path) => Path::File(path),
                None => Path::Invalid,
            });
        }
        Ok(Path::WindowsDirectory(text))
    }

    pub(super) fn profile_string(
        &self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        default_value: Option<&[u8]>,
        filename: Option<&[u8]>,
        output: Option<Win16OutputBuffer>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if section.is_none() {
            return self.absent_section_string(output, memory);
        }
        let Some(output) = output else { return Ok(0); };
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
        output: Option<Win16OutputBuffer>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if section.is_none() {
            return self.absent_section_string(output, memory);
        }
        let Some(output) = output else { return Ok(0); };
        let (bytes, copied) = host.win16_system_profile_string(
            section, key, default_value, output.capacity,
        )?;
        self.write_profile_result(section, key, output, &bytes, copied, memory)
    }

    /// KERNEL.142 and KERNEL.143. A null section on the string APIs is not
    /// this query, so enumeration stays on its own path.
    pub(super) fn profile_section_names(
        &self,
        filename: Option<&[u8]>,
        output: Option<Win16OutputBuffer>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        system: bool,
    ) -> Result<u32, RuntimeError> {
        let Some(output) = output else {
            return Ok(0);
        };
        let (bytes, copied) = if system {
            host.win16_system_profile_string(None, None, None, output.capacity)?
        } else {
            let filename = self.private_profile_path(filename, host)?;
            host.win16_profile_string(None, None, None, &filename, output.capacity)?
        };
        self.write_profile_result(None, None, output, &bytes, copied, memory)
    }

    /// A null section on `GetProfileString` or `GetPrivateProfileString`
    /// returns zero. A positive buffer receives one NUL and nothing else.
    fn absent_section_string(
        &self,
        output: Option<Win16OutputBuffer>,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let Some(output) = output else {
            return Ok(0);
        };
        self.write_output(memory, output, &[0])?;
        Ok(0)
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

/// A rooted or drive-qualified profile name is not looked up in the Windows
/// directory. The text is already ANSI-decoded, so only a real separator or
/// drive colon matches.
fn profile_path_is_outside_windows_directory(text: &str) -> bool {
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some('\\' | '/'), _) => true,
        (Some(drive), Some(':')) if drive.is_ascii_alphabetic() => true,
        _ => false,
    }
}

#[cfg(test)]
#[path = "win16_profile_contract_tests.rs"]
mod contract_tests;

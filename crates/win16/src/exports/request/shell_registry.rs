//! Typed requests for the SHELL DLL's Win16 registry API.

use guest_core::GuestMemory;

use crate::strings::read_ansi_z;
use crate::{SelectorTable, Win16Argument, Win16Error};

const MAX_WIN16_STRING_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ShellRegistryRequest {
    OpenKey {
        root: u32,
        subkey: Vec<u8>,
        output: u32,
    },
    CreateKey {
        root: u32,
        subkey: Vec<u8>,
        output: u32,
    },
    CloseKey {
        key: u32,
    },
    DeleteKey {
        root: u32,
        subkey: Vec<u8>,
    },
    SetValue {
        key: u32,
        subkey: Vec<u8>,
        value_type: u32,
        value: Option<Vec<u8>>,
    },
    QueryValue {
        key: u32,
        subkey: Vec<u8>,
        output: u32,
        byte_count: u32,
        byte_count_output: u32,
    },
    EnumKey {
        key: u32,
        index: u32,
        output: u32,
        capacity: u32,
    },
}

/// Decode the known SHELL registry exports by exact ordinal. Pointer fields
/// remain guest FAR values for runtime-side preflight and transactional output.
impl Win16ShellRegistryRequest {
    /// Decode the Windows 3.1 SHELL API (including its NULL-data convention).
    pub fn decode_export(
        ordinal: u16,
        arguments: &[Win16Argument],
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
    ) -> Result<Win16ShellRegistryRequest, Win16Error> {
        Self::decode(ordinal, arguments, selectors, memory, true)
    }

    /// KERNEL's 216..224 registry exports are Win32 registry thunks, rather
    /// than SHELL aliases. Share memory decoding but preserve NULL data.
    pub fn decode_kernel_export(
        ordinal: u16,
        arguments: &[Win16Argument],
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
    ) -> Result<Win16ShellRegistryRequest, Win16Error> {
        let ordinal = match ordinal {
            216 => 7,
            217 => 1,
            218 => 2,
            219 => 4,
            220 => 3,
            221 => 5,
            224 => 6,
            _ => return Err(Win16Error::InvalidRange),
        };
        Self::decode(ordinal, arguments, selectors, memory, false)
    }

    fn decode(
        ordinal: u16,
        arguments: &[Win16Argument],
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
        win31: bool,
    ) -> Result<Win16ShellRegistryRequest, Win16Error> {
        let request = match ordinal {
            1 => Win16ShellRegistryRequest::OpenKey {
                root: dword(arguments, 0)?,
                subkey: optional_string(dword(arguments, 1)?, selectors, memory)?,
                output: dword(arguments, 2)?,
            },
            2 => Win16ShellRegistryRequest::CreateKey {
                root: dword(arguments, 0)?,
                subkey: optional_string(dword(arguments, 1)?, selectors, memory)?,
                output: dword(arguments, 2)?,
            },
            3 => Win16ShellRegistryRequest::CloseKey {
                key: dword(arguments, 0)?,
            },
            4 => Win16ShellRegistryRequest::DeleteKey {
                root: dword(arguments, 0)?,
                subkey: optional_string(dword(arguments, 1)?, selectors, memory)?,
            },
            5 => {
                let value_type = dword(arguments, 2)?;
                // Win3.1 RegSetValue ignores cbData, including zero and DWORD_MAX.
                // Reject other types before dereferencing either string, as WOW
                // WS32RegSetValue does. A NULL data pointer denotes the text "0".
                let _ignored_count = dword(arguments, 4)?;
                let (subkey, value) = if value_type != 1 {
                    (Vec::new(), None)
                } else {
                    let far = dword(arguments, 3)?;
                    (
                        optional_string(dword(arguments, 1)?, selectors, memory)?,
                        if far == 0 {
                            win31.then(|| b"0".to_vec())
                        } else {
                            Some(read_ansi_z(selectors, memory, far, MAX_WIN16_STRING_BYTES)?)
                        },
                    )
                };
                Win16ShellRegistryRequest::SetValue {
                    key: dword(arguments, 0)?,
                    subkey,
                    value_type,
                    value,
                }
            }
            6 => {
                let byte_count_output = dword(arguments, 3)?;
                // SHELL rejects NULL lpcbData before inspecting either string
                // or output. KERNEL preserves the native optional-pointer API.
                let subkey = if win31 && byte_count_output == 0 {
                    Vec::new()
                } else {
                    optional_string(dword(arguments, 1)?, selectors, memory)?
                };
                let byte_count = if byte_count_output == 0 { 0 } else {
                    read_u32_far(byte_count_output, selectors, memory)?
                };
                Win16ShellRegistryRequest::QueryValue {
                    key: dword(arguments, 0)?,
                    subkey,
                    output: dword(arguments, 2)?,
                    byte_count,
                    byte_count_output,
                }
            }
            7 => Win16ShellRegistryRequest::EnumKey {
                key: dword(arguments, 0)?,
                index: dword(arguments, 1)?,
                output: dword(arguments, 2)?,
                capacity: dword(arguments, 3)?,
            },
            _ => return Err(Win16Error::InvalidRange),
        };
        Ok(request)
    }
}

fn optional_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    if far == 0 {
        Ok(Vec::new())
    } else {
        read_ansi_z(selectors, memory, far, MAX_WIN16_STRING_BYTES)
    }
}

fn read_u32_far(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<u32, Win16Error> {
    let mut bytes = [0_u8; 4];
    selectors.read(memory, selectors.pointer_from_far(far)?, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

#[cfg(test)]
#[path = "shell_registry_tests.rs"]
mod tests;

//! Safe extent checks for a Win16 version-information block.
//!
//! `VerQueryValue` accepts any caller-supplied version block, including one
//! copied from a resource. It does not require that `GetFileVersionInfo`
//! produced the block. The `VS_VERSION_INFO.wLength` WORD bounds the owned copy
//! passed to the bounded host codec; selector permissions and the available
//! guest range are checked by the runtime before this helper is called.

#[path = "win16_ver_codec.rs"]
mod codec;

pub use codec::{
    query_win16_ansi,
    transcode_win32_to_win16_ansi,
    TranscodeError as VersionInfoTranscodeError,
    VersionBlockError,
    VersionQueryValue,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionInfoExtentError {
    HeaderTooShort,
    InvalidLength(u16),
    ExceedsGuestRange { declared: u16, available: usize },
}

impl std::fmt::Display for VersionInfoExtentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderTooShort => f.write_str("Win16 version-information header is truncated"),
            Self::InvalidLength(length) => write!(f, "Win16 version-information length {length} is invalid"),
            Self::ExceedsGuestRange { declared, available } => write!(
                f,
                "Win16 version-information block length {declared} exceeds the checked guest range {available}"
            ),
        }
    }
}

impl std::error::Error for VersionInfoExtentError {}

/// Read the root `VS_VERSION_INFO.wLength` from its first two guest bytes and
/// ensure the complete version block lies within the already-checked selector
/// range. A Win16 node starts with two little-endian WORD fields.
pub fn version_info_extent(
    header: &[u8],
    available: usize,
) -> Result<usize, VersionInfoExtentError> {
    if header.len() < 2 {
        return Err(VersionInfoExtentError::HeaderTooShort);
    }
    let declared = u16::from_le_bytes([header[0], header[1]]);
    if declared < 4 {
        return Err(VersionInfoExtentError::InvalidLength(declared));
    }
    let length = usize::from(declared);
    if length > available {
        return Err(VersionInfoExtentError::ExceedsGuestRange { declared, available });
    }
    Ok(length)
}

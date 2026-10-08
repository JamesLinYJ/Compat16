//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelProfilesRequest {
    GetPrivateProfileInt {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        default_value: i16,
        filename: Option<Vec<u8>>,
    },

    GetPrivateProfileString {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        default_value: Option<Vec<u8>>,
        output_buffer: Win16OutputBuffer,
        filename: Option<Vec<u8>>,
    },

    /// Read from the host's Win.ini profile mapping through the Windows
    /// GetProfileString API. Nullable input strings preserve section/key
    /// enumeration semantics and the default-string contract.
    GetProfileString {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        default_value: Option<Vec<u8>>,
        output_buffer: Win16OutputBuffer,
    },

    WritePrivateProfileString {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        value: Option<Vec<u8>>,
        filename: Option<Vec<u8>>,
    },

    /// Read an integer from the host's Win.ini profile mapping through the
    /// Windows GetProfileInt API. Nullable guest strings remain explicit so
    /// the host adapter can preserve the native call's pointer semantics.
    GetProfileInt {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        default_value: i16,
    },
}

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

    /// `output_buffer` is absent when `cbReturnBuffer` is not a positive int.
    /// That call copies nothing and does not read the guest pointer.
    GetPrivateProfileString {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        default_value: Option<Vec<u8>>,
        output_buffer: Option<Win16OutputBuffer>,
        filename: Option<Vec<u8>>,
    },

    /// Read from the host's Win.ini profile mapping. A null key enumerates
    /// key names. A null section is not an enumeration; KERNEL.142 is.
    /// `output_buffer` is absent when `cbReturnBuffer` is not a positive int.
    GetProfileString {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        default_value: Option<Vec<u8>>,
        output_buffer: Option<Win16OutputBuffer>,
    },

    /// KERNEL.142. A null section on `GetProfileString` is not this query.
    GetProfileSectionNames {
        output_buffer: Option<Win16OutputBuffer>,
    },

    /// KERNEL.143. A null section on `GetPrivateProfileString` is not this query.
    GetPrivateProfileSectionNames {
        output_buffer: Option<Win16OutputBuffer>,
        filename: Option<Vec<u8>>,
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

    /// Opaque guest bytes. A null key or null data pointer is forwarded
    /// without reading a payload. Strings stay the caller's ANSI/DBCS bytes.
    WritePrivateProfileStruct {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        data: Option<Vec<u8>>,
        data_size: u16,
        filename: Option<Vec<u8>>,
    },

    /// `output` stays raw so a null pointer can fail before any guest write.
    GetPrivateProfileStruct {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        output: u32,
        capacity: u16,
        filename: Option<Vec<u8>>,
    },
}

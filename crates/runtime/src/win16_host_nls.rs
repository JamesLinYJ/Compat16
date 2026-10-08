//! Owned host-boundary values for Win16 OLE2NLS calls.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16NlsString {
    pub bytes: Vec<u8>,
    pub declared_count: i16,
    pub is_null: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16NlsOperation {
    GetUserDefaultLcid,
    GetSystemDefaultLcid,
    GetUserDefaultLangId,
    GetSystemDefaultLangId,
    GetLocaleInfoA { lcid: u32, info_type: u32, capacity: u16 },
    LcMapStringA {
        lcid: u32,
        flags: u32,
        source: Win16NlsString,
        destination_capacity: u16,
    },
    GetStringTypeA { lcid: u32, info_type: u32, source: Win16NlsString },
    CompareStringA { lcid: u32, flags: u32, left: Win16NlsString, right: Win16NlsString },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16NlsHostResult {
    Scalar(u32),
    Buffer { result: i32, bytes: Vec<u8> },
    /// On success, `values` has exactly one entry per UTF-16 unit produced
    /// by converting the owned ANSI source with its locale code page.
    StringTypes { result: i32, values: Vec<u16> },
}

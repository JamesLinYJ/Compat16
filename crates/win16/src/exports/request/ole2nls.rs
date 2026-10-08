//! Owned Win16 OLE2NLS calls. Guest addresses remain selector:offset values.

use crate::SegmentedPointer;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16Ole2NlsString {
    pub bytes: Vec<u8>,
    pub declared_count: i16,
    pub is_null: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16Ole2NlsRequest {
    GetUserDefaultLcid,
    GetSystemDefaultLcid,
    GetUserDefaultLangId,
    GetSystemDefaultLangId,
    GetLocaleInfoA {
        lcid: u32,
        info_type: u32,
        output: Option<SegmentedPointer>,
        capacity: u16,
    },
    LcMapStringA {
        lcid: u32,
        flags: u32,
        source: Win16Ole2NlsString,
        destination: Option<SegmentedPointer>,
        destination_capacity: u16,
    },
    GetStringTypeA {
        lcid: u32,
        info_type: u32,
        source: Win16Ole2NlsString,
        output: Option<SegmentedPointer>,
    },
    CompareStringA {
        lcid: u32,
        flags: u32,
        left: Win16Ole2NlsString,
        right: Win16Ole2NlsString,
    },
}

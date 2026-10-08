//! Owned host boundary for direct Win16 Audio Compression Manager calls.
//!
//! Format/filter images are copied Win16 bytes. Native handles and records
//! are reconstructed in the host adapter and never cross this interface.

use std::{error::Error, fmt};

/// Native ACM operation named by a retained MMRESULT failure cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostAcmNativeOperation {
    DriverEnum,
    FormatTagEnum,
    FilterTagEnum,
    FormatEnum,
    FilterEnum,
    StreamUnprepareHeader,
    StreamClose,
    DriverClose,
    DriverRemove,
    DriverIdRelease,
}

impl fmt::Display for Win16HostAcmNativeOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::DriverEnum => "acmDriverEnum",
            Self::FormatTagEnum => "acmFormatTagEnumA",
            Self::FilterTagEnum => "acmFilterTagEnumA",
            Self::FormatEnum => "acmFormatEnumA",
            Self::FilterEnum => "acmFilterEnumA",
            Self::StreamUnprepareHeader => "acmStreamUnprepareHeader",
            Self::StreamClose => "acmStreamClose",
            Self::DriverClose => "acmDriverClose",
            Self::DriverRemove => "acmDriverRemove",
            Self::DriverIdRelease => "ACM enumeration driver-identity release",
        };
        formatter.write_str(name)
    }
}

/// Operation and ordinary result code retained when native cleanup fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostAcmNativeFailure {
    operation: Win16HostAcmNativeOperation,
    result: u32,
}

impl Win16HostAcmNativeFailure {
    pub const fn new(operation: Win16HostAcmNativeOperation, result: u32) -> Self {
        Self { operation, result }
    }

    pub const fn operation(self) -> Win16HostAcmNativeOperation { self.operation }
    pub const fn result(self) -> u32 { self.result }
}

impl fmt::Display for Win16HostAcmNativeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} returned MMRESULT {:#x}", self.operation, self.result)
    }
}

impl Error for Win16HostAcmNativeFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostAcmHandle {
    token: u64,
    generation: u32,
}

impl Win16HostAcmHandle {
    /// Host-created identity; its parts are opaque to the runtime consumer.
    pub const fn new(token: u64, generation: u32) -> Self { Self { token, generation } }
    pub const fn token(self) -> u64 { self.token }
    pub const fn generation(self) -> u32 { self.generation }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostAcmObjectKind { DriverId, Driver, Stream }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostAcmTagKind { Format, Filter }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostAcmDetailQuery {
    Index { index: u32, tag: u32 },
    Tag(u32),
    Largest { tag: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostAcmDriverDetails {
    pub type_fourcc: u32,
    pub compression_fourcc: u32,
    pub manufacturer_id: u16,
    pub product_id: u16,
    pub acm_version: u32,
    pub driver_version: u32,
    pub support: u32,
    pub format_tag_count: u32,
    pub filter_tag_count: u32,
    pub icon: Option<crate::Win16HostIcon>,
    pub short_name: [u8; 32],
    pub long_name: [u8; 128],
    pub copyright: [u8; 80],
    pub licensing: [u8; 128],
    pub features: [u8; 512],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostAcmTagDetails {
    pub index: u32,
    pub tag: u32,
    pub data_bytes: u32,
    pub support: u32,
    pub standard_count: u32,
    pub name: [u8; 48],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostAcmItemDetails {
    pub index: u32,
    pub tag: u32,
    pub support: u32,
    pub name: [u8; 128],
    /// Complete owned Win16 WAVEFORMATEX or WAVEFILTER image.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostAcmEnumerationRecord {
    Driver { driver_id: Win16HostAcmHandle, support: u32 },
    Tag { driver_id: Win16HostAcmHandle, support: u32, details: Win16HostAcmTagDetails },
    Item { driver_id: Win16HostAcmHandle, support: u32, details: Win16HostAcmItemDetails },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostAcmChooseKind { Format, Filter }

#[derive(Debug)]
pub enum Win16HostAcmOperation {
    GetVersion,
    Metrics { object: Option<(Win16HostAcmObjectKind, Win16HostAcmHandle)>, metric: u16 },
    DriverEnum { instance: u32, flags: u32 },
    DriverAdd { module_instance: u16, name: Option<Vec<u8>>, priority: u32, flags: u32 },
    DriverRemove { driver_id: Win16HostAcmHandle, flags: u32 },
    /// Retire only a host-side borrowed identity created by enumeration or
    /// acmDriverID. Added driver IDs require the real acmDriverRemove path.
    DriverIdRelease { driver_id: Win16HostAcmHandle },
    DriverOpen { driver_id: Win16HostAcmHandle, flags: u32 },
    DriverClose { driver: Win16HostAcmHandle, flags: u32 },
    DriverId { object_kind: Win16HostAcmObjectKind, object: Win16HostAcmHandle, flags: u32 },
    DriverPriority { driver_id: Win16HostAcmHandle, priority: u32, flags: u32 },
    /// The host adapter only forwards documented scalar ACM messages; an
    /// unclassified message returns MMSYSERR_NOTSUPPORTED there.
    DriverMessage { driver: Win16HostAcmHandle, message: u16, param1: u32, param2: u32 },
    DriverDetails { driver_id: Win16HostAcmHandle, flags: u32 },
    TagDetails {
        kind: Win16HostAcmTagKind,
        driver: Option<(Win16HostAcmObjectKind, Win16HostAcmHandle)>,
        query: Win16HostAcmDetailQuery,
        initial: Win16HostAcmTagDetails,
    },
    TagEnum {
        kind: Win16HostAcmTagKind,
        driver: Option<Win16HostAcmHandle>,
        template: Win16HostAcmTagDetails,
        instance: u32,
        flags: u32,
    },
    ItemDetails {
        kind: Win16HostAcmTagKind,
        driver: Option<Win16HostAcmHandle>,
        query: Win16HostAcmDetailQuery,
        initial: Win16HostAcmItemDetails,
        capacity: u32,
    },
    ItemEnum {
        kind: Win16HostAcmTagKind,
        driver: Option<Win16HostAcmHandle>,
        template: Win16HostAcmItemDetails,
        capacity: u32,
        instance: u32,
        flags: u32,
    },
    FormatSuggest {
        driver: Option<Win16HostAcmHandle>,
        source: Vec<u8>,
        destination: Vec<u8>,
        flags: u32,
    },
    Choose {
        kind: Win16HostAcmChooseKind,
        owner: Option<crate::Win16HostWindow>,
        style: u32,
        data: Vec<u8>,
        /// Guest-declared pwfx/pwfltr output-buffer capacity.
        data_capacity: u32,
        title: Option<Vec<u8>>,
        tag_name: [u8; 48],
        item_name: [u8; 128],
        /// `None` means pszName was NULL; `Some` is the complete cchName buffer.
        saved_name: Option<Vec<u8>>,
        saved_name_capacity: u32,
        enum_flags: u32,
        enum_data: Vec<u8>,
    },
    StreamOpen {
        driver: Option<Win16HostAcmHandle>,
        source: Vec<u8>,
        destination: Vec<u8>,
        filter: Option<Vec<u8>>,
        flags: u32,
        query_only: bool,
    },
    StreamClose { stream: Win16HostAcmHandle, flags: u32 },
    StreamSize { stream: Win16HostAcmHandle, input_bytes: u32, flags: u32 },
    StreamPrepareHeader {
        stream: Win16HostAcmHandle,
        header_token: u64,
        flags: u32,
        status: u32,
        user: u32,
        source_user: u32,
        destination_user: u32,
        source: Vec<u8>,
        destination: Vec<u8>,
        reserved: [u32; 10],
    },
    StreamUnprepareHeader { stream: Win16HostAcmHandle, header_token: u64, flags: u32 },
    StreamConvert {
        stream: Win16HostAcmHandle,
        header_token: u64,
        source: Vec<u8>,
        destination: Vec<u8>,
        flags: u32,
    },
    StreamReset { stream: Win16HostAcmHandle, flags: u32 },
}

#[derive(Debug)]
pub enum Win16HostAcmResult {
    Scalar(u32),
    Metric { result: u32, value: u32 },
    Handle { result: u32, handle: Option<Win16HostAcmHandle> },
    Enumerated { result: u32, records: Vec<Win16HostAcmEnumerationRecord> },
    DriverDetails { result: u32, details: Win16HostAcmDriverDetails },
    TagDetails { result: u32, details: Win16HostAcmTagDetails },
    ItemDetails { result: u32, details: Win16HostAcmItemDetails },
    FormatSuggest { result: u32, destination: Vec<u8> },
    Chosen {
        result: u32,
        data: Vec<u8>,
        /// Native cbwfx/cbwfltr after return, including required size on
        /// ACMERR_NOTPOSSIBLE.
        data_bytes: u32,
        tag_name: [u8; 48],
        item_name: [u8; 128],
        /// `None` means pszName was NULL; `Some` owns the full cchName buffer.
        saved_name: Option<Vec<u8>>,
    },
    StreamSize { result: u32, output_bytes: u32 },
    StreamOpened { result: u32, stream: Option<Win16HostAcmHandle> },
    StreamHeader {
        result: u32,
        status: u32,
        /// True only when a native unprepare call on the exact retained
        /// header returned with PREPARED clear. A scalar result or cleared
        /// status alone is not an ownership-retirement receipt.
        header_retired: bool,
        source_used: u32,
        destination_used: u32,
        destination: Vec<u8>,
        reserved: [u32; 10],
    },
}

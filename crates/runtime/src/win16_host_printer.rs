//! Owned printer-query values; guest pointers never reach native drivers.

use crate::{Win16DrawingPoint, Win16HostDevMode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16PrinterCapabilities {
    pub device: Option<Vec<u8>>,
    pub port: Option<Vec<u8>>,
    pub index: u16,
    /// NULL guest output requests only the scalar value or item count.
    pub collect_output: bool,
    pub devmode: Option<Win16HostDevMode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16PrinterCapabilityData {
    Words(Vec<u16>),
    /// Host POINT coordinates are narrowed by the guest wire codec.
    Points(Vec<Win16DrawingPoint>),
    ResolutionPairs(Vec<[i32; 2]>),
    /// ANSI names occupy fixed records, including fully filled records
    /// without a NUL terminator. Do not reinterpret them as C strings.
    Names { record_bytes: u16, bytes: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16PrinterCapabilitiesResult {
    /// Win16 DeviceCapabilities returns DWORD, including raw -1 failure.
    pub value: u32,
    pub output: Option<Win16PrinterCapabilityData>,
}

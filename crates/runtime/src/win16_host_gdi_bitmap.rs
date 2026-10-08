//! Owned bitmap-data requests crossing from Win16 GDI to native Windows.

use crate::{Win16HostDc, Win16HostGdiObject};

/// Bitmap operations whose inputs or outputs include variable-sized DIB data.
/// Guest FAR pointers are resolved and copied by the runtime before requests
/// cross this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiBitmapOperation {
    SetBitmapBits {
        bitmap: Win16HostGdiObject,
        bytes: Vec<u8>,
    },
    GetBitmapBits {
        bitmap: Win16HostGdiObject,
        capacity: usize,
    },
    SetDibits {
        bitmap: Win16HostGdiObject,
        dc: Win16HostDc,
        start_scan: u16,
        scan_lines: u16,
        info: Option<Vec<u8>>,
        bits: Option<Vec<u8>>,
        color_usage: u32,
    },
    GetDibits {
        bitmap: Win16HostGdiObject,
        dc: Win16HostDc,
        start_scan: u16,
        scan_lines: u16,
        info: Option<Vec<u8>>,
        bits: Option<Vec<u8>>,
        color_usage: u32,
    },
    SetDibitsToDevice {
        dc: Win16HostDc,
        destination_x: i32,
        destination_y: i32,
        width: i32,
        height: i32,
        source_x: i32,
        source_y: i32,
        start_scan: u16,
        scan_lines: u16,
        info: Option<Vec<u8>>,
        bits: Option<Vec<u8>>,
        color_usage: u32,
    },
}

/// Native bitmap API result. GetDibits returns its updated buffers even when
/// the native line count is zero, preserving any writes made before failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiBitmapResult {
    Count(i32),
    GetBitmapBits { count: i32, bytes: Vec<u8> },
    GetDibits {
        count: i32,
        info: Option<Vec<u8>>,
        bits: Option<Vec<u8>>,
    },
}

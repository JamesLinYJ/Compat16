//! Owned Win16 MMSYSTEM MCI requests and target SDK parameter projections.

use crate::{SegmentedPointer, window_geometry::Rect16};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MciRequest {
    SendCommand {
        device_id: u16,
        message: u16,
        flags: u32,
        parameter_far: u32,
        /// Output bytes are tied to the selector identity captured at decode.
        parameter_output: Option<Win16MciGuestRange>,
        /// Alias reserved before native MCI_OPEN so host success cannot
        /// outlive an allocation failure while publishing the returned ID.
        reserved_device_id: Option<u16>,
        parameters: Win16MciParameters,
    },
    SendString {
        command: Vec<u8>,
        output: Win16MciOutputBuffer,
        callback_window: u16,
        /// Reserved only for the MCI `open ... alias name` string form.
        reserved_device_id: Option<u16>,
    },
    GetDeviceId {
        name: Vec<u8>,
    },
    LoadCommandResource {
        instance: u16,
        resource: Win16MciResourceName,
        resource_type: u16,
    },
    GetErrorString {
        error: u32,
        output: Win16MciOutputBuffer,
    },
    SetDriverData {
        device_id: u16,
        data: u32,
    },
    GetDriverData {
        device_id: u16,
    },
    DriverYield {
        device_id: u16,
    },
    DriverNotify {
        window: u16,
        device_id: u16,
        status: u16,
    },
    Execute {
        command: Vec<u8>,
        /// Reserved before an `open ... alias ...` command string can create a
        /// native device, just like the `mciSendString` entry point.
        reserved_device_id: Option<u16>,
    },
    FreeCommandResource {
        resource_id: u16,
    },
    SetYieldProc {
        device_id: u16,
        procedure: u32,
        /// Selector generation captured with the FAR callback before native
        /// registration. A later raw selector reuse cannot retarget the call.
        procedure_pointer: Option<crate::SegmentedPointer>,
        data: u32,
    },
    GetDeviceIdFromElement {
        element_id: u32,
        device_type: Vec<u8>,
    },
    GetYieldProc {
        device_id: u16,
        data_output: Option<Win16MciGuestRange>,
    },
    GetCreatorTask {
        device_id: u16,
    },
}

/// Guest output ranges remain FAR values until runtime selector validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MciOutputBuffer {
    pub far: u32,
    pub capacity: u32,
    /// The exact live selector generation and start offset validated at decode.
    pub range: Option<Win16MciGuestRange>,
}

/// Checked single-selector guest range retained across native continuations.
/// Raw FAR values can be reused by the guest, so asynchronous output must use
/// this captured SelectorRef rather than resolving the selector word again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MciGuestRange {
    pub pointer: SegmentedPointer,
    pub length: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MciResourceName {
    Id(u16),
    Name(Vec<u8>),
}

/// MCI parameter layouts established by SDK 3.1 MMSYSTEM.H. Unknown command
/// layouts are represented without reading the guest block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MciParameters {
    Null,
    Generic {
        callback: u32,
    },
    Open {
        callback: u32,
        device_type: Option<Win16MciOpenValue>,
        element: Option<Win16MciOpenValue>,
        alias: Option<Vec<u8>>,
        extension: Win16MciOpenExtension,
    },
    Play {
        callback: u32,
        from: u32,
        to: u32,
        /// Retained so runtime can read the optional DWORD only after resolving
        /// the device family that owns the overlapping SDK speed flags.
        parameter_pointer: SegmentedPointer,
    },
    Seek {
        callback: u32,
        to: u32,
    },
    Status {
        callback: u32,
        item: u32,
        track: u32,
        returned: u32,
    },
    Info {
        callback: u32,
        output: Win16MciOutputBuffer,
        item: u32,
    },
    GetDeviceCaps {
        callback: u32,
        item: u32,
        returned: u32,
    },
    SystemInfo {
        callback: u32,
        output: Win16MciOutputBuffer,
        item: u32,
        number: u32,
        device_type: u16,
    },
    Set {
        callback: u32,
        time_format: u32,
        audio: u32,
        extension: Win16MciSetExtension,
    },
    Record {
        callback: u32,
        from: u32,
        to: u32,
    },
    Break {
        callback: u32,
        virtual_key: u16,
        window: u16,
    },
    File {
        callback: u32,
        filename: Vec<u8>,
        /// SAVE/LOAD block retained by selector generation for device-specific
        /// Win16 layouts such as the overlay RECT tail.
        parameter_pointer: SegmentedPointer,
    },
    Sound {
        callback: u32,
        name: Vec<u8>,
    },
    Step {
        callback: u32,
        frames: u32,
    },
    Escape {
        callback: u32,
        command: Vec<u8>,
    },
    Window {
        callback: u32,
        window: u16,
        show_command: u16,
        text: Option<Vec<u8>>,
    },
    Rectangle {
        callback: u32,
        rectangle: Rect16,
        output: bool,
    },
    Delete {
        callback: u32,
        from: u32,
        to: u32,
    },
    /// The layout is known, but it includes a native object/window value for
    /// which no safe Win16-to-Windows handle bridge exists.
    UnsupportedHandle {
        message: u16,
        flags: u32,
    },
    Unsupported {
        message: u16,
        flags: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MciOpenValue {
    Ansi(Vec<u8>),
    ResourceId(u32),
    ElementId(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MciOpenExtension {
    None,
    Wave { buffer_seconds: u32 },
    Window { style: u32, parent_window: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MciSetExtension {
    None,
    /// WAVE_SET and SEQ_SET reuse the same flag values. The decoder keeps the
    /// guest FAR local so runtime can choose the exact documented record from
    /// the already-open device type without reading the wrong extent.
    DeviceSpecific {
        parameter_far: u32,
        flags: u32,
    },
    Wave {
        input: u16,
        output: u16,
        format_tag: u16,
        channels: u16,
        samples_per_second: u32,
        average_bytes_per_second: u32,
        block_align: u16,
        bits_per_sample: u16,
    },
    Sequencer {
        tempo: u32,
        port: u32,
        slave: u32,
        master: u32,
        offset: u32,
    },
}

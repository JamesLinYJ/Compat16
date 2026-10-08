//! Byte-aligned little-endian MCI records used by the Win16 decoder.
//!
//! SDK 3.1 parameter blocks contain guest pointers and WORD/DWORD fields with
//! compiler-specific aggregate alignment. These private layouts fix each
//! adopted field offset and let zerocopy validate the complete record before
//! the decoder projects any pointer or output field. They intentionally do not
//! mirror host pointer width.

use zerocopy::byteorder::little_endian::{I16, U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

macro_rules! wire_record {
    ($name:ident { $($field:ident : $ty:ty),+ $(,)? } = $size:expr) => {
        #[repr(C)]
        #[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
        pub(super) struct $name { $(pub(super) $field: $ty),+ }

        const _: () = {
            assert!(core::mem::size_of::<$name>() == $size);
            assert!(core::mem::align_of::<$name>() == 1);
        };
    };
}

wire_record!(Generic { callback: U32 } = 4);
wire_record!(
    Open {
        callback: U32,
        device_id: U16,
        reserved: U16,
        device_type: U32,
        element: U32,
        alias: U32,
    } = 20
);
wire_record!(
    WaveOpen {
        callback: U32,
        device_id: U16,
        reserved: U16,
        device_type: U32,
        element: U32,
        alias: U32,
        buffer_seconds: U32,
    } = 24
);
wire_record!(
    WindowOpen {
        callback: U32,
        device_id: U16,
        reserved: U16,
        device_type: U32,
        element: U32,
        alias: U32,
        style: U32,
        parent_window: U16,
        trailing: U16,
    } = 28
);
wire_record!(
    Play {
        callback: U32,
        from: U32,
        to: U32
    } = 12
);
wire_record!(
    PlaySpeed {
        callback: U32,
        from: U32,
        to: U32,
        speed: U32
    } = 16
);
wire_record!(
    Seek {
        callback: U32,
        to: U32
    } = 8
);
wire_record!(
    Status {
        callback: U32,
        returned: U32,
        item: U32,
        track: U32
    } = 16
);
wire_record!(
    Info {
        callback: U32,
        output: U32,
        capacity: U32
    } = 12
);
wire_record!(
    GetDeviceCaps {
        callback: U32,
        returned: U32,
        item: U32
    } = 12
);
wire_record!(
    SystemInfo {
        callback: U32,
        output: U32,
        capacity: U32,
        number: U32,
        device_type: U16,
        reserved: U16,
    } = 20
);
wire_record!(
    Set {
        callback: U32,
        time_format: U32,
        audio: U32
    } = 12
);
wire_record!(
    Record {
        callback: U32,
        from: U32,
        to: U32
    } = 12
);
wire_record!(
    Break {
        callback: U32,
        virtual_key: U16,
        reserved: U16,
        window: U16,
        trailing: U16,
    } = 12
);
wire_record!(
    File {
        callback: U32,
        filename: U32
    } = 8
);
wire_record!(
    OverlayFile {
        callback: U32,
        filename: U32,
        left: I16,
        top: I16,
        right: I16,
        bottom: I16,
    } = 16
);
wire_record!(
    Step {
        callback: U32,
        frames: U32
    } = 8
);
wire_record!(
    Window {
        callback: U32,
        window: U16,
        reserved: U16,
        show_command: U16,
        trailing: U16,
        text: U32,
    } = 16
);
wire_record!(
    Rect {
        callback: U32,
        left: I16,
        top: I16,
        right: I16,
        bottom: I16
    } = 12
);
wire_record!(
    Delete {
        callback: U32,
        from: U32,
        to: U32
    } = 12
);

pub(super) fn read<T: FromBytes + KnownLayout + Immutable>(
    bytes: &[u8],
) -> Result<&T, zerocopy::CastError<&[u8], T>> {
    T::ref_from_bytes(bytes)
}

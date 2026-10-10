//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserGeometryRequest {
    /// Write the desktop cursor location into a checked guest POINT16.
    GetCursorPos { point: u32 },
    /// Read the desktop cursor clipping rectangle into a checked RECT16.
    GetClipCursor { rect: u32 },
    GetWindowPlacement { window: u16, placement: u32 },
    SetWindowPlacement { window: u16, placement: u32 },
    /// Fill a checked guest RECT16 output through the raw FAR address.
    GetWindowRect {
        window: u16,
        rect: u32,
    },

    /// Fill a checked guest RECT16 output through the raw FAR address.
    GetClientRect {
        window: u16,
        rect: u32,
    },

    /// Convert a guest POINT16 in place; runtime owns its range validation/writeback.
    ClientToScreen {
        window: u16,
        point: u32,
    },

    /// Convert a guest POINT16 in place; runtime owns its range validation/writeback.
    ScreenToClient {
        window: u16,
        point: u32,
    },

    /// Convert a checked POINT16 array in place. Zero HWNDs select screen
    /// coordinates; a count of two also covers the two corners of a RECT16.
    MapWindowPoints {
        from: u16,
        to: u16,
        points: u32,
        count: u16,
    },

    /// POINT16 is supplied by value as two packed signed Win16 coordinates.
    WindowFromPoint {
        x: i16,
        y: i16,
    },

    MoveWindow {
        window: u16,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        repaint: u16,
    },

    SetWindowPos {
        window: u16,
        insert_after: u16,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        flags: u16,
    },

    /// Set a guest RECT16 from signed Win16 coordinates; USER.72 returns no value.
    SetRect {
        rect: u32,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    },

    /// Set all four edges of a checked guest RECT16 to zero. USER.73 is void
    /// in the Windows 3.1 SDK header; its export metadata does not define a
    /// meaningful AX result.
    SetRectEmpty {
        rect: u32,
    },

    /// Copy one checked guest RECT16 to another, allowing the ranges to alias.
    /// USER.74 is void in the Windows 3.1 SDK header.
    CopyRect {
        destination: u32,
        source: u32,
    },

    IsRectEmpty {
        rect: u32,
    },

    /// POINT16 is passed by value as two packed signed Win16 coordinates.
    PtInRect {
        rect: u32,
        x: i16,
        y: i16,
    },

    /// Update a guest RECT16 in place; USER.77 returns no value.
    OffsetRect {
        rect: u32,
        x: i16,
        y: i16,
    },

    /// Update a guest RECT16 in place; USER.78 returns no value.
    InflateRect {
        rect: u32,
        x: i16,
        y: i16,
    },

    /// Compute intersection into the destination RECT16 through raw guest addresses.
    IntersectRect {
        destination: u32,
        source1: u32,
        source2: u32,
    },

    /// Store the smallest rectangle containing the nonempty inputs. Both
    /// inputs are copied before the destination write, so aliases are safe.
    UnionRect {
        destination: u32,
        source1: u32,
        source2: u32,
    },

    EqualRect { source1: u32, source2: u32 },

    SubtractRect { destination: u32, source1: u32, source2: u32 },
}

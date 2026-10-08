//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserDrawingRequest {
    /// USER.81 copies an input RECT16; null is retained for a normal false result.
    FillRect {
        dc: u16,
        rect: Option<Rect16>,
        brush: u16,
    },

    InvertRect {
        dc: u16,
        rect: Option<Rect16>,
    },

    FrameRect {
        dc: u16,
        rect: Option<Rect16>,
        brush: u16,
    },

    DrawIcon {
        dc: u16,
        x: i16,
        y: i16,
        icon: u16,
    },

    DrawFocusRect {
        dc: u16,
        rect: Option<Rect16>,
    },

    /// USER.85 copies the text/initial rectangle and retains the raw rectangle
    /// address for runtime preflight and DT_CALCRECT writeback.
    DrawText {
        dc: u16,
        text: Vec<u8>,
        count: i16,
        rect: Option<Rect16>,
        rect_output: u32,
        flags: u16,
    },
}

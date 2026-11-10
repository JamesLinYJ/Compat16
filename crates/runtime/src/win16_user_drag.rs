//! USER.86 IconSize, USER.464 DragObject, and USER.465 DragDetect.
//!
//! Icon dimensions come from the Windows 3.1 `SM_CXICON` and `SM_CYICON`
//! indexes. DragDetect classifies screen samples against a four-pixel inset,
//! the published default of the later drag rectangle. The 3.1 header does not
//! publish `SM_CXDRAG`. DragObject does not send the drag messages and does
//! not turn guest window or cursor words into host pointers.

use crate::{RuntimeError, RuntimeHost, Win16DragSample};

/// Windows 3.1 `WINDOWS.H` `SM_CXICON`.
const SM_CXICON: i32 = 11;
/// Windows 3.1 `WINDOWS.H` `SM_CYICON`.
const SM_CYICON: i32 = 12;
/// Pixels from the origin to each exclusive edge. This is the published
/// default of `SM_CXDRAG` / `SM_CYDRAG`, which the 3.1 header does not define.
const DRAG_INSET: i32 = 4;
/// Distinct non-terminal samples after which a still-inside drag returns zero.
const MAX_DRAG_SAMPLES: usize = 256;

/// Pack system icon width in the low word and height in the high word.
///
/// USER.86 is absent from the Windows 3.1 header. Each half is the
/// `GetSystemMetrics` `int` for `SM_CXICON` or `SM_CYICON`. A Windows 3.1
/// `int` is signed and 16 bits wide. Learn returns 0 when `GetSystemMetrics`
/// fails, so a host metric outside -32768..=32767 is 0 in its word instead
/// of the low 16 bits. A metric that fits is unchanged, including a negative
/// value. 32768 through 65535 do not fit that signed `int`.
pub(super) fn icon_size(host: &mut impl RuntimeHost) -> Result<u32, RuntimeError> {
    let width = signed_metric_word(host.win16_get_system_metrics(SM_CXICON)?);
    let height = signed_metric_word(host.win16_get_system_metrics(SM_CYICON)?);
    Ok(u32::from(width) | (u32::from(height) << 16))
}

fn signed_metric_word(metric: i32) -> u16 {
    let Ok(metric) = i16::try_from(metric) else {
        return 0;
    };
    metric as u16
}

/// USER.464 returns zero. No sink is offered `WM_QUERYDROPOBJECT` (0x022B),
/// `WM_DRAGLOOP` (0x022D), `WM_DRAGSELECT` (0x022E), `WM_DRAGMOVE` (0x022F),
/// or `WM_DROPOBJECT` (0x022A), so there is no accepting HWND in the low word
/// and no drop result in the high word. The cursor is not changed.
pub(super) fn drag_object() -> u32 {
    0
}

/// Classify pointer samples until the button is released, Escape is down, the
/// pointer leaves the drag rectangle, a sample repeats, or the sample cap is
/// reached.
///
/// `window` is the guest HWND from the call. This slice does not capture it
/// and does not remove messages from its queue. Nonzero means the logical
/// left button was still down when the pointer left the rectangle. Escape and
/// button release return zero, including when that same sample is also outside.
pub(super) fn drag_detect(
    host: &mut impl RuntimeHost,
    _window: u16,
    origin_x: i16,
    origin_y: i16,
) -> Result<u32, RuntimeError> {
    let mut previous: Option<Win16DragSample> = None;
    for index in 0..MAX_DRAG_SAMPLES {
        let sample = host.win16_drag_poll(index != 0)?;
        if !sample.left_down || sample.escape_down {
            return Ok(0);
        }
        if pointer_outside_drag_rect(origin_x, origin_y, sample.x, sample.y) {
            return Ok(1);
        }
        if previous == Some(sample) {
            return Ok(0);
        }
        previous = Some(sample);
    }
    Ok(0)
}

/// `PtInRect` excludes the right and bottom edges, so a move of `DRAG_INSET`
/// pixels right or down leaves, and a move of `DRAG_INSET` pixels left or up
/// is still inside.
fn pointer_outside_drag_rect(origin_x: i16, origin_y: i16, x: i16, y: i16) -> bool {
    let origin_x = i32::from(origin_x);
    let origin_y = i32::from(origin_y);
    let x = i32::from(x);
    let y = i32::from(y);
    x < origin_x - DRAG_INSET
        || x >= origin_x + DRAG_INSET
        || y < origin_y - DRAG_INSET
        || y >= origin_y + DRAG_INSET
}

#[cfg(test)]
#[path = "win16_dispatch_drag_tests.rs"]
mod drag_tests;

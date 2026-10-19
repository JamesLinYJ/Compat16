//! Fixed-code-page WM_CHAR family conversion at every Unicode USER boundary.
//!
//! Packed Win16 DBCS words store the lead byte in LOWBYTE and the trail in
//! HIGHBYTE (the byte order consumed by the historical USER character thunk).
//! This adapter owns no cross-message lead-byte state: incomplete input is
//! rejected, rather than allowing one HWND's bytes to affect another HWND.

use super::win16_window_worker::WorkerState;
use runtime::RuntimeError;
use std::{cell::RefCell, rc::Rc};
use windows_sys::Win32::Globalization::IsDBCSLeadByteEx;

pub(super) fn accepts(message: u32) -> bool {
    matches!(message, 0x0102 | 0x0103 | 0x0106 | 0x0107)
}

pub(super) fn to_native(
    state: &Rc<RefCell<WorkerState>>,
    message: u32,
    word: u16,
) -> Result<Option<usize>, RuntimeError> {
    if !accepts(message) {
        return Ok(Some(usize::from(word)));
    }
    let codec = state.borrow().text_codec;
    let bytes = word.to_le_bytes();
    // SAFETY: `IsDBCSLeadByteEx` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let lead = unsafe { IsDBCSLeadByteEx(codec.code_page(), bytes[0]) } != 0;
    if lead && bytes[1] == 0 {
        return Ok(None);
    }
    let wide = codec.to_wide(&bytes[..if lead { 2 } else { 1 }])?;
    Ok((wide.len() == 1).then(|| usize::from(wide[0])))
}

pub(super) fn to_guest(state: &Rc<RefCell<WorkerState>>, message: u32, word: usize) -> Option<u16> {
    if accepts(message) {
        super::win16_window_text_context::native_guest_character(state, word)
    } else {
        Some(word as u16)
    }
}

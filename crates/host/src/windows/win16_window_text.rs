//! Window text stays in USER; only owned guest-byte buffers cross the worker boundary.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostWindow, Win16WindowResult};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetWindowTextLengthW, GetWindowTextW, SetWindowTextW,
};

use super::win16_window_worker::WorkerState;
use super::guest_text::GuestTextBuffer;

/// Non-NUL marker for owned text output buffers. Its value is not an encoding rule.
pub(super) const WIN16_TEXT_OUTPUT_FILL: u8 = u8::MAX;
const NATIVE_TEXT_OUTPUT_FILL: u16 = u16::MAX;

pub(super) fn set_text(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    text: Option<Vec<u8>>,
) -> Result<Win16WindowResult, RuntimeError> {
    let Some(hwnd) = super::win16_window_identity::resolve_user_window(state, window) else {
        return Ok(Win16WindowResult::WindowTextSet(false));
    };
    let native_text = text
        .as_deref()
        .map(|bytes| super::win16_window_text_context::wide_z_from_guest(state, bytes))
        .transpose()?;
    let _text_context = super::win16_window_text_context::enter(
        state,
        window,
        hwnd,
        super::win16_window_text_context::WindowTextCall::SetText,
    )?;
    // No state borrow spans USER: WM_SETTEXT can enter a guest WndProc and
    // synchronously reenter this worker before SetWindowTextW returns.
    let value = unsafe {
        SetWindowTextW(
            hwnd,
            native_text
                .as_ref()
                .map_or(std::ptr::null(), |text| text.as_ptr()),
        )
    };
    Ok(Win16WindowResult::WindowTextSet(value != 0))
}

pub(super) fn get_text(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    mut buffer: Vec<u8>,
) -> Result<Win16WindowResult, RuntimeError> {
    let Some(hwnd) = super::win16_window_identity::resolve_user_window(state, window) else {
        buffer.clear();
        return Ok(Win16WindowResult::WindowText { value: 0, buffer });
    };
    let guest_capacity = u16::try_from(buffer.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::InvalidInput,
            "Win16 window text capacity does not fit its 16-bit ABI field",
            error,
        )
    })?;
    let native_capacity = i32::try_from(buffer.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "window text buffer exceeds the native count range",
            error,
        )
    })?;
    super::win16_window_default::check_text_output_contract(state, hwnd)?;

    let native_allocation = buffer.len().max(1);
    let mut native_text = GuestTextBuffer::acquire();
    native_text
        .try_reserve_exact(native_allocation)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "cannot allocate the native UTF-16 window-text buffer",
                error,
            )
        })?;
    native_text.resize(native_allocation, NATIVE_TEXT_OUTPUT_FILL);
    let _text_context = super::win16_window_text_context::enter(
        state,
        window,
        hwnd,
        super::win16_window_text_context::WindowTextCall::GetText {
            guest_capacity_bytes: guest_capacity,
            buffer_is_null: false,
            native_capacity_units: buffer.len(),
        },
    )?;
    // USER owns truncation and the UTF-16 character-count result. The exact
    // guest byte capacity remains in the synchronous sidecar for reentrant
    // WndProc callbacks.
    let native_count = unsafe {
        GetWindowTextW(hwnd, native_text.as_mut_ptr(), native_capacity)
    };
    if native_count < 0 {
        buffer.clear();
        return Ok(Win16WindowResult::WindowText {
            value: native_count,
            buffer,
        });
    }
    let count = native_count as usize;
    if (buffer.is_empty() && count != 0)
        || (!buffer.is_empty() && count >= native_text.len())
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "GetWindowTextW returned a character count outside its output buffer",
        ));
    }
    if count == 0 {
        if native_text.first() == Some(&0) {
            let (guest_text, guest_count) =
                super::win16_window_text_context::native_prefix_to_guest_in_buffer(
                    state, &[], 0, buffer,
                )?;
            buffer = guest_text;
            return Ok(Win16WindowResult::WindowText {
                value: guest_count as i32,
                buffer,
            });
        }
        buffer.clear();
        return Ok(Win16WindowResult::WindowText { value: 0, buffer });
    }
    if native_text[count] != 0 || native_text[..count].contains(&0) {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "GetWindowTextW output does not match its returned terminated prefix",
        ));
    }
    let output_capacity = buffer.len().saturating_sub(1);
    let (guest_text, guest_count) = super::win16_window_text_context::native_prefix_to_guest_in_buffer(
        state,
        &native_text[..count],
        output_capacity,
        buffer,
    )?;
    buffer = guest_text;
    Ok(Win16WindowResult::WindowText {
        value: guest_count as i32,
        buffer,
    })
}

pub(super) fn text_length(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
) -> Result<Win16WindowResult, RuntimeError> {
    let Some(hwnd) = super::win16_window_identity::resolve_user_window(state, window) else {
        return Ok(Win16WindowResult::WindowTextLength(0));
    };
    let _text_context = super::win16_window_text_context::enter(
        state,
        window,
        hwnd,
        super::win16_window_text_context::WindowTextCall::GetTextLength,
    )?;
    let native_length = unsafe { GetWindowTextLengthW(hwnd) };
    let guest_length = match super::win16_window_text_context::recorded_guest_text_length_result(
        state, window, hwnd,
    ) {
        Some(length) => length as i32,
        None => super::win16_window_text_context::native_text_length_upper_bound(
            state, native_length,
        )?,
    };
    Ok(Win16WindowResult::WindowTextLength(guest_length))
}

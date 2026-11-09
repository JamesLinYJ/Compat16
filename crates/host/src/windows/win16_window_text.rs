//! Window text stays in USER; only owned guest-byte buffers cross the worker boundary.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostWindow, Win16WindowResult};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DefWindowProcW, GetWindowTextLengthW, GetWindowTextW, SetWindowTextW, WM_GETTEXT,
};

use super::win16_window_worker::WorkerState;
use crate::windows::guest_text::GuestTextBuffer;

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
    // SAFETY: SetWindowTextW reads a caller-owned NUL-terminated UTF-16 string that stays live for the call.
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
    // SAFETY: GetWindowTextW writes into a caller-owned UTF-16 buffer of the capacity passed with it.
    let native_count = unsafe { GetWindowTextW(hwnd, native_text.as_mut_ptr(), native_capacity) };
    if native_count < 0 {
        buffer.clear();
        return Ok(Win16WindowResult::WindowText {
            value: native_count,
            buffer,
        });
    }
    let count = native_count as usize;
    if (buffer.is_empty() && count != 0) || (!buffer.is_empty() && count >= native_text.len()) {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "GetWindowTextW returned a character count outside its output buffer",
        ));
    }
    if count == 0 {
        if native_text.first() == Some(&0) {
            let (guest_text, guest_count) =
                super::win16_window_text_context::native_prefix_to_guest_in_buffer(
                    state,
                    &[],
                    0,
                    buffer,
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
    let (guest_text, guest_count) =
        super::win16_window_text_context::native_prefix_to_guest_in_buffer(
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
    let pending = {
        let _text_context = super::win16_window_text_context::enter(
            state,
            window,
            hwnd,
            super::win16_window_text_context::WindowTextCall::GetTextLength,
        )?;
        // SAFETY: `GetWindowTextLengthW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let native_length = unsafe { GetWindowTextLengthW(hwnd) };
        match super::win16_window_text_context::recorded_guest_text_length_result(
            state, window, hwnd,
        ) {
            Some(length) => TextLengthSource::Recorded(length as i32),
            None => TextLengthSource::Native(native_length),
        }
    };
    let guest_length = match pending {
        TextLengthSource::Recorded(length) => length,
        TextLengthSource::Native(native_length) => {
            native_window_text_byte_length(state, hwnd, native_length)?
        }
    };
    Ok(Win16WindowResult::WindowTextLength(guest_length))
}

enum TextLengthSource {
    Recorded(i32),
    Native(i32),
}

/// Guest byte length when the length query did not record a guest result.
/// A guest dialog records a length only when its procedure handles the message,
/// so an absent result can still belong to a live dialog procedure.
fn native_window_text_byte_length(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    native_length: i32,
) -> Result<i32, RuntimeError> {
    if native_length <= 0 {
        return Ok(native_length);
    }
    let units = usize::try_from(native_length).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "positive native window text length does not fit a pointer-sized count",
            error,
        )
    })?;
    if super::win16_window_text_context::native_text_exceeds_checked_copy(units) {
        return super::win16_window_text_context::native_text_length_upper_bound(
            state,
            native_length,
        );
    }
    let allocation = units.checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::HostFailure,
            "native window text length overflows its terminator",
        )
    })?;
    let capacity = i32::try_from(allocation).map_err(|error| {
        RuntimeError::with_source(
            Kind::HostFailure,
            "native window text buffer does not fit the GetWindowTextW count",
            error,
        )
    })?;
    let mut native_text = GuestTextBuffer::acquire();
    native_text.try_reserve_exact(allocation).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "cannot allocate the native UTF-16 window-text length buffer",
            error,
        )
    })?;
    native_text.resize(allocation, 0);
    let count = if guest_routed_dialog(state, hwnd) {
        // GetWindowTextW delivers WM_GETTEXT to that dialog procedure. Its
        // handler can call GetWindowTextLength, and the unhandled length query
        // would enter this function again. DefWindowProcW reads the window text
        // and does not call the procedure.
        copy_default_window_text(hwnd, &mut native_text[..capacity as usize])?
    } else {
        // SAFETY: GetWindowTextW writes a caller-owned UTF-16 buffer of `capacity` units, including the terminator. No guest address is passed.
        unsafe { GetWindowTextW(hwnd, native_text.as_mut_ptr(), capacity) }
    };
    if count < 0 {
        return Ok(count);
    }
    let count = usize::try_from(count).map_err(|_| {
        RuntimeError::new(
            Kind::HostFailure,
            "window text query returned a character count outside its output buffer",
        )
    })?;
    if count >= native_text.len() || native_text[count] != 0 || native_text[..count].contains(&0) {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "window text output does not match its returned terminated prefix",
        ));
    }
    let bytes =
        super::win16_window_text_context::guest_text_byte_length(state, &native_text[..count])?;
    i32::try_from(bytes).map_err(|error| {
        RuntimeError::with_source(
            Kind::HostFailure,
            "guest window text byte length does not fit in a signed 32-bit count",
            error,
        )
    })
}

fn guest_routed_dialog(state: &Rc<RefCell<WorkerState>>, hwnd: HWND) -> bool {
    let route = state
        .borrow()
        .dialog_routes_by_native
        .get(&(hwnd as usize))
        .copied();
    route.is_some_and(|route| {
        super::win16_window_identity::resolve(state, route.window) == Some(hwnd)
    })
}

/// Copy the default window text. `DefWindowProcW` handles `WM_GETTEXT` itself
/// and does not call a window procedure or a dialog procedure.
pub(super) fn copy_default_window_text(
    hwnd: HWND,
    buffer: &mut [u16],
) -> Result<i32, RuntimeError> {
    let capacity = i32::try_from(buffer.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "default window text buffer does not fit the WM_GETTEXT count",
            error,
        )
    })?;
    // SAFETY: DefWindowProcW writes this caller-owned UTF-16 buffer of `capacity` units, including the terminator. It does not call the window or dialog procedure, and no guest address is passed.
    let count = unsafe {
        DefWindowProcW(
            hwnd,
            WM_GETTEXT,
            capacity as usize,
            buffer.as_mut_ptr() as isize,
        )
    };
    i32::try_from(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::HostFailure,
            "DefWindowProcW WM_GETTEXT returned a character count outside its output buffer",
            error,
        )
    })
}

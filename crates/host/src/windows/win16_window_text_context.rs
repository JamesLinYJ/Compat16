//! Explicit guest-code-page text conversion at the native Unicode USER edge.
//!
//! USER worker HWNDs are Unicode windows, while Win16 text buffers remain
//! guest-code-page byte strings. The context stack ties a synchronous text
//! callback to its exact operation and native window; a nested call cannot
//! borrow another frame's capacity merely because it uses the same message.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostWindow};
use windows_sys::Win32::Globalization::{CPINFO, GetCPInfo};
use windows_sys::Win32::UI::WindowsAndMessaging::{WM_GETTEXT, WM_GETTEXTLENGTH, WM_SETTEXT};

use super::win16_window_worker::WorkerState;
use crate::windows::guest_text::GuestTextBuffer;

const MAX_NATIVE_TEXT_UNITS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WindowTextCall {
    SetText,
    GetText {
        guest_capacity_bytes: u16,
        buffer_is_null: bool,
        native_capacity_units: usize,
    },
    GetTextLength,
}

impl WindowTextCall {
    fn message(self) -> u32 {
        match self {
            Self::SetText => WM_SETTEXT,
            Self::GetText { .. } => WM_GETTEXT,
            Self::GetTextLength => WM_GETTEXTLENGTH,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WindowTextContext {
    pub(super) operation_id: u64,
    pub(super) window: Win16HostWindow,
    pub(super) hwnd_bits: usize,
    pub(super) call: WindowTextCall,
    guest_text_length_result: Option<isize>,
}

#[derive(Default)]
pub(in crate::windows::win16_windows) struct WindowTextContextStack {
    next_token: u64,
    frames: Vec<WindowTextContextFrame>,
}

struct WindowTextContextFrame {
    token: u64,
    context: WindowTextContext,
}

pub(super) struct WindowTextContextGuard {
    state: Rc<RefCell<WorkerState>>,
    token: u64,
}

pub(super) fn enter(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: windows_sys::Win32::Foundation::HWND,
    call: WindowTextCall,
) -> Result<WindowTextContextGuard, RuntimeError> {
    let operation_id = state
        .try_borrow()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "read the active operation for a Unicode USER text call",
            )
        })?
        .active_operations
        .last()
        .map(|active| active.id)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Unicode USER text call has no active Win16 operation",
            )
        })?;
    let context = WindowTextContext {
        operation_id,
        window,
        hwnd_bits: hwnd as usize,
        call,
        guest_text_length_result: None,
    };
    let shared_state = Rc::clone(state);
    let mut state = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "reserve an exact Unicode USER text-call context",
        )
    })?;
    let stack = &mut state.window_text_contexts;
    let token = stack.next_token.checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Unicode USER text-call context identity is exhausted",
        )
    })?;
    stack.frames.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve a Unicode USER text-call context",
            error,
        )
    })?;
    stack.next_token = token;
    stack.frames.push(WindowTextContextFrame { token, context });
    Ok(WindowTextContextGuard {
        state: shared_state,
        token,
    })
}

impl Drop for WindowTextContextGuard {
    fn drop(&mut self) {
        let exact_top = self.state.try_borrow().ok().and_then(|state| {
            state
                .window_text_contexts
                .frames
                .last()
                .map(|frame| frame.token)
        }) == Some(self.token);
        if exact_top {
            if let Ok(mut state) = self.state.try_borrow_mut() {
                state.window_text_contexts.frames.pop();
                return;
            }
        }

        // The frame and all nested owners stay retained for diagnosis. A
        // failed LIFO retirement is worker corruption, never a stale sidecar
        // that may be silently skipped or reused by another callback.
        super::win16_window_callbacks::fail_worker(
            &self.state,
            RuntimeError::new(
                Kind::InternalInvariant,
                "Unicode USER text-call contexts did not unwind in exact LIFO order",
            ),
        );
    }
}

pub(super) fn current(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: windows_sys::Win32::Foundation::HWND,
    message: u32,
) -> Option<WindowTextContext> {
    let state = state.try_borrow().ok()?;
    let operation_id = state.active_operations.last()?.id;
    let frame = state.window_text_contexts.frames.last()?;
    let context = frame.context;
    (context.operation_id == operation_id
        && context.window == window
        && context.hwnd_bits == hwnd as usize
        && context.call.message() == message)
        .then_some(context)
}

/// Remember an exact Win16 byte-count returned from a guest text procedure.
/// A surrounding W GetTextLength operation must return that original value to
/// the guest, while a native-origin W query may use it as a safe upper bound.
pub(super) fn record_guest_text_length_result(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: windows_sys::Win32::Foundation::HWND,
    result: isize,
) {
    let Ok(mut state) = state.try_borrow_mut() else {
        return;
    };
    let Some(operation_id) = state.active_operations.last().map(|active| active.id) else {
        return;
    };
    let Some(frame) = state.window_text_contexts.frames.last_mut() else {
        return;
    };
    let context = &mut frame.context;
    if context.operation_id == operation_id
        && context.window == window
        && context.hwnd_bits == hwnd as usize
        && context.call == WindowTextCall::GetTextLength
    {
        context.guest_text_length_result = Some(result);
    }
}

pub(super) fn recorded_guest_text_length_result(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: windows_sys::Win32::Foundation::HWND,
) -> Option<isize> {
    current(state, window, hwnd, WM_GETTEXTLENGTH)?.guest_text_length_result
}

pub(super) fn guest_capacity(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: windows_sys::Win32::Foundation::HWND,
    message: u32,
    native_capacity_units: usize,
    native_buffer_is_null: bool,
) -> Result<(u16, bool), RuntimeError> {
    if let Some(WindowTextContext {
        call:
            WindowTextCall::GetText {
                guest_capacity_bytes,
                buffer_is_null,
                native_capacity_units: expected_native_units,
            },
        ..
    }) = current(state, window, hwnd, message)
    {
        if expected_native_units != native_capacity_units || buffer_is_null != native_buffer_is_null
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Unicode WM_GETTEXT callback changed its guest-origin capacity contract",
            ));
        }
        return Ok((guest_capacity_bytes, buffer_is_null));
    }

    Ok((
        guest_capacity_from_native_units(state, native_capacity_units)?,
        native_buffer_is_null,
    ))
}

/// Derive a guest byte capacity that cannot exceed the native UTF-16 payload
/// after the same explicit guest code-page conversion. One extra byte keeps
/// room for the Win16 terminator.
pub(super) fn guest_capacity_from_native_units(
    state: &Rc<RefCell<WorkerState>>,
    native_capacity_units: usize,
) -> Result<u16, RuntimeError> {
    if native_capacity_units == 0 {
        return Ok(0);
    }
    let max_char_bytes = maximum_guest_character_bytes(state)?;
    let guest_bytes = native_capacity_units
        .saturating_sub(1)
        .saturating_mul(max_char_bytes)
        .saturating_add(1)
        .min(usize::from(u16::MAX));
    Ok(guest_bytes as u16)
}

pub(super) fn maximum_guest_character_bytes(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<usize, RuntimeError> {
    let code_page = state.borrow().text_codec.code_page();
    let mut info = CPINFO::default();
    // SAFETY: GetCPInfo writes the fixed-size CPINFO record for this explicit
    // numeric guest code page; it retains no pointer.
    if unsafe { GetCPInfo(code_page, &mut info) } == 0 || info.MaxCharSize == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "Windows could not report the maximum byte width of the guest code page",
        ));
    }
    usize::try_from(info.MaxCharSize).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "convert the guest code-page maximum character width",
            error,
        )
    })
}

pub(super) fn native_text_length_upper_bound(
    state: &Rc<RefCell<WorkerState>>,
    native_length: i32,
) -> Result<i32, RuntimeError> {
    if native_length < 0 {
        return Ok(native_length);
    }
    let maximum = maximum_guest_character_bytes(state)?;
    let guest_upper_bound = (native_length as usize)
        .saturating_mul(maximum)
        .min(i32::MAX as usize);
    Ok(guest_upper_bound as i32)
}

pub(super) fn wide_z_from_guest(
    state: &Rc<RefCell<WorkerState>>,
    bytes: &[u8],
) -> Result<GuestTextBuffer, RuntimeError> {
    if bytes.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "owned Win16 window text contains an embedded NUL",
        ));
    }
    let codec = state.borrow().text_codec;
    let mut wide = GuestTextBuffer::acquire();
    codec.to_wide_z_into(bytes, &mut wide)?;
    Ok(wide)
}

/// Copy a USER-supplied UTF-16 C string during the synchronous native callback
/// and convert it to the fixed guest code page before the pointer can escape.
// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn copy_native_wide_z(
    state: &Rc<RefCell<WorkerState>>,
    pointer: *const u16,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    if pointer.is_null() {
        return Ok(None);
    }
    let mut length = 0_usize;
    while length < MAX_NATIVE_TEXT_UNITS {
        // SAFETY: USER supplied a readable, terminated UTF-16 string for the
        // duration of this synchronous callback; the limit rejects corrupt or
        // unterminated native inputs instead of scanning indefinitely.
        if unsafe { *pointer.add(length) } == 0 {
            let source = unsafe { std::slice::from_raw_parts(pointer, length) };
            let encoded = state.borrow().text_codec.from_wide(source)?;
            if encoded.used_default_char == Some(true) {
                super::win16_window_position::report_diagnostic(
                    state,
                    Kind::CompatibilityGap,
                    "native UTF-16 window text used the guest code-page default replacement",
                );
            }
            return Ok(Some(encoded.bytes));
        }
        length += 1;
    }
    Err(RuntimeError::new(
        Kind::HostFailure,
        "native UTF-16 window string exceeds the checked copy limit",
    ))
}

/// Convert one validated guest NUL-terminated output and clip it at a native
/// UTF-16 buffer boundary without splitting a surrogate pair.
pub(super) fn guest_z_to_native_prefix(
    state: &Rc<RefCell<WorkerState>>,
    guest_z: &[u8],
    native_capacity_units: usize,
) -> Result<(GuestTextBuffer, usize), RuntimeError> {
    if guest_z.last() != Some(&0) || guest_z[..guest_z.len().saturating_sub(1)].contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 window output is not a single terminated guest string",
        ));
    }
    if native_capacity_units == 0 {
        return Ok((GuestTextBuffer::acquire(), 0));
    }
    let codec = state.borrow().text_codec;
    let mut wide = GuestTextBuffer::acquire();
    codec.to_wide_z_into(&guest_z[..guest_z.len() - 1], &mut wide)?;
    wide.pop();
    let visible_limit = native_capacity_units.saturating_sub(1);
    if wide.len() > visible_limit {
        let mut visible = visible_limit;
        if visible > 0
            && (0xD800..=0xDBFF).contains(&wide[visible - 1])
            && wide
                .get(visible)
                .is_some_and(|unit| (0xDC00..=0xDFFF).contains(unit))
        {
            visible -= 1;
        }
        wide.truncate(visible);
    }
    let count = wide.len();
    // The converter reserved this terminator before the native-prefix clip.
    wide.push(0);
    Ok((wide, count))
}

/// Return guest bytes for an already validated native W output prefix.
pub(super) fn native_prefix_to_guest(
    state: &Rc<RefCell<WorkerState>>,
    native_text: &[u16],
    guest_capacity_bytes: usize,
) -> Result<(Vec<u8>, usize), RuntimeError> {
    native_prefix_to_guest_in_buffer(state, native_text, guest_capacity_bytes, Vec::new())
}

pub(super) fn native_prefix_to_guest_in_buffer(
    state: &Rc<RefCell<WorkerState>>,
    native_text: &[u16],
    guest_capacity_bytes: usize,
    buffer: Vec<u8>,
) -> Result<(Vec<u8>, usize), RuntimeError> {
    let bounded = state.borrow().text_codec.from_wide_bounded_in_buffer(
        native_text,
        guest_capacity_bytes,
        buffer,
    )?;
    let count = bounded.bytes.len();
    let used_default_char = bounded.used_default_char;
    let mut guest = bounded.bytes;
    guest.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "terminate converted guest window text",
            error,
        )
    })?;
    guest.push(0);
    if used_default_char == Some(true) {
        super::win16_window_position::report_diagnostic(
            state,
            Kind::CompatibilityGap,
            "native UTF-16 window text used the guest code-page default replacement",
        );
    }
    Ok((guest, count))
}

/// Project one Unicode character into a fixed guest ANSI/DBCS word. DBCS uses
/// low-byte lead/high-byte trail; encodings needing more than two bytes have
/// no representation in this Win16 message field.
pub(super) fn native_guest_character(
    state: &Rc<RefCell<WorkerState>>,
    native_w_param: usize,
) -> Option<u16> {
    let unit = u16::try_from(native_w_param).ok()?;
    let encoding = state.borrow().text_codec.from_wide(&[unit]).ok()?;
    if encoding.used_default_char == Some(true) {
        super::win16_window_position::report_diagnostic(
            state,
            Kind::CompatibilityGap,
            "native Unicode WM_CHAR required the guest code-page replacement character",
        );
    }
    match encoding.bytes.as_slice() {
        [byte] => Some(u16::from(*byte)),
        // SAFETY: `IsDBCSLeadByteEx` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        [lead, trail]
            if unsafe {
                windows_sys::Win32::Globalization::IsDBCSLeadByteEx(
                    state.borrow().text_codec.code_page(),
                    *lead,
                )
            } != 0 =>
        {
            Some(u16::from_le_bytes([*lead, *trail]))
        }
        _ => None,
    }
}

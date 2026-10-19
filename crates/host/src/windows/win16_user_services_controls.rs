//! Native adapters for USER dialog child-control operations.
//!
//! Calls run on the HWND-owning USER worker. Native child HWNDs are converted
//! to opaque worker tokens before a result crosses the runtime boundary.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    RuntimeError, Win16HostDialogControlOperation as Operation,
    Win16HostDialogControlResult as ResultValue, Win16HostRect, Win16HostWindow,
};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::UI::Controls::{
    CheckDlgButton, CheckRadioButton, DlgDirListComboBoxW, DlgDirListW, DlgDirSelectComboBoxExW,
    DlgDirSelectExW, IsDlgButtonChecked,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, GetDlgItem, GetDlgItemInt, GetDlgItemTextW, GetNextDlgGroupItem,
    GetNextDlgTabItem, MapDialogRect, SetDlgItemInt, SetDlgItemTextW,
};

use super::win16_window_worker::{self as worker, WorkerState};

type SharedWorker = Rc<RefCell<WorkerState>>;
const DIRECTORY_SELECT_UNWRITTEN: u16 = 0xffff;
const DIRECTORY_LIST_WIDE_BUFFER_UNITS: usize = 32_768;

pub(super) fn execute(
    state: &SharedWorker,
    operation: Operation,
) -> Result<ResultValue, RuntimeError> {
    use Operation as Call;
    use ResultValue as Result;

    let result = match operation {
        Call::GetItem { dialog, id } => {
            let Some(dialog) = hwnd(state, dialog) else {
                return Ok(Result::Item(None));
            };
            let native = unsafe { GetDlgItem(dialog, i32::from(id)) };
            Result::Item(token_for_native(state, native)?)
        }
        Call::GetControlId { control } => {
            let id = hwnd(state, control).map_or(0, |control| unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::GetDlgCtrlID(control)
            });
            Result::ControlId(id as u16)
        }
        Call::GetNextGroupItem {
            dialog,
            control,
            previous,
        } => {
            let Some(dialog) = hwnd(state, dialog) else {
                return Ok(Result::NextItem(None));
            };
            let control = match control {
                Some(control) => match hwnd(state, control) {
                    Some(control) => control,
                    None => return Ok(Result::NextItem(None)),
                },
                None => std::ptr::null_mut(),
            };
            let native = unsafe { GetNextDlgGroupItem(dialog, control, i32::from(previous)) };
            Result::NextItem(token_for_native(state, native)?)
        }
        Call::GetNextTabItem {
            dialog,
            control,
            previous,
        } => {
            let Some(dialog) = hwnd(state, dialog) else {
                return Ok(Result::NextItem(None));
            };
            let control = match control {
                Some(control) => match hwnd(state, control) {
                    Some(control) => control,
                    None => return Ok(Result::NextItem(None)),
                },
                None => std::ptr::null_mut(),
            };
            let native = unsafe { GetNextDlgTabItem(dialog, control, i32::from(previous)) };
            Result::NextItem(token_for_native(state, native)?)
        }
        Call::SetItemText { dialog, id, text } => {
            let Some(dialog) = hwnd(state, dialog) else {
                return Ok(Result::Succeeded(false));
            };
            let codec = state.borrow().text_codec;
            let text = text
                .as_deref()
                .map(|text| {
                    if text.contains(&0) {
                        return Err(RuntimeError::new(
                            runtime::DiagnosticKind::InvalidInput,
                            "Win16 dialog-control text contains an embedded NUL",
                        ));
                    }
                    codec.to_wide_z(text)
                })
                .transpose();
            let success = match text {
                Ok(text) => unsafe {
                    SetDlgItemTextW(
                        dialog,
                        i32::from(id),
                        text.as_ref().map_or(std::ptr::null(), |text| text.as_ptr()),
                    ) != 0
                },
                Err(_) => false,
            };
            Result::Succeeded(success)
        }
        Call::GetItemText {
            dialog,
            id,
            capacity,
            buffer_is_null,
        } => {
            let Some(dialog) = hwnd(state, dialog) else {
                return Ok(Result::Text {
                    value: 0,
                    bytes: Vec::new(),
                });
            };
            let control = unsafe { GetDlgItem(dialog, i32::from(id)) };
            if control.is_null() {
                return Ok(Result::Text {
                    value: 0,
                    bytes: Vec::new(),
                });
            }
            let control_token = worker::token_for_native(state, control)?;
            super::win16_window_default::check_text_output_contract(state, control)?;
            if buffer_is_null && capacity != 0 {
                return Err(RuntimeError::new(
                    runtime::DiagnosticKind::InvalidInput,
                    "Win16 GetDlgItemText has NULL output with nonzero capacity",
                ));
            }

            let guest_capacity = usize::from(capacity);
            let native_capacity = wide_capacity_for_guest_bytes(guest_capacity)?;
            let mut wide = if buffer_is_null {
                Vec::new()
            } else {
                let mut wide = zeroed_wide_buffer(
                    native_capacity.max(1),
                    "allocate Win16 dialog-control text output",
                )?;
                wide.fill(super::win16_window_text::WIN16_TEXT_OUTPUT_FILL as u16);
                wide
            };
            let output = if buffer_is_null {
                std::ptr::null_mut()
            } else {
                wide.as_mut_ptr()
            };
            let _text_context = super::win16_window_text_context::enter(
                state,
                control_token,
                control,
                super::win16_window_text_context::WindowTextCall::GetText {
                    guest_capacity_bytes: capacity,
                    buffer_is_null,
                    native_capacity_units: native_capacity,
                },
            )?;
            let copied_units =
                unsafe { GetDlgItemTextW(dialog, i32::from(id), output, native_capacity as i32) };
            let mut bytes = Vec::new();
            let mut guest_count = copied_units;
            if capacity == 0 || copied_units == u32::MAX {
                wide.clear();
            } else {
                let count = copied_units as usize;
                if count >= native_capacity {
                    return Err(RuntimeError::new(
                        runtime::DiagnosticKind::HostFailure,
                        "native GetDlgItemTextW count exceeds its UTF-16 output capacity",
                    ));
                }
                if copied_units == 0 && wide.first() != Some(&0) {
                    wide.clear();
                } else {
                    if wide.get(count) != Some(&0) || wide[..count].contains(&0) {
                        return Err(RuntimeError::new(
                            runtime::DiagnosticKind::HostFailure,
                            "native GetDlgItemTextW output does not match its terminated prefix",
                        ));
                    }
                    let codec = state.borrow().text_codec;
                    let encoded = codec.from_wide_bounded(&wide[..count], guest_capacity - 1)?;
                    guest_count = u32::try_from(encoded.bytes.len()).map_err(|error| {
                        RuntimeError::with_source(
                            runtime::DiagnosticKind::InternalInvariant,
                            "Win16 GetDlgItemText guest-byte count exceeds its result width",
                            error,
                        )
                    })?;
                    bytes = encoded.bytes;
                    bytes.push(0);
                }
            }
            if wide.is_empty() && (capacity == 0 || copied_units == u32::MAX) {
                bytes.clear();
            }
            Result::Text {
                value: guest_count,
                bytes,
            }
        }
        Call::SetItemInteger {
            dialog,
            id,
            value,
            signed,
        } => {
            let native_value = if signed {
                i32::from(value as i16) as u32
            } else {
                u32::from(value)
            };
            let success = hwnd(state, dialog).is_some_and(|dialog| unsafe {
                SetDlgItemInt(dialog, i32::from(id), native_value, i32::from(signed)) != 0
            });
            Result::Succeeded(success)
        }
        Call::GetItemInteger { dialog, id, signed } => {
            let mut translated = 0_i32;
            let value = hwnd(state, dialog).map_or(0, |dialog| unsafe {
                GetDlgItemInt(dialog, i32::from(id), &mut translated, i32::from(signed))
            });
            let in_win16_range = translated != 0
                && if signed {
                    i16::try_from(value as i32).is_ok()
                } else {
                    u16::try_from(value).is_ok()
                };
            Result::Integer {
                value: if in_win16_range { value as u16 } else { 0 },
                translated: in_win16_range,
                succeeded: in_win16_range,
            }
        }
        Call::CheckButton {
            dialog,
            id,
            state: check_state,
        } => {
            let success = hwnd(state, dialog).is_some_and(|dialog| unsafe {
                CheckDlgButton(dialog, i32::from(id), u32::from(check_state)) != 0
            });
            Result::Succeeded(success)
        }
        Call::IsButtonChecked { dialog, id } => {
            let state = hwnd(state, dialog).map_or(0, |dialog| unsafe {
                IsDlgButtonChecked(dialog, i32::from(id))
            });
            Result::ButtonState(state as u16)
        }
        Call::CheckRadioButton {
            dialog,
            first,
            last,
            checked,
        } => {
            let success = hwnd(state, dialog).is_some_and(|dialog| unsafe {
                CheckRadioButton(
                    dialog,
                    i32::from(first),
                    i32::from(last),
                    i32::from(checked),
                ) != 0
            });
            Result::Succeeded(success)
        }
        Call::DirectoryList {
            dialog,
            path_spec,
            path_capacity,
            list_id,
            path_id,
            file_type,
            combo_box,
        } => {
            let Some(dialog) = hwnd(state, dialog) else {
                return Ok(Result::DirectoryList {
                    selected: 0,
                    path_spec: None,
                });
            };
            let codec = state.borrow().text_codec;
            let Some(mut buffer) = path_spec
                .map(|path| bounded_path_buffer(codec, path, path_capacity))
                .transpose()?
            else {
                let success = unsafe {
                    if combo_box {
                        DlgDirListComboBoxW(
                            dialog,
                            std::ptr::null_mut(),
                            i32::from(list_id),
                            i32::from(path_id),
                            u32::from(file_type),
                        )
                    } else {
                        DlgDirListW(
                            dialog,
                            std::ptr::null_mut(),
                            i32::from(list_id),
                            i32::from(path_id),
                            u32::from(file_type),
                        )
                    }
                } != 0;
                return Ok(Result::DirectoryList {
                    selected: if success { 1 } else { 0 },
                    path_spec: None,
                });
            };
            let success = unsafe {
                if combo_box {
                    DlgDirListComboBoxW(
                        dialog,
                        buffer.as_mut_ptr(),
                        i32::from(list_id),
                        i32::from(path_id),
                        u32::from(file_type),
                    )
                } else {
                    DlgDirListW(
                        dialog,
                        buffer.as_mut_ptr(),
                        i32::from(list_id),
                        i32::from(path_id),
                        u32::from(file_type),
                    )
                }
            } != 0;
            let path_spec = if success {
                let Some(end) = buffer.iter().position(|unit| *unit == 0) else {
                    return Err(RuntimeError::new(
                        runtime::DiagnosticKind::HostFailure,
                        "native DlgDirListW output has no NUL terminator",
                    ));
                };
                let encoded = codec.from_wide_bounded(
                    &buffer[..end],
                    usize::from(path_capacity).saturating_sub(1),
                )?;
                let mut path_bytes = encoded.bytes;
                path_bytes.push(0);
                Some(path_bytes)
            } else {
                None
            };
            Result::DirectoryList {
                selected: if success { 1 } else { 0 },
                path_spec,
            }
        }
        Call::DirectorySelect {
            dialog,
            capacity,
            control_id,
            combo_box,
        } => {
            let guest_capacity = usize::from(capacity);
            let native_capacity = wide_capacity_for_guest_bytes(guest_capacity)?;
            let mut wide =
                zeroed_wide_buffer(native_capacity, "allocate Win16 DlgDirSelect output")?;
            // Detect the documented no-selection case, where DlgDirSelectEx
            // leaves lpString untouched. A nonzero sentinel also distinguishes
            // a written empty string when capacity is one.
            wide.fill(DIRECTORY_SELECT_UNWRITTEN);
            let selected = hwnd(state, dialog).is_some_and(|dialog| unsafe {
                if combo_box {
                    DlgDirSelectComboBoxExW(
                        dialog,
                        wide.as_mut_ptr(),
                        native_capacity as i32,
                        i32::from(control_id),
                    ) != 0
                } else {
                    DlgDirSelectExW(
                        dialog,
                        wide.as_mut_ptr(),
                        native_capacity as i32,
                        i32::from(control_id),
                    ) != 0
                }
            });
            let mut bytes = Vec::new();
            if wide.iter().all(|unit| *unit == DIRECTORY_SELECT_UNWRITTEN) {
                wide.clear();
            } else if let Some(end) = wide.iter().position(|unit| *unit == 0) {
                // Native output is a NUL-terminated string, including an
                // empty string for a one-byte destination.
                let codec = state.borrow().text_codec;
                let encoded =
                    codec.from_wide_bounded(&wide[..end], guest_capacity.saturating_sub(1))?;
                bytes = encoded.bytes;
                bytes.push(0);
            } else {
                return Err(RuntimeError::new(
                    runtime::DiagnosticKind::HostFailure,
                    "native DlgDirSelectExW wrote a buffer without a NUL terminator",
                ));
            }
            Result::DirectorySelect {
                selected,
                text: bytes,
            }
        }
        Call::AdjustWindowRect {
            rect,
            style,
            ex_style,
            menu,
        } => {
            let mut native = native_rect(rect);
            let succeeded =
                unsafe { AdjustWindowRectEx(&mut native, style, i32::from(menu), ex_style) != 0 };
            if succeeded && let Some(frame) = super::win16_frame_geometry::CaptionFrame::query(style, ex_style) {
                let Some(projected) = frame.adjust_outer(native) else { return Ok(Result::Rect(None)); };
                native = projected;
            }
            Result::Rect(succeeded.then(|| host_rect(native)))
        }
        Call::MapDialogRect { dialog, rect } => {
            let Some(dialog) = hwnd(state, dialog) else {
                return Ok(Result::Rect(None));
            };
            let mut native = native_rect(rect);
            let succeeded = unsafe { MapDialogRect(dialog, &mut native) != 0 };
            Result::Rect(succeeded.then(|| host_rect(native)))
        }
    };
    Ok(result)
}

fn hwnd(state: &SharedWorker, window: Win16HostWindow) -> Option<HWND> {
    super::win16_window_identity::resolve_user_window(state, window)
}

fn token_for_native(
    state: &SharedWorker,
    native: HWND,
) -> Result<Option<Win16HostWindow>, RuntimeError> {
    if native.is_null() {
        return Ok(None);
    }
    worker::token_for_native(state, native).map(Some)
}

fn zeroed_wide_buffer(length: usize, operation: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(runtime::DiagnosticKind::ResourceExhausted, operation, error)
    })?;
    buffer.resize(length, 0);
    Ok(buffer)
}

/// A guest byte buffer may hold one or two UTF-16 units per encoded byte:
/// supplementary characters can become a one-byte fallback in SBCS pages.
fn wide_capacity_for_guest_bytes(capacity: usize) -> Result<usize, RuntimeError> {
    if capacity == 0 {
        return Ok(0);
    }
    capacity
        .checked_sub(1)
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|units| units.checked_add(1))
        .ok_or_else(|| {
            RuntimeError::new(
                runtime::DiagnosticKind::ResourceExhausted,
                "size UTF-16 buffer for guest byte capacity",
            )
        })
}

fn bounded_path_buffer(
    codec: super::super::guest_text::GuestTextCodec,
    path: Vec<u8>,
    capacity: u16,
) -> Result<Vec<u16>, RuntimeError> {
    if path.contains(&0) {
        return Err(RuntimeError::new(
            runtime::DiagnosticKind::InvalidInput,
            "Win16 DlgDirList path contains an embedded NUL",
        ));
    }
    let wide = codec.to_wide_z(&path)?;
    let guest_capacity = usize::from(capacity).max(path.len().saturating_add(1));
    // DlgDirListW has no length parameter. Windows documents extended paths
    // up to 32,767 characters, so reserve one more UTF-16 unit for NUL as well
    // as the guest's known span; copyback is still capped in guest bytes.
    let capacity = wide_capacity_for_guest_bytes(guest_capacity)?
        .max(wide.len())
        .max(DIRECTORY_LIST_WIDE_BUFFER_UNITS);
    let mut buffer = zeroed_wide_buffer(capacity, "allocate bounded Win16 DlgDirList UTF-16 path")?;
    buffer[..wide.len()].copy_from_slice(&wide);
    Ok(buffer)
}

fn native_rect(rect: Win16HostRect) -> RECT {
    RECT {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn host_rect(rect: RECT) -> Win16HostRect {
    Win16HostRect {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

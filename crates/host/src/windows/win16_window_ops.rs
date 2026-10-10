//! Native USER forwarding for Win16 window-state and geometry operations.
//!
//! All calls run on the dedicated USER worker. This keeps native HWND access
//! on its owning thread and lets synchronous window procedures use the normal
//! worker callback continuation.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    RuntimeError, Win16HostPoint, Win16HostRect, Win16HostWindow,
    Win16WindowCall, Win16WindowCallResult, Win16WindowInsertAfter,
    Win16WindowSearchClass, Win16WindowTarget, Win16WindowPlacement,
};
use windows_sys::Win32::Foundation::{GetLastError, SetLastError, HWND, POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::{ClientToScreen, MapWindowPoints, ScreenToClient};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetActiveWindow, IsWindowEnabled, SetActiveWindow,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, FindWindowW, GetClientRect, GetClassNameW,
    GetCursorPos, GetDesktopWindow, GetDlgCtrlID, GetLastActivePopup, GetParent, GetTopWindow,
    GetWindow,
    GetWindowRect, IsIconic, IsWindow, IsWindowVisible, IsZoomed, MoveWindow,
    SetWindowPos, ShowOwnedPopups, WindowFromPoint, GetWindowPlacement, SetWindowPlacement,
    WINDOWPLACEMENT,
};

use super::win16_window_worker::{self as worker, WorkerState};

type SharedWorker = Rc<RefCell<WorkerState>>;

pub(super) fn execute(
    state: &SharedWorker,
    call: Win16WindowCall,
) -> Result<Win16WindowCallResult, RuntimeError> {
    use Win16WindowCall as Call;
    use Win16WindowCallResult as ResultValue;

    let result = match call {
        call @ (Call::CreateCaret { .. } | Call::DestroyCaret | Call::SetCaretPos { .. }
            | Call::HideCaret { .. } | Call::ShowCaret { .. } | Call::GetCaretPos) => {
                super::win16_window_caret::execute(state, call)?
            }
        Call::GetWindowPlacement { window } => {
            let mut placement = WINDOWPLACEMENT {
                length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
                ..Default::default()
            };
            let success = hwnd(state, window)
                .is_some_and(|native| unsafe { GetWindowPlacement(native, &mut placement) != 0 });
            ResultValue::Placement(success.then(|| Win16WindowPlacement {
                flags: placement.flags, show_command: placement.showCmd,
                minimum: host_point(placement.ptMinPosition), maximum: host_point(placement.ptMaxPosition),
                normal: host_rect(placement.rcNormalPosition),
            }))
        }
        Call::SetWindowPlacement { window, placement } => {
            // Windows owns workspace coordinates, work-area adjustment and
            // show-state rules. Only the guest/native field widths differ.
            let placement = WINDOWPLACEMENT {
                length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
                flags: placement.flags, showCmd: placement.show_command,
                ptMinPosition: native_point(placement.minimum), ptMaxPosition: native_point(placement.maximum),
                rcNormalPosition: RECT {
                    left: placement.normal.left, top: placement.normal.top,
                    right: placement.normal.right, bottom: placement.normal.bottom,
                },
            };
            ResultValue::Boolean(hwnd(state, window)
                .is_some_and(|native| unsafe { SetWindowPlacement(native, &placement) != 0 }))
        }
        Call::GetCursorPos => {
            let mut point = POINT::default();
            let success = unsafe { GetCursorPos(&mut point) != 0 };
            ResultValue::Point(success.then_some(host_point(point)))
        }
        call @ (Call::SetWindowProperty { .. } | Call::GetWindowProperty { .. }
            | Call::RemoveWindowProperty { .. } | Call::EnumWindowProperties { .. }) => {
                super::win16_window_properties::execute(state, call)?
            }
        Call::WindowData(call) => ResultValue::WindowData(
            super::win16_window_data::execute(state, call)?),
        Call::IsIconic { window } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { IsIconic(native) != 0 })),
        Call::GetWindowRect { window } => {
            let mut rect = RECT::default();
            let success = hwnd(state, window)
                .is_some_and(|native| unsafe { GetWindowRect(native, &mut rect) != 0 });
            ResultValue::Rect(success.then_some(host_rect(rect)))
        }
        Call::GetClientRect { window } => {
            let mut rect = RECT::default();
            let success = hwnd(state, window)
                .is_some_and(|native| unsafe { GetClientRect(native, &mut rect) != 0 });
            ResultValue::Rect(success.then_some(host_rect(rect)))
        }
        Call::EnableWindow { window, enable } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { EnableWindow(native, i32::from(enable)) != 0 })),
        Call::IsWindowEnabled { window } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { IsWindowEnabled(native) != 0 })),
        Call::BringWindowToTop { window } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { BringWindowToTop(native) != 0 })),
        Call::GetParent { window } => {
            let native = hwnd(state, window).map(|native| unsafe { GetParent(native) });
            ResultValue::Window(match native {
                Some(native) => token_for_native(state, native)?,
                None => None,
            })
        }
        Call::IsWindow { window } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { IsWindow(native) != 0 })),
        Call::IsWindowVisible { window } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { IsWindowVisible(native) != 0 })),
        Call::FindWindow { class, title } => {
            let title = title.as_deref().map(|bytes|
                super::win16_window_text_context::wide_z_from_guest(state, bytes)).transpose()?;
            let class = match class {
                Some(Win16WindowSearchClass::Name(name)) => Some(
                    super::win16_window_text_context::wide_z_from_guest(state, &name)?,
                ),
                Some(Win16WindowSearchClass::Registered(class)) => {
                    let Some(class) = state.borrow().classes.get(&class).cloned() else {
                        return Ok(ResultValue::Window(None));
                    };
                    Some(super::win16_window_text_context::wide_z_from_guest(
                        state, &class.name[..class.name.len().saturating_sub(1)],
                    )?)
                }
                None => None,
            };
            let native = unsafe {
                FindWindowW(
                    class.as_ref().map_or(std::ptr::null(), |value| value.as_ptr()),
                    title.as_ref().map_or(std::ptr::null(), |value| value.as_ptr()),
                )
            };
            ResultValue::Window(token_for_native(state, native)?)
        }
        Call::DestroyWindow { window } => {
            let (succeeded, invalidated_menus) = match window {
                Win16WindowTarget::Mapped(token) =>
                    worker::destroy_window_operation(state, token),
                Win16WindowTarget::Null | Win16WindowTarget::Invalid => (false, Vec::new()),
            };
            ResultValue::Destroyed { succeeded, invalidated_menus }
        }
        Call::GetClassName { window, capacity } => {
            let mut wide = vec![0xFFFF_u16; usize::from(capacity).max(1)];
            let native = hwnd(state, window);
            let valid_window = native.is_some_and(|native| unsafe { IsWindow(native) != 0 });
            let native_count = if capacity == 0 { 0 } else if let Some(native) = native {
                unsafe { GetClassNameW(native, wide.as_mut_ptr(), i32::from(capacity)) }
            } else {
                0
            };
            let (count, bytes) = if native_count > 0 {
                let units = native_count as usize;
                if units >= wide.len() || wide[units] != 0 || wide[..units].contains(&0) {
                    return Err(RuntimeError::new(runtime::DiagnosticKind::HostFailure,
                        "GetClassNameW returned an invalid terminated UTF-16 prefix"));
                }
                let encoded = state.borrow().text_codec.from_wide_bounded(
                    &wide[..units], usize::from(capacity).saturating_sub(1),
                )?;
                if encoded.used_default_char == Some(true) {
                    super::win16_window_position::report_diagnostic(
                        state,
                        runtime::DiagnosticKind::CompatibilityGap,
                        "native window class name used the guest code-page default replacement",
                    );
                }
                let count = i32::try_from(encoded.bytes.len()).unwrap_or(i32::MAX);
                let mut bytes = encoded.bytes;
                bytes.try_reserve(1).map_err(|error| RuntimeError::with_source(
                    runtime::DiagnosticKind::ResourceExhausted,
                    "terminate copied Win16 class name",
                    error,
                ))?;
                bytes.push(0);
                (count, bytes)
            } else if capacity == 1 && valid_window {
                (0, vec![0])
            } else {
                (0, Vec::new())
            };
            let class = if native_count > 0 || (capacity == 1 && valid_window) {
                native.and_then(|native| worker::registered_class_for_native(state, native))
            } else {
                None
            };
            ResultValue::ClassName { count, bytes, registered_class: class }
        }
        Call::SetActiveWindow { window } => {
            let native = hwnd(state, window).map(|native| unsafe { SetActiveWindow(native) });
            ResultValue::Window(match native {
                Some(native) => token_for_native(state, native)?,
                None => None,
            })
        }
        Call::GetActiveWindow => {
            let native = unsafe { GetActiveWindow() };
            ResultValue::Window(token_for_native(state, native)?)
        }
        Call::GetWindow { window, command } => {
            let native = hwnd(state, window)
                .map(|native| unsafe { GetWindow(native, u32::from(command)) });
            ResultValue::Window(match native {
                Some(native) => token_for_native(state, native)?,
                None => None,
            })
        }
        Call::GetTopWindow { window } => {
            let native = hwnd(state, window).map(|native| unsafe { GetTopWindow(native) });
            ResultValue::Window(match native {
                Some(native) => token_for_native(state, native)?,
                None => None,
            })
        }
        Call::ShowOwnedPopups { window, show } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { ShowOwnedPopups(native, i32::from(show)) != 0 })),
        Call::IsZoomed { window } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { IsZoomed(native) != 0 })),
        Call::GetDlgCtrlId { window } => {
            ResultValue::Integer(hwnd(state, window)
                .map_or(0, |native| unsafe { GetDlgCtrlID(native) }))
        }
        Call::GetDesktopWindow => {
            let native = unsafe { GetDesktopWindow() };
            ResultValue::Window(token_for_native(state, native)?)
        }
        Call::GetLastActivePopup { window } => {
            let native = hwnd(state, window)
                .map(|native| unsafe { GetLastActivePopup(native) });
            ResultValue::Window(match native {
                Some(native) => token_for_native(state, native)?,
                None => None,
            })
        }
        Call::ClientToScreen { window, point } => {
            let mut point = native_point(point);
            let success = hwnd(state, window)
                .is_some_and(|native| unsafe { ClientToScreen(native, &mut point) != 0 });
            ResultValue::Point(success.then_some(host_point(point)))
        }
        Call::ScreenToClient { window, point } => {
            let mut point = native_point(point);
            let success = hwnd(state, window)
                .is_some_and(|native| unsafe { ScreenToClient(native, &mut point) != 0 });
            ResultValue::Point(success.then_some(host_point(point)))
        }
        Call::MapWindowPoints { from, to, mut points } => {
            let (Some(from), Some(to)) = (hwnd(state, from), hwnd(state, to)) else {
                return Ok(ResultValue::Points(None));
            };
            for point in &mut points {
                let mut native = native_point(*point);
                // Win16 maps points, including the two RECT16 corners, without
                // Win32's later two-point RTL rectangle edge reordering. Map
                // each point separately as documented for independent points:
                // https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-mapwindowpoints
                // Zero displacement is successful, so distinguish it from an
                // error via last-error, never by testing the packed offset alone.
                unsafe { SetLastError(0); }
                let displacement = unsafe { MapWindowPoints(from, to, &mut native, 1) };
                if displacement == 0 && unsafe { GetLastError() } != 0 {
                    return Ok(ResultValue::Points(None));
                }
                *point = host_point(native);
            }
            ResultValue::Points(Some(points))
        }
        Call::WindowFromPoint { point } => {
            let native = unsafe { WindowFromPoint(native_point(point)) };
            ResultValue::Window(token_for_native(state, native)?)
        }
        Call::MoveWindow { window, x, y, width, height, repaint } => {
            ResultValue::Boolean(hwnd(state, window).is_some_and(|native| unsafe {
                MoveWindow(native, i32::from(x), i32::from(y),
                    i32::from(width), i32::from(height), i32::from(repaint)) != 0
            }))
        }
        Call::SetWindowPos { window, insert_after, x, y, width, height, flags } => {
            let insert_after = match insert_after {
                Win16WindowInsertAfter::Top => Some(std::ptr::null_mut()),
                Win16WindowInsertAfter::Bottom => Some(1_isize as HWND),
                Win16WindowInsertAfter::Topmost => Some((-1_isize) as HWND),
                Win16WindowInsertAfter::NotTopmost => Some((-2_isize) as HWND),
                Win16WindowInsertAfter::Window(token) =>
                    state.borrow().windows.get(&token).copied(),
            };
            ResultValue::Boolean(match (hwnd(state, window), insert_after) {
                (Some(native), Some(insert_after)) => unsafe {
                    SetWindowPos(native, insert_after,
                        i32::from(x), i32::from(y), i32::from(width), i32::from(height),
                        u32::from(flags)) != 0
                },
                _ => false,
            })
        }
    };
    Ok(result)
}

fn hwnd(state: &SharedWorker, target: Win16WindowTarget) -> Option<HWND> {
    match target {
        Win16WindowTarget::Null => Some(std::ptr::null_mut()),
        Win16WindowTarget::Invalid => None,
        Win16WindowTarget::Mapped(token) =>
            super::win16_window_identity::resolve_user_window(state, token),
    }
}

fn token_for_native(
    state: &SharedWorker,
    native: HWND,
) -> Result<Option<Win16HostWindow>, RuntimeError> {
    if native.is_null() { return Ok(None); }
    worker::token_for_native(state, native).map(Some)
}

fn host_rect(rect: RECT) -> Win16HostRect {
    Win16HostRect {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn native_point(point: Win16HostPoint) -> POINT {
    POINT { x: point.x, y: point.y }
}

fn host_point(point: POINT) -> Win16HostPoint {
    Win16HostPoint { x: point.x, y: point.y }
}

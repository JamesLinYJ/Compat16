//! Legacy minimized dimensions around native default WINDOWPOS processing.

use super::{
    win16_window_geometry::copy_minmax, win16_window_identity, win16_window_worker::WorkerState,
};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMinMaxInfo, Win16HostPoint, Win16HostWindow,
    Win16HostWindowPos,
};
use std::{cell::RefCell, rc::Rc};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GWL_STYLE, GetWindowLongPtrW, SM_CXBORDER, SM_CXICON, SM_CXMINIMIZED, SM_CYBORDER, SM_CYICON,
    SM_CYMINIMIZED, WM_GETMINMAXINFO, WS_MINIMIZEBOX,
};

fn legacy_minimized_size() -> Option<Win16HostPoint> {
    // Win3.x/NT 3.5's default minimized size is the icon plus four borders.
    // Modern USER substitutes a much wider minimized caption/taskbar size.
    // Use current metrics rather than a fixed application or board size.
    let axis = |icon, border| {
        let icon = crate::windows::win32_safe::system_metrics(icon);
        let border = crate::windows::win32_safe::system_metrics(border);
        (icon > 0 && border >= 0).then_some(())?;
        icon.checked_add(border.checked_mul(4)?)
    };
    Some(Win16HostPoint {
        x: axis(SM_CXICON, SM_CXBORDER)?,
        y: axis(SM_CYICON, SM_CYBORDER)?,
    })
}

/// Only the native default seed is projected. A caller-supplied different
/// reserved point and every other MINMAXINFO field retain their wire values.
pub(super) fn minmax_for_guest(
    native: &windows_sys::Win32::UI::WindowsAndMessaging::MINMAXINFO,
) -> Win16HostMinMaxInfo {
    let info = copy_minmax(native);
    let modern = Win16HostPoint {
        x: (crate::windows::win32_safe::system_metrics(SM_CXMINIMIZED)),
        y: (crate::windows::win32_safe::system_metrics(SM_CYMINIMIZED)),
    };
    project_seed(info, modern, legacy_minimized_size())
}

fn project_seed(
    mut info: Win16HostMinMaxInfo,
    modern: Win16HostPoint,
    legacy: Option<Win16HostPoint>,
) -> Win16HostMinMaxInfo {
    if info.reserved.x == modern.x
        && info.reserved.y == modern.y
        && let Some(legacy) = legacy
    {
        info.reserved = legacy;
    }
    info
}

#[derive(Clone, Copy)]
struct SizingKey {
    operation: u64,
    window: Win16HostWindow,
    hwnd: usize,
    cookie: usize,
    callback_depth: usize,
}

impl SizingKey {
    fn accepts(&self, other: Self) -> bool {
        self.operation == other.operation
            && self.window == other.window
            && self.hwnd == other.hwnd
            && self.cookie == other.cookie
            && self.callback_depth.checked_add(1) == Some(other.callback_depth)
    }
}

struct SizingFrame {
    id: u64,
    key: SizingKey,
    minmax: Option<Win16HostMinMaxInfo>,
}

#[derive(Default)]
pub(super) struct SizingContexts {
    next_id: u64,
    frames: Vec<SizingFrame>,
    creations: Vec<creation::CreationFrame>,
}

#[path = "win16_window_sizing_creation.rs"]
mod creation;
pub(super) use creation::MinimizedCreation;
#[cfg(test)]
pub(super) use creation::repair_restore_size;

#[cfg(test)]
impl SizingContexts {
    pub(super) fn is_empty(&self) -> bool {
        self.frames.is_empty() && self.creations.is_empty()
    }
}

pub(super) struct MinimizedDefault {
    state: Rc<RefCell<WorkerState>>,
    id: u64,
    key: SizingKey,
    minimum: Win16HostPoint,
    fixed_minimum: bool,
}

impl MinimizedDefault {
    /// Retain the exact default-operation and HWND incarnation while native
    /// USER asks the guest for constraints. Its post-message validation resets
    /// the reserved point, so observe the checked guest reply before that step.
    pub(super) fn enter(
        state: &Rc<RefCell<WorkerState>>,
        window: Win16HostWindow,
        hwnd: HWND,
    ) -> Result<Option<Self>, RuntimeError> {
        if win16_window_identity::resolve(state, window) != Some(hwnd) {
            return Ok(None);
        }
        let minimum = legacy_minimized_size().ok_or_else(|| {
            RuntimeError::new(Kind::HostFailure, "query legacy minimized-window metrics")
        })?;
        // SAFETY: `GetWindowLongPtrW`, `Err` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let style = unsafe {
            crate::windows::win32_safe::set_last_error(0);
            let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
            if style == 0 && crate::windows::win32_safe::last_error() != 0 {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "query minimized-window styles",
                ));
            }
            style as u32
        };
        let shared = Rc::clone(state);
        let mut state = state.borrow_mut();
        let Some(operation) = state.active_operations.last().map(|active| active.id) else {
            return Ok(None);
        };
        let Some(cookie) = state.window_identity_cookies.get(&window).copied() else {
            return Ok(None);
        };
        let key = SizingKey {
            operation,
            window,
            hwnd: hwnd as usize,
            cookie: cookie.value,
            callback_depth: state.live_callbacks.len(),
        };
        let contexts = &mut state.window_sizing_contexts;
        let id = contexts.next_id.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "minimized sizing context identity exhausted",
            )
        })?;
        contexts.frames.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve minimized sizing context",
                error,
            )
        })?;
        contexts.next_id = id;
        contexts.frames.push(SizingFrame {
            id,
            key,
            minmax: None,
        });
        Ok(Some(Self {
            state: shared,
            id,
            key,
            minimum,
            fixed_minimum: style & WS_MINIMIZEBOX != 0,
        }))
    }

    pub(super) fn adjust(
        &self,
        requested: Win16HostWindowPos,
        output: &mut Win16HostWindowPos,
    ) -> Result<(), RuntimeError> {
        let state = self.state.borrow();
        let frame = state
            .window_sizing_contexts
            .frames
            .last()
            .filter(|frame| frame.id == self.id && frame.key.operation == self.key.operation)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "minimized sizing context changed during native default processing",
                )
            })?;
        if let Some(info) = frame.minmax {
            let minimum = if self.fixed_minimum {
                self.minimum
            } else {
                info.reserved
            };
            output.width = clamp(requested.width, minimum.x, info.max_size.x);
            output.height = clamp(requested.height, minimum.y, info.max_size.y);
        }
        Ok(())
    }
}

fn clamp(requested: i32, minimum: i32, maximum: i32) -> i32 {
    // Legacy USER enforces the minimum last, including a maximum below it.
    minimum.max(requested.min(maximum))
}

impl Drop for MinimizedDefault {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        if state
            .window_sizing_contexts
            .frames
            .last()
            .is_some_and(|frame| frame.id == self.id)
        {
            state.window_sizing_contexts.frames.pop();
        } else {
            drop(state);
            super::win16_window_callbacks::fail_worker(
                &self.state,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "minimized sizing contexts did not unwind in LIFO order",
                ),
            );
        }
    }
}

/// Called only after the callback reply and its native output shape passed
/// validation. Nested defaults cannot supply constraints to an outer frame.
pub(super) fn record_minmax(
    state: &Rc<RefCell<WorkerState>>,
    receiver: Option<(Win16HostWindow, HWND)>,
    info: Win16HostMinMaxInfo,
) {
    let Some((window, hwnd)) = receiver else {
        return;
    };
    if win16_window_identity::resolve(state, window) != Some(hwnd) {
        return;
    }
    let mut state = state.borrow_mut();
    let Some(operation) = state.active_operations.last().map(|active| active.id) else {
        return;
    };
    let Some(callback) = state.live_callbacks.last() else {
        return;
    };
    if callback.operation != operation
        || callback.message != Some(WM_GETMINMAXINFO)
        || !callback
            .identity
            .is_some_and(|identity| identity.window == window)
    {
        return;
    }
    let creation = callback.identity.and_then(|identity| identity.creation);
    let Some(cookie) = state.window_identity_cookies.get(&window).copied() else {
        return;
    };
    let observed = SizingKey {
        operation,
        window,
        hwnd: hwnd as usize,
        cookie: cookie.value,
        callback_depth: state.live_callbacks.len(),
    };
    creation::record(&mut state, observed, creation, info);
    if let Some(frame) = state.window_sizing_contexts.frames.last_mut()
        && frame.key.accepts(observed)
    {
        frame.minmax = Some(info);
    }
}

#[cfg(test)]
#[path = "win16_window_sizing_tests.rs"]
mod tests;

//! Native NCCALCSIZE marshalling. Native pointers stay in this host module.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostNonClientCalcSize, Win16HostRect,
    Win16HostWindow, Win16WindowStep,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, RECT};
use windows_sys::Win32::UI::WindowsAndMessaging::{NCCALCSIZE_PARAMS, WINDOWPOS};

use super::WorkerState;

/// The input data is copied for the guest; this pointer is a host-only lease
/// to USER's original nested WINDOWPOS while the native WndProc is suspended.
pub(in crate::windows::win16_windows) struct NativeNonClientInput {
    pub(in crate::windows::win16_windows) w_param: u16,
    pub(in crate::windows::win16_windows) data: Win16HostNonClientCalcSize,
    pub(in crate::windows::win16_windows) original_position: Option<*mut WINDOWPOS>,
    pub(in crate::windows::win16_windows) original_position_high_flags: Option<u32>,
}

/// Host-owned native structures passed to a synchronous default/procedure/send
/// call. Boxes keep the LPARAM targets and nested WINDOWPOS stable through any
/// guest callback reentered by that call.
pub(in crate::windows::win16_windows) struct NativeNonClientCalcSize {
    data: NativeNonClientCalcSizeData,
}

enum NativeNonClientCalcSizeData {
    Rect(Box<RECT>),
    ValidRects {
        params: Box<NCCALCSIZE_PARAMS>,
        position: Option<Box<super::super::win16_window_position::NativeWindowPosition>>,
    },
}

pub(in crate::windows::win16_windows) fn copy_native_input(
    state: &Rc<RefCell<WorkerState>>,
    w_param: usize,
    l_param: LPARAM,
) -> Result<NativeNonClientInput, RuntimeError> {
    // This is a BOOL, not a scalar count. Preserve native values that fit a
    // Win16 word; normalize wider nonzero values to TRUE so layout and guest
    // shape cannot disagree after narrowing.
    let w_param = if w_param == 0 {
        0
    } else {
        u16::try_from(w_param).unwrap_or(1)
    };
    if l_param == 0 {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "native WM_NCCALCSIZE has a null structure pointer"));
    }

    if w_param == 0 {
        // SAFETY: USER supplies a writable RECT for the synchronous false
        // branch. Do not inspect any bytes after this first RECT.
        let rect = unsafe { &*(l_param as *const RECT) };
        return Ok(NativeNonClientInput {
            w_param,
            data: Win16HostNonClientCalcSize::Rect(copy_rect(rect)),
            original_position: None,
            original_position_high_flags: None,
        });
    }

    // SAFETY: USER supplies NCCALCSIZE_PARAMS for the true branch. Its nested
    // lppos remains valid until this native WndProc returns.
    let params = unsafe { &*(l_param as *const NCCALCSIZE_PARAMS) };
    let original_position = if params.lppos.is_null() {
        None
    } else {
        Some(params.lppos)
    };
    let (position, original_position_high_flags) = match original_position {
        Some(pointer) => {
            let (position, _identity, high_flags) =
                super::super::win16_window_position::copy_from_native(
                    state, unsafe { &*pointer },
                )?;
            (Some(position), Some(high_flags))
        }
        None => (None, None),
    };
    Ok(NativeNonClientInput {
        w_param,
        data: Win16HostNonClientCalcSize::ValidRects {
            rects: params.rgrc.map(|rect| copy_rect(&rect)),
            position,
        },
        original_position,
        original_position_high_flags,
    })
}

impl NativeNonClientCalcSize {
    pub(in crate::windows::win16_windows) fn from_owned(
        state: &Rc<RefCell<WorkerState>>,
        w_param: u16,
        data: Win16HostNonClientCalcSize,
    ) -> Result<Option<Box<Self>>, RuntimeError> {
        match (w_param == 0, data) {
            (true, Win16HostNonClientCalcSize::Rect(rect)) => {
                Ok(Some(Box::new(Self {
                    data: NativeNonClientCalcSizeData::Rect(Box::new(native_rect(rect))),
                })))
            }
            (false, Win16HostNonClientCalcSize::ValidRects { rects, position }) => {
                let position = match position {
                    Some(typed) => {
                        // The shared owner snapshots both raw handles and
                        // their tokens before reentrant USER execution.
                        let Some(native) =
                            super::super::win16_window_position::NativeWindowPosition::from_owned(
                                state, typed,
                            )?
                        else { return Ok(None); };
                        Some(native)
                    }
                    None => None,
                };
                let params = NCCALCSIZE_PARAMS {
                    rgrc: rects.map(native_rect),
                    // Derive this pointer only after the complete boxed owner
                    // reaches its final location in `l_param`.
                    lppos: std::ptr::null_mut(),
                };
                Ok(Some(Box::new(Self {
                    data: NativeNonClientCalcSizeData::ValidRects {
                        params: Box::new(params),
                        position,
                    },
                })))
            }
            _ => Err(RuntimeError::new(Kind::InvalidInput,
                "Win16 WM_NCCALCSIZE parameter and rectangle shape disagree")),
        }
    }

    /// Publish native pointers only after this boxed owner has been built.
    /// Callers must keep the Box in place and alive until the synchronous USER
    /// call returns; the returned LPARAM is not an independent owner/borrow.
    pub(in crate::windows::win16_windows) fn l_param(&mut self) -> LPARAM {
        match &mut self.data {
            NativeNonClientCalcSizeData::Rect(rect) => (&mut **rect as *mut RECT) as LPARAM,
            NativeNonClientCalcSizeData::ValidRects { params, position } => {
                params.lppos = position.as_deref_mut().map_or(std::ptr::null_mut(),
                    |position| position.native_ptr());
                (&mut **params as *mut NCCALCSIZE_PARAMS) as LPARAM
            }
        }
    }

    pub(in crate::windows::win16_windows) fn owned_output(
        &self,
        state: &Rc<RefCell<WorkerState>>,
    ) -> Result<Option<Win16HostNonClientCalcSize>, RuntimeError> {
        match &self.data {
            NativeNonClientCalcSizeData::Rect(rect) => {
                Ok(Some(Win16HostNonClientCalcSize::Rect(copy_rect(rect))))
            }
            NativeNonClientCalcSizeData::ValidRects { params, position } => {
                // This is the owned pointer projection limit: never follow
                // params.lppos after native code may have rewritten it. Read
                // only this call's WINDOWPOS box, never an unknown pointer.
                let expected_lppos = position.as_ref().map_or(
                    0,
                    |position| position.native_address(),
                );
                let pointer_changed = params.lppos as usize != expected_lppos;
                let position = match position.as_deref() {
                    Some(position) => {
                        let Some(position) = position.owned_output(state)? else {
                            return Ok(None);
                        };
                        Some(position)
                    }
                    None => None,
                };
                let rects = params.rgrc.map(|rect| copy_rect(&rect));
                if pointer_changed {
                    report_nonclient_gap(
                        state,
                        "native WINDOWPOS pointer changed; owned position retained, rectangle values returned",
                    );
                }
                Ok(Some(Win16HostNonClientCalcSize::ValidRects {
                    rects,
                    position,
                }))
            }
        }
    }

    pub(in crate::windows::win16_windows) fn receiver_is_current(
        state: &Rc<RefCell<WorkerState>>,
        window: Win16HostWindow,
        hwnd: HWND,
    ) -> bool {
        super::super::win16_window_identity::resolve_user_window(state, window) == Some(hwnd)
    }
}

pub(in crate::windows::win16_windows) fn write_output(
    state: &Rc<RefCell<WorkerState>>,
    receiver: Option<(Win16HostWindow, HWND)>,
    w_param: usize,
    l_param: LPARAM,
    original_position: Option<*mut WINDOWPOS>,
    original_position_high_flags: Option<u32>,
    data: Win16HostNonClientCalcSize,
) -> bool {
    if l_param == 0 { return false; }
    if receiver.is_some_and(|(window, hwnd)| {
        !NativeNonClientCalcSize::receiver_is_current(state, window, hwnd)
    }) {
        // Reentrant guest work may have destroyed this receiver. Its original
        // native payload is no longer a safe destination for callback output.
        return true;
    }

    match (w_param == 0, data) {
        (true, Win16HostNonClientCalcSize::Rect(rect)) => {
            let native = native_rect(rect);
            // SAFETY: The original synchronous false-branch caller supplied a
            // writable RECT and the owned shape was validated above.
            unsafe { *(l_param as *mut RECT) = native; }
            true
        }
        (false, Win16HostNonClientCalcSize::ValidRects { rects, position }) => {
            let (native_position, nullness_changed, invalid_position) =
                match (original_position, position) {
                (Some(_), Some(position)) => match super::super::win16_window_position::
                    checked_native_position(state, position)
                {
                    Ok(Some(mut position)) => {
                        let Some(original_high_flags) = original_position_high_flags else {
                            return false;
                        };
                        position.flags = super::super::win16_window_position::
                            merge_callback_flags(position.flags, original_high_flags);
                        (Some(position), false, false)
                    }
                    // Retain the native nested destination, but rectangles
                    // remain independently checked and can still be applied.
                    Ok(None) => (None, false, true),
                    Err(_) => return false,
                },
                (None, Some(position)) => {
                    // Validate every output handle even though there is no
                    // native nested destination in which to project the value.
                    match super::super::win16_window_position::checked_native_position(
                        state, position,
                    ) {
                        Ok(Some(_)) => (None, true, false),
                        Ok(None) => (None, false, true),
                        Err(_) => return false,
                    }
                }
                (Some(_), None) => (None, true, false),
                (None, None) => (None, false, false),
            };
            let native_rects = rects.map(native_rect);
            let params = l_param as *mut NCCALCSIZE_PARAMS;

            if invalid_position {
                report_nonclient_gap(
                    state,
                    "invalid or retired WINDOWPOS HWND; original native position retained, rectangle output applied",
                );
            } else if nullness_changed {
                report_pointer_nullness_change(state);
            }

            // SAFETY: All shape, destination, and opaque-handle checks finish
            // before the first write. Assign only the rectangles and, when
            // both sides supplied it, the original nested WINDOWPOS. Never
            // overwrite NCCALCSIZE_PARAMS::lppos with guest/shared data.
            unsafe {
                (*params).rgrc = native_rects;
                if let (Some(pointer), Some(position)) = (original_position, native_position) {
                    pointer.write(position);
                }
            }
            true
        }
        _ => false,
    }
}

fn report_pointer_nullness_change(state: &Rc<RefCell<WorkerState>>) {
    report_nonclient_gap(
        state,
        "WINDOWPOS pointer nullness changed; original native destination preserved, rectangle output applied",
    );
}

fn report_nonclient_gap(state: &Rc<RefCell<WorkerState>>, message: &'static str) {
    let active = state.borrow().active_operations.last().cloned();
    if let Some(active) = active {
        let diagnostic = runtime::Diagnostic::warning(Kind::CompatibilityGap, message);
        // Runtime consumes diagnostics as recoverable operation steps, then
        // resumes this same suspended USER call without a callback reply.
        let _ = active.response.send(Ok(Win16WindowStep::Diagnostic(diagnostic)));
    }
}

fn copy_rect(rect: &RECT) -> Win16HostRect {
    Win16HostRect {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn native_rect(rect: Win16HostRect) -> RECT {
    RECT {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

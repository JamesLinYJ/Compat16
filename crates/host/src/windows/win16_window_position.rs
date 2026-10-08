//! Native WINDOWPOS identity conversion and owned synchronous-call storage.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostWindow, Win16HostWindowPos,
    Win16WindowInsertAfter, Win16WindowStep,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BOTTOM, HWND_NOTOPMOST, HWND_TOP, HWND_TOPMOST, WINDOWPOS,
};

use super::win16_window_worker::{self as worker_window, WorkerState};

const WIN16_WINDOWPOS_FLAGS_MASK: u32 = u16::MAX as u32;

/// A native WINDOWPOS HWND after Win16 tokenization plus the exact raw values
/// observed when the token was copied. The tokens protect against HWND reuse
/// across reentrant USER calls.
#[derive(Clone, Copy)]
pub(in crate::windows::win16_windows) struct NativeWindowPosIdentity {
    typed: Win16HostWindowPos,
    hwnd: HWND,
    hwnd_insert_after: HWND,
}

/// Host-owned storage passed to DefWindowProc/CallWindowProc/SendMessage.
/// The outer Box remains in place throughout the synchronous native call.
pub(in crate::windows::win16_windows) struct NativeWindowPosition {
    position: Box<WINDOWPOS>,
    identity: NativeWindowPosIdentity,
}

pub(in crate::windows::win16_windows) struct NativeWindowPositionInput {
    pub(in crate::windows::win16_windows) w_param: u16,
    pub(in crate::windows::win16_windows) data: Win16HostWindowPos,
    pub(in crate::windows::win16_windows) native_high_flags: u32,
}

pub(in crate::windows::win16_windows) fn copy_native_input(
    state: &Rc<RefCell<WorkerState>>,
    w_param: usize,
    l_param: LPARAM,
) -> Result<Option<NativeWindowPositionInput>, RuntimeError> {
    if l_param == 0 {
        return Ok(None);
    }
    // Win16 WPARAM is a WORD; keep that value unchanged at the ABI boundary.
    let w_param = w_param as u16;
    // SAFETY: The native WndProc/DLGPROC caller owns a valid WINDOWPOS for this
    // synchronous message. Only copied fields and opaque host tokens escape.
    let native = unsafe { &*(l_param as *const WINDOWPOS) };
    let (data, _, native_high_flags) = copy_from_native(state, native)?;
    Ok(Some(NativeWindowPositionInput { w_param, data, native_high_flags }))
}

pub(in crate::windows::win16_windows) fn copy_from_native(
    state: &Rc<RefCell<WorkerState>>,
    native: &WINDOWPOS,
) -> Result<(Win16HostWindowPos, NativeWindowPosIdentity, u32), RuntimeError> {
    let window = if native.hwnd.is_null() {
        None
    } else {
        Some(worker_window::token_for_native(state, native.hwnd)?)
    };
    let insert_after = if native.hwndInsertAfter == HWND_TOP {
        Win16WindowInsertAfter::Top
    } else if native.hwndInsertAfter == HWND_BOTTOM {
        Win16WindowInsertAfter::Bottom
    } else if native.hwndInsertAfter == HWND_TOPMOST {
        Win16WindowInsertAfter::Topmost
    } else if native.hwndInsertAfter == HWND_NOTOPMOST {
        Win16WindowInsertAfter::NotTopmost
    } else {
        Win16WindowInsertAfter::Window(
            worker_window::token_for_native(state, native.hwndInsertAfter)?,
        )
    };
    let typed = Win16HostWindowPos {
        window,
        insert_after,
        x: native.x,
        y: native.y,
        width: native.cx,
        height: native.cy,
        flags: native.flags & WIN16_WINDOWPOS_FLAGS_MASK,
    };
    let identity = NativeWindowPosIdentity {
        typed,
        hwnd: native.hwnd,
        hwnd_insert_after: native.hwndInsertAfter,
    };
    Ok((typed, identity, native.flags & !WIN16_WINDOWPOS_FLAGS_MASK))
}

impl NativeWindowPosition {
    pub(in crate::windows::win16_windows) fn from_owned(
        state: &Rc<RefCell<WorkerState>>,
        typed: Win16HostWindowPos,
    ) -> Result<Option<Box<Self>>, RuntimeError> {
        let native = match native_from_owned(state, typed) {
            Ok(native) => native,
            Err(error) if error.kind() == Kind::InvalidInput => return Ok(None),
            Err(error) => return Err(error),
        };
        let identity = NativeWindowPosIdentity {
            typed,
            hwnd: native.hwnd,
            hwnd_insert_after: native.hwndInsertAfter,
        };
        Ok(Some(Box::new(Self {
            position: Box::new(native),
            identity,
        })))
    }

    /// Derive the pointer only after this owner is boxed. Keep this Box alive
    /// and unmoved until the synchronous native call returns.
    pub(in crate::windows::win16_windows) fn l_param(&mut self) -> LPARAM {
        self.native_ptr() as LPARAM
    }

    pub(in crate::windows::win16_windows) fn native_ptr(&mut self) -> *mut WINDOWPOS {
        std::ptr::from_mut(self.position.as_mut())
    }

    pub(in crate::windows::win16_windows) fn native_address(&self) -> usize {
        std::ptr::from_ref(self.position.as_ref()) as usize
    }

    pub(in crate::windows::win16_windows) fn owned_output(
        &self,
        state: &Rc<RefCell<WorkerState>>,
    ) -> Result<Option<Win16HostWindowPos>, RuntimeError> {
        project_window_pos(state, &self.position, self.identity)
    }
}

pub(in crate::windows::win16_windows) fn checked_native_position(
    state: &Rc<RefCell<WorkerState>>,
    position: Win16HostWindowPos,
) -> Result<Option<WINDOWPOS>, RuntimeError> {
    let window = resolve_window(state, position.window);
    let insert_after = resolve_insert_after(state, position.insert_after);
    let window = match window {
        Ok(window) => Some(window),
        Err(error) if error.kind() == Kind::InvalidInput => None,
        Err(error) => return Err(error),
    };
    let insert_after = match insert_after {
        Ok(insert_after) => Some(insert_after),
        Err(error) if error.kind() == Kind::InvalidInput => None,
        Err(error) => return Err(error),
    };
    let (Some(hwnd), Some(hwnd_insert_after)) = (window, insert_after) else {
        return Ok(None);
    };
    Ok(Some(native_position(position, hwnd, hwnd_insert_after)))
}

pub(in crate::windows::win16_windows) fn write_output(
    state: &Rc<RefCell<WorkerState>>,
    receiver: Option<(Win16HostWindow, HWND)>,
    l_param: LPARAM,
    position: Win16HostWindowPos,
    original_native_high_flags: u32,
) -> bool {
    if l_param == 0 {
        return false;
    }
    if receiver.is_some_and(|(window, hwnd)| !receiver_is_current(state, window, hwnd)) {
        // Guest reentry may destroy the receiver. Its old LPARAM is no longer
        // a valid output target, even if USER has since reused the HWND bits.
        return true;
    }
    let mut native = match checked_native_position(state, position) {
        Ok(Some(native)) => native,
        Ok(None) => {
            report_diagnostic(
                state,
                Kind::InvalidInput,
                "Win16 WINDOWPOS output contains an unmapped or stale HWND; original native WINDOWPOS preserved",
            );
            return true;
        }
        Err(_) => return false,
    };
    native.flags = merge_callback_flags(native.flags, original_native_high_flags);
    // SAFETY: USER owns this synchronous writable WINDOWPOS. All tokens and
    // the complete output shape were checked before the first native write.
    unsafe { (l_param as *mut WINDOWPOS).write(native); }
    true
}

pub(in crate::windows::win16_windows) fn report_missing_changing_output(
    state: &Rc<RefCell<WorkerState>>,
    receiver: Option<(Win16HostWindow, HWND)>,
    l_param: LPARAM,
) -> bool {
    if l_param == 0 {
        return false;
    }
    if receiver.is_some_and(|(window, hwnd)| !receiver_is_current(state, window, hwnd)) {
        return true;
    }
    report_diagnostic(
        state,
        Kind::CompatibilityGap,
        "Win16 WM_WINDOWPOSCHANGING returned no WINDOWPOS output; original native WINDOWPOS preserved",
    );
    true
}

pub(in crate::windows::win16_windows) fn merge_callback_flags(
    output_flags: u32,
    original_native_high_flags: u32,
) -> u32 {
    (output_flags & u16::MAX as u32)
        | (original_native_high_flags & !(u16::MAX as u32))
}

pub(in crate::windows::win16_windows) fn receiver_is_current(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
) -> bool {
    super::win16_window_identity::resolve_user_window(state, window) == Some(hwnd)
}

pub(in crate::windows::win16_windows) fn report_diagnostic(
    state: &Rc<RefCell<WorkerState>>,
    kind: Kind,
    message: impl Into<String>,
) {
    let active = state.borrow().active_operations.last().cloned();
    if let Some(active) = active {
        let diagnostic = runtime::Diagnostic::warning(kind, message);
        let _ = active.response.send(Ok(Win16WindowStep::Diagnostic(diagnostic)));
    }
}

fn native_from_owned(
    state: &Rc<RefCell<WorkerState>>,
    position: Win16HostWindowPos,
) -> Result<WINDOWPOS, RuntimeError> {
    let hwnd = resolve_window(state, position.window)?;
    let hwnd_insert_after = resolve_insert_after(state, position.insert_after)?;
    Ok(native_position(position, hwnd, hwnd_insert_after))
}

fn native_position(
    position: Win16HostWindowPos,
    hwnd: HWND,
    hwnd_insert_after: HWND,
) -> WINDOWPOS {
    WINDOWPOS {
        hwnd,
        hwndInsertAfter: hwnd_insert_after,
        x: position.x,
        y: position.y,
        cx: position.width,
        cy: position.height,
        flags: position.flags & WIN16_WINDOWPOS_FLAGS_MASK,
    }
}

fn resolve_window(
    state: &Rc<RefCell<WorkerState>>,
    window: Option<Win16HostWindow>,
) -> Result<HWND, RuntimeError> {
    match window {
        Some(token) => resolve_token(state, token),
        None => Ok(std::ptr::null_mut()),
    }
}

fn resolve_insert_after(
    state: &Rc<RefCell<WorkerState>>,
    insert_after: Win16WindowInsertAfter,
) -> Result<HWND, RuntimeError> {
    match insert_after {
        Win16WindowInsertAfter::Top => Ok(HWND_TOP),
        Win16WindowInsertAfter::Bottom => Ok(HWND_BOTTOM),
        Win16WindowInsertAfter::Topmost => Ok(HWND_TOPMOST),
        Win16WindowInsertAfter::NotTopmost => Ok(HWND_NOTOPMOST),
        Win16WindowInsertAfter::Window(token) => resolve_token(state, token),
    }
}

fn resolve_token(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
) -> Result<HWND, RuntimeError> {
    super::win16_window_identity::resolve_user_window(state, token).ok_or_else(|| {
        RuntimeError::new(Kind::InvalidInput,
            "Win16 WINDOWPOS contains an unmapped or stale non-NULL HWND token")
    })
}

fn project_window_pos(
    state: &Rc<RefCell<WorkerState>>,
    native: &WINDOWPOS,
    original: NativeWindowPosIdentity,
) -> Result<Option<Win16HostWindowPos>, RuntimeError> {
    let window = if native.hwnd == original.hwnd {
        match original.typed.window {
            Some(token) if resolve_token(state, token).ok() == Some(original.hwnd) => Some(token),
            None if original.hwnd.is_null() => None,
            _ => return Ok(None),
        }
    } else if native.hwnd.is_null() {
        None
    } else {
        match worker_window::token_for_native(state, native.hwnd) {
            Ok(token) => Some(token),
            Err(error) if error.kind() == Kind::InvalidInput => return Ok(None),
            Err(error) => return Err(error),
        }
    };

    let insert_after = if native.hwndInsertAfter == original.hwnd_insert_after {
        match original.typed.insert_after {
            Win16WindowInsertAfter::Window(token)
                if resolve_token(state, token).ok() == Some(original.hwnd_insert_after) =>
                    Win16WindowInsertAfter::Window(token),
            Win16WindowInsertAfter::Window(_) => return Ok(None),
            pseudo => pseudo,
        }
    } else if native.hwndInsertAfter == HWND_TOP {
        Win16WindowInsertAfter::Top
    } else if native.hwndInsertAfter == HWND_BOTTOM {
        Win16WindowInsertAfter::Bottom
    } else if native.hwndInsertAfter == HWND_TOPMOST {
        Win16WindowInsertAfter::Topmost
    } else if native.hwndInsertAfter == HWND_NOTOPMOST {
        Win16WindowInsertAfter::NotTopmost
    } else {
        match worker_window::token_for_native(state, native.hwndInsertAfter) {
            Ok(token) => Win16WindowInsertAfter::Window(token),
            Err(error) if error.kind() == Kind::InvalidInput => return Ok(None),
            Err(error) => return Err(error),
        }
    };

    Ok(Some(Win16HostWindowPos {
        window,
        insert_after,
        x: native.x,
        y: native.y,
        width: native.cx,
        height: native.cy,
        flags: native.flags & WIN16_WINDOWPOS_FLAGS_MASK,
    }))
}

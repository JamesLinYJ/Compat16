//! GrayStringW with an owner-thread guest callback and borrowed memory DC.

use super::super::win16_gdi::Win16Dcs;
use super::{
    Win16Objects,
    win16_window_worker::{LiveCallback, WorkerState},
};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCallback, Win16HostDc, Win16HostGdiObject,
    Win16NativeCallbackSource, Win16WindowOperation, Win16WindowStep,
};
use std::{
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};
use windows_sys::Win32::{
    Foundation::{LPARAM, SIZE},
    Graphics::Gdi::{
        CreateCompatibleDC, DeleteDC, GetTextExtentPoint32W, GrayStringW, HBRUSH, HDC, HGDIOBJ,
        SelectObject,
    },
};

/// A private selection keeps the exact native brush alive during the callback.
/// GDI rejects DeleteObject on a selected brush; no host table borrow or mutex
/// crosses native USER or guest execution. Native bits stay in this adapter.
pub(super) struct BrushLease {
    dc: usize,
    brush: usize,
    previous: usize,
}
impl BrushLease {
    pub(super) fn capture(objects: &Win16Objects, token: Win16HostGdiObject) -> Option<Self> {
        let brush = objects.native_brush(token)?;
        // SAFETY: NULL creates a private memory DC on the live runtime thread.
        let dc = unsafe { CreateCompatibleDC(std::ptr::null_mut()) };
        if dc.is_null() {
            return None;
        }
        // SAFETY: brush was type-checked by the host object table; this DC is private.
        let previous = unsafe { SelectObject(dc, brush) };
        if previous.is_null() || previous as isize == -1 {
            unsafe {
                DeleteDC(dc);
            }
            return None;
        }
        Some(Self {
            dc: dc as usize,
            brush: brush as usize,
            previous: previous as usize,
        })
    }
}
impl Drop for BrushLease {
    fn drop(&mut self) {
        // SAFETY: The selection DC is uniquely owned; the previous brush is
        // restored before deletion. The input brush belongs to Win16Objects.
        unsafe {
            SelectObject(self.dc as HDC, self.previous as HGDIOBJ);
            DeleteDC(self.dc as HDC);
        }
    }
}

struct CallbackContext {
    state: Rc<RefCell<WorkerState>>,
    dcs: Win16Dcs,
    count: i16,
}
struct CallbackDc {
    state: Rc<RefCell<WorkerState>>,
    dcs: Win16Dcs,
    callback: Win16HostCallback,
    dc: Win16HostDc,
}
impl Drop for CallbackDc {
    fn drop(&mut self) {
        super::win16_window_callbacks::remove_live_callback(&self.state, self.callback);
        if !self.dcs.retire_function_dc(self.dc, self.callback) {
            super::win16_window_callbacks::fail_worker(
                &self.state,
                invariant("GrayString callback lost its exact borrowed native DC"),
            );
        }
    }
}

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    request: Win16WindowOperation,
    brush: Option<&BrushLease>,
) -> Result<bool, RuntimeError> {
    let Win16WindowOperation::GrayString {
        dc,
        brush: requested_brush,
        text,
        count,
        x,
        y,
        width,
        height,
        callback,
    } = request
    else {
        return Err(invariant("GrayString worker received another operation"));
    };
    if requested_brush.is_some() && brush.is_none() {
        return Ok(false);
    }
    let (dcs, codec) = {
        let worker = state.borrow();
        (worker.dcs.clone(), worker.text_codec)
    };
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(false);
    };
    let mut wide = text
        .as_deref()
        .map(|text| codec.to_wide(text))
        .transpose()?;
    let text_count = wide.as_ref().map_or(0, Vec::len) as i32;
    if let Some(wide) = &mut wide {
        wide.push(0);
    }
    let mut cx = i32::from(width);
    let mut cy = i32::from(height);
    // lpData is opaque callback state. Resolve all documented string-derived
    // dimensions before replacing it with the private native callback context.
    if callback && (cx == 0 || cy == 0) {
        let Some(text) = &wide else {
            return Ok(false);
        };
        let mut size = SIZE::default();
        // SAFETY: dc_use pins the target; copied UTF-16 has text_count units.
        if unsafe { GetTextExtentPoint32W(dc_use.native(), text.as_ptr(), text_count, &mut size) }
            == 0
        {
            return Ok(false);
        }
        cx = size.cx;
        cy = size.cy;
        if cx == 0 || cy == 0 {
            return Ok(false);
        }
    }
    let brush = brush.map_or(std::ptr::null_mut(), |brush| brush.brush as HBRUSH);
    if callback {
        let context = CallbackContext {
            state: Rc::clone(state),
            dcs,
            count: count as i16,
        };
        // Native USER must not treat our private context as a NUL-terminated
        // string for an empty guest string. Guest callback count remains zero.
        let native_count = if count == 0 { 1 } else { count };
        // SAFETY: Context and native resources outlive GrayStringW and every
        // nested callback. No guest address is passed to the host function.
        Ok(unsafe {
            GrayStringW(
                dc_use.native(),
                brush,
                Some(draw_callback),
                (&context as *const CallbackContext) as LPARAM,
                native_count,
                i32::from(x),
                i32::from(y),
                cx,
                cy,
            )
        } != 0)
    } else {
        let Some(text) = &wide else {
            return Ok(false);
        };
        // SAFETY: The exact counted UTF-16 prefix and trailing NUL remain live.
        Ok(unsafe {
            GrayStringW(
                dc_use.native(),
                brush,
                None,
                text.as_ptr() as LPARAM,
                text_count,
                i32::from(x),
                i32::from(y),
                cx,
                cy,
            )
        } != 0)
    }
}

unsafe extern "system" fn draw_callback(dc: HDC, parameter: LPARAM, _native_count: i32) -> i32 {
    // SAFETY: Only execute installs this callback and passes its live context.
    let context = unsafe { &*(parameter as *const CallbackContext) };
    match catch_unwind(AssertUnwindSafe(|| draw_callback_inner(dc, context))) {
        Ok(value) => value,
        Err(_) => {
            super::win16_window_callbacks::fail_worker(
                &context.state,
                invariant("GrayString native callback panicked"),
            );
            0
        }
    }
}

fn draw_callback_inner(native: HDC, context: &CallbackContext) -> i32 {
    let state = &context.state;
    let active = {
        let worker = state.borrow();
        if worker.callbacks_enabled && !worker.aborted {
            worker.active_operations.last().cloned()
        } else {
            None
        }
    };
    let Some(active) = active else {
        super::win16_window_callbacks::fail_worker(
            state,
            invariant("GrayString callback has no active USER operation"),
        );
        return 0;
    };
    let reserved = state.borrow_mut().live_callbacks.try_reserve(1);
    if let Err(error) = reserved {
        super::win16_window_callbacks::fail_worker(
            state,
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve GrayString callback identity",
                error,
            ),
        );
        return 0;
    }
    let Some(callback) = super::win16_window_worker::allocate_callback_id(state) else {
        super::win16_window_callbacks::fail_worker(
            state,
            RuntimeError::new(
                Kind::ResourceExhausted,
                "GrayString callback identity exhausted",
            ),
        );
        return 0;
    };
    let dc = match context.dcs.adopt_function_dc(callback, native as usize) {
        Ok(Some(dc)) => dc,
        Ok(None) => return 0,
        Err(error) => {
            super::win16_window_callbacks::fail_worker(state, error);
            return 0;
        }
    };
    let source = Win16NativeCallbackSource::GrayString { dc };
    state.borrow_mut().live_callbacks.push(LiveCallback {
        callback,
        operation: active.id,
        source,
        creation: None,
        identity: None,
        message: None,
        hwnd: std::ptr::null_mut(),
        w_param: None,
        l_param: None,
        native_message_context: None,
        creation_cookie: None,
        mdi_create_struct: None,
    });
    let _guard = CallbackDc {
        state: Rc::clone(state),
        dcs: context.dcs.clone(),
        callback,
        dc,
    };
    crate::windows::win16_gdi::flush_thread_batch();
    if active
        .response
        .send(Ok(Win16WindowStep::GrayStringCallback {
            operation_id: runtime::Win16HostWindowOperationId(active.id),
            callback,
            dc,
            count: context.count,
            source,
        }))
        .is_err()
    {
        super::win16_window_callbacks::fail_worker(
            state,
            RuntimeError::new(
                Kind::HostFailure,
                "runtime dropped a suspended GrayString callback",
            ),
        );
        return 0;
    }
    let Some(reply) = super::win16_window_callbacks::wait_for_guest_reply(state, &active, callback)
    else {
        return 0;
    };
    if reply.native_control_color_result.is_some() {
        super::win16_window_callbacks::fail_worker(
            state,
            invariant("GrayString callback received an unrelated brush return"),
        );
        return 0;
    }
    i32::from(reply.result.value as u16 as i16)
}

fn invariant(message: &str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

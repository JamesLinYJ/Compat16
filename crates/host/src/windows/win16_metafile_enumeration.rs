//! Native WMF enumeration on the resumable owner-thread callback pump.
//!
//! Native tables remain in this adapter. A short locked snapshot transfers
//! only host-private handle bits between the parked worker and the main host;
//! no mutex or table borrow crosses native playback or guest execution.

use super::super::{win16_gdi::metafile::NativeMetafile, win16_gdi_objects::MetafileObjectNote};
use super::{
    Win16Objects, Win16Windows,
    win16_window_worker::{LiveCallback, WorkerState},
};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCallback, Win16HostDc, Win16HostGdiObject,
    Win16HostMetafileResult, Win16NativeCallbackSource, Win16WindowOperation, Win16WindowStep,
};
use std::{
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::LPARAM,
    Graphics::Gdi::{EnumMetaFile, HANDLETABLE, HDC, METARECORD},
};

#[path = "win16_metafile_session.rs"]
mod session;
pub(in crate::windows) use session::MetafileSession;
pub(super) use session::prepare;

struct Context<'a> {
    state: Rc<RefCell<WorkerState>>,
    dc: Win16HostDc,
    native_dc: usize,
    session: &'a MetafileSession,
}
struct TableGuard<'a> {
    context: &'a Context<'a>,
    callback: Win16HostCallback,
    native: *mut usize,
}
impl Drop for TableGuard<'_> {
    fn drop(&mut self) {
        let result = (|| {
            let mut state = self.context.session.lock()?;
            if state.callback != Some(self.callback) {
                return Err(invariant("WMF callback lost its table owner"));
            }
            if !state.table.is_empty() {
                // SAFETY: Native EnumMetaFile lends exactly count live HANDLE
                // slots for this callback. Our guard returns committed effects
                // even during abort, before GDI performs its own table cleanup.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        state.table.as_ptr(),
                        self.native,
                        state.table.len(),
                    );
                }
            }
            state.callback = None;
            state.final_table = None;
            Ok(())
        })();
        super::win16_window_callbacks::remove_live_callback(&self.context.state, self.callback);
        if let Err(error) = result {
            super::win16_window_callbacks::fail_worker(&self.context.state, error);
        }
    }
}

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    dc: Win16HostDc,
    bits: Vec<u8>,
    session: Option<&MetafileSession>,
) -> Result<bool, RuntimeError> {
    let session = session.ok_or_else(|| invariant("WMF worker has no prepared session"))?;
    let result = (|| {
        let Some(metafile) = NativeMetafile::from_bits(&bits) else {
            return Ok(false);
        };
        let dcs = state.borrow().dcs.clone();
        let Some(dc_use) = dcs.lease_dc(dc)? else {
            return Ok(false);
        };
        let context = Context {
            state: Rc::clone(state),
            dc,
            native_dc: dc_use.native() as usize,
            session,
        };
        // SAFETY: The native metafile, leased DC, callback context and session
        // all outlive EnumMetaFile and every nested guest/worker operation.
        Ok(unsafe {
            EnumMetaFile(
                dc_use.native(),
                metafile.0,
                Some(enumerate),
                (&context as *const Context<'_>) as LPARAM,
            )
        } != 0)
    })();
    session.finish()?;
    result
}
// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn enumerate(
    dc: HDC,
    table: *const HANDLETABLE,
    record: *const METARECORD,
    count: i32,
    parameter: LPARAM,
) -> i32 {
    // SAFETY: Only execute installs this callback with its live context.
    let context = unsafe { &*(parameter as *const Context<'_>) };
    match catch_unwind(AssertUnwindSafe(|| {
        enumerate_inner(context, dc, table, record, count)
    })) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            super::win16_window_callbacks::fail_worker(&context.state, error);
            0
        }
        Err(_) => {
            super::win16_window_callbacks::fail_worker(
                &context.state,
                invariant("WMF native callback panicked"),
            );
            0
        }
    }
}
fn enumerate_inner(
    context: &Context<'_>,
    dc: HDC,
    table: *const HANDLETABLE,
    record: *const METARECORD,
    count: i32,
) -> Result<i32, RuntimeError> {
    if dc as usize != context.native_dc
        || usize::try_from(count).ok() != Some(context.session.count)
        || record.is_null()
        || (count > 0 && table.is_null())
    {
        return Err(invariant(
            "native WMF callback changed its prepared extents",
        ));
    }
    let active = {
        let worker = context.state.borrow();
        if !worker.callbacks_enabled || worker.aborted {
            return Ok(0);
        }
        worker
            .active_operations
            .last()
            .filter(|active| active.id == context.session.operation)
            .cloned()
            .ok_or_else(|| invariant("WMF callback has no exact active operation"))?
    };
    // SAFETY: EnumMetaFile lends a METARECORD from our pinned, framing-checked
    // metafile. Read its fixed header first and bound the subsequent copy by
    // the actual maximum record size checked before native object creation.
    let words = unsafe { std::ptr::read_unaligned(record.cast::<u32>()) };
    let length = (words as usize)
        .checked_mul(2)
        .filter(|n| *n >= 6 && *n <= context.session.maximum_record_bytes)
        .ok_or_else(|| invariant("native WMF callback exceeded its checked record extent"))?;
    // SAFETY: The pointer and length were checked against the owning allocation, and the bytes stay live for this copy.
    let bytes = unsafe { std::slice::from_raw_parts(record.cast::<u8>(), length) }.to_vec();
    if formats::parse_wmf_record(&bytes).is_err() {
        return Err(invariant("native WMF callback supplied invalid framing"));
    }
    context
        .state
        .borrow_mut()
        .live_callbacks
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WMF callback identity",
                error,
            )
        })?;
    let callback =
        super::win16_window_worker::allocate_callback_id(&context.state).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "WMF callback identity exhausted")
        })?;
    {
        let mut shared = context.session.lock()?;
        if shared.callback.is_some() {
            return Err(invariant("WMF session already has a live callback"));
        }
        if count > 0 {
            // SAFETY: The count was checked against the prepared native header.
            shared.table.copy_from_slice(unsafe {
                std::slice::from_raw_parts(table.cast::<usize>(), count as usize)
            });
        }
        shared.callback = Some(callback);
        shared.final_table = None;
    }
    let source = Win16NativeCallbackSource::Metafile { dc: context.dc };
    context
        .state
        .borrow_mut()
        .live_callbacks
        .push(LiveCallback {
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
    let _guard = TableGuard {
        context,
        callback,
        native: table.cast_mut().cast(),
    };
    crate::windows::win16_gdi::flush_thread_batch();
    active
        .response
        .send(Ok(Win16WindowStep::MetafileCallback {
            operation_id: runtime::Win16HostWindowOperationId(active.id),
            callback,
            dc: context.dc,
            record: bytes,
            object_count: count as u16,
            source,
        }))
        .map_err(|_| {
            RuntimeError::new(
                Kind::HostFailure,
                "runtime dropped a suspended WMF callback",
            )
        })?;
    let Some(reply) =
        super::win16_window_callbacks::wait_for_guest_reply(&context.state, &active, callback)
    else {
        return Ok(0);
    };
    if reply.native_control_color_result.is_some() {
        return Err(invariant("WMF callback received an unrelated brush result"));
    }
    if context.session.lock()?.final_table.is_none() {
        return Err(invariant(
            "WMF callback resumed before its final table acknowledgement",
        ));
    }
    Ok(i32::from(reply.result.value as u16 as i16))
}
fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

#[cfg(test)]
#[path = "win16_metafile_native_tests.rs"]
mod tests;

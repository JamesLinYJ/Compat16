//! Native USER enumeration snapshots; guest callbacks run on the guest CPU.

use std::{cell::RefCell, rc::Rc};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16WindowEnumerationQuery as Query,
    Win16WindowEnumerationReply as Reply, Win16WindowEnumerationScope as Scope,
    Win16WindowTarget};
use windows_sys::Win32::{Foundation::{HWND, LPARAM}, System::Threading::GetCurrentThreadId,
    UI::WindowsAndMessaging::{EnumChildWindows, EnumThreadWindows, EnumWindows, IsWindow}};
use super::{win16_window_identity as identity, win16_window_worker::WorkerState};

#[derive(Default)]
struct Snapshot { windows: Vec<usize>, allocation_failed: bool }

// SAFETY: Enum* invokes this function synchronously with the address of its
// live Snapshot. No guest pointer, callback or worker borrow reaches USER.
unsafe extern "system" fn collect(window: HWND, parameter: LPARAM) -> i32 {
    let snapshot = unsafe { &mut *(parameter as *mut Snapshot) };
    if snapshot.windows.try_reserve(1).is_err() {
        snapshot.allocation_failed = true;
        return 0;
    }
    snapshot.windows.push(window as usize);
    1
}

pub(super) fn query(state: &Rc<RefCell<WorkerState>>, query: Query)
    -> Result<Reply, RuntimeError> {
    let scope = match query {
        Query::IsCurrent(window) => return identity::enumeration_current(state, window)
            .map(Reply::IsCurrent),
        Query::TaskQueue(window) => {
            // A worker's queue binding cannot change owner or be rebound after
            // retirement. Strict resolution proves this exact live HWND is on
            // that worker; borrowed foreign aliases never pass this check.
            let queue = identity::resolve(state, window).and_then(|_| {
                super::win16_guest_notifications::require_bound_queue(
                    super::win16_guest_notifications::current_queue(),
                )
            });
            return Ok(Reply::TaskQueue(queue));
        }
        Query::Snapshot(scope) => scope,
    };
    let mut snapshot = Snapshot::default();
    let parameter = (&mut snapshot as *mut Snapshot) as LPARAM;
    let success = match scope {
        Scope::Desktop | Scope::Children(Win16WindowTarget::Null) =>
            unsafe { EnumWindows(Some(collect), parameter) != 0 },
        Scope::Children(Win16WindowTarget::Invalid) => false,
        Scope::Children(Win16WindowTarget::Mapped(parent)) => {
            if let Some(parent) = identity::resolve_user_window(state, parent) {
                // Win32 documents this return value as unused. A live parent
                // and an uninterrupted collector constitute a completed scan.
                unsafe { EnumChildWindows(parent, Some(collect), parameter); }
                !snapshot.allocation_failed
            } else { false }
        }
        Scope::TaskQueue(queue) => {
            if super::win16_guest_notifications::require_bound_queue(Some(queue)).is_none() {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "window enumeration task queue is no longer bound to this worker"));
            }
            // The queue is explicitly bound to the guest task on this USER
            // worker. Its HWNDs include guest-created native modal dialogs.
            // HTASK is never interpreted as an OS thread number. This worker
            // creates no private top-level helper HWNDs.
            unsafe { EnumThreadWindows(GetCurrentThreadId(), Some(collect), parameter) != 0 }
        }
    };
    if snapshot.allocation_failed {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "retain the native USER window enumeration snapshot"));
    }
    let mut windows = Vec::new();
    windows.try_reserve(snapshot.windows.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "retain opaque enumerated window identities", error))?;
    if success {
        for raw in snapshot.windows {
            let hwnd = raw as HWND;
            if unsafe { IsWindow(hwnd) } == 0 { continue; }
            match identity::adopt(state, hwnd) {
                Ok(window) => windows.push(window),
                Err(_) if unsafe { IsWindow(hwnd) } == 0 => continue,
                Err(error) => return Err(error),
            }
        }
    }
    Ok(Reply::Snapshot { success, windows })
}

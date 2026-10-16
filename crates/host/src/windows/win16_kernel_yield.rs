//! USER's receive-sent-message half of KERNEL.Yield, on its owning thread.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostTaskQueue, Win16MessageCallResult};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MSG, PM_NOREMOVE, PM_QS_SENDMESSAGE, PeekMessageW,
};

use super::super::win16_guest_notifications as notifications;
use super::super::win16_window_worker::WorkerState;

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    task_queue: Win16HostTaskQueue,
) -> Result<Win16MessageCallResult, RuntimeError> {
    check_queue(state, task_queue)?;
    notifications::requeue_deferred()?;
    {
        let flags = PM_NOREMOVE | PM_QS_SENDMESSAGE;
        let _retrieval = notifications::guest_retrieval_scope(task_queue, flags)?;
        let mut message = MSG::default();
        // PeekMessage receives synchronous sends even when no posted message
        // matches. PM_NOREMOVE leaves posted input, timers and WM_QUIT queued
        // for the guest's GetMessage/PeekMessage and DispatchMessage calls.
        // No WorkerState borrow spans the reentrant native call.
        unsafe {
            PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, flags);
        }
    }
    check_queue(state, task_queue)?;
    std::thread::yield_now();
    Ok(Win16MessageCallResult::Yielded)
}

fn check_queue(
    state: &Rc<RefCell<WorkerState>>,
    queue: Win16HostTaskQueue,
) -> Result<(), RuntimeError> {
    if state.borrow().aborted || notifications::require_bound_queue(Some(queue)).is_none() {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "KERNEL.Yield no longer owns its task's native USER queue",
        ));
    }
    Ok(())
}

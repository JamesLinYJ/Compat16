//! Per-STA nested wait hook for synchronous native COM callbacks.
//!
//! The callback proxy has no USER worker dependency. The owning USER STA
//! installs this hook only around a native operation; the hook must wait on
//! the callback reply and pump that same worker's commands/messages.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::RuntimeError;

pub(in crate::windows) type StaCallbackWaiter = Rc<dyn Fn() -> Result<(), RuntimeError>>;

thread_local! {
    static STA_CALLBACK_WAITER: RefCell<Option<StaCallbackWaiter>> = const { RefCell::new(None) };
}

pub(in crate::windows) fn with_sta_callback_waiter<R>(
    waiter: StaCallbackWaiter,
    call: impl FnOnce() -> R,
) -> R {
    struct Restore(Option<StaCallbackWaiter>);
    impl Drop for Restore {
        fn drop(&mut self) {
            STA_CALLBACK_WAITER.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }

    let previous = STA_CALLBACK_WAITER.with(|slot| slot.replace(Some(waiter)));
    let restore = Restore(previous);
    let result = call();
    drop(restore);
    result
}

pub(super) fn wait_for_callback_reply() -> Result<(), RuntimeError> {
    // Clone the hook before calling it. The USER pump can recursively enter
    // another COM call, so no TLS RefCell borrow may span the wait.
    let waiter = STA_CALLBACK_WAITER.with(|slot| {
        slot.try_borrow().ok().and_then(|slot| slot.as_ref().cloned())
    });
    let waiter = waiter.ok_or_else(|| {
        RuntimeError::new(
            runtime::DiagnosticKind::HostFailure,
            "native COM callback reached the STA without its nested USER waiter",
        )
    })?;
    waiter()
}

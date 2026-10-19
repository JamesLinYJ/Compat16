//! Owner-STA executor for the typed Win16 COM/OLE request family.
//!
//! The caller dispatches `start` on the USER STA that initialized COM/OLE. A
//! native method may synchronously publish callback steps while it is in
//! progress; the independent callback ingress can deliver those steps to the
//! runtime and `continue` wakes the exact blocked frame. `Complete` is emitted
//! only after the native method and all callback frames have returned.

use std::cell::Cell;
use std::ptr;

use runtime::{
    DiagnosticKind, RuntimeError, Win16ComHostCompletion, Win16ComHostContinue,
    Win16ComHostExecutionFailure, Win16ComHostRequest, Win16ComHostResult, Win16ComHostStart,
    Win16ComHostStep, Win16HostWindow, Win16OleHostReply,
};
use windows_sys::Win32::Foundation::HWND;

use super::win16_com_callback_proxy::{
    Win16ComCallbackIngress, Win16ComCallbackRuntime, with_active_operation,
};
use super::win16_com_interface_calls;
use super::win16_com_objects::Win16ComObjects;
use super::{win16_ole_native, win16_storage_ole};
use crate::filesystem::Filesystem;

const S_OK: i32 = 0;
const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;

pub(super) enum PreparedWin16ComRequest {
    Native(Win16ComHostRequest),
    Storage(win16_storage_ole::PreparedStorageOperation),
}

pub(super) struct PreparedWin16ComStart {
    pub(super) operation: runtime::Win16ComHostOperationIdentity,
    pub(super) request: PreparedWin16ComRequest,
}

/// Resolve capability-filesystem paths before sending an operation to the
/// USER STA. The prepared request owns its UTF-16 paths and no longer borrows
/// `Filesystem` or carries a guest DOS path into native structured storage.
pub(super) fn prepare_start(
    filesystem: &mut Filesystem,
    start: Win16ComHostStart,
) -> Result<PreparedWin16ComStart, RuntimeError> {
    let request = match start.request {
        Win16ComHostRequest::Storage(operation) => {
            PreparedWin16ComRequest::Storage(win16_storage_ole::prepare(filesystem, operation)?)
        }
        request => PreparedWin16ComRequest::Native(request),
    };
    Ok(PreparedWin16ComStart {
        operation: start.operation,
        request,
    })
}

/// Start one typed native operation on the already initialized USER STA.
/// Callback steps are delivered through `ingress` while this synchronous
/// native call remains on its COM stack; checked guest execution must reply
/// through `continue_operation` before the STA callback can return.
pub(super) fn start_prepared(
    objects: &Win16ComObjects,
    callbacks: &Win16ComCallbackRuntime,
    apartment: &Win16ComApartmentRefs,
    start: PreparedWin16ComStart,
    resolve_window: impl Fn(Win16HostWindow) -> Option<HWND>,
) -> Result<Win16ComHostStep, RuntimeError> {
    if !start.operation.is_valid() {
        return Err(RuntimeError::new(
            DiagnosticKind::InvalidInput,
            "Win16 COM operation identity is invalid",
        ));
    }
    if objects.owner_identity() != callbacks.owner_identity() {
        return Err(RuntimeError::new(
            DiagnosticKind::InternalInvariant,
            "COM object table and callback port belong to different USER STA generations",
        ));
    }
    let operation = start.operation;
    let execution = with_active_operation(operation, || {
        execute_request(objects, callbacks, apartment, start.request, resolve_window)
    });
    // Always reconcile the callback journal, including when the native call
    // itself failed. This keeps callback causes paired with the exact terminal
    // operation and preserves any owned result returned alongside a callback
    // failure.
    let failures = callbacks.take_operation_failures(operation);
    match (execution, failures.is_empty()) {
        (Ok(result), true) => Ok(Win16ComHostStep::Complete(Win16ComHostCompletion {
            operation,
            result,
        })),
        (Ok(result), false) => Ok(Win16ComHostStep::OperationFailed {
            operation,
            failures,
            result: Some(result),
            execution_failure: None,
        }),
        (Err(error), true) => Err(error),
        (Err(error), false) => Ok(Win16ComHostStep::OperationFailed {
            operation,
            failures,
            result: None,
            execution_failure: Some(Win16ComHostExecutionFailure {
                kind: error.kind(),
                context: error.to_string(),
            }),
        }),
    }
}

/// Deliver the runtime's checked callback result. The callback bridge blocks
/// until this reply has been consumed on the native callback stack, then emits
/// CallbackFrameComplete; it never turns that frame result into API success.
pub(super) fn continue_operation(
    callbacks: &Win16ComCallbackRuntime,
    continuation: Win16ComHostContinue,
) -> Result<Win16ComHostStep, RuntimeError> {
    let Some(resume) = continuation.resume else {
        return Err(RuntimeError::new(
            DiagnosticKind::InvalidInput,
            "Win16 COM continuation has no callback reply",
        ));
    };
    if continuation
        .operation
        .is_some_and(|identity| !identity.is_valid())
    {
        return Err(RuntimeError::new(
            DiagnosticKind::InvalidInput,
            "Win16 COM operation identity is invalid",
        ));
    }
    if resume.parent != continuation.operation {
        return Err(RuntimeError::new(
            DiagnosticKind::InvalidInput,
            "Win16 COM callback reply names a different parent operation",
        ));
    }
    callbacks
        .resume(resume)
        .map_err(|reason| RuntimeError::new(DiagnosticKind::HostFailure, reason))
}

pub(super) fn next_callback(
    ingress: &Win16ComCallbackIngress,
) -> Result<Option<Win16ComHostStep>, RuntimeError> {
    ingress
        .try_next()
        .map_err(|reason| RuntimeError::new(DiagnosticKind::HostFailure, reason))
}

fn execute_request(
    objects: &Win16ComObjects,
    callbacks: &Win16ComCallbackRuntime,
    apartment: &Win16ComApartmentRefs,
    request: PreparedWin16ComRequest,
    resolve_window: impl Fn(Win16HostWindow) -> Option<HWND>,
) -> Result<Win16ComHostResult, RuntimeError> {
    match request {
        PreparedWin16ComRequest::Native(Win16ComHostRequest::Ole(operation)) => {
            win16_ole_native::execute(objects, apartment, operation).map(Win16ComHostResult::Ole)
        }
        PreparedWin16ComRequest::Storage(operation) => {
            win16_storage_ole::execute(objects, operation).map(Win16ComHostResult::Storage)
        }
        PreparedWin16ComRequest::Native(Win16ComHostRequest::CreateCallbackProxy { route }) => {
            let value = callbacks.create_proxy(objects, route).map_err(|error| {
                RuntimeError::with_source(
                    DiagnosticKind::HostFailure,
                    "create native OLE callback interfaces",
                    error,
                )
            })?;
            Ok(Win16ComHostResult::Ole(Win16OleHostReply {
                status: S_OK as u32,
                value,
            }))
        }
        PreparedWin16ComRequest::Native(Win16ComHostRequest::InterfaceCall { object, call }) => {
            win16_com_interface_calls::execute(objects, object, call, resolve_window)
                .map(Win16ComHostResult::Ole)
        }
        PreparedWin16ComRequest::Native(Win16ComHostRequest::ReleaseStorageMedium { medium }) => {
            objects.release_medium(medium).map_err(|error| {
                RuntimeError::with_source(
                    DiagnosticKind::HostFailure,
                    "release retained IDataObject storage medium on its owner STA",
                    error,
                )
            })?;
            Ok(Win16ComHostResult::MediumReleased { medium })
        }
        PreparedWin16ComRequest::Native(Win16ComHostRequest::ReleaseObject { object, owner }) => {
            if objects.owner_identity() != owner {
                return Err(RuntimeError::new(
                    DiagnosticKind::InvalidInput,
                    "native COM object release names a different USER STA generation",
                ));
            }
            let remaining_owned_references = objects.release(object).map_err(|error| {
                RuntimeError::with_source(
                    DiagnosticKind::HostFailure,
                    "release owned native COM interface reference on its owner STA",
                    error,
                )
            })?;
            Ok(Win16ComHostResult::ObjectReferenceReleased {
                object,
                owner,
                remaining_owned_references,
            })
        }
        PreparedWin16ComRequest::Native(Win16ComHostRequest::Storage(_)) => {
            unreachable!("guest-path storage operations must be prepared before STA submission")
        }
    }
}

/// Counts only guest-paired references. The worker's permanent OleInitialize
/// lease is owned separately and cannot be consumed by an unbalanced guest
/// CoUninitialize/OleUninitialize request.
pub(super) struct Win16ComApartmentRefs {
    guest_com: Cell<u32>,
    guest_ole: Cell<u32>,
}

impl Win16ComApartmentRefs {
    pub(super) const fn new() -> Self {
        Self {
            guest_com: Cell::new(0),
            guest_ole: Cell::new(0),
        }
    }

    pub(super) fn initialize(&self, ole: bool, reserved: u32) -> runtime::Win16OleHostReply {
        if reserved != 0 {
            return runtime::Win16OleHostReply {
                status: E_INVALIDARG as u32,
                value: runtime::Win16OleHostValue::None,
            };
        }
        let counter = if ole {
            &self.guest_ole
        } else {
            &self.guest_com
        };
        let Some(next) = counter.get().checked_add(1) else {
            return runtime::Win16OleHostReply {
                status: 0x8007_000eu32,
                value: runtime::Win16OleHostValue::None,
            };
        };
        // SAFETY: the STA holds a permanent OLE apartment lease; this call
        // adds one separately tracked guest reference on that same thread.
        let result = unsafe {
            if ole {
                windows_sys::Win32::System::Ole::OleInitialize(ptr::null())
            } else {
                windows_sys::Win32::System::Com::CoInitialize(ptr::null())
            }
        };
        if result >= 0 {
            counter.set(next);
        }
        runtime::Win16OleHostReply {
            status: result as u32,
            value: runtime::Win16OleHostValue::None,
        }
    }

    pub(super) fn uninitialize(&self, ole: bool) -> runtime::Win16OleHostReply {
        let counter = if ole {
            &self.guest_ole
        } else {
            &self.guest_com
        };
        let count = counter.get();
        if count != 0 {
            counter.set(count - 1);
            // SAFETY: only a reference previously acquired by the matching
            // guest initializer is released; the worker lease remains intact.
            if ole {
                crate::windows::win32_safe::ole_uninitialize()
            } else {
                crate::windows::win32_safe::co_uninitialize()
            }
        }
        runtime::Win16OleHostReply {
            status: S_OK as u32,
            value: runtime::Win16OleHostValue::None,
        }
    }

    pub(super) fn release_guest_refs(&self) {
        while self.guest_ole.get() != 0 {
            let _ = self.uninitialize(true);
        }
        while self.guest_com.get() != 0 {
            let _ = self.uninitialize(false);
        }
    }
}

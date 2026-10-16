//! Exact USER callback owner from fallible setup through guest return.

use std::sync::Arc;

use guest_core::Registers;
use win16_abi::SelectorRef;

use super::{CallbackFrameId, WindowCallbackContinuation};
use super::GuestWindowPayload;
use crate::{RuntimeError, Win16GuestNotification, Win16HostMdiChildCreation};

/// Registration ownership is independent of callback code and native resume
/// ownership. An unknown class must never be treated as a builtin class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::win16_runtime) enum WindowClassRoot {
    Class(crate::Win16HostClass),
    NoRegistration,
    Unresolved,
}

impl WindowClassRoot {
    pub(in crate::win16_runtime) fn from_native_message(
        source: crate::Win16NativeCallbackSource,
        native_window: crate::Win16HostWindow,
    ) -> Self {
        match source {
            crate::Win16NativeCallbackSource::WindowMessage { window, class, .. }
                if window == native_window => class.map_or(Self::NoRegistration, Self::Class),
            _ => Self::Unresolved,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::win16_runtime) enum WindowCallbackEntryPhase {
    Preparing,
    GuestCallback,
    SetupFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::win16_runtime) enum WindowCallbackSetupPhase {
    OwnerPublished,
    DestroyMarked,
    DialogDataInitialized,
    DialogResultReset,
    ProcedureValidated,
    PayloadAllocated,
    PayloadLocked,
    PayloadPrepared,
    FocusMapped,
    FocusAncestorChildMapped,
    FocusAncestorParentMapped,
    FocusAncestorLinked,
    CommandParentResolved,
    CallbackStackWritten,
    DialogProcedureCommitted,
    GuestEntryCommitted,
}

#[derive(Clone, Debug)]
pub(in crate::win16_runtime) struct WindowCallbackSetupJournal {
    pub(in crate::win16_runtime) last_completed: WindowCallbackSetupPhase,
    pub(in crate::win16_runtime) focus_links_completed: usize,
}

impl WindowCallbackSetupJournal {
    pub(in crate::win16_runtime) fn preparing() -> Self {
        Self {
            last_completed: WindowCallbackSetupPhase::OwnerPublished,
            focus_links_completed: 0,
        }
    }

    pub(in crate::win16_runtime) fn entered() -> Self {
        Self {
            last_completed: WindowCallbackSetupPhase::GuestEntryCommitted,
            focus_links_completed: 0,
        }
    }
}

pub(in crate::win16_runtime) struct WindowCallbackFrame {
    pub(in crate::win16_runtime) callback_id: CallbackFrameId,
    pub(in crate::win16_runtime) saved: Registers,
    pub(in crate::win16_runtime) payload: GuestWindowPayload,
    pub(in crate::win16_runtime) payload_allocation_locked: bool,
    /// Exact guest HGLOBAL retained only until WM_DROPFILES enters its guest
    /// callback. Entry transfers responsibility to the guest's DragFinish.
    pub(in crate::win16_runtime) guest_drop_global: Option<win16_abi::GlobalHandle>,
    /// Non-owning allocator-generation evidence retained for the exact
    /// callback lifetime. It prevents a freed HGLOBAL's reused numeric token
    /// from being mistaken for this WM_DROPFILES payload by DefWindowProc.
    pub(in crate::win16_runtime) guest_drop_generation: Option<win16_abi::GlobalHandle>,
    pub(in crate::win16_runtime) payload_selector: Option<SelectorRef>,
    pub(in crate::win16_runtime) guest_return_value: Option<u32>,
    pub(in crate::win16_runtime) payload_result: Option<crate::Win16HostMessageResult>,
    pub(in crate::win16_runtime) payload_error: Option<Arc<RuntimeError>>,
    pub(in crate::win16_runtime) payload_cleanup_error: Option<Arc<RuntimeError>>,
    pub(in crate::win16_runtime) payload_retained: Option<super::RetainedWindowPayloadCounts>,
    pub(in crate::win16_runtime) payload_cleaned: bool,
    pub(in crate::win16_runtime) window_tree_retired: bool,
    pub(in crate::win16_runtime) clipboard_retired: bool,
    pub(in crate::win16_runtime) trace_observed: bool,
    pub(in crate::win16_runtime) native_resume_error: Option<Arc<RuntimeError>>,
    pub(in crate::win16_runtime) setup_error: Option<Arc<RuntimeError>>,
    pub(in crate::win16_runtime) entry_phase: WindowCallbackEntryPhase,
    pub(in crate::win16_runtime) setup: WindowCallbackSetupJournal,
    pub(in crate::win16_runtime) guest_notification: Option<Win16GuestNotification>,
    /// Exact WM_MDICREATE child payload that owns this native WndProc callback.
    /// DefWindowProc/DefMDIChildProc can forward its checked guest edits only
    /// while this callback frame remains the innermost active owner.
    pub(in crate::win16_runtime) mdi_child_creation: Option<Win16HostMdiChildCreation>,
    pub(in crate::win16_runtime) callback_address: u32,
    /// Captured at entry and retained until paired frame retirement, even if
    /// the HWND is destroyed/reused or guest setup/native resume fails.
    pub(in crate::win16_runtime) class_root: WindowClassRoot,
    pub(in crate::win16_runtime) host_operation: Option<crate::Win16HostWindowOperationId>,
    pub(in crate::win16_runtime) native_source: Option<crate::Win16NativeCallbackSource>,
    pub(in crate::win16_runtime) continuation: WindowCallbackContinuation,
}

impl WindowCallbackFrame {
    pub(in crate::win16_runtime) fn guest(
        callback_id: CallbackFrameId,
        saved: Registers,
        payload: GuestWindowPayload,
        guest_notification: Option<Win16GuestNotification>,
        callback_address: u32,
        class_root: WindowClassRoot,
        host_operation: Option<crate::Win16HostWindowOperationId>,
        native_source: Option<crate::Win16NativeCallbackSource>,
        continuation: WindowCallbackContinuation,
    ) -> Self {
        Self {
            callback_id,
            saved,
            payload_allocation_locked: payload.allocation.is_some(),
            guest_drop_global: None,
            guest_drop_generation: None,
            payload_selector: None,
            payload,
            guest_return_value: None,
            payload_result: None,
            payload_error: None,
            payload_cleanup_error: None,
            payload_retained: None,
            payload_cleaned: false,
            window_tree_retired: false,
            clipboard_retired: false,
            trace_observed: false,
            native_resume_error: None,
            setup_error: None,
            entry_phase: WindowCallbackEntryPhase::GuestCallback,
            setup: WindowCallbackSetupJournal::entered(),
            guest_notification,
            mdi_child_creation: None,
            callback_address,
            class_root,
            host_operation,
            native_source,
            continuation,
        }
    }
}

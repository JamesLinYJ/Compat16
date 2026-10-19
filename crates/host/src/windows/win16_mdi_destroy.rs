//! Exact MDI child retirement and queued MDI dispatch receipts.
//!
//! System MDI children may never enter the host guest-WndProc path, so USER
//! destruction is observed after the native call and retired through the same
//! exact window-map bridge used by DestroyWindow.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMdiMessage,
    Win16HostMdiMessageQueuedKind as QueuedKind, Win16HostMdiMessageResult, Win16HostMdiOutput,
    Win16HostMdiQueuedMessage, Win16HostSystemClass, Win16HostWindow,
    Win16HostWindowRetirementBatch, Win16MdiEndpoint,
};
use windows_sys::Win32::Foundation::{HWND, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{GWL_EXSTYLE, GetWindowLongPtrW, WS_EX_MDICHILD};

use super::super::super::win16_window_worker::{
    self as worker, NativeWindowRetirementCandidate, WorkerState,
};
use super::super::{MessageInvocation, invoke_native_message};
use super::{resolve_window, with_menu_call_owners};

pub(super) fn invoke_destroy(
    state: &Rc<RefCell<WorkerState>>,
    invocation: MessageInvocation,
    hwnd: HWND,
    child: Option<Win16HostWindow>,
) -> Result<Option<Win16HostMdiMessageResult>, RuntimeError> {
    let client = match invocation {
        MessageInvocation::FrameDefault { mdi_client } if !mdi_client.is_null() => mdi_client,
        MessageInvocation::Send | MessageInvocation::Dispatch { .. } => hwnd,
        _ => {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 WM_MDIDESTROY requires an MDI client default, send, or dispatch route",
            ));
        }
    };
    let target = match resolve_window(state, child) {
        Some(target) => target,
        None => return Ok(None),
    };
    let Some(child) = child else {
        return Ok(None);
    };
    let Some(initial) = worker::capture_window_retirement_candidate(state, child, target) else {
        return Ok(None);
    };
    if !is_exact_mdi_child(state, initial, Some(client)) {
        return Ok(None);
    }
    let Some(preparation) = worker::prepare_window_retirement(state, child, target)? else {
        return Ok(None);
    };
    let current = preparation.candidate_for(child, target);
    let exact_current = preparation.ready
        && current.is_some_and(|candidate| {
            worker::same_candidate(initial, candidate)
                && is_exact_mdi_child(state, candidate, Some(client))
        });
    let value = if exact_current {
        invoke_native_message(invocation, hwnd, super::WM_MDIDESTROY, target as WPARAM, 0)
    } else {
        0
    };
    let finished = worker::finish_window_retirement(state, preparation.scope, true);
    let mut retirements = finished.receipts;
    let root_index = retirements
        .iter()
        .position(|receipt| receipt.window == child);
    let receipt = root_index.map(|index| retirements.remove(index));
    let additional_retirements = retirements;
    let invalidated_menus = finished.invalidated_menus;
    let output =
        if receipt.is_some() || !additional_retirements.is_empty() || !invalidated_menus.is_empty()
        {
            Win16HostMdiOutput::Destroyed {
                receipt,
                additional_retirements,
                invalidated_menus,
            }
        } else {
            Win16HostMdiOutput::None
        };
    if !exact_current && matches!(&output, Win16HostMdiOutput::None) {
        return Ok(None);
    }
    Ok(Some(Win16HostMdiMessageResult {
        value: value as i32 as u32,
        output,
    }))
}

pub(in crate::windows) struct WindowRetirementSnapshot {
    scope: Option<worker::WindowRetirementScope>,
}

pub(in crate::windows) fn snapshot_window_retirements(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    root_hwnd: HWND,
) -> Result<WindowRetirementSnapshot, RuntimeError> {
    Ok(WindowRetirementSnapshot {
        scope: worker::begin_window_retirement_observation(state, root, root_hwnd)?,
    })
}

pub(in crate::windows) fn finish_window_retirements(
    state: &Rc<RefCell<WorkerState>>,
    snapshot: WindowRetirementSnapshot,
) -> Win16HostWindowRetirementBatch {
    let Some(scope) = snapshot.scope else {
        return Win16HostWindowRetirementBatch {
            receipts: Vec::new(),
            invalidated_menus: Vec::new(),
        };
    };
    let finished = worker::finish_window_retirement(state, scope, true);
    Win16HostWindowRetirementBatch {
        receipts: finished.receipts,
        invalidated_menus: finished.invalidated_menus,
    }
}

pub(in crate::windows) fn dispatch_queued_message(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    guest_message: u16,
    queued: Win16HostMdiQueuedMessage,
    time: u32,
    point: runtime::Win16HostPoint,
) -> Result<Option<(Win16HostMdiMessageResult, Win16HostWindowRetirementBatch)>, RuntimeError> {
    let Some(_) = crate::windows::win16_windows::win16_message_loop::encode_mdi_message_call(
        state,
        window,
        hwnd,
        guest_message,
        queued,
    )?
    else {
        return Ok(None);
    };
    let Some(message) = queued_to_message(queued)? else {
        return Ok(None);
    };
    if !crate::windows::win16_windows::win16_message_loop::validate_mdi_owned_target(
        state, hwnd, &message,
    ) {
        return Ok(None);
    }
    let client = match queued.endpoint {
        Win16MdiEndpoint::Client => hwnd,
        Win16MdiEndpoint::Child(_) => crate::windows::win32_safe::get_parent(hwnd),
    };
    if client.is_null() {
        return Ok(None);
    }
    let Some(Some(client_window)) = super::window_token_for_native(state, client) else {
        return Ok(None);
    };
    let snapshot = snapshot_window_retirements(state, client_window, client)?;
    let frame = crate::windows::win32_safe::get_parent(client);
    let (requested_frame, requested_window) = match queued.message {
        QueuedKind::SetMenu {
            refresh: false,
            frame_menu,
            window_menu,
        } => (frame_menu, window_menu),
        _ => (None, None),
    };
    let result = with_menu_call_owners(state, frame, requested_frame, requested_window, || {
        super::invoke(
            state,
            MessageInvocation::Dispatch { time, point },
            hwnd,
            message,
        )
    });
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            // The USER closure may have run before a nested callback returned
            // an error. Finish the observation scope so menu pins and exact
            // dead-window maps are not stranded.
            let _ = finish_window_retirements(state, snapshot);
            return Err(error);
        }
    };
    let mut receipts = finish_window_retirements(state, snapshot);
    if let Some(Win16HostMdiMessageResult {
        output:
            Win16HostMdiOutput::Destroyed {
                receipt,
                additional_retirements,
                invalidated_menus: nested_invalidated_menus,
            },
        ..
    }) = &result
    {
        // The nested MDI call owns its destruction receipts. The outer client
        // snapshot reports only other retired host window tokens.
        receipts.receipts.retain(|candidate| {
            !receipt
                .as_ref()
                .is_some_and(|nested| nested.window == candidate.window)
                && !additional_retirements
                    .iter()
                    .any(|nested| nested.window == candidate.window)
        });
        receipts
            .invalidated_menus
            .retain(|menu| !nested_invalidated_menus.contains(menu));
    }
    match result {
        Some(result) => Ok(Some((result, receipts))),
        None if !receipts.receipts.is_empty() || !receipts.invalidated_menus.is_empty() => {
            Ok(Some((super::scalar_result(0), receipts)))
        }
        None => Ok(None),
    }
}

fn queued_to_message(
    queued: Win16HostMdiQueuedMessage,
) -> Result<Option<Win16HostMdiMessage>, RuntimeError> {
    let message = match queued.message {
        QueuedKind::ActivateClient { activating } => {
            if !matches!(queued.endpoint, Win16MdiEndpoint::Client) {
                return Ok(None);
            }
            Win16HostMdiMessage::ActivateClient { activating }
        }
        QueuedKind::ActivateChild {
            activating,
            deactivating,
        } => {
            let Win16MdiEndpoint::Child(child) = queued.endpoint else {
                return Ok(None);
            };
            Win16HostMdiMessage::ActivateChild {
                child,
                active: activating == Some(child),
                activating,
                deactivating,
            }
        }
        QueuedKind::Destroy { child } => Win16HostMdiMessage::Destroy { child },
        QueuedKind::Restore { child } => Win16HostMdiMessage::Restore { child },
        QueuedKind::Next { child, previous } => Win16HostMdiMessage::Next { child, previous },
        QueuedKind::Maximize { child } => Win16HostMdiMessage::Maximize { child },
        QueuedKind::Tile { flags } => Win16HostMdiMessage::Tile { flags },
        QueuedKind::Cascade { flags } => Win16HostMdiMessage::Cascade { flags },
        QueuedKind::IconArrange => Win16HostMdiMessage::IconArrange,
        QueuedKind::GetActive => Win16HostMdiMessage::GetActive,
        QueuedKind::SetMenu {
            refresh,
            frame_menu,
            window_menu,
        } => Win16HostMdiMessage::SetMenu {
            refresh,
            frame_menu,
            window_menu,
        },
    };
    Ok(Some(message))
}

fn is_exact_mdi_child(
    state: &Rc<RefCell<WorkerState>>,
    candidate: NativeWindowRetirementCandidate,
    expected_client: Option<HWND>,
) -> bool {
    let hwnd = candidate.hwnd;
    let identity = candidate.identity;
    if identity.window != candidate.window
        || !identity.owned
        || identity.creation.is_none()
        || identity.class.is_none()
        || { crate::windows::win32_safe::is_window(hwnd) } == 0
        || super::super::super::win16_window_identity::resolve(state, candidate.window)
            != Some(hwnd)
        || super::super::super::win16_window_identity::belongs_to_worker(hwnd) != Some(true)
    {
        return false;
    }
    // SAFETY: GetWindowThreadProcessId optionally writes a caller-owned process id.
    let (process_id, thread_id) = unsafe {
        let mut process = 0;
        let thread = windows_sys::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId(
            hwnd,
            &mut process,
        );
        (process, thread)
    };
    if process_id != (crate::windows::win32_safe::current_process_id())
        || thread_id != (crate::windows::win32_safe::current_thread_id())
        || process_id != identity.process_id
        || thread_id != identity.thread_id
    {
        return false;
    }
    let Some(class) = identity.class else {
        return false;
    };
    if !worker::native_class_name_matches(state, class, hwnd) {
        return false;
    }
    // SAFETY: GetWindowLongPtrW reads one window-long slot. The HWND is a window this thread created or was given by Windows.
    let extended_style = unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) } as u32;
    if extended_style & WS_EX_MDICHILD == 0 {
        return false;
    }
    let parent = crate::windows::win32_safe::get_parent(hwnd);
    if parent.is_null()
        || expected_client.is_some_and(|expected| expected != parent)
        || !is_exact_mdi_client(state, parent)
    {
        return false;
    }
    true
}

fn is_exact_mdi_client(state: &Rc<RefCell<WorkerState>>, hwnd: HWND) -> bool {
    if hwnd.is_null()
        || { crate::windows::win32_safe::is_window(hwnd) } == 0
        || super::super::super::win16_window_identity::belongs_to_worker(hwnd) != Some(true)
    {
        return false;
    }
    let identity = {
        let borrowed = state.borrow();
        let Some(identity) = borrowed.windows_by_native.get(&(hwnd as usize)).copied() else {
            return false;
        };
        if borrowed.windows.get(&identity.window).copied() != Some(hwnd) {
            return false;
        }
        identity
    };
    let Some(class) = identity.class else {
        return false;
    };
    let system_kind = state
        .borrow()
        .classes
        .get(&class)
        .map(|class| class.system_class_kind);
    identity.owned
        && identity.creation.is_some()
        && identity.thread_id == (crate::windows::win32_safe::current_thread_id())
        && identity.process_id == (crate::windows::win32_safe::current_process_id())
        && system_kind == Some(Some(Win16HostSystemClass::MdiClient))
        && super::super::super::win16_window_identity::resolve(state, identity.window) == Some(hwnd)
        && worker::native_class_name_matches(state, class, hwnd)
}

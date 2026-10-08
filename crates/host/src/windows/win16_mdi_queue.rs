//! Native queued-message marshalling for the pointer-free Win16 MDI messages.
//!
//! A queue entry is classified by its exact mapped receiver and native MDI
//! role. HWND/HMENU arguments stay as checked host identities until dispatch;
//! WM_MDICREATE remains on the synchronous native callback path because its
//! LPARAM is a pointer to caller-owned creation storage.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMdiMessage,
    Win16HostMdiMessageQueuedKind as MdiKind, Win16HostMdiQueuedMessage, Win16HostMenu,
    Win16HostQueuedMessage, Win16HostSystemClass, Win16HostWindow, Win16MdiEndpoint,
    Win16MessageParam, Win16MessageSource,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GWL_EXSTYLE, GetParent, GetWindowLongPtrW, IsWindow, WM_MDIACTIVATE, WM_MDICASCADE,
    WM_MDICREATE, WM_MDIDESTROY, WM_MDIGETACTIVE, WM_MDIICONARRANGE, WM_MDIMAXIMIZE, WM_MDINEXT,
    WM_MDIREFRESHMENU, WM_MDIRESTORE, WM_MDISETMENU, WM_MDITILE, WS_EX_MDICHILD,
};

use super::super::win16_window_worker::WorkerState;

#[derive(Clone, Copy)]
struct VerifiedEndpoint {
    window: Win16HostWindow,
    endpoint: Win16MdiEndpoint,
    client: HWND,
}

/// Copy one recognized native MDI message into host-owned, pointer-free data.
/// The endpoint comes from the exact receiving HWND's class or extended style,
/// never from the message number alone.
pub(in crate::windows) fn capture_native_queued_message(
    state: &Rc<RefCell<WorkerState>>,
    native: &windows_sys::Win32::UI::WindowsAndMessaging::MSG,
) -> Result<Option<Win16HostQueuedMessage>, RuntimeError> {
    if !is_native_mdi_message(native.message) || native.message == WM_MDICREATE {
        // WM_MDICREATE's LPARAM may point at an MDICREATESTRUCT owned by the
        // caller. It is deliberately left for synchronous DispatchMessageW.
        return Ok(None);
    }
    let Some(receiver) = verified_endpoint(state, native.hwnd) else {
        return Ok(None);
    };
    if matches!(receiver.endpoint, Win16MdiEndpoint::Child(_)) && native.message != WM_MDIACTIVATE {
        return Ok(None);
    }
    let Some(queued) = super::super::win16_window_default::mdi::capture_native_queued_message(
        state,
        receiver.endpoint,
        native.message,
        native.wParam,
        native.lParam,
    )?
    else {
        return Ok(None);
    };
    if queued.native_message_id() != native.message {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "typed MDI queue capture changed the native message identifier",
        ));
    }
    if !payload_references_live_children(state, receiver.client, queued) {
        return Ok(None);
    }
    let message = u16::try_from(native.message).map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "captured native MDI message does not fit the Win16 message word",
        )
    })?;
    Ok(Some(Win16HostQueuedMessage {
        source: Win16MessageSource::NativeQueue,
        window: Some(receiver.window),
        message,
        // Native WPARAM may be an HWND or HMENU. The typed sidecar carries
        // those identities and runtime creates the Win16 numeric projection.
        w_param: 0,
        l_param: Win16MessageParam::Mdi(queued),
        time: native.time,
        point: runtime::Win16HostPoint {
            x: native.pt.x,
            y: native.pt.y,
        },
    }))
}

/// Rebuild the native MDI message after runtime decoded the current guest
/// MSG16 fields into checked window/menu identities. User edits to the MSG16
/// are therefore honored, while the receiver and every embedded handle are
/// revalidated against the live native MDI relationship.
pub(super) fn encode_dispatch(
    state: &Rc<RefCell<WorkerState>>,
    window: Option<Win16HostWindow>,
    hwnd: HWND,
    guest_message: u16,
    queued: Win16HostMdiQueuedMessage,
) -> Result<Option<(u32, WPARAM, LPARAM)>, RuntimeError> {
    validate_guest_message_id(guest_message, queued)?;
    let Some(window) = window else {
        return Err(invalid_mdi_dispatch(
            "MDI dispatch has no receiving HWND identity",
        ));
    };
    if state.borrow().windows.get(&window).copied() != Some(hwnd) {
        return Ok(None);
    }
    let Some(receiver) = verified_endpoint(state, hwnd) else {
        return Ok(None);
    };
    if receiver.window != window || receiver.endpoint != queued.endpoint {
        return Err(invalid_mdi_dispatch(
            "typed MDI endpoint does not match the live receiving HWND role",
        ));
    }
    match (queued.endpoint, queued.message) {
        (Win16MdiEndpoint::Client, MdiKind::ActivateChild { .. })
        | (Win16MdiEndpoint::Child(_), MdiKind::ActivateClient { .. })
        | (Win16MdiEndpoint::Child(_), MdiKind::Destroy { .. })
        | (Win16MdiEndpoint::Child(_), MdiKind::Restore { .. })
        | (Win16MdiEndpoint::Child(_), MdiKind::Next { .. })
        | (Win16MdiEndpoint::Child(_), MdiKind::Maximize { .. })
        | (Win16MdiEndpoint::Child(_), MdiKind::Tile { .. })
        | (Win16MdiEndpoint::Child(_), MdiKind::Cascade { .. })
        | (Win16MdiEndpoint::Child(_), MdiKind::IconArrange)
        | (Win16MdiEndpoint::Child(_), MdiKind::GetActive)
        | (Win16MdiEndpoint::Child(_), MdiKind::SetMenu { .. }) => {
            return Err(invalid_mdi_dispatch(
                "typed MDI message family does not match its receiving endpoint",
            ));
        }
        _ => {}
    }

    let (message, w_param, l_param) = match queued.message {
        MdiKind::ActivateClient { activating } => {
            let Some(activating) = resolve_mdi_child(state, receiver.client, activating) else {
                return Ok(None);
            };
            (WM_MDIACTIVATE, activating as WPARAM, 0)
        }
        MdiKind::ActivateChild {
            activating,
            deactivating,
        } => {
            let Win16MdiEndpoint::Child(child) = queued.endpoint else {
                return Err(invalid_mdi_dispatch(
                    "child WM_MDIACTIVATE has a client endpoint",
                ));
            };
            if child != receiver.window {
                return Err(invalid_mdi_dispatch(
                    "child WM_MDIACTIVATE identity differs from its receiver",
                ));
            }
            let Some(activating) = resolve_mdi_child(state, receiver.client, activating) else {
                return Ok(None);
            };
            let Some(deactivating) = resolve_mdi_child(state, receiver.client, deactivating) else {
                return Ok(None);
            };
            if activating.is_null() && deactivating.is_null() {
                return Err(invalid_mdi_dispatch(
                    "child WM_MDIACTIVATE names neither an active nor inactive child",
                ));
            }
            (WM_MDIACTIVATE, deactivating as WPARAM, activating as LPARAM)
        }
        MdiKind::Destroy { child } => {
            let Some(child) = resolve_mdi_child(state, receiver.client, child) else {
                return Ok(None);
            };
            (WM_MDIDESTROY, child as WPARAM, 0)
        }
        MdiKind::Restore { child } => {
            let Some(child) = resolve_mdi_child(state, receiver.client, child) else {
                return Ok(None);
            };
            (WM_MDIRESTORE, child as WPARAM, 0)
        }
        MdiKind::Next { child, previous } => {
            let Some(child) = resolve_mdi_child(state, receiver.client, child) else {
                return Ok(None);
            };
            (WM_MDINEXT, child as WPARAM, isize::from(u8::from(previous)))
        }
        MdiKind::Maximize { child } => {
            let Some(child) = resolve_mdi_child(state, receiver.client, child) else {
                return Ok(None);
            };
            (WM_MDIMAXIMIZE, child as WPARAM, 0)
        }
        MdiKind::Tile { flags } => (WM_MDITILE, WPARAM::from(flags), 0),
        MdiKind::Cascade { flags } => (WM_MDICASCADE, WPARAM::from(flags), 0),
        MdiKind::IconArrange => (WM_MDIICONARRANGE, 0, 0),
        MdiKind::GetActive => (WM_MDIGETACTIVE, 0, 0),
        MdiKind::SetMenu {
            refresh: true,
            frame_menu,
            window_menu,
        } => {
            if frame_menu.is_some() || window_menu.is_some() {
                return Err(invalid_mdi_dispatch(
                    "MDI refresh message unexpectedly carries menu identities",
                ));
            }
            (WM_MDIREFRESHMENU, 0, 0)
        }
        MdiKind::SetMenu {
            refresh: false,
            frame_menu,
            window_menu,
        } => {
            let Some(frame_menu) = resolve_menu(state, frame_menu) else {
                return Ok(None);
            };
            let Some(window_menu) = resolve_menu(state, window_menu) else {
                return Ok(None);
            };
            (WM_MDISETMENU, frame_menu as WPARAM, window_menu as LPARAM)
        }
    };
    if message != queued.native_message_id() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "typed MDI dispatch changed the native message identifier",
        ));
    }
    Ok(Some((message, w_param, l_param)))
}

/// Revalidate the target of an owned synchronous MDI operation against the
/// worker's current native class/style/parent metadata. All MDI operations
/// target the real MDI client except child WM_MDIACTIVATE, whose endpoint must
/// be the exact live MDI child token carried by the message.
pub(in crate::windows) fn validate_owned_target(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    message: &Win16HostMdiMessage,
) -> bool {
    let Some(receiver) = verified_endpoint(state, hwnd) else {
        return false;
    };
    match (receiver.endpoint, message) {
        (
            Win16MdiEndpoint::Child(endpoint),
            Win16HostMdiMessage::ActivateChild {
                child,
                active,
                activating,
                deactivating,
            },
        ) => {
            if endpoint != *child {
                return false;
            }
            let expected = if *active { *activating } else { *deactivating };
            if expected != Some(*child) {
                return false;
            }
        }
        (Win16MdiEndpoint::Client, Win16HostMdiMessage::ActivateChild { .. })
        | (Win16MdiEndpoint::Child(_), _) => return false,
        (Win16MdiEndpoint::Client, _) => {}
    }
    if matches!(message, Win16HostMdiMessage::Create(_)) {
        // Create's nested class and copied structure are validated by the
        // synchronous creation path, which owns their lifetime.
        return true;
    }
    let message = match message {
        Win16HostMdiMessage::ActivateClient { activating } => MdiKind::ActivateClient {
            activating: *activating,
        },
        Win16HostMdiMessage::ActivateChild {
            activating,
            deactivating,
            ..
        } => MdiKind::ActivateChild {
            activating: *activating,
            deactivating: *deactivating,
        },
        Win16HostMdiMessage::Destroy { child } => MdiKind::Destroy { child: *child },
        Win16HostMdiMessage::Restore { child } => MdiKind::Restore { child: *child },
        Win16HostMdiMessage::Next { child, previous } => MdiKind::Next {
            child: *child,
            previous: *previous,
        },
        Win16HostMdiMessage::Maximize { child } => MdiKind::Maximize { child: *child },
        Win16HostMdiMessage::Tile { flags } => MdiKind::Tile { flags: *flags },
        Win16HostMdiMessage::Cascade { flags } => MdiKind::Cascade { flags: *flags },
        Win16HostMdiMessage::IconArrange => MdiKind::IconArrange,
        Win16HostMdiMessage::GetActive => MdiKind::GetActive,
        Win16HostMdiMessage::SetMenu {
            refresh,
            frame_menu,
            window_menu,
        } => MdiKind::SetMenu {
            refresh: *refresh,
            frame_menu: *frame_menu,
            window_menu: *window_menu,
        },
        Win16HostMdiMessage::Create(_) => unreachable!("MDI create handled above"),
    };
    payload_references_live_children(
        state,
        receiver.client,
        Win16HostMdiQueuedMessage {
            endpoint: receiver.endpoint,
            message,
        },
    )
}

pub(super) fn validate_guest_message_id(
    message: u16,
    queued: Win16HostMdiQueuedMessage,
) -> Result<(), RuntimeError> {
    if guest_message_id(queued) == message {
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "typed MDI payload does not match the guest MSG16 identifier",
        ))
    }
}

fn guest_message_id(queued: Win16HostMdiQueuedMessage) -> u16 {
    match queued.message {
        MdiKind::ActivateClient { .. } | MdiKind::ActivateChild { .. } => WM_MDIACTIVATE as u16,
        MdiKind::Destroy { .. } => WM_MDIDESTROY as u16,
        MdiKind::Restore { .. } => WM_MDIRESTORE as u16,
        MdiKind::Next { .. } => WM_MDINEXT as u16,
        MdiKind::Maximize { .. } => WM_MDIMAXIMIZE as u16,
        MdiKind::Tile { .. } => WM_MDITILE as u16,
        MdiKind::Cascade { .. } => WM_MDICASCADE as u16,
        MdiKind::IconArrange => WM_MDIICONARRANGE as u16,
        MdiKind::GetActive => WM_MDIGETACTIVE as u16,
        // Win16 projects the Win32 refresh notification to WM_MDISETMENU.
        MdiKind::SetMenu { .. } => WM_MDISETMENU as u16,
    }
}

fn is_native_mdi_message(message: u32) -> bool {
    matches!(
        message,
        WM_MDICREATE
            | WM_MDIDESTROY
            | WM_MDIACTIVATE
            | WM_MDIRESTORE
            | WM_MDINEXT
            | WM_MDIMAXIMIZE
            | WM_MDITILE
            | WM_MDICASCADE
            | WM_MDIICONARRANGE
            | WM_MDIGETACTIVE
            | WM_MDISETMENU
            | WM_MDIREFRESHMENU
    )
}

fn verified_endpoint(state: &Rc<RefCell<WorkerState>>, hwnd: HWND) -> Option<VerifiedEndpoint> {
    let (window, system_kind) = mapped_native_identity(state, hwnd)?;
    if system_kind == Some(Win16HostSystemClass::MdiClient) {
        return Some(VerifiedEndpoint {
            window,
            endpoint: Win16MdiEndpoint::Client,
            client: hwnd,
        });
    }
    let extended_style = unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 };
    if extended_style & WS_EX_MDICHILD == 0 {
        return None;
    }
    let client = unsafe { GetParent(hwnd) };
    if client.is_null()
        || mapped_native_identity(state, client).map_or(true, |(_, kind)| {
            kind != Some(Win16HostSystemClass::MdiClient)
        })
    {
        return None;
    }
    Some(VerifiedEndpoint {
        window,
        endpoint: Win16MdiEndpoint::Child(window),
        client,
    })
}

fn mapped_native_identity(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Option<(Win16HostWindow, Option<Win16HostSystemClass>)> {
    if hwnd.is_null() || unsafe { IsWindow(hwnd) } == 0 {
        return None;
    }
    let state = state.borrow();
    let identity = state.windows_by_native.get(&(hwnd as usize)).copied()?;
    if state.windows.get(&identity.window).copied() != Some(hwnd) {
        return None;
    }
    let system_kind = identity
        .class
        .and_then(|class| state.classes.get(&class))
        .and_then(|class| class.system_class_kind);
    Some((identity.window, system_kind))
}

fn resolve_mdi_child(
    state: &Rc<RefCell<WorkerState>>,
    client: HWND,
    token: Option<Win16HostWindow>,
) -> Option<HWND> {
    let Some(token) = token else {
        return Some(std::ptr::null_mut());
    };
    let hwnd = super::super::win16_window_identity::resolve_user_window(state, token)?;
    if hwnd.is_null() || unsafe { IsWindow(hwnd) } == 0 {
        return None;
    }
    let extended_style = unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 };
    (extended_style & WS_EX_MDICHILD != 0 && unsafe { GetParent(hwnd) } == client).then_some(hwnd)
}

fn payload_references_live_children(
    state: &Rc<RefCell<WorkerState>>,
    client: HWND,
    queued: Win16HostMdiQueuedMessage,
) -> bool {
    let child_is_live = |token| resolve_mdi_child(state, client, token).is_some();
    match queued.message {
        MdiKind::ActivateClient { activating } => child_is_live(activating),
        MdiKind::ActivateChild {
            activating,
            deactivating,
        } => match queued.endpoint {
            Win16MdiEndpoint::Child(child) => {
                child_is_live(Some(child))
                    && child_is_live(activating)
                    && child_is_live(deactivating)
                    && (activating == Some(child) || deactivating == Some(child))
            }
            Win16MdiEndpoint::Client => false,
        },
        MdiKind::Destroy { child }
        | MdiKind::Restore { child }
        | MdiKind::Next { child, .. }
        | MdiKind::Maximize { child } => child_is_live(child),
        MdiKind::Tile { .. }
        | MdiKind::Cascade { .. }
        | MdiKind::IconArrange
        | MdiKind::GetActive => true,
        MdiKind::SetMenu {
            refresh: true,
            frame_menu,
            window_menu,
        } => frame_menu.is_none() && window_menu.is_none(),
        MdiKind::SetMenu {
            refresh: false,
            frame_menu,
            window_menu,
        } => {
            resolve_menu(state, frame_menu).is_some() && resolve_menu(state, window_menu).is_some()
        }
    }
}

fn resolve_menu(
    state: &Rc<RefCell<WorkerState>>,
    token: Option<Win16HostMenu>,
) -> Option<windows_sys::Win32::UI::WindowsAndMessaging::HMENU> {
    let Some(token) = token else {
        return Some(std::ptr::null_mut());
    };
    let state = state.borrow();
    let native = state.menus.get(&token).copied()?;
    let bits = native as usize;
    (state.menus_by_native.get(&bits) == Some(&token)
        && !state.retiring_menu_native_handles.contains(&(token, bits))
        && !state.deferred_menu_retirements.contains(&(token, bits)))
    .then_some(native)
}

fn invalid_mdi_dispatch(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InvalidInput, message)
}

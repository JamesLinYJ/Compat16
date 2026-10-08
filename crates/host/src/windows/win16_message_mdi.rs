//! Native USER marshalling for typed Win16 MDI messages.
//!
//! Intended to be declared as a child module of `win16_window_default`, so it
//! can reuse the exact owner-thread invocation and checked identity helpers.
//! No native HWND, HMENU, HINSTANCE, or native structure pointer is returned
//! to the runtime.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMdiCreate, Win16HostMdiCreateFields,
    Win16HostMdiMessage, Win16HostMdiMessageQueuedKind, Win16HostMdiMessageResult,
    Win16HostMdiOutput, Win16HostMdiQueuedMessage, Win16HostMenu, Win16HostWindow,
    Win16MdiEndpoint,
};
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MDICREATESTRUCTW, WM_MDIACTIVATE, WM_MDICASCADE, WM_MDICREATE, WM_MDIDESTROY, WM_MDIGETACTIVE,
    WM_MDIICONARRANGE, WM_MDIMAXIMIZE, WM_MDINEXT, WM_MDIREFRESHMENU, WM_MDIRESTORE, WM_MDISETMENU,
    WM_MDITILE,
};

use super::super::win16_mdi_pending_creation::PendingMdiCreationGuard;
use super::super::win16_window_worker::WorkerState;
use super::{MessageInvocation, invoke_native_message};

const WM16_MDICREATE: u32 = 0x0220;
const WM16_MDIDESTROY: u32 = 0x0221;
const WM16_MDIACTIVATE: u32 = 0x0222;
const WM16_MDIRESTORE: u32 = 0x0223;
const WM16_MDINEXT: u32 = 0x0224;
const WM16_MDIMAXIMIZE: u32 = 0x0225;
const WM16_MDITILE: u32 = 0x0226;
const WM16_MDICASCADE: u32 = 0x0227;
const WM16_MDIICONARRANGE: u32 = 0x0228;
const WM16_MDIGETACTIVE: u32 = 0x0229;
const WM16_MDISETMENU: u32 = 0x0230;
const WM32_MDIREFRESHMENU: u32 = 0x0234;

#[path = "win16_mdi_destroy.rs"]
mod destroy;
pub(in crate::windows) use destroy::{
    dispatch_queued_message, finish_window_retirements,
    snapshot_window_retirements,
};

/// Keep all storage referenced by a native MDICREATESTRUCTW alive through the
/// complete DefFrameProc/SendMessage call, including reentrant guest callbacks.
pub(super) struct NativeMdiCreateStorage {
    pub(super) structure: MDICREATESTRUCTW,
    _class_name: Vec<u16>,
    _title: Option<Vec<u16>>,
}

impl NativeMdiCreateStorage {
    fn new(
        state: &Rc<RefCell<WorkerState>>,
        data: &Win16HostMdiCreate,
    ) -> Result<Option<Self>, RuntimeError> {
        let Some(class) = state.borrow().classes.get(&data.class).cloned() else {
            return Ok(None);
        };
        let class_bytes = class.name.strip_suffix(&[0]).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "registered native MDI class name has no final NUL",
            )
        })?;
        if class_bytes.is_empty() || class_bytes.contains(&0) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "registered native MDI class name is empty or contains an embedded NUL",
            ));
        }
        let (codec, title) = {
            let state = state.borrow();
            (
                state.text_codec,
                data.title
                    .as_deref()
                    .map(|bytes| state.text_codec.to_wide_z(bytes))
                    .transpose()?,
            )
        };
        let class_name = codec.to_wide_z(class_bytes)?;
        let structure = MDICREATESTRUCTW {
            szClass: class_name.as_ptr(),
            szTitle: title
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            // The guest hOwner is a 16-bit token. Native HINSTANCE comes only
            // from the resolved host class record, never from guest bits.
            hOwner: class.instance,
            x: mdi_coordinate(data.x),
            y: mdi_coordinate(data.y),
            cx: mdi_coordinate(data.cx),
            cy: mdi_coordinate(data.cy),
            style: data.style,
            lParam: data.parameter as i32 as LPARAM,
        };
        Ok(Some(Self {
            structure,
            _class_name: class_name,
            _title: title,
        }))
    }

    fn copied_fields(&self) -> Win16HostMdiCreateFields {
        // NTVDM's UnThunkWMMDICreate16 projects each native INT back to the
        // Win16 SHORT field. Keep that ABI-width truncation explicit here.
        Win16HostMdiCreateFields {
            x: self.structure.x as i16,
            y: self.structure.y as i16,
            cx: self.structure.cx as i16,
            cy: self.structure.cy as i16,
            style: self.structure.style,
            parameter: self.structure.lParam as u32,
        }
    }
}

fn mdi_coordinate(value: i16) -> i32 {
    if value == i16::MIN {
        i32::MIN
    } else {
        i32::from(value)
    }
}

fn resolve_window(
    state: &Rc<RefCell<WorkerState>>,
    token: Option<Win16HostWindow>,
) -> Option<HWND> {
    match token {
        None => Some(std::ptr::null_mut()),
        Some(token) => super::super::win16_window_identity::resolve_user_window(state, token),
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

fn window_token_for_native(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Option<Option<Win16HostWindow>> {
    if hwnd.is_null() {
        return Some(None);
    }
    let token = {
        let state = state.borrow();
        let identity = state.windows_by_native.get(&(hwnd as usize))?;
        (state.windows.get(&identity.window).copied() == Some(hwnd)).then_some(identity.window)?
    };
    if unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) } == 0 {
        return None;
    }
    Some(Some(token))
}

fn menu_token_for_native(
    state: &Rc<RefCell<WorkerState>>,
    menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
) -> Option<Option<Win16HostMenu>> {
    if menu.is_null() {
        return Some(None);
    }
    let state = state.borrow();
    let token = state.menus_by_native.get(&(menu as usize)).copied()?;
    (state.menus.get(&token).copied() == Some(menu)
        && !state
            .retiring_menu_native_handles
            .contains(&(token, menu as usize))
        && !state
            .deferred_menu_retirements
            .contains(&(token, menu as usize)))
    .then_some(Some(token))
}

/// Invoke one MDI message with owned inputs. The caller validates callback
/// provenance before calling this helper and supplies the invocation frame's
/// HWND plus the MDI client for frame-default processing.
pub(super) fn invoke(
    state: &Rc<RefCell<WorkerState>>,
    invocation: MessageInvocation,
    hwnd: HWND,
    message: Win16HostMdiMessage,
) -> Result<Option<Win16HostMdiMessageResult>, RuntimeError> {
    match message {
        Win16HostMdiMessage::ActivateClient { activating } => {
            let Some(activating) = resolve_window(state, activating) else {
                return Ok(None);
            };
            let result =
                invoke_native_message(invocation, hwnd, WM_MDIACTIVATE, activating as WPARAM, 0);
            Ok(Some(scalar_result(result)))
        }
        Win16HostMdiMessage::ActivateChild {
            child,
            activating,
            deactivating,
            ..
        } => {
            let Some(child) = resolve_window(state, Some(child)) else {
                return Ok(None);
            };
            if child != hwnd {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "Win16 child WM_MDIACTIVATE token differs from the receiving HWND",
                ));
            }
            let Some(activating) = resolve_window(state, activating) else {
                return Ok(None);
            };
            let Some(deactivating) = resolve_window(state, deactivating) else {
                return Ok(None);
            };
            // Win32 child WM_MDIACTIVATE: WPARAM is the deactivated child,
            // LPARAM is the activated child. Win16's BOOL+packed HWND16 form
            // is never forwarded directly.
            let result = invoke_native_message(
                invocation,
                child,
                WM_MDIACTIVATE,
                deactivating as WPARAM,
                activating as LPARAM,
            );
            Ok(Some(scalar_result(result)))
        }
        Win16HostMdiMessage::Create(data) => invoke_create(state, invocation, hwnd, data),
        Win16HostMdiMessage::Destroy { child } => {
            destroy::invoke_destroy(state, invocation, hwnd, child)
        }
        Win16HostMdiMessage::Restore { child } => {
            invoke_handle_message(state, invocation, hwnd, WM_MDIRESTORE, child, 0)
        }
        Win16HostMdiMessage::Next { child, previous } => invoke_handle_message(
            state,
            invocation,
            hwnd,
            WM_MDINEXT,
            child,
            isize::from(previous),
        ),
        Win16HostMdiMessage::Maximize { child } => {
            invoke_handle_message(state, invocation, hwnd, WM_MDIMAXIMIZE, child, 0)
        }
        Win16HostMdiMessage::Tile { flags } => {
            let result =
                invoke_native_message(invocation, hwnd, WM_MDITILE, usize::from(flags), 0);
            Ok(Some(scalar_result(result)))
        }
        Win16HostMdiMessage::Cascade { flags } => {
            let result =
                invoke_native_message(invocation, hwnd, WM_MDICASCADE, usize::from(flags), 0);
            Ok(Some(scalar_result(result)))
        }
        Win16HostMdiMessage::IconArrange => {
            let result = invoke_native_message(invocation, hwnd, WM_MDIICONARRANGE, 0, 0);
            Ok(Some(scalar_result(result)))
        }
        Win16HostMdiMessage::GetActive => {
            let mut maximized: BOOL = 0;
            let result = invoke_native_message(
                invocation,
                hwnd,
                WM_MDIGETACTIVE,
                0,
                (&mut maximized as *mut BOOL) as LPARAM,
            );
            let native_child = result as usize as HWND;
            let Some(child) = window_token_for_native(state, native_child) else {
                return Ok(None);
            };
            Ok(Some(Win16HostMdiMessageResult {
                value: 0,
                output: Win16HostMdiOutput::Active {
                    child,
                    maximized: maximized != 0,
                },
            }))
        }
        Win16HostMdiMessage::SetMenu { refresh: true, .. } => {
            // WM_MDIREFRESHMENU has no pointer arguments. It is the native
            // projection of the Win16 WM_MDISETMENU refresh form.
            let result = invoke_native_message(invocation, hwnd, WM_MDIREFRESHMENU, 0, 0);
            let native_previous =
                result as usize as windows_sys::Win32::UI::WindowsAndMessaging::HMENU;
            let Some(previous) = menu_token_for_native(state, native_previous) else {
                return Ok(None);
            };
            Ok(Some(Win16HostMdiMessageResult {
                value: 0,
                output: Win16HostMdiOutput::ReplacedFrameMenu(previous),
            }))
        }
        Win16HostMdiMessage::SetMenu {
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
            let result = invoke_native_message(
                invocation,
                hwnd,
                WM_MDISETMENU,
                frame_menu as WPARAM,
                window_menu as LPARAM,
            );
            let native_previous =
                result as usize as windows_sys::Win32::UI::WindowsAndMessaging::HMENU;
            let Some(previous) = menu_token_for_native(state, native_previous) else {
                return Ok(None);
            };
            Ok(Some(Win16HostMdiMessageResult {
                value: 0,
                output: Win16HostMdiOutput::ReplacedFrameMenu(previous),
            }))
        }
    }
}

fn invoke_handle_message(
    state: &Rc<RefCell<WorkerState>>,
    invocation: MessageInvocation,
    hwnd: HWND,
    message: u32,
    target: Option<Win16HostWindow>,
    l_param: LPARAM,
) -> Result<Option<Win16HostMdiMessageResult>, RuntimeError> {
    let Some(target) = resolve_window(state, target) else {
        return Ok(None);
    };
    let value = invoke_native_message(invocation, hwnd, message, target as WPARAM, l_param);
    Ok(Some(scalar_result(value)))
}

pub(super) fn with_menu_call_owners<T>(
    state: &Rc<RefCell<WorkerState>>,
    frame: HWND,
    requested_frame: Option<Win16HostMenu>,
    requested_window: Option<Win16HostMenu>,
    call: impl FnOnce() -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    let existing = if frame.is_null() {
        None
    } else {
        let borrowed = state.borrow();
        borrowed
            .windows_by_native
            .get(&(frame as usize))
            .and_then(|identity| borrowed.window_menus.get(&identity.window))
            .copied()
    };
    let mut roots = Vec::new();
    roots.try_reserve_exact(3).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve MDI frame menu roots before a reentrant USER call",
            error,
        )
    })?;
    roots.extend([existing, requested_frame, requested_window].into_iter().flatten());
    let _menu_owners = super::super::win16_menu_attachment::retain_menu_call_owners(
        state,
        &roots,
    )?;
    let result = call();
    super::super::win16_menu_attachment::reconcile_window_menu_ledger(state);
    result
}

fn scalar_result(value: isize) -> Win16HostMdiMessageResult {
    Win16HostMdiMessageResult {
        value: value as i32 as u32,
        output: Win16HostMdiOutput::None,
    }
}

fn invoke_create(
    state: &Rc<RefCell<WorkerState>>,
    invocation: MessageInvocation,
    hwnd: HWND,
    data: Win16HostMdiCreate,
) -> Result<Option<Win16HostMdiMessageResult>, RuntimeError> {
    match invocation {
        MessageInvocation::FrameDefault { mdi_client } if !mdi_client.is_null() => {}
        MessageInvocation::Send => {}
        _ => {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 WM_MDICREATE requires an MDI frame/client default or synchronous send",
            ));
        }
    }
    let Some(mut storage) = NativeMdiCreateStorage::new(state, &data)? else {
        return Ok(None);
    };
    let client = match invocation {
        MessageInvocation::FrameDefault { mdi_client } => mdi_client,
        MessageInvocation::Send => hwnd,
        _ => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "validated Win16 WM_MDICREATE invocation changed before dispatch",
            ));
        }
    };
    let frame = unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::GetParent(client)
    };
    let invocation_targets_exact_frame = match invocation {
        MessageInvocation::FrameDefault { mdi_client } => {
            mdi_client == client && hwnd == frame
        }
        MessageInvocation::Send => hwnd == client,
        _ => false,
    };
    if frame.is_null() || !invocation_targets_exact_frame {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 WM_MDICREATE did not target its exact registered MDI frame/client pair",
        ));
    }
    let pending = PendingMdiCreationGuard::register(
        state,
        client,
        frame,
        &storage.structure,
        &data,
    )?;
    let result = invoke_native_message(
        invocation,
        hwnd,
        WM_MDICREATE,
        0,
        (&mut storage.structure as *mut MDICREATESTRUCTW) as LPARAM,
    );
    pending.finish(result as usize as HWND)?;
    let child = if result == 0 {
        None
    } else {
        let native = result as usize as HWND;
        let Some(Some(token)) = window_token_for_native(state, native) else {
            return Ok(None);
        };
        Some(token)
    };
    let fields = storage.copied_fields();
    Ok(Some(Win16HostMdiMessageResult {
        value: 0,
        output: Win16HostMdiOutput::Created { child, fields },
    }))
}

/// Convert a native queued/callback MDI message into host-owned identities.
/// Pointer-bearing WM_MDICREATE is intentionally rejected without reading its
/// LPARAM; asynchronous MDI creation cannot safely retain that native pointer.
pub(in crate::windows) fn capture_native_queued_message(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16MdiEndpoint,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> Result<Option<Win16HostMdiQueuedMessage>, RuntimeError> {
    let map_window = |value: usize| -> Option<Option<Win16HostWindow>> {
        window_token_for_native(state, value as HWND)
    };
    let map_menu = |value: usize| -> Option<Option<Win16HostMenu>> {
        menu_token_for_native(
            state,
            value as windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
        )
    };
    let queued = match message {
        WM16_MDICREATE => return Ok(None),
        WM16_MDIACTIVATE => match endpoint {
            Win16MdiEndpoint::Client => {
                let Some(activating) = map_window(w_param) else {
                    return Ok(None);
                };
                Win16HostMdiMessageQueuedKind::ActivateClient { activating }
            }
            Win16MdiEndpoint::Child(_) => {
                // Native MDI-child WM_MDIACTIVATE packs the deactivated HWND
                // in WPARAM and activated HWND in LPARAM.
                let Some(deactivating) = map_window(w_param) else {
                    return Ok(None);
                };
                let Some(activating) = map_window(l_param as usize) else {
                    return Ok(None);
                };
                Win16HostMdiMessageQueuedKind::ActivateChild {
                    activating,
                    deactivating,
                }
            }
        },
        WM16_MDIDESTROY => {
            let Some(child) = map_window(w_param) else {
                return Ok(None);
            };
            Win16HostMdiMessageQueuedKind::Destroy { child }
        }
        WM16_MDIRESTORE => {
            let Some(child) = map_window(w_param) else {
                return Ok(None);
            };
            Win16HostMdiMessageQueuedKind::Restore { child }
        }
        WM16_MDINEXT => {
            let Some(child) = map_window(w_param) else {
                return Ok(None);
            };
            Win16HostMdiMessageQueuedKind::Next {
                child,
                previous: l_param != 0,
            }
        }
        WM16_MDIMAXIMIZE => {
            let Some(child) = map_window(w_param) else {
                return Ok(None);
            };
            Win16HostMdiMessageQueuedKind::Maximize { child }
        }
        WM16_MDITILE => Win16HostMdiMessageQueuedKind::Tile {
            flags: w_param as u16,
        },
        WM16_MDICASCADE => Win16HostMdiMessageQueuedKind::Cascade {
            flags: w_param as u16,
        },
        WM16_MDIICONARRANGE => Win16HostMdiMessageQueuedKind::IconArrange,
        WM16_MDIGETACTIVE => Win16HostMdiMessageQueuedKind::GetActive,
        WM16_MDISETMENU => {
            // Native WM_MDISETMENU uses pointer-sized HMENUs in WPARAM and
            // LPARAM; runtime later packs their guest words into Win16 LPARAM.
            let Some(frame_menu) = map_menu(w_param) else {
                return Ok(None);
            };
            let Some(window_menu) = map_menu(l_param as usize) else {
                return Ok(None);
            };
            Win16HostMdiMessageQueuedKind::SetMenu {
                refresh: false,
                frame_menu,
                window_menu,
            }
        }
        WM32_MDIREFRESHMENU => Win16HostMdiMessageQueuedKind::SetMenu {
            refresh: true,
            frame_menu: None,
            window_menu: None,
        },
        _ => return Ok(None),
    };
    Ok(Some(Win16HostMdiQueuedMessage {
        endpoint,
        message: queued,
    }))
}

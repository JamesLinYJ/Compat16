//! Copy USER owner-draw records while their synchronous native frame is live.

use std::cell::RefCell;
use std::rc::Rc;
use runtime::{RuntimeError, Win16HostMessage, Win16HostWindow,
    Win16OwnerDrawMessage as Owned, Win16OwnerDrawTarget as Target};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::UI::Controls::{
    COMPAREITEMSTRUCT, DELETEITEMSTRUCT, DRAWITEMSTRUCT, MEASUREITEMSTRUCT,
    ODT_MENU,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    WM_COMPAREITEM, WM_DELETEITEM, WM_DRAWITEM, WM_MEASUREITEM,
};
use super::win16_window_worker::{self as worker, WorkerState};

pub(super) fn is_message(message: u32) -> bool {
    matches!(message, WM_DRAWITEM | WM_MEASUREITEM | WM_DELETEITEM | WM_COMPAREITEM)
}

// USER uses UINT_MAX for the no-selection item (-1). All other WORD fields
// must fit the target ABI; opaque item data is a guest DWORD, never a pointer.
fn item_id(value: u32) -> Option<u16> {
    if value == u32::MAX { Some(u16::MAX) } else { u16::try_from(value).ok() }
}

fn window(state: &Rc<RefCell<WorkerState>>, hwnd: HWND)
    -> Result<Option<Win16HostWindow>, RuntimeError>
{
    if hwnd.is_null() { Ok(None) } else { worker::token_for_native(state, hwnd).map(Some) }
}

pub(super) fn copy_input(
    state: &Rc<RefCell<WorkerState>>, receiver: Win16HostWindow,
    message: u32, w_param: WPARAM, l_param: LPARAM,
) -> Result<Option<Win16HostMessage>, RuntimeError> {
    let Ok(control_id) = u16::try_from(w_param) else { return Ok(None); };
    if l_param == 0 { return Ok(None); }
    let owned = match message {
        WM_DRAWITEM => {
            // SAFETY: USER supplies DRAWITEMSTRUCT for this synchronous
            // callback; copy fields before guest reentry, retaining no pointer.
            let n = unsafe { &*(l_param as *const DRAWITEMSTRUCT) };
            let (Ok(ctl_type), Ok(ctl_id), Some(item_id), Ok(item_action), Ok(item_state), Ok(item_data)) = (
                u16::try_from(n.CtlType), u16::try_from(n.CtlID), item_id(n.itemID),
                u16::try_from(n.itemAction), u16::try_from(n.itemState), u32::try_from(n.itemData),
            ) else { return Ok(None); };
            let target = if n.CtlType == ODT_MENU {
                Target::Menu(if n.hwndItem.is_null() { None } else {
                    super::win16_menu_worker::intern_menu(state, n.hwndItem as _, false)?
                })
            } else { Target::Window(window(state, n.hwndItem)?) };
            let rect = runtime::Win16HostRect {
                left: n.rcItem.left, top: n.rcItem.top, right: n.rcItem.right, bottom: n.rcItem.bottom,
            };
            // Acquire this alias last. The caller immediately installs its
            // CallbackDcGuard; USER keeps ownership of the actual HDC.
            let dc = if n.hDC.is_null() { None } else {
                worker::adopt_callback_dc(state, receiver, n.hDC as usize)?
            };
            Owned::Draw { control_id, ctl_type, ctl_id, item_id, item_action,
                item_state, target, dc, rect, item_data }
        }
        WM_MEASUREITEM => {
            // SAFETY: USER owns the live MEASUREITEMSTRUCT for this message.
            let n = unsafe { &*(l_param as *const MEASUREITEMSTRUCT) };
            let (Ok(ctl_type), Ok(ctl_id), Some(item_id), Ok(width), Ok(height), Ok(item_data)) = (
                u16::try_from(n.CtlType), u16::try_from(n.CtlID), item_id(n.itemID),
                u16::try_from(n.itemWidth), u16::try_from(n.itemHeight), u32::try_from(n.itemData),
            ) else { return Ok(None); };
            Owned::Measure { control_id, ctl_type, ctl_id, item_id, width, height, item_data }
        }
        WM_DELETEITEM => {
            // SAFETY: USER owns the live DELETEITEMSTRUCT for this message.
            let n = unsafe { &*(l_param as *const DELETEITEMSTRUCT) };
            let (Ok(ctl_type), Ok(ctl_id), Some(item_id), Ok(item_data)) = (
                u16::try_from(n.CtlType), u16::try_from(n.CtlID), item_id(n.itemID), u32::try_from(n.itemData),
            ) else { return Ok(None); };
            Owned::Delete { control_id, ctl_type, ctl_id, item_id,
                window: window(state, n.hwndItem)?, item_data }
        }
        WM_COMPAREITEM => {
            // SAFETY: USER owns the live COMPAREITEMSTRUCT. Its later Win32
            // dwLocaleId field has no Windows 3.1 guest counterpart.
            let n = unsafe { &*(l_param as *const COMPAREITEMSTRUCT) };
            let (Ok(ctl_type), Ok(ctl_id), Some(item_id1), Some(item_id2), Ok(item_data1), Ok(item_data2)) = (
                u16::try_from(n.CtlType), u16::try_from(n.CtlID), item_id(n.itemID1), item_id(n.itemID2),
                u32::try_from(n.itemData1), u32::try_from(n.itemData2),
            ) else { return Ok(None); };
            Owned::Compare { control_id, ctl_type, ctl_id, window: window(state, n.hwndItem)?,
                item_id1, item_data1, item_id2, item_data2 }
        }
        _ => return Ok(None),
    };
    Ok(Some(Win16HostMessage::OwnerDraw(owned)))
}

pub(super) fn write_measure(
    l_param: LPARAM, width: u16, height: u16,
) -> bool {
    if l_param == 0 { return false; }
    // SAFETY: This function is called only on the exact suspended native
    // WM_MEASUREITEM frame. Its two output members are writable; all inputs,
    // including itemData, remain as supplied by USER.
    let n = unsafe { &mut *(l_param as *mut MEASUREITEMSTRUCT) };
    n.itemWidth = u32::from(width);
    n.itemHeight = u32::from(height);
    true
}

/// Rebuild a message in owned native storage. The invocation is synchronous;
/// HDC/menu leases span reentrant guest callbacks without holding table locks.
pub(super) fn invoke_owned(
    state: &Rc<RefCell<WorkerState>>, item: Owned, native_locale: Option<u32>,
    invoke: impl FnOnce(u32, usize, isize) -> runtime::Win16HostMessageResult,
) -> Result<Option<runtime::Win16HostMessageResult>, RuntimeError> {
    let message = u32::from(item.message_id());
    let w_param = usize::from(item.control_id());
    let native_item = |value: u16| if value == u16::MAX { u32::MAX } else { u32::from(value) };
    let resolve_window = |window: Option<Win16HostWindow>| match window {
        None => Some(std::ptr::null_mut()),
        Some(token) => super::win16_window_identity::resolve_user_window(state, token),
    };
    let result = match item {
        Owned::Draw { ctl_type, ctl_id, item_id, item_action, item_state,
            target, dc, rect, item_data, .. } => {
            let (hwnd_item, menu_token) = match target {
                Target::Window(window) => {
                    let Some(hwnd) = resolve_window(window) else { return Ok(None); };
                    (hwnd, None)
                }
                Target::Menu(None) => (std::ptr::null_mut(), None),
                Target::Menu(Some(menu)) => {
                    let Some(native) = state.borrow().menus.get(&menu).copied() else { return Ok(None); };
                    (native as HWND, Some(menu))
                }
            };
            let _menu_use = match menu_token {
                Some(menu) => Some(super::win16_menu_attachment::retain_menu_call_owners(state, &[menu])?),
                None => None,
            };
            let dcs = state.borrow().dcs.clone();
            let dc_use = match dc {
                Some(dc) => {
                    let Some(lease) = dcs.lease_dc(dc)? else { return Ok(None); };
                    Some(lease)
                }
                None => None,
            };
            let mut native = DRAWITEMSTRUCT {
                CtlType: u32::from(ctl_type), CtlID: u32::from(ctl_id), itemID: native_item(item_id),
                itemAction: u32::from(item_action), itemState: u32::from(item_state),
                hwndItem: hwnd_item, hDC: dc_use.as_ref().map_or(std::ptr::null_mut(), |lease| lease.native()),
                rcItem: windows_sys::Win32::Foundation::RECT {
                    left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
                }, itemData: item_data as usize,
            };
            invoke(message, w_param, (&mut native as *mut DRAWITEMSTRUCT) as isize)
        }
        Owned::Measure { ctl_type, ctl_id, item_id, width, height, item_data, .. } => {
            let mut native = MEASUREITEMSTRUCT { CtlType: u32::from(ctl_type), CtlID: u32::from(ctl_id),
                itemID: native_item(item_id), itemWidth: u32::from(width), itemHeight: u32::from(height),
                itemData: item_data as usize };
            let mut result = invoke(message, w_param, (&mut native as *mut MEASUREITEMSTRUCT) as isize);
            // The guest output uses WORD dimensions. Preserve that ABI's low
            // words, as for the existing USER geometry result conversions.
            result.output = runtime::Win16HostMessageOutput::OwnerDrawMeasure {
                width: native.itemWidth as u16, height: native.itemHeight as u16,
            };
            result
        }
        Owned::Delete { ctl_type, ctl_id, item_id, window, item_data, .. } => {
            let Some(hwnd_item) = resolve_window(window) else { return Ok(None); };
            let mut native = DELETEITEMSTRUCT { CtlType: u32::from(ctl_type), CtlID: u32::from(ctl_id),
                itemID: native_item(item_id), hwndItem: hwnd_item, itemData: item_data as usize };
            invoke(message, w_param, (&mut native as *mut DELETEITEMSTRUCT) as isize)
        }
        Owned::Compare { ctl_type, ctl_id, window, item_id1, item_data1, item_id2, item_data2, .. } => {
            let Some(hwnd_item) = resolve_window(window) else {
                // The receiver was valid at entry. An invalid item HWND is
                // a failed conversion, not a legitimate equal comparison.
                return Err(RuntimeError::new(runtime::DiagnosticKind::InvalidInput,
                    "COMPAREITEM item-window identity is no longer available"));
            };
            let mut native = COMPAREITEMSTRUCT { CtlType: u32::from(ctl_type), CtlID: u32::from(ctl_id),
                hwndItem: hwnd_item, itemID1: native_item(item_id1), itemID2: native_item(item_id2),
                itemData1: item_data1 as usize, itemData2: item_data2 as usize,
                // Independent guest records carry no locale member. Use
                // this USER worker's actual Windows locale for the native call.
                dwLocaleId: native_locale.unwrap_or_else(|| {
                    // SAFETY: This parameterless API reads the calling thread's
                    // Windows locale and neither dereferences guest data nor reenters.
                    unsafe { windows_sys::Win32::Globalization::GetThreadLocale() }
                }) };
            invoke(message, w_param, (&mut native as *mut COMPAREITEMSTRUCT) as isize)
        }
    };
    Ok(Some(result))
}

//! Native adapters for the extended Win16 common-control family.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ptr;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError,
    Win16HostCommonControlsOperation as Operation,
    Win16HostCommonControlsResult as ResultValue,
    Win16HostMenuHelpResolution as Help, Win16HostToolbarBitmap,
    Win16HostGdiObject};
use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{CreateDIBitmap, DeleteObject, GetDC, ReleaseDC,
    HBITMAP, BITMAPINFO, BITMAPINFOHEADER, CBM_INIT, DIB_RGB_COLORS};
use windows_sys::Win32::UI::Controls::{CreateToolbarEx, InitCommonControls, TBBUTTON,
    SB_SETTEXTW, SB_SIMPLE, SB_SIMPLEID, SBT_NOBORDERS};
use windows_sys::Win32::UI::WindowsAndMessaging::{CreateWindowExW, GetParent, SendMessageW,
    IsWindow, HMENU, WS_CHILD};

use super::WorkerState;
use super::super::win16_gdi_bitmap_lease::Win16BitmapLease;
use super::super::win16_common_controls_bitmap_pins::ToolbarBitmapOwner;

const HEADER_CLASS: &[u16] = &[
    0x006d, 0x0073, 0x0063, 0x0074, 0x006c, 0x0073, 0x005f, 0x0068,
    0x0065, 0x0061, 0x0064, 0x0065, 0x0072, 0x0062, 0x0061, 0x0072, 0,
];

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    operation: Operation,
    toolbar_bitmap_leases: &mut BTreeMap<Win16HostGdiObject, Option<Win16BitmapLease>>,
) -> Result<ResultValue, RuntimeError> {
    match operation {
        Operation::CreateHeaderWindow { style, text, parent, id } => {
            create_header_window(state, style, &text, parent, id)
        }
        Operation::CreateToolbar { style, parent, id, bitmap_count, bitmap, buttons,
            button_width, button_height, bitmap_width, bitmap_height, guest_button_size } => {
            create_toolbar(state, toolbar_bitmap_leases, style, parent, id, bitmap_count,
                bitmap, &buttons, button_width, button_height, bitmap_width, bitmap_height,
                guest_button_size)
        }
        Operation::MenuHelpResolve { message, w_param, flags, main_menu, selected_menu,
            status_bar: _, command_id_offset: _, menu_id_offset, popup_ids } => {
            resolve_menu_help(state, message, w_param, flags, main_menu,
                selected_menu, menu_id_offset, &popup_ids)
        }
        Operation::MenuHelpApply { status_bar, simple, text } => {
            apply_menu_help(state, status_bar, simple, text.as_deref())?;
            Ok(ResultValue::MenuHelpApplied)
        }
        Operation::MakeDragList { list_box, guest_list_box } => {
            super::super::win16_common_controls_drag_list::make_drag_list(
                state, list_box, guest_list_box,
            )
        }
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "non-extended operation reached the extended common-control adapter")),
    }
}

fn create_header_window(
    state: &Rc<RefCell<WorkerState>>,
    style: u32,
    text: &[u8],
    parent: runtime::Win16HostWindow,
    id: u16,
) -> Result<ResultValue, RuntimeError> {
    let Some(parent_hwnd) = super::super::win16_window_identity::resolve_user_window(state, parent)
        else { return Ok(created(None, None)); };
    if text.contains(&0) {return Err(RuntimeError::new(Kind::InvalidInput,
        "header-control text contains an embedded terminator"));}
    let text = state.borrow().text_codec.to_wide_z(text)?;
    unsafe { InitCommonControls() };
    // SDK 3.1 COMMCTRL declares the legacy `msctls_headerbar` class contract.
    // It is intentionally tried by name; SysHeader32 is a different control.
    // Coordinates are the API's undocumented default origin/extent, so a zero
    // rectangle is used without claiming behavioral equivalence to SysHeader32.
    let hwnd = unsafe {
        CreateWindowExW(0, HEADER_CLASS.as_ptr(), text.as_ptr(), style | WS_CHILD,
            0, 0, 0, 0, parent_hwnd, id as usize as HMENU, ptr::null_mut(), ptr::null())
    };
    create_result(state, hwnd)
}

#[allow(clippy::too_many_arguments)]
fn create_toolbar(
    state: &Rc<RefCell<WorkerState>>,
    toolbar_bitmap_leases: &mut BTreeMap<Win16HostGdiObject, Option<Win16BitmapLease>>,
    style: u32,
    parent: runtime::Win16HostWindow,
    id: u16,
    bitmap_count: i16,
    bitmap: Win16HostToolbarBitmap,
    buttons: &[runtime::Win16HostToolbarButton],
    button_width: i16,
    button_height: i16,
    bitmap_width: i16,
    bitmap_height: i16,
    guest_button_size: u16,
) -> Result<ResultValue, RuntimeError> {
    let Some(parent_hwnd) = super::super::win16_window_identity::resolve_user_window(state, parent)
        else { return Ok(created(None, None)); };
    if guest_button_size != 8 || bitmap_count < 0 || buttons.len() > i16::MAX as usize {
        return Ok(created(None, None));
    }
    unsafe { InitCommonControls() };
    let mut native_buttons = Vec::new();
    native_buttons.try_reserve_exact(buttons.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate native toolbar buttons", error))?;
    for button in buttons {
        // SDK 3.1 TBBUTTON.idsHelp is INT16. Its original Win16 DWORD bit
        // pattern is zero-extended to the modern ULONG_PTR dwData field.
        let help_data = (i32::from(button.help_data) as u32) as usize;
        native_buttons.push(TBBUTTON {
            iBitmap: i32::from(button.image_index),
            idCommand: i32::from(button.command_id),
            fsState: button.state,
            fsStyle: button.style,
            bReserved: [0; if core::mem::size_of::<usize>() == 8 { 6 } else { 2 }],
            dwData: help_data,
            iString: 0,
        });
    }
    if bitmap_count > 0 && matches!(&bitmap, Win16HostToolbarBitmap::None) {
        return Ok(created(None, None));
    }
    let operation = state.try_borrow().map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, "CreateToolbar could not inspect its active USER operation"))?
        .active_operations.last().map(|frame| frame.id).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "CreateToolbar has no active USER owner operation"))?;
    // Reserve both worker and post-join owner storage before transferring a
    // guest bitmap lease or acquiring a toolbar-owned HBITMAP.
    let mut staging = if matches!(&bitmap, Win16HostToolbarBitmap::GuestObject(_)
        | Win16HostToolbarBitmap::OwnedDib(_))
    {
        Some(super::super::win16_common_controls_bitmap_pins::reserve_stage_slot(
            state, operation, parent_hwnd, id,
        )?)
    } else { None };
    let owner_slot = match (matches!(&bitmap, Win16HostToolbarBitmap::GuestObject(_)
        | Win16HostToolbarBitmap::OwnedDib(_)), staging.as_mut())
    {
        (true, Some(slot)) => Some(slot),
        (true, None) => return Err(RuntimeError::new(Kind::InternalInvariant,
            "toolbar bitmap has no pre-reserved owner slot")),
        (false, _) => None,
    };
    let (native_instance, native_bitmap, staged) = match bitmap {
        Win16HostToolbarBitmap::None => (ptr::null_mut(), 0_usize, false),
        Win16HostToolbarBitmap::GuestObject(token) => {
            let Some(slot) = owner_slot else { return Err(RuntimeError::new(
                Kind::InternalInvariant, "guest toolbar bitmap has no owner slot")); };
            let Some(lease_slot) = toolbar_bitmap_leases.get_mut(&token) else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "CreateToolbarEx lost its pre-reserved bitmap lease entry"));
            };
            let Some(lease) = lease_slot.take() else {
                return Ok(created(None, None));
            };
            let handle = lease.native() as usize;
            stage_bitmap_owner(state, slot, ToolbarBitmapOwner::Guest(lease))?;
            (ptr::null_mut(), handle, true)
        }
        Win16HostToolbarBitmap::OwnedDib(dib) => {
            let Some(slot) = owner_slot else { return Err(RuntimeError::new(
                Kind::InternalInvariant, "toolbar DIB has no reserved owner slot")); };
            let Some(handle) = create_owned_dibitmap(state, &dib, slot)? else {
                return Ok(created(None, None));
            };
            stage_bitmap_owner(state, slot, ToolbarBitmapOwner::Owned(handle as usize))?;
            (ptr::null_mut(), handle as usize, true)
        }
        Win16HostToolbarBitmap::CommonControlResource(resource) => {
            // HINST_COMMCTRL is the SDK pseudo-instance (-1), not a host DLL
            // address. CreateToolbarEx recognizes this documented sentinel.
            (usize::MAX as HINSTANCE, usize::from(resource), false)
        }
    };
    // Microsoft TBADDBITMAP requires the caller's source HBITMAP to remain
    // alive until TB_REPLACEBITMAP or toolbar destruction. The pre-staged
    // owner survives both this call and any synchronous guest reentry.
    let native = unsafe {
        CreateToolbarEx(parent_hwnd, style | WS_CHILD, u32::from(id), i32::from(bitmap_count),
            native_instance, native_bitmap, native_buttons.as_mut_ptr(),
            buttons.len() as i32, i32::from(button_width), i32::from(button_height),
            i32::from(bitmap_width), i32::from(bitmap_height),
            core::mem::size_of::<TBBUTTON>() as u32)
    };
    let created = create_result(state, native);
    if staged {
        let native_live = !native.is_null() && unsafe { IsWindow(native) } != 0;
        if !native_live {
            let release = super::super::win16_common_controls_bitmap_pins::retire_failed_create(
                state, operation,
            );
            return match (created, release) {
                (Ok(result), Ok(())) => Ok(result),
                (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
                (Err(primary), Err(cleanup)) => Err(combine_cleanup(primary, Err(cleanup))),
            };
        }
        let window = created.as_ref().ok().and_then(|result| match result {
            ResultValue::CreatedWindow { window, .. } => *window,
            _ => None,
        });
        if let Err(primary) = super::super::win16_common_controls_bitmap_pins::bind_and_install(
            state, operation, window, native,
        ) {
            let cleanup = if let Some(window) = window {
                super::windows::cleanup_created_window(state, window, native)
            } else {
                super::super::win16_common_controls_bitmap_pins::destroy_orphan(
                    state, operation, native,
                )
            };
            let release = if unsafe { IsWindow(native) } == 0 {
                super::super::win16_common_controls_bitmap_pins::retire_destroyed(state, operation)
            } else { Ok(()) };
            let primary = match created {
                Err(created) => combine_cleanup(created, Err(primary)),
                Ok(_) => primary,
            };
            return Err(combine_cleanup(primary, combine_cleanup_results(cleanup, release)));
        }
        match created {
            Ok(result @ ResultValue::CreatedWindow { window: Some(_), .. }) => return Ok(result),
            Ok(result @ ResultValue::CreatedWindow { window: None, .. }) => {
                let cleanup = super::super::win16_common_controls_bitmap_pins::destroy_orphan(
                    state, operation, native,
                );
                let release = if unsafe { IsWindow(native) } == 0 {
                    super::super::win16_common_controls_bitmap_pins::retire_destroyed(state, operation)
                } else { Ok(()) };
                combine_cleanup_results(cleanup, release)?;
                return Ok(result);
            }
            Ok(_) => return Err(RuntimeError::new(Kind::InternalInvariant,
                "CreateToolbarEx returned an unexpected common-control result")),
            Err(primary) => {
                let cleanup = super::super::win16_common_controls_bitmap_pins::destroy_orphan(
                    state, operation, native,
                );
                let release = if unsafe { IsWindow(native) } == 0 {
                    super::super::win16_common_controls_bitmap_pins::retire_destroyed(state, operation)
                } else { Ok(()) };
                return Err(combine_cleanup(primary, combine_cleanup_results(cleanup, release)));
            }
        }
    }
    created
}

fn create_owned_dibitmap(
    state: &Rc<RefCell<WorkerState>>,
    dib: &runtime::Win16HostDib,
    staging: &mut super::super::win16_common_controls_bitmap_pins::ToolbarBitmapStageSlot,
) -> Result<Option<HBITMAP>, RuntimeError> {
    if dib.info.len() < core::mem::size_of::<BITMAPINFOHEADER>() {
        return Ok(None);
    }
    let words = dib.info.len().checked_add(3).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "align toolbar DIB information"))? / 4;
    let mut aligned = Vec::<u32>::new();
    aligned.try_reserve_exact(words).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate aligned toolbar DIB information", error))?;
    aligned.resize(words, 0);
    // The Win32 API consumes BITMAPINFO fields synchronously. Integer storage
    // gives this owned byte copy the documented DWORD alignment.
    unsafe {
        ptr::copy_nonoverlapping(dib.info.as_ptr(), aligned.as_mut_ptr().cast(), dib.info.len());
    }
    let header = aligned.as_ptr().cast::<BITMAPINFOHEADER>();
    let info = aligned.as_ptr().cast::<BITMAPINFO>();
    super::super::win16_common_controls_dc_retention::retry(state)?;
    super::super::win16_common_controls_dc_retention::reserve(state)?;
    let dc = unsafe { GetDC(ptr::null_mut()) };
    if dc.is_null() {
        super::super::win16_common_controls_dc_retention::cancel_reservation(state)?;
        return Ok(None);
    }
    let bitmap = unsafe { CreateDIBitmap(dc, header, CBM_INIT as u32, dib.bits.as_ptr().cast(),
        info, DIB_RGB_COLORS) };
    let released = unsafe { ReleaseDC(ptr::null_mut(), dc) } != 0;
    if !released {
        let last_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        let primary = RuntimeError::new(Kind::HostFailure,
            format!("ReleaseDC failed while creating a toolbar image bitmap (last error {last_error})"));
        // SAFETY: this record is pre-reserved and is retained on the same USER
        // thread; ReleaseDC has a creator-thread requirement.
        let dc_retention = super::super::win16_common_controls_dc_retention::retain(state, dc);
        let cleanup = if bitmap.is_null() || unsafe { DeleteObject(bitmap) } != 0 {
            Ok(())
        } else {
            let deletion = RuntimeError::new(Kind::HostFailure,
                "DeleteObject failed after toolbar bitmap DC release failed");
            match super::super::win16_common_controls_bitmap_pins::retain_unbound_owner(
                staging, ToolbarBitmapOwner::Owned(bitmap as usize),
            ) {
                Ok(()) => Err(deletion),
                Err((retention, owner)) => Err(
                    super::super::win16_common_controls_bitmap_pins::unretained_owner_error(
                        deletion, retention, owner,
                    )),
            }
        };
        let primary = combine_cleanup(primary, dc_retention);
        return Err(combine_cleanup(primary, cleanup));
    }
    if let Err(primary) = super::super::win16_common_controls_dc_retention::cancel_reservation(state) {
        if bitmap.is_null() {
            return Err(primary);
        }
        return match super::super::win16_common_controls_bitmap_pins::retain_unbound_owner(
            staging, ToolbarBitmapOwner::Owned(bitmap as usize),
        ) {
            Ok(()) => Err(primary),
            Err((retention, owner)) => Err(
                super::super::win16_common_controls_bitmap_pins::unretained_owner_error(
                    primary, retention, owner,
                )),
        };
    }
    Ok((!bitmap.is_null()).then_some(bitmap))
}

fn stage_bitmap_owner(
    state: &Rc<RefCell<WorkerState>>,
    slot: &mut super::super::win16_common_controls_bitmap_pins::ToolbarBitmapStageSlot,
    owner: ToolbarBitmapOwner,
) -> Result<(), RuntimeError> {
    match super::super::win16_common_controls_bitmap_pins::stage(state, slot, owner) {
        Ok(()) => Ok(()),
        Err((primary, owner)) => {
            match super::super::win16_common_controls_bitmap_pins::retain_unbound_owner(
                slot, owner,
            ) {
                Ok(()) => Err(primary),
                Err((retention, owner)) => Err(
                    super::super::win16_common_controls_bitmap_pins::unretained_owner_error(
                        primary, retention, owner,
                    )),
            }
        }
    }
}

fn create_result(state: &Rc<RefCell<WorkerState>>, hwnd: HWND)
    -> Result<ResultValue, RuntimeError> {
    let Some(window) = super::windows::register_owned_window(state, hwnd)? else {
        return Ok(created(None, None));
    };
    if super::super::win16_window_identity::resolve(state, window) != Some(hwnd) {
        super::windows::cleanup_created_window(state, window, hwnd)?;
        return Ok(created(None, None));
    }
    let actual_parent = unsafe { GetParent(hwnd) };
    let parent = if actual_parent.is_null() {
        None
    } else {
        match super::super::win16_window_worker::token_for_native(state, actual_parent) {
            Ok(parent) => Some(parent),
            Err(primary) => {
                let cleanup = super::windows::cleanup_created_window(state, window, hwnd);
                return Err(combine_cleanup(primary, cleanup));
            }
        }
    };
    Ok(created(Some(window), parent))
}

fn resolve_menu_help(
    state: &Rc<RefCell<WorkerState>>,
    message: u16,
    w_param: u16,
    flags: u16,
    main_menu: Option<runtime::Win16HostMenu>,
    selected_menu: Option<runtime::Win16HostMenu>,
    menu_id_offset: u16,
    popup_ids: &[(u16, runtime::Win16HostMenu)],
) -> Result<ResultValue, RuntimeError> {
    if message != 0x011f || flags & 0x0010 == 0 {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "MenuHelp resolution was requested outside popup WM_MENUSELECT"));
    }
    let Ok(state) = state.try_borrow() else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "MenuHelp could not borrow native menu identity state"));
    };
    let native = |token: runtime::Win16HostMenu| -> Option<windows_sys::Win32::UI::WindowsAndMessaging::HMENU> {
        let handle = *state.menus.get(&token)?;
        let key = handle as usize;
        (state.menus_by_native.get(&key) == Some(&token)
            && unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsMenu(handle) } != 0)
            .then_some(handle)
    };
    if let (Some(main), Some(selected)) = (main_menu.and_then(native), selected_menu.and_then(native)) {
        let count = unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetMenuItemCount(main) };
        if count >= 0 {
            for index in 0..count {
                let candidate = unsafe {
                    windows_sys::Win32::UI::WindowsAndMessaging::GetSubMenu(main, index)
                };
                if candidate == selected {
                    let string_id = menu_id_offset.wrapping_add(index as u16);
                    return Ok(ResultValue::MenuHelp(if string_id == 0 {
                        Help::NoChange
                    } else { Help::String(string_id) }));
                }
            }
        }
    }
    if let Some((id, _)) = popup_ids.iter().find(|(_, menu)| Some(*menu) == selected_menu) {
        return Ok(ResultValue::MenuHelp(Help::String(*id)));
    }
    let _ = w_param;
    Ok(ResultValue::MenuHelp(Help::NoChange))
}

fn apply_menu_help(
    state: &Rc<RefCell<WorkerState>>,
    status_bar: runtime::Win16HostWindow,
    simple: bool,
    text: Option<&[u8]>,
) -> Result<(), RuntimeError> {
    let Some(hwnd) = super::super::win16_window_identity::resolve_user_window(state, status_bar)
        else { return Ok(()); };
    if let Some(text) = text {
        let text=text.split(|byte|*byte==0).next().unwrap_or_default();
        let text=state.borrow().text_codec.to_wide_z(text)?;
        unsafe { SendMessageW(hwnd, SB_SETTEXTW, (SB_SIMPLEID | SBT_NOBORDERS) as WPARAM,
            text.as_ptr() as LPARAM); }
    }
    unsafe { SendMessageW(hwnd, SB_SIMPLE, usize::from(simple), 0); }
    Ok(())
}

fn created(window: Option<runtime::Win16HostWindow>, parent: Option<runtime::Win16HostWindow>)
    -> ResultValue {
    ResultValue::CreatedWindow { window, parent }
}

fn combine_cleanup(primary: RuntimeError, cleanup: Result<(), RuntimeError>) -> RuntimeError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => {
            let kind = primary.kind().with_cleanup(cleanup.kind());
            RuntimeError::with_source(kind,
                "common-control native operation and cleanup both failed",
                CommonControlsCleanupFailure { primary, cleanup })
        }
    }
}

fn combine_cleanup_results(
    primary: Result<(), RuntimeError>,
    cleanup: Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(combine_cleanup(primary, Err(cleanup))),
    }
}

#[derive(Debug)]
struct CommonControlsCleanupFailure { primary: RuntimeError, cleanup: RuntimeError }

impl std::fmt::Display for CommonControlsCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; cleanup also failed: {}", self.primary, self.cleanup)
    }
}

impl std::error::Error for CommonControlsCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.primary) }
}

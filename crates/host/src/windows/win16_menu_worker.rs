//! Native menu operations owned by the Win16 USER worker.
//!
//! Opaque menu identities and menu-tree ownership stay on this thread. No
//! RefCell borrow is held while calling USER because those calls can reenter a
//! window procedure and suspend the active worker operation.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostGdiObject, Win16HostMenu,
    Win16HostRect, Win16HostWindow, Win16MenuOperation, Win16MenuResult,
    Win16MenuTemplate, Win16MenuTemplateItem,
};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::HBITMAP;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CheckMenuItem, CheckMenuRadioItem, CreateMenu, CreatePopupMenu,
    DestroyMenu, DrawMenuBar, EnableMenuItem, EndMenu,
    GetMenu, GetMenuCheckMarkDimensions, GetMenuItemCount, GetMenuItemID,
    GetMenuItemInfoW, GetMenuItemRect, GetMenuState, GetSubMenu,
    GetSystemMenu, HiliteMenuItem, IsMenu,
    SetMenu, SetMenuItemBitmaps, TrackPopupMenu,
    MENUITEMINFOW, MIIM_SUBMENU,
    MF_BYPOSITION, MF_POPUP, MF_SEPARATOR,
    TPM_RETURNCMD,
};

use super::win16_menu_attachment::mark_owned;
use super::win16_window_worker::WorkerState;

#[path = "win16_menu_text.rs"]
mod text;

#[path = "win16_menu_worker_mutations.rs"]
mod mutations;

static NEXT_MENU_ID: AtomicU64 = AtomicU64::new(1);

type SetSystemMenuFn = unsafe extern "system" fn(
    HWND,
    windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
) -> windows_sys::core::BOOL;

static SET_SYSTEM_MENU: OnceLock<Option<SetSystemMenuFn>> = OnceLock::new();

fn set_system_menu_native(
    window: HWND,
    menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
) -> Option<bool> {
    let resolved = SET_SYSTEM_MENU.get_or_init(|| unsafe {
        let module = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(
            windows_sys::w!("user32.dll"));
        if module.is_null() { return None; }
        let address = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            module, b"SetSystemMenu\0".as_ptr())?;
        Some(std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            SetSystemMenuFn,
        >(address))
    });
    let Some(function) = *resolved else { return None; };
    Some(unsafe { function(window, menu) != 0 })
}

/// Executes one typed menu operation. `native_bitmaps` contains only checked
/// HBITMAP handles copied from the host's existing Win16Objects table; no
/// native handle is serialized into the runtime protocol.
pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    operation: Win16MenuOperation,
    native_bitmaps: &BTreeMap<Win16HostGdiObject, Option<usize>>,
) -> Result<Win16MenuResult, RuntimeError> {
    use Win16MenuOperation as Operation;

    match operation {
        Operation::Create { popup } => {
            let id = NEXT_MENU_ID.try_update(Ordering::Relaxed, Ordering::Relaxed,
                |value| value.checked_add(1)).map_err(|_| RuntimeError::new(
                    Kind::ResourceExhausted, "native menu identity space exhausted"))?;
            state.borrow_mut().menus_by_native.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve fresh native menu-generation publication", error)
            })?;
            let native = unsafe { if popup { CreatePopupMenu() } else { CreateMenu() } };
            let (menu, invalidated) = super::win16_menu_attachment::publish_fresh_menu_generation(
                state, native, Win16HostMenu(id),
            )?;
            if invalidated.is_empty() {
                Ok(Win16MenuResult::Created(menu))
            } else {
                Ok(Win16MenuResult::Menu { menu, invalidated })
            }
        }
        Operation::CreateFromTemplate { template } => {
            let owner_capacity = template_owner_capacity(&template)?;
            {
                let mut worker = state.borrow_mut();
                worker.retained_unmapped_menu_owners.try_reserve(owner_capacity).map_err(|error| {
                    RuntimeError::with_source(Kind::ResourceExhausted,
                        "reserve failed class-menu owner retention before native allocation", error)
                })?;
                worker.terminal_failures.try_reserve(owner_capacity).map_err(|error| {
                    RuntimeError::with_source(Kind::ResourceExhausted,
                        "reserve class-menu cleanup receipts before native allocation", error)
                })?;
            }
            let Some((native, native_menus, edges)) = build_template(state, &template)? else {
                return Ok(Win16MenuResult::Created(None));
            };
            let root = match intern_template_tree(state, native, native_menus, edges) {
                Ok(Some(root)) => root,
                Ok(None) => {
                    destroy_unpublished_menu(state, native);
                    return Ok(Win16MenuResult::Created(None));
                }
                Err(error) => {
                    destroy_unpublished_menu(state, native);
                    return Err(error);
                }
            };
            Ok(Win16MenuResult::Created(Some(root)))
        }
        Operation::Destroy { menu } => {
            mutations::destroy_menu(state, menu)
        }
        Operation::CheckItem { menu, item, flags } => {
            let previous = native_menu(state, menu).map_or(u32::MAX, |native| unsafe {
                CheckMenuItem(native, u32::from(item), u32::from(flags))
            });
            Ok(Win16MenuResult::ItemFlags(previous as u16))
        }
        Operation::EnableItem { menu, item, flags } => {
            let previous = native_menu(state, menu).map_or(-1_i32, |native| unsafe {
                EnableMenuItem(native, u32::from(item), u32::from(flags))
            });
            Ok(Win16MenuResult::ItemFlags(previous as u16))
        }
        Operation::HiliteItem { window, menu, item, flags } => {
            let hwnd = native_window(state, window);
            let hmenu = native_menu(state, menu);
            let succeeded = match (hwnd, hmenu) {
                (Some(hwnd), Some(hmenu)) => (unsafe {
                    HiliteMenuItem(hwnd, hmenu, u32::from(item), u32::from(flags))
                }) != 0,
                _ => false,
            };
            Ok(boolean(succeeded))
        }
        Operation::EndMenu => Ok(boolean(unsafe { EndMenu() } != 0)),
        Operation::IsMenu { menu } => Ok(boolean(native_menu(state, menu)
            .is_some_and(|native| unsafe { IsMenu(native) != 0 }))),
        Operation::GetMenuItemId { menu, position } => {
            let value = native_menu(state, menu).map_or(u32::MAX, |native| unsafe {
                GetMenuItemID(native, i32::from(position))
            });
            Ok(Win16MenuResult::ItemId(value as u16))
        }
        Operation::SetSystemMenu { window, menu } =>
            mutations::set_system_menu(state, window, menu),
        Operation::SetMenuContextHelpId { menu, help_id } => {
            let succeeded = native_menu(state, menu).is_some_and(|native| unsafe {
                windows_sys::Win32::UI::Shell::SetMenuContextHelpId(
                    native, u32::from(help_id)) != 0
            });
            Ok(boolean(succeeded))
        }
        Operation::GetMenuContextHelpId { menu } => {
            let value = native_menu(state, menu).map_or(0, |native| unsafe {
                windows_sys::Win32::UI::Shell::GetMenuContextHelpId(native)
            });
            Ok(Win16MenuResult::ContextHelpId(value))
        }
        Operation::GetMenuCheckMarkDimensions => Ok(
            Win16MenuResult::CheckMarkDimensions(
                unsafe { GetMenuCheckMarkDimensions() } as u32)),
        Operation::MakeMenuRToL { .. } => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 USER.485 MakeMenuRToL semantics have no verified Win32 equivalent",
        )),
        Operation::CheckRadioItem { menu, first, last, check, by_position } => {
            let succeeded = native_menu(state, menu).is_some_and(|native| unsafe {
                CheckMenuRadioItem(native, u32::from(first), u32::from(last),
                    u32::from(check), if by_position { MF_BYPOSITION } else { 0 }) != 0
            });
            Ok(boolean(succeeded))
        }
        Operation::GetSystemMenu { window, revert } => {
            let Some(hwnd) = native_window(state, window) else {
                return Ok(menu_result(None, Vec::new()));
            };
            let previous = { state.borrow().system_menus.get(&window).copied() };
            let identity_cookie = state.borrow().window_identity_cookies.get(&window)
                .filter(|binding| binding.hwnd == hwnd as usize)
                .map(|binding| binding.value);
            if previous.is_some_and(|previous| {
                super::win16_menu_attachment::cached_menu_tree_is_retiring(state, previous)
            }) {
                return Ok(menu_result(None, Vec::new()));
            }
            let previous_tree = if revert {
                match previous {
                    Some(previous) => {
                        let Some(previous_native) = native_menu(state, previous) else {
                            return Ok(menu_result(None, Vec::new()));
                        };
                        let Some(tree) = super::win16_menu_attachment::preflight_revert_system_menu(
                            state, window, hwnd, previous, previous_native,
                        )? else {
                            return Ok(menu_result(None, Vec::new()));
                        };
                        Some(tree)
                    }
                    None => None,
                }
            } else { None };
            let roots = previous.into_iter().collect::<Vec<_>>();
            let _menu_owners = super::win16_menu_attachment::retain_menu_call_owners(
                state, &roots,
            )?;
            let _reservation = match previous_tree.as_ref() {
                Some(tree) => Some(super::win16_menu_attachment::reserve_menu_retirement(state, tree)?),
                None => None,
            };
            let native = {
                unsafe { GetSystemMenu(hwnd, i32::from(revert)) }
            };
            drop(_reservation);
            drop(_menu_owners);
            let same_window = super::win16_window_identity::resolve_user_window(
                state, window,
            ) == Some(hwnd) && state.borrow().window_identity_cookies.get(&window)
                .filter(|binding| binding.hwnd == hwnd as usize)
                .map(|binding| binding.value) == identity_cookie;
            let same_ledger = state.borrow().system_menus.get(&window).copied() == previous;
            let invalidated = previous_tree.as_ref().map_or_else(Vec::new, |tree| {
                super::win16_menu_attachment::invalidate_menu_identities(
                    state, tree, revert && same_window && same_ledger,
                )
            });
            if !same_window {
                return Ok(menu_result(None, invalidated));
            }
            let token = intern_menu(state, native, false)?;
            if same_ledger {
                if let Some(token) = token {
                    state.borrow_mut().system_menus.insert(window, token);
                } else {
                    state.borrow_mut().system_menus.remove(&window);
                }
            }
            Ok(menu_result(token, invalidated))
        }
        Operation::GetMenu { window } => {
            let Some(hwnd) = native_window(state, window) else {
                return Ok(menu_result(None, Vec::new()));
            };
            let native = unsafe { GetMenu(hwnd) };
            let token = intern_menu(state, native, false)?;
            super::win16_menu_attachment::record_requested_attachment(
                state, window, hwnd, token, native,
            );
            Ok(menu_result(token, Vec::new()))
        }
        Operation::GetSubMenu { menu, position } => {
            if super::win16_menu_attachment::cached_menu_tree_is_retiring(state, menu) {
                return Ok(menu_result(None, Vec::new()));
            }
            let Some(root_native) = native_menu(state, menu) else {
                return Ok(menu_result(None, Vec::new()));
            };
            let native = unsafe { GetSubMenu(root_native, i32::from(position)) };
            let token = intern_menu(state, native, false)?;
            super::win16_menu_attachment::refresh_menu_tree(state, menu)
                .map_err(|error| RuntimeError::with_source(error.kind(),
                    format!("GetSubMenu returned a native handle (null={}); reconcile its owner graph",
                        native.is_null()), error))?;
            Ok(menu_result(token, Vec::new()))
        }
        Operation::SetMenu { window, menu } => {
            let hwnd = super::win16_window_identity::resolve_user_window(state, window);
            if menu.is_some_and(|menu| {
                super::win16_menu_attachment::cached_menu_tree_is_retiring(state, menu)
            }) {
                return Ok(boolean(false));
            }
            let hmenu = match menu {
                Some(menu) => native_menu(state, menu),
                None => Some(std::ptr::null_mut()),
            };
            let succeeded = match (hwnd, hmenu) {
                (Some(hwnd), Some(hmenu)) => {
                    let mut roots = menu.into_iter().collect::<Vec<_>>();
                    if let Some(previous) = super::win16_menu_attachment::token_for_native(
                        state, unsafe { GetMenu(hwnd) },
                    ) {
                        if super::win16_menu_attachment::cached_menu_tree_is_retiring(
                            state, previous,
                        ) {
                            return Ok(boolean(false));
                        }
                        roots.push(previous);
                    }
                    let _menu_owners = super::win16_menu_attachment::retain_menu_call_owners(
                        state, &roots,
                    )?;
                    unsafe { SetMenu(hwnd, hmenu) != 0 }
                }
                _ => false,
            };
            if let (Some(hwnd), Some(hmenu)) = (hwnd, hmenu) {
                // SetMenu can reenter and replace or retire this HWND. Record
                // only the requested attachment still present on the exact
                // token/cookie after the callback returns.
                super::win16_menu_attachment::record_requested_attachment(
                    state, window, hwnd, menu, hmenu,
                );
            }
            Ok(boolean(succeeded))
        }
        Operation::DrawMenuBar { window } => {
            if let Some(hwnd) = native_window(state, window) {
                let mut roots = {
                    let state = state.borrow();
                    state.window_menus.get(&window).copied()
                        .into_iter()
                        .chain(state.system_menus.get(&window).copied())
                        .collect::<Vec<_>>()
                };
                if let Some(root) = super::win16_menu_attachment::token_for_native(
                    state, unsafe { GetMenu(hwnd) },
                ) {
                    roots.push(root);
                }
                if roots.iter().any(|root| {
                    super::win16_menu_attachment::cached_menu_tree_is_retiring(state, *root)
                }) {
                    return Ok(Win16MenuResult::Drawn);
                }
                let _menu_owners = super::win16_menu_attachment::retain_menu_call_owners(
                    state, &roots,
                )?;
                let _ = unsafe { DrawMenuBar(hwnd) };
            }
            Ok(Win16MenuResult::Drawn)
        }
        Operation::GetMenuString { menu, item, flags, capacity } => {
            text::get_menu_string(state, menu, item, flags, capacity)
        }
        Operation::GetMenuState { menu, item, flags } => {
            let value = native_menu(state, menu).map_or(u32::MAX, |native| unsafe {
                GetMenuState(native, u32::from(item), u32::from(flags))
            });
            Ok(Win16MenuResult::ItemFlags(value as u16))
        }
        Operation::GetMenuItemCount { menu } => {
            let count = native_menu(state, menu).map_or(-1, |native| unsafe {
                GetMenuItemCount(native)
            });
            Ok(Win16MenuResult::ItemCount(count as i16))
        }
        Operation::GetMenuItemRect { window, menu, item } => {
            let hwnd = match window {
                Some(window) => native_window(state, window),
                None => Some(std::ptr::null_mut()),
            };
            let hmenu = native_menu(state, menu);
            let mut rect = RECT::default();
            let succeeded = match (hwnd, hmenu) {
                (Some(hwnd), Some(hmenu)) => (unsafe {
                    GetMenuItemRect(hwnd, hmenu, u32::from(item), &mut rect)
                }) != 0,
                _ => false,
            };
            let rect = succeeded.then_some(Win16HostRect {
                left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
            });
            Ok(Win16MenuResult::MenuRect { succeeded, rect })
        }
        Operation::InsertMenu { menu, position, flags, item } => {
            mutations::execute(state, native_bitmaps,
                Operation::InsertMenu { menu, position, flags, item })
        }
        Operation::AppendMenu { menu, flags, item } => {
            mutations::execute(state, native_bitmaps,
                Operation::AppendMenu { menu, flags, item })
        }
        Operation::ModifyMenu { menu, position, flags, item } => {
            mutations::execute(state, native_bitmaps,
                Operation::ModifyMenu { menu, position, flags, item })
        }
        Operation::SetMenuItemBitmaps { menu, position, flags, unchecked, checked } => {
            if super::win16_menu_attachment::cached_menu_tree_is_retiring(state, menu) {
                return Ok(boolean(false));
            }
            let native = native_menu(state, menu);
            let unchecked = resolve_bitmap(native_bitmaps, unchecked);
            let checked = resolve_bitmap(native_bitmaps, checked);
            let succeeded = match (native, unchecked, checked) {
                (Some(native), Some(unchecked), Some(checked)) => unsafe {
                    SetMenuItemBitmaps(native, u32::from(position), u32::from(flags),
                        unchecked as HBITMAP, checked as HBITMAP) != 0
                },
                _ => false,
            };
            Ok(boolean(succeeded))
        }
        Operation::RemoveMenu { menu, item, flags } => {
            mutations::execute(state, native_bitmaps,
                Operation::RemoveMenu { menu, item, flags })
        }
        Operation::DeleteMenu { menu, item, flags } => {
            mutations::execute(state, native_bitmaps,
                Operation::DeleteMenu { menu, item, flags })
        }
        Operation::TrackPopupMenu { menu, flags, x, y, reserved, owner, rect } => {
            if super::win16_menu_attachment::cached_menu_tree_is_retiring(state, menu) {
                return Ok(Win16MenuResult::Popup { value: 0, invalidated: Vec::new() });
            }
            let native = native_menu(state, menu);
            let hwnd = match owner {
                Some(owner) => native_window(state, owner),
                None => Some(std::ptr::null_mut()),
            };
            let native_rect = rect.map(|rect| RECT {
                left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
            });
            let _menu_owners = if native.is_some() {
                Some(super::win16_menu_attachment::retain_menu_call_owners(state, &[menu])?)
            } else {
                None
            };
            let value = match (native, hwnd) {
                (Some(menu), Some(hwnd)) => unsafe {
                    TrackPopupMenu(menu, u32::from(flags), i32::from(x), i32::from(y),
                        i32::from(reserved), hwnd,
                        native_rect.as_ref().map_or(std::ptr::null(), |rect| rect as *const RECT))
                },
                _ => 0,
            };
            // With TPM_RETURNCMD native USER returns the selected command ID;
            // otherwise it returns BOOL. Both are preserved in the Win16 word.
            let _returning_command = flags & (TPM_RETURNCMD as u16) != 0;
            Ok(Win16MenuResult::Popup { value: value as u16, invalidated: Vec::new() })
        }
    }
}

fn resolve_bitmap(
    bitmaps: &BTreeMap<Win16HostGdiObject, Option<usize>>,
    token: Option<Win16HostGdiObject>,
) -> Option<usize> {
    match token {
        None => Some(0),
        Some(token) => bitmaps.get(&token).copied().flatten(),
    }
}

fn native_menu(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostMenu,
) -> Option<windows_sys::Win32::UI::WindowsAndMessaging::HMENU> {
    let state = state.borrow();
    let native = state.menus.get(&token).copied()?;
    let raw = native as usize;
    if state.menus_by_native.get(&raw) != Some(&token)
        || state.retiring_menu_native_handles.contains(&(token, raw))
        || state.deferred_menu_retirements.contains(&(token, raw))
    {
        return None;
    }
    Some(native)
}

fn native_window(state: &Rc<RefCell<WorkerState>>, token: Win16HostWindow) -> Option<HWND> {
    super::win16_window_identity::resolve_user_window(state, token)
}

pub(super) fn intern_menu(
    state: &Rc<RefCell<WorkerState>>,
    native: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
    owned: bool,
) -> Result<Option<Win16HostMenu>, RuntimeError> {
    if native.is_null() { return Ok(None); }
    let native_value = native as usize;
    let existing = { state.borrow().menus_by_native.get(&(native as usize)).copied() };
    if let Some(token) = existing {
        let retiring = {
            let state = state.borrow();
            state.retiring_menu_native_handles.contains(&(token, native_value))
                || state.deferred_menu_retirements.contains(&(token, native_value))
        };
        if retiring { return Ok(None); }
        if state.borrow().menus.get(&token).copied() != Some(native) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native menu index points to a different token generation"));
        }
        if owned { mark_owned(state, token); }
        return Ok(Some(token));
    }
    if unsafe { IsMenu(native) } == 0 { return Ok(None); }
    let id = NEXT_MENU_ID.try_update(Ordering::Relaxed, Ordering::Relaxed,
        |value| value.checked_add(1)).map_err(|_| RuntimeError::new(
            Kind::ResourceExhausted, "native menu identity space exhausted"))?;
    let token = Win16HostMenu(id);
    let mut state = state.borrow_mut();
    if let Some(existing) = state.menus_by_native.get(&(native as usize)).copied() {
        if state.menus.get(&existing).copied() != Some(native) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native menu index changed to a different token generation"));
        }
        if owned {
            state.owned_menus.insert(existing);
            if !state.menu_children.values().any(|children| children.contains(&existing)) {
                state.owned_menu_roots.insert(existing);
            }
        }
        return Ok(Some(existing));
    }
    state.menus.insert(token, native);
    state.menus_by_native.insert(native as usize, token);
    if owned {
        state.owned_menus.insert(token);
        state.owned_menu_roots.insert(token);
    }
    Ok(Some(token))
}

fn query_submenu(
    state: &Rc<RefCell<WorkerState>>,
    menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
    item: u32,
    by_position: bool,
) -> Result<Option<Win16HostMenu>, RuntimeError> {
    let mut info = MENUITEMINFOW { cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
        fMask: MIIM_SUBMENU, ..MENUITEMINFOW::default() };
    let succeeded = unsafe { GetMenuItemInfoW(menu, item, i32::from(by_position), &mut info) };
    if succeeded == 0 || info.hSubMenu.is_null() { return Ok(None); }
    intern_menu(state, info.hSubMenu, false)
}

fn boolean(succeeded: bool) -> Win16MenuResult {
    Win16MenuResult::Boolean { succeeded, invalidated: Vec::new() }
}

fn menu_result(menu: Option<Win16HostMenu>, invalidated: Vec<Win16HostMenu>) -> Win16MenuResult {
    Win16MenuResult::Menu { menu, invalidated }
}

fn template_owner_capacity(template: &Win16MenuTemplate) -> Result<usize, RuntimeError> {
    fn count(template: &Win16MenuTemplate, depth: usize, total: &mut usize) -> Result<(), RuntimeError> {
        if depth > 32 {
            return Err(RuntimeError::new(Kind::CompatibilityGap,
                "native class-menu template exceeds supported nesting depth"));
        }
        for item in &template.items {
            *total = total.checked_add(1).ok_or_else(|| RuntimeError::new(
                Kind::ResourceExhausted, "class-menu item count overflowed"))?;
            if *total > 4096 {
                return Err(RuntimeError::new(Kind::CompatibilityGap,
                    "native class-menu template exceeds the bounded item count"));
            }
            if let Win16MenuTemplateItem::Popup { submenu, .. } = item {
                count(submenu, depth + 1, total)?;
            }
        }
        Ok(())
    }
    let mut total = 0;
    count(template, 0, &mut total)?;
    total.max(1).checked_mul(2).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "class-menu retained-owner capacity overflowed"))
}

fn destroy_unpublished_menu(
    state: &Rc<RefCell<WorkerState>>,
    native: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
) {
    if native.is_null() || unsafe { DestroyMenu(native) != 0 } {
        return;
    }
    if unsafe { IsMenu(native) } == 0 {
        return;
    }
    let mut worker = state.borrow_mut();
    if !worker.retained_unmapped_menu_owners.contains(&native) {
        worker.retained_unmapped_menu_owners.push(native);
    }
    worker.terminal_failures.push(Arc::new(RuntimeError::new(
        Kind::HostFailure,
        "class-menu materialization cleanup failed; native menu owner retained for worker shutdown",
    )));
}

fn build_template(
    state: &Rc<RefCell<WorkerState>>,
    template: &Win16MenuTemplate,
) -> Result<Option<(
    windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
    Vec<windows_sys::Win32::UI::WindowsAndMessaging::HMENU>,
    Vec<(windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
        windows_sys::Win32::UI::WindowsAndMessaging::HMENU)>,
)>, RuntimeError> {
    fn build(
        state: &Rc<RefCell<WorkerState>>,
        template: &Win16MenuTemplate,
        popup: bool,
    ) -> Result<Option<(
        windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
        Vec<windows_sys::Win32::UI::WindowsAndMessaging::HMENU>,
        Vec<(windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
            windows_sys::Win32::UI::WindowsAndMessaging::HMENU)>,
    )>, RuntimeError> {
        let root = unsafe { if popup { CreatePopupMenu() } else { CreateMenu() } };
        if root.is_null() { return Ok(None); }
        let mut menus = vec![root];
        let mut edges = Vec::new();
        for item in &template.items {
            let succeeded = match item {
                Win16MenuTemplateItem::Command { flags, id, text } => {
                    let text = match text::wide_z(state, text) {
                        Ok(text) => text,
                        Err(error) => {
                            destroy_unpublished_menu(state, root);
                            return Err(error);
                        }
                    };
                    unsafe { AppendMenuW(root, u32::from(*flags), usize::from(*id), text.as_ptr()) != 0 }
                }
                Win16MenuTemplateItem::Separator { flags, id } => unsafe {
                    AppendMenuW(root, u32::from(*flags) | MF_SEPARATOR, usize::from(*id), std::ptr::null()) != 0
                },
                Win16MenuTemplateItem::Popup { flags, text, submenu } => {
                    let child_build = build(state, submenu, true);
                    let (child, child_menus, child_edges) = match child_build {
                        Ok(Some(child)) => child,
                        Ok(None) => {
                            destroy_unpublished_menu(state, root);
                            return Ok(None);
                        }
                        Err(error) => {
                            destroy_unpublished_menu(state, root);
                            return Err(error);
                        }
                    };
                    let text = match text::wide_z(state, text) {
                        Ok(text) => text,
                        Err(error) => {
                            destroy_unpublished_menu(state, child);
                            destroy_unpublished_menu(state, root);
                            return Err(error);
                        }
                    };
                    if unsafe { AppendMenuW(root, u32::from(*flags) | MF_POPUP,
                        child as usize, text.as_ptr()) } == 0 {
                        destroy_unpublished_menu(state, child);
                        destroy_unpublished_menu(state, root);
                        return Ok(None);
                    }
                    menus.extend(child_menus);
                    edges.push((root, child));
                    edges.extend(child_edges);
                    true
                }
            };
            if !succeeded {
                destroy_unpublished_menu(state, root);
                return Ok(None);
            }
        }
        Ok(Some((root, menus, edges)))
    }
    build(state, template, false)
}

fn intern_template_tree(
    state: &Rc<RefCell<WorkerState>>,
    root: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
    menus: Vec<windows_sys::Win32::UI::WindowsAndMessaging::HMENU>,
    edges: Vec<(windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
        windows_sys::Win32::UI::WindowsAndMessaging::HMENU)>,
) -> Result<Option<Win16HostMenu>, RuntimeError> {
    {
        let state = state.borrow();
        if menus.iter().any(|native| {
            state.menus_by_native.get(&(*native as usize)).is_some_and(|token| {
                state.retiring_menu_native_handles.contains(&(*token, *native as usize))
            })
                || state.menus_by_native.contains_key(&(*native as usize))
        }) {
            return Ok(None);
        }
    }
    let mut tokens = BTreeMap::new();
    for native in menus {
        let id = match NEXT_MENU_ID.try_update(Ordering::Relaxed, Ordering::Relaxed,
            |value| value.checked_add(1)) {
            Ok(id) => id,
            Err(_) => return Err(RuntimeError::new(Kind::ResourceExhausted,
                "native menu identity space exhausted")),
        };
        tokens.insert(native as usize, Win16HostMenu(id));
    }
    let Some(root_token) = tokens.get(&(root as usize)).copied() else { return Ok(None); };
    let mut state = state.borrow_mut();
    for (native, token) in &tokens {
        let native = *native as windows_sys::Win32::UI::WindowsAndMessaging::HMENU;
        state.menus.insert(*token, native);
        state.menus_by_native.insert(native as usize, *token);
        state.owned_menus.insert(*token);
    }
    state.owned_menu_roots.insert(root_token);
    for (parent, child) in edges {
        if let (Some(parent), Some(child)) = (tokens.get(&(parent as usize)), tokens.get(&(child as usize))) {
            state.menu_children.entry(*parent).or_default().insert(*child);
            state.owned_menu_roots.remove(child);
        }
    }
    Ok(Some(root_token))
}

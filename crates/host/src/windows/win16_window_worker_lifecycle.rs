//! Native window-class registration and worker-owned shutdown cleanup.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostClass, Win16HostClassSpec,
    Win16HostSystemClass, Win16RegisteredClass,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    RegisterClassExW, UnregisterClassW, WNDCLASSEXW,
};

use super::super::win16_window_callbacks::host_window_proc;
use super::{NativeClass, WorkerState};

// Win16 SDK 3.0 DLGTEMPLATE requires a custom dialog class to reserve the
// 30-byte DLGWINDOWEXTRA area. Win32's DefDlgProc uses its native class extra
// storage for that state; guest cbWndExtra remains separately emulated.
const NATIVE_DLGWINDOWEXTRA_BYTES: i16 = 30;

pub(super) fn register_class(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostClass,
    spec: Win16HostClassSpec,
    icon: usize,
    cursor: usize,
    background: usize,
) -> Result<Option<Win16RegisteredClass>, RuntimeError> {
    if state.borrow().aborted { return Ok(None); }
    if spec.class_extra < 0 || spec.window_extra < 0 { return Ok(None); }
    if let Some(system_class) = spec.system_class {
        let name = predefined_class_name(system_class).to_vec();
        state.borrow_mut().classes.insert(token, Rc::new(NativeClass {
            name,
            instance: std::ptr::null_mut(),
            system_class: true,
            system_class_kind: Some(system_class),
            native_extras: None,
        }));
        // Atom zero marks an internal alias; it is never returned by a guest
        // RegisterClass operation or inserted in the guest class registry.
        return Ok(Some(Win16RegisteredClass { class: token, atom: 0 }));
    }
    let mut name = format!("Win16GuestClass_{}", token.0).into_bytes();
    name.push(0);
    // SAFETY: A NULL module name asks Windows for this process module.
    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    if instance.is_null() {
        return Err(RuntimeError::new(Kind::HostFailure,
            "GetModuleHandleW could not identify the Win16 host module"));
    }
    let Some((class_reserve, window_reserve)) = super::super::win16_system_classes::native_reserves()
        else { return Ok(None); };
    let class_extra = i32::from(spec.class_extra).max(class_reserve);
    let window_extra = i32::from(spec.window_extra.max(NATIVE_DLGWINDOWEXTRA_BYTES)).max(window_reserve);
    let native_class = Rc::new(NativeClass {
        name, instance, system_class: false, system_class_kind: None,
        native_extras: Some((class_extra, window_extra)),
    });
    let wide_name = native_class.name.iter().map(|byte| u16::from(*byte)).collect::<Vec<_>>();
    let class = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        style: u32::from(spec.style),
        lpfnWndProc: Some(host_window_proc),
        cbClsExtra: class_extra,
        cbWndExtra: window_extra,
        hInstance: instance,
        hIcon: icon as _,
        hCursor: cursor as _,
        hbrBackground: background as _,
        lpszClassName: wide_name.as_ptr(),
        ..WNDCLASSEXW::default()
    };
    // Resource numbers were resolved from host-owned tables before entering
    // the worker. They are reconstituted here and never sent back to runtime.
    let atom = unsafe { RegisterClassExW(&class) };
    if atom == 0 { return Ok(None); }
    state.borrow_mut().classes.insert(token, native_class);
    Ok(Some(Win16RegisteredClass { class: token, atom }))
}

pub(super) fn unregister_class(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostClass,
) -> bool {
    let Some(class) = state.borrow().classes.get(&token).cloned() else { return false; };
    if class.system_class {
        state.borrow_mut().classes.remove(&token);
        return true;
    }
    // SAFETY: This class name and module identify a class registered here.
    let wide_name = class.name.iter().map(|byte| u16::from(*byte)).collect::<Vec<_>>();
    if unsafe { UnregisterClassW(wide_name.as_ptr(), class.instance) } == 0 { return false; }
    state.borrow_mut().classes.remove(&token);
    true
}

pub(in super::super) fn shutdown_all(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    let dialog_cleanup = super::super::win16_common_dialog_worker::shutdown(state);
    let drag_list_cleanup = super::super::win16_common_controls_drag_list::retire_all(state);
    let mut result = combine_cleanup(dialog_cleanup, drag_list_cleanup);
    let mut windows = {
        let state = state.borrow();
        state.windows.iter().filter_map(|(token, hwnd)| {
            state.windows_by_native.get(&(*hwnd as usize))
                .filter(|identity| identity.owned && identity.window == *token)
                .map(|_| (*token, *hwnd))
        }).collect::<Vec<_>>()
    };
    windows.sort_unstable_by_key(|(token, _)| *token);
    for (token, hwnd) in windows {
        let (destroyed, _) = super::destroy_window_operation(state, token);
        if destroyed { continue; }
        if unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) } == 0 {
            super::super::win16_window_worker::remove_window_maps(state, token, hwnd);
        } else {
            result = combine_cleanup(result, Err(RuntimeError::new(
                Kind::HostFailure,
                "worker shutdown could not destroy an owned HWND; its identity remains live for retry",
            )));
        }
    }
    result = combine_cleanup(result,
        super::super::win16_common_controls_bitmap_pins::retire_all(state));

    let roots = {
        let state = state.borrow();
        state.owned_menu_roots.iter().copied().collect::<Vec<_>>()
    };
    for menu in roots {
        let native = { state.borrow().menus.get(&menu).copied() };
        let Some(native) = native else { continue; };
        if unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsMenu(native) } == 0 {
            let identities = super::super::win16_menu_attachment::menu_tree(state, menu)
                .into_iter().filter_map(|token| state.borrow().menus.get(&token).copied()
                    .map(|native| (token, native as usize)))
                .collect::<std::collections::BTreeMap<_, _>>();
            let _ = super::super::win16_menu_attachment::invalidate_menu_identities(
                state, &identities, false,
            );
            continue;
        }
        let tree = match super::super::win16_menu_attachment::preflight_destroy_menu_tree(
            state, menu, native,
        ) {
            Ok(Some(tree)) => tree,
            Ok(None) => {
                result = combine_cleanup(result, Err(RuntimeError::new(
                    Kind::HostFailure,
                    "worker shutdown retained a menu tree with a live, shared, or in-flight owner",
                )));
                continue;
            }
            Err(error) => {
                result = combine_cleanup(result, Err(error));
                continue;
            }
        };
        let owners = match super::super::win16_menu_attachment::retain_menu_call_owners(
            state, &[menu],
        ) {
            Ok(owners) => owners,
            Err(error) => {
                result = combine_cleanup(result, Err(error));
                continue;
            }
        };
        let reservation = match super::super::win16_menu_attachment::reserve_menu_retirement(
            state, &tree,
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                result = combine_cleanup(result, Err(error));
                drop(owners);
                continue;
            }
        };
        let destroyed = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::DestroyMenu(native) != 0
        };
        drop(reservation);
        let _ = super::super::win16_menu_attachment::invalidate_menu_identities(
            state, &tree, destroyed,
        );
        drop(owners);
        if !destroyed && super::super::win16_menu_attachment::menu_token_matches(
            state, menu, native,
        ) && unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsMenu(native) } != 0
        {
            result = combine_cleanup(result, Err(RuntimeError::new(
                Kind::HostFailure,
                "worker shutdown could not destroy a detached native menu; its owner remains mapped for retry",
            )));
        }
    }
    let mut unmapped_menus = {
        let mut state = state.borrow_mut();
        std::mem::take(&mut state.retained_unmapped_menu_owners)
    };
    let mut index = 0;
    while index < unmapped_menus.len() {
        let native = unmapped_menus[index];
        let live_before = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::IsMenu(native) != 0
        };
        let destroyed = !live_before || unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::DestroyMenu(native) != 0
        };
        let live_after = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::IsMenu(native) != 0
        };
        if destroyed || !live_after {
            unmapped_menus.swap_remove(index);
        } else {
            result = combine_cleanup(result, Err(RuntimeError::new(
                Kind::HostFailure,
                "worker shutdown retained an unmapped native class-menu owner after DestroyMenu failed",
            )));
            index += 1;
        }
    }
    state.borrow_mut().retained_unmapped_menu_owners = unmapped_menus;
    let owned_windows_remain = {
        let state = state.borrow();
        state.windows_by_native.values().any(|identity| identity.owned)
    };
    if !owned_windows_remain {
        let classes = {
            let state = state.borrow();
            state.classes.keys().copied().collect::<Vec<_>>()
        };
        for class in classes {
            if !unregister_class(state, class) {
                result = combine_cleanup(result, Err(RuntimeError::new(
                    Kind::HostFailure,
                    "worker shutdown could not unregister a native class; its owner remains mapped for retry",
                )));
            }
        }
        super::super::win16_window_properties::retire_all(state);
        super::super::win16_window_identity::retire_all(state);
    }
    result
}

fn predefined_class_name(class: Win16HostSystemClass) -> &'static [u8] {
    match class {
        Win16HostSystemClass::Button => b"BUTTON\0",
        Win16HostSystemClass::Edit => b"EDIT\0",
        Win16HostSystemClass::Static => b"STATIC\0",
        Win16HostSystemClass::ListBox => b"LISTBOX\0",
        Win16HostSystemClass::ComboBox => b"COMBOBOX\0",
        Win16HostSystemClass::ScrollBar => b"SCROLLBAR\0",
        Win16HostSystemClass::MdiClient => b"MDICLIENT\0",
    }
}

fn combine_cleanup(
    primary: Result<(), RuntimeError>,
    cleanup: Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(primary.with_cleanup(
            "multiple Win16 USER shutdown cleanup operations failed",
            cleanup,
        )),
    }
}

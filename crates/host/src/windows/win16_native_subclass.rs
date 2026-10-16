//! Exact-window installation and retirement of the native subclass bridge.

use super::*;
use windows_sys::Win32::UI::WindowsAndMessaging::SetWindowLongPtrW;

pub(in crate::windows::win16_windows) fn is_subclassed(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
) -> bool {
    let Some(hwnd) = win16_window_identity::resolve(state, window) else {
        return false;
    };
    let Some(identity) = identity_for(state, window, hwnd) else {
        return false;
    };
    state
        .borrow()
        .native_procedures
        .bases
        .get(&window)
        .is_some_and(|binding| {
            binding.subclass_generation.is_some()
                && binding.subclass_attached
                && binding.hwnd == identity.hwnd
                && binding.cookie == identity.value
        })
}

pub(in crate::windows::win16_windows) fn set_procedure(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    previous: Win16HostProcedure,
    restore: bool,
) -> Result<Option<Win16HostProcedure>, RuntimeError> {
    // Only a per-window capture is eligible. A class-wide token does not prove
    // which procedure this exact native control previously installed.
    let key = state
        .borrow()
        .native_procedures
        .entries
        .get(&previous)
        .map(|entry| entry.key);
    let Some(key) = key.filter(|key| key.window == window) else {
        return Ok(None);
    };
    let Some(hwnd) = win16_window_identity::resolve(state, window) else {
        return Ok(None);
    };
    let identity = WindowCookieBinding {
        hwnd: key.hwnd,
        value: key.cookie,
    };
    if !identity_is_live(state, window, identity) {
        return Ok(None);
    }
    let bridge = super::super::win16_window_callbacks::host_window_proc as *const () as isize;
    let existing = state.borrow().native_procedures.bases.get(&window).copied();
    let generation = if restore {
        let Some(binding) = existing.filter(|binding| {
            binding.procedure == previous
                && binding.hwnd == key.hwnd
                && binding.cookie == key.cookie
                && binding.subclass_attached
        }) else {
            return Ok(None);
        };
        let Some(generation) = binding.subclass_generation else {
            return Ok(None);
        };
        if get_window_procedure(hwnd) != Some(bridge) {
            return Ok(None);
        }
        generation
    } else {
        if state.borrow().aborted
            || existing.is_some()
            || key.native_procedure == bridge
            || get_window_procedure(hwnd) != Some(key.native_procedure)
        {
            return Ok(None);
        }
        let mut state = state.borrow_mut();
        let registry = &mut state.native_procedures;
        let generation = registry
            .next_subclass_generation
            .checked_add(1)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "native subclass generation exhausted",
                )
            })?;
        registry.bases.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native subclass owner before installation",
                error,
            )
        })?;
        registry.next_subclass_generation = generation;
        registry.bases.insert(
            window,
            NativeBaseBinding {
                procedure: previous,
                hwnd: key.hwnd,
                cookie: key.cookie,
                destroy_entered: false,
                subclass_generation: Some(generation),
                subclass_attached: true,
            },
        );
        generation
    };
    let replacement = if restore {
        key.native_procedure
    } else {
        bridge
    };
    let expected = if restore {
        bridge
    } else {
        key.native_procedure
    };
    // SAFETY: The exact same-worker HWND and current procedure were checked.
    // The saved provider remains pinned, and the callback owner was published
    // before entering USER. No worker borrow is held across this native call.
    let replaced = unsafe {
        SetLastError(0);
        let replaced = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, replacement);
        if replaced == 0 && GetLastError() != 0 {
            None
        } else {
            Some(replaced)
        }
    };
    if replaced != Some(expected) {
        // Preserve a later mutation if native reentry changed the generation.
        // On an ordinary USER failure no replacement occurred.
        if !restore && replaced.is_none() {
            remove_generation(state, window, generation);
            return Ok(None);
        }
        if restore && replaced.is_none() {
            return Ok(None);
        }
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native subclass replacement changed its captured previous procedure",
        ));
    }
    if restore {
        let destroying = state.borrow().live_callbacks.iter().any(|frame| {
            frame.hwnd == hwnd
                && frame.message == Some(windows_sys::Win32::UI::WindowsAndMessaging::WM_NCDESTROY)
        });
        if destroying {
            // The native procedure is restored, but this suspended NCDESTROY
            // still owns its once-only base cleanup. Keep the guard through an
            // explicit CallWindowProc(old) and the callback's final fallback.
            let mut state = state.borrow_mut();
            if let Some(binding) = state.native_procedures.bases.get_mut(&window)
                && binding.subclass_generation == Some(generation)
            {
                binding.subclass_attached = false;
            }
        } else {
            remove_generation(state, window, generation);
        }
    }
    Ok(Some(previous))
}

fn remove_generation(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow, generation: u64) {
    let mut state = state.borrow_mut();
    if state
        .native_procedures
        .bases
        .get(&window)
        .is_some_and(|binding| binding.subclass_generation == Some(generation))
    {
        state.native_procedures.bases.remove(&window);
    }
}

/// Owned windows were destroyed first. Restore surviving borrowed controls
/// before terminal receipts permit the runtime to release guest code roots.
pub(in crate::windows::win16_windows) fn restore_subclasses(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<(), RuntimeError> {
    let bindings = state
        .borrow()
        .native_procedures
        .bases
        .iter()
        .filter(|(_, binding)| binding.subclass_generation.is_some() && binding.subclass_attached)
        .map(|(&window, binding)| (window, *binding))
        .collect::<Vec<_>>();
    for (window, binding) in bindings {
        if win16_window_identity::resolve(state, window).is_none() {
            // An identity failure is not proof of destruction. Retain the
            // bridge owner rather than changing a potentially recycled HWND.
            if unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(binding.hwnd as HWND)
            } != 0
            {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "live native subclass lost its exact window identity during shutdown",
                ));
            }
            remove_generation(state, window, binding.subclass_generation.unwrap());
            continue;
        }
        if set_procedure(state, window, binding.procedure, true)?.is_none() {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "native subclass bridge could not be restored during worker shutdown",
            ));
        }
    }
    Ok(())
}

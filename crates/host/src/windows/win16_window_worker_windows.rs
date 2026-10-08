//! Native USER-window lifecycle and identity helpers.

use super::*;
use super::window_retirement;

pub(super) fn create_window(
    state: &Rc<RefCell<WorkerState>>,
    creation: Win16CreationId,
    data: Win16HostCreationData,
) -> Result<Win16HostWindowCreationResult, RuntimeError> {
    let Some(class) = state.borrow().classes.get(&data.class).cloned() else {
        return Ok(Win16HostWindowCreationResult::not_invoked(
            Win16WindowCreationRejection::NativeWindowClassUnavailable,
        ));
    };
    let is_mdi_client = class.system_class_kind == Some(runtime::Win16HostSystemClass::MdiClient);
    if is_mdi_client != data.mdi_client.is_some() {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "MDI client creation fields do not match their exact predefined class identity"));
    }
    let mut mdi_client = match data.mdi_client {
        Some(input) => {
            let native_menu = match input.window_menu {
                None => std::ptr::null_mut(),
                Some(menu) => match state.borrow().menus.get(&menu).copied() {
                    Some(native) => native,
                    None => return Ok(Win16HostWindowCreationResult::not_invoked(
                        Win16WindowCreationRejection::NativeMenuUnavailable,
                    )),
                },
            };
            Some(windows_sys::Win32::UI::WindowsAndMessaging::CLIENTCREATESTRUCT {
                hWindowMenu: native_menu,
                idFirstChild: u32::from(input.first_child_id),
            })
        }
        None => None,
    };
    let parent_handle = data
        .parent
        .map(|parent| super::super::win16_window_identity::resolve_user_window(state, parent));
    let parent = match (data.parent, parent_handle) {
        (Some(_), Some(Some(hwnd))) => {
            if unsafe { IsWindow(hwnd) } == 0 {
                return Ok(Win16HostWindowCreationResult::not_invoked(
                    Win16WindowCreationRejection::NativeParentUnavailable,
                ));
            }
            hwnd
        }
        (Some(_), _) => return Ok(Win16HostWindowCreationResult::not_invoked(
            Win16WindowCreationRejection::NativeParentUnavailable,
        )),
        (None, _) => std::ptr::null_mut(),
    };
    let title = super::super::win16_window_text_context::wide_z_from_guest(
        state,
        data.title.as_deref().unwrap_or_default(),
    )?;
    let class_name = class.name.iter().map(|byte| u16::from(*byte)).collect::<Vec<_>>();
    let child_id = data.child_id.map_or(std::ptr::null_mut(), |id| {
        usize::from(id) as *mut std::ffi::c_void
    });
    let child_window = data.style & windows_sys::Win32::UI::WindowsAndMessaging::WS_CHILD != 0;
    if (child_window || data.menu.is_some()) && data.class_menu_template.is_some() {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "class-menu template was sent for a child or alongside an explicit HMENU"));
    }
    let token = allocate_window_token(state)?;
    super::super::win16_window_identity::reserve_creation_owner_capacity(
        state, !class.system_class,
    )?;
    let creation_owner = super::super::win16_window_identity::native_creation_owner_identity(
        token, creation,
    )?;
    let mut class_menu_token = None;
    // HWND parent also represents an owner for popup/overlapped windows.
    // Only WS_CHILD changes hMenu into a child control identifier (SDK 3.1,
    // CreateWindow); owned top-level windows retain their translated menu.
    let menu = if child_window {
        child_id.cast()
    } else {
        match data.menu {
            Some(token) => match state.borrow().menus.get(&token).copied() {
                Some(native) => native,
                None => return Ok(Win16HostWindowCreationResult::not_invoked(
                    Win16WindowCreationRejection::NativeMenuUnavailable,
                )),
            },
            None => match data.class_menu_template.as_ref() {
                Some(template) => {
                    let Some(class_menu) = super::class_menu::create(state, template)? else {
                        return Ok(Win16HostWindowCreationResult::not_invoked(
                            Win16WindowCreationRejection::NativeMenuUnavailable,
                        ));
                    };
                    class_menu_token = Some(class_menu);
                    let class_menu_native = {
                        state.borrow().menus.get(&class_menu).copied()
                    };
                    match class_menu_native {
                        Some(native) => native,
                        None => {
                            let error = RuntimeError::new(Kind::InternalInvariant,
                                "materialized class menu lost its native owner record");
                            return match super::class_menu::retire_unattached_class_menu(
                                state, class_menu,
                            ) {
                                Ok(()) => Err(error),
                                Err(cleanup) => Err(error.with_cleanup(
                                    "class-menu owner record vanished before CreateWindowEx",
                                    cleanup,
                                )),
                            };
                        }
                    }
                }
                None => std::ptr::null_mut(),
            },
        }
    };
    let menu_owner = if !child_window {
        data.menu.or(class_menu_token)
    } else {
        None
    };
    if menu_owner.is_some_and(|menu| super::super::win16_menu_attachment::
        cached_menu_tree_is_retiring(state, menu))
    {
        if let Some(class_menu) = class_menu_token {
            super::class_menu::retire_unattached_class_menu(state, class_menu)?;
        }
        return Ok(Win16HostWindowCreationResult::not_invoked(
            Win16WindowCreationRejection::NativeMenuUnavailable,
        ));
    }
    // CreateWindowEx runs synchronous class callbacks before the HWND is
    // published in WorkerState; keep its hMenu tree alive through that frame.
    let mut menu_owners = menu_owner.into_iter().collect::<Vec<_>>();
    if let Some(menu) = data.mdi_client.and_then(|data| data.window_menu) {
        if !menu_owners.contains(&menu) { menu_owners.push(menu); }
    }
    let menu_owner_guard = if menu_owners.is_empty() { None } else {
        Some(super::super::win16_menu_attachment::retain_menu_call_owners(state, &menu_owners))
    };
    let menu_owner_guard = match menu_owner_guard {
        Some(Ok(guard)) => Some(guard),
        Some(Err(error)) => {
            if let Some(class_menu) = class_menu_token {
                return match super::class_menu::retire_unattached_class_menu(
                    state, class_menu,
                ) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(error.with_cleanup(
                        "failed to retain class-menu owner through CreateWindowEx",
                        cleanup,
                    )),
                };
            }
            return Err(error);
        }
        None => None,
    };
    let cookie = (!class.system_class).then(|| Box::new(NativeCreateCookie {
        creation,
        window: token,
        class: data.class,
    }));
    let cookie_value = cookie.as_ref().map_or(0, |cookie|
        (&**cookie as *const NativeCreateCookie) as usize);
    let native_parameter = match mdi_client.as_mut() {
        Some(data) => (data as *mut windows_sys::Win32::UI::WindowsAndMessaging::CLIENTCREATESTRUCT)
            .cast::<std::ffi::c_void>() as *const std::ffi::c_void,
        None => cookie_value as *const std::ffi::c_void,
    };
    if cookie.is_some() {
        state.borrow_mut().pending_creations.push(PendingCreation {
            creation,
            window: token,
            data: data.clone(),
            cookie: cookie_value,
        });
    }
    let coordinate = |value: i16| {
        if value == i16::MIN {
            CW_USEDEFAULT
        } else {
            i32::from(value)
        }
    };
    let coordinates = [
        coordinate(data.x),
        coordinate(data.y),
        coordinate(data.width),
        coordinate(data.height),
    ];
    let creation_hook = super::super::win16_window_creation_hook::NativeCreateCallScope::enter(
        state,
        creation,
        token,
        data.class,
        creation_owner.identity(),
        &title,
        coordinates,
        parent,
        menu,
        native_parameter,
        &data,
    );
    let creation_hook = match creation_hook {
        Ok(scope) => scope,
        Err(error) => {
            if cookie.is_some() {
                let pending_index = { state.borrow().pending_creations.iter()
                    .rposition(|pending| pending.window == token) };
                if let Some(index) = pending_index {
                    state.borrow_mut().pending_creations.remove(index);
                }
            }
            drop(menu_owner_guard);
            if let Some(class_menu) = class_menu_token {
                return match super::class_menu::retire_unattached_class_menu(
                    state, class_menu,
                ) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(error.with_cleanup(
                        "retire the class-menu owner after native creation-hook setup failed",
                        cleanup,
                    )),
                };
            }
            return Err(error);
        }
    };
    // SAFETY: Class/title are host-owned UTF-16 buffers. lpParam points only to
    // this worker's cookie or the typed native CLIENTCREATESTRUCT, each alive
    // through all synchronous USER callbacks; no guest pointer crosses. The
    // scoped CBT observer binds the exact HWND before USER can reenter a parent.
    let hwnd = unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::CreateWindowExW(
            data.ex_style,
            class_name.as_ptr(),
            title.as_ptr(),
            data.style,
            coordinates[0],
            coordinates[1],
            coordinates[2],
            coordinates[3],
            parent,
            menu,
            class.instance,
            native_parameter,
        )
    };
    let claimed_hwnd = creation_hook.claimed_hwnd();
    let creation_hook_result = creation_hook.finish(hwnd);
    let native_api_return = if hwnd.is_null() {
        Win16NativeWindowApiReturn::ReturnedNull
    } else {
        Win16NativeWindowApiReturn::ReturnedWindow
    };
    {
        let mut state = state.borrow_mut();
        if cookie.is_some() {
            if let Some(index) = state
            .pending_creations
            .iter()
            .rposition(|pending| pending.window == token)
            {
                state.pending_creations.remove(index);
            }
        }
    }
    drop(menu_owner_guard);
    if hwnd.is_null() {
        let hook_error = creation_hook_result.err();
        if let Some(class_menu) = class_menu_token {
            if let Err(error) = super::class_menu::retire_unattached_class_menu(state, class_menu) {
                super::class_menu::record_retained_owner_failure(state, error);
            }
        }
        remove_window_maps(state, token, claimed_hwnd.unwrap_or(hwnd));
        return match hook_error {
            Some(error) => Err(error),
            None => Ok(Win16HostWindowCreationResult::returned_null()),
        };
    }
    let mut hook_error = creation_hook_result.err();
    if unsafe { IsWindow(hwnd) } == 0 {
        remove_window_maps(state, token, hwnd);
        return Err(hook_error.take().unwrap_or_else(|| RuntimeError::new(
            Kind::HostFailure,
            "CreateWindowExW returned an HWND that was already destroyed during native creation",
        )));
    }
    let queried_owner = super::super::win16_window_identity::native_owner_identity(hwnd);
    let (process_id, thread_id) = queried_owner.unwrap_or_else(|| {
        // The exact synchronous CreateWindowEx call created this live HWND on
        // its invoking thread; bind that caller identity to this token/generation.
        creation_owner.identity()
    });
    let identity = NativeWindowIdentity {
        window: token,
        class: Some(data.class),
        creation: Some(creation),
        process_id,
        thread_id,
        owned: true,
    };
    if !creation_owner.matches(token, creation)
        || queried_owner.is_some_and(|owner| owner != creation_owner.identity())
    {
        let owner_error = RuntimeError::new(Kind::HostFailure,
            "CreateWindowExW returned an HWND with an owner identity inconsistent with its exact creation call; the queried owner record was retained");
        if let Err(cleanup) = retain_created_window_owner(state, hwnd, identity) {
            return Err(hook_error.take().unwrap_or(owner_error).with_cleanup(
                "retain exact native ownership after a CreateWindowEx identity mismatch",
                cleanup,
            ));
        }
        return Err(match hook_error.take() {
            Some(error) => error.with_cleanup(
                "preserve the native creation-hook failure after owner validation also failed",
                owner_error,
            ),
            None => owner_error,
        });
    }
    if state.borrow().aborted {
        retain_created_window_owner(state, hwnd, identity)?;
        destroy_native_quiet(state, token, hwnd)?;
        if let Some(error) = hook_error.take() {
            return Err(error);
        }
        return Ok(Win16HostWindowCreationResult {
            native_api_return,
            preflight_rejection: None,
            live_window: None,
        });
    }
    if let Err(bind_error) = super::super::win16_window_identity::bind(state, token, hwnd) {
        let hook_failed = hook_error.is_some();
        let primary_error = match hook_error.take() {
            Some(error) => error.with_cleanup(
                "bind the exact returned HWND after its creation-time route failed",
                bind_error,
            ),
            None => bind_error,
        };
        if let Err(retention_error) = retain_created_window_owner(state, hwnd, identity) {
            // Retaining cleanup ownership can fail because the HWND already
            // has another identity. Preserve the original binding failure so
            // this secondary failure does not hide the creation boundary.
            return Err(primary_error.with_cleanup(
                "retaining native cleanup ownership after Win16 HWND binding failed",
                retention_error,
            ));
        }
        return match destroy_native_quiet(state, token, hwnd) {
            Ok(()) if hook_failed => Err(primary_error),
            Ok(()) => Ok(Win16HostWindowCreationResult {
                    native_api_return,
                    preflight_rejection: None,
                    live_window: None,
                }),
            Err(cleanup_error) => Err(primary_error.with_cleanup(
                "Win16 HWND identity binding failed and native cleanup remains pending",
                cleanup_error,
            )),
        };
    }
    // Callbacks may replace the creation menu. Publish only the HMENU still
    // attached to this exact HWND after CreateWindowEx returns.
    let attached_menu = super::super::win16_menu_attachment::token_for_native(
        state, unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetMenu(hwnd) },
    );
    {
        let mut state = state.borrow_mut();
        state.windows.insert(token, hwnd);
        state.windows_by_native.insert(
            hwnd as usize,
            identity,
        );
        if let Some(menu) = attached_menu {
            state.window_menus.insert(token, menu);
        }
    }
    super::super::win16_menu_attachment::reconcile_window_menu_ledger(state);
    if let Some(class_menu) = class_menu_token
        && attached_menu != Some(class_menu)
    {
        let Some(native) = state.borrow().menus.get(&class_menu).copied() else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "successful HWND lost its internally materialized class-menu owner"));
        };
        if !super::super::win16_menu_attachment::menu_attached_to_live_window(
            state, class_menu, native,
        )? {
            if let Err(error) = super::class_menu::retire_unattached_class_menu(state, class_menu) {
                super::class_menu::record_retained_owner_failure(state, error);
            }
        }
    }
    if let Some(error) = hook_error.take() {
        return match destroy_native_quiet(state, token, hwnd) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.with_cleanup(
                "destroy the exact returned HWND after its creation-time route failed",
                cleanup,
            )),
        };
    }
    Ok(Win16HostWindowCreationResult {
        native_api_return,
        preflight_rejection: None,
        live_window: Some(token),
    })
}

pub(in crate::windows::win16_windows) fn show_window(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    command: i16,
) -> Option<bool> {
    let hwnd = super::super::win16_window_identity::resolve_user_window(state, token)?;
    // ShowWindow returns previous visibility, not operation success.
    Some(unsafe { ShowWindow(hwnd, i32::from(command)) } != 0)
}

pub(in crate::windows::win16_windows) fn destroy_window_operation(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
) -> (bool, Vec<Win16HostMenu>) {
    let Some(hwnd) = destruction_target(state, token) else {
        return (false, Vec::new());
    };
    let preparation = match window_retirement::prepare_window_retirement(
        state, token, hwnd,
    ) {
        Ok(Some(preparation)) => preparation,
        Ok(None) => return (false, Vec::new()),
        Err(error) => {
            super::super::win16_menu_attachment::latch_retirement_failure(state, error);
            return (false, Vec::new());
        }
    };
    if !preparation.ready {
        let _ = window_retirement::finish_window_retirement(state, preparation.scope, false);
        return (false, Vec::new());
    }
    let destroyed = unsafe { DestroyWindow(hwnd) } != 0;
    let finished = window_retirement::finish_window_retirement(
        state, preparation.scope, destroyed,
    );
    (destroyed, finished.invalidated_menus)
}

pub(in crate::windows::win16_windows) fn destroy_quiet(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
) -> bool {
    let Some(hwnd) = state.borrow().windows.get(&token).copied() else {
        return true;
    };
    let restore_callbacks = state.borrow().callbacks_enabled;
    let prior_failure_count = state.borrow().terminal_failures.len();
    state.borrow_mut().callbacks_enabled = false;
    let result = if super::super::win16_window_identity::resolve(state, token) != Some(hwnd) {
        remove_window_maps(state, token, hwnd);
        true
    } else {
        destroy_window_operation(state, token).0
    };
    let retirement_succeeded = state.borrow().terminal_failures.len() == prior_failure_count;
    if restore_callbacks && retirement_succeeded {
        state.borrow_mut().callbacks_enabled = true;
    }
    result
}

fn destroy_native_quiet(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    hwnd: HWND,
) -> Result<(), RuntimeError> {
    if unsafe { IsWindow(hwnd) } == 0 {
        remove_window_maps(state, token, hwnd);
        return Ok(());
    }
    let identity = retained_created_window_owner(state, token, hwnd).ok_or_else(|| {
        RuntimeError::new(Kind::InternalInvariant,
            "quiet HWND cleanup has no exact retained native owner record")
    })?;
    if !native_owner_record_is_live(state, token, hwnd, identity) {
        return Err(RuntimeError::new(Kind::HostFailure,
            "quiet HWND cleanup could not revalidate its exact native owner; owner record retained"));
    }
    let restore_callbacks = state.borrow().callbacks_enabled;
    let prior_failure_count = state.borrow().terminal_failures.len();
    state.borrow_mut().callbacks_enabled = false;
    let (destroyed, _) = destroy_window_operation(state, token);
    if !destroyed && unsafe { IsWindow(hwnd) } == 0 {
        remove_window_maps(state, token, hwnd);
    } else if !destroyed {
        return Err(RuntimeError::new(Kind::HostFailure,
            "DestroyWindow failed for a retained Win16 HWND owner; ownership remains available for retry"));
    }
    let retirement_succeeded = state.borrow().terminal_failures.len() == prior_failure_count;
    if restore_callbacks && retirement_succeeded && !state.borrow().aborted {
        state.borrow_mut().callbacks_enabled = true;
    }
    if !retirement_succeeded {
        return Err(RuntimeError::new(Kind::HostFailure,
            "native HWND was destroyed but one or more owner sidecars remain pending retirement"));
    }
    Ok(())
}

fn destruction_target(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
) -> Option<HWND> {
    let hwnd = state.borrow().windows.get(&token).copied()?;
    native_window_is_destruction_target(state, token, hwnd).then_some(hwnd)
}

pub(super) fn native_window_is_destruction_target(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    hwnd: HWND,
) -> bool {
    if super::super::win16_window_identity::resolve(state, token) == Some(hwnd) {
        return true;
    }
    retained_created_window_owner(state, token, hwnd)
        .is_some_and(|identity| native_owner_record_is_live(state, token, hwnd, identity))
}

fn retain_created_window_owner(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    identity: NativeWindowIdentity,
) -> Result<(), RuntimeError> {
    let native = hwnd as usize;
    let attached_menu = super::super::win16_menu_attachment::token_for_native(
        state,
        unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetMenu(hwnd) },
    );
    let mut state = state.try_borrow_mut().map_err(|_| RuntimeError::new(
        Kind::InternalInvariant,
        "retain an unpublished Win16 HWND owner without a conflicting worker borrow",
    ))?;
    if state.windows.get(&identity.window).is_some_and(|current| *current != hwnd)
        || state.windows_by_native.get(&native).is_some_and(|current| {
            current.window != identity.window
                || current.process_id != identity.process_id
                || current.thread_id != identity.thread_id
                || current.creation != identity.creation
        })
    {
        return Err(RuntimeError::new(Kind::HostFailure,
            "retain a failed HWND binding without replacing another native owner"));
    }
    state.windows.try_reserve(1).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "retain the unpublished HWND owner for native cleanup", error,
    ))?;
    state.windows_by_native.try_reserve(1).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "retain the HWND's exact native owner identity", error,
    ))?;
    state.windows.insert(identity.window, hwnd);
    state.windows_by_native.insert(native, identity);
    if let Some(menu) = attached_menu {
        state.window_menus.insert(identity.window, menu);
    }
    Ok(())
}

fn retained_created_window_owner(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    hwnd: HWND,
) -> Option<NativeWindowIdentity> {
    let state = state.borrow();
    if state.windows.get(&token).copied() != Some(hwnd) {
        return None;
    }
    state.windows_by_native.get(&(hwnd as usize)).copied().filter(|identity| {
        identity.window == token && identity.owned && identity.class.is_some()
            && identity.creation.is_some()
    })
}

fn native_owner_record_is_live(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    hwnd: HWND,
    identity: NativeWindowIdentity,
) -> bool {
    if retained_created_window_owner(state, token, hwnd).is_none_or(|current| {
        current.window != identity.window
            || current.class != identity.class
            || current.process_id != identity.process_id
            || current.thread_id != identity.thread_id
            || current.creation != identity.creation
            || !current.owned
    }) || super::super::win16_window_identity::native_owner_identity(hwnd)
        != Some((identity.process_id, identity.thread_id))
        || super::super::win16_window_identity::belongs_to_worker(hwnd) != Some(true)
    {
        return false;
    }
    if super::super::win16_window_identity::resolve(state, token) == Some(hwnd) {
        return true;
    }
    let Some(class_token) = identity.class else { return false; };
    native_class_name_matches(state, class_token, hwnd)
}

pub(in crate::windows::win16_windows) fn identify_window(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Option<(
    NativeWindowIdentity,
    Option<Win16HostCreationData>,
    usize,
    Option<Win16CreationId>,
)> {
    let native = hwnd as usize;
    let existing = { state.borrow().windows_by_native.get(&native).copied() };
    let existing = match existing {
        Some(identity)
            if super::super::win16_window_identity::resolve(state, identity.window)
                != Some(hwnd) =>
        {
            remove_window_maps(state, identity.window, hwnd);
            None
        }
        other => other,
    };
    if let Some(identity) = existing {
        let dialog_creation = {
            state.borrow().dialog_creation_data.get(&native)
                .map(|(creation, data)| (*creation, data.clone()))
        };
        if let Some((creation, data)) = dialog_creation {
            return Some((identity, Some(data), 0, Some(creation)));
        }
        let pending = {
            let state = state.borrow();
            state
                .pending_creations
                .iter()
                .rev()
                .find(|pending| pending.window == identity.window)
                .map(|pending| (pending.data.clone(), pending.cookie, pending.creation))
        };
        let (creation_data, cookie, creation) = pending
            .map_or((None, 0, None), |(data, cookie, creation)| {
                (Some(data), cookie, Some(creation))
            });
        return Some((identity, creation_data, cookie, creation));
    }
    // Every CreateWindowEx request is bound by the scoped HCBT_CREATEWND
    // observer before the first class callback. Dialog and MDI routes are
    // handled by their own exact creation frames above this fallback. An
    // unmapped callback HWND must not be assigned to whichever pending create
    // happens to be newest.
    None
}

pub(in crate::windows::win16_windows) fn native_class_name_matches(
    state: &Rc<RefCell<WorkerState>>,
    class_token: Win16HostClass,
    hwnd: HWND,
) -> bool {
    let (class_name, codec) = {
        let Ok(state) = state.try_borrow() else { return false; };
        let Some(class) = state.classes.get(&class_token) else { return false; };
        let Some(class_name) = class.name.strip_suffix(&[0]) else { return false; };
        if class_name.contains(&0) { return false; }
        (class_name.to_vec(), state.text_codec)
    };
    let Ok(expected) = codec.to_wide(&class_name) else { return false; };
    if expected.is_empty() || expected.len() >= i32::MAX as usize {
        return false;
    }
    let mut native = vec![0_u16; expected.len() + 1];
    let copied = unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::GetClassNameW(
            hwnd, native.as_mut_ptr(), native.len() as i32,
        )
    };
    copied > 0
        && copied as usize == expected.len()
        && native[..expected.len()] == expected
}

pub(in crate::windows::win16_windows) fn allocate_callback_id(
    state: &Rc<RefCell<WorkerState>>,
) -> Option<Win16HostCallback> {
    let source = Arc::clone(&state.borrow().identity_source);
    source
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1).filter(|next| *next != 0)
        })
        .ok()
        .map(Win16HostCallback)
}

pub(in crate::windows::win16_windows) fn allocate_window_token(
    state: &Rc<RefCell<WorkerState>>,
)
-> Result<Win16HostWindow, RuntimeError> {
    {
        let mut state = state.try_borrow_mut().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant,
            "reserve a retired Win16 window identity without a conflicting worker borrow",
        ))?;
        let outstanding = state.windows.len()
            .checked_add(state.pending_creations.len())
            .and_then(|count| count.checked_add(state.pending_mdi_creations.len()))
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
                "Win16 retired-window identity capacity is exhausted"))?;
        state.retired_window_tokens.try_reserve(outstanding).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact Win16 window retirement evidence before issuing its token",
                error,
            )
        })?;
    }
    static NEXT_WINDOW_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_WINDOW_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map(Win16HostWindow)
        .map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 native window identity exhausted",
            )
        })
}

/// Resolve a borrowed native HWND to a stable worker identity. This helper is
/// called only on the USER thread; native calls run after all RefCell borrows
/// used to inspect the maps have ended.
pub(in crate::windows::win16_windows) fn token_for_native(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Result<Win16HostWindow, RuntimeError> {
    let window = super::super::win16_window_identity::adopt(state, hwnd)?;
    super::super::win16_window_identity::associate_dialog_child(state, hwnd);
    Ok(window)
}

pub(in crate::windows::win16_windows) fn registered_class_for_native(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Option<Win16HostClass> {
    let class = state
        .borrow()
        .windows_by_native
        .get(&(hwnd as usize))?
        .class?;
    state.borrow().classes.contains_key(&class).then_some(class)
}

pub(in crate::windows::win16_windows) fn adopt_callback_dc(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    raw_hdc: usize,
) -> Result<Option<Win16HostDc>, RuntimeError> {
    let dcs = state.borrow().dcs.clone();
    dcs.adopt_callback_dc(window, raw_hdc)
}

pub(in crate::windows::win16_windows) fn forget_callback_dc(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostDc,
    window: Win16HostWindow,
) -> bool {
    let dcs = state.borrow().dcs.clone();
    dcs.forget_callback_dc(token, window)
}

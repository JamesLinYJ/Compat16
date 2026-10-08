//! Native dialog-family USER calls that execute on the window worker.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCallback, Win16HostDialogAtom,
    Win16HostDialogResult, Win16HostDialogTemplate, Win16HostMessage, Win16HostQueuedMessage,
    Win16HostWindow, Win16HostWindowCreationResult, Win16MessageParam, Win16MessageSource,
    Win16NativeWindowApiReturn, Win16WindowCreationRejection, Win16WindowInputMessage,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateDialogIndirectParamW, DLGPROC, DLGTEMPLATE, DialogBoxIndirectParamW, EndDialog,
    GetDialogBaseUnits, IsDialogMessageW, IsWindow, MSG,
};

use super::win16_window_worker::WorkerState;

static NEXT_DIALOG_ROUTE_COOKIE: AtomicUsize = AtomicUsize::new(1);

#[path = "win16_user_services_dialog_cleanup.rs"]
mod cleanup;
#[path = "win16_user_services_dialog_template.rs"]
mod template;
use cleanup::{
    cleanup_dialog_resources, cleanup_dialog_route, cleanup_menu_after_error, reject_after_menu,
};

pub(super) fn default_procedure(
    state: &Rc<RefCell<WorkerState>>,
    dialog: Win16HostWindow,
    callback: Win16HostCallback,
    message: &Win16HostMessage,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Win16HostDialogResult, RuntimeError> {
    let result = super::win16_window_default::dialog_default_message(
        state,
        dialog,
        Some(callback),
        message.clone(),
        control_color_return,
    )?;
    Ok(Win16HostDialogResult::DefaultResult(result))
}

/// Present a Unicode message box owned by a translated guest window. The native call
/// runs without a RefCell borrow, allowing its modal message pump to reenter
/// the worker's guest-callback continuation.
pub(super) fn message_box(
    state: &Rc<RefCell<WorkerState>>,
    owner: Option<Win16HostWindow>,
    text: Option<&[u8]>,
    caption: Option<&[u8]>,
    style: u16,
) -> Result<Win16HostDialogResult, RuntimeError> {
    let native_owner = {
        let state = state.borrow();
        match owner {
            Some(owner) => match state.windows.get(&owner).copied() {
                Some(hwnd) => Some(hwnd),
                None => return Ok(Win16HostDialogResult::MessageBox(0)),
            },
            None => None,
        }
    };
    let codec = state.borrow().text_codec;
    let result =
        super::super::win16::message_box_with_owner(codec, native_owner, text, caption, style)?;
    Ok(Win16HostDialogResult::MessageBox(result))
}

/// Create a Win32 dialog from the owned, pointer-free Win16 template and use
/// the worker's dedicated DLGPROC trampoline. The template buffer is DWORD
/// aligned and may be released once User32 returns.
pub(super) fn create(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
    creation: runtime::Win16CreationId,
    guest_instance: u16,
    owner: Option<Win16HostWindow>,
    mut template: Win16HostDialogTemplate,
    modal: bool,
    init_parameter: u32,
    dialog_proc: DLGPROC,
) -> Result<Win16HostDialogResult, RuntimeError> {
    let owner_window = match resolve_window(state, owner) {
        Some(owner) => owner,
        None if owner.is_none() => std::ptr::null_mut(),
        None => {
            return Ok(create_failure(
                modal,
                Win16WindowCreationRejection::NativeOwnerUnavailable,
            ));
        }
    };
    let Some(encoded) = template::encode_native_template(state, &template, creation)? else {
        return Ok(create_failure(
            modal,
            Win16WindowCreationRejection::NativeTemplateUnavailable,
        ));
    };
    let menu = match create_template_menu(state, template.menu_template.take())? {
        Ok(menu) => menu,
        Err(()) => {
            return Ok(create_failure(
                modal,
                Win16WindowCreationRejection::NativeMenuUnavailable,
            ));
        }
    };
    let template_base = encoded.words.as_ptr().cast::<u8>() as usize;
    let root_token = match super::win16_window_worker::allocate_window_token(state) {
        Ok(token) => token,
        Err(error) => return Err(cleanup_menu_after_error(state, menu, error)),
    };
    let (root, controls) = match build_creation_routes(
        state,
        &template,
        guest_instance,
        owner,
        menu,
        template_base,
        &encoded.control_offsets,
    ) {
        Ok(Some(routes)) => routes,
        Ok(None) => {
            return reject_after_menu(
                state,
                menu,
                modal,
                Win16WindowCreationRejection::NativeTemplateUnavailable,
            );
        }
        Err(error) => {
            return Err(cleanup_menu_after_error(state, menu, error));
        }
    };
    let creation_is_active = state
        .borrow()
        .pending_dialog_routes
        .iter()
        .any(|route| route.creation == creation);
    if creation_is_active {
        let primary = RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 dialog creation identity is already active",
        );
        return Err(cleanup_menu_after_error(state, menu, primary));
    }
    let cookie = match allocate_dialog_route_cookie() {
        Ok(cookie) => cookie,
        Err(error) => return Err(cleanup_menu_after_error(state, menu, error)),
    };
    // The template is an owned memory block in this process, and custom
    // native classes were registered against this same module instance.
    let native_instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    if native_instance.is_null() {
        let primary = RuntimeError::new(
            Kind::HostFailure,
            "GetModuleHandleW could not identify the dialog-template module",
        );
        return Err(cleanup_menu_after_error(state, menu, primary));
    }
    let route_reservation = state
        .borrow_mut()
        .pending_dialog_routes
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native dialog creation route",
                error,
            )
        });
    if let Err(error) = route_reservation {
        return Err(cleanup_menu_after_error(state, menu, error));
    }
    let Some(identity_count) = controls.len().checked_add(1) else {
        let primary = RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 dialog identity count overflowed",
        );
        return Err(cleanup_menu_after_error(state, menu, primary));
    };
    let identity_reservation = reserve_dialog_identity_storage(state, identity_count);
    if let Err(error) = identity_reservation {
        return Err(cleanup_menu_after_error(state, menu, error));
    }
    {
        let mut worker = state.borrow_mut();
        worker
            .pending_dialog_routes
            .push(super::win16_window_worker::PendingDialogRoute {
                operation,
                creation,
                cookie,
                guest_instance,
                init_parameter,
                root_token,
                owner: owner_window,
                root,
                root_window: None,
                controls,
                menu,
            });
    }
    let template_pointer = encoded.words.as_ptr().cast();
    let native_result = if modal {
        let result = unsafe {
            DialogBoxIndirectParamW(
                native_instance,
                template_pointer,
                owner_window,
                dialog_proc,
                cookie as isize,
            )
        };
        Ok(Win16HostDialogResult::ModalResult(Some(result as i16)))
    } else {
        create_modeless(
            state,
            native_instance,
            template_pointer,
            owner_window,
            cookie,
            root_token,
            dialog_proc,
        )
    };
    let retain_modeless = !modal
        && matches!(
            &native_result,
            Ok(Win16HostDialogResult::Created { creation, .. })
                if creation.live_window == Some(root_token)
        )
        && super::win16_window_identity::resolve(state, root_token)
            .is_some_and(|hwnd| unsafe { IsWindow(hwnd) } != 0);
    let route_pop = pop_creation_route(state, operation, creation);
    let (result, mut failure) = match native_result {
        Ok(result) => (Some(result), None),
        Err(error) => (None, Some(error)),
    };
    let preserve_route = retain_modeless && route_pop.error.is_none() && route_pop.route.is_some();
    let cleanup = match route_pop.route {
        Some(_route) if preserve_route => Ok(()),
        Some(route) => cleanup_dialog_route(state, route),
        None => cleanup_dialog_resources(state, root_token, std::iter::empty(), menu),
    };
    if let Some(route_error) = route_pop.error {
        failure = Some(match failure {
            Some(primary) => combine_dialog_cleanup_failure(
                primary,
                route_error,
                "native dialog returned with an out-of-order creation route",
            ),
            None => route_error,
        });
    }
    if let Some(cleanup) = cleanup.err() {
        failure = Some(match failure {
            Some(primary) => combine_dialog_cleanup_failure(
                primary,
                cleanup,
                "native dialog result could not be fully retired",
            ),
            None => cleanup,
        });
    }
    if let Some(error) = failure {
        Err(error)
    } else {
        result.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "dialog creation lost its successful native result",
            )
        })
    }
}

fn create_modeless(
    state: &Rc<RefCell<WorkerState>>,
    native_instance: windows_sys::Win32::Foundation::HINSTANCE,
    template: *const DLGTEMPLATE,
    owner: HWND,
    cookie: usize,
    root_token: runtime::Win16HostWindow,
    dialog_proc: DLGPROC,
) -> Result<Win16HostDialogResult, RuntimeError> {
    let native = unsafe {
        CreateDialogIndirectParamW(
            native_instance,
            template,
            owner,
            dialog_proc,
            cookie as isize,
        )
    };
    let native_api_return = if native.is_null() {
        Win16NativeWindowApiReturn::ReturnedNull
    } else {
        Win16NativeWindowApiReturn::ReturnedWindow
    };
    if native.is_null() || unsafe { IsWindow(native) } == 0 {
        return Ok(Win16HostDialogResult::Created {
            creation: Win16HostWindowCreationResult {
                native_api_return,
                preflight_rejection: None,
                live_window: None,
            },
            menu: None,
        });
    }
    let token = match super::win16_window_identity::resolve(state, root_token) {
        Some(hwnd) if hwnd == native => root_token,
        _ => {
            // A recycled HWND can remain live after the original dialog was
            // destroyed in WM_INITDIALOG. Without the reserved token's exact
            // USER property, DestroyWindow could hit that unrelated window.
            // The post-return route rollback retires only identities still
            // bound to this creation token.
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "modeless dialog returned an HWND without its reserved identity; recycled HWND cleanup was withheld",
            ));
        }
    };
    let identity = {
        state
            .borrow()
            .windows_by_native
            .get(&(native as usize))
            .copied()
    };
    if let Some(identity) = identity {
        let mut owned = identity;
        owned.owned = true;
        state
            .borrow_mut()
            .windows_by_native
            .insert(native as usize, owned);
    }
    let menu = state.borrow().window_menus.get(&token).copied();
    Ok(Win16HostDialogResult::Created {
        creation: Win16HostWindowCreationResult {
            native_api_return,
            preflight_rejection: None,
            live_window: Some(token),
        },
        menu,
    })
}

fn create_template_menu(
    state: &Rc<RefCell<WorkerState>>,
    template: Option<runtime::Win16MenuTemplate>,
) -> Result<Result<Option<runtime::Win16HostMenu>, ()>, RuntimeError> {
    let Some(template) = template else {
        return Ok(Ok(None));
    };
    let result = super::win16_menu_worker::execute(
        state,
        runtime::Win16MenuOperation::CreateFromTemplate { template },
        &BTreeMap::new(),
    )?;
    match result {
        runtime::Win16MenuResult::Created(Some(menu)) => Ok(Ok(Some(menu))),
        runtime::Win16MenuResult::Created(None) => Ok(Err(())),
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native menu-template operation returned the wrong result variant",
        )),
    }
}

fn reserve_dialog_identity_storage(
    state: &Rc<RefCell<WorkerState>>,
    count: usize,
) -> Result<(), RuntimeError> {
    let mut state = state.borrow_mut();
    state
        .windows_by_native
        .try_reserve(count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve HWND identities for a dialog template",
                error,
            )
        })?;
    state
        .window_identity_cookies
        .try_reserve(count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native identity cookies for a dialog template",
                error,
            )
        })?;
    state
        .dialog_creation_data
        .try_reserve(count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve CREATESTRUCT records for a dialog template",
                error,
            )
        })?;
    state
        .dialog_children_by_native
        .try_reserve(count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve dialog child identity records",
                error,
            )
        })?;
    state
        .dialog_routes_by_native
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve a dialog-procedure route",
                error,
            )
        })?;
    Ok(())
}

fn allocate_dialog_route_cookie() -> Result<usize, RuntimeError> {
    NEXT_DIALOG_ROUTE_COOKIE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1).filter(|value| *value != 0)
        })
        .map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native dialog route cookie identity exhausted",
            )
        })
}

fn build_creation_routes(
    state: &Rc<RefCell<WorkerState>>,
    template: &Win16HostDialogTemplate,
    guest_instance: u16,
    owner: Option<Win16HostWindow>,
    menu: Option<runtime::Win16HostMenu>,
    template_base: usize,
    offsets: &[Option<(usize, usize)>],
) -> Result<
    Option<(
        Option<super::win16_window_worker::DialogRootCreationRoute>,
        Vec<super::win16_window_worker::DialogControlCreationRoute>,
    )>,
    RuntimeError,
> {
    if offsets.len() != template.items.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "dialog control route offsets do not match the parsed template",
        ));
    }
    let root = match &template.class {
        Win16HostDialogAtom::GuestClass(class) => {
            let Some(guest_class_name) = template.guest_class_name.as_ref() else {
                return Ok(None);
            };
            Some(super::win16_window_worker::DialogRootCreationRoute {
                data: runtime::Win16HostCreationData {
                    class: *class,
                    guest_instance,
                    guest_class_name: copy_class_name(guest_class_name)?,
                    guest_menu: dialog_menu_word(&template.menu),
                    class_menu_template: None,
                    // lpParamInit belongs to WM_INITDIALOG. It is neither a
                    // Win16 CREATESTRUCT16 parameter nor the host-only dialog
                    // route cookie used to match that later callback.
                    create_parameter: 0,
                    creation_data: None,
                    mdi_client: None,
                    dialog_root: true,
                    menu,
                    title: copy_dialog_title(&template.title)?,
                    style: template.style,
                    ex_style: 0,
                    x: template.x,
                    y: template.y,
                    width: template.width,
                    height: template.height,
                    parent: owner,
                    child_id: None,
                },
            })
        }
        _ => None,
    };
    let mut controls = Vec::new();
    controls
        .try_reserve_exact(template.items.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve custom dialog control routes",
                error,
            )
        })?;
    for (index, item) in template.items.iter().enumerate() {
        let Win16HostDialogAtom::GuestClass(class) = &item.class else {
            continue;
        };
        let Some(guest_class_name) = item.guest_class_name.as_ref() else {
            return Ok(None);
        };
        let Some((size_offset, data_offset)) = offsets[index] else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "custom dialog control has no encoded route cookie",
            ));
        };
        let (Some(size_pointer), Some(data_pointer)) = (
            template_base.checked_add(size_offset),
            template_base.checked_add(data_offset),
        ) else {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "native dialog template address overflowed its control route",
            ));
        };
        let creation_data = if item.creation_data.is_empty() {
            None
        } else {
            Some(copy_host_bytes(
                &item.creation_data,
                "dialog control creation data",
            )?)
        };
        let window_token = super::win16_window_worker::allocate_window_token(state)?;
        controls.push(super::win16_window_worker::DialogControlCreationRoute {
            size_pointer,
            data_pointer,
            window_token,
            data: runtime::Win16HostCreationData {
                class: *class,
                guest_instance,
                guest_class_name: copy_class_name(guest_class_name)?,
                guest_menu: item.id,
                class_menu_template: None,
                create_parameter: 0,
                creation_data,
                mdi_client: None,
                dialog_root: false,
                menu: None,
                title: copy_dialog_title(&item.title)?,
                style: item.style,
                ex_style: 0,
                x: item.x,
                y: item.y,
                width: item.width,
                height: item.height,
                parent: None,
                child_id: Some(item.id),
            },
        });
    }
    Ok(Some((root, controls)))
}

fn copy_class_name(
    name: &runtime::Win16HostClassName,
) -> Result<runtime::Win16HostClassName, RuntimeError> {
    match name {
        runtime::Win16HostClassName::Atom(atom) => Ok(runtime::Win16HostClassName::Atom(*atom)),
        runtime::Win16HostClassName::Name(bytes) => Ok(runtime::Win16HostClassName::Name(
            copy_host_bytes(bytes, "guest dialog class identity")?,
        )),
    }
}

fn copy_dialog_title(title: &Win16HostDialogAtom) -> Result<Option<Vec<u8>>, RuntimeError> {
    match title {
        Win16HostDialogAtom::String(bytes) => {
            Ok(Some(copy_host_bytes(bytes, "guest dialog title")?))
        }
        Win16HostDialogAtom::None
        | Win16HostDialogAtom::Ordinal(_)
        | Win16HostDialogAtom::GuestClass(_) => Ok(None),
    }
}

fn dialog_menu_word(menu: &Win16HostDialogAtom) -> u16 {
    match menu {
        Win16HostDialogAtom::Ordinal(id) => *id,
        _ => 0,
    }
}

struct DialogRoutePop {
    route: Option<super::win16_window_worker::PendingDialogRoute>,
    error: Option<RuntimeError>,
}

fn pop_creation_route(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
    creation: runtime::Win16CreationId,
) -> DialogRoutePop {
    let mut state = state.borrow_mut();
    let Some(index) = state
        .pending_dialog_routes
        .iter()
        .rposition(|route| route.operation == operation && route.creation == creation)
    else {
        return DialogRoutePop {
            route: None,
            error: Some(RuntimeError::new(
                Kind::InternalInvariant,
                "native dialog creation route disappeared before return",
            )),
        };
    };
    let returned_out_of_order = index + 1 != state.pending_dialog_routes.len();
    let route = state.pending_dialog_routes.remove(index);
    DialogRoutePop {
        route: Some(route),
        error: returned_out_of_order.then(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "native dialog creation routes returned out of stack order",
            )
        }),
    }
}

#[derive(Debug)]
pub(super) struct DialogCreationCleanupFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl DialogCreationCleanupFailure {
    pub(super) fn causes(&self) -> (&RuntimeError, &RuntimeError) {
        (&self.primary, &self.cleanup)
    }
}

pub(super) fn combine_dialog_cleanup_failure(
    primary: RuntimeError,
    cleanup: RuntimeError,
    message: &'static str,
) -> RuntimeError {
    // Host cannot call runtime's crate-private with_cleanup helper. Preserve
    // both typed causes here, and keep any internal invariant critical even
    // when another host cleanup failure is also present.
    let kind = match (primary.kind(), cleanup.kind()) {
        (Kind::InternalInvariant, _) | (_, Kind::InternalInvariant) => Kind::InternalInvariant,
        (Kind::ExecutionLimit, additional) => additional,
        (primary, _) => primary,
    };
    RuntimeError::with_source(
        kind,
        message,
        DialogCreationCleanupFailure { primary, cleanup },
    )
}

impl std::fmt::Display for DialogCreationCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (primary, cleanup) = self.causes();
        write!(
            formatter,
            "{}; dialog route cleanup failed: {}",
            primary, cleanup
        )
    }
}

impl std::error::Error for DialogCreationCleanupFailure {
    // Error::source has one edge; callers that downcast the composite retain
    // access to both typed failures through causes().
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

pub(super) fn end(
    state: &Rc<RefCell<WorkerState>>,
    dialog: Win16HostWindow,
    result: i16,
) -> Win16HostDialogResult {
    let succeeded = resolve_window(state, Some(dialog))
        .is_some_and(|dialog| unsafe { EndDialog(dialog, isize::from(result)) != 0 });
    Win16HostDialogResult::Ended(succeeded)
}

/// Convert a checked guest MSG16 into a temporary native MSG. HWND-bearing
/// LPARAM families are accepted only as typed identities; guest FAR values
/// are never cast to host pointers here.
pub(super) fn is_message(
    state: &Rc<RefCell<WorkerState>>,
    dialog: Win16HostWindow,
    message: Win16HostQueuedMessage,
) -> Result<Win16HostDialogResult, RuntimeError> {
    if message.source != Win16MessageSource::GuestMessage {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "IsDialogMessage received a native-queue message payload",
        ));
    }
    validate_window_input_tag(message)?;
    let Some(dialog) = resolve_window(state, Some(dialog)) else {
        return Ok(Win16HostDialogResult::MessageHandled(false));
    };
    let window = match resolve_window(state, message.window) {
        Some(window) => window,
        None if message.window.is_none() => std::ptr::null_mut(),
        None => return Ok(Win16HostDialogResult::MessageHandled(false)),
    };
    let (native_message, w_param, l_param) = match message.l_param {
        Win16MessageParam::WindowInput(input) => {
            let Some((native_message, native_w, native_l)) =
                super::win16_window_input::encode_window_input(state, input)?
            else {
                return Ok(Win16HostDialogResult::MessageHandled(false));
            };
            if native_message != u32::from(message.message) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "window-input conversion changed the native message identifier",
                ));
            }
            (native_message, native_w, native_l)
        }
        Win16MessageParam::Scalar(value)
            if runtime::Win16ScalarMessage::from_raw(message.message).is_some() =>
        {
            (
                u32::from(message.message),
                usize::from(message.w_param),
                (value as i32) as isize,
            )
        }
        Win16MessageParam::Command {
            control, notify, ..
        } if message.message == 0x0111 => {
            let control = match resolve_window(state, control) {
                Some(control) => control,
                None if control.is_none() => std::ptr::null_mut(),
                None => return Ok(Win16HostDialogResult::MessageHandled(false)),
            };
            (
                u32::from(message.message),
                usize::from(message.w_param) | (usize::from(notify) << 16),
                control as isize,
            )
        }
        Win16MessageParam::GuestBits(value) if message.message >= 0x0400 => (
            u32::from(message.message),
            usize::from(message.w_param),
            (value as i32) as isize,
        ),
        _ => return Ok(Win16HostDialogResult::MessageHandled(false)),
    };
    let mut native = MSG {
        hwnd: window,
        message: native_message,
        wParam: w_param as WPARAM,
        lParam: l_param as LPARAM,
        time: message.time,
        pt: POINT {
            x: message.point.x,
            y: message.point.y,
        },
    };
    Ok(Win16HostDialogResult::MessageHandled(unsafe {
        IsDialogMessageW(dialog, &mut native) != 0
    }))
}

fn validate_window_input_tag(message: Win16HostQueuedMessage) -> Result<(), RuntimeError> {
    if let Win16MessageParam::WindowInput(input) = message.l_param {
        if !Win16WindowInputMessage::accepts(message.message)
            || input.message_id() != message.message
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "typed window-input payload was used for a different message",
            ));
        }
    }
    Ok(())
}

pub(super) fn base_units() -> Win16HostDialogResult {
    Win16HostDialogResult::BaseUnits(unsafe { GetDialogBaseUnits() as u32 })
}

fn resolve_window(
    state: &Rc<RefCell<WorkerState>>,
    window: Option<Win16HostWindow>,
) -> Option<HWND> {
    let token = window?;
    let hwnd = super::win16_window_identity::resolve_user_window(state, token)?;
    (unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) } != 0).then_some(hwnd)
}

fn create_failure(modal: bool, rejection: Win16WindowCreationRejection) -> Win16HostDialogResult {
    if modal {
        Win16HostDialogResult::ModalResult(Some(-1))
    } else {
        Win16HostDialogResult::Created {
            creation: Win16HostWindowCreationResult::not_invoked(rejection),
            menu: None,
        }
    }
}

fn copy_host_bytes(bytes: &[u8], what: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, format!("allocate {what}"), error)
    })?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

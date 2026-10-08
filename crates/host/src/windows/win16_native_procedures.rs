//! Retained, window-bound native WNDPROC identities for Win16 CallWindowProc.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMessage, Win16HostMessageResult,
    Win16HostProcedure, Win16HostStaticIconOperation, Win16HostStaticIconResult, Win16HostWindow,
};
use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE, HWND, SetLastError};
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GetModuleHandleExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GWLP_WNDPROC, GetWindowLongPtrW};

use super::win16_window_default;
use super::win16_window_identity::{self, WindowCookieBinding};
use super::win16_window_worker::WorkerState;

/// Procedure entries and provider module references live until the USER worker
/// state is dropped. A retired HWND leaves a tombstone entry so a recycled
/// HWND value cannot make a saved Win16 procedure token valid again.
#[derive(Default)]
pub(super) struct NativeProcedures {
    next_token: u64,
    by_key: HashMap<ProcedureKey, Win16HostProcedure>,
    entries: HashMap<Win16HostProcedure, ProcedureEntry>,
    class_entries: HashMap<Win16HostProcedure, SystemProcedureEntry>,
    class_by_kind: HashMap<runtime::Win16HostSystemClass, Win16HostProcedure>,
    bases: HashMap<Win16HostWindow, NativeBaseBinding>,
}

struct SystemProcedureEntry {
    kind: runtime::Win16HostSystemClass,
    native_procedure: isize,
    provider_procedure: isize,
    class_extra: i32,
    window_extra: i32,
    _module: ModuleLease,
}

#[derive(Clone, Copy)]
struct NativeBaseBinding {
    procedure: Win16HostProcedure,
    hwnd: usize,
    cookie: usize,
    destroy_entered: bool,
}

pub(super) fn capture_system_class(
    state: &Rc<RefCell<WorkerState>>,
    kind: runtime::Win16HostSystemClass,
    unicode: &windows_sys::Win32::UI::WindowsAndMessaging::WNDCLASSEXW,
) -> Result<Option<Win16HostProcedure>, RuntimeError> {
    let Some(provider_proc) = unicode.lpfnWndProc else {
        return Ok(None);
    };
    let native_procedure = provider_proc as usize as isize;
    let provider_procedure = provider_proc as usize as isize;
    let existing = {
        let state = state.borrow();
        state
            .native_procedures
            .class_by_kind
            .get(&kind)
            .and_then(|token| {
                state
                    .native_procedures
                    .class_entries
                    .get(token)
                    .filter(|entry| {
                        entry.native_procedure == native_procedure
                            && entry.provider_procedure == provider_procedure
                            && entry.class_extra == unicode.cbClsExtra
                            && entry.window_extra == unicode.cbWndExtra
                    })
                    .map(|_| *token)
            })
    };
    if existing.is_some() {
        return Ok(existing);
    }
    let Some(module) = pin_provider(provider_procedure) else {
        return Ok(None);
    };
    let mut state = state.borrow_mut();
    let Some(token) = state.native_procedures.allocate_token() else {
        drop(state);
        drop(module);
        return Ok(None);
    };
    state.native_procedures.class_entries.insert(
        token,
        SystemProcedureEntry {
            kind,
            native_procedure,
            provider_procedure,
            class_extra: unicode.cbClsExtra,
            window_extra: unicode.cbWndExtra,
            _module: module,
        },
    );
    state.native_procedures.class_by_kind.insert(kind, token);
    Ok(Some(token))
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProcedureKey {
    window: Win16HostWindow,
    hwnd: usize,
    cookie: usize,
    native_procedure: isize,
    provider_procedure: isize,
}

struct ProcedureEntry {
    key: ProcedureKey,
    _module: ModuleLease,
}

/// A successful FROM_ADDRESS lookup increments the provider module's loader
/// reference count; one FreeLibrary balances that retained reference.
struct ModuleLease(HMODULE);

impl Drop for ModuleLease {
    fn drop(&mut self) {
        // SAFETY: This handle is exactly the reference acquired by
        // GetModuleHandleExW(FROM_ADDRESS) and is released once by this RAII
        // owner, on the worker thread when the registry is dropped.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

impl NativeProcedures {
    fn allocate_token(&mut self) -> Option<Win16HostProcedure> {
        let token_value = self.next_token.checked_add(1)?;
        self.next_token = token_value;
        Some(Win16HostProcedure(token_value))
    }
}

/// Capture the current native procedure of a live same-worker-thread window.
/// Guest-owned HWNDs are registered as Unicode classes. Capture their W
/// procedure with the W getter and return it only through CallWindowProcW.
pub(super) fn query(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
) -> Result<Option<Win16HostProcedure>, RuntimeError> {
    let Some(hwnd) = win16_window_identity::resolve(state, window) else {
        return Ok(None);
    };
    let Some(identity) = identity_for(state, window, hwnd) else {
        return Ok(None);
    };

    // SAFETY: resolve() established a live HWND on this worker thread, and
    // neither call dispatches a message or enters guest code.
    let Some(native_procedure) = get_window_procedure(hwnd) else {
        return Ok(None);
    };
    if native_procedure == 0 {
        return Ok(None);
    }
    let provider_procedure = native_procedure;

    let key = ProcedureKey {
        window,
        hwnd: identity.hwnd,
        cookie: identity.value,
        native_procedure,
        provider_procedure,
    };

    // A prior exact capture is itself a strong provider-lifetime anchor. It
    // remains in the registry even if its window has since been destroyed.
    let existing = { state.borrow().native_procedures.by_key.get(&key).copied() };
    if let Some(token) = existing {
        return if identity_is_live(state, window, identity) {
            Ok(Some(token))
        } else {
            Ok(None)
        };
    }

    let Some(module) = pin_provider(provider_procedure) else {
        // A heap-generated or otherwise unowned procedure has no module lease
        // in this registry. Do not publish a token that can outlive its code.
        return Ok(None);
    };
    if !identity_is_live(state, window, identity) {
        drop(module);
        return Ok(None);
    }

    let mut state = state.borrow_mut();
    if let Some(token) = state.native_procedures.by_key.get(&key).copied() {
        // FreeLibrary is a native call, so release the state borrow before
        // dropping a redundant pin acquired above.
        drop(state);
        drop(module);
        return Ok(Some(token));
    }
    let Some(token) = state.native_procedures.allocate_token() else {
        drop(state);
        drop(module);
        return Ok(None);
    };
    state.native_procedures.by_key.insert(key, token);
    state.native_procedures.entries.insert(
        token,
        ProcedureEntry {
            key,
            _module: module,
        },
    );
    Ok(Some(token))
}

/// Call a previously captured procedure only on the exact HWND incarnation
/// from which it was queried. Native HWND pointers never leave this module.
pub(super) fn call(
    state: &Rc<RefCell<WorkerState>>,
    procedure: Win16HostProcedure,
    window: Win16HostWindow,
    callback: Option<runtime::Win16HostCallback>,
    message: Win16HostMessage,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    if !prepare_class_call(state, procedure, window, callback, &message)? {
        return Ok(None);
    }
    let Some((key, _hwnd)) = resolve_call_target(state, procedure, window)? else {
        return Ok(None);
    };

    // This value may be an internal USER thunk and is not directly callable.
    // CallWindowProcW alone interprets it as a Unicode window procedure.
    if key.native_procedure == 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "retained native procedure token contains a null WNDPROC",
        ));
    }
    let nc_destroy = matches!(
        &message,
        Win16HostMessage::Scalar {
            kind: runtime::Win16ScalarMessage::NcDestroy,
            ..
        }
    );
    if nc_destroy && let Some(binding) = state.borrow_mut().native_procedures.bases.get_mut(&window)
    {
        if binding.destroy_entered {
            return Ok(Some(Win16HostMessageResult {
                value: 0,
                output: runtime::Win16HostMessageOutput::None,
                dialog_result: None,
            }));
        }
        binding.destroy_entered = true;
    }
    let result = win16_window_default::procedure_message(
        state,
        window,
        callback,
        procedure,
        key.native_procedure,
        message,
        control_color_return,
    );
    // NcDestroy is scalar: a successful call has no post-call conversion that
    // could fail after the base released its state. Undo only a rejected call.
    if nc_destroy
        && !matches!(&result, Ok(Some(_)))
        && let Some(binding) = state.borrow_mut().native_procedures.bases.get_mut(&window)
    {
        binding.destroy_entered = false;
    }
    result
}

/// Call a captured native procedure with the native static-control icon
/// messages. The shared target resolver preserves the same retained module,
/// HWND, and cookie checks as `call` before the opaque procedure is invoked.
pub(super) fn call_static_icon(
    state: &Rc<RefCell<WorkerState>>,
    procedure: Win16HostProcedure,
    window: Win16HostWindow,
    operation: Win16HostStaticIconOperation,
) -> Result<Win16HostStaticIconResult, RuntimeError> {
    let family = state
        .borrow()
        .native_procedures
        .class_entries
        .get(&procedure)
        .map(|entry| entry.kind);
    if let Some(family) = family {
        if family != runtime::Win16HostSystemClass::Static
            || !prepare_class_call(
                state,
                procedure,
                window,
                None,
                &Win16HostMessage::Scalar {
                    kind: runtime::Win16ScalarMessage::Null,
                    w_param: 0,
                    l_param: 0,
                },
            )?
        {
            return Ok(Win16HostStaticIconResult::Untranslated);
        }
    }
    let Some((key, _hwnd)) = resolve_call_target(state, procedure, window)? else {
        return Ok(Win16HostStaticIconResult::Icon(None));
    };
    if key.native_procedure == 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "retained native procedure token contains a null WNDPROC",
        ));
    }
    super::win16_static_controls::icon(state, window, Some(key.native_procedure), operation)
}

/// Resolve a procedure token only while its exact captured window identity is
/// live. The retained entry also anchors the provider module for this call.
fn resolve_call_target(
    state: &Rc<RefCell<WorkerState>>,
    procedure: Win16HostProcedure,
    window: Win16HostWindow,
) -> Result<Option<(ProcedureKey, HWND)>, RuntimeError> {
    let class_proc = state
        .borrow()
        .native_procedures
        .class_entries
        .get(&procedure)
        .map(|entry| (entry.native_procedure, entry.provider_procedure));
    if let Some((native_procedure, provider_procedure)) = class_proc {
        let Some(hwnd) = win16_window_identity::resolve(state, window) else {
            return Ok(None);
        };
        let Some(identity) = identity_for(state, window, hwnd) else {
            return Ok(None);
        };
        return Ok(Some((
            ProcedureKey {
                window,
                hwnd: identity.hwnd,
                cookie: identity.value,
                native_procedure,
                provider_procedure,
            },
            hwnd,
        )));
    }
    let key = state
        .borrow()
        .native_procedures
        .entries
        .get(&procedure)
        .map(|entry| entry.key)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 CallWindowProc refers to an unknown native procedure token",
            )
        })?;
    if key.window != window {
        return Ok(None);
    }
    let Some(hwnd) = win16_window_identity::resolve(state, window) else {
        return Ok(None);
    };
    let identity = WindowCookieBinding {
        hwnd: hwnd as usize,
        value: key.cookie,
    };
    if key.hwnd != hwnd as usize || !identity_is_live(state, window, identity) {
        return Ok(None);
    }
    Ok(Some((key, hwnd)))
}

fn prepare_class_call(
    state: &Rc<RefCell<WorkerState>>,
    procedure: Win16HostProcedure,
    window: Win16HostWindow,
    callback: Option<runtime::Win16HostCallback>,
    message: &Win16HostMessage,
) -> Result<bool, RuntimeError> {
    let class = state
        .borrow()
        .native_procedures
        .class_entries
        .get(&procedure)
        .map(|entry| (entry.kind, entry.class_extra, entry.window_extra));
    let Some((kind, class_extra, window_extra)) = class else {
        return Ok(true);
    };
    let Some(hwnd) = win16_window_identity::resolve(state, window) else {
        return Ok(false);
    };
    let Some(identity) = identity_for(state, window, hwnd) else {
        return Ok(false);
    };
    let native_class = {
        let state = state.borrow();
        state
            .windows_by_native
            .get(&(hwnd as usize))
            .and_then(|identity| {
                identity
                    .class
                    .and_then(|class| state.classes.get(&class).cloned())
            })
    };
    if let Some(class) = native_class.filter(|class| !class.system_class) {
        let Some((reserved_class, reserved_window)) = class.native_extras else {
            return Ok(false);
        };
        if reserved_class < class_extra || reserved_window < window_extra {
            return Ok(false);
        }
        let existing = state.borrow().native_procedures.bases.get(&window).copied();
        if let Some(binding) = existing {
            return Ok(binding.procedure == procedure
                && binding.hwnd == identity.hwnd
                && binding.cookie == identity.value);
        }
        if !matches!(
            message,
            Win16HostMessage::Creation {
                non_client: true,
                ..
            }
        ) {
            return Ok(false);
        }
        // First binding must come from USER's actual creation callback.
        // Merely sending an application-defined NCCREATE to a live window
        // cannot initialize native control storage a second time.
        return Ok(callback.is_some_and(|callback| {
            state.borrow().live_callbacks.iter().any(|frame| {
                frame.callback == callback
                    && frame.hwnd == hwnd
                    && frame.message
                        == Some(windows_sys::Win32::UI::WindowsAndMessaging::WM_NCCREATE)
                    && frame.creation.is_some()
                    && frame
                        .identity
                        .is_some_and(|identity| identity.window == window)
            })
        }));
    }
    // Existing real native controls already initialized their own base state.
    // Confirm their actual system family before accepting a class procedure.
    let mut name = [0_u16; 64];
    // SAFETY: resolve established a live HWND; this bounded UTF-16 buffer is writable.
    let count = unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::GetClassNameW(
            hwnd,
            name.as_mut_ptr(),
            name.len() as i32,
        )
    };
    let expected = super::win16_system_classes::name(kind);
    let expected = expected[..expected.len() - 1]
        .iter()
        .map(|byte| u16::from(*byte))
        .collect::<Vec<_>>();
    Ok(count > 0
        && name[..count as usize].len() == expected.len()
        && name[..count as usize]
            .iter()
            .zip(&expected)
            .all(|(actual, expected)| ascii_upper_wide(*actual) == ascii_upper_wide(*expected)))
}

fn ascii_upper_wide(value: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&value) {
        value - u16::from(b'a' - b'A')
    } else {
        value
    }
}

/// Publish only after creation arguments have been validated and rebuilt.
/// The caller invokes USER immediately afterwards, so reentry can observe the
/// binding without retaining one for a rejected, never-entered native call.
pub(super) fn enter_creation(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    procedure: Win16HostProcedure,
) -> bool {
    if !state
        .borrow()
        .native_procedures
        .class_entries
        .contains_key(&procedure)
    {
        return true;
    }
    let Some(window) = state
        .borrow()
        .windows_by_native
        .get(&(hwnd as usize))
        .map(|identity| identity.window)
    else {
        return false;
    };
    if win16_window_identity::resolve(state, window) != Some(hwnd) {
        return false;
    }
    let Some(identity) = identity_for(state, window, hwnd) else {
        return false;
    };
    let mut state = state.borrow_mut();
    if let Some(binding) = state.native_procedures.bases.get(&window) {
        return binding.procedure == procedure
            && binding.hwnd == identity.hwnd
            && binding.cookie == identity.value
            && !binding.destroy_entered;
    }
    // Family provenance is explicit, never inferred from a guest class name.
    state.native_procedures.bases.insert(
        window,
        NativeBaseBinding {
            procedure,
            hwnd: identity.hwnd,
            cookie: identity.value,
            destroy_entered: false,
        },
    );
    true
}

/// Native-only fallback after guest callbacks are disabled or a message has
/// no Win16 representation. A superclass retains cleanup for its exact HWND
/// incarnation; its provider module remains pinned by the class entry.
pub(super) fn base_fallback(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> Option<isize> {
    let window = state
        .borrow()
        .windows_by_native
        .get(&(hwnd as usize))?
        .window;
    if win16_window_identity::resolve(state, window) != Some(hwnd) {
        return None;
    }
    let identity = identity_for(state, window, hwnd)?;
    let (binding, procedure) = {
        let state = state.borrow();
        let binding = *state.native_procedures.bases.get(&window)?;
        let entry = state
            .native_procedures
            .class_entries
            .get(&binding.procedure)?;
        (binding, entry.native_procedure)
    };
    if binding.hwnd != identity.hwnd || binding.cookie != identity.value {
        return None;
    }
    if binding.destroy_entered {
        return Some(0);
    }
    if message == windows_sys::Win32::UI::WindowsAndMessaging::WM_NCDESTROY {
        state
            .borrow_mut()
            .native_procedures
            .bases
            .get_mut(&window)?
            .destroy_entered = true;
    }
    // SAFETY: USER supplied native message parameters; the native provider is
    // retained and capacity was checked before its first NCCREATE invocation.
    Some(unsafe {
        win16_window_default::call_window_proc_w_opaque(procedure, hwnd, message, w_param, l_param)
    })
}

pub(super) fn retire_base(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow) {
    state.borrow_mut().native_procedures.bases.remove(&window);
}

/// Family provenance for a private superclass, checked against its live
/// cookie. A class name supplied by guest code never establishes this fact.
pub(super) fn bound_family(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Option<runtime::Win16HostSystemClass> {
    let window = state
        .borrow()
        .windows_by_native
        .get(&(hwnd as usize))?
        .window;
    if win16_window_identity::resolve(state, window) != Some(hwnd) {
        return None;
    }
    let identity = identity_for(state, window, hwnd)?;
    let state = state.borrow();
    let binding = state.native_procedures.bases.get(&window)?;
    if binding.hwnd != identity.hwnd || binding.cookie != identity.value || binding.destroy_entered
    {
        return None;
    }
    state
        .native_procedures
        .class_entries
        .get(&binding.procedure)
        .map(|entry| entry.kind)
}

pub(super) fn control_procedure_family(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    procedure: Win16HostProcedure,
) -> Result<Option<runtime::Win16HostSystemClass>, RuntimeError> {
    let Some((_, hwnd)) = resolve_call_target(state, procedure, window)? else {
        return Ok(None);
    };
    let kind = state
        .borrow()
        .native_procedures
        .class_entries
        .get(&procedure)
        .map(|entry| entry.kind);
    if let Some(kind) = kind {
        if bound_family(state, hwnd) != Some(kind) {
            return Ok(None);
        }
        if !prepare_class_call(
            state,
            procedure,
            window,
            None,
            &Win16HostMessage::Scalar {
                kind: runtime::Win16ScalarMessage::Null,
                w_param: 0,
                l_param: 0,
            },
        )? {
            return Ok(None);
        }
        return Ok(Some(kind));
    }
    Ok(bound_family(state, hwnd))
}

/// Unsized GETTEXT may only enter the actual built-in procedure. A captured
/// subclass/custom procedure can run guest callbacks and change item length
/// between probing and copying, so it cannot use native's unsized contract.
pub(super) fn is_builtin_control_target(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    dispatch: runtime::Win16HostControlDispatch,
    kind: runtime::Win16HostSystemClass,
) -> Result<bool, RuntimeError> {
    let Some(template) = super::win16_system_classes::native_template(kind) else {
        return Ok(false);
    };
    let Some(expected) = template.lpfnWndProc.map(|proc| proc as usize as isize) else {
        return Ok(false);
    };
    let address = match dispatch {
        runtime::Win16HostControlDispatch::CallWindowProc { procedure } => {
            let Some((key, _)) = resolve_call_target(state, procedure, window)? else {
                return Ok(false);
            };
            key.native_procedure
        }
        runtime::Win16HostControlDispatch::Send => {
            let Some(hwnd) = win16_window_identity::resolve(state, window) else {
                return Ok(false);
            };
            let Some(address) = get_window_procedure(hwnd) else {
                return Ok(false);
            };
            address
        }
    };
    Ok(address == expected)
}

fn identity_for(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
) -> Option<WindowCookieBinding> {
    let binding = state
        .borrow()
        .window_identity_cookies
        .get(&window)
        .copied()?;
    (binding.hwnd == hwnd as usize && binding.value != 0).then_some(binding)
}

fn identity_is_live(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    expected: WindowCookieBinding,
) -> bool {
    let Some(hwnd) = win16_window_identity::resolve(state, window) else {
        return false;
    };
    if hwnd as usize != expected.hwnd {
        return false;
    }
    state
        .borrow()
        .window_identity_cookies
        .get(&window)
        .is_some_and(|actual| actual.hwnd == expected.hwnd && actual.value == expected.value)
}

fn get_window_procedure(hwnd: HWND) -> Option<isize> {
    // A zero result can be valid for several GetWindowLong indexes. Clear and
    // inspect last error so this helper preserves the documented distinction.
    // GWLP_WNDPROC is never callable when null, so even successful zero maps
    // to unsupported/no native procedure rather than a fabricated callback.
    // SAFETY: hwnd is live on the worker thread and GWLP_WNDPROC is the index.
    unsafe {
        SetLastError(0);
        let value = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
        // x86 uses the GetWindowLongW i32 alias; widen only to this
        // host's pointer-sized integer, never to a guest procedure value.
        if value == 0 && GetLastError() != 0 {
            None
        } else {
            Some(value as isize)
        }
    }
}

fn pin_provider(address: isize) -> Option<ModuleLease> {
    if address == 0 {
        return None;
    }
    let mut module = std::ptr::null_mut();
    // SAFETY: FROM_ADDRESS interprets lpModuleName as a code address. The
    // matching GetWindowLongPtr getter supplied that address; successful
    // calls increment the provider's loader reference count.
    let pinned = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            address as *const u16,
            &mut module,
        )
    };
    if pinned != 0 && !module.is_null() {
        Some(ModuleLease(module))
    } else {
        None
    }
}

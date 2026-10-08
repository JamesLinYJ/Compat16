//! Type-safe icon-message bridging for native STATIC controls.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError,
    Win16HostStaticIconOperation, Win16HostStaticIconResult, Win16HostWindow,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetClassNameW, GetWindowLongPtrW, HICON, SendMessageW, GWL_STYLE, STM_GETICON, STM_SETICON,
};

use super::super::win16_images::Win16Images;
use super::win16_window_worker::WorkerState;

const STATIC_CLASS: &[u16] = &[b'S' as u16, b'T' as u16, b'A' as u16, b'T' as u16,
    b'I' as u16, b'C' as u16];
// windows-sys 0.61.2 Win32::System::SystemServices::SS_TYPEMASK is 0x1f;
// that optional feature is not enabled by this host crate.
const STATIC_TYPE_MASK: u32 = 0x001f;
// Windows 3.1 SDK WINDOWS.H, line 4448: SS_ICON = 0x00000003.
const STATIC_ICON_STYLE: u32 = 0x0003;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeStaticControlKind {
    Icon,
    Other,
}

/// Get or set the icon on a mapped native STATIC control with SS_ICON style.
///
/// `procedure` is an opaque native WNDPROC value captured for this exact
/// window, or `None` to use SendMessageW. HICON values cross only the native
/// call boundary and the host-private image table; callers receive opaque
/// Win16HostIcon tokens.
pub(super) fn icon(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    procedure: Option<isize>,
    operation: Win16HostStaticIconOperation,
) -> Result<Win16HostStaticIconResult, RuntimeError> {
    let Some(mapped_hwnd) = mapped_window_identity(state, window)? else {
        return Ok(Win16HostStaticIconResult::Icon(None));
    };
    let Some(hwnd) = super::win16_window_identity::resolve_user_window(state, window) else {
        return Ok(Win16HostStaticIconResult::Icon(None));
    };
    if hwnd != mapped_hwnd {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 static icon window mapping changed during identity resolution"));
    }

    match native_static_control_kind(state, hwnd) {
        None => return Ok(Win16HostStaticIconResult::Untranslated),
        Some(NativeStaticControlKind::Other) => {
            return Ok(Win16HostStaticIconResult::Icon(None));
        }
        Some(NativeStaticControlKind::Icon) => {}
    }

    // Clone the shared table before using it. Neither RefCell nor its mutex is
    // held while USER dispatches the synchronous message.
    let images: Win16Images = { state.borrow().images.clone() };
    let icon_use = match operation {
        Win16HostStaticIconOperation::Set { icon: Some(icon) } => {
            match images.lease_icon(icon)? {
                Some(lease) => Some(lease),
                None => return Ok(Win16HostStaticIconResult::Icon(None)),
            }
        }
        _ => None,
    };
    let (message, w_param) = match operation {
        Win16HostStaticIconOperation::Get => (STM_GETICON, 0),
        Win16HostStaticIconOperation::Set { .. } => {
            let native = icon_use.as_ref()
                .map_or(std::ptr::null_mut(), |lease| lease.native());
            (STM_SETICON, native as usize)
        }
    };

    // Microsoft STM_GETICON documentation specifies SS_ICON. Restrict both
    // messages to this style so their result is interpreted as an HICON only
    // under the documented control contract.
    //
    // windows-sys exposes the native Win32 message values (STM_SETICON
    // 0x0170, STM_GETICON 0x0171). The Windows 3.1 SDK WINDOWS.H lines
    // 4462-4463 define guest Win16 values as WM_USER+0/+1 (0x0400/0x0401);
    // those guest numbers must not be sent to native USER32.
    //
    // SAFETY: hwnd is the resolved, live target. Message parameters contain
    // only scalar values or a leased host HICON, never guest pointer bits.
    // The lease survives any nested guest callback and result adoption.
    // CallWindowProcW interprets opaque USER WNDPROC sentinels without us
    // fabricating a Rust function pointer.
    let result = unsafe {
        match procedure {
            Some(procedure) => super::win16_window_default::call_window_proc_w_opaque(
                procedure, hwnd, message, w_param, 0,
            ),
            None => SendMessageW(hwnd, message, w_param, 0),
        }
    };

    // LRESULT and HICON are both host-pointer-sized here. The image table
    // records an unknown handle as borrowed; a known token keeps its existing
    // ownership flag. Observing this result does not transfer ownership from
    // the control or track how long the control continues to reference it.
    images.adopt_borrowed_icon(result as HICON)
        .map(Win16HostStaticIconResult::Icon)
}

/// Identify the built-in STATIC class and its documented type once for both
/// icon-message dispatch and WM_GETTEXT result-layout protection. Guest-owned
/// class registrations require an explicit, checked native base binding.
pub(super) fn native_static_control_kind(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Option<NativeStaticControlKind> {
    let bound_static = super::win16_native_procedures::bound_family(state, hwnd)
        == Some(runtime::Win16HostSystemClass::Static);
    let is_native_alias = {
        let state = state.borrow();
        state.windows_by_native.get(&(hwnd as usize))
            .is_some_and(|identity| identity.class.is_none()
                || identity.class.and_then(|class| state.classes.get(&class))
                    .is_some_and(|class| class.system_class))
    };
    if !bound_static && !is_native_alias {
        return None;
    }

    let mut class_name = [0_u16; 16];
    // SAFETY: hwnd was resolved from this worker's USER mapping and the local
    // output buffer remains writable for the full class-name query.
    let class_length = unsafe {
        GetClassNameW(hwnd, class_name.as_mut_ptr(), class_name.len() as i32)
    };
    if !bound_static && (class_length <= 0
        || class_length as usize != STATIC_CLASS.len()
        || class_length as usize > class_name.len()
        || !class_name[..class_length as usize].iter().zip(STATIC_CLASS).all(
            |(actual, expected)| ascii_fold(*actual) == ascii_fold(*expected),
        ))
    {
        return None;
    }

    // SAFETY: hwnd is a live USER window resolved by the caller.
    let style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) as u32 };
    Some(if style & STATIC_TYPE_MASK == STATIC_ICON_STYLE {
        NativeStaticControlKind::Icon
    } else {
        NativeStaticControlKind::Other
    })
}

fn ascii_fold(unit: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
        unit + (u16::from(b'a') - u16::from(b'A'))
    } else {
        unit
    }
}

/// Validate host-side mapping consistency before USER can classify the
/// target. A guest token with no HWND is an ordinary failed lookup; a token
/// that still maps to an HWND without its reverse identity is damaged state.
fn mapped_window_identity(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
) -> Result<Option<HWND>, RuntimeError> {
    let state = state.borrow();
    let Some(hwnd) = state.windows.get(&window).copied() else { return Ok(None); };
    if hwnd.is_null() {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 window token maps to a null native HWND"));
    }
    let identity = state.windows_by_native.get(&(hwnd as usize)).ok_or_else(|| {
        RuntimeError::new(Kind::InternalInvariant,
            "mapped Win16 window has no reverse native identity")
    })?;
    if identity.window != window {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "mapped Win16 window reverse identity refers to another token"));
    }
    Ok(Some(hwnd))
}

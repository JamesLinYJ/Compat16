//! Bounded access to the USER-owned MCS copy in an active MDI callback.

use std::cell::RefCell;
use std::ffi::c_void;
use std::mem::{MaybeUninit, size_of};
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, GWL_EXSTYLE, GetClassNameW, GetWindowLongPtrW, MDICREATESTRUCTW, WS_EX_MDICHILD,
};

use super::super::super::win16_window_worker::WorkerState;
use super::super::PendingMdiCreation;

/// Copy the MCS named by USER's CREATESTRUCT without forming a Rust reference
/// to an address that originated in native callback data.
pub(in super::super) fn read_callback_mdi_struct(pointer: usize) -> Option<MDICREATESTRUCTW> {
    if pointer == 0 {
        return None;
    }
    let mut output = MaybeUninit::<MDICREATESTRUCTW>::uninit();
    let mut transferred = 0_usize;
    // SAFETY: ReadProcessMemory validates the native pointer and copies into a
    // separate local buffer. The callback is synchronous, so USER keeps its
    // MCS copy live for this bounded read.
    let succeeded = unsafe {
        ReadProcessMemory(
            crate::windows::win32_safe::current_process(),
            pointer as *const c_void,
            output.as_mut_ptr().cast::<c_void>(),
            size_of::<MDICREATESTRUCTW>(),
            &mut transferred,
        )
    };
    if succeeded == 0 || transferred != size_of::<MDICREATESTRUCTW>() {
        return None;
    }
    // SAFETY: ReadProcessMemory copied exactly the size of the all-integer /
    // pointer native ABI structure into initialized storage.
    Some(unsafe { output.assume_init() })
}

pub(in super::super) fn write_callback_mdi_struct(
    pointer: usize,
    value: &MDICREATESTRUCTW,
) -> Result<(), RuntimeError> {
    if pointer == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "write MDI fields through a nonnull live MCS pointer",
        ));
    }
    let mut transferred = 0_usize;
    // SAFETY: Callers use either the host-owned original MCS or the MCS copy
    // found in the still-suspended USER callback. This writes from a separate
    // local snapshot and does not create an aliased Rust reference.
    let succeeded = unsafe {
        WriteProcessMemory(
            crate::windows::win32_safe::current_process(),
            pointer as *mut c_void,
            (value as *const MDICREATESTRUCTW).cast::<c_void>(),
            size_of::<MDICREATESTRUCTW>(),
            &mut transferred,
        )
    };
    if succeeded == 0 || transferred != size_of::<MDICREATESTRUCTW>() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "write checked mutable fields to the active MDI create structure",
        ));
    }
    Ok(())
}

/// Cheap HWND/client/class prefilter used before boundedly reading the MCS.
/// The caller also requires the exact synchronous operation and frame guard;
/// USER is allowed to copy both the MCS and its strings.
pub(in super::super) fn native_callback_candidate_matches(
    hwnd: HWND,
    create: &CREATESTRUCTW,
    pending: &PendingMdiCreation,
) -> bool {
    if hwnd.is_null()
        ||  { crate::windows::win32_safe::is_window(hwnd) } == 0
        || create.lpCreateParams.is_null()
        || create.hwndParent != pending.client
        ||  { crate::windows::win32_safe::get_parent(hwnd) } != pending.client
        || create.dwExStyle & WS_EX_MDICHILD == 0
        // SAFETY: GetWindowLongPtrW reads one window-long slot. The HWND is a window this thread created or was given by Windows.
        || unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 } & WS_EX_MDICHILD == 0
        || !native_class_matches(hwnd, &pending.native_class_name)
    {
        return false;
    }
    super::super::super::win16_window_identity::native_owner_identity(hwnd).is_some_and(
        |(process_id, thread_id)| {
            process_id == pending.owner_process && thread_id == pending.owner_thread
        },
    )
}

pub(in super::super) fn native_class_matches(hwnd: HWND, expected: &[u16]) -> bool {
    if expected.is_empty() || expected.len() >= i32::MAX as usize {
        return false;
    }
    let Some(capacity) = expected.len().checked_add(1) else {
        return false;
    };
    let mut actual = Vec::new();
    if actual.try_reserve_exact(capacity).is_err() {
        return false;
    }
    actual.resize(capacity, 0);
    // SAFETY: GetClassNameW writes into a caller-owned UTF-16 buffer of the capacity passed with it.
    let copied = unsafe { GetClassNameW(hwnd, actual.as_mut_ptr(), capacity as i32) };
    copied > 0
        && copied as usize == expected.len()
        && actual[..expected.len()]
            .iter()
            .zip(expected)
            .all(|(actual, expected)| fold_ascii_wide(*actual) == fold_ascii_wide(*expected))
}

fn fold_ascii_wide(value: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&value) {
        value - u16::from(b'a') + u16::from(b'A')
    } else {
        value
    }
}

pub(in super::super) fn validate_native_candidate(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    create: &CREATESTRUCTW,
    callback_mdi_struct: usize,
    pending: &PendingMdiCreation,
) -> Result<(), RuntimeError> {
    if hwnd.is_null()
        ||  { crate::windows::win32_safe::is_window(hwnd) } == 0
        || create.lpCreateParams as usize != callback_mdi_struct
        || create.hwndParent != pending.client
        ||  { crate::windows::win32_safe::get_parent(hwnd) } != pending.client
        || create.dwExStyle & WS_EX_MDICHILD == 0
        // SAFETY: GetWindowLongPtrW reads one window-long slot. The HWND is a window this thread created or was given by Windows.
        || unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 } & WS_EX_MDICHILD == 0
        || !native_class_matches(hwnd, &pending.native_class_name)
    {
        return Err(super::super::mdi_route_error(
            Kind::HostFailure,
            "native MDI child failed callback MCS, parent, class, or WS_EX_MDICHILD validation",
        ));
    }
    let (process_id, thread_id) =
        super::super::super::win16_window_identity::native_owner_identity(hwnd).ok_or_else(
            || {
                super::super::mdi_route_error(
                    Kind::HostFailure,
                    "read the live native MDI child process and thread",
                )
            },
        )?;
    if process_id != pending.owner_process || thread_id != pending.owner_thread {
        return Err(super::super::mdi_route_error(
            Kind::HostFailure,
            "native MDI child belongs to a different process or owner thread",
        ));
    }
    let copied_mdi = read_callback_mdi_struct(callback_mdi_struct).ok_or_else(|| {
        super::super::mdi_route_error(
            Kind::HostFailure,
            "read USER's copied MDI structure during its synchronous callback",
        )
    })?;
    let (class_instance, expected_title) = {
        let borrowed = state.try_borrow().map_err(|_| {
            super::super::mdi_route_error(
                Kind::InternalInvariant,
                "validate the registered MDI child class without a conflicting borrow",
            )
        })?;
        let class = borrowed.classes.get(&pending.class).ok_or_else(|| {
            super::super::mdi_route_error(
                Kind::HostFailure,
                "registered MDI child class disappeared during native creation",
            )
        })?;
        let title = pending
            .mdi
            .title
            .as_deref()
            .map(|bytes| borrowed.text_codec.to_wide(bytes))
            .transpose()?;
        (class.instance, title)
    };
    let canonical_mdi = read_callback_mdi_struct(pending.native_mdi_struct).ok_or_else(|| {
        super::super::mdi_route_error(
            Kind::HostFailure,
            "read the host-owned MDI create structure during its synchronous callback",
        )
    })?;
    if create.hInstance != class_instance
        || !canonical_mdi_matches_pending(
            &canonical_mdi,
            pending,
            class_instance,
            expected_title.as_deref(),
        )
        || !callback_mdi_identity_matches(
            &copied_mdi,
            pending,
            class_instance,
            canonical_mdi.lParam,
        )
    {
        return Err(super::super::mdi_route_error(
            Kind::HostFailure,
            "canonical or USER-copied MDI identity differs from the exact active create request",
        ));
    }
    Ok(())
}

fn canonical_mdi_matches_pending(
    mdi: &MDICREATESTRUCTW,
    pending: &PendingMdiCreation,
    class_instance: windows_sys::Win32::Foundation::HINSTANCE,
    expected_title: Option<&[u16]>,
) -> bool {
    mdi.hOwner == class_instance
        && remote_wide_string_matches(mdi.szClass, &pending.native_class_name, true)
        && match expected_title {
            Some(title) => remote_wide_string_matches(mdi.szTitle, title, false),
            None => mdi.szTitle.is_null(),
        }
        && mdi.x == super::mdi_coordinate(pending.mdi.x)
        && mdi.y == super::mdi_coordinate(pending.mdi.y)
        && mdi.cx == super::mdi_coordinate(pending.mdi.cx)
        && mdi.cy == super::mdi_coordinate(pending.mdi.cy)
        && mdi.style == pending.mdi.style
        && mdi.lParam == pending.mdi.parameter as i32 as isize
}

fn callback_mdi_identity_matches(
    mdi: &MDICREATESTRUCTW,
    pending: &PendingMdiCreation,
    class_instance: windows_sys::Win32::Foundation::HINSTANCE,
    canonical_parameter: windows_sys::Win32::Foundation::LPARAM,
) -> bool {
    // Windows may normalize mutable creation fields in its temporary MCS copy.
    // Only immutable class/owner and the guest-defined lParam must agree with
    // the still-owned canonical request; their pointer addresses may differ.
    mdi.hOwner == class_instance
        && remote_wide_string_matches(mdi.szClass, &pending.native_class_name, true)
        && mdi.lParam == canonical_parameter
}

/// Read only the bounded string size already owned by the active request.
/// The source pointer may be a USER copy, so never form a Rust reference to it.
fn remote_wide_string_matches(
    pointer: *const u16,
    expected: &[u16],
    ascii_case_insensitive: bool,
) -> bool {
    if pointer.is_null() {
        return false;
    }
    let Some(units) = expected.len().checked_add(1) else {
        return false;
    };
    let Some(byte_count) = units.checked_mul(size_of::<u16>()) else {
        return false;
    };
    let mut actual = Vec::new();
    if actual.try_reserve_exact(units).is_err() {
        return false;
    }
    actual.resize(units, 0_u16);
    let mut transferred = 0_usize;
    // SAFETY: RPM validates the untrusted USER-owned string pointer and copies
    // only the exact expected string length plus its terminator.
    let succeeded = unsafe {
        ReadProcessMemory(
            crate::windows::win32_safe::current_process(),
            pointer.cast::<c_void>(),
            actual.as_mut_ptr().cast::<c_void>(),
            byte_count,
            &mut transferred,
        )
    };
    if succeeded == 0 || transferred != byte_count || actual[expected.len()] != 0 {
        return false;
    }
    actual[..expected.len()]
        .iter()
        .zip(expected)
        .all(|(actual, expected)| {
            if ascii_case_insensitive {
                fold_ascii_wide(*actual) == fold_ascii_wide(*expected)
            } else {
                actual == expected
            }
        })
}

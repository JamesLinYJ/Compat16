//! Owned lifetime and notification routing for modeless FINDREPLACE dialogs.

use std::cell::{Cell, RefCell, UnsafeCell};
use std::ptr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCommonDialogResult as ResultValue,
    Win16HostFindReplaceDialog, Win16HostFindReplaceNotification, Win16HostFindReplaceUpdate,
    Win16HostWindow,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Controls::Dialogs::{FINDREPLACEW, FindTextW, ReplaceTextW};

use super::super::{win16_window_identity, win16_window_worker::WorkerState};
#[path = "win16_common_dialog_find_replace_text.rs"]
mod text_bridge;
use text_bridge::{
    copy_native_text, guest_text_for_native, native_buffer_length, native_field_capacity,
    native_text,
};

const FR_DIALOGTERM: u32 = 0x0000_0040;
const FR_HOOK_OR_TEMPLATE: u32 = 0x0000_2300;

/// Storage that USER/COMMDLG may keep reading after an abnormal worker exit.
/// Its fields are accessed only on the HWND-owning worker through the private
/// `LiveFindReplaceDialog` accessors below.
struct NativeBacking {
    native: UnsafeCell<FINDREPLACEW>,
    find_text: Box<[UnsafeCell<u16>]>,
    replace_text: Option<Box<[UnsafeCell<u16>]>>,
}

/// Opaque ownership handoff for backing storage. The receiver must retain the
/// guard until the owning Windows thread has joined; it has no API to inspect
/// or mutate the bytes.
pub(in crate::windows::win16_windows) struct ShutdownStorageGuard(Arc<NativeBacking>);

// SAFETY: This wrapper only moves an Arc ownership reference between threads.
// No reference to NativeBacking is exposed through the wrapper. USER and all
// raw-pointer access are confined to the HWND-owning worker; the receiver may
// only retain/drop the guard after that worker has joined. NativeBacking has
// no destructor with USER effects, only owned Rust allocations and the POD
// FINDREPLACEW record.
unsafe impl Send for ShutdownStorageGuard {}

pub(in crate::windows::win16_windows) type ShutdownStoragePool =
    Arc<Mutex<Vec<ShutdownStorageGuard>>>;

/// The dialog library mutates this record and its text during a modeless
/// lifetime. Each cell has stable storage; no Rust slice or shared reference
/// to native-writable bytes survives a call into USER/COMMDLG.
pub(in crate::windows::win16_windows) struct LiveFindReplaceDialog {
    request_id: u64,
    owner_token: Win16HostWindow,
    find_message: u16,
    replace: bool,
    dialog_token: Cell<Option<Win16HostWindow>>,
    dialog_hwnd: Cell<HWND>,
    route_active: Cell<bool>,
    find_guest_capacity: usize,
    replace_guest_capacity: Option<usize>,
    backing: Arc<NativeBacking>,
}

impl LiveFindReplaceDialog {
    fn native_ptr(&self) -> *mut FINDREPLACEW {
        self.backing.native.get()
    }

    fn native_address(&self) -> isize {
        self.native_ptr() as isize
    }

    fn find_text_ptr(&self) -> *mut u16 {
        // SAFETY: UnsafeCell is repr(transparent), and this owned boxed slice
        // remains at a stable address until the native dialog is destroyed.
        self.backing.find_text.as_ptr().cast_mut().cast::<u16>()
    }

    fn replace_text_ptr(&self) -> *mut u16 {
        self.backing
            .replace_text
            .as_ref()
            .map_or(ptr::null_mut(), |text| {
                // SAFETY: UnsafeCell is repr(transparent); native writes are
                // observed only through raw pointers into these owned cells.
                text.as_ptr().cast_mut().cast::<u16>()
            })
    }

    fn flags(&self) -> u32 {
        // SAFETY: Native callbacks run synchronously on this UI thread. The
        // FINDREPLACEW lives in UnsafeCell, so this raw read does not create a
        // Rust reference that aliases USER's native writes.
        unsafe { ptr::addr_of!((*self.native_ptr()).Flags).read() }
    }

    fn snapshot(
        &self,
        state: &Rc<RefCell<WorkerState>>,
    ) -> Result<Win16HostFindReplaceNotification, RuntimeError> {
        let native = self.native_ptr();
        // SAFETY: These fields are read through raw pointers while the native
        // API is suspended in its same-thread owner-window callback.
        let (find_pointer, replace_pointer, find_len, replace_len) = unsafe {
            (
                ptr::addr_of!((*native).lpstrFindWhat).read(),
                ptr::addr_of!((*native).lpstrReplaceWith).read(),
                usize::from(ptr::addr_of!((*native).wFindWhatLen).read()),
                usize::from(ptr::addr_of!((*native).wReplaceWithLen).read()),
            )
        };
        let expected_find_len = native_field_capacity(self.find_guest_capacity)?;
        let expected_replace_len = self
            .replace_guest_capacity
            .map(native_field_capacity)
            .transpose()?;
        if find_pointer != self.find_text_ptr()
            || find_len != usize::from(expected_find_len)
            || find_pointer.is_null()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native FINDREPLACE find buffer no longer matches its owned record",
            ));
        }
        match (
            &self.backing.replace_text,
            replace_pointer.is_null(),
            replace_len,
        ) {
            (Some(_text), false, length)
                if replace_pointer == self.replace_text_ptr()
                    && expected_replace_len.map(usize::from) == Some(length) => {}
            (None, true, 0) => {}
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native FINDREPLACE replacement buffer no longer matches its owned record",
                ));
            }
        }
        Ok(Win16HostFindReplaceNotification {
            request_id: self.request_id,
            dialog: self.dialog_token.get(),
            owner: self.owner_token,
            find_message: self.find_message,
            flags: self.flags(),
            find_text: copy_native_text(
                state,
                self.backing.find_text.as_ptr(),
                self.backing.find_text.len(),
                self.find_guest_capacity,
                "copy native FINDREPLACEW find buffer",
            )?,
            replace_text: self
                .backing
                .replace_text
                .as_ref()
                .map(|text| {
                    copy_native_text(
                        state,
                        text.as_ptr(),
                        text.len(),
                        self.replace_guest_capacity.unwrap_or_default(),
                        "copy native FINDREPLACEW replacement buffer",
                    )
                })
                .transpose()?,
            dialog_terminated: self.flags() & FR_DIALOGTERM != 0,
        })
    }

    fn apply(
        &self,
        state: &Rc<RefCell<WorkerState>>,
        update: &Win16HostFindReplaceUpdate,
    ) -> Result<(), RuntimeError> {
        if update.request_id != self.request_id
            || update.find_text.len() != self.find_guest_capacity
            || !update.find_text.contains(&0)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "guest FINDREPLACE update does not match its registered buffer",
            ));
        }
        match (&self.backing.replace_text, update.replace_text.as_ref()) {
            (Some(_buffer), Some(bytes))
                if self.replace_guest_capacity == Some(bytes.len()) && bytes.contains(&0) => {}
            (None, None) => {}
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "guest FINDREPLACE replacement update does not match its registered buffer",
                ));
            }
        }
        let native = self.native_ptr();
        // SAFETY: No native message is being dispatched while the synchronous
        // host-to-guest callback completion applies this owned update.
        let (find_pointer, replace_pointer) = unsafe {
            (
                ptr::addr_of!((*native).lpstrFindWhat).read(),
                ptr::addr_of!((*native).lpstrReplaceWith).read(),
            )
        };
        if find_pointer != self.find_text_ptr() || replace_pointer != self.replace_text_ptr() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native FINDREPLACE record lost its owned text-buffer pointers",
            ));
        }
        let find_wide = match guest_text_for_native(
            state,
            &update.find_text,
            self.backing.find_text.len(),
            usize::from(native_field_capacity(self.find_guest_capacity)?) / 2,
            "Win16 FINDREPLACE find update exceeds W buffer",
        ) {
            Ok(wide) => wide,
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                super::super::win16_window_position::report_diagnostic(
                    state,
                    Kind::CompatibilityGap,
                    "Find/Replace guest text update is not representable in its native W buffer; update ignored",
                );
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let replace_wide = match update.replace_text.as_ref() {
            Some(bytes) => match guest_text_for_native(
                state,
                bytes,
                self.backing
                    .replace_text
                    .as_ref()
                    .map_or(0, |value| value.len()),
                usize::from(native_field_capacity(
                    self.replace_guest_capacity.unwrap_or_default(),
                )?) / 2,
                "Win16 FINDREPLACE replacement update exceeds W buffer",
            ) {
                Ok(wide) => Some(wide),
                Err(error) if error.kind() == Kind::CompatibilityGap => {
                    super::super::win16_window_position::report_diagnostic(
                        state,
                        Kind::CompatibilityGap,
                        "Find/Replace replacement update is not representable in its native W buffer; update ignored",
                    );
                    return Ok(());
                }
                Err(error) => return Err(error),
            },
            None => None,
        };
        // SAFETY: The destination pointers refer to stable UnsafeCell UTF-16
        // arrays owned by this live record; guest byte capacities and W-unit
        // lengths were checked above.
        unsafe {
            ptr::copy_nonoverlapping(find_wide.as_ptr(), self.find_text_ptr(), find_wide.len());
            ptr::write_bytes(
                self.find_text_ptr().add(find_wide.len()),
                0,
                self.backing.find_text.len() - find_wide.len(),
            );
            if let Some(wide) = replace_wide.as_ref() {
                ptr::copy_nonoverlapping(wide.as_ptr(), self.replace_text_ptr(), wide.len());
                let capacity = self
                    .backing
                    .replace_text
                    .as_ref()
                    .map_or(0, |value| value.len());
                ptr::write_bytes(
                    self.replace_text_ptr().add(wide.len()),
                    0,
                    capacity - wide.len(),
                );
            }
            ptr::addr_of_mut!((*native).Flags).write(update.flags);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(in crate::windows::win16_windows) enum RegisteredCommonDialogMessage {
    NotFamily,
    NativeOnly,
    FindReplace(Win16HostFindReplaceNotification),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RegisteredCommonDialogMessageIds {
    pub find_replace: u16,
    pub help: u16,
}

pub(super) fn create(
    state: &Rc<RefCell<WorkerState>>,
    request: Win16HostFindReplaceDialog,
) -> Result<ResultValue, RuntimeError> {
    if request.flags & FR_HOOK_OR_TEMPLATE != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 FINDREPLACE hook or template needs guest callback/resource conversion",
        ));
    }
    if request.request_id == 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "runtime supplied a zero common-dialog request identity",
        ));
    }
    let Some(owner_token) = request.owner else {
        return Ok(failed_create(request.request_id, 0, 0));
    };
    let Some(owner) = win16_window_identity::resolve_user_window(state, owner_token) else {
        return Ok(failed_create(request.request_id, 0, 0));
    };
    let find_len = native_buffer_length(request.find_text.len(), "find")?;
    if find_len == 0 || !request.find_text.contains(&0) {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 FINDREPLACE find buffer is empty or not NUL terminated",
        ));
    }
    let replace_len = if request.replace {
        let Some(bytes) = request.replace_text.as_ref() else {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Win16 ReplaceText has no replacement buffer",
            ));
        };
        let length = native_buffer_length(bytes.len(), "replacement")?;
        if length == 0 || !bytes.contains(&0) {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Win16 ReplaceText buffer is empty or not NUL terminated",
            ));
        }
        length
    } else {
        // FindText does not consume the replacement pointer or capacity.
        0
    };

    let find_message = match super::find_replace_message_id() {
        Ok(message) => message,
        Err(_) => return Ok(failed_create(request.request_id, 0, 0)),
    };
    // Register the help message before entering USER, but a failure to expose
    // this optional message must not reject the dialog itself. The classifier
    // treats help notifications as native-only when its ID is available.
    let _ = super::help_message_id();
    let request_id = request.request_id;
    if state.borrow().live_find_replace.contains_key(&request_id) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "runtime reused an active Find/Replace request identity",
        ));
    }
    let record = Rc::new(make_live_record(
        state,
        request,
        owner,
        find_message,
        find_len,
        replace_len,
    )?);
    let storage_pool = { state.borrow().shutdown_storage.clone() };
    storage_pool
        .lock()
        .map_err(|_| {
            RuntimeError::new(
                Kind::HostFailure,
                "Find/Replace shutdown storage pool is poisoned",
            )
        })?
        .push(ShutdownStorageGuard(Arc::clone(&record.backing)));
    {
        let mut state = state.borrow_mut();
        if state.live_find_replace.contains_key(&request_id) {
            release_shutdown_storage(&storage_pool, &record);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "runtime reused an active Find/Replace request identity",
            ));
        }
        state
            .live_find_replace
            .insert(request_id, Rc::clone(&record));
    }

    // The request record is visible to registered-message callbacks before
    // entering COMMDLG. The native API and any nested WndProc use raw pointers
    // into this Rc-owned UnsafeCell record; no Rust borrow crosses that call.
    // SAFETY: ReplaceTextW reads a caller-owned FINDREPLACE that stays live for the dialog. FindTextW reads a caller-owned FINDREPLACE that stays live for the dialog.
    let dialog = unsafe {
        if record.replace {
            ReplaceTextW(record.native_ptr())
        } else {
            FindTextW(record.native_ptr())
        }
    };
    // Read immediately on the same worker thread as the native dialog call.
    let extended_error = super::commdlg_extended_error();
    let extended_error = if dialog.is_null() { extended_error } else { 0 };
    super::set_last_extended_error(extended_error);
    if dialog.is_null() {
        remove_request_if_same(state, request_id, &record);
        release_shutdown_storage(&storage_pool, &record);
        return Ok(failed_create(request_id, find_message, extended_error));
    }

    record.dialog_hwnd.set(dialog);
    let token = match win16_window_identity::adopt_created_owned(state, dialog) {
        Ok(token) => token,
        Err(error) => {
            if cleanup_unregistered_dialog(state, dialog) {
                remove_request_if_same(state, request_id, &record);
                release_shutdown_storage(&storage_pool, &record);
            } else {
                record.route_active.set(false);
            }
            return Err(error);
        }
    };
    record.dialog_token.set(Some(token));
    Ok(ResultValue::FindReplaceCreated {
        request_id,
        window: Some(token),
        find_message,
        extended_error,
    })
}

pub(super) fn classify_registered_message(
    state: &Rc<RefCell<WorkerState>>,
    owner: Win16HostWindow,
    message: u16,
    l_param: isize,
) -> Result<RegisteredCommonDialogMessage, RuntimeError> {
    let ids = super::registered_message_ids()?;
    if ids.help != 0 && message == ids.help {
        return Ok(RegisteredCommonDialogMessage::NativeOnly);
    }
    if message != ids.find_replace {
        return Ok(RegisteredCommonDialogMessage::NotFamily);
    }
    let record = {
        let state = state.borrow();
        state
            .live_find_replace
            .values()
            .find(|record| {
                record.route_active.get()
                    && record.owner_token == owner
                    && record.find_message == message
                    && record.native_address() == l_param
            })
            .cloned()
    };
    match record {
        Some(record) => Ok(RegisteredCommonDialogMessage::FindReplace(
            record.snapshot(state)?,
        )),
        None => Ok(RegisteredCommonDialogMessage::NativeOnly),
    }
}

/// Keep native-writable state pinned until the synchronous guest callback has
/// returned to USER/COMMDLG, even if FR_DIALOGTERM retires its route meanwhile.
pub(super) fn notification_guard(
    state: &Rc<RefCell<WorkerState>>,
    request_id: u64,
) -> Option<Rc<LiveFindReplaceDialog>> {
    state.borrow().live_find_replace.get(&request_id).cloned()
}

/// Apply the guest's copied record edits only to the exact live native record
/// that caused this callback. `false` means the callback output is stale.
pub(super) fn apply_find_replace_update(
    state: &Rc<RefCell<WorkerState>>,
    request_id: u64,
    native_l_param: isize,
    update: Option<&Win16HostFindReplaceUpdate>,
) -> Result<bool, RuntimeError> {
    let Some(record) = notification_guard(state, request_id) else {
        return Ok(false);
    };
    if record.native_address() != native_l_param {
        return Ok(false);
    }
    let Some(update) = update else {
        return Ok(true);
    };
    if !record.route_active.get() {
        return Ok(false);
    }
    record.apply(state, update)?;
    Ok(true)
}

/// Retire the dialog host identity after a captured FR_DIALOGTERM callback.
/// The opaque shutdown pool remains pinned until USER has unwound and the
/// owning worker thread has joined, even if the HWND still appears live here.
pub(in crate::windows::win16_windows) fn finish_terminal(
    state: &Rc<RefCell<WorkerState>>,
    notification: &Win16HostFindReplaceNotification,
) -> Result<bool, RuntimeError> {
    if !notification.dialog_terminated {
        return Ok(false);
    }
    let Some(record) = notification_guard(state, notification.request_id) else {
        return Ok(false);
    };
    if record.owner_token != notification.owner
        || record.find_message != notification.find_message
        || record.dialog_token.get() != notification.dialog
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "terminal Find/Replace notification does not match its live dialog identity",
        ));
    }
    record.route_active.set(false);
    let (Some(token), dialog) = (notification.dialog, record.dialog_hwnd.get()) else {
        // A terminal callback cannot normally precede FindText's return. If
        // USER reports one before adoption, preserve the record and guard;
        // later worker shutdown remains the only release boundary.
        return Ok(true);
    };
    if dialog.is_null() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "terminal Find/Replace identity has no native HWND",
        ));
    }

    let mapped = { state.borrow().windows.get(&token).copied() };
    match mapped {
        Some(hwnd) if hwnd == dialog => {
            // This removes only the matching token/cookie sidecars. It does
            // not DestroyWindow or release native backing; FR_DIALOGTERM can
            // still be inside the owner's native callback stack.
            super::super::win16_window_worker::remove_window_maps(state, token, dialog);
        }
        Some(_) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "terminal Find/Replace token was rebound to a different native HWND",
            ));
        }
        None => {
            // A WM_NCDESTROY/property-retirement path may already have removed
            // the token. That does not release backing; the outer pool still
            // owns it through thread join.
        }
    }
    Ok(true)
}

/// Disable the route whose property-bound host identity retired. If the HWND
/// still exists, keep its backing in the shutdown pool: a lost cookie does not
/// prove USER has unwound a nested common-dialog procedure.
pub(super) fn retire_window(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow) -> bool {
    let candidates = {
        let state = state.borrow();
        state
            .live_find_replace
            .iter()
            .filter_map(|(id, record)| {
                (record.dialog_token.get() == Some(window)).then_some((
                    *id,
                    Rc::clone(record),
                    record.dialog_hwnd.get(),
                ))
            })
            .collect::<Vec<_>>()
    };
    let mut retired = false;
    for (request_id, record, dialog) in candidates {
        if record.route_active.replace(false) {
            retired = true;
        }
        // SAFETY: The opaque HWND was created by this UI worker. IsWindow does
        // not dispatch to its procedure or expose native pointers.
        if dialog.is_null() || { crate::windows::win32_safe::is_window(dialog) } == 0 {
            // IsWindow==0 is positive evidence that this HWND no longer
            // exists. A missing/replaced cookie alone is not: USER may still
            // be unwinding a nested common-dialog procedure that holds the
            // raw FINDREPLACE pointer, so that backing stays in the shutdown
            // pool until the owning worker has joined.
            retired |= remove_request_if_same(state, request_id, &record);
        }
    }
    retired
}

/// Destroy modeless dialogs before normal worker exit. A failed native destroy
/// preserves its route storage and returns a fatal host error; the outer
/// shutdown pool retains native backing until the Windows thread has joined.
pub(super) fn shutdown(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    let records = {
        let state = state.borrow();
        state
            .live_find_replace
            .iter()
            .map(|(id, record)| (*id, Rc::clone(record)))
            .collect::<Vec<_>>()
    };
    for (request_id, record) in records {
        let dialog = record.dialog_hwnd.get();
        if dialog.is_null() {
            remove_request_if_same(state, request_id, &record);
            continue;
        }
        let storage_pool = { state.borrow().shutdown_storage.clone() };
        let Some(token) = record.dialog_token.get() else {
            // SAFETY: The HWND came from FindTextW on this worker; no state
            // borrow spans this same-thread liveness query.
            if (crate::windows::win32_safe::is_window(dialog)) == 0 {
                remove_request_if_same(state, request_id, &record);
                release_shutdown_storage(&storage_pool, &record);
                continue;
            }
            record.route_active.set(false);
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Find/Replace HWND remains live after dialog identity adoption failed",
            ));
        };
        if win16_window_identity::resolve(state, token) != Some(dialog) {
            // SAFETY: IsWindow checks only the retained opaque HWND. Missing
            // cookies alone are not proof that USER stopped reading it.
            if (crate::windows::win32_safe::is_window(dialog)) == 0 {
                // The native window is gone, so no dialog procedure can read
                // the retained structure or text allocations.
                remove_request_if_same(state, request_id, &record);
                release_shutdown_storage(&storage_pool, &record);
                continue;
            }
            // A lost/replaced property cookie does not prove that USER has
            // stopped reading this structure. Keep the map entry for retry
            // and the outer shutdown pool through thread join.
            record.route_active.set(false);
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Find/Replace HWND is live but its original identity is unavailable",
            ));
        }
        // Keep the native record alive in the external shutdown pool from the
        // first native pointer publication until the thread joins. No
        // RefCell borrow spans DestroyWindow or callbacks it may dispatch.
        // SAFETY: Strict identity resolution proves the exact current HWND
        // incarnation and destruction runs on its owning worker thread.
        let destroyed = (crate::windows::win32_safe::destroy_window(dialog)) != 0;
        if destroyed {
            remove_request_if_same(state, request_id, &record);
            release_shutdown_storage(&storage_pool, &record);
            continue;
        }
        // Preserve GetLastError before the follow-up IsWindow call.
        let destroy_error = crate::windows::win32_safe::last_error();
        // SAFETY: DestroyWindow returned; this checks whether nested callbacks
        // nevertheless completed destruction before it reported failure.
        if (crate::windows::win32_safe::is_window(dialog)) == 0 {
            remove_request_if_same(state, request_id, &record);
            release_shutdown_storage(&storage_pool, &record);
            continue;
        }
        record.route_active.set(false);
        return Err(RuntimeError::with_source(
            Kind::HostFailure,
            "DestroyWindow failed for a live modeless Find/Replace dialog",
            std::io::Error::from_raw_os_error(destroy_error as i32),
        ));
    }
    Ok(())
}

fn make_live_record(
    state: &Rc<RefCell<WorkerState>>,
    request: Win16HostFindReplaceDialog,
    owner: HWND,
    find_message: u16,
    find_len: u16,
    replace_len: u16,
) -> Result<LiveFindReplaceDialog, RuntimeError> {
    let find_guest_capacity = usize::from(find_len);
    let replace_guest_capacity = request.replace.then_some(usize::from(replace_len));
    let find_text = native_text(state, request.find_text, "FindText")?;
    let replace_text = if request.replace {
        request
            .replace_text
            .map(|bytes| native_text(state, bytes, "ReplaceText"))
            .transpose()?
    } else {
        None
    };
    let mut native = FINDREPLACEW::default();
    native.lStructSize = std::mem::size_of::<FINDREPLACEW>() as u32;
    native.hwndOwner = owner;
    native.hInstance = ptr::null_mut();
    native.Flags = request.flags;
    native.lpstrFindWhat = find_text.as_ptr().cast_mut().cast::<u16>();
    native.lpstrReplaceWith = replace_text.as_ref().map_or(ptr::null_mut(), |text| {
        text.as_ptr().cast_mut().cast::<u16>()
    });
    native.wFindWhatLen = native_field_capacity(find_guest_capacity)?;
    native.wReplaceWithLen = replace_guest_capacity
        .map(native_field_capacity)
        .transpose()?
        .unwrap_or(0);
    native.lCustData = 0;
    native.lpfnHook = None;
    native.lpTemplateName = ptr::null();
    Ok(LiveFindReplaceDialog {
        request_id: request.request_id,
        owner_token: request.owner.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "validated Find/Replace request lost its owner token",
            )
        })?,
        find_message,
        replace: request.replace,
        dialog_token: Cell::new(None),
        dialog_hwnd: Cell::new(ptr::null_mut()),
        route_active: Cell::new(true),
        find_guest_capacity,
        replace_guest_capacity,
        backing: Arc::new(NativeBacking {
            native: UnsafeCell::new(native),
            find_text,
            replace_text,
        }),
    })
}

fn failed_create(request_id: u64, find_message: u16, extended_error: u32) -> ResultValue {
    super::set_last_extended_error(extended_error);
    ResultValue::FindReplaceCreated {
        request_id,
        window: None,
        find_message,
        extended_error,
    }
}

fn remove_request_if_same(
    state: &Rc<RefCell<WorkerState>>,
    request_id: u64,
    record: &Rc<LiveFindReplaceDialog>,
) -> bool {
    let mut state = state.borrow_mut();
    if state
        .live_find_replace
        .get(&request_id)
        .is_some_and(|current| Rc::ptr_eq(current, record))
    {
        state.live_find_replace.remove(&request_id);
        true
    } else {
        false
    }
}

fn release_shutdown_storage(pool: &ShutdownStoragePool, record: &LiveFindReplaceDialog) {
    if let Ok(mut guards) = pool.lock() {
        guards.retain(|guard| !Arc::ptr_eq(&guard.0, &record.backing));
    }
    // A poisoned pool conservatively retains the backing until WindowWorker
    // clears it after join.
}

fn cleanup_unregistered_dialog(state: &Rc<RefCell<WorkerState>>, dialog: HWND) -> bool {
    let mapped = {
        state
            .borrow()
            .windows_by_native
            .get(&(dialog as usize))
            .map(|identity| identity.window)
    };
    let exact =
        mapped.is_some_and(|token| win16_window_identity::resolve(state, token) == Some(dialog));
    let untracked_worker_window =
        mapped.is_none() && win16_window_identity::belongs_to_worker(dialog) == Some(true);
    if exact || untracked_worker_window {
        // SAFETY: Either the current cookie proves this exact window, or this
        // is the just-returned same-thread dialog before another USER call can
        // recycle its HWND. No state borrow spans native destruction.
        if (crate::windows::win32_safe::destroy_window(dialog)) != 0 {
            return true;
        }
    }
    // SAFETY: `dialog` was returned by FindTextW on this worker. No state
    // borrow remains, and this query does not dispatch the dialog procedure.
    crate::windows::win32_safe::is_window(dialog) == 0
}

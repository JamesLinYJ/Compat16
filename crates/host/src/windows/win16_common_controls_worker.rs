//! Common-control calls on the HWND-owning UI worker.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ptr;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError,
    Win16HostCommonControlsOperation as Operation,
    Win16HostCommonControlsResult as ResultValue,
};
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::UI::Controls::{
    GetEffectiveClientRect, InitCommonControls,
};

use super::win16_window_worker::WorkerState;

#[path = "win16_common_controls_windows.rs"]
mod windows;
#[path = "win16_common_controls_extended.rs"]
mod extended;

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    operation: Operation,
    toolbar_bitmap_leases: &mut BTreeMap<
        runtime::Win16HostGdiObject,
        Option<super::win16_gdi_bitmap_lease::Win16BitmapLease>,
    >,
) -> Result<ResultValue, RuntimeError> {
    match operation {
        Operation::Init => {
            // SAFETY: This API has no pointer arguments and initializes the
            // common-control classes on the owning UI worker.
            unsafe { InitCommonControls() };
            Ok(ResultValue::Initialized)
        }
        Operation::CreateStatusWindow { style, text, parent, id } => {
            windows::create_status_window(state, style, &text, parent, id)
        }
        Operation::GetEffectiveClientRect { window, layout_info } => {
            if !valid_effective_client_layout(&layout_info) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "COMMCTRL effective-client layout is not a complete terminated pair array"));
            }
            let Some(window) = super::win16_window_identity::resolve_user_window(state, window) else {
                return Ok(ResultValue::Rect(None));
            };
            let mut rect = RECT::default();
            // SAFETY: `rect` is writable local storage and `layout_info` owns a
            // structurally checked menu pair, complete flag/ID pairs, and its
            // final zero flag for the full synchronous call.
            unsafe { GetEffectiveClientRect(window, &mut rect, layout_info.as_ptr()) };
            Ok(ResultValue::Rect(Some(runtime::Win16HostRect {
                left: rect.left,
                top: rect.top,
                right: rect.right,
                bottom: rect.bottom,
            })))
        }
        Operation::WritePrivateProfileStruct { section, key, data, data_size, file_name } => {
            if data.as_ref().is_some_and(|bytes| bytes.len() != usize::from(data_size)) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "COMMCTRL profile input length differs from its checked Win16 size"));
            }
            let section = section.as_deref().map(|bytes|
                super::win16_common_dialog_worker::guest_z_to_wide(
                    state, bytes, "COMMCTRL profile section contains an embedded NUL",
                )).transpose()?;
            let key = key.as_deref().map(|bytes|
                super::win16_common_dialog_worker::guest_z_to_wide(
                    state, bytes, "COMMCTRL profile key contains an embedded NUL",
                )).transpose()?;
            let file_name = file_name.as_deref().map(|bytes|
                super::win16_common_dialog_worker::guest_z_to_wide(
                    state, bytes, "COMMCTRL profile path contains an embedded NUL",
                )).transpose()?;
            let data_pointer: *const core::ffi::c_void = data.as_ref()
                .map_or(ptr::null(), |bytes| bytes.as_ptr().cast());
            // SAFETY: All strings and the owned payload slice remain alive for
            // the synchronous profile API call.
            let succeeded = unsafe {
                windows_sys::Win32::System::WindowsProgramming::WritePrivateProfileStructW(
                    section.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                    key.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                    data_pointer,
                    u32::from(data_size),
                    file_name.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                )
            } != 0;
            Ok(ResultValue::Bool(succeeded))
        }
        Operation::GetPrivateProfileStruct { section, key, capacity, file_name } => {
            let section = super::win16_common_dialog_worker::guest_z_to_wide(
                state, &section, "COMMCTRL profile section contains an embedded NUL")?;
            let key = super::win16_common_dialog_worker::guest_z_to_wide(
                state, &key, "COMMCTRL profile key contains an embedded NUL")?;
            let file_name = super::win16_common_dialog_worker::guest_z_to_wide(
                state, &file_name, "COMMCTRL profile path contains an embedded NUL")?;
            let mut data = Vec::new();
            let allocation_size = usize::from(capacity).max(1);
            data.try_reserve_exact(allocation_size).map_err(|_| RuntimeError::new(
                Kind::ResourceExhausted, "cannot allocate COMMCTRL profile structure buffer"))?;
            data.resize(allocation_size, 0);
            // SAFETY: `data` owns at least the requested output capacity and
            // each UTF-16 string buffer has a trailing NUL.
            let succeeded = unsafe {
                windows_sys::Win32::System::WindowsProgramming::GetPrivateProfileStructW(
                    section.as_ptr(),
                    key.as_ptr(),
                    data.as_mut_ptr().cast(),
                    u32::from(capacity),
                    file_name.as_ptr(),
                )
            } != 0;
            data.truncate(usize::from(capacity));
            Ok(ResultValue::ProfileData { succeeded, data })
        }
        Operation::CreateHeaderWindow { .. }
        | Operation::CreateToolbar { .. }
        | Operation::MenuHelpResolve { .. }
        | Operation::MenuHelpApply { .. }
        | Operation::MakeDragList { .. } => {
            extended::execute(state, operation, toolbar_bitmap_leases)
        }
    }
}

fn valid_effective_client_layout(layout: &[i32]) -> bool {
    if layout.len() < 3 || layout.len() % 2 == 0 || layout.last() != Some(&0) {
        return false;
    }
    // The first two INTs describe the ignored menu pair. Thereafter the even
    // slots are flags; only a zero flag terminates the native walk. Requiring
    // that sentinel at the final even slot prevents native reads past the Vec.
    (2..layout.len() - 1).step_by(2).all(|index| layout[index] != 0)
}

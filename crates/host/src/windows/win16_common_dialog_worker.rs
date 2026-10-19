//! Unicode common-dialog calls with explicit Win16 guest-code-page buffers.

use std::cell::{Cell, RefCell};
use std::ptr;
use std::rc::Rc;
use std::sync::OnceLock;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCommonDialogOperation as Operation,
    Win16HostCommonDialogResult as ResultValue, Win16HostFindReplaceUpdate, Win16HostLogFont,
    Win16HostOpenFileDialog, Win16HostWindow,
};
use windows_sys::Win32::Graphics::Gdi::LOGFONTW;
use windows_sys::Win32::UI::Controls::Dialogs::{
    CHOOSECOLORW, CHOOSEFONTW, ChooseColorW, ChooseFontW, CommDlgExtendedError, FINDMSGSTRINGW,
    GetFileTitleW, GetOpenFileNameW, GetSaveFileNameW, HELPMSGSTRINGW, OPENFILENAMEW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::RegisterWindowMessageW;

use super::{win16_window_identity, win16_window_worker::WorkerState};

#[path = "win16_common_dialog_find_replace.rs"]
mod find_replace;
#[path = "win16_common_dialog_print.rs"]
mod print;
#[path = "win16_common_dialog_printer_mode.rs"]
mod printer_mode;
#[path = "win16_common_dialog_text.rs"]
mod text;

pub(super) use text::{guest_devnames_to_wide, guest_z_to_wide, native_wide_devnames_to_guest};

use find_replace::RegisteredCommonDialogMessageIds;
pub(in crate::windows::win16_windows) use find_replace::{
    LiveFindReplaceDialog, RegisteredCommonDialogMessage, ShutdownStorageGuard,
};

thread_local! {
    /// The common-dialog API error is thread-local. All bridged dialog calls
    /// and CommDlgExtendedError execute on this same UI worker thread.
    static LAST_EXTENDED_ERROR: Cell<u32> = const { Cell::new(0) };
}

/// Executes native common dialogs on the HWND-owning UI worker. Find/Replace
/// retains its native record and buffers in `live_find_replace` after return.
pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    operation: Operation,
) -> Result<ResultValue, RuntimeError> {
    // Registered IDs are cached and known before any dialog call can dispatch
    // a message to a guest-owned window procedure.
    if !matches!(&operation, &Operation::ExtendedError) {
        let _ = registered_message_ids();
    }
    match operation {
        Operation::OpenFile(request) => open_file(state, request, false),
        Operation::SaveFile(request) => open_file(state, request, true),
        Operation::ChooseColor(request) => choose_color(state, request),
        Operation::FindReplace(request) => find_replace::create(state, request),
        Operation::ChooseFont(request) => choose_font(state, request),
        Operation::Print(request) => self::print::print_dialog(state, request),
        Operation::PrinterMode(request) => printer_mode::execute(state, request),
        Operation::GetFileTitle {
            file_name,
            capacity,
            title_is_null,
        } => get_file_title(state, &file_name, capacity, title_is_null),
        Operation::ExtendedError => Ok(ResultValue::ExtendedError(
            LAST_EXTENDED_ERROR.with(Cell::get),
        )),
    }
}

static FIND_REPLACE_MESSAGE_ID: OnceLock<u16> = OnceLock::new();
static HELP_MESSAGE_ID: OnceLock<u16> = OnceLock::new();

pub(super) fn find_replace_message_id() -> Result<u16, RuntimeError> {
    let message = *FIND_REPLACE_MESSAGE_ID.get_or_init(|| {
        // SAFETY: FINDMSGSTRINGW is a static UTF-16 NUL-terminated system name.
        u16::try_from(unsafe { RegisterWindowMessageW(FINDMSGSTRINGW) }).unwrap_or(0)
    });
    if message == 0 {
        Err(RuntimeError::new(
            Kind::HostFailure,
            "Windows could not register the common-dialog Find/Replace message",
        ))
    } else {
        Ok(message)
    }
}

pub(super) fn help_message_id() -> Result<u16, RuntimeError> {
    let message = *HELP_MESSAGE_ID.get_or_init(|| {
        // SAFETY: HELPMSGSTRINGW is a static UTF-16 NUL-terminated system name.
        u16::try_from(unsafe { RegisterWindowMessageW(HELPMSGSTRINGW) }).unwrap_or(0)
    });
    if message == 0 {
        Err(RuntimeError::new(
            Kind::HostFailure,
            "Windows could not register the common-dialog help message",
        ))
    } else {
        Ok(message)
    }
}

fn registered_message_ids() -> Result<RegisteredCommonDialogMessageIds, RuntimeError> {
    // Attempt both registrations before any common-dialog native call. Help
    // is optional, so its registration failure does not block the dialog.
    let help = help_message_id().unwrap_or(0);
    let find_replace = find_replace_message_id()?;
    Ok(RegisteredCommonDialogMessageIds { find_replace, help })
}

pub(super) fn classify_registered_message(
    state: &Rc<RefCell<WorkerState>>,
    owner: Win16HostWindow,
    message: u16,
    l_param: isize,
) -> Result<RegisteredCommonDialogMessage, RuntimeError> {
    find_replace::classify_registered_message(state, owner, message, l_param)
}

pub(super) fn notification_guard(
    state: &Rc<RefCell<WorkerState>>,
    request_id: u64,
) -> Option<Rc<LiveFindReplaceDialog>> {
    find_replace::notification_guard(state, request_id)
}

pub(super) fn apply_find_replace_update(
    state: &Rc<RefCell<WorkerState>>,
    request_id: u64,
    native_l_param: isize,
    update: Option<&Win16HostFindReplaceUpdate>,
) -> Result<bool, RuntimeError> {
    find_replace::apply_find_replace_update(state, request_id, native_l_param, update)
}

pub(in crate::windows::win16_windows) fn finish_terminal(
    state: &Rc<RefCell<WorkerState>>,
    notification: &runtime::Win16HostFindReplaceNotification,
) -> Result<bool, RuntimeError> {
    find_replace::finish_terminal(state, notification)
}

pub(super) fn retire_window(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow) -> bool {
    find_replace::retire_window(state, window)
}

pub(super) fn shutdown(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    find_replace::shutdown(state)
}

pub(super) fn commdlg_extended_error() -> u32 {
    // SAFETY: The error is queried on the same UI worker immediately after the
    // corresponding common-dialog API call.
    unsafe { CommDlgExtendedError() as u32 }
}

pub(super) fn set_last_extended_error(error: u32) {
    LAST_EXTENDED_ERROR.with(|last| last.set(error));
}

fn open_file(
    state: &Rc<RefCell<WorkerState>>,
    request: Win16HostOpenFileDialog,
    save: bool,
) -> Result<ResultValue, RuntimeError> {
    const HOOK_OR_TEMPLATE: u32 = 0x20 | 0x40 | 0x80;
    const HISTORICAL_FLAGS: u32 = 0x0001_ffff;
    if request.flags & HOOK_OR_TEMPLATE != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 OPENFILENAME hook/template flags require guest callback or NE-template conversion",
        ));
    }
    if request.flags & !HISTORICAL_FLAGS != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 OPENFILENAME contains flags outside the verified Windows 3.x set",
        ));
    }
    let declared_file_capacity = request.file.len();
    if declared_file_capacity != 0 && !request.file.contains(&0) {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 OPENFILENAME file buffer is not NUL terminated",
        ));
    }
    let native_file_capacity = u32::try_from(declared_file_capacity).map_err(|_| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 OPENFILENAME file capacity exceeds the native DWORD field",
        )
    })?;
    let owner = match request.owner {
        Some(token) => {
            win16_window_identity::resolve_user_window(state, token).ok_or_else(|| {
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "Win16 OPENFILENAME owner window is no longer mapped",
                )
            })?
        }
        None => ptr::null_mut(),
    };
    let mut filter = request
        .filter
        .as_deref()
        .map(|bytes| {
            text::guest_multisz_to_wide(
                state,
                bytes,
                "Win16 OPENFILENAME filter list is not a valid MULTI_SZ",
            )
        })
        .transpose()?;
    if let Some(filter) = filter.as_mut() {
        if filter.is_empty() {
            filter.extend_from_slice(&[0, 0]);
        }
    }
    let initial_dir = text::optional_guest_z_to_wide(
        state,
        request.initial_dir.as_deref(),
        "Win16 OPENFILENAME initial directory contains an embedded NUL",
    )?;
    let title = text::optional_guest_z_to_wide(
        state,
        request.title.as_deref(),
        "Win16 OPENFILENAME title contains an embedded NUL",
    )?;
    let default_extension = text::optional_guest_z_to_wide(
        state,
        request.default_extension.as_deref(),
        "Win16 OPENFILENAME default extension contains an embedded NUL",
    )?;

    let file_title_was_supplied = request.file_title.is_some();
    let custom_filter_was_supplied = request.custom_filter.is_some();
    let file_title_capacity = request.file_title.as_ref().map_or(0, Vec::len);
    let custom_filter_capacity = request.custom_filter.as_ref().map_or(0, Vec::len);
    let mut file_title = request.file_title.clone().unwrap_or_default();
    let mut custom_filter = request.custom_filter.clone().unwrap_or_default();
    let mut native_file = text::zeroed_wide(
        declared_file_capacity.max(1),
        "allocate native OPENFILENAMEW file buffer",
    )?;
    if declared_file_capacity != 0 {
        text::guest_buffer_to_wide(
            state,
            &request.file,
            &mut native_file,
            "Win16 OPENFILENAME file buffer cannot fit its native UTF-16 form",
        )?;
    }
    let mut native_file_title = if file_title_was_supplied {
        Some(text::zeroed_wide(
            file_title_capacity.max(1),
            "allocate native OPENFILENAMEW file-title buffer",
        )?)
    } else {
        None
    };
    let mut native_custom_filter = if custom_filter_was_supplied {
        Some(text::zeroed_wide(
            custom_filter_capacity.max(2),
            "allocate native OPENFILENAMEW custom-filter buffer",
        )?)
    } else {
        None
    };
    if let (Some(bytes), Some(wide)) = (
        request.custom_filter.as_deref(),
        native_custom_filter.as_mut(),
    ) {
        text::guest_custom_filter_to_wide(
            state,
            bytes,
            wide,
            "Win16 OPENFILENAME custom-filter buffer is not NUL terminated",
        )?;
    }
    let filter_ptr = filter.as_ref().map_or(ptr::null(), |value| value.as_ptr());
    let custom_filter_ptr = native_custom_filter
        .as_mut()
        .map_or(ptr::null_mut(), |value| value.as_mut_ptr());
    let file_title_ptr = native_file_title
        .as_mut()
        .map_or(ptr::null_mut(), |value| value.as_mut_ptr());
    let initial_dir_ptr = initial_dir.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    let title_ptr = title.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    let default_extension_ptr = default_extension
        .as_ref()
        .map_or(ptr::null(), |s| s.as_ptr());
    let mut native = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        hInstance: ptr::null_mut(),
        lpstrFilter: filter_ptr,
        lpstrCustomFilter: custom_filter_ptr,
        nMaxCustFilter: u32::try_from(custom_filter_capacity).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 OPENFILENAME custom-filter capacity exceeds DWORD",
            )
        })?,
        nFilterIndex: request.filter_index,
        lpstrFile: native_file.as_mut_ptr(),
        // A WCHAR capacity equal to the guest byte capacity is a safe upper
        // bound for every valid code-page string in that guest buffer.
        nMaxFile: native_file_capacity,
        lpstrFileTitle: file_title_ptr,
        nMaxFileTitle: u32::try_from(file_title_capacity).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 OPENFILENAME title capacity exceeds DWORD",
            )
        })?,
        lpstrInitialDir: initial_dir_ptr,
        lpstrTitle: title_ptr,
        Flags: request.flags,
        // These are output-only offsets in OPENFILENAME.
        nFileOffset: 0,
        nFileExtension: 0,
        lpstrDefExt: default_extension_ptr,
        lCustData: 0,
        lpfnHook: None,
        lpTemplateName: ptr::null(),
        pvReserved: ptr::null_mut(),
        dwReserved: 0,
        FlagsEx: 0,
    };
    // SAFETY: Every pointer in `native` refers to an owned UTF-16 buffer or
    // local option string that remains alive for the synchronous API call.
    let accepted = unsafe {
        if save {
            GetSaveFileNameW(&mut native)
        } else {
            GetOpenFileNameW(&mut native)
        }
    } != 0;
    let extended_error = commdlg_extended_error();
    set_last_extended_error(extended_error);
    let required_size = if !accepted && extended_error == 0x3003 && declared_file_capacity >= 2 {
        Some(text::wide_units_to_guest_upper_bound(
            state,
            usize::from(native_file[0]),
        )?)
    } else {
        None
    };
    if accepted {
        if declared_file_capacity == 0 {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "OPENFILENAMEW accepted a dialog without a writable Win16 file buffer",
            ));
        }
        let mut file_end = native_file
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "OPENFILENAMEW returned a file buffer without a terminator",
                )
            })?
            + 1;
        let is_multiselect = request.flags & 0x0000_0200 != 0;
        if is_multiselect {
            file_end = (0..native_file.len().saturating_sub(1))
                .find(|index| native_file[*index] == 0 && native_file[*index + 1] == 0)
                .map(|index| index + 2)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::HostFailure,
                        "OPENFILENAMEW multi-select result is not double NUL terminated",
                    )
                })?;
        }
        if usize::from(native.nFileOffset) > file_end
            || usize::from(native.nFileExtension) > file_end
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "OPENFILENAMEW returned an offset outside its terminated file result",
            ));
        }
        let file_offset = text::native_wide_prefix_guest_bytes(
            state,
            &native_file[..usize::from(native.nFileOffset)],
            "convert OPENFILENAMEW file-name offset to guest bytes",
        )?;
        let file_extension = text::native_wide_prefix_guest_bytes(
            state,
            &native_file[..usize::from(native.nFileExtension)],
            "convert OPENFILENAMEW extension offset to guest bytes",
        )?;
        let file_offset = u16::try_from(file_offset).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "OPENFILENAMEW file-name offset exceeds Win16 WORD",
            )
        })?;
        let file_extension = u16::try_from(file_extension).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "OPENFILENAMEW extension offset exceeds Win16 WORD",
            )
        })?;

        let mut file_output = request.file.clone();
        let file_projection = if is_multiselect {
            text::write_native_multisz_to_guest(
                state,
                &native_file[..file_end],
                &mut file_output,
                "convert OPENFILENAMEW multi-select result to guest bytes",
            )?
        } else {
            text::write_native_z_to_guest(
                state,
                &native_file[..file_end],
                &mut file_output,
                "convert OPENFILENAMEW file result to guest bytes",
            )?
        };
        report_projection_loss(
            state,
            &file_projection,
            "OPENFILENAMEW file result was truncated to the Win16 buffer",
            "OPENFILENAMEW file result used guest-code-page replacement characters",
        );

        if let (Some(output), Some(wide)) =
            (request.file_title.as_ref(), native_file_title.as_ref())
        {
            let mut title_output = output.clone();
            let projection = text::write_native_z_to_guest(
                state,
                wide,
                &mut title_output,
                "convert OPENFILENAMEW file-title result to guest bytes",
            )?;
            report_projection_loss(
                state,
                &projection,
                "OPENFILENAMEW file title was truncated to the Win16 buffer",
                "OPENFILENAMEW file title used guest-code-page replacement characters",
            );
            file_title = title_output;
        }
        if let (Some(output), Some(wide)) = (
            request.custom_filter.as_ref(),
            native_custom_filter.as_ref(),
        ) {
            let mut custom_output = output.clone();
            let projection = text::write_native_custom_filter_to_guest(
                state,
                wide,
                &mut custom_output,
                "convert OPENFILENAMEW custom-filter result to guest bytes",
            )?;
            report_projection_loss(
                state,
                &projection,
                "OPENFILENAMEW custom filter was truncated to the Win16 buffer",
                "OPENFILENAMEW custom filter used guest-code-page replacement characters",
            );
            custom_filter = custom_output;
        }
        if file_projection.truncated {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "OPENFILENAMEW selected path cannot be represented within the guest byte capacity",
            ));
        }
        return Ok(ResultValue::File {
            accepted,
            extended_error,
            flags: native.Flags,
            filter_index: native.nFilterIndex,
            required_size: None,
            file: file_output,
            file_title: file_title_was_supplied.then_some(file_title),
            file_offset,
            file_extension,
            custom_filter: custom_filter_was_supplied.then_some(custom_filter),
        });
    }
    Ok(ResultValue::File {
        accepted,
        extended_error,
        flags: native.Flags,
        filter_index: native.nFilterIndex,
        required_size,
        file: Vec::new(),
        file_title: file_title_was_supplied.then_some(file_title),
        file_offset: 0,
        file_extension: 0,
        custom_filter: custom_filter_was_supplied.then_some(custom_filter),
    })
}

fn choose_color(
    state: &Rc<RefCell<WorkerState>>,
    request: runtime::Win16HostChooseColorDialog,
) -> Result<ResultValue, RuntimeError> {
    const HOOK_OR_TEMPLATE: u32 = 0x10 | 0x20 | 0x40;
    const HISTORICAL_FLAGS: u32 = 0x007f;
    if request.flags & HOOK_OR_TEMPLATE != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 CHOOSECOLOR hook/template flags require guest callback or NE-template conversion",
        ));
    }
    if request.flags & !HISTORICAL_FLAGS != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 CHOOSECOLOR contains flags outside the verified Windows 3.x set",
        ));
    }
    let owner = match request.owner {
        Some(token) => {
            win16_window_identity::resolve_user_window(state, token).ok_or_else(|| {
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "Win16 CHOOSECOLOR owner window is no longer mapped",
                )
            })?
        }
        None => ptr::null_mut(),
    };
    let mut custom_colors = request.custom_colors;
    const CC_RGBINIT: u32 = 0x0000_0001;
    let mut native = CHOOSECOLORW {
        lStructSize: std::mem::size_of::<CHOOSECOLORW>() as u32,
        hwndOwner: owner,
        hInstance: ptr::null_mut(),
        rgbResult: if request.flags & CC_RGBINIT != 0 {
            request.initial_color
        } else {
            0
        },
        lpCustColors: custom_colors.as_mut_ptr(),
        Flags: request.flags,
        lCustData: 0,
        lpfnHook: None,
        lpTemplateName: ptr::null(),
    };
    // SAFETY: `native` and the sixteen-entry custom-color array are writable
    // local storage that outlives the synchronous ChooseColorW call.
    let accepted = unsafe { ChooseColorW(&mut native) } != 0;
    let extended_error = commdlg_extended_error();
    set_last_extended_error(extended_error);
    Ok(ResultValue::Color {
        accepted,
        extended_error,
        color: native.rgbResult,
        custom_colors,
    })
}

fn get_file_title(
    state: &Rc<RefCell<WorkerState>>,
    file_name: &[u8],
    capacity: u16,
    title_is_null: bool,
) -> Result<ResultValue, RuntimeError> {
    if file_name.contains(&0) {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 GetFileTitle input contains an embedded NUL",
        ));
    }
    if title_is_null && capacity != 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 GetFileTitle has a null output pointer with nonzero capacity",
        ));
    }
    let file_name = text::guest_z_to_wide(
        state,
        file_name,
        "Win16 GetFileTitle input contains an embedded NUL",
    )?;
    // SAFETY: `GetFileTitleW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let query_status = unsafe { GetFileTitleW(file_name.as_ptr(), ptr::null_mut(), 0) };
    if query_status < 0 {
        return Ok(ResultValue::FileTitle {
            status: query_status,
            title: Vec::new(),
        });
    }
    let required_wide = usize::try_from(query_status.max(1)).map_err(|error| {
        RuntimeError::with_source(
            Kind::HostFailure,
            "convert GetFileTitleW required UTF-16 capacity",
            error,
        )
    })?;
    let required_wide_u16 = u16::try_from(required_wide).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "GetFileTitleW required capacity exceeds WORD",
            error,
        )
    })?;
    let mut native_title =
        text::zeroed_wide(required_wide, "allocate full GetFileTitleW result buffer")?;
    // SAFETY: Both UTF-16 buffers remain live for the synchronous call. This
    // second call retrieves the complete title so the guest-byte requirement
    // can be computed exactly for its explicit code page.
    let status = unsafe {
        GetFileTitleW(
            file_name.as_ptr(),
            native_title.as_mut_ptr(),
            required_wide_u16,
        )
    };
    if status != 0 {
        return Ok(ResultValue::FileTitle {
            status,
            title: Vec::new(),
        });
    }
    let end = native_title
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::HostFailure,
                "GetFileTitleW succeeded without terminating its output string",
            )
        })?;
    let encoded = state.borrow().text_codec.from_wide(&native_title[..end])?;
    if encoded.used_default_char == Some(true) {
        super::win16_window_position::report_diagnostic(
            state,
            Kind::CompatibilityGap,
            "GetFileTitleW result used guest-code-page replacement characters",
        );
    }
    let required_guest = encoded.bytes.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "GetFileTitleW guest result size overflow",
        )
    })?;
    let required_status = i16::try_from(required_guest).map_err(|_| {
        RuntimeError::new(
            Kind::CompatibilityGap,
            "GetFileTitleW guest result size exceeds the Win16 signed return range",
        )
    })?;
    let mut title = Vec::new();
    if !title_is_null && usize::from(capacity) >= required_guest {
        title.try_reserve_exact(required_guest).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate converted Win16 GetFileTitle output",
                error,
            )
        })?;
        title.extend_from_slice(&encoded.bytes);
        title.push(0);
        Ok(ResultValue::FileTitle { status: 0, title })
    } else {
        Ok(ResultValue::FileTitle {
            status: required_status,
            title,
        })
    }
}

fn choose_font(
    state: &Rc<RefCell<WorkerState>>,
    request: runtime::Win16HostChooseFontDialog,
) -> Result<ResultValue, RuntimeError> {
    const HOOK_OR_TEMPLATE: u32 = 0x0000_0038;
    const CF_PRINTERFONTS: u32 = 0x0000_0002;
    const CF_INITTOLOGFONTSTRUCT: u32 = 0x0000_0040;
    const CF_USESTYLE: u32 = 0x0000_0080;
    const CF_EFFECTS: u32 = 0x0000_0100;
    const CF_LIMITSIZE: u32 = 0x0000_2000;
    const CF_WYSIWYG: u32 = 0x0000_8000;
    const HISTORICAL_FLAGS: u32 = 0x003f_ffff;
    if request.flags & HOOK_OR_TEMPLATE != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 CHOOSEFONT hook or template needs guest callback/resource conversion",
        ));
    }
    if request.flags & !HISTORICAL_FLAGS != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 CHOOSEFONT contains flags outside the verified Windows 3.1 set",
        ));
    }
    if request.flags & (CF_PRINTERFONTS | CF_WYSIWYG) != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 printer-font selection requires a guest printer DC mapping",
        ));
    }
    let owner = match request.owner {
        Some(token) => {
            win16_window_identity::resolve_user_window(state, token).ok_or_else(|| {
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "Win16 CHOOSEFONT owner HWND is no longer mapped",
                )
            })?
        }
        None => ptr::null_mut(),
    };
    // The guest HDC is inactive for screen-font selection and is never a
    // native pointer. Printer-font use was rejected above as an explicit gap.
    let use_style = request.flags & CF_USESTYLE != 0;
    if use_style && request.style.is_none() {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 CHOOSEFONT CF_USESTYLE requires its guest style buffer",
        ));
    }
    let original_style = request.style.clone().unwrap_or_default();
    let mut native_style = if use_style && request.style.is_some() {
        Some(text::zeroed_wide(
            32,
            "allocate native CHOOSEFONTW style buffer",
        )?)
    } else {
        None
    };
    if let (Some(bytes), Some(wide)) = (request.style.as_deref(), native_style.as_mut()) {
        text::guest_buffer_to_wide(
            state,
            bytes,
            wide,
            "Win16 CHOOSEFONT style buffer cannot fit its UTF-16 form",
        )?;
    }
    let mut log_font = if request.flags & CF_INITTOLOGFONTSTRUCT != 0 {
        LOGFONTW {
            lfHeight: i32::from(request.log_font.height),
            lfWidth: i32::from(request.log_font.width),
            lfEscapement: i32::from(request.log_font.escapement),
            lfOrientation: i32::from(request.log_font.orientation),
            lfWeight: i32::from(request.log_font.weight),
            lfItalic: request.log_font.italic,
            lfUnderline: request.log_font.underline,
            lfStrikeOut: request.log_font.strikeout,
            lfCharSet: request.log_font.char_set,
            lfOutPrecision: request.log_font.out_precision,
            lfClipPrecision: request.log_font.clip_precision,
            lfQuality: request.log_font.quality,
            lfPitchAndFamily: request.log_font.pitch_and_family,
            lfFaceName: text::fixed_guest_text_to_wide(
                state,
                &request.log_font.face_name,
                "Win16 LOGFONT face name cannot fit the native UTF-16 field",
            )?,
        }
    } else {
        LOGFONTW::default()
    };
    let mut native = CHOOSEFONTW {
        lStructSize: std::mem::size_of::<CHOOSEFONTW>() as u32,
        hwndOwner: owner,
        hDC: ptr::null_mut(),
        lpLogFont: &mut log_font,
        iPointSize: 0,
        Flags: request.flags,
        rgbColors: if request.flags & CF_EFFECTS != 0 {
            request.color
        } else {
            0
        },
        lCustData: 0,
        lpfnHook: None,
        lpTemplateName: ptr::null(),
        hInstance: ptr::null_mut(),
        lpszStyle: native_style
            .as_mut()
            .map_or(ptr::null_mut(), |buffer| buffer.as_mut_ptr()),
        nFontType: 0,
        ___MISSING_ALIGNMENT__: 0,
        nSizeMin: if request.flags & CF_LIMITSIZE != 0 {
            i32::from(request.min_size)
        } else {
            0
        },
        nSizeMax: if request.flags & CF_LIMITSIZE != 0 {
            i32::from(request.max_size)
        } else {
            0
        },
    };
    // SAFETY: `native`, `log_font`, and the optional NUL-terminated UTF-16
    // style buffer are host-owned storage alive through ChooseFontW.
    let accepted = unsafe { ChooseFontW(&mut native) } != 0;
    let extended_error = commdlg_extended_error();
    set_last_extended_error(extended_error);
    let point_size = i16::try_from(native.iPointSize).map_err(|_| {
        RuntimeError::new(
            Kind::CompatibilityGap,
            "CHOOSEFONT returned a point size outside the Win16 range",
        )
    })?;
    let (face_bytes, face_truncated, face_default) = {
        let end = log_font
            .lfFaceName
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(log_font.lfFaceName.len());
        let encoded = state
            .borrow()
            .text_codec
            .from_wide_bounded(&log_font.lfFaceName[..end], 31)?;
        (
            encoded.bytes,
            encoded.truncated,
            encoded.used_default_char == Some(true),
        )
    };
    if face_truncated {
        super::win16_window_position::report_diagnostic(
            state,
            Kind::CompatibilityGap,
            "CHOOSEFONTW face name was truncated to the Win16 LOGFONT field",
        );
    }
    if face_default {
        super::win16_window_position::report_diagnostic(
            state,
            Kind::CompatibilityGap,
            "CHOOSEFONTW face name used guest-code-page replacement characters",
        );
    }
    let mut face_name = [0_u8; 32];
    face_name[..face_bytes.len()].copy_from_slice(&face_bytes);
    let log_font = Win16HostLogFont {
        height: i16::try_from(log_font.lfHeight).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "CHOOSEFONT returned a font height outside the Win16 range",
            )
        })?,
        width: i16::try_from(log_font.lfWidth).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "CHOOSEFONT returned a font width outside the Win16 range",
            )
        })?,
        escapement: i16::try_from(log_font.lfEscapement).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "CHOOSEFONT returned a font escapement outside the Win16 range",
            )
        })?,
        orientation: i16::try_from(log_font.lfOrientation).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "CHOOSEFONT returned a font orientation outside the Win16 range",
            )
        })?,
        weight: i16::try_from(log_font.lfWeight).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "CHOOSEFONT returned a font weight outside the Win16 range",
            )
        })?,
        italic: log_font.lfItalic,
        underline: log_font.lfUnderline,
        strikeout: log_font.lfStrikeOut,
        char_set: log_font.lfCharSet,
        out_precision: log_font.lfOutPrecision,
        clip_precision: log_font.lfClipPrecision,
        quality: log_font.lfQuality,
        pitch_and_family: log_font.lfPitchAndFamily,
        face_name,
    };
    let style = if use_style {
        if let Some(native_style) = native_style.as_ref() {
            let end = native_style
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(native_style.len());
            let encoded = state
                .borrow()
                .text_codec
                .from_wide_bounded(&native_style[..end], 31)?;
            let projection = text::TextProjection {
                bytes: encoded.bytes,
                truncated: encoded.truncated || end == native_style.len(),
                used_default_char: encoded.used_default_char == Some(true),
            };
            report_projection_loss(
                state,
                &projection,
                "CHOOSEFONTW style was truncated to the Win16 32-byte buffer",
                "CHOOSEFONTW style used guest-code-page replacement characters",
            );
            let mut output = projection.bytes;
            output.push(0);
            output
        } else {
            vec![0]
        }
    } else if original_style.is_empty() {
        vec![0]
    } else {
        original_style
    };
    Ok(ResultValue::Font {
        accepted,
        extended_error,
        log_font,
        point_size,
        color: if request.flags & CF_EFFECTS != 0 {
            native.rgbColors
        } else {
            request.color
        },
        flags: native.Flags,
        style,
        font_type: native.nFontType,
    })
}

fn report_projection_loss(
    state: &Rc<RefCell<WorkerState>>,
    projection: &text::TextProjection,
    truncated_message: &'static str,
    replacement_message: &'static str,
) {
    if projection.truncated {
        super::win16_window_position::report_diagnostic(
            state,
            Kind::CompatibilityGap,
            truncated_message,
        );
    }
    if projection.used_default_char {
        super::win16_window_position::report_diagnostic(
            state,
            Kind::CompatibilityGap,
            replacement_message,
        );
    }
}

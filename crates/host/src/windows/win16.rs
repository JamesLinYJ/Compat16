//! Native Windows services requested by the Win16 guest ABI.

mod dos_file_io;
mod file_ioctl;
pub(super) mod file_metadata;

use super::bindings::{LZClose, LZRead, LZSeek};
#[cfg(test)]
use super::guest_text::GuestTextCodec;
use runtime::Win16HostFile;
use runtime::Win16HostFileClose;
use runtime::{DiagnosticKind as Kind, RuntimeError};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use windows_sys::Win32::Foundation::{ERROR_NO_UNICODE_TRANSLATION, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, HWND};
#[cfg(test)]
use windows_sys::Win32::Storage::FileSystem::{CREATE_ALWAYS, CreateFileW, OPEN_EXISTING};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
    FILE_BEGIN, FILE_CURRENT, FILE_END, FILE_SHARE_READ, FILE_SHARE_WRITE, ReadFile, SetEndOfFile,
    SetFilePointerEx, WriteFile,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_ESCAPE;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, HHOOK, MSG, MSGF_DIALOGBOX, MSGF_MESSAGEBOX, MessageBoxW, SetWindowsHookExW,
    WH_MSGFILTER, WM_KEYDOWN,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16NativeFile {
    /// A pointer-sized HANDLE returned by CreateFileW. It must only be used
    /// with HANDLE APIs and must never be narrowed to an HFILE.
    NativeHandle(HANDLE),
    /// A native token returned by LZInit. Even ordinary files
    /// can receive a distinct LZ token, so numeric equality is not a type test.
    LzHandle(Win16LzNative),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16LzNative {
    pub handle: i32,
    /// An LZInit wrapper owns a duplicate of this original ordinary file.
    /// LZClose consumes the original Win16 HFILE as well.
    pub source_alias: Option<Win16HostFile>,
}

/// Owns native compatibility file identities. The guest receives only
/// bounded 16-bit numbers allocated by the runtime, never host HFILEs/HANDLEs.
pub(super) struct Win16Files {
    files: BTreeMap<Win16HostFile, RetainedFile>,
    next_id: u64,
}

#[derive(Clone, Copy)]
struct RetainedFile {
    native: Win16NativeFile,
    // None marks LZ wrappers or imported handles whose access was not
    // supplied. Never infer read-only rights from a failed native flush.
    access: Option<u32>,
    dos_drive: Option<u8>,
    written: bool,
}

impl Win16Files {
    pub(super) fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            next_id: 1,
        }
    }

    pub(super) fn retain_native(
        &mut self,
        native: Win16NativeFile,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        self.retain_file(native, None, None)
    }

    pub(super) fn retain_native_with_access(
        &mut self,
        native: Win16NativeFile,
        access: u32,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        self.retain_file(native, Some(access), None)
    }

    pub(super) fn retain_mapped_file(
        &mut self,
        native: Win16NativeFile,
        access: u32,
        drive: u8,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        if drive > 25 {
            close_native(native);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "invalid mapped DOS drive",
            ));
        }
        self.retain_file(native, Some(access), Some(drive))
    }

    fn retain_file(
        &mut self,
        native: Win16NativeFile,
        access: Option<u32>,
        dos_drive: Option<u8>,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        let Some(next_id) = self.next_id.checked_add(1) else {
            close_native(native);
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 host file identity exhausted",
            ));
        };
        let token = Win16HostFile(self.next_id);
        self.next_id = next_id;
        self.files.insert(
            token,
            RetainedFile {
                native,
                access,
                dos_drive,
                written: false,
            },
        );
        Ok(Some(token))
    }

    pub(super) fn native_file(&self, file: Win16HostFile) -> Option<Win16NativeFile> {
        self.files.get(&file).map(|entry| entry.native)
    }

    pub(super) fn mark_written(&mut self, file: Win16HostFile) {
        if let Some(entry) = self.files.get_mut(&file) {
            entry.written = true;
        }
    }

    fn ordinary_handle(
        &self,
        file: Win16HostFile,
    ) -> Result<(HANDLE, Option<u32>), dos_kernel::DosHostError> {
        let entry = self
            .files
            .get(&file)
            .ok_or_else(|| super::invalid(dos_kernel::DosErrorCode::InvalidHandle))?;
        let handle = match entry.native {
            Win16NativeFile::NativeHandle(handle) => handle,
            Win16NativeFile::LzHandle(_) => {
                return Err(super::invalid(dos_kernel::DosErrorCode::InvalidFunction));
            }
        };
        Ok((handle, entry.access))
    }

    #[cfg(test)]
    pub(super) fn open(
        &mut self,
        codec: GuestTextCodec,
        path: &[u8],
        mode: u16,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        if path.contains(&0) {
            return Ok(None);
        }
        let Some((access, share)) = open_access_and_share(mode) else {
            return Ok(None);
        };
        let Some(path_wide_z) = guest_file_path(codec, path)? else {
            return Ok(None);
        };
        // _lopen's access/share modes are mapped to their documented CreateFile
        // equivalents. The guest bytes are decoded with its fixed codec rather
        // than the process ACP. No HANDLE is represented as an HFILE.
        // SAFETY: `path_wide_z` is owned UTF-16 with a trailing NUL and stays
        // alive for the synchronous CreateFileW call.
        let handle = unsafe {
            CreateFileW(
                path_wide_z.as_ptr(),
                access,
                share,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Ok(None);
        }
        self.retain_native_with_access(Win16NativeFile::NativeHandle(handle), access)
    }

    #[cfg(test)]
    pub(super) fn create(
        &mut self,
        codec: GuestTextCodec,
        path: &[u8],
        attributes: u16,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        if path.contains(&0) {
            return Ok(None);
        }
        let Some(native_attributes) = create_attributes(attributes) else {
            return Ok(None);
        };
        let Some(path_wide_z) = guest_file_path(codec, path)? else {
            return Ok(None);
        };
        // _lcreat creates or truncates and opens for read/write. Its documented
        // attributes are the DOS low bits, not arbitrary CreateFile flags.
        // SAFETY: `path_wide_z` is owned UTF-16 with a trailing NUL and stays
        // alive for the synchronous CreateFileW call.
        let handle = unsafe {
            CreateFileW(
                path_wide_z.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                CREATE_ALWAYS,
                native_attributes,
                std::ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Ok(None);
        }
        self.retain_native_with_access(
            Win16NativeFile::NativeHandle(handle),
            GENERIC_READ | GENERIC_WRITE,
        )
    }

    pub(super) fn read(
        &mut self,
        file: Win16HostFile,
        count: u32,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        let Some(native) = self.native_file(file) else {
            return Ok(None);
        };
        let length = usize::try_from(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "Win16 file read length does not fit host memory",
                error,
            )
        })?;
        // A zero-byte call still reaches Windows for native handle/access
        // validation. Its pointer names a local byte, never guest memory.
        let storage_length = length.max(1);
        let mut data = Vec::new();
        data.try_reserve_exact(storage_length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 file read buffer",
                error,
            )
        })?;
        data.resize(storage_length, 0);
        // One native read preserves Windows short-read and EOF behavior; do
        // not turn this into read_exact or loop to fill the requested range.
        // SAFETY: `data` owns `count` writable bytes and the native file
        // identity is retained in this adapter. The guest pointer never reaches Windows.
        let read = match native {
            Win16NativeFile::LzHandle(lz) => {
                let Ok(count) = i32::try_from(count) else {
                    return Ok(None);
                };
                // SAFETY: `data` owns `count` writable bytes; `handle` is an
                // LZ handle retained by this adapter, not a guest HFILE value.
                let read = unsafe { LZRead(lz.handle, data.as_mut_ptr().cast(), count) };
                if read < 0 {
                    return Ok(None);
                }
                read as u32
            }
            Win16NativeFile::NativeHandle(handle) => {
                let mut bytes_read = 0_u32;
                // SAFETY: `data` owns at least one byte even for a zero-byte
                // request, and `handle` is an owned CreateFileW HANDLE.
                let success = unsafe {
                    ReadFile(
                        handle,
                        data.as_mut_ptr().cast(),
                        count,
                        &mut bytes_read,
                        std::ptr::null_mut(),
                    )
                };
                if success == 0 {
                    return Ok(None);
                }
                bytes_read
            }
        };
        let read = usize::try_from(read).map_err(|error| {
            RuntimeError::with_source(
                Kind::InternalInvariant,
                "Win16 native file read length is not representable",
                error,
            )
        })?;
        if read > length {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 native file read exceeded its buffer",
            ));
        }
        data.truncate(read);
        Ok(Some(data))
    }

    pub(super) fn seek(
        &mut self,
        file: Win16HostFile,
        offset: i32,
        origin: u16,
    ) -> Result<Option<i32>, RuntimeError> {
        let Some(native) = self.native_file(file) else {
            return Ok(None);
        };
        // SAFETY: `native` is an HFILE owned by this adapter; offset and
        // origin are scalar Win16 arguments already copied out of guest state.
        let position = match native {
            Win16NativeFile::LzHandle(lz) => {
                // SAFETY: `handle` is an LZ HFILE owned by this adapter.
                unsafe { LZSeek(lz.handle, offset, i32::from(origin)) }
            }
            Win16NativeFile::NativeHandle(handle) => {
                let method = match origin {
                    0 => FILE_BEGIN,
                    1 => FILE_CURRENT,
                    2 => FILE_END,
                    _ => return Ok(None),
                };
                let mut previous = 0_i64;
                // SAFETY: `handle` is retained by this adapter. A zero move
                // from the current position records the pointer so a result
                // that does not fit in a successful LONG can be undone.
                let saved = unsafe {
                    SetFilePointerEx(handle, 0, &mut previous, FILE_CURRENT)
                } != 0;
                let mut new_position = 0_i64;
                // SAFETY: `handle` is retained by this adapter; the output is
                // a local LARGE_INTEGER-compatible i64 and method is checked.
                if unsafe { SetFilePointerEx(handle, i64::from(offset), &mut new_position, method) }
                    == 0
                {
                    return Ok(None);
                }
                if let Some(position) = signed_file_position(new_position) {
                    position
                } else if saved {
                    let mut restored = 0_i64;
                    // SAFETY: `handle` is retained by this adapter. `previous`
                    // is the pointer recorded before this seek.
                    if unsafe { SetFilePointerEx(handle, previous, &mut restored, FILE_BEGIN) }
                        == 0
                        || restored != previous
                    {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "Win16 seek could not restore a position past the signed result",
                        ));
                    }
                    return Ok(None);
                } else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 seek moved past the signed result without a saved pointer",
                    ));
                }
            }
        };
        if position == -1 {
            return Ok(None);
        }
        Ok(Some(position))
    }

    pub(super) fn write(
        &mut self,
        file: Win16HostFile,
        data: &[u8],
    ) -> Result<Option<u32>, RuntimeError> {
        let Some(native) = self.native_file(file) else {
            return Ok(None);
        };
        let count = u32::try_from(data.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::InvalidInput,
                "Win16 write length exceeds Windows API limit",
                error,
            )
        })?;
        match native {
            Win16NativeFile::LzHandle(_) => Ok(None),
            Win16NativeFile::NativeHandle(handle) if count == 0 => {
                // _lwrite(HFILE, NULL, 0) truncates or extends at the current
                // position. WriteFile(0) alone is a no-op, so use the native
                // equivalent SetEndOfFile primitive explicitly.
                // SAFETY: `handle` is an owned synchronous file HANDLE.
                if unsafe { SetEndOfFile(handle) } == 0 {
                    return Ok(None);
                }
                self.mark_written(file);
                Ok(Some(0))
            }
            Win16NativeFile::NativeHandle(handle) => {
                let mut bytes_written = 0_u32;
                // SAFETY: `data` is the owned copy of the guest bytes and
                // remains alive for the synchronous WriteFile call.
                let success = unsafe {
                    WriteFile(
                        handle,
                        data.as_ptr(),
                        count,
                        &mut bytes_written,
                        std::ptr::null_mut(),
                    )
                };
                if success == 0 {
                    return Ok(None);
                }
                if bytes_written > count {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 native write exceeded its input buffer",
                    ));
                }
                if bytes_written != 0 {
                    self.mark_written(file);
                }
                Ok(Some(bytes_written))
            }
        }
    }

    pub(super) fn close(
        &mut self,
        file: Win16HostFile,
    ) -> Result<Win16HostFileClose, RuntimeError> {
        Ok(self.close_checked(file).unwrap_or(Win16HostFileClose {
            closed: false,
            consumed_source: None,
        }))
    }

    pub(super) fn close_checked(
        &mut self,
        file: Win16HostFile,
    ) -> Result<Win16HostFileClose, dos_kernel::DosHostError> {
        let native = self
            .native_file(file)
            .ok_or_else(|| super::invalid(dos_kernel::DosErrorCode::InvalidHandle))?;
        let consumed_source = match native {
            Win16NativeFile::NativeHandle(handle) => {
                // SAFETY: The HANDLE is still owned here; a failed close
                // keeps it in the table so the caller can retry.
                if (crate::windows::win32_safe::close_handle(handle)) == 0 {
                    return Err(file_error(crate::windows::win32_safe::last_error()));
                }
                None
            }
            Win16NativeFile::LzHandle(lz) => {
                // LZClose releases the LZ token and its duplicate. The original
                // source file is consumed below when this was an LZInit alias.
                close_native(native);
                if let Some(source) = lz.source_alias {
                    // The source remains separately owned. A failed close
                    // keeps its table entry and guest alias available for retry.
                    let closed = match self.native_file(source) {
                        Some(Win16NativeFile::NativeHandle(handle)) => {
                            // This is the table's owned source HANDLE.
                            crate::windows::win32_safe::close_handle(handle) != 0
                        }
                        _ => false,
                    };
                    if closed {
                        self.files.remove(&source);
                        Some(source)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };
        self.files.remove(&file);
        Ok(Win16HostFileClose {
            closed: true,
            consumed_source,
        })
    }
}

/// `_llseek` returns a LONG offset, and HFILE_ERROR is -1. Only
/// `0..=i32::MAX` is a successful absolute position.
fn signed_file_position(position: i64) -> Option<i32> {
    u32::try_from(position)
        .ok()
        .and_then(|value| i32::try_from(value).ok())
}

impl Drop for Win16Files {
    fn drop(&mut self) {
        let mut consumed_sources = BTreeSet::new();
        for native in self.files.values().map(|entry| entry.native) {
            if let Win16NativeFile::LzHandle(lz) = native {
                close_native(native);
                if let Some(source) = lz.source_alias {
                    consumed_sources.insert(source);
                }
            }
        }
        for source in &consumed_sources {
            if let Some(native @ Win16NativeFile::NativeHandle(_)) = self.native_file(*source) {
                // Its LZInit duplicate was closed above; consume the original
                // owned source only once even if multiple tokens alias it.
                close_native(native);
            }
        }
        for (token, entry) in &self.files {
            if matches!(entry.native, Win16NativeFile::NativeHandle(_))
                && !consumed_sources.contains(token)
            {
                close_native(entry.native);
            }
        }
    }
}

fn file_error(code: u32) -> dos_kernel::DosHostError {
    if code == windows_sys::Win32::Foundation::ERROR_INVALID_FUNCTION {
        super::invalid(dos_kernel::DosErrorCode::InvalidFunction)
    } else {
        super::os_error(std::io::Error::from_raw_os_error(code as i32))
    }
}

fn close_native(native: Win16NativeFile) {
    match native {
        Win16NativeFile::LzHandle(lz) => {
            // SAFETY: This LZ HFILE was returned by a successful native LZ
            // operation and remains owned by this adapter.
            unsafe { LZClose(lz.handle) };
        }
        Win16NativeFile::NativeHandle(handle) => {
            // SAFETY: This HANDLE was returned by CreateFileW and remains
            // owned by this adapter.
            (crate::windows::win32_safe::close_handle(handle));
        }
    }
}

#[cfg(test)]
fn guest_file_path(codec: GuestTextCodec, path: &[u8]) -> Result<Option<Vec<u16>>, RuntimeError> {
    match codec.to_wide_z(path) {
        Ok(path) => Ok(Some(path)),
        // Invalid guest text is an ordinary file-open failure. Allocation and
        // other host failures retain their cause instead of becoming HFILE_ERROR.
        Err(error)
            if error.kind() == Kind::InvalidInput
                || (error.kind() == Kind::HostFailure
                    && (crate::windows::win32_safe::last_error())
                        == ERROR_NO_UNICODE_TRANSLATION) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn open_access_and_share(mode: u16) -> Option<(u32, u32)> {
    const ACCESS_MASK: u16 = 0x0003;
    const SHARE_MASK: u16 = 0x0070;
    if mode & !(ACCESS_MASK | SHARE_MASK) != 0 {
        return None;
    }
    let access = match mode & ACCESS_MASK {
        0 => GENERIC_READ,                 // OF_READ
        1 => GENERIC_WRITE,                // OF_WRITE
        2 => GENERIC_READ | GENERIC_WRITE, // OF_READWRITE
        _ => return None,
    };
    let share = match mode & SHARE_MASK {
        0x0000 | 0x0040 => FILE_SHARE_READ | FILE_SHARE_WRITE, // COMPAT / DENY_NONE
        0x0010 => 0,                                           // OF_SHARE_EXCLUSIVE
        0x0020 => FILE_SHARE_READ,                             // OF_SHARE_DENY_WRITE
        0x0030 => FILE_SHARE_WRITE,                            // OF_SHARE_DENY_READ
        _ => return None,
    };
    Some((access, share))
}

pub(super) fn create_attributes(attributes: u16) -> Option<u32> {
    match attributes {
        0 => Some(FILE_ATTRIBUTE_NORMAL),
        1 => Some(FILE_ATTRIBUTE_READONLY),
        2 => Some(FILE_ATTRIBUTE_HIDDEN),
        4 => Some(FILE_ATTRIBUTE_SYSTEM),
        _ => None,
    }
}

struct MessageBoxEscapeFilter {
    hook: HHOOK,
    eat_escape: Vec<bool>,
}

thread_local! {
    static MESSAGE_BOX_ESCAPE: RefCell<MessageBoxEscapeFilter> =
        RefCell::new(MessageBoxEscapeFilter {
            hook: std::ptr::null_mut(),
            eat_escape: Vec::new(),
        });
}

struct MessageBoxEscapeGuard;

impl Drop for MessageBoxEscapeGuard {
    fn drop(&mut self) {
        let hook = MESSAGE_BOX_ESCAPE.with(|slot| {
            let mut filter = slot.borrow_mut();
            filter.eat_escape.pop();
            if filter.eat_escape.is_empty() {
                Some(filter.hook)
            } else {
                None
            }
        });
        let Some(hook) = hook else {
            return;
        };
        if hook.is_null() {
            return;
        }
        if crate::windows::win32_safe::unhook_windows_hook(hook) != 0 {
            MESSAGE_BOX_ESCAPE.with(|slot| slot.borrow_mut().hook = std::ptr::null_mut());
        }
    }
}

/// `MB_OKCANCEL`, `MB_YESNOCANCEL`, and `MB_RETRYCANCEL` are the button
/// types that include Cancel. Icon, default-button, and modality bits sit
/// outside the low nibble.
fn message_box_style_has_cancel(style: u16) -> bool {
    matches!(style & 0x000F, 1 | 3 | 5)
}

fn push_message_box_escape_policy(eat_escape: bool) -> MessageBoxEscapeGuard {
    MESSAGE_BOX_ESCAPE.with(|slot| slot.borrow_mut().eat_escape.push(eat_escape));
    MessageBoxEscapeGuard
}

fn begin_message_box_escape_filter(
    eat_escape: bool,
) -> Result<MessageBoxEscapeGuard, RuntimeError> {
    let needs_hook = MESSAGE_BOX_ESCAPE.with(|slot| slot.borrow().hook.is_null());
    let guard = push_message_box_escape_policy(eat_escape);
    if !needs_hook {
        return Ok(guard);
    }
    let thread = crate::windows::win32_safe::current_thread_id();
    // SAFETY: The procedure is a static function. hmod is null because the
    // filter is limited to this thread. The returned HHOOK is an opaque host
    // handle, not a guest address.
    let hook = unsafe {
        SetWindowsHookExW(
            WH_MSGFILTER,
            Some(message_box_escape_proc),
            std::ptr::null_mut(),
            thread,
        )
    };
    if hook.is_null() {
        drop(guard);
        let error = crate::windows::win32_safe::last_error();
        return Err(RuntimeError::with_source(
            Kind::HostFailure,
            "install the Win16 message-box Escape filter",
            std::io::Error::from_raw_os_error(error as i32),
        ));
    }
    let stored = MESSAGE_BOX_ESCAPE.with(|slot| {
        let mut filter = slot.borrow_mut();
        if filter.hook.is_null() {
            filter.hook = hook;
            true
        } else {
            false
        }
    });
    if !stored {
        let _ = crate::windows::win32_safe::unhook_windows_hook(hook);
    }
    Ok(guard)
}

fn should_eat_escape(code: i32, l_param: isize) -> bool {
    let filter_code = u32::try_from(code).unwrap_or(u32::MAX);
    if code < 0
        || (filter_code != MSGF_DIALOGBOX as u32 && filter_code != MSGF_MESSAGEBOX as u32)
        || l_param == 0
    {
        return false;
    }
    let eat =
        MESSAGE_BOX_ESCAPE.with(|slot| slot.borrow().eat_escape.last().copied().unwrap_or(false));
    if !eat {
        return false;
    }
    // SAFETY: WH_MSGFILTER passes a pointer to the MSG Windows is filtering.
    // That pointer is valid for this call and is not a guest address.
    let message = unsafe { &*(l_param as *const MSG) };
    message.message == WM_KEYDOWN as u32 && message.wParam == VK_ESCAPE as usize
}

// SAFETY: Windows calls this function with the system ABI in its signature.
// Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn message_box_escape_proc(
    code: i32,
    w_param: usize,
    l_param: isize,
) -> isize {
    let eat = std::panic::catch_unwind(|| should_eat_escape(code, l_param)).unwrap_or(false);
    if eat {
        return 1;
    }
    // SAFETY: CallNextHookEx forwards the hook arguments Windows passed into this callback.
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, w_param, l_param) }
}

pub(super) fn message_box(
    codec: super::guest_text::GuestTextCodec,
    text: &[u8],
    caption: &[u8],
    style: u16,
) -> Result<u16, RuntimeError> {
    message_box_with_owner(codec, None, Some(text), Some(caption), style)
}

pub(super) fn message_box_with_owner(
    codec: super::guest_text::GuestTextCodec,
    owner: Option<HWND>,
    text: Option<&[u8]>,
    caption: Option<&[u8]>,
    style: u16,
) -> Result<u16, RuntimeError> {
    if text.is_some_and(|text| text.contains(&0))
        || caption.is_some_and(|caption| caption.contains(&0))
    {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 message box text contains an embedded NUL",
        ));
    }
    let text_z = text.map(|text| codec.to_wide_z(text)).transpose()?;
    let caption_z = caption
        .map(|caption| codec.to_wide_z(caption))
        .transpose()?;
    // Windows 3.1 ignores Escape when the box has no Cancel button.
    // MessageBoxW treats Escape as OK for MB_OK, so the filter eats that key.
    let _escape = begin_message_box_escape_filter(!message_box_style_has_cancel(style))?;

    // Preserve NULL separately from an empty string: MessageBoxW supplies
    // its own default caption for NULL, including the host's localization.
    // SAFETY: Present buffers are owned, NUL-terminated UTF-16 strings and
    // remain alive for this synchronous Windows call. `owner` is resolved
    // from the worker's opaque HWND table; no guest handle or guest pointer
    // crosses this boundary. A zero result remains the guest API's failure
    // return.
    let result = unsafe {
        MessageBoxW(
            owner.unwrap_or(std::ptr::null_mut()),
            text_z
                .as_ref()
                .map_or(std::ptr::null(), |text| text.as_ptr()),
            caption_z
                .as_ref()
                .map_or(std::ptr::null(), |caption| caption.as_ptr()),
            u32::from(style),
        )
    };
    Ok(result as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{message_box_style_has_cancel, push_message_box_escape_policy, should_eat_escape};
    use std::fs;
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MSG, MSGF_DIALOGBOX, MSGF_MESSAGEBOX, WM_KEYDOWN,
    };

    #[test]
    fn escape_does_nothing_when_the_message_box_has_no_cancel_button() {
        assert!(!message_box_style_has_cancel(0));
        assert!(message_box_style_has_cancel(1));
        assert!(!message_box_style_has_cancel(2));
        assert!(message_box_style_has_cancel(3));
        assert!(!message_box_style_has_cancel(4));
        assert!(message_box_style_has_cancel(5));
        assert!(!message_box_style_has_cancel(0x0030));
        assert!(message_box_style_has_cancel(0x0101));
        assert!(!message_box_style_has_cancel(0x2004));
        assert!(message_box_style_has_cancel(0x3005));

        let escape = MSG {
            hwnd: std::ptr::null_mut(),
            message: WM_KEYDOWN,
            wParam: 0x1B,
            lParam: 0,
            time: 0,
            pt: POINT { x: 0, y: 0 },
        };
        let escape_param = &escape as *const MSG as isize;
        let _outer = push_message_box_escape_policy(true);
        assert!(should_eat_escape(MSGF_DIALOGBOX as i32, escape_param));
        assert!(should_eat_escape(MSGF_MESSAGEBOX as i32, escape_param));
        {
            let _inner = push_message_box_escape_policy(false);
            assert!(!should_eat_escape(MSGF_DIALOGBOX as i32, escape_param));
        }
        assert!(should_eat_escape(MSGF_DIALOGBOX as i32, escape_param));
        assert!(!should_eat_escape(-1, escape_param));
        assert!(!should_eat_escape(2, escape_param));
        assert!(!should_eat_escape(MSGF_DIALOGBOX as i32, 0));
        let return_key = MSG {
            wParam: 0x0D,
            ..escape
        };
        assert!(!should_eat_escape(
            MSGF_DIALOGBOX as i32,
            &return_key as *const MSG as isize
        ));
    }

    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_directory() -> PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("win16-files-文件-{}-{id}", std::process::id()));
        fs::create_dir(&path).expect("create Unicode Win16 file test directory");
        path
    }

    fn guest_utf8_path(path: &Path) -> Vec<u8> {
        path.to_string_lossy().as_bytes().to_vec()
    }

    fn utf8_codec() -> GuestTextCodec {
        GuestTextCodec::new(65_001).expect("Windows UTF-8 code page")
    }

    #[test]
    fn invalid_guest_path_returns_a_file_failure() {
        let mut files = Win16Files::new();
        assert_eq!(files.open(utf8_codec(), &[0xff], 0).unwrap(), None);
        assert_eq!(files.create(utf8_codec(), &[0xff], 0).unwrap(), None);
    }

    #[test]
    fn lcreat_attributes_map_only_documented_values() {
        assert_eq!(create_attributes(0), Some(FILE_ATTRIBUTE_NORMAL));
        assert_eq!(create_attributes(1), Some(FILE_ATTRIBUTE_READONLY));
        assert_eq!(create_attributes(2), Some(FILE_ATTRIBUTE_HIDDEN));
        assert_eq!(create_attributes(4), Some(FILE_ATTRIBUTE_SYSTEM));
        assert_eq!(create_attributes(3), None);
    }

    #[test]
    fn createfilew_native_handle_preserves_unicode_io_and_zero_write_truncation() {
        let directory = temp_directory();
        let path = directory.join("資料.bin");
        let mut files = Win16Files::new();
        let guest_path = guest_utf8_path(&path);
        let file = files
            .create(utf8_codec(), &guest_path, 0)
            .expect("create through the guest text codec")
            .expect("CreateFileW should create the Unicode path");

        assert!(matches!(
            files.native_file(file),
            Some(Win16NativeFile::NativeHandle(_))
        ));
        assert_eq!(files.write(file, b"abcdef").unwrap(), Some(6));
        assert_eq!(files.seek(file, 2, 0).unwrap(), Some(2));
        assert_eq!(files.write(file, &[]).unwrap(), Some(0));
        assert_eq!(files.seek(file, 0, 0).unwrap(), Some(0));
        assert_eq!(files.read(file, 6).unwrap(), Some(b"ab".to_vec()));
        assert_eq!(files.read(file, 1).unwrap(), Some(Vec::new()));
        assert!(files.close(file).unwrap().closed);

        assert_eq!(fs::read(&path).expect("read created Unicode path"), b"ab");
        fs::remove_file(&path).expect("remove Unicode test file");
        fs::remove_dir(&directory).expect("remove Unicode test directory");
    }

    #[test]
    fn lopen_share_mode_mapping_keeps_deny_write_behavior() {
        let directory = temp_directory();
        let path = directory.join("sharing.dat");
        fs::write(&path, b"shared").expect("write test input");
        let guest_path = guest_utf8_path(&path);
        let codec = utf8_codec();
        let mut files = Win16Files::new();

        // OF_READ | OF_SHARE_DENY_WRITE. CreateFile's reciprocal share check
        // must reject a later write handle while this read handle is live.
        let reader = files
            .open(codec, &guest_path, 0x0020)
            .expect("open through the guest text codec")
            .expect("open read-only handle");
        assert_eq!(files.open(codec, &guest_path, 0x0041).unwrap(), None);
        assert_eq!(files.open(codec, &guest_path, 0x0003).unwrap(), None);
        assert!(files.close(reader).unwrap().closed);

        let writer = files
            .open(codec, &guest_path, 0x0041)
            .unwrap()
            .expect("deny-write share is released after close");
        assert!(files.close(writer).unwrap().closed);
        fs::remove_file(&path).expect("remove test file");
        fs::remove_dir(&directory).expect("remove test directory");
    }

    #[test]
    fn signed_file_position_accepts_only_a_nonnegative_long() {
        assert_eq!(signed_file_position(0), Some(0));
        assert_eq!(signed_file_position(i64::from(i32::MAX)), Some(i32::MAX));
        assert_eq!(signed_file_position(i64::from(i32::MAX) + 1), None);
        assert_eq!(signed_file_position(-1), None);
        assert_eq!(signed_file_position(i64::from(u32::MAX)), None);
    }

    #[test]
    fn llseek_rejects_positions_past_the_signed_result_without_moving() {
        let directory = temp_directory();
        let path = directory.join("seek.bin");
        let mut files = Win16Files::new();
        let guest_path = guest_utf8_path(&path);
        let file = files
            .create(utf8_codec(), &guest_path, 0)
            .expect("create through the guest text codec")
            .expect("CreateFileW should create the seek fixture");
        assert_eq!(files.write(file, b"ab").unwrap(), Some(2));
        assert_eq!(files.seek(file, i32::MAX, 0).unwrap(), Some(i32::MAX));
        assert_eq!(files.seek(file, 1, 1).unwrap(), None);
        assert_eq!(files.seek(file, 0, 1).unwrap(), Some(i32::MAX));
        assert_eq!(files.seek(file, 0, 3).unwrap(), None);
        assert_eq!(files.seek(file, 0, 0).unwrap(), Some(0));
        assert!(files.close(file).unwrap().closed);
        fs::remove_file(&path).expect("remove seek fixture");
        fs::remove_dir(&directory).expect("remove seek fixture directory");
    }
}

//! Synchronous KERNEL32 file services with native HANDLEs retained privately.

use std::ptr;
use core::ffi::c_void;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win32HostFileCall as C, Win32HostFindData,
    Win32HostImportValue as V, Win32HostSearchHandle, Win32ImportString as S,
    Win32ImportTextEncoding as X,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, SetLastError},
    Storage::FileSystem::{
        CopyFileW, CreateDirectoryW, CreateFileW, DeleteFileW, FlushFileBuffers,
        GetFileAttributesW, GetFileSize, GetFileSizeEx, GetFileType, MoveFileW, ReadFile,
        RemoveDirectoryW, SetEndOfFile, SetFileAttributesW, SetFilePointer, WriteFile,
        FILE_TYPE_UNKNOWN, FindClose, FindFirstFileW, FindFirstFileExW, FindNextFileW,
        WIN32_FIND_DATAW,
    },
};

use super::{Win32ImportSystem, api_error, result, set_api_error, text};

pub(super) fn execute(
    owner: &mut Win32ImportSystem, call: C,
) -> Result<runtime::Win32HostImportResult, RuntimeError> {
    match call {
        C::Create { path, desired_access, share_mode, creation_disposition,
            flags_and_attributes, template } => create(owner, path, desired_access,
                share_mode, creation_disposition, flags_and_attributes, template),
        C::Read { handle, capacity } => read(owner, handle, capacity),
        C::Write { handle, bytes } => write(owner, handle, bytes),
        C::Close { handle } => close(owner, handle),
        C::Delete { path } => delete(owner.codec, path),
        C::Move { from, to } => move_file(owner.codec, from, to),
        C::Copy { from, to, fail_if_exists } => copy_file(owner.codec, from, to, fail_if_exists),
        C::CreateDirectory { path } => create_directory(owner.codec, path),
        C::RemoveDirectory { path } => remove_directory(owner.codec, path),
        C::GetAttributes { path } => get_attributes(owner.codec, path),
        C::SetAttributes { path, attributes } => set_attributes(owner.codec, path, attributes),
        C::GetType { handle } => get_type(owner, handle),
        C::GetSize { handle, high_output } => get_size(owner, handle, high_output),
        C::GetSizeEx { handle } => get_size_ex(owner, handle),
        C::SetPointer { handle, low, high, method } => set_pointer(owner, handle, low, high, method),
        C::SetEndOfFile { handle } => unary_handle(owner, handle, "SetEndOfFile", |raw| {
            // SAFETY: raw is a live handle owned by this adapter.
            unsafe { SetEndOfFile(raw) }
        }),
        C::Flush { handle } => unary_handle(owner, handle, "FlushFileBuffers", |raw| {
            // SAFETY: raw is a live handle owned by this adapter.
            unsafe { FlushFileBuffers(raw) }
        }),
        C::FindFirst { path } => find_first(owner, path),
        C::FindFirstEx { path, information_level, search_operation, additional_flags } =>
            find_first_ex(owner, path, information_level, search_operation, additional_flags),
        C::FindNext { handle, encoding } => find_next(owner, handle, encoding),
        C::FindClose { handle } => close_search(owner, handle),
    }
}

fn find_first(owner: &mut Win32ImportSystem, path: S)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let id = owner.reserve_search_handle()?;
    let ansi = matches!(path, S::Ansi(_));
    let path = text::to_wide_z(owner.codec, path, "Win32 find path contains embedded NUL")?;
    let mut native = WIN32_FIND_DATAW::default();
    // SAFETY: path and output record are adapter-owned and valid for this
    // synchronous W call; no guest pointer crosses the host boundary.
    let raw = unsafe { FindFirstFileW(path.as_ptr(), &mut native) };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Ok(result(V::FindStart { handle: None, data: None }, Some(api_error())));
    }
    owner.publish_search_handle(id, raw);
    let data = match host_find_data(owner.codec, &native, ansi) {
        Ok(data) => data,
        Err(primary) => {
            if close_search_raw(raw) {
                let _ = owner.remove_search_handle(Win32HostSearchHandle::from_host_id(id));
            }
            return Err(primary);
        }
    };
    Ok(result(V::FindStart {
        handle: Some(Win32HostSearchHandle::from_host_id(id)), data: Some(data),
    }, None))
}

fn find_first_ex(owner: &mut Win32ImportSystem, path: S, information_level: u32,
    search_operation: u32, additional_flags: u32)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let id = owner.reserve_search_handle()?;
    let ansi = matches!(path, S::Ansi(_));
    let path = text::to_wide_z(owner.codec, path, "Win32 find path contains embedded NUL")?;
    let mut native = WIN32_FIND_DATAW::default();
    // SAFETY: only native-owned path and output memory are supplied; the PE32
    // filter pointer is validated NULL and remains native NULL here.
    let raw = unsafe { FindFirstFileExW(path.as_ptr(), information_level as i32,
        (&mut native as *mut WIN32_FIND_DATAW).cast::<c_void>(), search_operation as i32,
        ptr::null(), additional_flags) };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Ok(result(V::FindStart { handle: None, data: None }, Some(api_error())));
    }
    owner.publish_search_handle(id, raw);
    let data = match host_find_data(owner.codec, &native, ansi) {
        Ok(data) => data,
        Err(primary) => {
            if close_search_raw(raw) {
                let _ = owner.remove_search_handle(Win32HostSearchHandle::from_host_id(id));
            }
            return Err(primary);
        }
    };
    Ok(result(V::FindStart {
        handle: Some(Win32HostSearchHandle::from_host_id(id)), data: Some(data),
    }, None))
}

fn find_next(owner: &Win32ImportSystem, token: Win32HostSearchHandle, encoding: X)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let raw = owner.native_search_handle(token)?;
    match encoding {
        X::Ansi => {
            let mut data = WIN32_FIND_DATAW::default();
            // SAFETY: the table-owned search HANDLE and W output record remain
            // valid for this synchronous call.
            if unsafe { FindNextFileW(raw, &mut data) } != 0 {
                Ok(result(V::FindData(Some(host_find_data(owner.codec, &data, true)?)), None))
            } else { Ok(result(V::FindData(None), Some(api_error()))) }
        }
        X::Wide => {
            let mut data = WIN32_FIND_DATAW::default();
            // SAFETY: the search HANDLE and native output record remain owned
            // and valid for the duration of FindNextFileW.
            if unsafe { FindNextFileW(raw, &mut data) } != 0 {
                Ok(result(V::FindData(Some(host_find_data(owner.codec, &data, false)?)), None))
            } else {
                Ok(result(V::FindData(None), Some(api_error())))
            }
        }
    }
}

pub(super) fn close_search(owner: &mut Win32ImportSystem, token: Win32HostSearchHandle)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let raw = owner.native_search_handle(token)?;
    let closed = close_search_raw(raw);
    let error = (!closed).then(api_error);
    if closed { let _ = owner.remove_search_handle(token)?; }
    Ok(result(V::Bool(closed), error))
}

pub(super) fn close_search_raw(raw: HANDLE) -> bool {
    // SAFETY: callers pass only a live search HANDLE owned by the host table.
    unsafe { FindClose(raw) != 0 }
}

fn create(
    owner: &mut Win32ImportSystem,
    path: S,
    desired_access: u32,
    share_mode: u32,
    creation_disposition: u32,
    flags_and_attributes: u32,
    template: Option<runtime::Win32HostHandle>,
) -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let template = template.map(|token| owner.native_handle(token)).transpose()?.unwrap_or(ptr::null_mut());
    const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    if flags_and_attributes & (FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED) != 0 {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "native file mode needs aligned or pending I/O ownership"));
    }
    let id = owner.reserve_file_handle()?;
    let path = text::to_wide_z(owner.codec, path,
        "Win32 file path contains embedded NUL")?;
    // SAFETY: path is owned and terminated; security attributes are NULL and
    // the optional template is a validated host HANDLE token.
    let (raw, last_error) = unsafe {
        SetLastError(0);
        let raw = CreateFileW(path.as_ptr(), desired_access, share_mode, ptr::null(),
            creation_disposition, flags_and_attributes, template);
        (raw, windows_sys::Win32::Foundation::GetLastError())
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Ok(result(V::FileHandle(None), Some(last_error)));
    }
    owner.publish_file_handle(id, raw);
    // CREATE_ALWAYS and OPEN_ALWAYS define a successful LastError value:
    // zero for a new file or ERROR_ALREADY_EXISTS for an existing one.
    // Other successful CreateFile calls leave the guest's prior LastError
    // untouched even though the host TLS slot was cleared for capture.
    const CREATE_ALWAYS: u32 = 2;
    const OPEN_ALWAYS: u32 = 4;
    let report_success_error = matches!(creation_disposition, CREATE_ALWAYS | OPEN_ALWAYS);
    Ok(result(V::FileHandle(Some(runtime::Win32HostHandle::from_host_id(id))),
        report_success_error.then_some(last_error)))
}

fn read(owner: &Win32ImportSystem, token: runtime::Win32HostHandle, capacity: u32)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let length = usize::try_from(capacity).map_err(|_| exhausted("ReadFile output buffer"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve ReadFile output buffer", error))?;
    bytes.resize(length, 0);
    let mut count = 0_u32;
    let raw = owner.file_handle(token)?;
    // SAFETY: output buffer covers capacity bytes and count points to a local
    // DWORD. This synchronous path deliberately supplies no OVERLAPPED record.
    let success = unsafe { ReadFile(raw, bytes.as_mut_ptr(), capacity, &mut count, ptr::null_mut()) } != 0;
    if usize::try_from(count).map_or(true, |count| count > bytes.len()) {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "ReadFile returned more bytes than its checked output capacity"));
    }
    bytes.truncate(count as usize);
    let error = (!success).then(api_error);
    Ok(result(V::Transfer { success, bytes, count }, error))
}

fn write(owner: &Win32ImportSystem, token: runtime::Win32HostHandle, bytes: Vec<u8>)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let length = u32::try_from(bytes.len()).map_err(|_| exhausted("WriteFile input size"))?;
    let mut count = 0_u32;
    let raw = owner.file_handle(token)?;
    // SAFETY: input points to the owned byte vector for the duration of this
    // synchronous call; no asynchronous view escapes the adapter.
    let success = unsafe { WriteFile(raw, bytes.as_ptr(), length, &mut count, ptr::null_mut()) } != 0;
    if count > length {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "WriteFile returned a byte count larger than its input"));
    }
    let error = (!success).then(api_error);
    Ok(result(V::Transfer { success, bytes: Vec::new(), count }, error))
}

pub(super) fn close(owner: &mut Win32ImportSystem, token: runtime::Win32HostHandle)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let raw = owner.file_handle(token)?;
    // SAFETY: raw remains table-owned until a successful close removes it.
    let closed = unsafe { CloseHandle(raw) } != 0;
    let error = (!closed).then(api_error);
    if closed { let _ = owner.remove_file_handle(token)?; }
    Ok(result(V::Bool(closed), error))
}

fn delete(codec: super::super::guest_text::GuestTextCodec, path: S)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let path = text::to_wide_z(codec, path, "Win32 file path contains embedded NUL")?;
    // SAFETY: path is an owned, terminated UTF-16 name.
    let success = unsafe { DeleteFileW(path.as_ptr()) != 0 };
    Ok(bool_result(success, true))
}

fn move_file(codec: super::super::guest_text::GuestTextCodec, from: S, to: S)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    if from.encoding() != to.encoding() { return Err(contract("MoveFile paths use different encodings")); }
    let from = text::to_wide_z(codec, from, "Win32 source path contains embedded NUL")?;
    let to = text::to_wide_z(codec, to, "Win32 destination path contains embedded NUL")?;
    // SAFETY: both native input names are owned UTF-16 strings and remain live.
    let success = unsafe { MoveFileW(from.as_ptr(), to.as_ptr()) != 0 };
    Ok(bool_result(success, true))
}

fn copy_file(codec: super::super::guest_text::GuestTextCodec, from: S, to: S, fail_if_exists: bool)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let fail_if_exists = i32::from(fail_if_exists);
    if from.encoding() != to.encoding() { return Err(contract("CopyFile paths use different encodings")); }
    let from = text::to_wide_z(codec, from, "Win32 source path contains embedded NUL")?;
    let to = text::to_wide_z(codec, to, "Win32 destination path contains embedded NUL")?;
    // SAFETY: both native input names are owned UTF-16 strings and remain live.
    let success = unsafe { CopyFileW(from.as_ptr(), to.as_ptr(), fail_if_exists) != 0 };
    Ok(bool_result(success, true))
}

fn create_directory(codec: super::super::guest_text::GuestTextCodec, path: S)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let path = text::to_wide_z(codec, path, "Win32 directory path contains embedded NUL")?;
    // SAFETY: path is terminated; this service uses NULL security attributes.
    let success = unsafe { CreateDirectoryW(path.as_ptr(), ptr::null()) != 0 };
    Ok(bool_result(success, true))
}

fn remove_directory(codec: super::super::guest_text::GuestTextCodec, path: S)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let path = text::to_wide_z(codec, path, "Win32 directory path contains embedded NUL")?;
    // SAFETY: path is an owned, terminated UTF-16 name.
    let success = unsafe { RemoveDirectoryW(path.as_ptr()) != 0 };
    Ok(bool_result(success, true))
}

fn get_attributes(codec: super::super::guest_text::GuestTextCodec, path: S)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let path = text::to_wide_z(codec, path, "Win32 file path contains embedded NUL")?;
    // SAFETY: path is an owned, terminated UTF-16 name.
    let value = unsafe { GetFileAttributesW(path.as_ptr()) };
    let error = (value == u32::MAX).then(api_error);
    Ok(result(V::Dword(value), error))
}

fn set_attributes(codec: super::super::guest_text::GuestTextCodec, path: S, attributes: u32)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let path = text::to_wide_z(codec, path, "Win32 file path contains embedded NUL")?;
    // SAFETY: path is terminated; the native attribute DWORD is preserved.
    let success = unsafe { SetFileAttributesW(path.as_ptr(), attributes) != 0 };
    Ok(bool_result(success, true))
}

fn host_find_data(codec: super::super::guest_text::GuestTextCodec,
    data: &WIN32_FIND_DATAW, ansi: bool) -> Result<Win32HostFindData, RuntimeError> {
    let common = (data.dwFileAttributes,
        data.ftCreationTime.dwLowDateTime, data.ftCreationTime.dwHighDateTime,
        data.ftLastAccessTime.dwLowDateTime, data.ftLastAccessTime.dwHighDateTime,
        data.ftLastWriteTime.dwLowDateTime, data.ftLastWriteTime.dwHighDateTime,
        data.nFileSizeHigh, data.nFileSizeLow, data.dwReserved0, data.dwReserved1);
    if ansi {
        Ok(Win32HostFindData::Ansi {
            attributes: common.0,
            creation_time_low: common.1, creation_time_high: common.2,
            last_access_time_low: common.3, last_access_time_high: common.4,
            last_write_time_low: common.5, last_write_time_high: common.6,
            file_size_high: common.7, file_size_low: common.8,
            reserved0: common.9, reserved1: common.10,
            file_name: text::fixed_ansi(codec, &data.cFileName,
                "successful FindFirst/FindNext W returned unterminated filename")?,
            alternate_file_name: text::fixed_ansi(codec, &data.cAlternateFileName,
                "successful FindFirst/FindNext W returned unterminated alternate filename")?,
        })
    } else {
        Ok(Win32HostFindData::Wide {
            attributes: common.0,
            creation_time_low: common.1, creation_time_high: common.2,
            last_access_time_low: common.3, last_access_time_high: common.4,
            last_write_time_low: common.5, last_write_time_high: common.6,
            file_size_high: common.7, file_size_low: common.8,
            reserved0: common.9, reserved1: common.10,
            file_name: data.cFileName,
            alternate_file_name: data.cAlternateFileName,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::guest_text::GuestTextCodec;

    fn cp936() -> GuestTextCodec {
        GuestTextCodec::new(936).expect("Windows should provide code page 936")
    }

    #[test]
    fn find_data_ansi_projection_preserves_fixed_fields_and_guest_byte_arrays() {
        let codec = cp936();
        let mut native = WIN32_FIND_DATAW::default();
        native.dwFileAttributes = 0x20;
        native.ftCreationTime.dwLowDateTime = 1;
        native.ftCreationTime.dwHighDateTime = 2;
        native.ftLastAccessTime.dwLowDateTime = 3;
        native.ftLastAccessTime.dwHighDateTime = 4;
        native.ftLastWriteTime.dwLowDateTime = 5;
        native.ftLastWriteTime.dwHighDateTime = 6;
        native.nFileSizeHigh = 7;
        native.nFileSizeLow = 8;
        native.dwReserved0 = 9;
        native.dwReserved1 = 10;
        native.cFileName[..3].copy_from_slice(&[0x4e2d, b'A' as u16, 0]);
        native.cAlternateFileName[..2].copy_from_slice(&[b'B' as u16, 0]);

        let projected = host_find_data(codec, &native, true).unwrap();
        let Win32HostFindData::Ansi { attributes, creation_time_low,
            creation_time_high, last_access_time_low, last_access_time_high,
            last_write_time_low, last_write_time_high, file_size_high,
            file_size_low, reserved0, reserved1, file_name, alternate_file_name } = projected else {
            panic!("ANSI guest path must use the ANSI fixed-field record");
        };
        assert_eq!((attributes, creation_time_low, creation_time_high), (0x20, 1, 2));
        assert_eq!((last_access_time_low, last_access_time_high), (3, 4));
        assert_eq!((last_write_time_low, last_write_time_high), (5, 6));
        assert_eq!((file_size_high, file_size_low, reserved0, reserved1), (7, 8, 9, 10));
        assert_eq!(&file_name[..4], &[0xd6, 0xd0, b'A', 0]);
        assert_eq!(&alternate_file_name[..2], &[b'B', 0]);
    }

    #[test]
    fn find_data_wide_projection_preserves_native_fixed_width_arrays() {
        let mut native = WIN32_FIND_DATAW::default();
        native.cFileName[..2].copy_from_slice(&[0x4e2d, 0]);
        native.cAlternateFileName[..2].copy_from_slice(&[b'X' as u16, 0]);
        let projected = host_find_data(cp936(), &native, false).unwrap();
        let Win32HostFindData::Wide { file_name, alternate_file_name, .. } = projected else {
            panic!("wide guest path must use the wide fixed-field record");
        };
        assert_eq!(&file_name[..2], &[0x4e2d, 0]);
        assert_eq!(&alternate_file_name[..2], &[b'X' as u16, 0]);
        assert_eq!(file_name.len(), 260);
        assert_eq!(alternate_file_name.len(), 14);
    }
}

fn get_type(owner: &Win32ImportSystem, token: runtime::Win32HostHandle)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let raw = owner.file_handle(token)?;
    set_api_error(0);
    // SAFETY: raw is a live, table-owned file HANDLE.
    let value = unsafe { GetFileType(raw) };
    let error = (value == FILE_TYPE_UNKNOWN).then(api_error).filter(|error| *error != 0);
    Ok(result(V::Dword(value), error))
}

fn get_size(owner: &Win32ImportSystem, token: runtime::Win32HostHandle, high_output: bool)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let raw = owner.file_handle(token)?;
    let mut high = 0_u32;
    set_api_error(0);
    // SAFETY: raw is owned and high is either the requested local output or NULL.
    let low = unsafe { GetFileSize(raw, if high_output { &mut high } else { ptr::null_mut() }) };
    let error_code = api_error();
    let success = low != u32::MAX || error_code == 0;
    Ok(result(V::FileSize { success, low, high: high_output.then_some(high) },
        (!success).then_some(error_code)))
}

fn get_size_ex(owner: &Win32ImportSystem, token: runtime::Win32HostHandle)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let raw = owner.file_handle(token)?;
    let mut size = 0_i64;
    // SAFETY: raw is owned and size points to a local writable 64-bit integer.
    let success = unsafe { GetFileSizeEx(raw, &mut size) } != 0;
    Ok(result(V::FileSize { success, low: size as u64 as u32,
        high: Some((size as u64 >> 32) as u32) }, (!success).then(api_error)))
}

fn set_pointer(owner: &Win32ImportSystem, token: runtime::Win32HostHandle,
    low: i32, high: Option<i32>, method: u32)
    -> Result<runtime::Win32HostImportResult, RuntimeError> {
    let raw = owner.file_handle(token)?;
    let mut high_output = high.unwrap_or(0);
    set_api_error(0);
    // SAFETY: raw is owned; high is passed only when the guest supplied it and
    // otherwise NULL preserves SetFilePointer's low-DWORD-only contract.
    let position = unsafe { SetFilePointer(raw, low,
        high.map_or(ptr::null_mut(), |_| &mut high_output), method) };
    let error_code = api_error();
    let success = position != u32::MAX || error_code == 0;
    Ok(result(V::FilePosition { success, low: position,
        high: high.map(|_| high_output) }, (!success).then_some(error_code)))
}

fn unary_handle<F>(owner: &Win32ImportSystem, token: runtime::Win32HostHandle,
    _name: &'static str, call: F) -> Result<runtime::Win32HostImportResult, RuntimeError>
where F: FnOnce(HANDLE) -> i32 {
    let raw = owner.file_handle(token)?;
    let success = call(raw) != 0;
    Ok(bool_result(success, true))
}

fn bool_result(success: bool, last_error: bool) -> runtime::Win32HostImportResult {
    result(V::Bool(success), (last_error && !success).then(api_error))
}

fn contract(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn exhausted(resource: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!("{resource} exhausted"))
}

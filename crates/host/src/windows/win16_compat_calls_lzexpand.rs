//! Native Windows LZEXPAND services for the checked Win16 HFILE bridge.

use super::bindings::{
    LZClose, LZCopy, LZDone, LZInit,
    LZRead, LZSeek, LZStart, OF_CREATE, OF_DELETE, OF_EXIST, OF_PARSE, OF_READ, OF_READWRITE,
    OF_WRITE,
};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostFile, Win16HostFileClose, Win16HostLzInit,
    Win16HostLzRead,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_SYSTEM_RESOURCES,
    ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY,
    ERROR_TOO_MANY_OPEN_FILES, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_BEGIN, FILE_CURRENT, FILE_END, ReadFile, SetFilePointerEx,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::win16::{Win16Files, Win16LzNative, Win16NativeFile};

const LZERROR_BADINHANDLE: i16 = -1;
const LZERROR_BADOUTHANDLE: i16 = -2;
const LZERROR_GLOBALLOC: i16 = -5;

pub(super) fn init(
    files: &mut Win16Files,
    file: Win16HostFile,
    can_create_stream: bool,
) -> Result<Win16HostLzInit, RuntimeError> {
    let source = match files.native_file(file) {
        Some(Win16NativeFile::NativeHandle(handle)) => handle,
        Some(Win16NativeFile::LzHandle(_)) => return Ok(Win16HostLzInit::File(file)),
        None => return Ok(Win16HostLzInit::Error(LZERROR_BADINHANDLE)),
    };
    if !can_create_stream {
        return Ok(Win16HostLzInit::Error(LZERROR_GLOBALLOC));
    }
    let duplicate_result = duplicate_kernel_file_handle(source)?;
    let duplicate = match duplicate_result {
        Ok(duplicate) => duplicate,
        Err(error) => return Ok(Win16HostLzInit::Error(error)),
    };
    // SAFETY: `duplicate` is an owned kernel file handle whose complete value
    // was checked to fit HFILE. Windows' 64-bit interoperability contract and
    // the existing Win16 LZ thunk bridge this representation. DuplicateHandle
    // gives the LZ token independent ownership while sharing the file cursor.
    let native_lz_handle = unsafe { LZInit(duplicate) };
    if native_lz_handle < 0 {
        // SAFETY: LZInit failed and did not yield an owned LZ token; the
        // duplicate is still our kernel HANDLE, so close it with CloseHandle.
        unsafe { CloseHandle(hfile_as_kernel_handle(duplicate)) };
        return Ok(Win16HostLzInit::Error(signed_lz_result(native_lz_handle)?));
    }
    let retained = files.retain_native(Win16NativeFile::LzHandle(Win16LzNative {
        handle: native_lz_handle,
        source_alias: Some(file),
    }))?;
    match retained {
        Some(file) => Ok(Win16HostLzInit::File(file)),
        None => {
            // `retain_native` normally returns a token or a typed error. If
            // that contract changes, release only the duplicate-backed LZ
            // token; the guest's source file remains open and owned.
            // SAFETY: Windows returned this live LZ token above.
            unsafe { LZClose(native_lz_handle) };
            Ok(Win16HostLzInit::Error(-5))
        }
    }
}

pub(super) fn read(
    files: &Win16Files,
    file: Win16HostFile,
    count: u16,
) -> Result<Option<Win16HostLzRead>, RuntimeError> {
    let Some(native) = files.native_file(file) else {
        return Ok(None);
    };
    let length = usize::from(count);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length.max(1)).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate native LZRead buffer",
            error,
        )
    })?;
    bytes.resize(length.max(1), 0);
    // SAFETY: `bytes` owns the bounded output region; the native LZ handle
    // belongs to this Win16Files instance and no guest address crosses here.
    let result = match native {
        Win16NativeFile::NativeHandle(handle) => {
            let mut bytes_read = 0_u32;
            // SAFETY: `handle` is an owned CreateFileW file HANDLE and `bytes`
            // is a local output buffer. The guest only supplied the bounded
            // u16 request count; no guest pointer is passed to ReadFile.
            if unsafe {
                ReadFile(
                    handle,
                    bytes.as_mut_ptr().cast(),
                    u32::from(count),
                    &mut bytes_read,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Ok(Some(Win16HostLzRead::Error(LZERROR_BADINHANDLE)));
            }
            i32::try_from(bytes_read).map_err(|error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "native HANDLE read length does not fit i32",
                    error,
                )
            })?
        }
        Win16NativeFile::LzHandle(lz) => {
            // SAFETY: `bytes` owns the bounded output region and `lz.handle`
            // belongs to the native LZ table.
            unsafe { LZRead(lz.handle, bytes.as_mut_ptr().cast(), i32::from(count)) }
        }
    };
    if result < 0 {
        return Ok(Some(Win16HostLzRead::Error(signed_lz_result(result)?)));
    }
    let read = usize::try_from(result).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "native LZRead length does not fit host memory",
            error,
        )
    })?;
    if read > length {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native LZRead exceeded the requested guest byte count",
        ));
    }
    bytes.truncate(read);
    Ok(Some(Win16HostLzRead::Bytes(bytes)))
}

pub(super) fn seek(
    files: &Win16Files,
    file: Win16HostFile,
    offset: i32,
    origin: u16,
) -> Result<Option<i32>, RuntimeError> {
    let Some(native) = files.native_file(file) else {
        return Ok(None);
    };
    // SAFETY: This is the owned native LZ handle; scalar arguments are copied
    // guest values and no guest pointer is passed to Windows.
    let result = match native {
        Win16NativeFile::NativeHandle(handle) => {
            let method = match origin {
                0 => FILE_BEGIN,
                1 => FILE_CURRENT,
                2 => FILE_END,
                _ => return Ok(Some(-1)),
            };
            let mut position = 0_i64;
            // SAFETY: `handle` is an owned CreateFileW file HANDLE and the
            // scalar offset/origin were checked before the synchronous call.
            if unsafe { SetFilePointerEx(handle, i64::from(offset), &mut position, method) } == 0 {
                -1
            } else {
                i32::try_from(position).unwrap_or(-1)
            }
        }
        Win16NativeFile::LzHandle(lz) => {
            // SAFETY: `lz.handle` is the native LZ token retained by Win16Files.
            unsafe { LZSeek(lz.handle, offset, i32::from(origin)) }
        }
    };
    Ok(Some(result))
}

pub(super) fn close(
    files: &mut Win16Files,
    file: Win16HostFile,
) -> Result<Win16HostFileClose, RuntimeError> {
    files.close(file)
}

pub(super) fn copy(
    files: &Win16Files,
    source: Win16HostFile,
    destination: Win16HostFile,
) -> Result<Option<i32>, RuntimeError> {
    let Some(source_native) = files.native_file(source) else {
        return Ok(None);
    };
    let Some(destination_native) = files.native_file(destination) else {
        return Ok(Some(i32::from(LZERROR_BADOUTHANDLE)));
    };
    if matches!(destination_native, Win16NativeFile::LzHandle(_)) {
        return Ok(Some(i32::from(LZERROR_BADOUTHANDLE)));
    }
    let source_temporary = match source_native {
        Win16NativeFile::NativeHandle(handle) => match temporary_lz_handle_from_kernel(handle)? {
            Ok(handle) => Some(handle),
            Err(error) => return Ok(Some(i32::from(error))),
        },
        Win16NativeFile::LzHandle(_) => None,
    };
    let destination_temporary = match destination_native {
        Win16NativeFile::NativeHandle(handle) => match temporary_hfile_from_kernel(handle)? {
            Ok(handle) => handle,
            Err(LZERROR_BADINHANDLE) => return Ok(Some(i32::from(LZERROR_BADOUTHANDLE))),
            Err(error) => return Ok(Some(i32::from(error))),
        },
        Win16NativeFile::LzHandle(_) => return Ok(Some(i32::from(LZERROR_BADOUTHANDLE))),
    };
    let source_handle = match (source_native, source_temporary.as_ref()) {
        (Win16NativeFile::NativeHandle(_), Some(temporary)) => temporary.handle,
        (Win16NativeFile::NativeHandle(_), None) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native LZCopy source lacks its temporary LZ wrapper",
            ));
        }
        (Win16NativeFile::LzHandle(lz), _) => lz.handle,
    };
    // SAFETY: LZCopy takes an LZ/HFILE source and a raw writable HFILE
    // destination. Duplicated ordinary/kernel file handles are checked before
    // entering that API and the RAII wrapper keeps the destination alive.
    let destination_handle = destination_temporary.handle;
    let result = unsafe { LZCopy(source_handle, destination_handle) };
    Ok(Some(result))
}

struct TemporaryHFile {
    handle: i32,
}

impl Drop for TemporaryHFile {
    fn drop(&mut self) {
        // SAFETY: This exact kernel HANDLE was returned by DuplicateHandle,
        // checked to fit HFILE, and is still owned by this guard.
        unsafe { CloseHandle(hfile_as_kernel_handle(self.handle)) };
    }
}

struct TemporaryLzHandle {
    handle: i32,
}

impl Drop for TemporaryLzHandle {
    fn drop(&mut self) {
        // SAFETY: This token was returned by a successful LZInit on an owned
        // duplicate and has not been closed elsewhere.
        unsafe { LZClose(self.handle) };
    }
}

fn temporary_lz_handle_from_kernel(
    source: HANDLE,
) -> Result<Result<TemporaryLzHandle, i16>, RuntimeError> {
    let duplicate = match duplicate_kernel_file_handle(source)? {
        Ok(duplicate) => duplicate,
        Err(error) => return Ok(Err(error)),
    };
    initialize_duplicate_lz_handle(duplicate)
}

fn initialize_duplicate_lz_handle(
    duplicate: i32,
) -> Result<Result<TemporaryLzHandle, i16>, RuntimeError> {
    // SAFETY: The duplicate is a same-access native file handle. LZInit may
    // return zero for an ordinary stream; every nonnegative result is valid.
    let initialized = unsafe { LZInit(duplicate) };
    if initialized < 0 {
        // SAFETY: No LZ token was returned; release the duplicate kernel
        // HANDLE directly because this helper owns the DuplicateHandle result.
        unsafe { CloseHandle(hfile_as_kernel_handle(duplicate)) };
        return Ok(Err(signed_lz_result(initialized)?));
    }
    Ok(Ok(TemporaryLzHandle {
        handle: initialized,
    }))
}

fn temporary_hfile_from_kernel(
    source: HANDLE,
) -> Result<Result<TemporaryHFile, i16>, RuntimeError> {
    duplicate_kernel_file_handle(source)
        .map(|result| result.map(|handle| TemporaryHFile { handle }))
}

fn duplicate_kernel_file_handle(source: HANDLE) -> Result<Result<i32, i16>, RuntimeError> {
    // This bridge is called only for owned file HANDLEs stored in
    // NativeHandle. Reject sentinel/non-file values and any HANDLE whose
    // complete signed value cannot be represented by HFILE; never truncate.
    if checked_hfile_from_kernel_handle(source).is_none() {
        return Ok(Err(LZERROR_BADINHANDLE));
    }
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate: HANDLE = std::ptr::null_mut();
    // SAFETY: Both process values are this process's pseudo handle, source is
    // an owned kernel file handle, and output owns one HANDLE slot.
    let success = unsafe {
        DuplicateHandle(
            process,
            source,
            process,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if success == 0 {
        // DuplicateHandle supplies a Win32 error; LZ callers receive their
        // documented handle/resource error rather than an execution failure.
        let error = unsafe { GetLastError() };
        return Ok(Err(match error {
            ERROR_NOT_ENOUGH_MEMORY
            | ERROR_OUTOFMEMORY
            | ERROR_NO_SYSTEM_RESOURCES
            | ERROR_TOO_MANY_OPEN_FILES => LZERROR_GLOBALLOC,
            _ => LZERROR_BADINHANDLE,
        }));
    }
    let Some(duplicate_hfile) = checked_hfile_from_kernel_handle(duplicate) else {
        // SAFETY: DuplicateHandle succeeded and this output HANDLE is ours.
        unsafe { CloseHandle(duplicate) };
        return Ok(Err(LZERROR_BADINHANDLE));
    };
    Ok(Ok(duplicate_hfile))
}

fn checked_hfile_from_kernel_handle(handle: HANDLE) -> Option<i32> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return None;
    }
    // Windows documents x86/x64 handle interoperability
    // (https://learn.microsoft.com/en-us/windows/win32/winprog64/interprocess-communication),
    // and the existing Win16 LZ thunk passes file HANDLEs as HFILEs. Keep only
    // exact positive signed-i32 values; never truncate. The full 64-bit handle
    // range has not been validated for the LZ APIs.
    let value = i32::try_from(handle as isize).ok()?;
    (value > 0).then_some(value)
}

fn hfile_as_kernel_handle(handle: i32) -> HANDLE {
    // HFILE is signed; sign extension restores its documented 64-bit HANDLE
    // interoperability representation without deriving a host pointer.
    handle as isize as HANDLE
}

pub(super) fn start() -> Result<i16, RuntimeError> {
    // SAFETY: LZStart has no pointer arguments or state preconditions.
    signed_lz_result(unsafe { LZStart() })
}

pub(super) fn done() {
    // SAFETY: LZDone has no pointer arguments; Windows owns its internal LZ
    // subsystem bookkeeping.
    unsafe { LZDone() };
}

fn signed_lz_result(result: i32) -> Result<i16, RuntimeError> {
    i16::try_from(result).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "native LZ result does not fit the Win16 signed HFILE result",
            error,
        )
    })
}

fn is_action_only_style(style: i32) -> bool {
    style & (OF_DELETE | OF_EXIST | OF_PARSE) != 0
}

pub(super) fn is_lz_read_style(style: i32) -> bool {
    let access = style & (OF_READ | OF_WRITE | OF_READWRITE);
    access == OF_READ && style & OF_CREATE == 0 && !is_action_only_style(style)
}

#[cfg(test)]
#[path = "win16_compat_calls_lzexpand_tests.rs"]
mod tests;

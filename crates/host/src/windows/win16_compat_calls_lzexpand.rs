//! Native Windows LZEXPAND services for the checked Win16 HFILE bridge.

use std::mem::size_of;

use super::bindings::{
    _lclose, _llseek, _lread, GetExpandedNameW, LZClose, LZCopy, LZDone, LZInit, LZOpenFileW,
    LZRead, LZSeek, LZStart, OF_CREATE, OF_DELETE, OF_EXIST, OF_PARSE, OF_READ, OF_READWRITE,
    OF_REOPEN, OF_WRITE, OFSTRUCT,
};
use super::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostFile, Win16HostFileClose, Win16HostLzInit,
    Win16HostLzName, Win16HostLzOpen, Win16HostLzRead,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_SYSTEM_RESOURCES,
    ERROR_NO_UNICODE_TRANSLATION, ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY,
    ERROR_TOO_MANY_OPEN_FILES, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Globalization::GetOEMCP;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_BEGIN, FILE_CURRENT, FILE_END, ReadFile, SetFilePointerEx,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::win16::{Win16Files, Win16LzNative, Win16NativeFile};

const OFSTRUCT_BYTES: usize = 136;
const MAX_PATH_UNITS: usize = 260;
const MAX_WIDE_PATH_UNITS: usize = 32 * 1024;
const LZERROR_BADINHANDLE: i16 = -1;
const LZERROR_BADOUTHANDLE: i16 = -2;
const LZERROR_GLOBALLOC: i16 = -5;
const LZERROR_BADVALUE: i16 = -7;

pub(super) fn open_file(
    files: &mut Win16Files,
    codec: GuestTextCodec,
    path: &[u8],
    style: u16,
    previous_ofstruct: Vec<u8>,
) -> Result<Win16HostLzOpen, RuntimeError> {
    if previous_ofstruct.len() != OFSTRUCT_BYTES || size_of::<OFSTRUCT>() != OFSTRUCT_BYTES {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 LZOpenFile requires a complete 136-byte OFSTRUCT",
        ));
    }
    let style_flags = i32::from(style);
    let mut output = match decode_ofstruct(&previous_ofstruct, codec, style_flags & OF_REOPEN != 0)
    {
        Ok(output) => output,
        Err(error) if is_guest_path_conversion_error(&error) => {
            return Ok(Win16HostLzOpen {
                result: LZERROR_BADINHANDLE,
                file: None,
                ofstruct: previous_ofstruct,
            });
        }
        Err(error) => return Err(error),
    };
    let path_wide_z = match guest_wide_z(codec, path, "Win16 LZOpenFile path") {
        Ok(Some(path)) => path,
        Ok(None) => {
            return Ok(Win16HostLzOpen {
                result: LZERROR_BADINHANDLE,
                file: None,
                ofstruct: previous_ofstruct,
            });
        }
        Err(error) if is_guest_path_conversion_error(&error) => {
            return Ok(Win16HostLzOpen {
                result: LZERROR_BADINHANDLE,
                file: None,
                ofstruct: previous_ofstruct,
            });
        }
        Err(error) => return Err(error),
    };

    let action_only = is_action_only_style(style_flags);
    let read_mode = is_lz_read_style(style_flags);
    // LZOpenFileW is the W entry point for every LZOpenFile style, including
    // OF_WRITE, OF_READWRITE, and OF_CREATE. For styles other than OF_READ it
    // returns an ordinary HFILE suitable for the shared Win16 HFILE API; only
    // OF_READ may return the special LZ token used by LZRead/LZSeek/LZClose.
    // SAFETY: `path_wide_z` is owned and NUL terminated. Its OFSTRUCT path
    // field is OEM-encoded as documented by LZOpenFileW.
    let opened = unsafe { LZOpenFileW(path_wide_z.as_ptr(), &mut output, style) };
    let mut ofstruct = previous_ofstruct;
    if let Err(error) = encode_ofstruct(codec, &output, &mut ofstruct) {
        if !action_only && opened >= 0 {
            if read_mode {
                // SAFETY: Successful LZOpenFileW yielded an owned native token.
                unsafe { LZClose(opened) };
            } else {
                // SAFETY: Successful non-OF_READ LZOpenFileW returned an
                // owned ordinary HFILE.
                unsafe { _lclose(opened) };
            }
        }
        return Err(error);
    }
    if opened < 0 {
        return Ok(Win16HostLzOpen {
            result: signed_lz_result(opened)?,
            file: None,
            ofstruct,
        });
    }

    // These modes complete an action without returning a live HFILE. Preserve
    // the native success value and keep the OS's already-closed handle out of
    // the owned file table.
    if action_only {
        return Ok(Win16HostLzOpen {
            result: signed_lz_result(opened)?,
            file: None,
            ofstruct,
        });
    }

    // A successful LZOpenFile read returns a native LZ token for both plain
    // and compressed input. Do not infer its kind from the numeric value.
    // Write modes remain ordinary HFILEs so shared KERNEL file writes use the
    // native DOS file API; LZEXPAND has no LZWrite operation.
    let kind = if read_mode {
        Win16NativeFile::LzHandle(Win16LzNative {
            handle: opened,
            source_alias: None,
        })
    } else {
        Win16NativeFile::Ordinary(opened)
    };
    let file = files.retain_native(kind)?;
    Ok(Win16HostLzOpen {
        result: 0,
        file,
        ofstruct,
    })
}

fn is_guest_path_conversion_error(error: &RuntimeError) -> bool {
    error.kind() == Kind::InvalidInput
        || (error.kind() == Kind::HostFailure
            && unsafe { GetLastError() } == ERROR_NO_UNICODE_TRANSLATION)
}

pub(super) fn init(
    files: &mut Win16Files,
    file: Win16HostFile,
    can_create_stream: bool,
) -> Result<Win16HostLzInit, RuntimeError> {
    let Some(native) = files.native_file(file) else {
        return Ok(Win16HostLzInit::Error(LZERROR_BADINHANDLE));
    };
    let source = match native {
        Win16NativeFile::Ordinary(source) => Some(source),
        Win16NativeFile::NativeHandle(_) => None,
        Win16NativeFile::LzHandle(_) => return Ok(Win16HostLzInit::File(file)),
    };
    if !can_create_stream {
        return Ok(Win16HostLzInit::Error(LZERROR_GLOBALLOC));
    }
    let duplicate_result = match (native, source) {
        (Win16NativeFile::Ordinary(_), Some(source)) => duplicate_hfile(source)?,
        (Win16NativeFile::NativeHandle(handle), None) => duplicate_kernel_file_handle(handle)?,
        _ => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 LZInit source changed while selecting its native bridge",
            ));
        }
    };
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
        Win16NativeFile::Ordinary(handle) => {
            // SAFETY: `bytes` owns the output buffer and this is the original
            // ordinary HFILE path used for non-LZ Win16 file handles.
            let read = unsafe { _lread(handle, bytes.as_mut_ptr().cast(), u32::from(count)) };
            if read == u32::MAX {
                return Ok(Some(Win16HostLzRead::Error(LZERROR_BADINHANDLE)));
            }
            i32::try_from(read).map_err(|error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "native HFILE read length does not fit i32",
                    error,
                )
            })?
        }
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
        Win16NativeFile::Ordinary(handle) => {
            // SAFETY: The ordinary HFILE is retained by Win16Files.
            unsafe { _llseek(handle, offset, i32::from(origin)) }
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
        Win16NativeFile::Ordinary(handle) => match temporary_lz_handle(handle)? {
            Ok(handle) => Some(handle),
            Err(error) => return Ok(Some(i32::from(error))),
        },
        Win16NativeFile::NativeHandle(handle) => match temporary_lz_handle_from_kernel(handle)? {
            Ok(handle) => Some(handle),
            Err(error) => return Ok(Some(i32::from(error))),
        },
        Win16NativeFile::LzHandle(_) => None,
    };
    let destination_temporary = match destination_native {
        Win16NativeFile::Ordinary(handle) => match temporary_hfile_from_hfile(handle)? {
            Ok(handle) => handle,
            Err(LZERROR_BADINHANDLE) => return Ok(Some(i32::from(LZERROR_BADOUTHANDLE))),
            Err(error) => return Ok(Some(i32::from(error))),
        },
        Win16NativeFile::NativeHandle(handle) => match temporary_hfile_from_kernel(handle)? {
            Ok(handle) => handle,
            Err(LZERROR_BADINHANDLE) => return Ok(Some(i32::from(LZERROR_BADOUTHANDLE))),
            Err(error) => return Ok(Some(i32::from(error))),
        },
        Win16NativeFile::LzHandle(_) => return Ok(Some(i32::from(LZERROR_BADOUTHANDLE))),
    };
    let source_handle = match (source_native, source_temporary.as_ref()) {
        (Win16NativeFile::Ordinary(_), Some(temporary)) => temporary.handle,
        (Win16NativeFile::Ordinary(_), None) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "ordinary LZCopy source lacks its temporary LZ wrapper",
            ));
        }
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

fn temporary_lz_handle(source: i32) -> Result<Result<TemporaryLzHandle, i16>, RuntimeError> {
    let duplicate = match duplicate_hfile(source)? {
        Ok(duplicate) => duplicate,
        Err(error) => return Ok(Err(error)),
    };
    initialize_duplicate_lz_handle(duplicate)
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

fn temporary_hfile_from_hfile(source: i32) -> Result<Result<TemporaryHFile, i16>, RuntimeError> {
    duplicate_hfile(source).map(|result| result.map(|handle| TemporaryHFile { handle }))
}

fn temporary_hfile_from_kernel(
    source: HANDLE,
) -> Result<Result<TemporaryHFile, i16>, RuntimeError> {
    duplicate_kernel_file_handle(source)
        .map(|result| result.map(|handle| TemporaryHFile { handle }))
}

fn duplicate_hfile(source: i32) -> Result<Result<i32, i16>, RuntimeError> {
    // This is a native HFILE retained by Win16Files, not a guest value. Windows
    // represents legacy HFILEs as signed 32-bit HANDLE values on 64-bit hosts.
    if source <= 0 {
        return Ok(Err(LZERROR_BADINHANDLE));
    }
    duplicate_kernel_file_handle(hfile_as_kernel_handle(source))
}

fn duplicate_kernel_file_handle(source: HANDLE) -> Result<Result<i32, i16>, RuntimeError> {
    // This bridge is called only for owned file HANDLEs stored in
    // `NativeHandle`, or for a native HFILE reconstructed from a retained
    // `Ordinary` entry. Reject sentinel/non-file values and any HANDLE whose
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

pub(super) fn hfile_as_kernel_handle(handle: i32) -> HANDLE {
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

pub(super) fn expanded_name(
    codec: GuestTextCodec,
    source: &[u8],
) -> Result<Win16HostLzName, RuntimeError> {
    let Some(source_z) = guest_wide_z(codec, source, "Win16 GetExpandedName source")? else {
        return Ok(Win16HostLzName::Error(LZERROR_BADVALUE));
    };
    // GetExpandedNameW has no output-capacity parameter. Its documented
    // MAX_PATH-sized result is not sufficient when it copies a longer input
    // name unchanged, so keep the entire source-sized fallback in owned memory.
    let output_capacity = MAX_PATH_UNITS.max(source_z.len());
    let mut output = Vec::new();
    output.try_reserve_exact(output_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate native GetExpandedNameW output",
            error,
        )
    })?;
    output.resize(output_capacity, 0);
    // SAFETY: Both path and output are owned UTF-16 buffers. The path is NUL
    // terminated; output is at least MAX_PATH units and can hold an unchanged
    // copy of the full input including its terminator.
    let result = unsafe { GetExpandedNameW(source_z.as_ptr(), output.as_mut_ptr()) };
    if result != 1 {
        return Ok(Win16HostLzName::Error(signed_lz_result(result)?));
    }
    let Some(end) = output.iter().position(|unit| *unit == 0) else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native GetExpandedNameW returned an unterminated path",
        ));
    };
    output.truncate(end);
    Ok(Win16HostLzName::Name(codec.from_wide(&output)?.bytes))
}

fn guest_wide_z(
    codec: GuestTextCodec,
    bytes: &[u8],
    operation: &'static str,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    if bytes.contains(&0) {
        return Ok(None);
    }
    let mut output = codec.to_wide(bytes)?;
    let length = output.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, format!("{operation} is too long"))
    })?;
    if length > MAX_WIDE_PATH_UNITS {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("{operation} exceeds the host path resource limit"),
        ));
    }
    output.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            format!("terminate {operation}"),
            error,
        )
    })?;
    output.push(0);
    Ok(Some(output))
}

fn decode_ofstruct(
    bytes: &[u8],
    codec: GuestTextCodec,
    reopen: bool,
) -> Result<OFSTRUCT, RuntimeError> {
    let mut output = OFSTRUCT::default();
    output.cBytes = bytes[0];
    output.fFixedDisk = bytes[1];
    output.nErrCode = u16::from_le_bytes([bytes[2], bytes[3]]);
    output.Reserved1 = u16::from_le_bytes([bytes[4], bytes[5]]);
    output.Reserved2 = u16::from_le_bytes([bytes[6], bytes[7]]);
    if reopen {
        let guest_path = &bytes[8..];
        let Some(end) = guest_path.iter().position(|byte| *byte == 0) else {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 OFSTRUCT reopen pathname is not terminated",
            ));
        };
        let wide = codec.to_wide(&guest_path[..end])?;
        let oem_codec = GuestTextCodec::new(unsafe { GetOEMCP() })?;
        let encoded = oem_codec.from_wide_bounded(&wide, output.szPathName.len() - 1)?;
        if encoded.truncated || encoded.used_default_char == Some(true) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 OFSTRUCT reopen pathname cannot be represented in the host OEM field",
            ));
        }
        for (target, source) in output.szPathName.iter_mut().zip(encoded.bytes) {
            *target = source as i8;
        }
    }
    Ok(output)
}

fn encode_ofstruct(
    codec: GuestTextCodec,
    value: &OFSTRUCT,
    bytes: &mut [u8],
) -> Result<(), RuntimeError> {
    bytes[0] = value.cBytes;
    bytes[1] = value.fFixedDisk;
    bytes[2..4].copy_from_slice(&value.nErrCode.to_le_bytes());
    bytes[4..6].copy_from_slice(&value.Reserved1.to_le_bytes());
    bytes[6..8].copy_from_slice(&value.Reserved2.to_le_bytes());
    let mut host_oem_path = Vec::new();
    host_oem_path
        .try_reserve_exact(value.szPathName.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "copy LZ OFSTRUCT OEM pathname",
                error,
            )
        })?;
    host_oem_path.extend(value.szPathName.iter().map(|byte| *byte as u8));
    let end = host_oem_path
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(host_oem_path.len());
    let oem_codec = GuestTextCodec::new(unsafe { GetOEMCP() })?;
    let wide = oem_codec.to_wide(&host_oem_path[..end])?;
    let encoded = codec.from_wide_bounded(&wide, bytes.len() - 9)?;
    bytes[8..].fill(0);
    bytes[8..8 + encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    if encoded.bytes.len() < bytes.len() - 8 {
        bytes[8 + encoded.bytes.len()] = 0;
    }
    Ok(())
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

fn is_lz_read_style(style: i32) -> bool {
    let access = style & (OF_READ | OF_WRITE | OF_READWRITE);
    access == OF_READ && style & OF_CREATE == 0 && !is_action_only_style(style)
}

#[cfg(test)]
#[path = "win16_compat_calls_lzexpand_tests.rs"]
mod tests;

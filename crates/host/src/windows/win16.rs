//! Native Windows services requested by the Win16 guest ABI.

use super::bindings::{_lclose, _llseek, _lread, _lwrite, LZClose, LZRead, LZSeek};
use super::guest_text::GuestTextCodec;
use runtime::Win16HostFile;
use runtime::Win16HostFileClose;
use runtime::{DiagnosticKind as Kind, RuntimeError};
use std::collections::{BTreeMap, BTreeSet};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_UNICODE_TRANSLATION, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    HWND, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FILE_BEGIN, FILE_CURRENT, FILE_END,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile, SetEndOfFile, SetFilePointerEx,
    WriteFile,
};
use windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16NativeFile {
    /// A real HFILE returned by a legacy HFILE API such as LZOpenFileW.
    Ordinary(i32),
    /// A pointer-sized HANDLE returned by CreateFileW. It must only be used
    /// with HANDLE APIs and must never be narrowed to an HFILE.
    NativeHandle(HANDLE),
    /// A native token returned by LZOpenFile or LZInit. Even ordinary files
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
    files: BTreeMap<Win16HostFile, Win16NativeFile>,
    next_id: u64,
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
        let Some(next_id) = self.next_id.checked_add(1) else {
            close_native(native);
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 host file identity exhausted",
            ));
        };
        let token = Win16HostFile(self.next_id);
        self.next_id = next_id;
        self.files.insert(token, native);
        Ok(Some(token))
    }

    pub(super) fn native_file(&self, file: Win16HostFile) -> Option<Win16NativeFile> {
        self.files.get(&file).copied()
    }

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
        self.retain_native(Win16NativeFile::NativeHandle(handle))
    }

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
        self.retain_native(Win16NativeFile::NativeHandle(handle))
    }

    pub(super) fn read(
        &mut self,
        file: Win16HostFile,
        count: u32,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        let Some(native) = self.files.get(&file).copied() else {
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
            Win16NativeFile::Ordinary(handle) => {
                // SAFETY: `data` owns `count` writable bytes and the HFILE is
                // retained in this adapter. The guest pointer never reaches Windows.
                let read = unsafe { _lread(handle, data.as_mut_ptr().cast(), count) };
                if read == u32::MAX {
                    return Ok(None);
                }
                read
            }
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
        let Some(native) = self.files.get(&file).copied() else {
            return Ok(None);
        };
        // SAFETY: `native` is an HFILE owned by this adapter; offset and
        // origin are scalar Win16 arguments already copied out of guest state.
        let position = match native {
            Win16NativeFile::Ordinary(handle) => {
                // SAFETY: `handle` is an HFILE owned by this adapter.
                unsafe { _llseek(handle, offset, i32::from(origin)) }
            }
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
                let mut new_position = 0_i64;
                // SAFETY: `handle` is retained by this adapter; the output is
                // a local LARGE_INTEGER-compatible i64 and method is checked.
                if unsafe { SetFilePointerEx(handle, i64::from(offset), &mut new_position, method) }
                    == 0
                {
                    return Ok(None);
                }
                new_position as i32
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
        let Some(native) = self.files.get(&file).copied() else {
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
            Win16NativeFile::Ordinary(native) => {
                // One native call keeps short writes and the Windows
                // zero-length truncation behavior intact.
                // SAFETY: The guest buffer was copied to `data`; the HFILE is owned.
                let written = unsafe { _lwrite(native, data.as_ptr().cast(), count) };
                if written == u32::MAX {
                    return Ok(None);
                }
                Ok(Some(written))
            }
            Win16NativeFile::LzHandle(_) => Ok(None),
            Win16NativeFile::NativeHandle(handle) if count == 0 => {
                // _lwrite(HFILE, NULL, 0) truncates or extends at the current
                // position. WriteFile(0) alone is a no-op, so use the native
                // equivalent SetEndOfFile primitive explicitly.
                // SAFETY: `handle` is an owned synchronous file HANDLE.
                Ok((unsafe { SetEndOfFile(handle) } != 0).then_some(0))
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
                Ok(Some(bytes_written))
            }
        }
    }

    pub(super) fn close(
        &mut self,
        file: Win16HostFile,
    ) -> Result<Win16HostFileClose, RuntimeError> {
        let Some(native) = self.files.get(&file).copied() else {
            return Ok(Win16HostFileClose {
                closed: false,
                consumed_source: None,
            });
        };
        let consumed_source = match native {
            Win16NativeFile::Ordinary(handle) => {
                // SAFETY: The HFILE is still owned here; failed close keeps it for retry.
                if unsafe { _lclose(handle) } == -1 {
                    return Ok(Win16HostFileClose {
                        closed: false,
                        consumed_source: None,
                    });
                }
                None
            }
            Win16NativeFile::NativeHandle(handle) => {
                // SAFETY: The HANDLE is still owned here; a failed close
                // keeps it in the table so the caller can retry.
                if unsafe { CloseHandle(handle) } == 0 {
                    return Ok(Win16HostFileClose {
                        closed: false,
                        consumed_source: None,
                    });
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
                    let closed = match self.files.get(&source).copied() {
                        Some(Win16NativeFile::Ordinary(handle)) => {
                            // SAFETY: This is the table's owned source HFILE.
                            unsafe { _lclose(handle) != -1 }
                        }
                        Some(Win16NativeFile::NativeHandle(handle)) => {
                            // SAFETY: This is the table's owned source HANDLE.
                            unsafe { CloseHandle(handle) != 0 }
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

impl Drop for Win16Files {
    fn drop(&mut self) {
        let mut consumed_sources = BTreeSet::new();
        for native in self.files.values().copied() {
            if let Win16NativeFile::LzHandle(lz) = native {
                close_native(native);
                if let Some(source) = lz.source_alias {
                    consumed_sources.insert(source);
                }
            }
        }
        for source in &consumed_sources {
            if let Some(
                native @ (Win16NativeFile::Ordinary(_) | Win16NativeFile::NativeHandle(_)),
            ) = self.files.get(source).copied()
            {
                // Its LZInit duplicate was closed above; consume the original
                // owned source only once even if multiple tokens alias it.
                close_native(native);
            }
        }
        for (token, native) in &self.files {
            if matches!(
                native,
                Win16NativeFile::Ordinary(_) | Win16NativeFile::NativeHandle(_)
            ) && !consumed_sources.contains(token)
            {
                close_native(*native);
            }
        }
    }
}

fn close_native(native: Win16NativeFile) {
    match native {
        Win16NativeFile::Ordinary(handle) => {
            // SAFETY: This HFILE was returned by a successful native legacy
            // file API and remains owned by this adapter.
            unsafe { _lclose(handle) };
        }
        Win16NativeFile::LzHandle(lz) => {
            // SAFETY: This LZ HFILE was returned by a successful native LZ
            // operation and remains owned by this adapter.
            unsafe { LZClose(lz.handle) };
        }
        Win16NativeFile::NativeHandle(handle) => {
            // SAFETY: This HANDLE was returned by CreateFileW and remains
            // owned by this adapter.
            unsafe { CloseHandle(handle) };
        }
    }
}

fn guest_file_path(codec: GuestTextCodec, path: &[u8]) -> Result<Option<Vec<u16>>, RuntimeError> {
    match codec.to_wide_z(path) {
        Ok(path) => Ok(Some(path)),
        // Invalid guest text is an ordinary file-open failure. Allocation and
        // other host failures retain their cause instead of becoming HFILE_ERROR.
        Err(error)
            if error.kind() == Kind::InvalidInput
                || (error.kind() == Kind::HostFailure
                    && unsafe { GetLastError() } == ERROR_NO_UNICODE_TRANSLATION) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn open_access_and_share(mode: u16) -> Option<(u32, u32)> {
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

fn create_attributes(attributes: u16) -> Option<u32> {
    match attributes {
        0 => Some(FILE_ATTRIBUTE_NORMAL),
        1 => Some(FILE_ATTRIBUTE_READONLY),
        2 => Some(FILE_ATTRIBUTE_HIDDEN),
        4 => Some(FILE_ATTRIBUTE_SYSTEM),
        _ => None,
    }
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
    if text.is_some_and(|text| text.contains(&0)) || caption.is_some_and(|caption| caption.contains(&0))
    {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 message box text contains an embedded NUL",
        ));
    }
    let text_z = text.map(|text| codec.to_wide_z(text)).transpose()?;
    let caption_z = caption.map(|caption| codec.to_wide_z(caption)).transpose()?;

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
            text_z.as_ref().map_or(std::ptr::null(), |text| text.as_ptr()),
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
    use std::fs;
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
}

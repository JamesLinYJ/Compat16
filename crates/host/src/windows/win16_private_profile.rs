//! Native INI parsing of a private snapshot; target IO stays capability-held.
//!
//! Profile APIs have no handle overload. Only a host-created temporary name
//! reaches them, so they cannot reopen a guest pathname outside its capability
//! or apply modern IniFileMapping redirects to an application's Win3 INI name.

use super::guest_text::GuestTextCodec;
use crate::filesystem::Filesystem;
use cap_std::fs::{OpenOptions, OpenOptionsExt};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16ProfilePath};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::FromRawHandle;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_TEMPORARY, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Com::CoCreateGuid;
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::Win32::System::WindowsProgramming::WritePrivateProfileStringW;

pub(super) fn read<T>(
    filesystem: &mut Filesystem,
    codec: GuestTextCodec,
    path: &Win16ProfilePath,
    operation: impl FnOnce(&[u16]) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    // A missing/unreadable profile has the native default/empty semantics.
    // Read-only queries never request target write access or copy anything back.
    let bytes = target(filesystem, path, false)
        .ok()
        .flatten()
        .and_then(|mut file| read_file(&mut file).ok())
        .unwrap_or_default();
    let (wide, _) = decode_file(codec, &bytes)?;
    let mut snapshot = Snapshot::new(&wide)?;
    let result = operation(&snapshot.path)?;
    snapshot.close()?;
    Ok(result)
}

pub(super) fn write(
    filesystem: &mut Filesystem,
    codec: GuestTextCodec,
    path: &Win16ProfilePath,
    flush_only: bool,
    operation: impl FnOnce(&[u16]) -> Result<bool, RuntimeError>,
) -> Result<bool, RuntimeError> {
    let mut target = match target(filesystem, path, !flush_only) {
        Ok(target) => target,
        Err(_) => return Ok(false),
    };
    if !flush_only && target.is_none() {
        return Ok(false);
    }
    let bytes = match target.as_mut().map(read_file).transpose() {
        Ok(bytes) => bytes.unwrap_or_default(),
        Err(_) => return Ok(false),
    };
    let (wide, encoding) = decode_file(codec, &bytes)?;
    let mut snapshot = Snapshot::new(&wide)?;
    let mut success = operation(&snapshot.path)?;
    if success && !flush_only {
        // Evict this unique name's native cache before reading the same file
        // handle. A failed flush or copyback cannot be reported as success.
        success = snapshot.flush_cache();
        if success {
            let changed = read_file(snapshot.file.as_mut().expect("live snapshot"));
            let changed = changed.map_err(io_error)?;
            let output = encode_file(codec, &changed, encoding)?;
            let file = target.as_mut().expect("writable target checked above");
            success = (|| -> io::Result<()> {
                file.seek(SeekFrom::Start(0))?;
                file.write_all(&output)?;
                file.set_len(output.len() as u64)?;
                file.sync_all()
            })()
            .is_ok();
        }
    }
    snapshot.close()?;
    Ok(success)
}

fn target(
    filesystem: &mut Filesystem,
    path: &Win16ProfilePath,
    write: bool,
) -> Result<Option<File>, dos_kernel::DosHostError> {
    use crate::windows::{invalid, os_error};
    use dos_kernel::DosErrorCode;
    let path = match path {
        Win16ProfilePath::File(path) => {
            super::win16_file_paths::resolve(filesystem, path, true, write)
        }
        Win16ProfilePath::WindowsDirectory(name) => {
            let mut directory = vec![0u16; 32768];
            let directory_buffer = directory.as_mut_ptr();
            let directory_capacity = directory.len() as u32;
            // SAFETY: `directory_buffer` addresses `directory_capacity` writable
            // UTF-16 units in `directory`, which stays live for this call.
            // GetWindowsDirectoryW writes the Windows directory and returns the
            // character count excluding the terminating null, the required size
            // when the buffer is too small, or zero on failure. It retains no
            // pointer. No pointer is a guest address.
            let length =
                unsafe { GetWindowsDirectoryW(directory_buffer, directory_capacity) } as usize;
            if length == 0 || length >= directory.len() {
                return Err(invalid(DosErrorCode::PathNotFound));
            }
            let absolute = PathBuf::from(std::ffi::OsString::from_wide(&directory[..length]));
            let relative = absolute
                .strip_prefix(&filesystem.canonical_root)
                .map_err(|_| invalid(DosErrorCode::UnknownUnit))?;
            // The Windows directory is a canonical host identity, while each
            // appended component comes from the guest and must resolve aliases.
            let Some(canonical) = filesystem.canonical_win16_path(filesystem.drive(), relative)?
            else {
                return Err(invalid(DosErrorCode::InvalidData));
            };
            let mut guest = runtime::Win16GuestPath {
                drive: canonical.drive,
                namespace: runtime::Win16PathNamespace::DosVirtual,
                components: canonical.components.into_iter().map(|text| runtime::Win16PathComponent {
                    text,
                    source: runtime::Win16PathComponentSource::CanonicalCwd,
                }).collect(),
            };
            // Normalize relative input without allowing escape above the
            // capability root. Preserve guest identity for alias lookup.
            for part in name.split(['\\', '/']) {
                match part {
                    "" | "." => {}
                    ".." => {
                        if guest.components.pop().is_none() {
                            return Err(invalid(DosErrorCode::AccessDenied));
                        }
                    }
                    text => guest.components.push(runtime::Win16PathComponent {
                        text: text.to_owned(),
                        source: runtime::Win16PathComponentSource::GuestInput,
                    }),
                }
            }
            super::win16_file_paths::resolve(filesystem, &guest, true, write)
        }
        _ => return Err(invalid(DosErrorCode::InvalidData)),
    };
    let path = match path {
        Ok(path) => path,
        Err(error) if !write && error.code == DosErrorCode::FileNotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut options = OpenOptions::new();
    // A writer holds one exclusive open description from snapshot through
    // copyback. Readers deny concurrent writes while taking their snapshot.
    options
        .read(true)
        .write(write)
        .create(write)
        .share_mode(if write { 0 } else { FILE_SHARE_READ });
    match filesystem.root.open_with(path, &options) {
        Ok(file) => Ok(Some(file.into_std())),
        Err(error) if !write && error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(os_error(error)),
    }
}

#[derive(Clone, Copy)]
enum Encoding {
    Ansi,
    Utf16Le,
    Utf16Be,
}

fn decode_file(codec: GuestTextCodec, bytes: &[u8]) -> Result<(Vec<u16>, Encoding), RuntimeError> {
    let (body, encoding) = if bytes.starts_with(&[0xff, 0xfe]) {
        (&bytes[2..], Encoding::Utf16Le)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        (&bytes[2..], Encoding::Utf16Be)
    } else {
        return Ok((codec.to_wide(bytes)?, Encoding::Ansi));
    };
    if body.len() % 2 != 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "odd UTF-16 INI byte count",
        ));
    }
    let wide = body
        .chunks_exact(2)
        .map(|pair| match encoding {
            Encoding::Utf16Be => u16::from_be_bytes([pair[0], pair[1]]),
            _ => u16::from_le_bytes([pair[0], pair[1]]),
        })
        .collect();
    Ok((wide, encoding))
}

fn encode_file(
    codec: GuestTextCodec,
    bytes: &[u8],
    encoding: Encoding,
) -> Result<Vec<u8>, RuntimeError> {
    let (wide, _) = decode_file(codec, bytes)?;
    match encoding {
        Encoding::Ansi => {
            let encoded = codec.from_wide(&wide)?;
            if encoded.used_default_char == Some(true) {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "INI write cannot preserve the guest encoding",
                ));
            }
            Ok(encoded.bytes)
        }
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let mut output = Vec::with_capacity(2 + wide.len() * 2);
            output.extend_from_slice(if matches!(encoding, Encoding::Utf16Be) {
                &[0xfe, 0xff]
            } else {
                &[0xff, 0xfe]
            });
            for unit in wide {
                output.extend_from_slice(&if matches!(encoding, Encoding::Utf16Be) {
                    unit.to_be_bytes()
                } else {
                    unit.to_le_bytes()
                });
            }
            Ok(output)
        }
    }
}

fn read_file(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let length =
        usize::try_from(file.metadata()?.len()).map_err(|_| io::ErrorKind::FileTooLarge)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    // Do not allow a changing file to grow an unbounded allocation.
    file.take(length as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > length {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}

struct Snapshot {
    path: Vec<u16>,
    name: PathBuf,
    file: Option<File>,
}

impl Snapshot {
    fn new(wide: &[u16]) -> Result<Self, RuntimeError> {
        let mut guid = windows_sys::core::GUID::default();
        let guid_slot = &mut guid;
        // SAFETY: `guid_slot` addresses the initialized GUID in `guid`, which
        // stays live for this call. CoCreateGuid writes a new GUID and returns
        // an HRESULT. It retains no pointer. No pointer is a guest address.
        if unsafe { CoCreateGuid(guid_slot) } < 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        let name = std::env::temp_dir().join(format!(
            "compat16-ini-{:08x}-{:04x}-{:04x}-{:02x?}.tmp",
            guid.data1, guid.data2, guid.data3, guid.data4
        ));
        let path: Vec<u16> = name.as_os_str().encode_wide().chain(Some(0)).collect();
        // A protected owner-only DACL avoids inheriting a permissive TMP/TEMP
        // directory ACL. CREATE_NEW atomically reserves the unique host name.
        let sddl: Vec<u16> = "D:P(A;;FA;;;OW)".encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let sddl_text = sddl.as_ptr();
        let descriptor_slot = &mut descriptor;
        // SAFETY: `sddl_text` points at the owned NUL-terminated UTF-16 SDDL in
        // `sddl`, which stays live for this call. `descriptor_slot` addresses
        // the null `descriptor` slot, which stays live. The size pointer is
        // null and the revision is 1. The call allocates a security descriptor,
        // writes it through `descriptor_slot`, and returns nonzero on success.
        // It retains no caller pointer. No pointer is a guest address.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_text,
                1,
                descriptor_slot,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io_error(io::Error::last_os_error()));
        }
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let path_name = path.as_ptr();
        let security_attributes = &security;
        // SAFETY: `path_name` points at the owned NUL-terminated UTF-16 path in
        // `path`, which stays live for this call. `security_attributes` points
        // at the initialized SECURITY_ATTRIBUTES in `security`, whose
        // descriptor is the allocation just stored in `descriptor`, and that
        // record stays live. The template handle is null. CreateFileW returns
        // the new file handle, or INVALID_HANDLE_VALUE on failure. It retains
        // no pointer. No pointer is a guest address.
        let handle = unsafe {
            CreateFileW(
                path_name,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                security_attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY,
                std::ptr::null_mut(),
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: `descriptor` is the security descriptor
        // ConvertStringSecurityDescriptorToSecurityDescriptorW just allocated.
        // LocalFree releases that allocation exactly once and returns the
        // result, which is discarded. It retains no pointer. It is not a guest
        // address.
        unsafe {
            LocalFree(descriptor);
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(io_error(error));
        }
        // SAFETY: `handle` is the file HANDLE CreateFileW just returned, and it
        // is not INVALID_HANDLE_VALUE. This conversion takes ownership of that
        // handle exactly once. It is not a guest address.
        let file = unsafe { File::from_raw_handle(handle) };
        let mut snapshot = Self {
            path,
            name,
            file: Some(file),
        };
        let file = snapshot.file.as_mut().expect("new snapshot");
        file.write_all(&[0xff, 0xfe]).map_err(io_error)?;
        for unit in wide {
            file.write_all(&unit.to_le_bytes()).map_err(io_error)?;
        }
        file.flush().map_err(io_error)?;
        Ok(snapshot)
    }

    fn flush_cache(&self) -> bool {
        let profile_path = self.path.as_ptr();
        // SAFETY: The section, key, and value pointers are null, which flushes
        // the profile cache. `profile_path` points at the owned NUL-terminated
        // UTF-16 temporary path in `self.path`, which stays live for this call.
        // WritePrivateProfileStringW returns nonzero when the flush succeeds
        // and retains no pointer. No pointer is a guest address.
        let flushed = unsafe {
            WritePrivateProfileStringW(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                profile_path,
            )
        };
        flushed != 0
    }

    fn close(&mut self) -> Result<(), RuntimeError> {
        self.flush_cache();
        drop(self.file.take());
        std::fs::remove_file(&self.name).map_err(io_error)
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        if self.file.is_some() {
            self.flush_cache();
            drop(self.file.take());
        }
        let _ = std::fs::remove_file(&self.name);
    }
}

fn io_error(error: io::Error) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure, "private profile snapshot IO", error)
}

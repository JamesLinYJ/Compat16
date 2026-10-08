//! Native structured-storage adapter used by the Win16 STORAGE/OLE2 bridge.
//!
//! Guest paths are first resolved by the DOS capability filesystem. Guest
//! interface addresses arrive here only after the runtime resolves them to a
//! shared COM object key. Raw COM pointers and `IStorage` results stay in this
//! host module and the private object table.

use std::ffi::c_void;
use std::ptr;

use compat_services::com::{ComObjectId, IID_ILOCK_BYTES, IID_ISTORAGE, ReferenceDisposition};
use runtime::{
    DiagnosticKind, RuntimeError, Win16ComHostInterface,
    Win16StorageHostOperation as Win16StorageNativeOperation,
    Win16StorageHostReply as Win16StorageNativeReply,
};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::System::Com::StructuredStorage::{
    CreateILockBytesOnHGlobal, StgCreateDocfile, StgCreateDocfileOnILockBytes, StgIsStorageFile,
    StgIsStorageILockBytes, StgOpenStorage, StgOpenStorageOnILockBytes, StgSetTimes,
};

use crate::filesystem::Filesystem;

use super::win16_com_objects::{NativeComError, Win16ComObjects};

const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;
const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;

/// Host-private prepared form. Paths are resolved and confined while the
/// owning `Filesystem` is borrowed by the runtime-side coordinator; the USER
/// STA receives only the resulting owned UTF-16 path and never accesses the
/// guest DOS namespace or a copied `Filesystem`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PreparedStorageOperation {
    CreateMemoryDocFile { mode: u32, reserved: u32 },
    CreateDocFile { path: Vec<u16>, mode: u32, reserved: u32 },
    CreateDocFileOnLockBytes { lock_bytes: ComObjectId, mode: u32, reserved: u32 },
    OpenStorage {
        path: Vec<u16>, priority_storage: Option<ComObjectId>, mode: u32,
        excluded_names: Vec<Vec<u16>>, reserved: u32,
    },
    OpenStorageOnLockBytes {
        lock_bytes: ComObjectId, priority_storage: Option<ComObjectId>, mode: u32,
        excluded_names: Vec<Vec<u16>>, reserved: u32,
    },
    IsStorageFile { path: Vec<u16> },
    IsStorageLockBytes { lock_bytes: ComObjectId },
    SetTimes {
        path: Vec<u16>, creation_time: Option<[u8; 8]>,
        access_time: Option<[u8; 8]>, modification_time: Option<[u8; 8]>,
    },
}

pub(super) fn prepare(
    filesystem: &mut crate::filesystem::Filesystem,
    operation: Win16StorageNativeOperation,
) -> Result<PreparedStorageOperation, RuntimeError> {
    Ok(match operation {
        Win16StorageNativeOperation::CreateMemoryDocFile { mode, reserved } =>
            PreparedStorageOperation::CreateMemoryDocFile { mode, reserved },
        Win16StorageNativeOperation::CreateDocFile { path, mode, reserved } =>
            PreparedStorageOperation::CreateDocFile {
                path: storage_path(filesystem, &path, false)?, mode, reserved,
            },
        Win16StorageNativeOperation::CreateDocFileOnLockBytes { lock_bytes, mode, reserved } =>
            PreparedStorageOperation::CreateDocFileOnLockBytes { lock_bytes, mode, reserved },
        Win16StorageNativeOperation::OpenStorage {
            path, priority_storage, mode, excluded_names, reserved,
        } => PreparedStorageOperation::OpenStorage {
            path: storage_path(filesystem, &path, true)?, priority_storage, mode,
            excluded_names, reserved,
        },
        Win16StorageNativeOperation::OpenStorageOnLockBytes {
            lock_bytes, priority_storage, mode, excluded_names, reserved,
        } => PreparedStorageOperation::OpenStorageOnLockBytes {
            lock_bytes, priority_storage, mode, excluded_names, reserved,
        },
        Win16StorageNativeOperation::IsStorageFile { path } =>
            PreparedStorageOperation::IsStorageFile {
                path: storage_path(filesystem, &path, true)?,
            },
        Win16StorageNativeOperation::IsStorageLockBytes { lock_bytes } =>
            PreparedStorageOperation::IsStorageLockBytes { lock_bytes },
        Win16StorageNativeOperation::SetTimes {
            path, creation_time, access_time, modification_time,
        } => PreparedStorageOperation::SetTimes {
            path: storage_path(filesystem, &path, true)?,
            creation_time, access_time, modification_time,
        },
    })
}

pub(super) fn execute(
    objects: &Win16ComObjects,
    operation: PreparedStorageOperation,
) -> Result<Win16StorageNativeReply, RuntimeError> {
    let (hresult, object) = match operation {
        PreparedStorageOperation::CreateMemoryDocFile { mode, reserved } => {
            let (result, output) = create_memory_docfile(objects, mode, reserved)?;
            (result, Some(output))
        }
        PreparedStorageOperation::CreateDocFile {
            path,
            mode,
            reserved,
        } => {
            let mut output = ptr::null_mut();
            // SAFETY: `path` is an owned NUL-terminated UTF-16 path resolved
            // inside the configured filesystem root. `output` is writable.
            let result = unsafe { StgCreateDocfile(path.as_ptr(), mode, reserved, &mut output) };
            (result, Some(output))
        }
        PreparedStorageOperation::CreateDocFileOnLockBytes {
            lock_bytes,
            mode,
            reserved,
        } => {
            let result = objects
                .with_interface(lock_bytes, IID_ILOCK_BYTES, |lock_bytes| {
                    let mut output = ptr::null_mut();
                    // SAFETY: the borrowed interface lease is a live ILockBytes;
                    // the output slot remains writable for the call.
                    let result = unsafe {
                        StgCreateDocfileOnILockBytes(lock_bytes, mode, reserved, &mut output)
                    };
                    (result, output)
                })
                .map_err(com_error)?;
            result.map_or((E_NOINTERFACE, None), |(result, output)| {
                (result, Some(output))
            })
        }
        PreparedStorageOperation::OpenStorage {
            path,
            priority_storage,
            mode,
            excluded_names,
            reserved,
        } => {
            let result = with_optional_storage(objects, priority_storage, |priority| {
                let mut output = ptr::null_mut();
                let Some((excluded_names, excluded_pointers)) = exclusion_table(&excluded_names)
                else {
                    return (E_INVALIDARG, output);
                };
                let snb = if excluded_pointers.is_empty() {
                    ptr::null()
                } else {
                    excluded_pointers.as_ptr()
                };
                // SAFETY: the path is capability-confined and NUL-terminated;
                // priority is a live IStorage lease when non-null; SNB points
                // to owned, NUL-terminated strings and a null pointer sentinel
                // that remain alive for this native call.
                let result = unsafe {
                    StgOpenStorage(path.as_ptr(), priority, mode, snb, reserved, &mut output)
                };
                drop(excluded_names);
                (result, output)
            })?;
            result.map_or((E_NOINTERFACE, None), |(result, output)| {
                (result, Some(output))
            })
        }
        PreparedStorageOperation::OpenStorageOnLockBytes {
            lock_bytes,
            priority_storage,
            mode,
            excluded_names,
            reserved,
        } => {
            let result = objects
                .with_interface(lock_bytes, IID_ILOCK_BYTES, |lock_bytes| {
                    with_optional_storage(objects, priority_storage, |priority| {
                        let mut output = ptr::null_mut();
                        let Some((excluded_names, excluded_pointers)) =
                            exclusion_table(&excluded_names)
                        else {
                            return (E_INVALIDARG, output);
                        };
                        let snb = if excluded_pointers.is_empty() {
                            ptr::null()
                        } else {
                            excluded_pointers.as_ptr()
                        };
                        // SAFETY: both interface leases stay live for this native
                        // call; SNB points to owned, NUL-terminated strings and a
                        // null pointer sentinel that remain alive through the call.
                        let result = unsafe {
                            StgOpenStorageOnILockBytes(
                                lock_bytes,
                                priority,
                                mode,
                                snb,
                                reserved,
                                &mut output,
                            )
                        };
                        drop(excluded_names);
                        (result, output)
                    })
                })
                .map_err(com_error)?;
            match result {
                Some(inner) => match inner? {
                    Some((result, output)) => (result, Some(output)),
                    None => (E_NOINTERFACE, None),
                },
                None => (E_NOINTERFACE, None),
            }
        }
        PreparedStorageOperation::IsStorageFile { path } => {
            // SAFETY: `path` is an owned NUL-terminated UTF-16 path resolved
            // inside the configured filesystem root.
            (unsafe { StgIsStorageFile(path.as_ptr()) }, None)
        }
        PreparedStorageOperation::IsStorageLockBytes { lock_bytes } => {
            let result = objects
                .with_interface(lock_bytes, IID_ILOCK_BYTES, |lock_bytes| {
                    // SAFETY: the lease is a live ILockBytes interface.
                    unsafe { StgIsStorageILockBytes(lock_bytes) }
                })
                .map_err(com_error)?;
            (result.unwrap_or(E_NOINTERFACE), None)
        }
        PreparedStorageOperation::SetTimes {
            path,
            creation_time,
            access_time,
            modification_time,
        } => {
            let creation_time = creation_time.map(file_time);
            let access_time = access_time.map(file_time);
            let modification_time = modification_time.map(file_time);
            // SAFETY: the path is confined and all optional FILETIME pointers
            // reference local values that remain alive through the call.
            let result = unsafe {
                StgSetTimes(
                    path.as_ptr(),
                    creation_time
                        .as_ref()
                        .map_or(ptr::null(), |time| time as *const FILETIME),
                    access_time
                        .as_ref()
                        .map_or(ptr::null(), |time| time as *const FILETIME),
                    modification_time
                        .as_ref()
                        .map_or(ptr::null(), |time| time as *const FILETIME),
                )
            };
            (result, None)
        }
    };

    let storage = match object {
        Some(interface) if hresult >= 0 => {
            if interface.is_null() {
                return Err(RuntimeError::new(
                    DiagnosticKind::InternalInvariant,
                    "structured storage returned success with a null IStorage",
                ));
            }
            Some(Win16ComHostInterface {
                object: objects.insert_owned(interface).map_err(com_error)?,
                owner: objects.owner_identity(),
                iid: IID_ISTORAGE,
                disposition: ReferenceDisposition::Owned,
            })
        }
        Some(interface) if !interface.is_null() => {
            objects.discard_owned(interface).map_err(com_error)?;
            None
        }
        Some(_) if hresult >= 0 => {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "structured storage returned success without an IStorage",
            ));
        }
        _ => None,
    };
    Ok(Win16StorageNativeReply {
        hresult: hresult as u32,
        storage,
    })
}

/// Build an owned in-memory storage using the system lock-bytes implementation.
/// The temporary ILockBytes output is released on every path; a successfully
/// created IStorage retains its own backing reference.
fn create_memory_docfile(
    objects: &Win16ComObjects,
    mode: u32,
    reserved: u32,
) -> Result<(i32, *mut c_void), RuntimeError> {
    let mut lock_bytes = ptr::null_mut();
    // SAFETY: NULL requests a system-allocated HGLOBAL backing store; TRUE
    // transfers its lifetime to the returned ILockBytes object.
    let lock_result = unsafe { CreateILockBytesOnHGlobal(ptr::null_mut(), 1, &mut lock_bytes) };
    if lock_result < 0 {
        if !lock_bytes.is_null() {
            objects.discard_owned(lock_bytes).map_err(com_error)?;
        }
        return Ok((lock_result, ptr::null_mut()));
    }
    if lock_bytes.is_null() {
        return Err(RuntimeError::new(
            DiagnosticKind::InternalInvariant,
            "CreateILockBytesOnHGlobal succeeded with a null ILockBytes",
        ));
    }

    let mut storage = ptr::null_mut();
    // SAFETY: the created ILockBytes reference remains owned until after this
    // call; `storage` is a writable output slot.
    let result = unsafe { StgCreateDocfileOnILockBytes(lock_bytes, mode, reserved, &mut storage) };
    if let Err(error) = objects.discard_owned(lock_bytes) {
        if !storage.is_null() {
            let _ = objects.discard_owned(storage);
        }
        return Err(com_error(error));
    }
    Ok((result, storage))
}

fn with_optional_storage<R>(
    objects: &Win16ComObjects,
    storage: Option<ComObjectId>,
    operation: impl FnOnce(*mut c_void) -> R,
) -> Result<Option<R>, RuntimeError> {
    match storage {
        Some(storage) => objects
            .with_interface(storage, IID_ISTORAGE, operation)
            .map_err(com_error),
        None => Ok(Some(operation(ptr::null_mut()))),
    }
}

/// Build the native Windows SNB representation from owned UTF-16 names. The
/// guest-side Win16 SNB decoder must establish each name's bounds before it
/// constructs this host value; this function never reads guest memory.
fn exclusion_table(names: &[Vec<u16>]) -> Option<(Vec<Vec<u16>>, Vec<*const u16>)> {
    if names.iter().any(|name| name.contains(&0)) {
        return None;
    }
    let owned = names
        .iter()
        .map(|name| name.iter().copied().chain(std::iter::once(0)).collect())
        .collect::<Vec<Vec<u16>>>();
    let mut pointers = owned.iter().map(|name| name.as_ptr()).collect::<Vec<_>>();
    if !pointers.is_empty() {
        pointers.push(ptr::null());
    }
    Some((owned, pointers))
}

fn storage_path(
    filesystem: &mut Filesystem,
    guest_path: &[u8],
    follow_final: bool,
) -> Result<Vec<u16>, RuntimeError> {
    let relative = filesystem
        .resolve_path(guest_path, false)
        .map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::HostFailure,
                "resolve Win16 storage path",
                error,
            )
        })?;
    // Let structured-storage APIs produce their native not-found HRESULT;
    // the canonical parent is still checked before passing a missing leaf.
    let confined = filesystem
        .confined_path(&relative, follow_final, true)
        .map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::HostFailure,
                "confine Win16 storage path",
                error,
            )
        })?;
    let full = filesystem.canonical_root.join(confined);
    use std::os::windows::ffi::OsStrExt;
    Ok(full
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

fn file_time(bytes: [u8; 8]) -> FILETIME {
    FILETIME {
        dwLowDateTime: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        dwHighDateTime: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    }
}

fn com_error(error: NativeComError) -> RuntimeError {
    RuntimeError::with_source(
        DiagnosticKind::HostFailure,
        "Win16 native COM object",
        error,
    )
}

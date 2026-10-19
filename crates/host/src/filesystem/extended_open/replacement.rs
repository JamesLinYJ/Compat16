//! Same-object replacement attributes and reduction to the requested access.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};

use cap_std::fs::{File, MetadataExt};
use dos_kernel::DosHostError;
use windows_sys::Win32::Foundation::{DuplicateHandle, GENERIC_READ, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_SYSTEM, FILE_BASIC_INFO, FileBasicInfo, SetFileInformationByHandle,
};

use crate::windows::os_error;

pub(super) fn set_attributes(file: &File, attributes: u8) -> Result<(), DosHostError> {
    const MUTABLE: u32 = FILE_ATTRIBUTE_READONLY
        | FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_ARCHIVE;
    // Replacement gives the existing file the creation attributes and marks
    // its changed contents for archival. Preserve flags with no DOS meaning.
    let old = file.metadata().map_err(os_error)?.file_attributes();
    let mut native = (old & !MUTABLE) | u32::from(attributes & 0x27) | FILE_ATTRIBUTE_ARCHIVE;
    native &= !FILE_ATTRIBUTE_NORMAL;
    let basic = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: native,
    };
    // SAFETY: The write-capable handle is owned by the capability-opened File.
    // Attribute changes address this exact object, never a reopened pathname.
    let success = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileBasicInfo,
            (&basic as *const FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if success == 0 {
        Err(os_error(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

pub(super) fn read_only_handle(file: File) -> Result<File, DosHostError> {
    let process = crate::windows::win32_safe::current_process();
    let mut duplicate: HANDLE = std::ptr::null_mut();
    // SAFETY: Source and destination are this process; the source File owns
    // a valid kernel handle and output is one initialized HANDLE slot.
    // No DUPLICATE_SAME_ACCESS: the resulting object has only read access.
    let success = unsafe {
        DuplicateHandle(
            process,
            file.as_raw_handle() as HANDLE,
            process,
            &mut duplicate,
            GENERIC_READ,
            0,
            0,
        )
    };
    if success == 0 {
        return Err(os_error(io::Error::last_os_error()));
    }
    // SAFETY: Successful duplication transfers a unique owned file HANDLE.
    // The temporary mutation-capable source closes when this function returns.
    let read_only = unsafe { std::fs::File::from_raw_handle(duplicate.cast()) };
    Ok(File::from_std(read_only))
}

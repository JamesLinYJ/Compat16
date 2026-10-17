//! KERNEL profile-struct calls on the private-profile snapshot.
//!
//! Section, key, and file names are guest ANSI/DBCS. The payload is opaque
//! bytes. WritePrivateProfileStructW stores the checksummed form; this module
//! does not invent a second encoding. A null filename is forwarded as a null
//! file pointer and is not rewritten into WIN.INI.

use std::ptr;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16ProfilePath};
use windows_sys::Win32::System::WindowsProgramming::{
    GetPrivateProfileStructW, WritePrivateProfileStructW,
};

use super::guest_text::GuestTextCodec;
use super::win16_private_profile;
use crate::filesystem::Filesystem;

pub(super) fn write(
    filesystem: &mut Filesystem,
    codec: GuestTextCodec,
    path: &Win16ProfilePath,
    section: Option<&[u8]>,
    key: Option<&[u8]>,
    data: Option<&[u8]>,
    data_size: u16,
) -> Result<bool, RuntimeError> {
    if data.is_some_and(|bytes| bytes.len() != usize::from(data_size)) {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "profile-struct input length differs from its Win16 size"));
    }
    if matches!(path, Win16ProfilePath::Invalid) {
        return Ok(false);
    }
    if matches!(path, Win16ProfilePath::System) {
        return store(codec, section, key, data, data_size, None);
    }
    let flush_only = section.is_none() && key.is_none() && data.is_none();
    win16_private_profile::write(filesystem, codec, path, flush_only, |file| {
        store(codec, section, key, data, data_size, Some(file))
    })
}

pub(super) fn read(
    filesystem: &mut Filesystem,
    codec: GuestTextCodec,
    path: &Win16ProfilePath,
    section: Option<&[u8]>,
    key: Option<&[u8]>,
    capacity: u16,
) -> Result<(bool, Vec<u8>), RuntimeError> {
    if matches!(path, Win16ProfilePath::Invalid) {
        return Ok((false, Vec::new()));
    }
    if matches!(path, Win16ProfilePath::System) {
        return load(codec, section, key, capacity, None);
    }
    win16_private_profile::read(filesystem, codec, path, |file| {
        load(codec, section, key, capacity, Some(file))
    })
}

fn store(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    key: Option<&[u8]>,
    data: Option<&[u8]>,
    data_size: u16,
    file: Option<&[u16]>,
) -> Result<bool, RuntimeError> {
    if !names_fit(&[section, key]) {
        return Ok(false);
    }
    let section = wide_name(codec, section)?;
    let key = wide_name(codec, key)?;
    // A zero-length structure is still a non-null pointer. Null deletes the key.
    let data_pointer = match data {
        Some(bytes) => bytes.as_ptr().cast(),
        None => ptr::null(),
    };
    let file_pointer = file.map_or(ptr::null(), <[u16]>::as_ptr);
    // SAFETY: each non-null string is an owned NUL-terminated UTF-16 buffer
    // that outlives this synchronous call. The payload slice, including a
    // zero-length one, stays borrowed for the same call. A null payload
    // pointer is the native delete-key request.
    Ok(unsafe {
        WritePrivateProfileStructW(
            section.as_ref().map_or(ptr::null(), Vec::as_ptr),
            key.as_ref().map_or(ptr::null(), Vec::as_ptr),
            data_pointer,
            u32::from(data_size),
            file_pointer,
        )
    } != 0)
}

fn load(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    key: Option<&[u8]>,
    capacity: u16,
    file: Option<&[u16]>,
) -> Result<(bool, Vec<u8>), RuntimeError> {
    if !names_fit(&[section, key]) {
        return Ok((false, Vec::new()));
    }
    let section = wide_name(codec, section)?;
    let key = wide_name(codec, key)?;
    let mut data = Vec::new();
    let allocation = usize::from(capacity).max(1);
    data.try_reserve_exact(allocation).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate Win16 profile-struct output", error))?;
    data.resize(allocation, 0);
    let file_pointer = file.map_or(ptr::null(), <[u16]>::as_ptr);
    // SAFETY: `data` owns at least one writable byte, and the requested size
    // is never larger than that allocation. Name pointers follow `store`.
    let succeeded = unsafe {
        GetPrivateProfileStructW(
            section.as_ref().map_or(ptr::null(), Vec::as_ptr),
            key.as_ref().map_or(ptr::null(), Vec::as_ptr),
            data.as_mut_ptr().cast(),
            u32::from(capacity),
            file_pointer,
        )
    } != 0;
    if !succeeded {
        return Ok((false, Vec::new()));
    }
    data.truncate(usize::from(capacity));
    Ok((true, data))
}

fn names_fit(values: &[Option<&[u8]>]) -> bool {
    values.iter().flatten().all(|value| !value.contains(&0) && value.len() < (1 << 16))
}

fn wide_name(codec: GuestTextCodec, value: Option<&[u8]>) -> Result<Option<Vec<u16>>, RuntimeError> {
    value.map(|bytes| codec.to_wide_z(bytes)).transpose()
}

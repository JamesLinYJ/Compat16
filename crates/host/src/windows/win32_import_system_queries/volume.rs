use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win32HostImportResult, Win32HostImportValue as V,
    Win32HostVolumeCall as C, Win32ImportString as S, Win32ImportTextEncoding as E,
};
use windows_sys::Win32::{
    Foundation::ERROR_MORE_DATA,
    Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetDiskFreeSpaceW, GetDriveTypeW, GetLogicalDrives,
        GetVolumeInformationW,
    },
};

use super::super::super::guest_text::GuestTextCodec;
use super::super::{api_error, result, text};

pub(super) fn execute(
    call: C,
    codec: GuestTextCodec,
) -> Result<Win32HostImportResult, RuntimeError> {
    match call {
        C::LogicalDrives => {
            let drives = logical_drives();
            let error = (drives == 0).then(api_error);
            Ok(result(V::Dword(drives), error))
        }
        C::DriveType { root, wide } => drive_type(root, wide, codec),
        C::DiskFreeSpace { root, wide } => disk_free_space(root, wide, codec),
        C::DiskFreeSpaceEx {
            root,
            wide,
            available_present,
            total_present,
            free_present,
        } => disk_free_space_ex(
            root,
            wide,
            available_present,
            total_present,
            free_present,
            codec,
        ),
        C::VolumeInformation {
            root,
            wide,
            volume_name_capacity,
            filesystem_name_capacity,
            volume_name_buffer_present,
            filesystem_name_buffer_present,
            want_serial,
            want_maximum_component,
            want_flags,
        } => volume_info(
            root,
            wide,
            volume_name_capacity,
            filesystem_name_capacity,
            volume_name_buffer_present,
            filesystem_name_buffer_present,
            want_serial,
            want_maximum_component,
            want_flags,
            codec,
        ),
    }
}

fn native_root(
    codec: GuestTextCodec,
    root: Option<S>,
    wide: bool,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let encoding = if wide { E::Wide } else { E::Ansi };
    if root
        .as_ref()
        .is_some_and(|root| root.encoding() != encoding)
    {
        return Err(contract(
            "volume root encoding differs from the selected guest API",
        ));
    }
    text::optional_to_wide_z(codec, root, "Win32 volume root contains embedded NUL")
}

fn drive_type(
    root: Option<S>,
    wide: bool,
    codec: GuestTextCodec,
) -> Result<Win32HostImportResult, RuntimeError> {
    let root = native_root(codec, root, wide)?;
    // SAFETY: `root` is null or an owned NUL-terminated UTF-16 path that stays
    // live for this call. GetDriveTypeW returns a drive-type code and retains
    // no pointer.
    let value = unsafe { GetDriveTypeW(root.as_ref().map_or(ptr::null(), Vec::as_ptr)) };
    Ok(result(V::Dword(value), None))
}

fn disk_free_space(
    root: Option<S>,
    wide: bool,
    codec: GuestTextCodec,
) -> Result<Win32HostImportResult, RuntimeError> {
    let root = native_root(codec, root, wide)?;
    let mut values = [0u32; 4];
    // SAFETY: `root` is null or an owned NUL-terminated UTF-16 path that stays
    // live for this call. The four outputs are local integers that also stay
    // live. A zero BOOL is the only failure result.
    let success = unsafe {
        GetDiskFreeSpaceW(
            root.as_ref().map_or(ptr::null(), Vec::as_ptr),
            &mut values[0],
            &mut values[1],
            &mut values[2],
            &mut values[3],
        )
    } != 0;
    let error = (!success).then(api_error);
    Ok(result(
        V::DiskFreeSpace {
            success,
            sectors_per_cluster: values[0],
            bytes_per_sector: values[1],
            free_clusters: values[2],
            total_clusters: values[3],
        },
        error,
    ))
}

fn disk_free_space_ex(
    root: Option<S>,
    wide: bool,
    available_present: bool,
    total_present: bool,
    free_present: bool,
    codec: GuestTextCodec,
) -> Result<Win32HostImportResult, RuntimeError> {
    let root = native_root(codec, root, wide)?;
    let mut available = 0u64;
    let mut total = 0u64;
    let mut free = 0u64;
    let available_ptr = if available_present {
        &mut available
    } else {
        ptr::null_mut()
    };
    let total_ptr = if total_present {
        &mut total
    } else {
        ptr::null_mut()
    };
    let free_ptr = if free_present {
        &mut free
    } else {
        ptr::null_mut()
    };
    // SAFETY: `root` is null or an owned NUL-terminated UTF-16 path that stays
    // live for this call. Each output pointer is null or one of those local
    // integers, which also stay live for the call. A zero BOOL is the only
    // failure result.
    let success = unsafe {
        GetDiskFreeSpaceExW(
            root.as_ref().map_or(ptr::null(), Vec::as_ptr),
            available_ptr,
            total_ptr,
            free_ptr,
        )
    } != 0;
    let error = (!success).then(api_error);
    Ok(result(
        V::DiskFreeSpaceEx {
            success,
            available,
            total,
            free,
        },
        error,
    ))
}

#[allow(clippy::too_many_arguments)]
fn volume_info(
    root: Option<S>,
    guest_wide: bool,
    volume_capacity: u32,
    filesystem_capacity: u32,
    volume_present: bool,
    filesystem_present: bool,
    want_serial: bool,
    want_maximum_component: bool,
    want_flags: bool,
    codec: GuestTextCodec,
) -> Result<Win32HostImportResult, RuntimeError> {
    let root = native_root(codec, root, guest_wide)?;
    let mut serial = 0u32;
    let mut maximum_component = 0u32;
    let mut flags = 0u32;
    if guest_wide {
        let mut volume = wide_buffer(volume_capacity, volume_present)?;
        let mut filesystem = wide_buffer(filesystem_capacity, filesystem_present)?;
        let success = query_volume_information(
            &root,
            &mut volume,
            volume_capacity,
            volume_present,
            &mut filesystem,
            filesystem_capacity,
            filesystem_present,
            &mut serial,
            want_serial,
            &mut maximum_component,
            want_maximum_component,
            &mut flags,
            want_flags,
        );
        let error = (!success).then(api_error);
        let volume_name = if success && volume_present {
            S::Wide(prefix_wide(&volume)?)
        } else {
            S::Wide(Vec::new())
        };
        let filesystem_name = if success && filesystem_present {
            S::Wide(prefix_wide(&filesystem)?)
        } else {
            S::Wide(Vec::new())
        };
        return Ok(result(
            V::VolumeInformation {
                success,
                volume_name,
                filesystem_name,
                serial: want_serial.then_some(serial),
                maximum_component: want_maximum_component.then_some(maximum_component),
                flags: want_flags.then_some(flags),
            },
            error,
        ));
    }

    // The native W buffers use the documented maximum for these names. The A
    // guest buffers are measured in encoded bytes and are checked after the
    // host strings have been converted through its fixed code-page codec.
    const MAX_VOLUME_TEXT: u32 = 261;
    let mut volume = wide_buffer(MAX_VOLUME_TEXT, volume_present)?;
    let mut filesystem = wide_buffer(MAX_VOLUME_TEXT, filesystem_present)?;
    // Guest capacities count encoded bytes, so the W call uses the documented
    // host maximum instead of those guest sizes.
    let native_success = query_volume_information(
        &root,
        &mut volume,
        if volume_present { MAX_VOLUME_TEXT } else { 0 },
        volume_present,
        &mut filesystem,
        if filesystem_present {
            MAX_VOLUME_TEXT
        } else {
            0
        },
        filesystem_present,
        &mut serial,
        want_serial,
        &mut maximum_component,
        want_maximum_component,
        &mut flags,
        want_flags,
    );
    if !native_success {
        return Ok(result(
            V::VolumeInformation {
                success: false,
                volume_name: S::Ansi(Vec::new()),
                filesystem_name: S::Ansi(Vec::new()),
                serial: want_serial.then_some(serial),
                maximum_component: want_maximum_component.then_some(maximum_component),
                flags: want_flags.then_some(flags),
            },
            Some(api_error()),
        ));
    }
    let volume_wide = if volume_present {
        prefix_wide(&volume)?
    } else {
        Vec::new()
    };
    let filesystem_wide = if filesystem_present {
        prefix_wide(&filesystem)?
    } else {
        Vec::new()
    };
    let volume_name = text::from_wide(codec, &volume_wide)?;
    let filesystem_name = text::from_wide(codec, &filesystem_wide)?;
    let volume_fits = !volume_present || encoded_name_fits(&volume_name, volume_capacity)?;
    let filesystem_fits =
        !filesystem_present || encoded_name_fits(&filesystem_name, filesystem_capacity)?;
    let success = volume_fits && filesystem_fits;
    let error = (!success).then_some(ERROR_MORE_DATA);
    Ok(result(
        V::VolumeInformation {
            success,
            volume_name: S::Ansi(if success && volume_present {
                volume_name
            } else {
                Vec::new()
            }),
            filesystem_name: S::Ansi(if success && filesystem_present {
                filesystem_name
            } else {
                Vec::new()
            }),
            serial: want_serial.then_some(serial),
            maximum_component: want_maximum_component.then_some(maximum_component),
            flags: want_flags.then_some(flags),
        },
        error,
    ))
}

fn logical_drives() -> u32 {
    // SAFETY: GetLogicalDrives takes no pointers. Zero is its only failure code.
    unsafe { GetLogicalDrives() }
}

#[allow(clippy::too_many_arguments)]
fn query_volume_information(
    root: &Option<Vec<u16>>,
    volume: &mut [u16],
    volume_capacity: u32,
    volume_present: bool,
    filesystem: &mut [u16],
    filesystem_capacity: u32,
    filesystem_present: bool,
    serial: &mut u32,
    want_serial: bool,
    maximum_component: &mut u32,
    want_maximum_component: bool,
    flags: &mut u32,
    want_flags: bool,
) -> bool {
    let root_ptr = root.as_ref().map_or(ptr::null(), Vec::as_ptr);
    let volume_ptr = if volume_present {
        volume.as_mut_ptr()
    } else {
        ptr::null_mut()
    };
    let filesystem_ptr = if filesystem_present {
        filesystem.as_mut_ptr()
    } else {
        ptr::null_mut()
    };
    let serial_ptr = if want_serial { serial } else { ptr::null_mut() };
    let component_ptr = if want_maximum_component {
        maximum_component
    } else {
        ptr::null_mut()
    };
    let flags_ptr = if want_flags { flags } else { ptr::null_mut() };
    // SAFETY: `root_ptr` is null or an owned NUL-terminated UTF-16 path that
    // stays live for this call. Each output pointer is null or a caller-owned
    // buffer or local that also stays live for the call. A zero BOOL is the
    // only failure result.
    (unsafe {
        GetVolumeInformationW(
            root_ptr,
            volume_ptr,
            volume_capacity,
            serial_ptr,
            component_ptr,
            flags_ptr,
            filesystem_ptr,
            filesystem_capacity,
        )
    }) != 0
}

fn encoded_name_fits(value: &[u8], capacity: u32) -> Result<bool, RuntimeError> {
    let required = value
        .len()
        .checked_add(1)
        .ok_or_else(|| exhausted("volume name"))?;
    let capacity = usize::try_from(capacity).map_err(|_| exhausted("volume name capacity"))?;
    Ok(required <= capacity)
}

fn wide_buffer(capacity: u32, present: bool) -> Result<Vec<u16>, RuntimeError> {
    let count = if present {
        usize::try_from(capacity).map_err(|_| exhausted("volume buffer"))?
    } else {
        0
    };
    let count = count.max(usize::from(present && count == 0));
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve volume-information buffer",
            error,
        )
    })?;
    buffer.resize(count, 0);
    Ok(buffer)
}

fn prefix_wide(buffer: &[u16]) -> Result<Vec<u16>, RuntimeError> {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| contract("successful volume API returned unterminated UTF-16 text"))?;
    let mut text = Vec::new();
    text.try_reserve_exact(end).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy volume text", error)
    })?;
    text.extend_from_slice(&buffer[..end]);
    Ok(text)
}

fn exhausted(resource: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!("{resource} exhausted"))
}

fn contract(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

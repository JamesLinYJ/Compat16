use std::collections::TryReserveError;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use runtime::{
    RuntimeError, Win16HostAcmDriverDetails, Win16HostAcmEnumerationRecord,
    Win16HostAcmHandle as Handle, Win16HostAcmNativeOperation as NativeOperation,
    Win16HostAcmObjectKind as ObjectKind, Win16HostAcmResult as ResultValue,
};
use windows_sys::Win32::Media::Audio::{
    ACM_DRIVERADDF_NAME, ACM_DRIVERADDF_TYPEMASK, ACMDRIVERDETAILSW, HACMDRIVER, HACMDRIVERID,
    acmDriverAddW, acmDriverClose, acmDriverDetailsW, acmDriverEnum, acmDriverID, acmDriverOpen,
};
use windows_sys::Win32::Media::{
    MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM, MMSYSERR_NOERROR, MMSYSERR_NOTSUPPORTED,
};

use super::super::guest_text::GuestTextCodec;
use super::super::win16_images::Win16Images;
use super::text::wide_fixed_to_guest;
use super::{
    NativeObject, Win16AcmHost, callback_panic_error, native_allocation_error, retain_native_result,
};

#[derive(Default)]
struct DriverRows {
    rows: Vec<(usize, u32)>,
    allocation_error: Option<TryReserveError>,
    callback_panicked: bool,
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn driver_enum_callback(
    driver_id: HACMDRIVERID,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if instance == 0 || driver_id.is_null() {
        return 1;
    }
    // SAFETY: `instance` was set to the stack-owned DriverRows for this
    // synchronous acmDriverEnum call and is never retained by MSACM.
    let context = unsafe { &mut *(instance as *mut DriverRows) };
    match catch_unwind(AssertUnwindSafe(|| {
        context.rows.try_reserve(1)?;
        context.rows.push((driver_id as usize, support));
        Ok::<(), TryReserveError>(())
    })) {
        Ok(Ok(())) => 1,
        Ok(Err(error)) => {
            context.allocation_error = Some(error);
            0
        }
        Err(_) => {
            context.callback_panicked = true;
            0
        }
    }
}

pub(super) fn enumerate(host: &mut Win16AcmHost, flags: u32) -> Result<ResultValue, RuntimeError> {
    let mut rows = DriverRows::default();
    // SAFETY: callback context remains live for the complete synchronous API
    // call; callback copies only native scalar identities and support flags.
    let result = unsafe {
        acmDriverEnum(
            Some(driver_enum_callback),
            (&mut rows as *mut DriverRows) as usize,
            flags,
        )
    };
    if let Some(error) = rows.allocation_error {
        return Err(native_allocation_error(
            NativeOperation::DriverEnum,
            result,
            error,
        ));
    }
    if rows.callback_panicked {
        return Err(callback_panic_error(NativeOperation::DriverEnum, result));
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(rows.rows.len())
        .map_err(|error| native_allocation_error(NativeOperation::DriverEnum, result, error))?;
    let mut raw_ids = Vec::new();
    raw_ids
        .try_reserve_exact(rows.rows.len())
        .map_err(|error| native_allocation_error(NativeOperation::DriverEnum, result, error))?;
    raw_ids.extend(rows.rows.iter().map(|(raw, _)| *raw));
    let driver_ids = host
        .map_borrowed_driver_ids(&raw_ids)
        .map_err(|error| retain_native_result(error, NativeOperation::DriverEnum, result))?;
    for ((_, support), driver_id) in rows.rows.into_iter().zip(driver_ids) {
        records.push(Win16HostAcmEnumerationRecord::Driver { driver_id, support });
    }
    Ok(ResultValue::Enumerated { result, records })
}

pub(super) fn add(
    host: &mut Win16AcmHost,
    codec: GuestTextCodec,
    module_instance: u16,
    name: Option<&[u8]>,
    priority: u32,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let add_kind = flags & (ACM_DRIVERADDF_TYPEMASK as u32);
    if add_kind != ACM_DRIVERADDF_NAME as u32 || module_instance != 0 {
        return Ok(ResultValue::Handle {
            result: MMSYSERR_NOTSUPPORTED,
            handle: None,
        });
    }
    let Some(name) = name else {
        return Ok(ResultValue::Handle {
            result: MMSYSERR_INVALPARAM,
            handle: None,
        });
    };
    if name.contains(&0) {
        return Ok(ResultValue::Handle {
            result: MMSYSERR_INVALPARAM,
            handle: None,
        });
    }
    let wide_name = codec.to_wide_z(name)?;
    let reserved_handle = host.reserve_identity()?;
    let mut native_id: HACMDRIVERID = ptr::null_mut();
    // SAFETY: `wide_name` is an owned NUL-terminated UTF-16 name; no guest
    // instance, callback, or pointer value is passed through the host boundary.
    let mut result = unsafe {
        acmDriverAddW(
            &mut native_id,
            ptr::null_mut(),
            wide_name.as_ptr() as isize,
            priority,
            flags,
        )
    };
    let handle = if result == MMSYSERR_NOERROR {
        if native_id.is_null() {
            result = windows_sys::Win32::Media::MMSYSERR_INVALHANDLE;
            None
        } else {
            host.store_reserved(
                reserved_handle,
                NativeObject::DriverId {
                    raw: native_id as usize,
                    added: true,
                },
            )?;
            Some(reserved_handle)
        }
    } else {
        None
    };
    Ok(ResultValue::Handle { result, handle })
}

pub(super) fn open(
    host: &mut Win16AcmHost,
    driver_id: Handle,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(native_id) = host.driver_id(driver_id) else {
        return Ok(ResultValue::Handle {
            result: MMSYSERR_INVALHANDLE,
            handle: None,
        });
    };
    let reserved_handle = host.reserve_identity()?;
    let mut native: HACMDRIVER = ptr::null_mut();
    // SAFETY: native_id is from a live host table entry and output is local.
    let mut result = unsafe { acmDriverOpen(&mut native, native_id, flags) };
    let handle = if result == MMSYSERR_NOERROR {
        if native.is_null() {
            result = windows_sys::Win32::Media::MMSYSERR_INVALHANDLE;
            None
        } else {
            host.store_reserved(reserved_handle, NativeObject::Driver(native as usize))?;
            Some(reserved_handle)
        }
    } else {
        None
    };
    Ok(ResultValue::Handle { result, handle })
}

pub(super) fn close(
    host: &mut Win16AcmHost,
    driver: Handle,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(native) = host.driver(driver) else {
        return Ok(ResultValue::Scalar(MMSYSERR_INVALHANDLE));
    };
    // SAFETY: native is a live ACM driver handle retained by this host.
    let result = unsafe { acmDriverClose(native, flags) };
    if result == MMSYSERR_NOERROR {
        host.remove(driver);
    }
    Ok(ResultValue::Scalar(result))
}

pub(super) fn driver_id(
    host: &mut Win16AcmHost,
    object_kind: ObjectKind,
    object: Handle,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(raw) = host.object_address(object, object_kind) else {
        return Ok(ResultValue::Handle {
            result: MMSYSERR_INVALHANDLE,
            handle: None,
        });
    };
    let mut native_id: HACMDRIVERID = ptr::null_mut();
    // SAFETY: raw was selected from the typed native handle table.
    let result = unsafe { acmDriverID(raw as *mut core::ffi::c_void, &mut native_id, flags) };
    let handle = if result == MMSYSERR_NOERROR {
        host.handle_for_driver_id(native_id)?
    } else {
        None
    };
    Ok(ResultValue::Handle { result, handle })
}

pub(super) fn details(
    host: &mut Win16AcmHost,
    codec: GuestTextCodec,
    driver_id: Handle,
    flags: u32,
    images: &Win16Images,
) -> Result<ResultValue, RuntimeError> {
    let Some(native_id) = host.driver_id(driver_id) else {
        return Ok(ResultValue::DriverDetails {
            result: MMSYSERR_INVALHANDLE,
            details: empty_details(),
        });
    };
    let mut native = ACMDRIVERDETAILSW::default();
    // ACM requires cbStruct to be initialized to the native structure size.
    // SAFETY: The field belongs to a packed record. addr_of plus write_unaligned writes it without creating a misaligned reference.
    unsafe {
        ptr::addr_of_mut!(native.cbStruct)
            .write_unaligned(std::mem::size_of::<ACMDRIVERDETAILSW>() as u32);
    }
    // SAFETY: native is a complete local Unicode details structure.
    let result = unsafe { acmDriverDetailsW(native_id, &mut native, flags) };
    let icon = unsafe { ptr::addr_of!(native.hicon).read_unaligned() };
    let details = unsafe {
        Win16HostAcmDriverDetails {
            type_fourcc: ptr::addr_of!(native.fccType).read_unaligned(),
            compression_fourcc: ptr::addr_of!(native.fccComp).read_unaligned(),
            manufacturer_id: ptr::addr_of!(native.wMid).read_unaligned(),
            product_id: ptr::addr_of!(native.wPid).read_unaligned(),
            acm_version: ptr::addr_of!(native.vdwACM).read_unaligned(),
            driver_version: ptr::addr_of!(native.vdwDriver).read_unaligned(),
            support: ptr::addr_of!(native.fdwSupport).read_unaligned(),
            format_tag_count: ptr::addr_of!(native.cFormatTags).read_unaligned(),
            filter_tag_count: ptr::addr_of!(native.cFilterTags).read_unaligned(),
            icon: if result == MMSYSERR_NOERROR {
                images.retain_acm_icon(icon)?
            } else {
                None
            },
            short_name: wide_fixed_to_guest(
                codec,
                &ptr::addr_of!(native.szShortName).read_unaligned(),
            )?,
            long_name: wide_fixed_to_guest(
                codec,
                &ptr::addr_of!(native.szLongName).read_unaligned(),
            )?,
            copyright: wide_fixed_to_guest(
                codec,
                &ptr::addr_of!(native.szCopyright).read_unaligned(),
            )?,
            licensing: wide_fixed_to_guest(
                codec,
                &ptr::addr_of!(native.szLicensing).read_unaligned(),
            )?,
            features: wide_fixed_to_guest(
                codec,
                &ptr::addr_of!(native.szFeatures).read_unaligned(),
            )?,
        }
    };
    Ok(ResultValue::DriverDetails { result, details })
}

pub(super) fn empty_details() -> Win16HostAcmDriverDetails {
    Win16HostAcmDriverDetails {
        type_fourcc: 0,
        compression_fourcc: 0,
        manufacturer_id: 0,
        product_id: 0,
        acm_version: 0,
        driver_version: 0,
        support: 0,
        format_tag_count: 0,
        filter_tag_count: 0,
        icon: None,
        short_name: [0; 32],
        long_name: [0; 128],
        copyright: [0; 80],
        licensing: [0; 128],
        features: [0; 512],
    }
}

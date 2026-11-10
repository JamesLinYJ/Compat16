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

// SAFETY: Windows calls this function with the system ABI. `driver_id` is an
// HACMDRIVERID valid only for this invocation. `instance` is the host context
// address passed to acmDriverEnum and is not a guest address.
unsafe extern "system" fn driver_enum_callback(
    driver_id: HACMDRIVERID,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if instance == 0 || driver_id.is_null() {
        return 1;
    }
    let context_pointer = instance as *mut DriverRows;
    // SAFETY: `context_pointer` addresses the stack-owned `DriverRows` passed
    // as `instance` for this synchronous acmDriverEnum call. MSACM does not
    // retain that pointer. It is a host address, not a guest address.
    let context = unsafe { &mut *context_pointer };
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
    let rows_pointer = &mut rows as *mut DriverRows;
    let context = rows_pointer as usize;
    // SAFETY: `context` is the address of the stack-owned `rows` for this
    // synchronous acmDriverEnum call. The callback copies only native scalar
    // identities and support flags. MSACM retains no pointer after the call
    // returns. The pointer is a host address, not a guest address.
    let result = unsafe { acmDriverEnum(Some(driver_enum_callback), context, flags) };
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
    let name_units = wide_name.as_ptr();
    let name_parameter = name_units as isize;
    // SAFETY: `native_id` is a local HACMDRIVERID that stays live for this
    // call. `name_parameter` is the address of the NUL-terminated UTF-16 name
    // in `wide_name`, which stays live for this call. The module instance is
    // null. acmDriverAddW writes the driver id and returns an MMRESULT. It
    // retains no pointer. No pointer is a guest address.
    let mut result = unsafe {
        acmDriverAddW(
            &mut native_id,
            ptr::null_mut(),
            name_parameter,
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
    // SAFETY: `native_id` is an HACMDRIVERID from a live host table entry.
    // `native` is a local HACMDRIVER that stays live for this call.
    // acmDriverOpen writes that handle and returns an MMRESULT. It retains no
    // pointer. Neither handle is a guest address.
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
    // SAFETY: `native` is an HACMDRIVER retained by this host table for
    // `driver`. acmDriverClose releases that driver and returns an MMRESULT.
    // It retains no pointer. The handle is not a guest address.
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
    let native_object = raw as *mut core::ffi::c_void;
    // SAFETY: `native_object` is the host ACM handle selected from the typed
    // native handle table. `native_id` is a local HACMDRIVERID that stays live
    // for this call. acmDriverID writes that id and returns an MMRESULT. It
    // retains no pointer. Neither value is a guest address.
    let result = unsafe { acmDriverID(native_object, &mut native_id, flags) };
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
    let struct_size = std::mem::size_of::<ACMDRIVERDETAILSW>() as u32;
    let cb_struct = ptr::addr_of_mut!(native.cbStruct);
    // SAFETY: `cb_struct` addresses the packed `cbStruct` field of this
    // caller-owned `ACMDRIVERDETAILSW`. The record stays live for the write
    // and is a host address, not a guest address. `write_unaligned` stores
    // the structure size without a misaligned reference.
    unsafe { cb_struct.write_unaligned(struct_size) };
    // SAFETY: `native_id` is an HACMDRIVERID from a live host table entry.
    // `native` is a caller-owned `ACMDRIVERDETAILSW` that stays live for this
    // synchronous call. acmDriverDetailsW fills that record and returns an
    // MMRESULT. It retains no pointer. Neither value is a guest address.
    let result = unsafe { acmDriverDetailsW(native_id, &mut native, flags) };
    let icon_field = ptr::addr_of!(native.hicon);
    // SAFETY: `icon_field` addresses the packed `hicon` field of this
    // caller-owned `ACMDRIVERDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // HICON and does not retain the pointer.
    let icon_handle = unsafe { icon_field.read_unaligned() };
    let type_field = ptr::addr_of!(native.fccType);
    // SAFETY: `type_field` addresses the packed `fccType` field of this
    // caller-owned `ACMDRIVERDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let type_fourcc = unsafe { type_field.read_unaligned() };
    let compression_field = ptr::addr_of!(native.fccComp);
    // SAFETY: `compression_field` addresses the packed `fccComp` field of this
    // caller-owned `ACMDRIVERDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let compression_fourcc = unsafe { compression_field.read_unaligned() };
    let manufacturer_field = ptr::addr_of!(native.wMid);
    // SAFETY: `manufacturer_field` addresses the packed `wMid` field of this
    // caller-owned `ACMDRIVERDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u16` and does not retain the pointer.
    let manufacturer_id = unsafe { manufacturer_field.read_unaligned() };
    let product_field = ptr::addr_of!(native.wPid);
    // SAFETY: `product_field` addresses the packed `wPid` field of this
    // caller-owned `ACMDRIVERDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u16` and does not retain the pointer.
    let product_id = unsafe { product_field.read_unaligned() };
    let acm_version_field = ptr::addr_of!(native.vdwACM);
    // SAFETY: `acm_version_field` addresses the packed `vdwACM` field of this
    // caller-owned `ACMDRIVERDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let acm_version = unsafe { acm_version_field.read_unaligned() };
    let driver_version_field = ptr::addr_of!(native.vdwDriver);
    // SAFETY: `driver_version_field` addresses the packed `vdwDriver` field of
    // this caller-owned `ACMDRIVERDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the `u32` and does not retain the pointer.
    let driver_version = unsafe { driver_version_field.read_unaligned() };
    let support_field = ptr::addr_of!(native.fdwSupport);
    // SAFETY: `support_field` addresses the packed `fdwSupport` field of this
    // caller-owned `ACMDRIVERDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let support = unsafe { support_field.read_unaligned() };
    let format_tag_count_field = ptr::addr_of!(native.cFormatTags);
    // SAFETY: `format_tag_count_field` addresses the packed `cFormatTags` field
    // of this caller-owned `ACMDRIVERDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the `u32` and does not retain the pointer.
    let format_tag_count = unsafe { format_tag_count_field.read_unaligned() };
    let filter_tag_count_field = ptr::addr_of!(native.cFilterTags);
    // SAFETY: `filter_tag_count_field` addresses the packed `cFilterTags` field
    // of this caller-owned `ACMDRIVERDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the `u32` and does not retain the pointer.
    let filter_tag_count = unsafe { filter_tag_count_field.read_unaligned() };
    let short_name_field = ptr::addr_of!(native.szShortName);
    // SAFETY: `short_name_field` addresses the packed `szShortName` array of
    // this caller-owned `ACMDRIVERDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the array and does not retain the pointer.
    let short_name_units = unsafe { short_name_field.read_unaligned() };
    let long_name_field = ptr::addr_of!(native.szLongName);
    // SAFETY: `long_name_field` addresses the packed `szLongName` array of
    // this caller-owned `ACMDRIVERDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the array and does not retain the pointer.
    let long_name_units = unsafe { long_name_field.read_unaligned() };
    let copyright_field = ptr::addr_of!(native.szCopyright);
    // SAFETY: `copyright_field` addresses the packed `szCopyright` array of
    // this caller-owned `ACMDRIVERDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the array and does not retain the pointer.
    let copyright_units = unsafe { copyright_field.read_unaligned() };
    let licensing_field = ptr::addr_of!(native.szLicensing);
    // SAFETY: `licensing_field` addresses the packed `szLicensing` array of
    // this caller-owned `ACMDRIVERDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the array and does not retain the pointer.
    let licensing_units = unsafe { licensing_field.read_unaligned() };
    let features_field = ptr::addr_of!(native.szFeatures);
    // SAFETY: `features_field` addresses the packed `szFeatures` array of this
    // caller-owned `ACMDRIVERDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // array and does not retain the pointer.
    let features_units = unsafe { features_field.read_unaligned() };
    let icon = if result == MMSYSERR_NOERROR {
        images.retain_acm_icon(icon_handle)?
    } else {
        None
    };
    let short_name = wide_fixed_to_guest(codec, &short_name_units)?;
    let long_name = wide_fixed_to_guest(codec, &long_name_units)?;
    let copyright = wide_fixed_to_guest(codec, &copyright_units)?;
    let licensing = wide_fixed_to_guest(codec, &licensing_units)?;
    let features = wide_fixed_to_guest(codec, &features_units)?;
    let details = Win16HostAcmDriverDetails {
        type_fourcc,
        compression_fourcc,
        manufacturer_id,
        product_id,
        acm_version,
        driver_version,
        support,
        format_tag_count,
        filter_tag_count,
        icon,
        short_name,
        long_name,
        copyright,
        licensing,
        features,
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

use std::collections::TryReserveError;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostAcmDetailQuery, Win16HostAcmEnumerationRecord,
    Win16HostAcmHandle as Handle, Win16HostAcmItemDetails,
    Win16HostAcmNativeOperation as NativeOperation, Win16HostAcmObjectKind,
    Win16HostAcmResult as ResultValue, Win16HostAcmTagDetails, Win16HostAcmTagKind,
};
use windows_sys::Win32::Media::Audio::{
    ACM_FILTERDETAILSF_FILTER, ACM_FILTERDETAILSF_INDEX, ACM_FILTERTAGDETAILSF_FILTERTAG,
    ACM_FILTERTAGDETAILSF_INDEX, ACM_FILTERTAGDETAILSF_LARGESTSIZE, ACM_FORMATDETAILSF_FORMAT,
    ACM_FORMATDETAILSF_INDEX, ACM_FORMATTAGDETAILSF_FORMATTAG, ACM_FORMATTAGDETAILSF_INDEX,
    ACM_FORMATTAGDETAILSF_LARGESTSIZE, ACMFILTERDETAILSW, ACMFILTERTAGDETAILSW,
    ACMFORMATTAGDETAILSW, HACMDRIVER, HACMDRIVERID, WAVEFILTER, WAVEFORMATEX, acmFilterDetailsW,
    acmFilterEnumW, acmFilterTagDetailsW, acmFilterTagEnumW, acmFormatDetailsW, acmFormatEnumW,
    acmFormatSuggest, acmFormatTagDetailsW, acmFormatTagEnumW, tACMFORMATDETAILSW,
};
use windows_sys::Win32::Media::{MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM, MMSYSERR_NOERROR};

use super::super::guest_text::GuestTextCodec;
use super::text::wide_fixed_to_guest;
use super::{
    Win16AcmHost, callback_contract_error, callback_panic_error, native_allocation_error,
    retain_native_result,
};

pub(super) const WFX_BYTES: usize = 18;
pub(super) const WAVEFILTER_BYTES: usize = 32;

fn driver_handle(host: &Win16AcmHost, driver: Option<Handle>) -> Result<HACMDRIVER, u32> {
    match driver {
        None => Ok(ptr::null_mut()),
        Some(handle) => host.driver(handle).ok_or(MMSYSERR_INVALHANDLE),
    }
}

fn tag_enum_operation(kind: Win16HostAcmTagKind) -> NativeOperation {
    match kind {
        Win16HostAcmTagKind::Format => NativeOperation::FormatTagEnum,
        Win16HostAcmTagKind::Filter => NativeOperation::FilterTagEnum,
    }
}

fn item_enum_operation(kind: Win16HostAcmTagKind) -> NativeOperation {
    match kind {
        Win16HostAcmTagKind::Format => NativeOperation::FormatEnum,
        Win16HostAcmTagKind::Filter => NativeOperation::FilterEnum,
    }
}

pub(super) fn tag_details(
    host: &Win16AcmHost,
    codec: GuestTextCodec,
    kind: Win16HostAcmTagKind,
    driver: Option<(Win16HostAcmObjectKind, Handle)>,
    query: Win16HostAcmDetailQuery,
    initial: Win16HostAcmTagDetails,
) -> Result<ResultValue, RuntimeError> {
    let native_driver = match driver {
        None => ptr::null_mut(),
        Some((kind, handle)) => match host.object_address(handle, kind) {
            Some(raw) => raw as HACMDRIVER,
            None => {
                return Ok(ResultValue::TagDetails {
                    result: MMSYSERR_INVALHANDLE,
                    details: initial,
                });
            }
        },
    };
    let (query_flags, index, tag) = tag_query(kind, query);
    match kind {
        Win16HostAcmTagKind::Format => {
            let mut native = ACMFORMATTAGDETAILSW::default();
            let struct_size = std::mem::size_of::<ACMFORMATTAGDETAILSW>() as u32;
            let cb_struct = ptr::addr_of_mut!(native.cbStruct);
            // SAFETY: `cb_struct` addresses the packed `cbStruct` field of this
            // caller-owned `ACMFORMATTAGDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address. `write_unaligned`
            // stores the structure size without a misaligned reference.
            unsafe { cb_struct.write_unaligned(struct_size) };
            let tag_index = ptr::addr_of_mut!(native.dwFormatTagIndex);
            // SAFETY: `tag_index` addresses the packed `dwFormatTagIndex` field
            // of this caller-owned `ACMFORMATTAGDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores `index` without a misaligned reference.
            unsafe { tag_index.write_unaligned(index) };
            let format_tag = ptr::addr_of_mut!(native.dwFormatTag);
            // SAFETY: `format_tag` addresses the packed `dwFormatTag` field of
            // this caller-owned `ACMFORMATTAGDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores `tag` without a misaligned reference.
            unsafe { format_tag.write_unaligned(tag) };
            // SAFETY: `native_driver` is null or a host `HACMDRIVER`. `native` is
            // a caller-owned `ACMFORMATTAGDETAILSW` that stays live for this
            // synchronous call. `acmFormatTagDetailsW` returns a non-zero
            // `MMRESULT` on failure and retains no pointer. The address is a
            // host address, not a guest address.
            let result = unsafe { acmFormatTagDetailsW(native_driver, &mut native, query_flags) };
            let details = { format_tag_from_native(codec, &native)? };
            return Ok(ResultValue::TagDetails { result, details });
        }
        Win16HostAcmTagKind::Filter => {
            let mut native = ACMFILTERTAGDETAILSW::default();
            let struct_size = std::mem::size_of::<ACMFILTERTAGDETAILSW>() as u32;
            let cb_struct = ptr::addr_of_mut!(native.cbStruct);
            // SAFETY: `cb_struct` addresses the packed `cbStruct` field of this
            // caller-owned `ACMFILTERTAGDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address. `write_unaligned`
            // stores the structure size without a misaligned reference.
            unsafe { cb_struct.write_unaligned(struct_size) };
            let tag_index = ptr::addr_of_mut!(native.dwFilterTagIndex);
            // SAFETY: `tag_index` addresses the packed `dwFilterTagIndex` field
            // of this caller-owned `ACMFILTERTAGDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores `index` without a misaligned reference.
            unsafe { tag_index.write_unaligned(index) };
            let filter_tag = ptr::addr_of_mut!(native.dwFilterTag);
            // SAFETY: `filter_tag` addresses the packed `dwFilterTag` field of
            // this caller-owned `ACMFILTERTAGDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores `tag` without a misaligned reference.
            unsafe { filter_tag.write_unaligned(tag) };
            // SAFETY: `native_driver` is null or a host `HACMDRIVER`. `native` is
            // a caller-owned `ACMFILTERTAGDETAILSW` that stays live for this
            // synchronous call. `acmFilterTagDetailsW` returns a non-zero
            // `MMRESULT` on failure and retains no pointer. The address is a
            // host address, not a guest address.
            let result = unsafe { acmFilterTagDetailsW(native_driver, &mut native, query_flags) };
            let details = { filter_tag_from_native(codec, &native)? };
            return Ok(ResultValue::TagDetails { result, details });
        }
    }
}

fn tag_query(kind: Win16HostAcmTagKind, query: Win16HostAcmDetailQuery) -> (u32, u32, u32) {
    match (kind, query) {
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Index { index, tag }) => {
            (ACM_FORMATTAGDETAILSF_INDEX as u32, index, tag)
        }
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Tag(tag)) => {
            (ACM_FORMATTAGDETAILSF_FORMATTAG as u32, 0, tag)
        }
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Largest { tag }) => {
            (ACM_FORMATTAGDETAILSF_LARGESTSIZE as u32, 0, tag)
        }
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Index { index, tag }) => {
            (ACM_FILTERTAGDETAILSF_INDEX as u32, index, tag)
        }
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Tag(tag)) => {
            (ACM_FILTERTAGDETAILSF_FILTERTAG as u32, 0, tag)
        }
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Largest { tag }) => {
            (ACM_FILTERTAGDETAILSF_LARGESTSIZE as u32, 0, tag)
        }
    }
}

fn format_tag_from_native(
    codec: GuestTextCodec,
    native: &ACMFORMATTAGDETAILSW,
) -> Result<Win16HostAcmTagDetails, RuntimeError> {
    let index_field = ptr::addr_of!(native.dwFormatTagIndex);
    // SAFETY: `index_field` addresses the packed `dwFormatTagIndex` field of
    // this caller-owned `ACMFORMATTAGDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the `u32` and does not retain the pointer.
    let index = unsafe { index_field.read_unaligned() };
    let tag_field = ptr::addr_of!(native.dwFormatTag);
    // SAFETY: `tag_field` addresses the packed `dwFormatTag` field of this
    // caller-owned `ACMFORMATTAGDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let tag = unsafe { tag_field.read_unaligned() };
    let size_field = ptr::addr_of!(native.cbFormatSize);
    // SAFETY: `size_field` addresses the packed `cbFormatSize` field of this
    // caller-owned `ACMFORMATTAGDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let data_bytes = unsafe { size_field.read_unaligned() };
    let support_field = ptr::addr_of!(native.fdwSupport);
    // SAFETY: `support_field` addresses the packed `fdwSupport` field of this
    // caller-owned `ACMFORMATTAGDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let support = unsafe { support_field.read_unaligned() };
    let count_field = ptr::addr_of!(native.cStandardFormats);
    // SAFETY: `count_field` addresses the packed `cStandardFormats` field of
    // this caller-owned `ACMFORMATTAGDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the `u32` and does not retain the pointer.
    let standard_count = unsafe { count_field.read_unaligned() };
    let name_field = ptr::addr_of!(native.szFormatTag);
    // SAFETY: `name_field` addresses the packed `szFormatTag` array of this
    // caller-owned `ACMFORMATTAGDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // array and does not retain the pointer.
    let name_units = unsafe { name_field.read_unaligned() };
    let name = wide_fixed_to_guest(codec, &name_units)?;
    Ok(Win16HostAcmTagDetails {
        index,
        tag,
        data_bytes,
        support,
        standard_count,
        name,
    })
}

fn filter_tag_from_native(
    codec: GuestTextCodec,
    native: &ACMFILTERTAGDETAILSW,
) -> Result<Win16HostAcmTagDetails, RuntimeError> {
    let index_field = ptr::addr_of!(native.dwFilterTagIndex);
    // SAFETY: `index_field` addresses the packed `dwFilterTagIndex` field of
    // this caller-owned `ACMFILTERTAGDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the `u32` and does not retain the pointer.
    let index = unsafe { index_field.read_unaligned() };
    let tag_field = ptr::addr_of!(native.dwFilterTag);
    // SAFETY: `tag_field` addresses the packed `dwFilterTag` field of this
    // caller-owned `ACMFILTERTAGDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let tag = unsafe { tag_field.read_unaligned() };
    let size_field = ptr::addr_of!(native.cbFilterSize);
    // SAFETY: `size_field` addresses the packed `cbFilterSize` field of this
    // caller-owned `ACMFILTERTAGDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let data_bytes = unsafe { size_field.read_unaligned() };
    let support_field = ptr::addr_of!(native.fdwSupport);
    // SAFETY: `support_field` addresses the packed `fdwSupport` field of this
    // caller-owned `ACMFILTERTAGDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // `u32` and does not retain the pointer.
    let support = unsafe { support_field.read_unaligned() };
    let count_field = ptr::addr_of!(native.cStandardFilters);
    // SAFETY: `count_field` addresses the packed `cStandardFilters` field of
    // this caller-owned `ACMFILTERTAGDETAILSW`. The record stays live for the
    // read and is a host address, not a guest address. `read_unaligned` copies
    // the `u32` and does not retain the pointer.
    let standard_count = unsafe { count_field.read_unaligned() };
    let name_field = ptr::addr_of!(native.szFilterTag);
    // SAFETY: `name_field` addresses the packed `szFilterTag` array of this
    // caller-owned `ACMFILTERTAGDETAILSW`. The record stays live for the read
    // and is a host address, not a guest address. `read_unaligned` copies the
    // array and does not retain the pointer.
    let name_units = unsafe { name_field.read_unaligned() };
    let name = wide_fixed_to_guest(codec, &name_units)?;
    Ok(Win16HostAcmTagDetails {
        index,
        tag,
        data_bytes,
        support,
        standard_count,
        name,
    })
}

struct TagRows {
    codec: GuestTextCodec,
    rows: Vec<(usize, u32, Win16HostAcmTagDetails)>,
    allocation_error: Option<TryReserveError>,
    conversion_error: Option<RuntimeError>,
    callback_panicked: bool,
}

impl TagRows {
    fn new(codec: GuestTextCodec) -> Self {
        Self {
            codec,
            rows: Vec::new(),
            allocation_error: None,
            conversion_error: None,
            callback_panicked: false,
        }
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn format_tag_callback(
    driver_id: HACMDRIVERID,
    native: *mut ACMFORMATTAGDETAILSW,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if driver_id.is_null() || native.is_null() || instance == 0 {
        return 1;
    }
    // SAFETY: `instance` is the non-zero address of the stack-owned `TagRows`
    // passed to this synchronous ACM callback. The reference does not outlive
    // the callback and is a host address, not a guest address.
    let context = unsafe { &mut *(instance as *mut TagRows) };
    match catch_unwind(AssertUnwindSafe(|| {
        if let Err(error) = context.rows.try_reserve(1) {
            context.allocation_error = Some(error);
            return false;
        }
        // SAFETY: `native` is the non-null `ACMFORMATTAGDETAILSW` ACM passed to
        // this synchronous callback. The record stays live for the call and is
        // a host address, not a guest address.
        let record = unsafe { &*native };
        let details = match format_tag_from_native(context.codec, record) {
            Ok(details) => details,
            Err(error) => {
                context.conversion_error = Some(error);
                return false;
            }
        };
        context.rows.push((driver_id as usize, support, details));
        true
    })) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => {
            context.callback_panicked = true;
            0
        }
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn filter_tag_callback(
    driver_id: HACMDRIVERID,
    native: *mut ACMFILTERTAGDETAILSW,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if driver_id.is_null() || native.is_null() || instance == 0 {
        return 1;
    }
    // SAFETY: `instance` is the non-zero address of the stack-owned `TagRows`
    // passed to this synchronous ACM callback. The reference does not outlive
    // the callback and is a host address, not a guest address.
    let context = unsafe { &mut *(instance as *mut TagRows) };
    match catch_unwind(AssertUnwindSafe(|| {
        if let Err(error) = context.rows.try_reserve(1) {
            context.allocation_error = Some(error);
            return false;
        }
        // SAFETY: `native` is the non-null `ACMFILTERTAGDETAILSW` ACM passed to
        // this synchronous callback. The record stays live for the call and is
        // a host address, not a guest address.
        let record = unsafe { &*native };
        let details = match filter_tag_from_native(context.codec, record) {
            Ok(details) => details,
            Err(error) => {
                context.conversion_error = Some(error);
                return false;
            }
        };
        context.rows.push((driver_id as usize, support, details));
        true
    })) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => {
            context.callback_panicked = true;
            0
        }
    }
}

pub(super) fn tag_enum(
    host: &mut Win16AcmHost,
    codec: GuestTextCodec,
    kind: Win16HostAcmTagKind,
    driver: Option<Handle>,
    template: Win16HostAcmTagDetails,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let native_driver = match driver_handle(host, driver) {
        Ok(value) => value,
        Err(result) => {
            return Ok(ResultValue::Enumerated {
                result,
                records: Vec::new(),
            });
        }
    };
    let mut rows = TagRows::new(codec);
    let result = match kind {
        Win16HostAcmTagKind::Format => {
            let mut details = ACMFORMATTAGDETAILSW::default();
            let struct_size = std::mem::size_of::<ACMFORMATTAGDETAILSW>() as u32;
            let cb_struct = ptr::addr_of_mut!(details.cbStruct);
            // SAFETY: `cb_struct` addresses the packed `cbStruct` field of this
            // caller-owned `ACMFORMATTAGDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address. `write_unaligned`
            // stores the structure size without a misaligned reference.
            unsafe { cb_struct.write_unaligned(struct_size) };
            let tag_index = ptr::addr_of_mut!(details.dwFormatTagIndex);
            // SAFETY: `tag_index` addresses the packed `dwFormatTagIndex` field
            // of this caller-owned `ACMFORMATTAGDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores the template index without a misaligned
            // reference.
            unsafe { tag_index.write_unaligned(template.index) };
            let format_tag = ptr::addr_of_mut!(details.dwFormatTag);
            // SAFETY: `format_tag` addresses the packed `dwFormatTag` field of
            // this caller-owned `ACMFORMATTAGDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores the template tag without a misaligned
            // reference.
            unsafe { format_tag.write_unaligned(template.tag) };
            let instance = (&mut rows as *mut TagRows) as usize;
            // SAFETY: `native_driver` is null or a host `HACMDRIVER`. `details`
            // is a caller-owned `ACMFORMATTAGDETAILSW` that stays live for this
            // synchronous call. `format_tag_callback` is a static callback.
            // `instance` is the address of the stack-owned `rows` and does not
            // escape the call. `acmFormatTagEnumW` returns a non-zero
            // `MMRESULT` on failure and retains no pointer. Every pointer is a
            // host address, not a guest address.
            let result = unsafe {
                acmFormatTagEnumW(
                    native_driver,
                    &mut details,
                    Some(format_tag_callback),
                    instance,
                    flags,
                )
            };
            result
        }
        Win16HostAcmTagKind::Filter => {
            let mut details = ACMFILTERTAGDETAILSW::default();
            let struct_size = std::mem::size_of::<ACMFILTERTAGDETAILSW>() as u32;
            let cb_struct = ptr::addr_of_mut!(details.cbStruct);
            // SAFETY: `cb_struct` addresses the packed `cbStruct` field of this
            // caller-owned `ACMFILTERTAGDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address. `write_unaligned`
            // stores the structure size without a misaligned reference.
            unsafe { cb_struct.write_unaligned(struct_size) };
            let tag_index = ptr::addr_of_mut!(details.dwFilterTagIndex);
            // SAFETY: `tag_index` addresses the packed `dwFilterTagIndex` field
            // of this caller-owned `ACMFILTERTAGDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores the template index without a misaligned
            // reference.
            unsafe { tag_index.write_unaligned(template.index) };
            let filter_tag = ptr::addr_of_mut!(details.dwFilterTag);
            // SAFETY: `filter_tag` addresses the packed `dwFilterTag` field of
            // this caller-owned `ACMFILTERTAGDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores the template tag without a misaligned
            // reference.
            unsafe { filter_tag.write_unaligned(template.tag) };
            let instance = (&mut rows as *mut TagRows) as usize;
            // SAFETY: `native_driver` is null or a host `HACMDRIVER`. `details`
            // is a caller-owned `ACMFILTERTAGDETAILSW` that stays live for this
            // synchronous call. `filter_tag_callback` is a static callback.
            // `instance` is the address of the stack-owned `rows` and does not
            // escape the call. `acmFilterTagEnumW` returns a non-zero
            // `MMRESULT` on failure and retains no pointer. Every pointer is a
            // host address, not a guest address.
            let result = unsafe {
                acmFilterTagEnumW(
                    native_driver,
                    &mut details,
                    Some(filter_tag_callback),
                    instance,
                    flags,
                )
            };
            result
        }
    };
    let operation = tag_enum_operation(kind);
    if let Some(error) = rows.conversion_error.take() {
        return Err(retain_native_result(error, operation, result));
    }
    if rows.callback_panicked {
        return Err(callback_panic_error(operation, result));
    }
    if let Some(error) = rows.allocation_error.take() {
        return Err(native_allocation_error(operation, result, error));
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(rows.rows.len())
        .map_err(|error| native_allocation_error(operation, result, error))?;
    let mut raw_ids = Vec::new();
    raw_ids
        .try_reserve_exact(rows.rows.len())
        .map_err(|error| native_allocation_error(operation, result, error))?;
    raw_ids.extend(rows.rows.iter().map(|(raw, _, _)| *raw));
    let driver_ids = host
        .map_borrowed_driver_ids(&raw_ids)
        .map_err(|error| retain_native_result(error, operation, result))?;
    for ((_, support, details), driver_id) in rows.rows.into_iter().zip(driver_ids) {
        records.push(Win16HostAcmEnumerationRecord::Tag {
            driver_id,
            support,
            details,
        });
    }
    Ok(ResultValue::Enumerated { result, records })
}

pub(super) fn item_details(
    host: &Win16AcmHost,
    codec: GuestTextCodec,
    kind: Win16HostAcmTagKind,
    driver: Option<Handle>,
    query: Win16HostAcmDetailQuery,
    initial: Win16HostAcmItemDetails,
    capacity: u32,
) -> Result<ResultValue, RuntimeError> {
    let native_driver = match driver_handle(host, driver) {
        Ok(value) => value,
        Err(result) => {
            return Ok(ResultValue::ItemDetails {
                result,
                details: initial,
            });
        }
    };
    let capacity = match usize::try_from(capacity) {
        Ok(value) => value,
        Err(_) => {
            return Ok(ResultValue::ItemDetails {
                result: MMSYSERR_INVALPARAM,
                details: initial,
            });
        }
    };
    let minimum = if kind == Win16HostAcmTagKind::Format {
        WFX_BYTES
    } else {
        WAVEFILTER_BYTES
    };
    if capacity < minimum {
        return Ok(ResultValue::ItemDetails {
            result: MMSYSERR_INVALPARAM,
            details: initial,
        });
    }
    if kind == Win16HostAcmTagKind::Filter
        && matches!(query, Win16HostAcmDetailQuery::Tag(_))
        && filter_size(&initial.data, capacity).is_none()
    {
        return Ok(ResultValue::ItemDetails {
            result: MMSYSERR_INVALPARAM,
            details: initial,
        });
    }
    if kind == Win16HostAcmTagKind::Format
        && matches!(query, Win16HostAcmDetailQuery::Tag(_))
        && normalize_wfx(try_copy_bytes(&initial.data)?)?.is_none()
    {
        return Ok(ResultValue::ItemDetails {
            result: MMSYSERR_INVALPARAM,
            details: initial,
        });
    }
    let mut data = zeroed(capacity)?;
    let copy = initial.data.len().min(capacity);
    data[..copy].copy_from_slice(&initial.data[..copy]);
    let (flags, index, tag) = item_query(kind, query);
    let (result, details) = match kind {
        Win16HostAcmTagKind::Format => {
            let mut native = tACMFORMATDETAILSW::default();
            let struct_size = std::mem::size_of::<tACMFORMATDETAILSW>() as u32;
            let format_bytes = capacity as u32;
            let format_pointer = data.as_mut_ptr().cast::<WAVEFORMATEX>();
            let cb_struct = ptr::addr_of_mut!(native.cbStruct);
            // SAFETY: `cb_struct` addresses the packed `cbStruct` field of this
            // caller-owned `tACMFORMATDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address. `write_unaligned`
            // stores the structure size without a misaligned reference.
            unsafe { cb_struct.write_unaligned(struct_size) };
            let format_index = ptr::addr_of_mut!(native.dwFormatIndex);
            // SAFETY: `format_index` addresses the packed `dwFormatIndex` field
            // of this caller-owned `tACMFORMATDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores `index` without a misaligned reference.
            unsafe { format_index.write_unaligned(index) };
            let format_tag = ptr::addr_of_mut!(native.dwFormatTag);
            // SAFETY: `format_tag` addresses the packed `dwFormatTag` field of
            // this caller-owned `tACMFORMATDETAILSW`. The record stays live for
            // the write and is a host address, not a guest address.
            // `write_unaligned` stores `tag` without a misaligned reference.
            unsafe { format_tag.write_unaligned(tag) };
            let format_field = ptr::addr_of_mut!(native.pwfx);
            // SAFETY: `format_field` addresses the packed `pwfx` field of this
            // caller-owned `tACMFORMATDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address.
            // `write_unaligned` stores `format_pointer` and does not dereference
            // it.
            unsafe { format_field.write_unaligned(format_pointer) };
            let byte_count = ptr::addr_of_mut!(native.cbwfx);
            // SAFETY: `byte_count` addresses the packed `cbwfx` field of this
            // caller-owned `tACMFORMATDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address.
            // `write_unaligned` stores `format_bytes` without a misaligned
            // reference.
            unsafe { byte_count.write_unaligned(format_bytes) };
            // SAFETY: `native_driver` is null or a host `HACMDRIVER`. `native`
            // is a caller-owned `tACMFORMATDETAILSW` whose `pwfx` addresses the
            // caller-owned `data` buffer of `format_bytes` bytes. Both stay
            // live for this synchronous call. `acmFormatDetailsW` returns a
            // non-zero `MMRESULT` on failure and retains no pointer. Every
            // pointer is a host address, not a guest address.
            let result = unsafe { acmFormatDetailsW(native_driver, &mut native, flags) };
            if result != MMSYSERR_NOERROR {
                return Ok(ResultValue::ItemDetails {
                    result,
                    details: initial,
                });
            }
            let index_field = ptr::addr_of!(native.dwFormatIndex);
            // SAFETY: `index_field` addresses the packed `dwFormatIndex` field
            // of this caller-owned `tACMFORMATDETAILSW`. The record stays live
            // for the read and is a host address, not a guest address.
            // `read_unaligned` copies the `u32` and does not retain the pointer.
            let index = unsafe { index_field.read_unaligned() };
            let tag_field = ptr::addr_of!(native.dwFormatTag);
            // SAFETY: `tag_field` addresses the packed `dwFormatTag` field of
            // this caller-owned `tACMFORMATDETAILSW`. The record stays live for
            // the read and is a host address, not a guest address.
            // `read_unaligned` copies the `u32` and does not retain the pointer.
            let tag = unsafe { tag_field.read_unaligned() };
            let support_field = ptr::addr_of!(native.fdwSupport);
            // SAFETY: `support_field` addresses the packed `fdwSupport` field of
            // this caller-owned `tACMFORMATDETAILSW`. The record stays live for
            // the read and is a host address, not a guest address.
            // `read_unaligned` copies the `u32` and does not retain the pointer.
            let support = unsafe { support_field.read_unaligned() };
            let name_field = ptr::addr_of!(native.szFormat);
            // SAFETY: `name_field` addresses the packed `szFormat` array of this
            // caller-owned `tACMFORMATDETAILSW`. The record stays live for the
            // read and is a host address, not a guest address. `read_unaligned`
            // copies the array and does not retain the pointer.
            let name_units = unsafe { name_field.read_unaligned() };
            let name = wide_fixed_to_guest(codec, &name_units)?;
            let item_data = take_format_data(&data, capacity)?;
            let item = Win16HostAcmItemDetails {
                index,
                tag,
                support,
                name,
                data: item_data,
            };
            (result, item)
        }
        Win16HostAcmTagKind::Filter => {
            let mut native = ACMFILTERDETAILSW::default();
            let struct_size = std::mem::size_of::<ACMFILTERDETAILSW>() as u32;
            let filter_bytes = capacity as u32;
            let filter_pointer = data.as_mut_ptr().cast::<WAVEFILTER>();
            let cb_struct = ptr::addr_of_mut!(native.cbStruct);
            // SAFETY: `cb_struct` addresses the packed `cbStruct` field of this
            // caller-owned `ACMFILTERDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address. `write_unaligned`
            // stores the structure size without a misaligned reference.
            unsafe { cb_struct.write_unaligned(struct_size) };
            let filter_index = ptr::addr_of_mut!(native.dwFilterIndex);
            // SAFETY: `filter_index` addresses the packed `dwFilterIndex` field
            // of this caller-owned `ACMFILTERDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores `index` without a misaligned reference.
            unsafe { filter_index.write_unaligned(index) };
            let filter_tag = ptr::addr_of_mut!(native.dwFilterTag);
            // SAFETY: `filter_tag` addresses the packed `dwFilterTag` field of
            // this caller-owned `ACMFILTERDETAILSW`. The record stays live for
            // the write and is a host address, not a guest address.
            // `write_unaligned` stores `tag` without a misaligned reference.
            unsafe { filter_tag.write_unaligned(tag) };
            let filter_field = ptr::addr_of_mut!(native.pwfltr);
            // SAFETY: `filter_field` addresses the packed `pwfltr` field of this
            // caller-owned `ACMFILTERDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address.
            // `write_unaligned` stores `filter_pointer` and does not dereference
            // it.
            unsafe { filter_field.write_unaligned(filter_pointer) };
            let byte_count = ptr::addr_of_mut!(native.cbwfltr);
            // SAFETY: `byte_count` addresses the packed `cbwfltr` field of this
            // caller-owned `ACMFILTERDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address.
            // `write_unaligned` stores `filter_bytes` without a misaligned
            // reference.
            unsafe { byte_count.write_unaligned(filter_bytes) };
            // SAFETY: `native_driver` is null or a host `HACMDRIVER`. `native`
            // is a caller-owned `ACMFILTERDETAILSW` whose `pwfltr` addresses the
            // caller-owned `data` buffer of `filter_bytes` bytes. Both stay
            // live for this synchronous call. `acmFilterDetailsW` returns a
            // non-zero `MMRESULT` on failure and retains no pointer. Every
            // pointer is a host address, not a guest address.
            let result = unsafe { acmFilterDetailsW(native_driver, &mut native, flags) };
            if result != MMSYSERR_NOERROR {
                return Ok(ResultValue::ItemDetails {
                    result,
                    details: initial,
                });
            }
            let index_field = ptr::addr_of!(native.dwFilterIndex);
            // SAFETY: `index_field` addresses the packed `dwFilterIndex` field
            // of this caller-owned `ACMFILTERDETAILSW`. The record stays live
            // for the read and is a host address, not a guest address.
            // `read_unaligned` copies the `u32` and does not retain the pointer.
            let index = unsafe { index_field.read_unaligned() };
            let tag_field = ptr::addr_of!(native.dwFilterTag);
            // SAFETY: `tag_field` addresses the packed `dwFilterTag` field of
            // this caller-owned `ACMFILTERDETAILSW`. The record stays live for
            // the read and is a host address, not a guest address.
            // `read_unaligned` copies the `u32` and does not retain the pointer.
            let tag = unsafe { tag_field.read_unaligned() };
            let support_field = ptr::addr_of!(native.fdwSupport);
            // SAFETY: `support_field` addresses the packed `fdwSupport` field of
            // this caller-owned `ACMFILTERDETAILSW`. The record stays live for
            // the read and is a host address, not a guest address.
            // `read_unaligned` copies the `u32` and does not retain the pointer.
            let support = unsafe { support_field.read_unaligned() };
            let name_field = ptr::addr_of!(native.szFilter);
            // SAFETY: `name_field` addresses the packed `szFilter` array of this
            // caller-owned `ACMFILTERDETAILSW`. The record stays live for the
            // read and is a host address, not a guest address. `read_unaligned`
            // copies the array and does not retain the pointer.
            let name_units = unsafe { name_field.read_unaligned() };
            let name = wide_fixed_to_guest(codec, &name_units)?;
            let item_data = take_filter_data(&data, capacity)?;
            let item = Win16HostAcmItemDetails {
                index,
                tag,
                support,
                name,
                data: item_data,
            };
            (result, item)
        }
    };
    Ok(ResultValue::ItemDetails { result, details })
}

fn item_query(kind: Win16HostAcmTagKind, query: Win16HostAcmDetailQuery) -> (u32, u32, u32) {
    match (kind, query) {
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Index { index, tag }) => {
            (ACM_FORMATDETAILSF_INDEX as u32, index, tag)
        }
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Tag(tag)) => {
            (ACM_FORMATDETAILSF_FORMAT as u32, 0, tag)
        }
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Largest { tag }) => {
            (ACM_FORMATDETAILSF_INDEX as u32, 0, tag)
        }
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Index { index, tag }) => {
            (ACM_FILTERDETAILSF_INDEX as u32, index, tag)
        }
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Tag(tag)) => {
            (ACM_FILTERDETAILSF_FILTER as u32, 0, tag)
        }
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Largest { tag }) => {
            (ACM_FILTERDETAILSF_INDEX as u32, 0, tag)
        }
    }
}

struct ItemRows {
    codec: GuestTextCodec,
    capacity: usize,
    data: Vec<u8>,
    rows: Vec<(usize, u32, Win16HostAcmItemDetails)>,
    failed: bool,
    allocation_error: Option<TryReserveError>,
    conversion_error: Option<RuntimeError>,
    invalid_native_buffer: bool,
    callback_panicked: bool,
}

fn read_wave_bytes(pointer: *mut WAVEFORMATEX, capacity: usize) -> Option<usize> {
    if pointer.is_null() || capacity < WFX_BYTES {
        return None;
    }
    // SAFETY: `pointer` addresses the caller-owned enumeration buffer for at
    // least `capacity` bytes. The callback checked that this is that buffer
    // before calling. The slice does not outlive this function. The address is
    // a host address, not a guest address.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), capacity) };
    wave_size(bytes, capacity)
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn format_enum_callback(
    driver_id: HACMDRIVERID,
    native: *mut tACMFORMATDETAILSW,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if driver_id.is_null() || native.is_null() || instance == 0 {
        return 1;
    }
    // SAFETY: `instance` is the non-zero address of the stack-owned `ItemRows`
    // passed to this synchronous ACM callback. The reference does not outlive
    // the callback and is a host address, not a guest address.
    let context = unsafe { &mut *(instance as *mut ItemRows) };
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `native` is the non-null `tACMFORMATDETAILSW` ACM passed to
        // this synchronous callback. `pwfx` is a packed pointer field. The
        // record stays live for the read and is a host address, not a guest
        // address. `read_unaligned` copies the pointer and does not retain it.
        let data_pointer = unsafe { ptr::addr_of!((*native).pwfx).read_unaligned() };
        if data_pointer.is_null() || data_pointer.cast::<u8>() != context.data.as_mut_ptr() {
            context.invalid_native_buffer = true;
            return Err(());
        }
        // SAFETY: `native` is the non-null `tACMFORMATDETAILSW` ACM passed to
        // this synchronous callback. `cbwfx` is a packed field. The record
        // stays live for the read and is a host address, not a guest address.
        // `read_unaligned` copies the `u32` and does not retain the pointer.
        let cbwfx = unsafe { ptr::addr_of!((*native).cbwfx).read_unaligned() } as usize;
        if cbwfx > context.capacity {
            context.invalid_native_buffer = true;
            return Err(());
        }
        let Some(actual_bytes) = read_wave_bytes(data_pointer, context.capacity) else {
            context.invalid_native_buffer = true;
            return Err(());
        };
        if let Err(error) = context.rows.try_reserve(1) {
            context.allocation_error = Some(error);
            return Err(());
        }
        let mut data = Vec::new();
        if let Err(error) = data.try_reserve_exact(actual_bytes) {
            context.allocation_error = Some(error);
            return Err(());
        }
        data.extend_from_slice(&context.data[..actual_bytes]);
        // SAFETY: `native` is the non-null `tACMFORMATDETAILSW` ACM passed to
        // this synchronous callback. `dwFormatIndex` is a packed field. The
        // record stays live for the read and is a host address, not a guest
        // address. `read_unaligned` copies the `u32` and does not retain it.
        let index = unsafe { ptr::addr_of!((*native).dwFormatIndex).read_unaligned() };
        // SAFETY: `native` is the non-null `tACMFORMATDETAILSW` ACM passed to
        // this synchronous callback. `dwFormatTag` is a packed field. The
        // record stays live for the read and is a host address, not a guest
        // address. `read_unaligned` copies the `u32` and does not retain it.
        let tag = unsafe { ptr::addr_of!((*native).dwFormatTag).read_unaligned() };
        // SAFETY: `native` is the non-null `tACMFORMATDETAILSW` ACM passed to
        // this synchronous callback. `fdwSupport` is a packed field. The record
        // stays live for the read and is a host address, not a guest address.
        // `read_unaligned` copies the `u32` and does not retain the pointer.
        let item_support = unsafe { ptr::addr_of!((*native).fdwSupport).read_unaligned() };
        // SAFETY: `native` is the non-null `tACMFORMATDETAILSW` ACM passed to
        // this synchronous callback. `szFormat` is a packed array. The record
        // stays live for the read and is a host address, not a guest address.
        // `read_unaligned` copies the array and does not retain the pointer.
        let name_units = unsafe { ptr::addr_of!((*native).szFormat).read_unaligned() };
        let name = match wide_fixed_to_guest(context.codec, &name_units) {
            Ok(name) => name,
            Err(error) => {
                context.conversion_error = Some(error);
                return Err(());
            }
        };
        let details = Win16HostAcmItemDetails {
            index,
            tag,
            support: item_support,
            name,
            data,
        };
        context.rows.push((driver_id as usize, support, details));
        Ok::<(), ()>(())
    })) {
        Ok(Ok(())) => 1,
        Ok(Err(())) => {
            context.failed = true;
            0
        }
        Err(_) => {
            context.failed = true;
            context.callback_panicked = true;
            0
        }
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn filter_enum_callback(
    driver_id: HACMDRIVERID,
    native: *mut ACMFILTERDETAILSW,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if driver_id.is_null() || native.is_null() || instance == 0 {
        return 1;
    }
    // SAFETY: `instance` is the non-zero address of the stack-owned `ItemRows`
    // passed to this synchronous ACM callback. The reference does not outlive
    // the callback and is a host address, not a guest address.
    let context = unsafe { &mut *(instance as *mut ItemRows) };
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `native` is the non-null `ACMFILTERDETAILSW` ACM passed to
        // this synchronous callback. `pwfltr` is a packed pointer field. The
        // record stays live for the read and is a host address, not a guest
        // address. `read_unaligned` copies the pointer and does not retain it.
        let data_pointer = unsafe { ptr::addr_of!((*native).pwfltr).read_unaligned() };
        if data_pointer.is_null() || data_pointer.cast::<u8>() != context.data.as_mut_ptr() {
            context.invalid_native_buffer = true;
            return Err(());
        }
        // SAFETY: `native` is the non-null `ACMFILTERDETAILSW` ACM passed to
        // this synchronous callback. `cbwfltr` is a packed field. The record
        // stays live for the read and is a host address, not a guest address.
        // `read_unaligned` copies the `u32` and does not retain the pointer.
        let cbwfltr = unsafe { ptr::addr_of!((*native).cbwfltr).read_unaligned() } as usize;
        if cbwfltr > context.capacity {
            context.invalid_native_buffer = true;
            return Err(());
        }
        let Some(actual_bytes) = filter_size(&context.data, context.capacity) else {
            context.invalid_native_buffer = true;
            return Err(());
        };
        if let Err(error) = context.rows.try_reserve(1) {
            context.allocation_error = Some(error);
            return Err(());
        }
        let mut data = Vec::new();
        if let Err(error) = data.try_reserve_exact(actual_bytes) {
            context.allocation_error = Some(error);
            return Err(());
        }
        data.extend_from_slice(&context.data[..actual_bytes]);
        // SAFETY: `native` is the non-null `ACMFILTERDETAILSW` ACM passed to
        // this synchronous callback. `dwFilterIndex` is a packed field. The
        // record stays live for the read and is a host address, not a guest
        // address. `read_unaligned` copies the `u32` and does not retain it.
        let index = unsafe { ptr::addr_of!((*native).dwFilterIndex).read_unaligned() };
        // SAFETY: `native` is the non-null `ACMFILTERDETAILSW` ACM passed to
        // this synchronous callback. `dwFilterTag` is a packed field. The
        // record stays live for the read and is a host address, not a guest
        // address. `read_unaligned` copies the `u32` and does not retain it.
        let tag = unsafe { ptr::addr_of!((*native).dwFilterTag).read_unaligned() };
        // SAFETY: `native` is the non-null `ACMFILTERDETAILSW` ACM passed to
        // this synchronous callback. `fdwSupport` is a packed field. The record
        // stays live for the read and is a host address, not a guest address.
        // `read_unaligned` copies the `u32` and does not retain the pointer.
        let item_support = unsafe { ptr::addr_of!((*native).fdwSupport).read_unaligned() };
        // SAFETY: `native` is the non-null `ACMFILTERDETAILSW` ACM passed to
        // this synchronous callback. `szFilter` is a packed array. The record
        // stays live for the read and is a host address, not a guest address.
        // `read_unaligned` copies the array and does not retain the pointer.
        let name_units = unsafe { ptr::addr_of!((*native).szFilter).read_unaligned() };
        let name = match wide_fixed_to_guest(context.codec, &name_units) {
            Ok(name) => name,
            Err(error) => {
                context.conversion_error = Some(error);
                return Err(());
            }
        };
        let details = Win16HostAcmItemDetails {
            index,
            tag,
            support: item_support,
            name,
            data,
        };
        context.rows.push((driver_id as usize, support, details));
        Ok::<(), ()>(())
    })) {
        Ok(Ok(())) => 1,
        Ok(Err(())) => {
            context.failed = true;
            0
        }
        Err(_) => {
            context.failed = true;
            context.callback_panicked = true;
            0
        }
    }
}

pub(super) fn item_enum(
    host: &mut Win16AcmHost,
    codec: GuestTextCodec,
    kind: Win16HostAcmTagKind,
    driver: Option<Handle>,
    template: Win16HostAcmItemDetails,
    capacity: u32,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let native_driver = match driver_handle(host, driver) {
        Ok(value) => value,
        Err(result) => {
            return Ok(ResultValue::Enumerated {
                result,
                records: Vec::new(),
            });
        }
    };
    let capacity = match usize::try_from(capacity) {
        Ok(value) => value,
        Err(_) => {
            return Ok(ResultValue::Enumerated {
                result: MMSYSERR_INVALPARAM,
                records: Vec::new(),
            });
        }
    };
    let minimum = if kind == Win16HostAcmTagKind::Format {
        WFX_BYTES
    } else {
        WAVEFILTER_BYTES
    };
    if capacity < minimum {
        return Ok(ResultValue::Enumerated {
            result: MMSYSERR_INVALPARAM,
            records: Vec::new(),
        });
    }
    // The native enumeration flags decide which template members are input.
    // The runtime zero-fills the owned host buffer and copies only fields
    // declared valid by those flags; normalizing the entire WFX/WAVEFILTER
    // here would reject legal templates with untouched, uninitialized bytes.
    let mut data = zeroed(capacity)?;
    let copy = template.data.len().min(capacity);
    data[..copy].copy_from_slice(&template.data[..copy]);
    let mut rows = ItemRows {
        codec,
        capacity,
        data,
        rows: Vec::new(),
        failed: false,
        allocation_error: None,
        conversion_error: None,
        invalid_native_buffer: false,
        callback_panicked: false,
    };
    let result = match kind {
        Win16HostAcmTagKind::Format => {
            let mut native = tACMFORMATDETAILSW::default();
            let struct_size = std::mem::size_of::<tACMFORMATDETAILSW>() as u32;
            let format_bytes = capacity as u32;
            let format_pointer: *mut WAVEFORMATEX = rows.data.as_mut_ptr().cast();
            let cb_struct = ptr::addr_of_mut!(native.cbStruct);
            // SAFETY: `cb_struct` addresses the packed `cbStruct` field of this
            // caller-owned `tACMFORMATDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address. `write_unaligned`
            // stores the structure size without a misaligned reference.
            unsafe { cb_struct.write_unaligned(struct_size) };
            let format_index = ptr::addr_of_mut!(native.dwFormatIndex);
            // SAFETY: `format_index` addresses the packed `dwFormatIndex` field
            // of this caller-owned `tACMFORMATDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores the template index without a misaligned
            // reference.
            unsafe { format_index.write_unaligned(template.index) };
            let format_tag = ptr::addr_of_mut!(native.dwFormatTag);
            // SAFETY: `format_tag` addresses the packed `dwFormatTag` field of
            // this caller-owned `tACMFORMATDETAILSW`. The record stays live for
            // the write and is a host address, not a guest address.
            // `write_unaligned` stores the template tag without a misaligned
            // reference.
            unsafe { format_tag.write_unaligned(template.tag) };
            let format_field = ptr::addr_of_mut!(native.pwfx);
            // SAFETY: `format_field` addresses the packed `pwfx` field of this
            // caller-owned `tACMFORMATDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address.
            // `write_unaligned` stores `format_pointer` and does not dereference
            // it.
            unsafe { format_field.write_unaligned(format_pointer) };
            let byte_count = ptr::addr_of_mut!(native.cbwfx);
            // SAFETY: `byte_count` addresses the packed `cbwfx` field of this
            // caller-owned `tACMFORMATDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address.
            // `write_unaligned` stores `format_bytes` without a misaligned
            // reference.
            unsafe { byte_count.write_unaligned(format_bytes) };
            let instance = (&mut rows as *mut ItemRows) as usize;
            // SAFETY: `native_driver` is null or a host `HACMDRIVER`. `native`
            // is a caller-owned `tACMFORMATDETAILSW` whose `pwfx` addresses the
            // caller-owned `rows.data` buffer. `format_enum_callback` is a
            // static callback. `instance` is the address of the stack-owned
            // `rows` and does not escape the call. All of that storage stays
            // live for this synchronous call. `acmFormatEnumW` returns a
            // non-zero `MMRESULT` on failure and retains no pointer. Every
            // pointer is a host address, not a guest address.
            unsafe {
                acmFormatEnumW(
                    native_driver,
                    &mut native,
                    Some(format_enum_callback),
                    instance,
                    flags,
                )
            }
        }
        Win16HostAcmTagKind::Filter => {
            let mut native = ACMFILTERDETAILSW::default();
            let struct_size = std::mem::size_of::<ACMFILTERDETAILSW>() as u32;
            let filter_bytes = capacity as u32;
            let filter_pointer: *mut WAVEFILTER = rows.data.as_mut_ptr().cast();
            let cb_struct = ptr::addr_of_mut!(native.cbStruct);
            // SAFETY: `cb_struct` addresses the packed `cbStruct` field of this
            // caller-owned `ACMFILTERDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address. `write_unaligned`
            // stores the structure size without a misaligned reference.
            unsafe { cb_struct.write_unaligned(struct_size) };
            let filter_index = ptr::addr_of_mut!(native.dwFilterIndex);
            // SAFETY: `filter_index` addresses the packed `dwFilterIndex` field
            // of this caller-owned `ACMFILTERDETAILSW`. The record stays live
            // for the write and is a host address, not a guest address.
            // `write_unaligned` stores the template index without a misaligned
            // reference.
            unsafe { filter_index.write_unaligned(template.index) };
            let filter_tag = ptr::addr_of_mut!(native.dwFilterTag);
            // SAFETY: `filter_tag` addresses the packed `dwFilterTag` field of
            // this caller-owned `ACMFILTERDETAILSW`. The record stays live for
            // the write and is a host address, not a guest address.
            // `write_unaligned` stores the template tag without a misaligned
            // reference.
            unsafe { filter_tag.write_unaligned(template.tag) };
            let filter_field = ptr::addr_of_mut!(native.pwfltr);
            // SAFETY: `filter_field` addresses the packed `pwfltr` field of this
            // caller-owned `ACMFILTERDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address.
            // `write_unaligned` stores `filter_pointer` and does not dereference
            // it.
            unsafe { filter_field.write_unaligned(filter_pointer) };
            let byte_count = ptr::addr_of_mut!(native.cbwfltr);
            // SAFETY: `byte_count` addresses the packed `cbwfltr` field of this
            // caller-owned `ACMFILTERDETAILSW`. The record stays live for the
            // write and is a host address, not a guest address.
            // `write_unaligned` stores `filter_bytes` without a misaligned
            // reference.
            unsafe { byte_count.write_unaligned(filter_bytes) };
            let instance = (&mut rows as *mut ItemRows) as usize;
            // SAFETY: `native_driver` is null or a host `HACMDRIVER`. `native`
            // is a caller-owned `ACMFILTERDETAILSW` whose `pwfltr` addresses the
            // caller-owned `rows.data` buffer. `filter_enum_callback` is a
            // static callback. `instance` is the address of the stack-owned
            // `rows` and does not escape the call. All of that storage stays
            // live for this synchronous call. `acmFilterEnumW` returns a
            // non-zero `MMRESULT` on failure and retains no pointer. Every
            // pointer is a host address, not a guest address.
            unsafe {
                acmFilterEnumW(
                    native_driver,
                    &mut native,
                    Some(filter_enum_callback),
                    instance,
                    flags,
                )
            }
        }
    };
    let operation = item_enum_operation(kind);
    if rows.invalid_native_buffer {
        return Err(callback_contract_error(
            operation,
            result,
            "native ACM enumeration returned an unexpected data buffer",
        ));
    }
    if rows.callback_panicked {
        return Err(callback_panic_error(operation, result));
    }
    if let Some(error) = rows.allocation_error.take() {
        return Err(native_allocation_error(operation, result, error));
    }
    if let Some(error) = rows.conversion_error.take() {
        return Err(retain_native_result(error, operation, result));
    }
    if rows.failed {
        return Err(callback_contract_error(
            operation,
            result,
            "native ACM item-enumeration callback failed without a recorded cause",
        ));
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(rows.rows.len())
        .map_err(|error| native_allocation_error(operation, result, error))?;
    let mut raw_ids = Vec::new();
    raw_ids
        .try_reserve_exact(rows.rows.len())
        .map_err(|error| native_allocation_error(operation, result, error))?;
    raw_ids.extend(rows.rows.iter().map(|(raw, _, _)| *raw));
    let driver_ids = host
        .map_borrowed_driver_ids(&raw_ids)
        .map_err(|error| retain_native_result(error, operation, result))?;
    for ((_, support, details), driver_id) in rows.rows.into_iter().zip(driver_ids) {
        records.push(Win16HostAcmEnumerationRecord::Item {
            driver_id,
            support,
            details,
        });
    }
    Ok(ResultValue::Enumerated { result, records })
}

pub(super) fn suggest(
    host: &Win16AcmHost,
    driver: Option<Handle>,
    source: Vec<u8>,
    mut destination: Vec<u8>,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let native_driver = match driver_handle(host, driver) {
        Ok(value) => value,
        Err(result) => {
            return Ok(ResultValue::FormatSuggest {
                result,
                destination,
            });
        }
    };
    let Some(source) = normalize_wfx(source)? else {
        return Ok(ResultValue::FormatSuggest {
            result: MMSYSERR_INVALPARAM,
            destination,
        });
    };
    if destination.len() < WFX_BYTES || destination.len() > u32::MAX as usize {
        return Ok(ResultValue::FormatSuggest {
            result: MMSYSERR_INVALPARAM,
            destination,
        });
    }
    let source_format = source.as_ptr().cast_mut().cast::<WAVEFORMATEX>();
    let destination_format = destination.as_mut_ptr().cast::<WAVEFORMATEX>();
    let destination_bytes = destination.len() as u32;
    // SAFETY: `source_format` and `destination_format` address the caller-owned
    // WAVEFORMATEX buffers, which stay live for this synchronous call.
    // `destination_bytes` is the destination length. `native_driver` is null or
    // a host `HACMDRIVER`. `acmFormatSuggest` returns a non-zero `MMRESULT` on
    // failure and retains no pointer. Both pointers are host addresses, not
    // guest addresses.
    let mut result = unsafe {
        acmFormatSuggest(
            native_driver,
            source_format,
            destination_format,
            destination_bytes,
            flags,
        )
    };
    if result == MMSYSERR_NOERROR {
        if let Some(length) = wave_size(&destination, destination.len()) {
            destination.truncate(length);
        } else {
            result = MMSYSERR_INVALPARAM;
        }
    }
    Ok(ResultValue::FormatSuggest {
        result,
        destination,
    })
}

pub(super) fn zeroed(length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate native ACM data buffer",
            error,
        )
    })?;
    bytes.resize(length, 0);
    Ok(bytes)
}

pub(super) fn normalize_wfx(mut bytes: Vec<u8>) -> Result<Option<Vec<u8>>, RuntimeError> {
    if bytes.len() < 2 || bytes.len() > u32::MAX as usize {
        return Ok(None);
    }
    let format_tag = u16::from_le_bytes([bytes[0], bytes[1]]);
    if format_tag == 1 {
        if bytes.len() < 16 {
            return Ok(None);
        }
        if bytes.len() < WFX_BYTES {
            bytes
                .try_reserve_exact(WFX_BYTES - bytes.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "normalize host PCMWAVEFORMAT",
                        error,
                    )
                })?;
            bytes.resize(WFX_BYTES, 0);
        }
        bytes[16..18].copy_from_slice(&0u16.to_le_bytes());
        bytes.truncate(WFX_BYTES);
        return Ok(Some(bytes));
    }
    if bytes.len() < WFX_BYTES {
        return Ok(None);
    }
    let cb_size = u16::from_le_bytes([bytes[16], bytes[17]]) as usize;
    let Some(needed) = WFX_BYTES.checked_add(cb_size) else {
        return Ok(None);
    };
    if needed > bytes.len() {
        return Ok(None);
    }
    bytes.truncate(needed);
    Ok(Some(bytes))
}

pub(super) fn try_copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy host ACM format bytes", error)
    })?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

pub(super) fn wave_size(bytes: &[u8], capacity: usize) -> Option<usize> {
    if capacity < WFX_BYTES || bytes.len() < WFX_BYTES {
        return None;
    }
    let cb_size = u16::from_le_bytes([bytes[16], bytes[17]]) as usize;
    let needed = WFX_BYTES.checked_add(cb_size)?;
    (needed <= capacity && needed <= bytes.len()).then_some(needed)
}

pub(super) fn filter_size(bytes: &[u8], capacity: usize) -> Option<usize> {
    if capacity < WAVEFILTER_BYTES || bytes.len() < 4 {
        return None;
    }
    let declared = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let actual = declared.max(WAVEFILTER_BYTES);
    (actual <= capacity && actual <= bytes.len()).then_some(actual)
}

fn take_format_data(bytes: &[u8], capacity: usize) -> Result<Vec<u8>, RuntimeError> {
    let Some(length) = wave_size(bytes, capacity) else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native ACM produced an invalid WAVEFORMATEX result extent",
        ));
    };
    try_copy_bytes(&bytes[..length])
}

fn take_filter_data(bytes: &[u8], capacity: usize) -> Result<Vec<u8>, RuntimeError> {
    let Some(length) = filter_size(bytes, capacity) else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native ACM produced an invalid WAVEFILTER result extent",
        ));
    };
    try_copy_bytes(&bytes[..length])
}

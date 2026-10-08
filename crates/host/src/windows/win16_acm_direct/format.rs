use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::collections::TryReserveError;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostAcmDetailQuery,
    Win16HostAcmEnumerationRecord, Win16HostAcmHandle as Handle, Win16HostAcmItemDetails,
    Win16HostAcmNativeOperation as NativeOperation, Win16HostAcmObjectKind,
    Win16HostAcmResult as ResultValue,
    Win16HostAcmTagDetails, Win16HostAcmTagKind,
};
use windows_sys::Win32::Media::Audio::{
    ACMFILTERDETAILSW, ACMFILTERTAGDETAILSW, ACMFORMATTAGDETAILSW,
    ACM_FILTERDETAILSF_FILTER,
    ACM_FILTERDETAILSF_INDEX, ACM_FILTERTAGDETAILSF_FILTERTAG,
    ACM_FILTERTAGDETAILSF_INDEX, ACM_FILTERTAGDETAILSF_LARGESTSIZE,
    ACM_FORMATDETAILSF_FORMAT,
    ACM_FORMATDETAILSF_INDEX, ACM_FORMATTAGDETAILSF_FORMATTAG,
    ACM_FORMATTAGDETAILSF_INDEX, ACM_FORMATTAGDETAILSF_LARGESTSIZE,
    HACMDRIVER, HACMDRIVERID, WAVEFILTER, WAVEFORMATEX, tACMFORMATDETAILSW,
    acmFilterDetailsW, acmFilterEnumW,
    acmFilterTagDetailsW, acmFilterTagEnumW, acmFormatDetailsW,
    acmFormatEnumW, acmFormatSuggest, acmFormatTagDetailsW, acmFormatTagEnumW,
};
use windows_sys::Win32::Media::{MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM,
    MMSYSERR_NOERROR};

use super::{Win16AcmHost, callback_contract_error, callback_panic_error,
    native_allocation_error, retain_native_result};
use super::super::guest_text::GuestTextCodec;
use super::text::wide_fixed_to_guest;

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
            None => return Ok(ResultValue::TagDetails {
                result: MMSYSERR_INVALHANDLE, details: initial,
            }),
        },
    };
    let (query_flags, index, tag) = tag_query(kind, query);
    match kind {
        Win16HostAcmTagKind::Format => {
            let mut native = ACMFORMATTAGDETAILSW::default();
            unsafe {
                ptr::addr_of_mut!(native.cbStruct).write_unaligned(
                    std::mem::size_of::<ACMFORMATTAGDETAILSW>() as u32,
                );
                ptr::addr_of_mut!(native.dwFormatTagIndex).write_unaligned(index);
                ptr::addr_of_mut!(native.dwFormatTag).write_unaligned(tag);
            }
            let result = unsafe { acmFormatTagDetailsW(native_driver, &mut native, query_flags) };
            let details = unsafe { format_tag_from_native(codec, &native)? };
            return Ok(ResultValue::TagDetails { result, details });
        }
        Win16HostAcmTagKind::Filter => {
            let mut native = ACMFILTERTAGDETAILSW::default();
            unsafe {
                ptr::addr_of_mut!(native.cbStruct).write_unaligned(
                    std::mem::size_of::<ACMFILTERTAGDETAILSW>() as u32,
                );
                ptr::addr_of_mut!(native.dwFilterTagIndex).write_unaligned(index);
                ptr::addr_of_mut!(native.dwFilterTag).write_unaligned(tag);
            }
            let result = unsafe { acmFilterTagDetailsW(native_driver, &mut native, query_flags) };
            let details = unsafe { filter_tag_from_native(codec, &native)? };
            return Ok(ResultValue::TagDetails { result, details });
        }
    }
}

fn tag_query(kind: Win16HostAcmTagKind, query: Win16HostAcmDetailQuery) -> (u32, u32, u32) {
    match (kind, query) {
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Index { index, tag }) =>
            (ACM_FORMATTAGDETAILSF_INDEX as u32, index, tag),
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Tag(tag)) =>
            (ACM_FORMATTAGDETAILSF_FORMATTAG as u32, 0, tag),
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Largest { tag }) =>
            (ACM_FORMATTAGDETAILSF_LARGESTSIZE as u32, 0, tag),
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Index { index, tag }) =>
            (ACM_FILTERTAGDETAILSF_INDEX as u32, index, tag),
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Tag(tag)) =>
            (ACM_FILTERTAGDETAILSF_FILTERTAG as u32, 0, tag),
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Largest { tag }) =>
            (ACM_FILTERTAGDETAILSF_LARGESTSIZE as u32, 0, tag),
    }
}

unsafe fn format_tag_from_native(
    codec: GuestTextCodec,
    native: &ACMFORMATTAGDETAILSW,
) -> Result<Win16HostAcmTagDetails, RuntimeError> {
    // SAFETY: windows-sys marks ACM records packed; all fields are unaligned.
    unsafe {
        Ok(Win16HostAcmTagDetails {
            index: ptr::addr_of!(native.dwFormatTagIndex).read_unaligned(),
            tag: ptr::addr_of!(native.dwFormatTag).read_unaligned(),
            data_bytes: ptr::addr_of!(native.cbFormatSize).read_unaligned(),
            support: ptr::addr_of!(native.fdwSupport).read_unaligned(),
            standard_count: ptr::addr_of!(native.cStandardFormats).read_unaligned(),
            name: wide_fixed_to_guest(codec, &ptr::addr_of!(native.szFormatTag).read_unaligned())?,
        })
    }
}

unsafe fn filter_tag_from_native(
    codec: GuestTextCodec,
    native: &ACMFILTERTAGDETAILSW,
) -> Result<Win16HostAcmTagDetails, RuntimeError> {
    // SAFETY: windows-sys marks ACM records packed; all fields are unaligned.
    unsafe {
        Ok(Win16HostAcmTagDetails {
            index: ptr::addr_of!(native.dwFilterTagIndex).read_unaligned(),
            tag: ptr::addr_of!(native.dwFilterTag).read_unaligned(),
            data_bytes: ptr::addr_of!(native.cbFilterSize).read_unaligned(),
            support: ptr::addr_of!(native.fdwSupport).read_unaligned(),
            standard_count: ptr::addr_of!(native.cStandardFilters).read_unaligned(),
            name: wide_fixed_to_guest(codec, &ptr::addr_of!(native.szFilterTag).read_unaligned())?,
        })
    }
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
        Self { codec, rows: Vec::new(), allocation_error: None,
            conversion_error: None, callback_panicked: false }
    }
}

unsafe extern "system" fn format_tag_callback(
    driver_id: HACMDRIVERID,
    native: *mut ACMFORMATTAGDETAILSW,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if driver_id.is_null() || native.is_null() || instance == 0 { return 1; }
    // SAFETY: instance and native record are valid only during the native
    // synchronous enumeration callback; details are copied before returning.
    let context = unsafe { &mut *(instance as *mut TagRows) };
    match catch_unwind(AssertUnwindSafe(|| {
        if let Err(error) = context.rows.try_reserve(1) {
            context.allocation_error = Some(error);
            return false;
        }
        let details = match unsafe { format_tag_from_native(context.codec, &*native) } {
            Ok(details) => details,
            Err(error) => { context.conversion_error = Some(error); return false; }
        };
        context.rows.push((driver_id as usize, support, details));
        true
    })) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => { context.callback_panicked = true; 0 }
    }
}

unsafe extern "system" fn filter_tag_callback(
    driver_id: HACMDRIVERID,
    native: *mut ACMFILTERTAGDETAILSW,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if driver_id.is_null() || native.is_null() || instance == 0 { return 1; }
    // SAFETY: instance and native record are valid only during the native
    // synchronous enumeration callback; details are copied before returning.
    let context = unsafe { &mut *(instance as *mut TagRows) };
    match catch_unwind(AssertUnwindSafe(|| {
        if let Err(error) = context.rows.try_reserve(1) {
            context.allocation_error = Some(error);
            return false;
        }
        let details = match unsafe { filter_tag_from_native(context.codec, &*native) } {
            Ok(details) => details,
            Err(error) => { context.conversion_error = Some(error); return false; }
        };
        context.rows.push((driver_id as usize, support, details));
        true
    })) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => { context.callback_panicked = true; 0 }
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
        Err(result) => return Ok(ResultValue::Enumerated { result, records: Vec::new() }),
    };
    let mut rows = TagRows::new(codec);
    let result = match kind {
        Win16HostAcmTagKind::Format => {
            let mut details = ACMFORMATTAGDETAILSW::default();
            unsafe {
                ptr::addr_of_mut!(details.cbStruct).write_unaligned(
                    std::mem::size_of::<ACMFORMATTAGDETAILSW>() as u32,
                );
                ptr::addr_of_mut!(details.dwFormatTagIndex).write_unaligned(template.index);
                ptr::addr_of_mut!(details.dwFormatTag).write_unaligned(template.tag);
            }
            let result = unsafe { acmFormatTagEnumW(
                native_driver, &mut details, Some(format_tag_callback),
                (&mut rows as *mut TagRows) as usize, flags,
            ) };
            result
        }
        Win16HostAcmTagKind::Filter => {
            let mut details = ACMFILTERTAGDETAILSW::default();
            unsafe {
                ptr::addr_of_mut!(details.cbStruct).write_unaligned(
                    std::mem::size_of::<ACMFILTERTAGDETAILSW>() as u32,
                );
                ptr::addr_of_mut!(details.dwFilterTagIndex).write_unaligned(template.index);
                ptr::addr_of_mut!(details.dwFilterTag).write_unaligned(template.tag);
            }
            let result = unsafe { acmFilterTagEnumW(
                native_driver, &mut details, Some(filter_tag_callback),
                (&mut rows as *mut TagRows) as usize, flags,
            ) };
            result
        }
    };
    let operation = tag_enum_operation(kind);
    if let Some(error) = rows.conversion_error.take() {
        return Err(retain_native_result(error, operation, result));
    }
    if rows.callback_panicked { return Err(callback_panic_error(operation, result)); }
    if let Some(error) = rows.allocation_error.take() {
        return Err(native_allocation_error(operation, result, error));
    }
    let mut records = Vec::new();
    records.try_reserve_exact(rows.rows.len()).map_err(|error|
        native_allocation_error(operation, result, error))?;
    let mut raw_ids = Vec::new();
    raw_ids.try_reserve_exact(rows.rows.len()).map_err(|error|
        native_allocation_error(operation, result, error))?;
    raw_ids.extend(rows.rows.iter().map(|(raw, _, _)| *raw));
    let driver_ids = host.map_borrowed_driver_ids(&raw_ids).map_err(|error|
        retain_native_result(error, operation, result))?;
    for ((_, support, details), driver_id) in rows.rows.into_iter().zip(driver_ids) {
        records.push(Win16HostAcmEnumerationRecord::Tag { driver_id, support, details });
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
        Err(result) => return Ok(ResultValue::ItemDetails { result, details: initial }),
    };
    let capacity = match usize::try_from(capacity) {
        Ok(value) => value,
        Err(_) => return Ok(ResultValue::ItemDetails {
            result: MMSYSERR_INVALPARAM, details: initial,
        }),
    };
    let minimum = if kind == Win16HostAcmTagKind::Format { WFX_BYTES } else { WAVEFILTER_BYTES };
    if capacity < minimum {
        return Ok(ResultValue::ItemDetails { result: MMSYSERR_INVALPARAM, details: initial });
    }
    if kind == Win16HostAcmTagKind::Filter
        && matches!(query, Win16HostAcmDetailQuery::Tag(_))
        && filter_size(&initial.data, capacity).is_none()
    {
        return Ok(ResultValue::ItemDetails { result: MMSYSERR_INVALPARAM, details: initial });
    }
    if kind == Win16HostAcmTagKind::Format
        && matches!(query, Win16HostAcmDetailQuery::Tag(_))
        && normalize_wfx(try_copy_bytes(&initial.data)?)?.is_none()
    {
        return Ok(ResultValue::ItemDetails { result: MMSYSERR_INVALPARAM, details: initial });
    }
    let mut data = zeroed(capacity)?;
    let copy = initial.data.len().min(capacity);
    data[..copy].copy_from_slice(&initial.data[..copy]);
    let (flags, index, tag) = item_query(kind, query);
    let (result, details) = match kind {
        Win16HostAcmTagKind::Format => {
            let mut native = tACMFORMATDETAILSW::default();
            unsafe {
                ptr::addr_of_mut!(native.cbStruct).write_unaligned(
                    std::mem::size_of::<tACMFORMATDETAILSW>() as u32,
                );
                ptr::addr_of_mut!(native.dwFormatIndex).write_unaligned(index);
                ptr::addr_of_mut!(native.dwFormatTag).write_unaligned(tag);
                ptr::addr_of_mut!(native.pwfx).write_unaligned(data.as_mut_ptr().cast::<WAVEFORMATEX>());
                ptr::addr_of_mut!(native.cbwfx).write_unaligned(capacity as u32);
            }
            // SAFETY: structure and WAVEFORMATEX storage are host-owned and
            // remain live through this synchronous details call.
            let result = unsafe { acmFormatDetailsW(native_driver, &mut native, flags) };
            if result != MMSYSERR_NOERROR {
                return Ok(ResultValue::ItemDetails { result, details: initial });
            }
            let item = unsafe {
                Win16HostAcmItemDetails {
                    index: ptr::addr_of!(native.dwFormatIndex).read_unaligned(),
                    tag: ptr::addr_of!(native.dwFormatTag).read_unaligned(),
                    support: ptr::addr_of!(native.fdwSupport).read_unaligned(),
                    name: wide_fixed_to_guest(codec, &ptr::addr_of!(native.szFormat).read_unaligned())?,
                    data: take_format_data(&data, capacity)?,
                }
            };
            (result, item)
        }
        Win16HostAcmTagKind::Filter => {
            let mut native = ACMFILTERDETAILSW::default();
            unsafe {
                ptr::addr_of_mut!(native.cbStruct).write_unaligned(
                    std::mem::size_of::<ACMFILTERDETAILSW>() as u32,
                );
                ptr::addr_of_mut!(native.dwFilterIndex).write_unaligned(index);
                ptr::addr_of_mut!(native.dwFilterTag).write_unaligned(tag);
                ptr::addr_of_mut!(native.pwfltr).write_unaligned(data.as_mut_ptr().cast::<WAVEFILTER>());
                ptr::addr_of_mut!(native.cbwfltr).write_unaligned(capacity as u32);
            }
            // SAFETY: structure and WAVEFILTER storage are host-owned and
            // remain live through this synchronous details call.
            let result = unsafe { acmFilterDetailsW(native_driver, &mut native, flags) };
            if result != MMSYSERR_NOERROR {
                return Ok(ResultValue::ItemDetails { result, details: initial });
            }
            let item = unsafe {
                Win16HostAcmItemDetails {
                    index: ptr::addr_of!(native.dwFilterIndex).read_unaligned(),
                    tag: ptr::addr_of!(native.dwFilterTag).read_unaligned(),
                    support: ptr::addr_of!(native.fdwSupport).read_unaligned(),
                    name: wide_fixed_to_guest(codec, &ptr::addr_of!(native.szFilter).read_unaligned())?,
                    data: take_filter_data(&data, capacity)?,
                }
            };
            (result, item)
        }
    };
    Ok(ResultValue::ItemDetails { result, details })
}

fn item_query(kind: Win16HostAcmTagKind, query: Win16HostAcmDetailQuery) -> (u32, u32, u32) {
    match (kind, query) {
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Index { index, tag }) =>
            (ACM_FORMATDETAILSF_INDEX as u32, index, tag),
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Tag(tag)) =>
            (ACM_FORMATDETAILSF_FORMAT as u32, 0, tag),
        (Win16HostAcmTagKind::Format, Win16HostAcmDetailQuery::Largest { tag }) =>
            (ACM_FORMATDETAILSF_INDEX as u32, 0, tag),
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Index { index, tag }) =>
            (ACM_FILTERDETAILSF_INDEX as u32, index, tag),
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Tag(tag)) =>
            (ACM_FILTERDETAILSF_FILTER as u32, 0, tag),
        (Win16HostAcmTagKind::Filter, Win16HostAcmDetailQuery::Largest { tag }) =>
            (ACM_FILTERDETAILSF_INDEX as u32, 0, tag),
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
    if pointer.is_null() || capacity < WFX_BYTES { return None; }
    // SAFETY: callback verification ensures this pointer targets the owned
    // per-enumeration buffer with at least `capacity` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), capacity) };
    wave_size(bytes, capacity)
}

unsafe extern "system" fn format_enum_callback(
    driver_id: HACMDRIVERID,
    native: *mut tACMFORMATDETAILSW,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if driver_id.is_null() || native.is_null() || instance == 0 { return 1; }
    // SAFETY: callback context points to stack-owned native enumeration state.
    let context = unsafe { &mut *(instance as *mut ItemRows) };
    match catch_unwind(AssertUnwindSafe(|| {
        let data_pointer = unsafe { ptr::addr_of!((*native).pwfx).read_unaligned() };
        if data_pointer.is_null() || data_pointer.cast::<u8>() != context.data.as_mut_ptr() {
            context.invalid_native_buffer = true;
            return Err(());
        }
        let cbwfx = unsafe { ptr::addr_of!((*native).cbwfx).read_unaligned() } as usize;
        if cbwfx > context.capacity { context.invalid_native_buffer = true; return Err(()); }
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
        let details = unsafe {
            Win16HostAcmItemDetails {
                index: ptr::addr_of!((*native).dwFormatIndex).read_unaligned(),
                tag: ptr::addr_of!((*native).dwFormatTag).read_unaligned(),
                support: ptr::addr_of!((*native).fdwSupport).read_unaligned(),
                name: match wide_fixed_to_guest(
                    context.codec,
                    &ptr::addr_of!((*native).szFormat).read_unaligned(),
                ) {
                    Ok(name) => name,
                    Err(error) => {
                        context.conversion_error = Some(error);
                        return Err(());
                    }
                },
                data,
            }
        };
        context.rows.push((driver_id as usize, support, details));
        Ok::<(), ()>(())
    })) {
        Ok(Ok(())) => 1,
        Ok(Err(())) => { context.failed = true; 0 }
        Err(_) => { context.failed = true; context.callback_panicked = true; 0 }
    }
}

unsafe extern "system" fn filter_enum_callback(
    driver_id: HACMDRIVERID,
    native: *mut ACMFILTERDETAILSW,
    instance: usize,
    support: u32,
) -> windows_sys::core::BOOL {
    if driver_id.is_null() || native.is_null() || instance == 0 { return 1; }
    // SAFETY: callback context points to stack-owned native enumeration state.
    let context = unsafe { &mut *(instance as *mut ItemRows) };
    match catch_unwind(AssertUnwindSafe(|| {
        let data_pointer = unsafe { ptr::addr_of!((*native).pwfltr).read_unaligned() };
        if data_pointer.is_null() || data_pointer.cast::<u8>() != context.data.as_mut_ptr() {
            context.invalid_native_buffer = true;
            return Err(());
        }
        let cbwfltr = unsafe { ptr::addr_of!((*native).cbwfltr).read_unaligned() } as usize;
        if cbwfltr > context.capacity { context.invalid_native_buffer = true; return Err(()); }
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
        let details = unsafe {
            Win16HostAcmItemDetails {
                index: ptr::addr_of!((*native).dwFilterIndex).read_unaligned(),
                tag: ptr::addr_of!((*native).dwFilterTag).read_unaligned(),
                support: ptr::addr_of!((*native).fdwSupport).read_unaligned(),
                name: match wide_fixed_to_guest(
                    context.codec,
                    &ptr::addr_of!((*native).szFilter).read_unaligned(),
                ) {
                    Ok(name) => name,
                    Err(error) => {
                        context.conversion_error = Some(error);
                        return Err(());
                    }
                },
                data,
            }
        };
        context.rows.push((driver_id as usize, support, details));
        Ok::<(), ()>(())
    })) {
        Ok(Ok(())) => 1,
        Ok(Err(())) => { context.failed = true; 0 }
        Err(_) => { context.failed = true; context.callback_panicked = true; 0 }
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
        Err(result) => return Ok(ResultValue::Enumerated { result, records: Vec::new() }),
    };
    let capacity = match usize::try_from(capacity) {
        Ok(value) => value,
        Err(_) => return Ok(ResultValue::Enumerated { result: MMSYSERR_INVALPARAM,
            records: Vec::new() }),
    };
    let minimum = if kind == Win16HostAcmTagKind::Format { WFX_BYTES } else { WAVEFILTER_BYTES };
    if capacity < minimum {
        return Ok(ResultValue::Enumerated { result: MMSYSERR_INVALPARAM, records: Vec::new() });
    }
    // The native enumeration flags decide which template members are input.
    // The runtime zero-fills the owned host buffer and copies only fields
    // declared valid by those flags; normalizing the entire WFX/WAVEFILTER
    // here would reject legal templates with untouched, uninitialized bytes.
    let mut data = zeroed(capacity)?;
    let copy = template.data.len().min(capacity);
    data[..copy].copy_from_slice(&template.data[..copy]);
    let mut rows = ItemRows {
        codec, capacity, data, rows: Vec::new(), failed: false, allocation_error: None,
        conversion_error: None,
        invalid_native_buffer: false, callback_panicked: false,
    };
    let result = match kind {
        Win16HostAcmTagKind::Format => {
            let mut native = tACMFORMATDETAILSW::default();
            unsafe {
                ptr::addr_of_mut!(native.cbStruct).write_unaligned(
                    std::mem::size_of::<tACMFORMATDETAILSW>() as u32,
                );
                ptr::addr_of_mut!(native.dwFormatIndex).write_unaligned(template.index);
                ptr::addr_of_mut!(native.dwFormatTag).write_unaligned(template.tag);
                ptr::addr_of_mut!(native.pwfx).write_unaligned(rows.data.as_mut_ptr().cast());
                ptr::addr_of_mut!(native.cbwfx).write_unaligned(capacity as u32);
            }
            // SAFETY: callback and mutable format storage are stack/heap owned
            // for the entire synchronous enumeration call.
            unsafe { acmFormatEnumW(native_driver, &mut native, Some(format_enum_callback),
                (&mut rows as *mut ItemRows) as usize, flags) }
        }
        Win16HostAcmTagKind::Filter => {
            let mut native = ACMFILTERDETAILSW::default();
            unsafe {
                ptr::addr_of_mut!(native.cbStruct).write_unaligned(
                    std::mem::size_of::<ACMFILTERDETAILSW>() as u32,
                );
                ptr::addr_of_mut!(native.dwFilterIndex).write_unaligned(template.index);
                ptr::addr_of_mut!(native.dwFilterTag).write_unaligned(template.tag);
                ptr::addr_of_mut!(native.pwfltr).write_unaligned(rows.data.as_mut_ptr().cast());
                ptr::addr_of_mut!(native.cbwfltr).write_unaligned(capacity as u32);
            }
            // SAFETY: callback and mutable filter storage are stack/heap owned
            // for the entire synchronous enumeration call.
            unsafe { acmFilterEnumW(native_driver, &mut native, Some(filter_enum_callback),
                (&mut rows as *mut ItemRows) as usize, flags) }
        }
    };
    let operation = item_enum_operation(kind);
    if rows.invalid_native_buffer {
        return Err(callback_contract_error(operation, result,
            "native ACM enumeration returned an unexpected data buffer"));
    }
    if rows.callback_panicked { return Err(callback_panic_error(operation, result)); }
    if let Some(error) = rows.allocation_error.take() {
        return Err(native_allocation_error(operation, result, error));
    }
    if let Some(error) = rows.conversion_error.take() {
        return Err(retain_native_result(error, operation, result));
    }
    if rows.failed {
        return Err(callback_contract_error(operation, result,
            "native ACM item-enumeration callback failed without a recorded cause"));
    }
    let mut records = Vec::new();
    records.try_reserve_exact(rows.rows.len()).map_err(|error|
        native_allocation_error(operation, result, error))?;
    let mut raw_ids = Vec::new();
    raw_ids.try_reserve_exact(rows.rows.len()).map_err(|error|
        native_allocation_error(operation, result, error))?;
    raw_ids.extend(rows.rows.iter().map(|(raw, _, _)| *raw));
    let driver_ids = host.map_borrowed_driver_ids(&raw_ids).map_err(|error|
        retain_native_result(error, operation, result))?;
    for ((_, support, details), driver_id) in rows.rows.into_iter().zip(driver_ids) {
        records.push(Win16HostAcmEnumerationRecord::Item { driver_id, support, details });
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
        Err(result) => return Ok(ResultValue::FormatSuggest { result, destination }),
    };
    let Some(source) = normalize_wfx(source)? else {
        return Ok(ResultValue::FormatSuggest { result: MMSYSERR_INVALPARAM, destination });
    };
    if destination.len() < WFX_BYTES || destination.len() > u32::MAX as usize {
        return Ok(ResultValue::FormatSuggest { result: MMSYSERR_INVALPARAM, destination });
    }
    // SAFETY: vectors hold packed host WAVEFORMATEX records and stay stable
    // through the synchronous call. Destination capacity is explicitly passed.
    let mut result = unsafe {
        acmFormatSuggest(
            native_driver,
            source.as_ptr().cast_mut().cast::<WAVEFORMATEX>(),
            destination.as_mut_ptr().cast::<WAVEFORMATEX>(),
            destination.len() as u32,
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
    Ok(ResultValue::FormatSuggest { result, destination })
}

pub(super) fn zeroed(length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate native ACM data buffer", error,
    ))?;
    bytes.resize(length, 0);
    Ok(bytes)
}

pub(super) fn normalize_wfx(mut bytes: Vec<u8>) -> Result<Option<Vec<u8>>, RuntimeError> {
    if bytes.len() < 2 || bytes.len() > u32::MAX as usize { return Ok(None); }
    let format_tag = u16::from_le_bytes([bytes[0], bytes[1]]);
    if format_tag == 1 {
        if bytes.len() < 16 { return Ok(None); }
        if bytes.len() < WFX_BYTES {
            bytes.try_reserve_exact(WFX_BYTES - bytes.len()).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "normalize host PCMWAVEFORMAT", error))?;
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
    let Some(needed) = WFX_BYTES.checked_add(cb_size) else { return Ok(None); };
    if needed > bytes.len() { return Ok(None); }
    bytes.truncate(needed);
    Ok(Some(bytes))
}

pub(super) fn try_copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy host ACM format bytes", error))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

pub(super) fn wave_size(bytes: &[u8], capacity: usize) -> Option<usize> {
    if capacity < WFX_BYTES || bytes.len() < WFX_BYTES { return None; }
    let cb_size = u16::from_le_bytes([bytes[16], bytes[17]]) as usize;
    let needed = WFX_BYTES.checked_add(cb_size)?;
    (needed <= capacity && needed <= bytes.len()).then_some(needed)
}

pub(super) fn filter_size(bytes: &[u8], capacity: usize) -> Option<usize> {
    if capacity < WAVEFILTER_BYTES || bytes.len() < 4 { return None; }
    let declared = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let actual = declared.max(WAVEFILTER_BYTES);
    (actual <= capacity && actual <= bytes.len()).then_some(actual)
}

fn take_format_data(bytes: &[u8], capacity: usize) -> Result<Vec<u8>, RuntimeError> {
    let Some(length) = wave_size(bytes, capacity) else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native ACM produced an invalid WAVEFORMATEX result extent"));
    };
    try_copy_bytes(&bytes[..length])
}

fn take_filter_data(bytes: &[u8], capacity: usize) -> Result<Vec<u8>, RuntimeError> {
    let Some(length) = filter_size(bytes, capacity) else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native ACM produced an invalid WAVEFILTER result extent"));
    };
    try_copy_bytes(&bytes[..length])
}

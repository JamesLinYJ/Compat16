//! Typed calls on the finite COM interface set used by Win16 OLE adapters.
//!
//! The generated `com_bindings::generated` module supplies the official interface
//! wrappers and SDK vtable layouts. Direct generated-vtable calls are used where
//! the bridge must preserve a nonzero success HRESULT exactly; no handwritten
//! COM vtable or slot number is part of this adapter.

use std::ffi::c_void;
use std::mem;
use std::ptr;

use compat_services::com::{ComObjectId, Guid, ReferenceDisposition};
use runtime::{
    DiagnosticKind, RuntimeError, Win16ComHostFormatEtc, Win16ComHostInterface,
    Win16ComHostInterfaceCall, Win16ComHostStorageMedium, Win16HostRect, Win16HostWindow,
    Win16OleHostReply, Win16OleHostValue,
};
use windows_core::{HRESULT, Interface, PCWSTR};

use super::com_bindings::generated::{
    CLIPFORMAT, CoTaskMemFree, DEVMODEW, DVTARGETDEVICE, FORMATETC, GlobalLock, GlobalSize, HWND,
    IDataObject, IEnumFORMATETC, IMoniker, IOleClientSite, IOleObject, IPersistFile,
    IPersistStorage, IStorage, IStream, RECT, ReleaseStgMedium, SIZE, STGMEDIUM,
};
use super::win16_com_callback_copy::{read_file_medium_contents, unlock_medium};
use super::win16_com_objects::{NativeComError, Win16ComObjects};
use windows_sys::Win32::Foundation::HWND as RawHwnd;

const E_INVALIDARG: HRESULT = HRESULT(0x8007_0057u32 as i32);
const TYMED_HGLOBAL_VALUE: u32 = 1;
const TYMED_FILE_VALUE: u32 = 2;
const TYMED_ISTREAM_VALUE: u32 = 4;
const TYMED_ISTORAGE_VALUE: u32 = 8;
const TYMED_GDI_VALUE: u32 = 16;
const TYMED_MFPICT_VALUE: u32 = 32;
const TYMED_ENHMF_VALUE: u32 = 64;
const MAX_FORMAT_COUNT: u32 = 4096;
const MAX_TARGET_DEVICE_BYTES: usize = 64 * 1024;
const MAX_MEDIUM_BYTES: usize = 64 * 1024 * 1024;

/// Execute one typed call on the owning USER STA. Runtime window tokens are
/// resolved by the worker; they are never cast to native HWND values.
pub(super) fn execute(
    objects: &Win16ComObjects,
    object: ComObjectId,
    call: Win16ComHostInterfaceCall,
    resolve_window: impl Fn(Win16HostWindow) -> Option<RawHwnd>,
) -> Result<Win16OleHostReply, RuntimeError> {
    let (status, value) = match call {
        Win16ComHostInterfaceCall::OleSetClientSite { site } => {
            let result = with_object::<IOleObject, _>(objects, object, |native| {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                with_optional::<IOleClientSite, _>(objects, site, |site| unsafe {
                    (native.vtable().SetClientSite)(
                        native.as_raw(),
                        site.map_or(ptr::null_mut(), |site| site.as_raw()),
                    )
                })
            })??;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::OleSetHostNames {
            application,
            document,
        } => {
            let (Some(application), Some(document)) = (wide_z(&application), wide_z(&document))
            else {
                return Ok(reply(E_INVALIDARG, Win16OleHostValue::None));
            };
            // SAFETY: `PCWSTR` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            let result = with_object::<IOleObject, _>(objects, object, |native| unsafe {
                (native.vtable().SetHostNames)(
                    native.as_raw(),
                    PCWSTR(application.as_ptr()),
                    PCWSTR(document.as_ptr()),
                )
            })?;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::OleSetMoniker { assign, moniker } => {
            let result = with_object::<IOleObject, _>(objects, object, |native| {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                with_object::<IMoniker, _>(objects, moniker, |moniker| unsafe {
                    (native.vtable().SetMoniker)(native.as_raw(), assign, moniker.as_raw())
                })
            })??;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::OleAdvise { sink } => {
            let (result, cookie) = with_object::<IOleObject, _>(objects, object, |native| {
                let mut cookie = 0;
                let result = with_object::<super::com_bindings::generated::IAdviseSink, _>(
                    objects,
                    sink,
                    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                    |sink| unsafe {
                        (native.vtable().Advise)(native.as_raw(), sink.as_raw(), &mut cookie)
                    },
                );
                (result, cookie)
            })?;
            (result?, Win16OleHostValue::Scalar(cookie))
        }
        Win16ComHostInterfaceCall::OleUnadvise { cookie } => {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let result = with_object::<IOleObject, _>(objects, object, |native| unsafe {
                (native.vtable().Unadvise)(native.as_raw(), cookie)
            })?;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::OleGetExtent { aspect } => {
            let (result, size) = with_object::<IOleObject, _>(objects, object, |native| {
                let mut size = SIZE::default();
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                let result =
                    unsafe { (native.vtable().GetExtent)(native.as_raw(), aspect, &mut size) };
                (result, size)
            })?;
            (
                result,
                Win16OleHostValue::Extent {
                    width: size.cx,
                    height: size.cy,
                },
            )
        }
        Win16ComHostInterfaceCall::OleSetExtent {
            aspect,
            width,
            height,
        } => {
            let size = SIZE {
                cx: width,
                cy: height,
            };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let result = with_object::<IOleObject, _>(objects, object, |native| unsafe {
                (native.vtable().SetExtent)(native.as_raw(), aspect, &size)
            })?;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::OleDoVerb {
            verb,
            site,
            window,
            position,
        } => {
            let hwnd = match window {
                Some(window) => match resolve_window(window) {
                    Some(hwnd) => HWND(hwnd),
                    None => return Ok(reply(E_INVALIDARG, Win16OleHostValue::None)),
                },
                None => HWND(ptr::null_mut()),
            };
            let rect = position.map(native_rect);
            let rect_pointer = rect
                .as_ref()
                .map_or(ptr::null(), |rect| rect as *const RECT);
            let result = with_object::<IOleObject, _>(objects, object, |native| {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                with_optional::<IOleClientSite, _>(objects, site, |site| unsafe {
                    (native.vtable().DoVerb)(
                        native.as_raw(),
                        verb,
                        ptr::null(),
                        site.map_or(ptr::null_mut(), |site| site.as_raw()),
                        0,
                        hwnd,
                        rect_pointer,
                    )
                })
            })??;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::OleClose { save_option } => {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let result = with_object::<IOleObject, _>(objects, object, |native| unsafe {
                (native.vtable().Close)(native.as_raw(), save_option)
            })?;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::OleUpdate => {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let result = with_object::<IOleObject, _>(objects, object, |native| unsafe {
                (native.vtable().Update)(native.as_raw())
            })?;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::PersistStorageInitNew { storage } => {
            let result = with_object::<IPersistStorage, _>(objects, object, |persist| {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                with_object::<IStorage, _>(objects, storage, |storage| unsafe {
                    (persist.vtable().InitNew)(persist.as_raw(), storage.as_raw())
                })
            })??;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::PersistStorageLoad { storage } => {
            let result = with_object::<IPersistStorage, _>(objects, object, |persist| {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                with_object::<IStorage, _>(objects, storage, |storage| unsafe {
                    (persist.vtable().Load)(persist.as_raw(), storage.as_raw())
                })
            })??;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::PersistStorageSave {
            storage,
            same_as_load,
        } => {
            let result = with_object::<IPersistStorage, _>(objects, object, |persist| {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                with_object::<IStorage, _>(objects, storage, |storage| unsafe {
                    (persist.vtable().Save)(persist.as_raw(), storage.as_raw(), same_as_load.into())
                })
            })??;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::PersistStorageSaveCompleted { storage } => {
            let result = with_object::<IPersistStorage, _>(objects, object, |persist| {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                with_optional::<IStorage, _>(objects, storage, |storage| unsafe {
                    (persist.vtable().SaveCompleted)(
                        persist.as_raw(),
                        storage.map_or(ptr::null_mut(), |storage| storage.as_raw()),
                    )
                })
            })??;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::PersistStorageHandsOff => {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let result = with_object::<IPersistStorage, _>(objects, object, |persist| unsafe {
                (persist.vtable().HandsOffStorage)(persist.as_raw())
            })?;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::PersistFileLoad { path, mode } => {
            let Some(path) = wide_z(&path) else {
                return Ok(reply(E_INVALIDARG, Win16OleHostValue::None));
            };
            // SAFETY: `PCWSTR` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            let result = with_object::<IPersistFile, _>(objects, object, |persist| unsafe {
                (persist.vtable().Load)(persist.as_raw(), PCWSTR(path.as_ptr()), mode)
            })?;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::PersistFileSave { path, remember } => {
            let Some(path) = wide_z(&path) else {
                return Ok(reply(E_INVALIDARG, Win16OleHostValue::None));
            };
            // SAFETY: `PCWSTR` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            let result = with_object::<IPersistFile, _>(objects, object, |persist| unsafe {
                (persist.vtable().Save)(persist.as_raw(), PCWSTR(path.as_ptr()), remember.into())
            })?;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::DataObjectQueryGetData { format } => {
            let Some(result) = with_format(&format, |native_format| {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                with_object::<IDataObject, _>(objects, object, |data| unsafe {
                    (data.vtable().QueryGetData)(data.as_raw(), &native_format)
                })
            }) else {
                return Ok(reply(E_INVALIDARG, Win16OleHostValue::None));
            };
            (result?, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::DataObjectGetData { format } => {
            let Some(result) = with_format(&format, |native_format| {
                with_object::<IDataObject, _>(objects, object, |data| {
                    let mut medium = STGMEDIUM::default();
                    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                    let result = unsafe {
                        (data.vtable().GetData)(data.as_raw(), &native_format, &mut medium)
                    };
                    (result, medium)
                })
            }) else {
                return Ok(reply(E_INVALIDARG, Win16OleHostValue::None));
            };
            let (result, medium) = result?;
            if result.0 < 0 {
                (result, Win16OleHostValue::None)
            } else {
                let copied = copy_storage_medium(objects, medium)?;
                (result, Win16OleHostValue::StorageMedium(copied))
            }
        }
        Win16ComHostInterfaceCall::DataObjectEnumFormatEtc { direction } => {
            let (result, output) = with_object::<IDataObject, _>(objects, object, |data| {
                let mut output = ptr::null_mut();
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                let result =
                    unsafe { (data.vtable().EnumFormatEtc)(data.as_raw(), direction, &mut output) };
                (result, output)
            })?;
            adopt_output::<IEnumFORMATETC>(
                objects,
                result,
                output,
                interface_guid::<IEnumFORMATETC>(),
            )?
        }
        Win16ComHostInterfaceCall::EnumFormatEtcNext { enumerator, count } => {
            if count == 0 || count > MAX_FORMAT_COUNT {
                return Ok(reply(E_INVALIDARG, Win16OleHostValue::None));
            }
            let (result, formats) =
                with_object::<IEnumFORMATETC, _>(objects, enumerator, |native| {
                    let mut formats = vec![FORMATETC::default(); count as usize];
                    let mut fetched = 0;
                    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                    let result = unsafe {
                        (native.vtable().Next)(
                            native.as_raw(),
                            count,
                            formats.as_mut_ptr(),
                            &mut fetched,
                        )
                    };
                    if fetched > count {
                        fetched = count;
                    }
                    formats.truncate(fetched as usize);
                    (result, formats)
                })?;
            let copied = take_formats(formats)?;
            (result, Win16OleHostValue::Formats(copied))
        }
        Win16ComHostInterfaceCall::EnumFormatEtcReset { enumerator } => {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let result = with_object::<IEnumFORMATETC, _>(objects, enumerator, |native| unsafe {
                (native.vtable().Reset)(native.as_raw())
            })?;
            (result, Win16OleHostValue::None)
        }
        Win16ComHostInterfaceCall::EnumFormatEtcSkip { enumerator, count } => {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let result = with_object::<IEnumFORMATETC, _>(objects, enumerator, |native| unsafe {
                (native.vtable().Skip)(native.as_raw(), count)
            })?;
            (result, Win16OleHostValue::None)
        }
    };
    Ok(reply(status, value))
}

fn with_object<I: Interface, R>(
    objects: &Win16ComObjects,
    object: ComObjectId,
    call: impl FnOnce(&I) -> R,
) -> Result<R, RuntimeError> {
    objects
        .with_typed_interface(object, call)
        .map_err(com_error)?
        .ok_or_else(|| {
            RuntimeError::new(
                DiagnosticKind::HostFailure,
                "native COM object does not implement the requested interface",
            )
        })
}

fn with_optional<I: Interface, R>(
    objects: &Win16ComObjects,
    object: Option<ComObjectId>,
    call: impl FnOnce(Option<&I>) -> R,
) -> Result<R, RuntimeError> {
    match object {
        Some(object) => with_object(objects, object, |interface| call(Some(interface))),
        None => Ok(call(None)),
    }
}

fn com_error(error: NativeComError) -> RuntimeError {
    RuntimeError::with_source(
        DiagnosticKind::HostFailure,
        "native COM interface call failed",
        error,
    )
}

fn reply(status: HRESULT, value: Win16OleHostValue) -> Win16OleHostReply {
    Win16OleHostReply {
        status: status.0 as u32,
        value,
    }
}

fn wide_z(text: &[u16]) -> Option<Vec<u16>> {
    if text.contains(&0) {
        None
    } else {
        Some(text.iter().copied().chain([0]).collect())
    }
}

fn native_rect(rect: Win16HostRect) -> RECT {
    RECT {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn with_format<R>(format: &Win16ComHostFormatEtc, call: impl FnOnce(FORMATETC) -> R) -> Option<R> {
    if format
        .target_device
        .as_deref()
        .is_some_and(|bytes| !valid_target_device(bytes))
    {
        return None;
    }
    let mut target_device_words = format.target_device.as_ref().map(|bytes| {
        let mut words = vec![0u32; bytes.len().div_ceil(mem::size_of::<u32>())];
        // DVTARGETDEVICE is a variable-size SDK byte record. Keep its complete
        // owned bytes aligned while the native call borrows the generated type.
        // SAFETY: The source and destination are non-overlapping, and both spans were checked to cover the copied length.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr().cast::<u8>(), bytes.len());
        }
        words
    });
    let target_pointer = match (&format.target_device, target_device_words.as_mut()) {
        (None, _) => ptr::null_mut(),
        (Some(_), Some(words)) => words.as_mut_ptr().cast::<DVTARGETDEVICE>(),
        _ => return None,
    };
    Some(call(FORMATETC {
        cfFormat: CLIPFORMAT(format.format),
        ptd: target_pointer,
        dwAspect: format.aspect,
        lindex: format.index,
        tymed: format.tymed,
    }))
}

pub(super) fn valid_target_device(bytes: &[u8]) -> bool {
    if !(12..=MAX_TARGET_DEVICE_BYTES).contains(&bytes.len())
        || u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .expect("checked target-device header"),
        ) as usize
            != bytes.len()
    {
        return false;
    }
    let offset = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize;
    [4usize, 6, 8].into_iter().all(|at| {
        let value = offset(at);
        value == 0
            || (value >= 12
                && value < bytes.len()
                && value % 2 == 0
                && bytes[value..].chunks_exact(2).any(|unit| unit == [0, 0]))
    }) && valid_host_devmode(bytes, offset(10))
}

/// Validate only a host-side DEVMODEW prefix. `dmSize` may describe an older
/// valid prefix; private driver bytes follow it and remain opaque to this
/// bridge. Guest DEVMODE layouts are converted before reaching this layer.
fn valid_host_devmode(bytes: &[u8], offset: usize) -> bool {
    if offset == 0 {
        return true;
    }
    if offset < 12 || offset % 2 != 0 || offset >= bytes.len() {
        return false;
    }

    let size_field = offset + std::mem::offset_of!(DEVMODEW, dmSize);
    let extra_field = offset + std::mem::offset_of!(DEVMODEW, dmDriverExtra);
    let fields_end = extra_field.checked_add(std::mem::size_of::<u16>());
    let Some(fields_end) = fields_end else {
        return false;
    };
    if fields_end > bytes.len() {
        return false;
    }
    let dm_size = u16::from_le_bytes([bytes[size_field], bytes[size_field + 1]]) as usize;
    let driver_extra = u16::from_le_bytes([bytes[extra_field], bytes[extra_field + 1]]) as usize;
    if dm_size < std::mem::offset_of!(DEVMODEW, dmDriverExtra) + std::mem::size_of::<u16>() {
        return false;
    }
    offset
        .checked_add(dm_size)
        .and_then(|end| end.checked_add(driver_extra))
        .is_some_and(|end| end <= bytes.len())
}

fn take_formats(mut formats: Vec<FORMATETC>) -> Result<Vec<Win16ComHostFormatEtc>, RuntimeError> {
    let mut copied = Vec::with_capacity(formats.len());
    for index in 0..formats.len() {
        match take_format(&mut formats[index]) {
            Ok(format) => copied.push(format),
            Err(error) => {
                for remaining in formats.iter_mut().skip(index + 1) {
                    free_target_device(remaining);
                }
                return Err(error);
            }
        }
    }
    Ok(copied)
}

fn take_format(format: &mut FORMATETC) -> Result<Win16ComHostFormatEtc, RuntimeError> {
    let target_device = if format.ptd.is_null() {
        None
    } else {
        // IEnumFORMATETC transfers each ptd task allocation to its caller.
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let size = unsafe { (*format.ptd).tdSize as usize };
        if !(12..=MAX_TARGET_DEVICE_BYTES).contains(&size) {
            free_target_device(format);
            return Err(RuntimeError::new(
                DiagnosticKind::HostFailure,
                "IEnumFORMATETC returned an invalid target-device size",
            ));
        }
        // SAFETY: The pointer and length were checked against the owning allocation, and the bytes stay live for this copy.
        let bytes = unsafe { std::slice::from_raw_parts(format.ptd.cast::<u8>(), size) }.to_vec();
        free_target_device(format);
        if !valid_target_device(&bytes) {
            return Err(RuntimeError::new(
                DiagnosticKind::HostFailure,
                "IEnumFORMATETC returned a malformed target-device record",
            ));
        }
        Some(bytes)
    };
    Ok(Win16ComHostFormatEtc {
        format: format.cfFormat.0,
        target_device,
        aspect: format.dwAspect,
        index: format.lindex,
        tymed: format.tymed,
    })
}

fn free_target_device(format: &mut FORMATETC) {
    if !format.ptd.is_null() {
        // CoTaskMemFree is the allocator paired with IEnumFORMATETC::Next.
        // SAFETY: CoTaskMemFree releases a COM allocation this owner holds, or null.
        unsafe { CoTaskMemFree(format.ptd.cast()) };
        format.ptd = ptr::null_mut();
    }
}

fn adopt_output<I: Interface>(
    objects: &Win16ComObjects,
    result: HRESULT,
    output: *mut c_void,
    iid: Guid,
) -> Result<(HRESULT, Win16OleHostValue), RuntimeError> {
    if result.0 < 0 {
        if !output.is_null() {
            objects.discard_owned(output).map_err(com_error)?;
        }
        return Ok((result, Win16OleHostValue::None));
    }
    if output.is_null() {
        return Err(RuntimeError::new(
            DiagnosticKind::InternalInvariant,
            "native COM method succeeded with a null interface",
        ));
    }
    // SAFETY: the successful generated COM method transferred one reference
    // whose IID is the generated `I` selected by this call site.
    let interface = unsafe { I::from_raw(output) };
    let object = objects.insert_typed_owned(interface).map_err(com_error)?;
    Ok((
        result,
        Win16OleHostValue::Object(Win16ComHostInterface {
            object,
            owner: objects.owner_identity(),
            iid,
            disposition: ReferenceDisposition::Owned,
        }),
    ))
}

fn interface_guid<I: Interface>() -> Guid {
    let iid = I::IID;
    Guid::new(iid.data1, iid.data2, iid.data3, iid.data4)
}

fn copy_storage_medium(
    objects: &Win16ComObjects,
    mut medium: STGMEDIUM,
) -> Result<Win16ComHostStorageMedium, RuntimeError> {
    let mut transferred = false;
    let copied = (|| match medium.tymed {
        TYMED_HGLOBAL_VALUE => {
            // SAFETY: `tymed` selects the HGLOBAL union member.
            let handle = unsafe { medium.Anonymous.hGlobal };
            let size = unsafe { GlobalSize(handle) };
            if handle.0.is_null() || size > MAX_MEDIUM_BYTES {
                Err(RuntimeError::new(
                    DiagnosticKind::HostFailure,
                    "IDataObject returned an invalid or oversized HGLOBAL medium",
                ))
            } else if size == 0 {
                Ok(Win16ComHostStorageMedium::HGlobal(Vec::new()))
            } else {
                // SAFETY: GlobalLock locks an HGLOBAL this owner holds and returns a pointer valid until GlobalUnlock.
                let locked = unsafe { GlobalLock(handle) };
                if locked.is_null() {
                    Err(RuntimeError::new(
                        DiagnosticKind::HostFailure,
                        "GlobalLock failed for IDataObject HGLOBAL medium",
                    ))
                } else {
                    // SAFETY: The pointer and length were checked against the owning allocation, and the bytes stay live for this copy.
                    let bytes =
                        unsafe { std::slice::from_raw_parts(locked.cast::<u8>(), size) }.to_vec();
                    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                    unsafe { unlock_medium(handle) }.map_err(|error| {
                        RuntimeError::with_source(
                            DiagnosticKind::HostFailure,
                            "unlock IDataObject HGLOBAL medium",
                            error,
                        )
                    })?;
                    Ok(Win16ComHostStorageMedium::HGlobal(bytes))
                }
            }
        }
        TYMED_FILE_VALUE => {
            // SAFETY: `tymed` selects the NUL-terminated UTF-16 path member.
            let path = unsafe { medium.Anonymous.lpszFileName }.0;
            if path.is_null() {
                Err(RuntimeError::new(
                    DiagnosticKind::HostFailure,
                    "IDataObject returned a null TYMED_FILE path",
                ))
            } else {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                let contents = unsafe { read_file_medium_contents(path) }.map_err(|error| {
                    RuntimeError::with_source(
                        DiagnosticKind::HostFailure,
                        "copy IDataObject TYMED_FILE contents before releasing its medium",
                        error,
                    )
                })?;
                Ok(Win16ComHostStorageMedium::FileContents(contents))
            }
        }
        TYMED_ISTREAM_VALUE | TYMED_ISTORAGE_VALUE => {
            // The generated SDK union stores typed Option<IStream/IStorage>
            // inside ManuallyDrop. Borrow its existing reference, clone it
            // through windows-core (AddRef), then ReleaseStgMedium below.
            if medium.tymed == TYMED_ISTREAM_VALUE {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                let slot = unsafe {
                    <std::mem::ManuallyDrop<Option<IStream>> as std::ops::Deref>::deref(
                        &medium.Anonymous.pstm,
                    )
                };
                let borrowed = slot.as_ref().ok_or_else(|| {
                    RuntimeError::new(DiagnosticKind::HostFailure, "null IStream medium")
                })?;
                let interface = borrowed.clone();
                let object = objects.insert_typed_owned(interface).map_err(com_error)?;
                Ok(Win16ComHostStorageMedium::Stream(Win16ComHostInterface {
                    object,
                    owner: objects.owner_identity(),
                    iid: interface_guid::<IStream>(),
                    disposition: ReferenceDisposition::Owned,
                }))
            } else {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                let slot = unsafe {
                    <std::mem::ManuallyDrop<Option<IStorage>> as std::ops::Deref>::deref(
                        &medium.Anonymous.pstg,
                    )
                };
                let borrowed = slot.as_ref().ok_or_else(|| {
                    RuntimeError::new(DiagnosticKind::HostFailure, "null IStorage medium")
                })?;
                let interface = borrowed.clone();
                let object = objects.insert_typed_owned(interface).map_err(com_error)?;
                Ok(Win16ComHostStorageMedium::Storage(Win16ComHostInterface {
                    object,
                    owner: objects.owner_identity(),
                    iid: interface_guid::<IStorage>(),
                    disposition: ReferenceDisposition::Owned,
                }))
            }
        }
        TYMED_GDI_VALUE | TYMED_MFPICT_VALUE | TYMED_ENHMF_VALUE => {
            // Keep the complete native union and its optional pUnkForRelease
            // under an opaque owner-STA token. A runtime layer may request its
            // release, but cannot inspect or free the native resource itself.
            let tymed = medium.tymed;
            let token = objects.store_medium(&mut medium).map_err(com_error)?;
            transferred = true;
            Ok(Win16ComHostStorageMedium::NativeResource { tymed, token })
        }
        _ => Err(RuntimeError::new(
            DiagnosticKind::HostFailure,
            format!(
                "IDataObject returned unsupported STGMEDIUM type {}",
                medium.tymed
            ),
        )),
    })();
    // STGMEDIUM uses an SDK cleanup function because pUnkForRelease may own
    // the resources instead of the union's apparent handle.
    if !transferred {
        // SAFETY: GetData transferred this medium to the host adapter. Unless
        // the whole structure was moved into the owner table, release every
        // supported/unsupported result through the SDK helper.
        unsafe { ReleaseStgMedium(&medium) }
    };
    copied
}

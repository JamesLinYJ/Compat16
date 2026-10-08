//! Native COM/OLE operations for Win16 adapters.
//!
//! This boundary accepts logical GUID values and opaque object keys. Native
//! interface pointers and OLE allocated strings are consumed here and never
//! become runtime or guest-visible pointer values.

use std::ptr;

use compat_services::com::{
    IID_IBIND_CTX, IID_IDATA_OBJECT, IID_IMALLOC, IID_IOLE_CLIENT_SITE, IID_IPERSIST_STORAGE,
    IID_IPERSIST_STREAM, IID_IRUNNING_OBJECT_TABLE, IID_ISTORAGE, IID_ISTREAM, IID_IUNKNOWN,
};
use runtime::{
    DiagnosticKind, RuntimeError,
    Win16OleHostOperation as Win16OleNativeOperation, Win16OleHostReply as Win16OleNativeReply,
    Win16OleHostValue as Win16OleNativeValue,
};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::core::HRESULT;
use windows_sys::Win32::System::Com::StructuredStorage::{
    GetConvertStg, ReadClassStg, ReadClassStm, ReadFmtUserTypeStg, SetConvertStg, WriteClassStg,
    WriteClassStm, WriteFmtUserTypeStg,
};
use windows_sys::Win32::System::Com::{
    CLSIDFromProgID, CLSIDFromString, CoBuildVersion, CoCreateGuid, CoCreateInstance,
    CoDisconnectObject, CoDosDateTimeToFileTime, CoFileTimeNow, CoFileTimeToDosDateTime,
    CoFreeUnusedLibraries, CoGetClassObject, CoGetCurrentProcess, CoGetMalloc, CoGetTreatAsClass,
    CoIsOle1Class, CoLockObjectExternal, CoTaskMemFree, CoTreatAsClass,
    CreateBindCtx, GetRunningObjectTable, ProgIDFromCLSID, StringFromCLSID, StringFromGUID2,
    StringFromIID,
};
use windows_sys::Win32::System::Ole::{
    OleDoAutoConvert, OleFlushClipboard, OleGetAutoConvert, OleGetClipboard,
    OleIsCurrentClipboard, OleIsRunning, OleLoad, OleLoadFromStream, OleLockRunning,
    OleNoteObjectVisible, OleQueryCreateFromData, OleQueryLinkFromData, OleRun, OleSave,
    OleSaveToStream, OleSetAutoConvert, OleSetClipboard, OleSetContainedObject,
};
use windows_sys::core::{GUID as NativeGuid, PWSTR};

use super::win16_com_objects::Win16ComObjects;
use super::win16_com_request_executor::Win16ComApartmentRefs;
use self::support::{
    adopt_interface, ascii_wide_z, com_error, copy_native_wide, decode_guest_text,
    file_time_bytes, file_time_from_bytes, logical_guid, native_guid, status, wide_z,
    with_optional_interface, with_optional_unknown, with_required_interface,
    with_two_required_interfaces,
};

#[path = "win16_ole_native_monikers.rs"]
mod monikers;
#[path = "win16_ole_native_support.rs"]
mod support;

const E_NOINTERFACE: HRESULT = 0x8000_4002u32 as i32;
const E_INVALIDARG: HRESULT = 0x8007_0057u32 as i32;

pub(super) fn execute(
    objects: &Win16ComObjects,
    apartment: &Win16ComApartmentRefs,
    operation: Win16OleNativeOperation,
) -> Result<Win16OleNativeReply, RuntimeError> {
    let reply = match operation {
        moniker @ (Win16OleNativeOperation::CreateFileMoniker { .. }
        | Win16OleNativeOperation::CreateItemMoniker { .. }
        | Win16OleNativeOperation::CreateGenericComposite { .. }
        | Win16OleNativeOperation::BindMoniker { .. }
        | Win16OleNativeOperation::ParseDisplayName { .. }) => {
            return monikers::execute(objects, moniker);
        }
        Win16OleNativeOperation::Initialize { ole, reserved } => {
            let reply = apartment.initialize(ole, reserved);
            Win16OleNativeReply { status: reply.status, value: reply.value }
        }
        Win16OleNativeOperation::Uninitialize { ole } => {
            let reply = apartment.uninitialize(ole);
            Win16OleNativeReply { status: reply.status, value: reply.value }
        }
        Win16OleNativeOperation::BuildVersion => {
            // SAFETY: scalar query with no pointer preconditions.
            let version = unsafe { CoBuildVersion() };
            status(version as HRESULT, Win16OleNativeValue::Scalar(version))
        }
        Win16OleNativeOperation::GetCurrentProcess => {
            // SAFETY: scalar query with no pointer preconditions.
            let process = unsafe { CoGetCurrentProcess() };
            status(process as HRESULT, Win16OleNativeValue::Scalar(process))
        }
        Win16OleNativeOperation::GetMalloc { context } => {
            let mut output = ptr::null_mut();
            // SAFETY: `output` is a valid writable native interface slot.
            let result = unsafe { CoGetMalloc(context, &mut output) };
            let (result, value) = adopt_interface(objects, result, output, IID_IMALLOC)?;
            status(result, value)
        }
        Win16OleNativeOperation::FreeUnusedLibraries => {
            // SAFETY: the native routine has no pointer preconditions.
            unsafe { CoFreeUnusedLibraries() };
            status(0, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::QueryLinkFromData { data_object } => {
            let Some(result) = with_required_interface(
                objects,
                data_object,
                IID_IDATA_OBJECT,
                "IDataObject",
                |data_object| {
                    // SAFETY: `data_object` is a live IDataObject lease.
                    unsafe { OleQueryLinkFromData(data_object) }
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::QueryCreateFromData { data_object } => {
            let Some(result) = with_required_interface(
                objects,
                data_object,
                IID_IDATA_OBJECT,
                "IDataObject",
                |data_object| {
                    // SAFETY: `data_object` is a live IDataObject lease.
                    unsafe { OleQueryCreateFromData(data_object) }
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::SetClipboard { data_object } => {
            let Some(result) = with_required_interface(
                objects,
                data_object,
                IID_IDATA_OBJECT,
                "IDataObject",
                |data_object| {
                    // SAFETY: `data_object` is a live IDataObject lease.
                    unsafe { OleSetClipboard(data_object) }
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::GetClipboard => {
            let mut output = ptr::null_mut();
            // SAFETY: `output` is a writable native interface slot.
            let result = unsafe { OleGetClipboard(&mut output) };
            let (result, value) = adopt_interface(objects, result, output, IID_IDATA_OBJECT)?;
            status(result, value)
        }
        Win16OleNativeOperation::FlushClipboard => {
            // SAFETY: no pointer arguments or other preconditions.
            status(unsafe { OleFlushClipboard() }, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::IsCurrentClipboard { data_object } => {
            let Some(result) = with_required_interface(
                objects,
                data_object,
                IID_IDATA_OBJECT,
                "IDataObject",
                |data_object| {
                    // SAFETY: `data_object` is a live IDataObject lease.
                    unsafe { OleIsCurrentClipboard(data_object) }
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::DoAutoConvert { storage } => {
            let Some((result, clsid)) =
                with_required_interface(objects, storage, IID_ISTORAGE, "IStorage", |storage| {
                    let mut clsid = NativeGuid::default();
                    // SAFETY: the storage lease is live and `clsid` is a
                    // writable local GUID slot.
                    let result = unsafe { OleDoAutoConvert(storage, &mut clsid) };
                    (result, logical_guid(clsid))
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::Guid(clsid))
        }
        Win16OleNativeOperation::GetAutoConvert { clsid } => {
            let old = native_guid(clsid);
            let mut output = NativeGuid::default();
            // SAFETY: both GUID pointers refer to valid local values.
            let result = unsafe { OleGetAutoConvert(&old, &mut output) };
            status(result, Win16OleNativeValue::Guid(logical_guid(output)))
        }
        Win16OleNativeOperation::SetAutoConvert { clsid, convert_to } => {
            let old = native_guid(clsid);
            let new = native_guid(convert_to);
            // SAFETY: both GUID pointers refer to valid local values.
            status(
                unsafe { OleSetAutoConvert(&old, &new) },
                Win16OleNativeValue::None,
            )
        }
        Win16OleNativeOperation::GetConvertStg { storage } => {
            let Some(result) =
                with_required_interface(objects, storage, IID_ISTORAGE, "IStorage", |storage| {
                    // SAFETY: `storage` is a live IStorage lease.
                    unsafe { GetConvertStg(storage) }
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::SetConvertStg { storage, converted } => {
            let Some(result) =
                with_required_interface(objects, storage, IID_ISTORAGE, "IStorage", |storage| {
                    // SAFETY: `storage` is a live IStorage lease.
                    unsafe { SetConvertStg(storage, i32::from(converted)) }
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::ReadFormatUserType { storage } => {
            let Some((result, format, output)) =
                with_required_interface(objects, storage, IID_ISTORAGE, "IStorage", |storage| {
                    let mut format = 0;
                    let mut output: PWSTR = ptr::null_mut();
                    // SAFETY: `storage` is a live IStorage lease and both
                    // output slots are writable local values.
                    let result = unsafe { ReadFmtUserTypeStg(storage, &mut format, &mut output) };
                    (result, format, output)
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            let user_type = if result >= 0 {
                copy_native_wide(output)
            } else {
                None
            };
            if !output.is_null() {
                // SAFETY: the OLE API returned this allocated user-type string.
                unsafe { CoTaskMemFree(output.cast()) };
            }
            if result >= 0 && user_type.is_none() {
                return Err(RuntimeError::new(
                    DiagnosticKind::HostFailure,
                    "native structured-storage reader returned an invalid user-type string",
                ));
            }
            let value = user_type.map_or(Win16OleNativeValue::None, |user_type| {
                Win16OleNativeValue::FormatUserType { format, user_type }
            });
            status(result, value)
        }
        Win16OleNativeOperation::WriteFormatUserType {
            storage,
            format,
            user_type,
            code_page,
        } => {
            let user_type = decode_guest_text(&user_type, code_page)?;
            let wide: Vec<_> = user_type.encode_utf16().collect();
            let Some(user_type) = wide_z(&wide) else {
                return Ok(status(E_INVALIDARG, Win16OleNativeValue::None));
            };
            let Some(result) =
                with_required_interface(objects, storage, IID_ISTORAGE, "IStorage", |storage| {
                    // SAFETY: `storage` is a live IStorage lease and the
                    // owned user-type text is terminated for this call.
                    unsafe { WriteFmtUserTypeStg(storage, format, user_type.as_ptr()) }
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::Run { object } => {
            let Some(result) =
                with_required_interface(objects, object, IID_IUNKNOWN, "IUnknown", |unknown| {
                    // SAFETY: `unknown` is a live host-owned IUnknown lease.
                    unsafe { OleRun(unknown) }
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::IsRunning { object } => {
            let Some(answer) =
                with_required_interface(objects, object, IID_IUNKNOWN, "IUnknown", |unknown| {
                    // SAFETY: `unknown` is a live host-owned IUnknown lease.
                    unsafe { OleIsRunning(unknown) }
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::Scalar(0)));
            };
            status(
                answer as HRESULT,
                Win16OleNativeValue::Scalar(answer as u32),
            )
        }
        Win16OleNativeOperation::LockRunning {
            object,
            lock,
            last_unlock_closes,
        } => {
            let Some(result) =
                with_required_interface(objects, object, IID_IUNKNOWN, "IUnknown", |unknown| {
                    // SAFETY: `unknown` is a live host-owned IUnknown lease.
                    unsafe {
                        OleLockRunning(unknown, i32::from(lock), i32::from(last_unlock_closes))
                    }
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::DisconnectObject { object, reserved } => {
            let result = objects
                .with_interface(object, IID_IUNKNOWN, |unknown| {
                    // SAFETY: `unknown` is a live host-owned IUnknown lease.
                    unsafe { CoDisconnectObject(unknown, reserved) }
                })
                .map_err(com_error)?;
            status(result.unwrap_or(E_NOINTERFACE), Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::LockObjectExternal {
            object,
            lock,
            last_unlock_releases,
        } => {
            let result = objects
                .with_interface(object, IID_IUNKNOWN, |unknown| {
                    // SAFETY: `unknown` is a live host-owned IUnknown lease.
                    unsafe {
                        CoLockObjectExternal(
                            unknown,
                            i32::from(lock),
                            i32::from(last_unlock_releases),
                        )
                    }
                })
                .map_err(com_error)?;
            status(result.unwrap_or(E_NOINTERFACE), Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::CreateGuid => {
            let mut output = NativeGuid::default();
            // SAFETY: `output` is a valid writable native GUID.
            let result = unsafe { CoCreateGuid(&mut output) };
            status(result, Win16OleNativeValue::Guid(logical_guid(output)))
        }
        Win16OleNativeOperation::GuidFromString { text } => {
            let Some(text) = ascii_wide_z(&text) else {
                return Ok(status(E_INVALIDARG, Win16OleNativeValue::None));
            };
            let mut output = NativeGuid::default();
            // SAFETY: `text` is an owned NUL-terminated UTF-16 GUID string and
            // `output` is a valid writable native GUID.
            let result = unsafe { CLSIDFromString(text.as_ptr(), &mut output) };
            status(result, Win16OleNativeValue::Guid(logical_guid(output)))
        }
        Win16OleNativeOperation::ClsidFromProgId { progid, code_page } => {
            let decoded = decode_guest_text(&progid, code_page)?;
            let wide_units: Vec<u16> = decoded.encode_utf16().collect();
            let Some(wide) = wide_z(&wide_units) else {
                return Ok(status(E_INVALIDARG, Win16OleNativeValue::None));
            };
            let mut output = NativeGuid::default();
            // SAFETY: `wide` is owned NUL-terminated UTF-16 and `output` is a
            // valid writable native GUID.
            let result = unsafe { CLSIDFromProgID(wide.as_ptr(), &mut output) };
            status(result, Win16OleNativeValue::Guid(logical_guid(output)))
        }
        Win16OleNativeOperation::GuidToString {
            guid,
            allocated: false,
            iid: _,
        } => {
            let native = native_guid(guid);
            let mut wide = [0u16; 39];
            // SAFETY: `wide` has the 39 WCHAR slots required for a braced GUID
            // and the input GUID lives for the duration of the call.
            let length = unsafe { StringFromGUID2(&native, wide.as_mut_ptr(), wide.len() as i32) };
            if length == 0 {
                status(E_INVALIDARG, Win16OleNativeValue::None)
            } else {
                let text = wide[..length as usize]
                    .iter()
                    .map(|unit| *unit as u8)
                    .collect();
                status(length as HRESULT, Win16OleNativeValue::GuidText(text))
            }
        }
        Win16OleNativeOperation::GuidToString {
            guid,
            allocated: true,
            iid,
            ..
        } => {
            let native = native_guid(guid);
            let mut output: PWSTR = ptr::null_mut();
            // SAFETY: the APIs write one CoTaskMem-owned UTF-16 string to the
            // writable output slot. It is copied and freed below.
            let result = unsafe {
                if iid {
                    StringFromIID(&native, &mut output)
                } else {
                    StringFromCLSID(&native, &mut output)
                }
            };
            let wide = if result >= 0 {
                copy_native_wide(output)
            } else {
                None
            };
            if !output.is_null() {
                // SAFETY: output is either null or the allocator-owned string
                // returned by StringFromIID/StringFromCLSID.
                unsafe { CoTaskMemFree(output.cast()) };
            }
            if result >= 0 && wide.is_none() {
                return Err(RuntimeError::new(
                    DiagnosticKind::HostFailure,
                    "native COM GUID formatter returned an invalid allocated string",
                ));
            }
            status(
                result,
                wide.map_or(Win16OleNativeValue::None, Win16OleNativeValue::WideText),
            )
        }
        Win16OleNativeOperation::ProgIdFromClsid { clsid } => {
            let native = native_guid(clsid);
            let mut output: PWSTR = ptr::null_mut();
            // SAFETY: the API writes one CoTaskMem-owned UTF-16 string to the
            // writable output slot. It is copied and freed below.
            let result = unsafe { ProgIDFromCLSID(&native, &mut output) };
            let wide = if result >= 0 {
                copy_native_wide(output)
            } else {
                None
            };
            if !output.is_null() {
                // SAFETY: output is either null or the allocator-owned string
                // returned by ProgIDFromCLSID.
                unsafe { CoTaskMemFree(output.cast()) };
            }
            if result >= 0 && wide.is_none() {
                return Err(RuntimeError::new(
                    DiagnosticKind::HostFailure,
                    "native COM ProgID formatter returned an invalid allocated string",
                ));
            }
            status(
                result,
                wide.map_or(Win16OleNativeValue::None, Win16OleNativeValue::WideText),
            )
        }
        Win16OleNativeOperation::IsEqualGuid { left, right } => status(
            u32::from(left == right) as HRESULT,
            Win16OleNativeValue::None,
        ),
        Win16OleNativeOperation::IsOle1Class { clsid } => {
            let native = native_guid(clsid);
            // SAFETY: the input is a valid native GUID pointer.
            let answer = unsafe { CoIsOle1Class(&native) };
            status(
                answer as HRESULT,
                Win16OleNativeValue::Scalar(answer as u32),
            )
        }
        Win16OleNativeOperation::GetTreatAsClass { clsid } => {
            let old = native_guid(clsid);
            let mut output = NativeGuid::default();
            // SAFETY: both GUID pointers refer to valid local values.
            let result = unsafe { CoGetTreatAsClass(&old, &mut output) };
            status(result, Win16OleNativeValue::Guid(logical_guid(output)))
        }
        Win16OleNativeOperation::TreatAsClass { clsid, treat_as } => {
            let old = native_guid(clsid);
            let new = native_guid(treat_as);
            // SAFETY: both GUID pointers refer to valid local values.
            let result = unsafe { CoTreatAsClass(&old, &new) };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::CreateInstance {
            clsid,
            outer,
            context,
            iid,
        } => {
            let class_id = native_guid(clsid);
            let interface_id = native_guid(iid);
            let Some((result, output)) = with_optional_unknown(objects, outer, |outer| {
                let mut output = ptr::null_mut();
                // SAFETY: GUID inputs are valid local values, the optional
                // outer is a leased IUnknown, and `output` is writable.
                let result = unsafe {
                    CoCreateInstance(&class_id, outer, context, &interface_id, &mut output)
                };
                (result, output)
            })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            let (result, value) = adopt_interface(objects, result, output, iid)?;
            status(result, value)
        }
        Win16OleNativeOperation::GetClassObject {
            clsid,
            context,
            iid,
        } => {
            let class_id = native_guid(clsid);
            let interface_id = native_guid(iid);
            let mut output = ptr::null_mut();
            // SAFETY: GUID inputs and output slot are valid. Runtime only
            // issues this operation after confirming that the Win16
            // COSERVERINFO pointer was null; guest structures never cross.
            let result = unsafe {
                CoGetClassObject(&class_id, context, ptr::null(), &interface_id, &mut output)
            };
            let (result, value) = adopt_interface(objects, result, output, iid)?;
            status(result, value)
        }
        Win16OleNativeOperation::CreateBindContext { reserved } => {
            let mut output = ptr::null_mut();
            // SAFETY: `output` is a writable native interface slot.
            let result = unsafe { CreateBindCtx(reserved, &mut output) };
            let (result, value) = adopt_interface(objects, result, output, IID_IBIND_CTX)?;
            status(result, value)
        }
        Win16OleNativeOperation::GetRunningObjectTable { reserved } => {
            let mut output = ptr::null_mut();
            // SAFETY: `output` is a writable native interface slot.
            let result = unsafe { GetRunningObjectTable(reserved, &mut output) };
            let (result, value) =
                adopt_interface(objects, result, output, IID_IRUNNING_OBJECT_TABLE)?;
            status(result, value)
        }
        Win16OleNativeOperation::ReadClassStorage { storage } => {
            let Some((result, clsid)) = with_required_interface(
                objects,
                storage,
                compat_services::com::IID_ISTORAGE,
                "IStorage",
                |storage| {
                    let mut clsid = NativeGuid::default();
                    // SAFETY: `storage` is a live IStorage lease and `clsid`
                    // is a writable local GUID slot.
                    let result = unsafe { ReadClassStg(storage, &mut clsid) };
                    (result, logical_guid(clsid))
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::Guid(clsid))
        }
        Win16OleNativeOperation::WriteClassStorage { storage, clsid } => {
            let clsid = native_guid(clsid);
            let Some(result) = with_required_interface(
                objects,
                storage,
                compat_services::com::IID_ISTORAGE,
                "IStorage",
                |storage| {
                    // SAFETY: `storage` is a live IStorage lease and `clsid`
                    // is a valid local GUID pointer.
                    unsafe { WriteClassStg(storage, &clsid) }
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::ReadClassStream { stream } => {
            let Some((result, clsid)) = with_required_interface(
                objects,
                stream,
                compat_services::com::IID_ISTREAM,
                "IStream",
                |stream| {
                    let mut clsid = NativeGuid::default();
                    // SAFETY: `stream` is a live IStream lease and `clsid` is
                    // a writable local GUID slot.
                    let result = unsafe { ReadClassStm(stream, &mut clsid) };
                    (result, logical_guid(clsid))
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::Guid(clsid))
        }
        Win16OleNativeOperation::WriteClassStream { stream, clsid } => {
            let clsid = native_guid(clsid);
            let Some(result) = with_required_interface(
                objects,
                stream,
                compat_services::com::IID_ISTREAM,
                "IStream",
                |stream| {
                    // SAFETY: `stream` is a live IStream lease and `clsid` is
                    // a valid local GUID pointer.
                    unsafe { WriteClassStm(stream, &clsid) }
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::SetContainedObject { object, contained } => {
            let Some(result) =
                with_required_interface(objects, object, IID_IUNKNOWN, "IUnknown", |unknown| {
                    // SAFETY: `unknown` is a live host-owned IUnknown lease.
                    unsafe { OleSetContainedObject(unknown, i32::from(contained)) }
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::NoteObjectVisible { object, visible } => {
            let Some(result) =
                with_required_interface(objects, object, IID_IUNKNOWN, "IUnknown", |unknown| {
                    // SAFETY: `unknown` is a live host-owned IUnknown lease.
                    unsafe { OleNoteObjectVisible(unknown, i32::from(visible)) }
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::Load {
            storage,
            iid,
            client_site,
        } => {
            let logical_iid = iid;
            let native_iid = native_guid(logical_iid);
            let Some(site_result) =
                with_required_interface(objects, storage, IID_ISTORAGE, "IStorage", |storage| {
                    with_optional_interface(
                        objects,
                        client_site,
                        IID_IOLE_CLIENT_SITE,
                        |client_site| {
                            let mut output = ptr::null_mut();
                            // SAFETY: `storage` and optional `client_site` are
                            // live interface leases; the GUID is local and the
                            // output pointer is writable.
                            let result =
                                unsafe { OleLoad(storage, &native_iid, client_site, &mut output) };
                            (result, output)
                        },
                    )
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            let Some((result, output)) = site_result? else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            let (result, value) = adopt_interface(objects, result, output, logical_iid)?;
            status(result, value)
        }
        Win16OleNativeOperation::Save {
            persist_storage,
            storage,
            same_as_load,
        } => {
            let Some(result) = with_two_required_interfaces(
                objects,
                persist_storage,
                IID_IPERSIST_STORAGE,
                storage,
                IID_ISTORAGE,
                |persist_storage, storage| {
                    // SAFETY: both pointers are live leases for the requested
                    // interfaces.
                    unsafe { OleSave(persist_storage, storage, i32::from(same_as_load)) }
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::LoadFromStream { stream, iid } => {
            let logical_iid = iid;
            let native_iid = native_guid(logical_iid);
            let Some((result, output)) =
                with_required_interface(objects, stream, IID_ISTREAM, "IStream", |stream| {
                    let mut output = ptr::null_mut();
                    // SAFETY: `stream` is a live IStream lease, the GUID is
                    // local, and `output` is writable.
                    let result = unsafe { OleLoadFromStream(stream, &native_iid, &mut output) };
                    (result, output)
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            let (result, value) = adopt_interface(objects, result, output, logical_iid)?;
            status(result, value)
        }
        Win16OleNativeOperation::SaveToStream {
            persist_stream,
            stream,
        } => {
            let Some(result) = with_two_required_interfaces(
                objects,
                persist_stream,
                IID_IPERSIST_STREAM,
                stream,
                IID_ISTREAM,
                |persist_stream, stream| {
                    // SAFETY: both pointers are live leases for the requested
                    // interfaces.
                    unsafe { OleSaveToStream(persist_stream, stream) }
                },
            )?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            status(result, Win16OleNativeValue::None)
        }
        Win16OleNativeOperation::FileTimeNow => {
            let mut output = FILETIME::default();
            // SAFETY: `output` is a valid writable native FILETIME.
            let result = unsafe { CoFileTimeNow(&mut output) };
            status(
                result,
                Win16OleNativeValue::FileTime(file_time_bytes(output)),
            )
        }
        Win16OleNativeOperation::FileTimeToDosDateTime { file_time } => {
            let input = file_time_from_bytes(file_time);
            let (mut date, mut time) = (0u16, 0u16);
            // SAFETY: the input FILETIME and both output words are valid local
            // values for this native conversion call.
            let result = unsafe { CoFileTimeToDosDateTime(&input, &mut date, &mut time) };
            status(
                result as HRESULT,
                Win16OleNativeValue::DosDateTime { date, time },
            )
        }
        Win16OleNativeOperation::DosDateTimeToFileTime { date, time } => {
            let mut output = FILETIME::default();
            // SAFETY: `output` is a valid writable native FILETIME.
            let result = unsafe { CoDosDateTimeToFileTime(date, time, &mut output) };
            status(
                result as HRESULT,
                Win16OleNativeValue::FileTime(file_time_bytes(output)),
            )
        }
    };
    Ok(reply)
}

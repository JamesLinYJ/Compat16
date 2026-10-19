//! Native MSACM adapter. Native handles stay in this host-owned table;
//! callbacks copy native records into owned values before returning.

#[path = "win16_acm_direct/choose.rs"]
mod choose;
#[path = "win16_acm_direct/driver.rs"]
mod driver;
#[path = "win16_acm_direct/format.rs"]
mod format;
#[path = "win16_acm_direct/stream.rs"]
mod stream;
#[path = "win16_acm_direct/text.rs"]
mod text;

use std::{
    collections::{HashMap, TryReserveError},
    error::Error,
    fmt,
};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostAcmHandle as Handle, Win16HostAcmNativeFailure,
    Win16HostAcmNativeOperation, Win16HostAcmObjectKind as ObjectKind,
    Win16HostAcmOperation as Operation, Win16HostAcmResult as ResultValue,
};
use windows_sys::Win32::Media::Audio::{HACMDRIVER, HACMDRIVERID, HACMSTREAM};

use super::win16_images::Win16Images;

const NOERROR: u32 = windows_sys::Win32::Media::MMSYSERR_NOERROR;
const INVALHANDLE: u32 = windows_sys::Win32::Media::MMSYSERR_INVALHANDLE;
const NOTSUPPORTED: u32 = windows_sys::Win32::Media::MMSYSERR_NOTSUPPORTED;

#[derive(Debug)]
struct NativeCallbackAllocationFailure {
    native: Win16HostAcmNativeFailure,
    allocation: TryReserveError,
}

impl fmt::Display for NativeCallbackAllocationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; retaining callback data failed: {}",
            self.native, self.allocation
        )
    }
}

impl Error for NativeCallbackAllocationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.allocation)
    }
}

#[derive(Debug)]
struct NativeAcmContextFailure {
    native: Win16HostAcmNativeFailure,
    cause: RuntimeError,
}

impl fmt::Display for NativeAcmContextFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; retaining native ACM identities failed: {}",
            self.native, self.cause
        )
    }
}

impl Error for NativeAcmContextFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

pub(super) fn retain_native_result(
    error: RuntimeError,
    operation: Win16HostAcmNativeOperation,
    result: u32,
) -> RuntimeError {
    let kind = error.kind();
    RuntimeError::with_source(
        kind,
        "native ACM operation result is retained with a subsequent adapter failure",
        NativeAcmContextFailure {
            native: Win16HostAcmNativeFailure::new(operation, result),
            cause: error,
        },
    )
}

pub(super) fn native_allocation_error(
    operation: Win16HostAcmNativeOperation,
    result: u32,
    allocation: TryReserveError,
) -> RuntimeError {
    RuntimeError::with_source(
        Kind::ResourceExhausted,
        "native ACM operation could not retain an enumeration record",
        NativeCallbackAllocationFailure {
            native: Win16HostAcmNativeFailure::new(operation, result),
            allocation,
        },
    )
}

pub(super) fn callback_panic_error(
    operation: Win16HostAcmNativeOperation,
    result: u32,
) -> RuntimeError {
    RuntimeError::with_source(
        Kind::InternalInvariant,
        "native ACM callback panicked after its native operation returned",
        Win16HostAcmNativeFailure::new(operation, result),
    )
}

pub(super) fn callback_contract_error(
    operation: Win16HostAcmNativeOperation,
    result: u32,
    message: &'static str,
) -> RuntimeError {
    RuntimeError::with_source(
        Kind::InternalInvariant,
        message,
        Win16HostAcmNativeFailure::new(operation, result),
    )
}

enum NativeObject {
    DriverId { raw: usize, added: bool },
    Driver(usize),
    Stream(stream::NativeStream),
}

/// Owns every native ACM identity and stream allocation created by this host.
#[derive(Default)]
pub(super) struct Win16AcmHost {
    next_identity: u64,
    objects: HashMap<Handle, NativeObject>,
}

impl Win16AcmHost {
    pub(super) fn execute(
        &mut self,
        operation: Operation,
        images: &Win16Images,
        codec: super::guest_text::GuestTextCodec,
    ) -> std::result::Result<ResultValue, RuntimeError> {
        match operation {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            Operation::GetVersion => Ok(ResultValue::Scalar(unsafe {
                windows_sys::Win32::Media::Audio::acmGetVersion()
            })),
            Operation::Metrics { object, metric } => {
                let mut value = 0u32;
                let native = match object {
                    Some((kind, handle)) => match self.object_address(handle, kind) {
                        Some(raw) => raw as *mut core::ffi::c_void,
                        None => {
                            return Ok(ResultValue::Metric {
                                result: INVALHANDLE,
                                value,
                            });
                        }
                    },
                    None => std::ptr::null_mut(),
                };
                // SAFETY: acmMetrics writes into a caller-owned output slot.
                let result = unsafe {
                    windows_sys::Win32::Media::Audio::acmMetrics(
                        native,
                        u32::from(metric),
                        (&mut value as *mut u32).cast(),
                    )
                };
                Ok(ResultValue::Metric { result, value })
            }
            Operation::DriverEnum { instance: _, flags } => driver::enumerate(self, flags),
            Operation::DriverAdd {
                module_instance,
                name,
                priority,
                flags,
            } => driver::add(
                self,
                codec,
                module_instance,
                name.as_deref(),
                priority,
                flags,
            ),
            Operation::DriverRemove { driver_id, flags } => {
                let Some(native) = self.added_driver_id(driver_id) else {
                    return Ok(ResultValue::Scalar(INVALHANDLE));
                };
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                let result =
                    unsafe { windows_sys::Win32::Media::Audio::acmDriverRemove(native, flags) };
                if result == NOERROR {
                    self.objects.remove(&driver_id);
                }
                Ok(ResultValue::Scalar(result))
            }
            Operation::DriverIdRelease { driver_id } => {
                let released = self.release_borrowed_driver_id(driver_id);
                Ok(ResultValue::Scalar(if released {
                    NOERROR
                } else {
                    INVALHANDLE
                }))
            }
            Operation::DriverOpen { driver_id, flags } => driver::open(self, driver_id, flags),
            Operation::DriverClose { driver, flags } => driver::close(self, driver, flags),
            Operation::DriverId {
                object_kind,
                object,
                flags,
            } => driver::driver_id(self, object_kind, object, flags),
            Operation::DriverPriority {
                driver_id,
                priority,
                flags,
            } => {
                let Some(native) = self.driver_id(driver_id) else {
                    return Ok(ResultValue::Scalar(INVALHANDLE));
                };
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                let result = unsafe {
                    windows_sys::Win32::Media::Audio::acmDriverPriority(native, priority, flags)
                };
                Ok(ResultValue::Scalar(result))
            }
            // The ABI gives message parameters no trustworthy type metadata.
            // Do not pass guest integers as HWNDs, pointers, or LPARAM values.
            Operation::DriverMessage {
                driver,
                message: _,
                param1: _,
                param2: _,
            } => Ok(ResultValue::Scalar(if self.driver(driver).is_some() {
                NOTSUPPORTED
            } else {
                INVALHANDLE
            })),
            Operation::DriverDetails { driver_id, flags } => {
                driver::details(self, codec, driver_id, flags, images)
            }
            Operation::TagDetails {
                kind,
                driver,
                query,
                initial,
            } => format::tag_details(self, codec, kind, driver, query, initial),
            Operation::TagEnum {
                kind,
                driver,
                template,
                instance: _,
                flags,
            } => format::tag_enum(self, codec, kind, driver, template, flags),
            Operation::ItemDetails {
                kind,
                driver,
                query,
                initial,
                capacity,
            } => format::item_details(self, codec, kind, driver, query, initial, capacity),
            Operation::ItemEnum {
                kind,
                driver,
                template,
                capacity,
                instance: _,
                flags,
            } => format::item_enum(self, codec, kind, driver, template, capacity, flags),
            Operation::FormatSuggest {
                driver,
                source,
                destination,
                flags,
            } => format::suggest(self, driver, source, destination, flags),
            Operation::Choose {
                kind,
                owner,
                style,
                data,
                data_capacity,
                title,
                tag_name,
                item_name,
                saved_name,
                saved_name_capacity,
                enum_flags,
                enum_data,
            } => choose::choose(
                codec,
                kind,
                owner,
                style,
                data,
                data_capacity,
                title,
                tag_name,
                item_name,
                saved_name,
                saved_name_capacity,
                enum_flags,
                enum_data,
            ),
            Operation::StreamOpen {
                driver,
                source,
                destination,
                filter,
                flags,
                query_only,
            } => stream::open(self, driver, source, destination, filter, flags, query_only),
            Operation::StreamClose { stream, flags } => stream::close(self, stream, flags),
            Operation::StreamSize {
                stream,
                input_bytes,
                flags,
            } => stream::size(self, stream, input_bytes, flags),
            Operation::StreamPrepareHeader {
                stream,
                header_token,
                flags,
                status,
                user,
                source_user,
                destination_user,
                source,
                destination,
                reserved,
            } => stream::prepare(
                self,
                stream,
                header_token,
                flags,
                status,
                user,
                source_user,
                destination_user,
                source,
                destination,
                reserved,
            ),
            Operation::StreamUnprepareHeader {
                stream,
                header_token,
                flags,
            } => stream::unprepare(self, stream, header_token, flags),
            Operation::StreamConvert {
                stream,
                header_token,
                source,
                destination,
                flags,
            } => stream::convert(self, stream, header_token, source, destination, flags),
            Operation::StreamReset { stream, flags } => stream::reset(self, stream, flags),
        }
    }

    pub(super) fn reserve_identity(&mut self) -> std::result::Result<Handle, RuntimeError> {
        self.reserve_identities(1)?.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "reserved native ACM identity was not returned",
            )
        })
    }

    fn reserve_identities(
        &mut self,
        count: usize,
    ) -> std::result::Result<Vec<Handle>, RuntimeError> {
        let count_u64 = u64::try_from(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "native ACM identity count exceeds token width",
                error,
            )
        })?;
        let final_identity = self.next_identity.checked_add(count_u64).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native ACM identity space is exhausted",
            )
        })?;
        let mut handles = Vec::new();
        handles.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native ACM identity batch",
                error,
            )
        })?;
        self.objects.try_reserve(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native ACM owner-table entries",
                error,
            )
        })?;
        for offset in 0..count_u64 {
            handles.push(Handle::new(self.next_identity + offset + 1, 1));
        }
        self.next_identity = final_identity;
        Ok(handles)
    }

    /// Allocate every borrowed DriverId token before publishing any of them.
    /// Enumeration callbacks return native IDs in a batch; an allocation
    /// failure must not strand only the earlier identities in this table.
    pub(super) fn map_borrowed_driver_ids(
        &mut self,
        raw_ids: &[usize],
    ) -> std::result::Result<Vec<Handle>, RuntimeError> {
        let mut mapped = Vec::new();
        mapped.try_reserve_exact(raw_ids.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve mapped ACM enumeration identities",
                error,
            )
        })?;
        let mut new_count = 0usize;
        for (index, raw) in raw_ids.iter().copied().enumerate() {
            if raw == 0 {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native ACM enumeration returned a null driver identity",
                ));
            }
            let already_owned = self.objects.values().any(|object| {
                matches!(object,
                NativeObject::DriverId { raw: existing, .. } if *existing == raw)
            });
            if !already_owned && !raw_ids[..index].contains(&raw) {
                new_count = new_count.checked_add(1).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "ACM enumeration identity count overflow",
                    )
                })?;
            }
        }
        let mut planned = Vec::new();
        planned.try_reserve_exact(new_count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve borrowed ACM identity publication plan",
                error,
            )
        })?;
        let reserved = self.reserve_identities(new_count)?;
        let mut reserved_index = 0usize;
        for (index, raw) in raw_ids.iter().copied().enumerate() {
            if let Some((handle, _)) = self.objects.iter().find(|(_, object)| {
                matches!(object,
                NativeObject::DriverId { raw: existing, .. } if *existing == raw)
            }) {
                mapped.push(*handle);
                continue;
            }
            if let Some(previous) = raw_ids[..index].iter().position(|prior| *prior == raw) {
                mapped.push(mapped[previous]);
                continue;
            }
            let handle = reserved.get(reserved_index).copied().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "ACM enumeration identity reservation was incomplete",
                )
            })?;
            reserved_index += 1;
            planned.push((raw, handle));
            mapped.push(handle);
        }
        for (raw, handle) in planned {
            self.objects
                .insert(handle, NativeObject::DriverId { raw, added: false });
        }
        Ok(mapped)
    }

    fn store_reserved(
        &mut self,
        handle: Handle,
        object: NativeObject,
    ) -> std::result::Result<(), RuntimeError> {
        if self.objects.contains_key(&handle) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "reserved native ACM identity was already published",
            ));
        }
        self.objects.insert(handle, object);
        Ok(())
    }

    pub(super) fn handle_for_driver_id(
        &mut self,
        driver_id: HACMDRIVERID,
    ) -> std::result::Result<Option<Handle>, RuntimeError> {
        if driver_id.is_null() {
            return Ok(None);
        }
        let raw = driver_id as usize;
        if let Some((handle, _)) = self.objects.iter().find(|(_, object)| {
            matches!(object, NativeObject::DriverId { raw: existing, .. } if *existing == raw)
        }) {
            return Ok(Some(*handle));
        }
        let handle = self.reserve_identity()?;
        self.store_reserved(handle, NativeObject::DriverId { raw, added: false })?;
        Ok(Some(handle))
    }

    pub(super) fn driver_id(&self, handle: Handle) -> Option<HACMDRIVERID> {
        match self.objects.get(&handle) {
            Some(NativeObject::DriverId { raw, .. }) => Some(*raw as HACMDRIVERID),
            _ => None,
        }
    }

    fn added_driver_id(&self, handle: Handle) -> Option<HACMDRIVERID> {
        match self.objects.get(&handle) {
            Some(NativeObject::DriverId { raw, added: true }) => Some(*raw as HACMDRIVERID),
            _ => None,
        }
    }

    pub(super) fn release_borrowed_driver_id(&mut self, handle: Handle) -> bool {
        if !matches!(
            self.objects.get(&handle),
            Some(NativeObject::DriverId { added: false, .. })
        ) {
            return false;
        }
        self.objects.remove(&handle);
        true
    }

    pub(super) fn driver(&self, handle: Handle) -> Option<HACMDRIVER> {
        match self.objects.get(&handle) {
            Some(NativeObject::Driver(raw)) => Some(*raw as HACMDRIVER),
            _ => None,
        }
    }

    pub(super) fn stream(&self, handle: Handle) -> Option<HACMSTREAM> {
        match self.objects.get(&handle) {
            Some(NativeObject::Stream(stream)) => Some(stream.native()),
            _ => None,
        }
    }

    fn stream_mut(&mut self, handle: Handle) -> Option<&mut stream::NativeStream> {
        match self.objects.get_mut(&handle) {
            Some(NativeObject::Stream(stream)) => Some(stream),
            _ => None,
        }
    }

    pub(super) fn object_address(&self, handle: Handle, kind: ObjectKind) -> Option<usize> {
        match (self.objects.get(&handle)?, kind) {
            (NativeObject::DriverId { raw, .. }, ObjectKind::DriverId) => Some(*raw),
            (NativeObject::Driver(raw), ObjectKind::Driver) => Some(*raw),
            (NativeObject::Stream(stream), ObjectKind::Stream) => Some(stream.native() as usize),
            _ => None,
        }
    }

    pub(super) fn remove(&mut self, handle: Handle) {
        self.objects.remove(&handle);
    }
}

impl Drop for Win16AcmHost {
    fn drop(&mut self) {
        // Runtime teardown owns retry and error reporting. Preserve native
        // resources only when a driver or stream owner is still live; borrowed
        // driver-ID identities alone contain no native resource to keep alive.
        if self.objects.values().any(|object| match object {
            NativeObject::DriverId { added, .. } => *added,
            NativeObject::Driver(_) | NativeObject::Stream(_) => true,
        }) {
            std::mem::forget(std::mem::take(&mut self.objects));
        }
    }
}

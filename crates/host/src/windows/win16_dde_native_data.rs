//! Native DDEML data-handle access and storage operations.

use super::transaction::DataCopyCreation;
use super::*;

pub(super) fn create_data(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    data: Option<Vec<u8>>,
    count: u32,
    offset: u32,
    item: Option<Win16HostDdeString>,
    format: u16,
    flags: u16,
) -> Result<Win16HostDdeResult, RuntimeError> {
    ensure_byte_payload_format(format)?;
    let (native_instance, native_item) = {
        let state = context.state.borrow();
        (
            state.native_instance(instance)?,
            state.native_optional_string(instance, item)?,
        )
    };
    if data
        .as_ref()
        .is_some_and(|bytes| bytes.len() != count as usize)
    {
        return Err(protocol_error(
            "DDE CreateData source length differs from cbInitData",
        ));
    }
    let source = data.as_ref().map_or(ptr::null(), |bytes| {
        if bytes.is_empty() {
            ptr::null()
        } else {
            bytes.as_ptr()
        }
    });
    // SAFETY: DdeCreateDataHandle reads a caller-owned byte span.
    let native = unsafe {
        DdeCreateDataHandle(
            native_instance,
            source,
            count,
            offset,
            native_item,
            u32::from(format),
            u32::from(flags),
        )
    };
    if native.is_null() {
        return Ok(result(
            Win16HostDdeValue::Data(None),
            native_error(native_instance),
        ));
    }
    match context.state.borrow_mut().intern_data(
        instance,
        native,
        format,
        DataOrigin::Created {
            retain_after_transfer: flags & compat_services::win16_dde::data_flag::HDATA_APPOWNED
                != 0,
        },
        item,
    ) {
        Ok(token) => Ok(result(Win16HostDdeValue::Data(token), 0)),
        Err(error) => {
            // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
            if unsafe { DdeFreeDataHandle(native) } == 0 {
                return Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "index DDE CreateData result and release native handle",
                    error,
                ));
            }
            Err(error)
        }
    }
}

pub(super) fn add_data(
    context: &WorkerContext,
    data: Win16HostDdeData,
    bytes: Vec<u8>,
    offset: u32,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_data, instance, format, origin, item) = {
        let state = context.state.borrow();
        let record = state
            .data
            .get(&data)
            .filter(|record| record.available)
            .ok_or_else(|| protocol_error("DDE AddData references an unavailable token"))?;
        ensure_byte_payload_format(record.format)?;
        (
            state.native_data(data)?,
            record.instance,
            record.format,
            state.data_origin(data)?,
            record.item,
        )
    };
    let native_instance = context.state.borrow().native_instance(instance)?;
    let length = u32::try_from(bytes.len()).map_err(|_| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "DDE AddData payload exceeds DWORD size",
        )
    })?;
    let source = if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    };
    // SAFETY: DdeAddData reads a caller-owned byte span.
    let native = unsafe { DdeAddData(native_data, source, length, offset) };
    if native.is_null() {
        return Ok(result(
            Win16HostDdeValue::Data(None),
            native_error(native_instance),
        ));
    }
    let changed_handle = native != native_data;
    let interned = context
        .state
        .borrow_mut()
        .intern_data(instance, native, format, origin, item);
    if changed_handle {
        context.state.borrow_mut().remove_data(data)?;
    }
    match interned {
        Ok(token) => Ok(result(Win16HostDdeValue::Data(token), 0)),
        Err(error) => {
            // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
            if unsafe { DdeFreeDataHandle(native) } == 0 {
                return Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "index DDE AddData result and release native handle",
                    error,
                ));
            }
            Err(error)
        }
    }
}

/// Duplicate an app-owned byte view into a fresh native DDEML-created handle.
/// This boundary has no Win16/native representation for DDE formats 2, 3, and
/// 9; those are rejected before the copy path. The DDEML lease acquired here
/// is always paired before the new handle can be passed to a transaction.
pub(super) fn copy_transaction_data(
    native_instance: u32,
    source: HDDEDATA,
    item: HSZ,
    format: u16,
) -> Result<DataCopyCreation, RuntimeError> {
    let bytes = snapshot_transaction_data(source)?;
    let count = u32::try_from(bytes.len()).map_err(|_| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "DDE transaction copy exceeds DWORD size",
        )
    })?;
    let source = if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    };
    // SAFETY: DdeCreateDataHandle reads a caller-owned byte span.
    let copy = unsafe {
        DdeCreateDataHandle(
            native_instance,
            source,
            count,
            0,
            item,
            u32::from(format),
            0,
        )
    };
    if !copy.is_null() {
        return Ok(DataCopyCreation::Created(copy));
    }
    let error = (crate::windows::win32_safe::dde_last_error(native_instance)) as u16;
    if matches!(
        error,
        compat_services::win16_dde::error::DLL_NOT_INITIALIZED
            | compat_services::win16_dde::error::INVALIDPARAMETER
            | compat_services::win16_dde::error::MEMORY_ERROR
    ) {
        return Ok(DataCopyCreation::Failed(error));
    }
    Err(RuntimeError::new(
        Kind::HostFailure,
        "DDE transaction copy creation failed without an attributable documented DDEML error",
    ))
}

/// Copy a DDE object while pairing its DdeAccessData lease before returning.
pub(super) fn snapshot_transaction_data(source: HDDEDATA) -> Result<Vec<u8>, RuntimeError> {
    let mut length = 0u32;
    // SAFETY: DdeAccessData locks a data handle this instance owns.
    let pointer = unsafe { DdeAccessData(source, &mut length) };
    if pointer.is_null() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "DDE transaction source could not be accessed for a safe copy",
        ));
    }
    let length_usize = match usize::try_from(length) {
        Ok(value) => value,
        Err(_) => {
            // SAFETY: DdeUnaccessData balances one DdeAccessData.
            if unsafe { DdeUnaccessData(source) } == 0 {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "DDE transaction source size overflowed and its access lease could not be released",
                ));
            }
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE transaction source size does not fit the host",
            ));
        }
    };
    let mut bytes = Vec::new();
    if let Err(error) = bytes.try_reserve_exact(length_usize) {
        // SAFETY: DdeUnaccessData balances one DdeAccessData.
        let released = unsafe { DdeUnaccessData(source) } != 0;
        if !released {
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "allocate DDE transaction copy and release its native access lease",
                error,
            ));
        }
        return Err(RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate DDE transaction data copy",
            error,
        ));
    }
    // SAFETY: DdeAccessData returned a valid view of `length` bytes. The
    // bytes become an owned snapshot before the matching native unaccess.
    bytes.extend_from_slice(unsafe { std::slice::from_raw_parts(pointer, length_usize) });
    if unsafe { DdeUnaccessData(source) } == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "release DDE transaction source access lease after copying",
        ));
    }
    Ok(bytes)
}

pub(super) fn get_data(
    context: &WorkerContext,
    data: Win16HostDdeData,
    capacity: Option<u32>,
    offset: u32,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_data, native_instance) = {
        let state = context.state.borrow();
        let record = state
            .data
            .get(&data)
            .ok_or_else(|| protocol_error("DDE GetData references an unknown host data token"))?;
        ensure_byte_payload_format(record.format)?;
        if !record.available {
            return Err(protocol_error("DDE GetData references a consumed handle"));
        }
        (record.native, state.native_instance(record.instance)?)
    };
    let capacity_usize = match capacity {
        Some(value) => Some(usize::try_from(value).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE GetData capacity does not fit the host",
            )
        })?),
        None => None,
    };
    let Some(capacity) = capacity_usize else {
        let _ = native_error(native_instance);
        // SAFETY: DdeGetData writes into a caller-owned buffer.
        let copied = unsafe { DdeGetData(native_data, ptr::null_mut(), 0, offset) };
        let error = if copied == 0 {
            native_error(native_instance)
        } else {
            0
        };
        return Ok(result(
            Win16HostDdeValue::GetData {
                bytes: Vec::new(),
                copied,
            },
            error,
        ));
    };
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate DDE GetData output",
            error,
        )
    })?;
    bytes.resize(capacity, 0);
    let mut zero_capacity_buffer = 0u8;
    let destination = if bytes.is_empty() {
        &mut zero_capacity_buffer
    } else {
        bytes.as_mut_ptr()
    };
    let _ = native_error(native_instance);
    // SAFETY: DdeGetData writes into a caller-owned buffer.
    let copied = unsafe { DdeGetData(native_data, destination, capacity as u32, offset) };
    bytes.truncate(usize::try_from(copied).unwrap_or(capacity).min(capacity));
    let error = if copied == 0 {
        native_error(native_instance)
    } else {
        0
    };
    if error != 0 {
        bytes.clear();
    }
    Ok(result(Win16HostDdeValue::GetData { bytes, copied }, error))
}

pub(super) fn access_data(
    context: &WorkerContext,
    data: Win16HostDdeData,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_data, native_instance, writable) = {
        let state = context.state.borrow();
        let record = state.data.get(&data).ok_or_else(|| {
            protocol_error("DDE AccessData references an unknown host data token")
        })?;
        ensure_byte_payload_format(record.format)?;
        if !record.available {
            return Err(protocol_error(
                "DDE AccessData references a consumed handle",
            ));
        }
        (
            record.native,
            state.native_instance(record.instance)?,
            state.data_writable(data)?,
        )
    };
    context.state.borrow_mut().reserve_access_slot(data)?;
    let mut length = 0u32;
    // SAFETY: DdeAccessData locks a data handle this instance owns.
    let pointer = unsafe { DdeAccessData(native_data, &mut length) };
    if pointer.is_null() {
        context.state.borrow_mut().cancel_access_slot(data);
        // DdeAccessData identifies failure by a NULL pointer. The SDK's error
        // table permits NO_ERROR here, so an empty snapshot would falsely
        // manufacture a lease that can never be paired with UnaccessData.
        return Ok(result(
            Win16HostDdeValue::None,
            native_error(native_instance),
        ));
    }
    let length_usize = match usize::try_from(length) {
        Ok(length) => length,
        Err(_) => {
            // SAFETY: DdeUnaccessData balances one DdeAccessData.
            if unsafe { DdeUnaccessData(native_data) } != 0 {
                context.state.borrow_mut().cancel_access_slot(data);
                return Err(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "DDE AccessData length does not fit the host",
                ));
            }
            let mut state = context.state.borrow_mut();
            state.note_access(data, pointer, length)?;
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "DDE AccessData length overflowed and its native lease could not be released",
            ));
        }
    };
    let mut bytes = Vec::new();
    if let Err(error) = bytes.try_reserve_exact(length_usize) {
        // SAFETY: DdeUnaccessData balances one DdeAccessData.
        if unsafe { DdeUnaccessData(native_data) } == 0 {
            context
                .state
                .borrow_mut()
                .note_access(data, pointer, length)?;
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "allocate DDE AccessData snapshot and release its native lease",
                error,
            ));
        }
        context.state.borrow_mut().cancel_access_slot(data);
        return Err(RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate DDE AccessData snapshot",
            error,
        ));
    }
    // SAFETY: DdeAccessData returned a pointer to `length` bytes and the data
    // object remains locked until the matching DdeUnaccessData operation.
    let source = unsafe { std::slice::from_raw_parts(pointer, length_usize) };
    bytes.extend_from_slice(source);
    if let Err(error) = context
        .state
        .borrow_mut()
        .note_access(data, pointer, length)
    {
        // SAFETY: DdeUnaccessData balances one DdeAccessData.
        if unsafe { DdeUnaccessData(native_data) } == 0 {
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "record DDE AccessData lease and release native lease",
                error,
            ));
        }
        context.state.borrow_mut().cancel_access_slot(data);
        return Err(error);
    }
    Ok(result(Win16HostDdeValue::AccessData { bytes, writable }, 0))
}

pub(super) fn unaccess_data(
    context: &WorkerContext,
    data: Win16HostDdeData,
    copyback: Option<Vec<u8>>,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_data, native_instance, access_lease, writable) = {
        let state = context.state.borrow();
        let record = state.data.get(&data).ok_or_else(|| {
            protocol_error("DDE UnaccessData references an unknown host data token")
        })?;
        (
            state.native_data_for_unaccess(data)?,
            state.native_instance(record.instance)?,
            state.latest_access_lease(data)?,
            record.available
                && matches!(record.origin, DataOrigin::Created { .. })
                && !record.transferred,
        )
    };
    if context.state.borrow().access_count(data) == 0 {
        return Err(protocol_error(
            "DDE UnaccessData has no matching AccessData lease",
        ));
    }
    let invalid_copyback = copyback.as_ref().is_some_and(|bytes| {
        writable && usize::try_from(access_lease.byte_length).ok() != Some(bytes.len())
    });
    if let Some(bytes) = copyback.as_ref().filter(|_| writable && !invalid_copyback) {
        // SAFETY: this pointer is the exact live AccessData lease associated
        // with the guest snapshot. `invalid_copyback` proves equal lengths.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), access_lease.pointer, bytes.len());
        }
    }
    // SAFETY: DdeUnaccessData balances one DdeAccessData.
    let succeeded = unsafe { DdeUnaccessData(native_data) } != 0;
    let error = if succeeded {
        0
    } else {
        native_error(native_instance)
    };
    if succeeded {
        let mut state = context.state.borrow_mut();
        state.note_unaccess(data)?;
        state.collect_consumed_data(data)?;
    }
    if succeeded && invalid_copyback {
        return Err(protocol_error("DDE AccessData copyback length changed"));
    }
    Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
}

pub(super) fn free_data(
    context: &WorkerContext,
    data: Win16HostDdeData,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_data, native_instance, freeable) = {
        let state = context.state.borrow();
        let record = state
            .data
            .get(&data)
            .ok_or_else(|| protocol_error("DDE FreeData references an unknown host data token"))?;
        (
            record.native,
            state.native_instance(record.instance)?,
            state.data_freeable(data)?,
        )
    };
    if !freeable {
        return Ok(result(
            Win16HostDdeValue::Boolean(false),
            compat_services::win16_dde::error::INVALIDPARAMETER,
        ));
    }
    // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
    let succeeded = unsafe { DdeFreeDataHandle(native_data) } != 0;
    let error = if succeeded {
        0
    } else {
        native_error(native_instance)
    };
    if succeeded {
        context
            .state
            .borrow_mut()
            .note_guest_free_retirement(data)?;
    }
    Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
}

use std::collections::HashMap;
use std::ptr;

use runtime::{RuntimeError, Win16HostAcmHandle as Handle, Win16HostAcmResult as ResultValue};
use windows_sys::Win32::Media::Audio::{
    ACM_STREAMOPENF_ASYNC, ACM_STREAMOPENF_QUERY, ACMSTREAMHEADER, ACMSTREAMHEADER_STATUSF_DONE,
    ACMSTREAMHEADER_STATUSF_INQUEUE, ACMSTREAMHEADER_STATUSF_PREPARED, HACMSTREAM, WAVEFILTER,
    WAVEFORMATEX, acmStreamClose, acmStreamConvert, acmStreamOpen, acmStreamPrepareHeader,
    acmStreamReset, acmStreamSize, acmStreamUnprepareHeader,
};
use windows_sys::Win32::Media::{
    MMSYSERR_ALLOCATED, MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM, MMSYSERR_NOERROR,
    MMSYSERR_NOTSUPPORTED,
};

use super::format::normalize_wfx;
use super::{NativeObject, Win16AcmHost};

const INVALHANDLE: u32 = MMSYSERR_INVALHANDLE;
const INVALPARAM: u32 = MMSYSERR_INVALPARAM;

const FILTER_BYTES: usize = 32;
const GUEST_RESERVED_DWORDS: usize = 10;

pub(super) struct NativeStream {
    raw: usize,
    headers: HashMap<u64, NativeHeader>,
}

struct NativeHeader {
    native: Vec<ACMSTREAMHEADER>,
    source: Vec<u8>,
    destination: Vec<u8>,
}

impl NativeStream {
    pub(super) fn native(&self) -> HACMSTREAM {
        self.raw as HACMSTREAM
    }
}

impl NativeHeader {
    fn new(
        status: u32,
        user: u32,
        source_user: u32,
        destination_user: u32,
        source: Vec<u8>,
        destination: Vec<u8>,
    ) -> Result<Option<Self>, RuntimeError> {
        let Ok(source_len) = u32::try_from(source.len()) else {
            return Ok(None);
        };
        let Ok(destination_len) = u32::try_from(destination.len()) else {
            return Ok(None);
        };
        // Vec provides aligned stable storage while avoiding infallible Box
        // allocation after guest-owned buffers have crossed this boundary.
        let mut native = Vec::new();
        native.try_reserve_exact(1).map_err(|error| {
            RuntimeError::with_source(
                runtime::DiagnosticKind::ResourceExhausted,
                "reserve native ACM header storage",
                error,
            )
        })?;
        native.push(ACMSTREAMHEADER::default());
        let header = native.as_mut_ptr();
        let struct_size = std::mem::size_of::<ACMSTREAMHEADER>() as u32;
        let transient = (ACMSTREAMHEADER_STATUSF_DONE
            | ACMSTREAMHEADER_STATUSF_INQUEUE
            | ACMSTREAMHEADER_STATUSF_PREPARED) as u32;
        let stored_status = status & !transient;
        let user_value = user as usize;
        let source_user_value = source_user as usize;
        let destination_user_value = destination_user as usize;
        let source_bytes = if source.is_empty() {
            ptr::null_mut()
        } else {
            source.as_ptr().cast_mut()
        };
        let destination_bytes = if destination.is_empty() {
            ptr::null_mut()
        } else {
            destination.as_ptr().cast_mut()
        };
        // SAFETY: `(*header).cbStruct` is the packed `cbStruct` field of this
        // caller-owned `ACMSTREAMHEADER` in `native`. The record stays live for
        // the write and is a host address, not a guest address. `addr_of_mut`
        // plus `write_unaligned` stores the structure size without a misaligned
        // reference.
        unsafe { ptr::addr_of_mut!((*header).cbStruct).write_unaligned(struct_size) };
        // SAFETY: `(*header).fdwStatus` is the packed `fdwStatus` field of this
        // caller-owned `ACMSTREAMHEADER` in `native`. The record stays live for
        // the write and is a host address, not a guest address. `addr_of_mut`
        // plus `write_unaligned` stores `stored_status` without a misaligned
        // reference.
        unsafe { ptr::addr_of_mut!((*header).fdwStatus).write_unaligned(stored_status) };
        // SAFETY: `(*header).dwUser` is the packed `dwUser` field of this
        // caller-owned `ACMSTREAMHEADER` in `native`. The record stays live for
        // the write and is a host address, not a guest address. `addr_of_mut`
        // plus `write_unaligned` stores `user_value` without a misaligned
        // reference.
        unsafe { ptr::addr_of_mut!((*header).dwUser).write_unaligned(user_value) };
        // SAFETY: `(*header).pbSrc` is the packed `pbSrc` field of this
        // caller-owned `ACMSTREAMHEADER` in `native`. The record stays live for
        // the write and is a host address, not a guest address. `source_bytes`
        // is null or the owned source buffer, which stays allocated in this
        // owner. `addr_of_mut` plus `write_unaligned` stores that pointer
        // without a misaligned reference.
        unsafe { ptr::addr_of_mut!((*header).pbSrc).write_unaligned(source_bytes) };
        // SAFETY: `(*header).cbSrcLength` is the packed `cbSrcLength` field of
        // this caller-owned `ACMSTREAMHEADER` in `native`. The record stays live
        // for the write and is a host address, not a guest address. `addr_of_mut`
        // plus `write_unaligned` stores `source_len` without a misaligned
        // reference.
        unsafe { ptr::addr_of_mut!((*header).cbSrcLength).write_unaligned(source_len) };
        // SAFETY: `(*header).cbSrcLengthUsed` is the packed `cbSrcLengthUsed`
        // field of this caller-owned `ACMSTREAMHEADER` in `native`. The record
        // stays live for the write and is a host address, not a guest address.
        // `addr_of_mut` plus `write_unaligned` stores zero without a misaligned
        // reference.
        unsafe { ptr::addr_of_mut!((*header).cbSrcLengthUsed).write_unaligned(0) };
        // SAFETY: `(*header).dwSrcUser` is the packed `dwSrcUser` field of this
        // caller-owned `ACMSTREAMHEADER` in `native`. The record stays live for
        // the write and is a host address, not a guest address. `addr_of_mut`
        // plus `write_unaligned` stores `source_user_value` without a misaligned
        // reference.
        unsafe { ptr::addr_of_mut!((*header).dwSrcUser).write_unaligned(source_user_value) };
        // SAFETY: `(*header).pbDst` is the packed `pbDst` field of this
        // caller-owned `ACMSTREAMHEADER` in `native`. The record stays live for
        // the write and is a host address, not a guest address. `destination_bytes`
        // is null or the owned destination buffer, which stays allocated in this
        // owner. `addr_of_mut` plus `write_unaligned` stores that pointer without
        // a misaligned reference.
        unsafe { ptr::addr_of_mut!((*header).pbDst).write_unaligned(destination_bytes) };
        // SAFETY: `(*header).cbDstLength` is the packed `cbDstLength` field of
        // this caller-owned `ACMSTREAMHEADER` in `native`. The record stays live
        // for the write and is a host address, not a guest address. `addr_of_mut`
        // plus `write_unaligned` stores `destination_len` without a misaligned
        // reference.
        unsafe { ptr::addr_of_mut!((*header).cbDstLength).write_unaligned(destination_len) };
        // SAFETY: `(*header).cbDstLengthUsed` is the packed `cbDstLengthUsed`
        // field of this caller-owned `ACMSTREAMHEADER` in `native`. The record
        // stays live for the write and is a host address, not a guest address.
        // `addr_of_mut` plus `write_unaligned` stores zero without a misaligned
        // reference.
        unsafe { ptr::addr_of_mut!((*header).cbDstLengthUsed).write_unaligned(0) };
        // SAFETY: `(*header).dwDstUser` is the packed `dwDstUser` field of this
        // caller-owned `ACMSTREAMHEADER` in `native`. The record stays live for
        // the write and is a host address, not a guest address. `addr_of_mut`
        // plus `write_unaligned` stores `destination_user_value` without a
        // misaligned reference.
        unsafe { ptr::addr_of_mut!((*header).dwDstUser).write_unaligned(destination_user_value) };
        // Reserved driver state belongs to this native header. In
        // particular, never import guest DWORDs as native codec state or
        // return native values that could encode host pointers.
        Ok(Some(Self {
            native,
            source,
            destination,
        }))
    }

    fn pointer(&mut self) -> *mut ACMSTREAMHEADER {
        self.native.as_mut_ptr()
    }

    fn reserve_result_buffer(&self, bytes: usize) -> Result<Vec<u8>, RuntimeError> {
        let mut destination = Vec::new();
        destination.try_reserve_exact(bytes).map_err(|error| {
            RuntimeError::with_source(
                runtime::DiagnosticKind::ResourceExhausted,
                "reserve ACM stream-header reply before native operation",
                error,
            )
        })?;
        Ok(destination)
    }

    fn result(
        &self,
        result: u32,
        mut destination: Vec<u8>,
        bytes: usize,
        header_retired: bool,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(output) = self.destination.get(..bytes) else {
            return Err(RuntimeError::new(
                runtime::DiagnosticKind::InternalInvariant,
                "ACM stream reply exceeds the retained native destination buffer",
            ));
        };
        // Every caller reserved this reply buffer before entering native ACM.
        let header = self.native.as_ptr();
        // SAFETY: `(*header).fdwStatus` is the packed `fdwStatus` field of this
        // caller-owned `ACMSTREAMHEADER` in `self.native`. The record stays live
        // for the read and is a host address, not a guest address. `addr_of`
        // plus `read_unaligned` copies the `u32` and does not retain the pointer.
        let status = unsafe { ptr::addr_of!((*header).fdwStatus).read_unaligned() };
        // SAFETY: `(*header).cbSrcLengthUsed` is the packed `cbSrcLengthUsed`
        // field of this caller-owned `ACMSTREAMHEADER` in `self.native`. The
        // record stays live for the read and is a host address, not a guest
        // address. `addr_of` plus `read_unaligned` copies the `u32` and does not
        // retain the pointer.
        let source_used = unsafe { ptr::addr_of!((*header).cbSrcLengthUsed).read_unaligned() };
        // SAFETY: `(*header).cbDstLengthUsed` is the packed `cbDstLengthUsed`
        // field of this caller-owned `ACMSTREAMHEADER` in `self.native`. The
        // record stays live for the read and is a host address, not a guest
        // address. `addr_of` plus `read_unaligned` copies the `u32` and does not
        // retain the pointer.
        let destination_used = unsafe { ptr::addr_of!((*header).cbDstLengthUsed).read_unaligned() };
        destination.extend_from_slice(output);
        Ok(ResultValue::StreamHeader {
            result,
            status,
            header_retired,
            source_used,
            destination_used,
            destination,
            reserved: [0; GUEST_RESERVED_DWORDS],
        })
    }
}

pub(super) fn open(
    host: &mut Win16AcmHost,
    driver: Option<Handle>,
    source: Vec<u8>,
    destination: Vec<u8>,
    filter: Option<Vec<u8>>,
    mut flags: u32,
    query_only: bool,
) -> Result<ResultValue, RuntimeError> {
    if flags & ACM_STREAMOPENF_ASYNC != 0 {
        return Ok(ResultValue::StreamOpened {
            result: MMSYSERR_NOTSUPPORTED,
            stream: None,
        });
    }
    let native_driver = match driver {
        None => ptr::null_mut(),
        Some(handle) => match host.driver(handle) {
            Some(native) => native,
            None => {
                return Ok(ResultValue::StreamOpened {
                    result: MMSYSERR_INVALHANDLE,
                    stream: None,
                });
            }
        },
    };
    let Some(mut source) = normalize_wfx(source)? else {
        return Ok(ResultValue::StreamOpened {
            result: MMSYSERR_INVALPARAM,
            stream: None,
        });
    };
    let Some(mut destination) = normalize_wfx(destination)? else {
        return Ok(ResultValue::StreamOpened {
            result: MMSYSERR_INVALPARAM,
            stream: None,
        });
    };
    let mut filter = filter;
    if let Some(data) = filter.as_ref() {
        if data.len() < FILTER_BYTES || data.len() > u32::MAX as usize {
            return Ok(ResultValue::StreamOpened {
                result: MMSYSERR_INVALPARAM,
                stream: None,
            });
        }
        let declared = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        if declared > data.len() || declared < FILTER_BYTES {
            return Ok(ResultValue::StreamOpened {
                result: MMSYSERR_INVALPARAM,
                stream: None,
            });
        }
    }
    let query = query_only || flags & ACM_STREAMOPENF_QUERY != 0;
    if query {
        flags |= ACM_STREAMOPENF_QUERY;
    }
    let reserved_handle = if query {
        None
    } else {
        Some(host.reserve_identity()?)
    };
    let mut native: HACMSTREAM = ptr::null_mut();
    let output_stream = if query { ptr::null_mut() } else { &mut native };
    let filter_ptr = filter.as_mut().map_or(ptr::null_mut(), |bytes| {
        bytes.as_mut_ptr().cast::<WAVEFILTER>()
    });
    let source_format = source.as_mut_ptr().cast::<WAVEFORMATEX>();
    let destination_format = destination.as_mut_ptr().cast::<WAVEFORMATEX>();
    // SAFETY: `output_stream` is null for a query or addresses `native`, which
    // stays live for this call. `native_driver` is null or a host `HACMDRIVER`.
    // `source_format`, `destination_format`, and `filter_ptr` are null or point
    // at caller-owned bytes that stay live. `acmStreamOpen` returns an
    // `MMRESULT` and retains no pointer. No pointer is a guest address.
    let result = unsafe {
        acmStreamOpen(
            output_stream,
            native_driver,
            source_format,
            destination_format,
            filter_ptr,
            0,
            0,
            flags,
        )
    };
    if result != MMSYSERR_NOERROR {
        return Ok(ResultValue::StreamOpened {
            result,
            stream: None,
        });
    }
    if query {
        return Ok(ResultValue::StreamOpened {
            result,
            stream: None,
        });
    }
    if native.is_null() {
        return Ok(ResultValue::StreamOpened {
            result: INVALHANDLE,
            stream: None,
        });
    }
    let handle = reserved_handle.ok_or_else(|| {
        RuntimeError::new(
            runtime::DiagnosticKind::InternalInvariant,
            "non-query ACM stream has no reserved native identity",
        )
    })?;
    host.store_reserved(
        handle,
        NativeObject::Stream(NativeStream {
            raw: native as usize,
            headers: HashMap::new(),
        }),
    )?;
    Ok(ResultValue::StreamOpened {
        result,
        stream: Some(handle),
    })
}

pub(super) fn close(
    host: &mut Win16AcmHost,
    handle: Handle,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(native) = host.stream_mut(handle) else {
        return Ok(ResultValue::Scalar(INVALHANDLE));
    };
    if !native.headers.is_empty() {
        // ACMSTREAMHEADER storage is owned by this table. A stream close is
        // not an unprepare receipt, so keep the stream and every header owner
        // until the actual unprepare calls retire them.
        return Ok(ResultValue::Scalar(MMSYSERR_ALLOCATED));
    }
    let native_stream = native.native();
    // SAFETY: `native_stream` is an `HACMSTREAM` owned by the host table. Its
    // prepared-header table was empty above, so this close does not release
    // header storage. `acmStreamClose` returns an `MMRESULT` and retains no
    // pointer. The handle is a host value, not a guest address.
    let result = unsafe { acmStreamClose(native_stream, flags) };
    if result == MMSYSERR_NOERROR {
        host.remove(handle);
    }
    Ok(ResultValue::Scalar(result))
}

pub(super) fn size(
    host: &Win16AcmHost,
    handle: Handle,
    input_bytes: u32,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(native) = host.stream(handle) else {
        return Ok(ResultValue::StreamSize {
            result: INVALHANDLE,
            output_bytes: 0,
        });
    };
    let mut output_bytes = 0u32;
    // SAFETY: `native` is a live host `HACMSTREAM`. `output_bytes` is a local
    // `u32` that stays live for this call. `acmStreamSize` writes that `u32`
    // and returns an `MMRESULT`. No pointer is a guest address.
    let result = unsafe { acmStreamSize(native, input_bytes, &mut output_bytes, flags) };
    Ok(ResultValue::StreamSize {
        result,
        output_bytes,
    })
}

pub(super) fn prepare(
    host: &mut Win16AcmHost,
    handle: Handle,
    header_token: u64,
    flags: u32,
    status: u32,
    user: u32,
    source_user: u32,
    destination_user: u32,
    source: Vec<u8>,
    destination: Vec<u8>,
    _reserved: [u32; GUEST_RESERVED_DWORDS],
) -> Result<ResultValue, RuntimeError> {
    let Some(header) = NativeHeader::new(
        status,
        user,
        source_user,
        destination_user,
        source,
        destination,
    )?
    else {
        return Ok(ResultValue::StreamHeader {
            result: INVALPARAM,
            status,
            header_retired: false,
            source_used: 0,
            destination_used: 0,
            destination: Vec::new(),
            reserved: [0; 10],
        });
    };
    let Some(stream) = host.stream_mut(handle) else {
        return Ok(ResultValue::StreamHeader {
            result: INVALHANDLE,
            status,
            header_retired: false,
            source_used: 0,
            destination_used: 0,
            destination: Vec::new(),
            reserved: [0; 10],
        });
    };
    if stream.headers.contains_key(&header_token) {
        let destination = header.reserve_result_buffer(header.destination.len())?;
        return header.result(INVALPARAM, destination, header.destination.len(), false);
    }
    stream.headers.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            runtime::DiagnosticKind::ResourceExhausted,
            "reserve native ACM prepared-header owner before prepare",
            error,
        )
    })?;
    let reply_bytes = header.destination.len();
    let reply_destination = header.reserve_result_buffer(reply_bytes)?;
    stream.headers.insert(header_token, header);
    let native_stream = stream.native();
    let header = stream.headers.get_mut(&header_token).ok_or_else(|| {
        RuntimeError::new(
            runtime::DiagnosticKind::InternalInvariant,
            "native ACM prepared-header owner disappeared before prepare",
        )
    })?;
    let native_header = header.pointer();
    // SAFETY: `native_stream` is a live host `HACMSTREAM`. `native_header`
    // points at the `ACMSTREAMHEADER` retained in the handle table with its
    // source and destination buffers. Those stay live while
    // `acmStreamPrepareHeader` marks the header prepared. The call returns an
    // `MMRESULT` and retains no pointer. No pointer is a guest address.
    let result = unsafe { acmStreamPrepareHeader(native_stream, native_header, flags) };
    // SAFETY: `(*native_header).fdwStatus` is the packed `fdwStatus` field of
    // the caller-owned `ACMSTREAMHEADER` at `native_header`. The record stays
    // live for the read and is a host address, not a guest address. `addr_of`
    // plus `read_unaligned` copies the `u32` and does not retain the pointer.
    let status = unsafe { ptr::addr_of!((*native_header).fdwStatus).read_unaligned() };
    let prepared = status & (ACMSTREAMHEADER_STATUSF_PREPARED as u32) != 0;
    let reply = header.result(result, reply_destination, reply_bytes, false)?;
    if result != MMSYSERR_NOERROR && !prepared {
        stream.headers.remove(&header_token);
    }
    Ok(reply)
}

pub(super) fn unprepare(
    host: &mut Win16AcmHost,
    handle: Handle,
    header_token: u64,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(stream) = host.stream_mut(handle) else {
        return Ok(ResultValue::StreamHeader {
            result: INVALHANDLE,
            status: 0,
            header_retired: false,
            source_used: 0,
            destination_used: 0,
            destination: Vec::new(),
            reserved: [0; 10],
        });
    };
    let native_stream = stream.native();
    let Some(header) = stream.headers.get_mut(&header_token) else {
        return Ok(ResultValue::StreamHeader {
            result: INVALPARAM,
            status: 0,
            header_retired: false,
            source_used: 0,
            destination_used: 0,
            destination: Vec::new(),
            reserved: [0; 10],
        });
    };
    let reply_bytes = header.destination.len();
    let reply_destination = header.reserve_result_buffer(reply_bytes)?;
    let source_capacity = u32::try_from(header.source.len()).map_err(|error| {
        RuntimeError::with_source(
            runtime::DiagnosticKind::InternalInvariant,
            "retained ACM source capacity no longer fits the native header",
            error,
        )
    })?;
    let destination_capacity = u32::try_from(header.destination.len()).map_err(|error| {
        RuntimeError::with_source(
            runtime::DiagnosticKind::InternalInvariant,
            "retained ACM destination capacity no longer fits the native header",
            error,
        )
    })?;
    let native_header = header.pointer();
    // ACM requires the original prepared capacities when unpreparing. Convert
    // may have shortened these retained native lengths for a single call.
    // SAFETY: `(*native_header).cbSrcLength` is the packed `cbSrcLength` field
    // of the caller-owned `ACMSTREAMHEADER` at `native_header`. The record stays
    // live for the write and is a host address, not a guest address.
    // `addr_of_mut` plus `write_unaligned` stores `source_capacity` without a
    // misaligned reference.
    unsafe { ptr::addr_of_mut!((*native_header).cbSrcLength).write_unaligned(source_capacity) };
    // SAFETY: `(*native_header).cbDstLength` is the packed `cbDstLength` field
    // of the caller-owned `ACMSTREAMHEADER` at `native_header`. The record stays
    // live for the write and is a host address, not a guest address.
    // `addr_of_mut` plus `write_unaligned` stores `destination_capacity` without
    // a misaligned reference.
    unsafe {
        ptr::addr_of_mut!((*native_header).cbDstLength).write_unaligned(destination_capacity)
    };
    // SAFETY: `native_stream` is a live host `HACMSTREAM`. `native_header`
    // points at the prepared `ACMSTREAMHEADER` retained in the host table.
    // That record and its buffers stay live for this call.
    // `acmStreamUnprepareHeader` returns an `MMRESULT` and retains no pointer.
    // No pointer is a guest address.
    let result = unsafe { acmStreamUnprepareHeader(native_stream, native_header, flags) };
    // SAFETY: `(*native_header).fdwStatus` is the packed `fdwStatus` field of
    // the caller-owned `ACMSTREAMHEADER` at `native_header`. The record stays
    // live for the read and is a host address, not a guest address. `addr_of`
    // plus `read_unaligned` copies the `u32` and does not retain the pointer.
    let status = unsafe { ptr::addr_of!((*native_header).fdwStatus).read_unaligned() };
    // Microsoft permits selected unprepare failures to clear PREPARED. This
    // flag is a retirement receipt only because this exact retained header
    // was passed to the native call above and its native status was read back.
    let unprepared = status & ACMSTREAMHEADER_STATUSF_PREPARED as u32 == 0;
    let reply = header.result(result, reply_destination, reply_bytes, unprepared)?;
    if unprepared {
        stream.headers.remove(&header_token);
    }
    Ok(reply)
}

pub(super) fn convert(
    host: &mut Win16AcmHost,
    handle: Handle,
    header_token: u64,
    source: Vec<u8>,
    destination: Vec<u8>,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(stream) = host.stream_mut(handle) else {
        return Ok(ResultValue::StreamHeader {
            result: INVALHANDLE,
            status: 0,
            header_retired: false,
            source_used: 0,
            destination_used: 0,
            destination: Vec::new(),
            reserved: [0; 10],
        });
    };
    let native_stream = stream.native();
    let Some(header) = stream.headers.get_mut(&header_token) else {
        return Ok(ResultValue::StreamHeader {
            result: INVALPARAM,
            status: 0,
            header_retired: false,
            source_used: 0,
            destination_used: 0,
            destination: Vec::new(),
            reserved: [0; 10],
        });
    };
    if source.len() > header.source.len() || destination.len() > header.destination.len() {
        return Ok(ResultValue::StreamHeader {
            result: INVALPARAM,
            status: ACMSTREAMHEADER_STATUSF_PREPARED as u32,
            header_retired: false,
            source_used: 0,
            destination_used: 0,
            destination: Vec::new(),
            reserved: [0; GUEST_RESERVED_DWORDS],
        });
    }
    let reply_destination = header.reserve_result_buffer(destination.len())?;
    header.source[..source.len()].copy_from_slice(&source);
    header.destination[..destination.len()].copy_from_slice(&destination);
    let native_header = header.pointer();
    // Used counts and completion flags describe one conversion call. Clear
    // their prior values while retaining PREPARED and other driver state.
    let source_bytes = source.len() as u32;
    let destination_bytes = destination.len() as u32;
    let completed = (ACMSTREAMHEADER_STATUSF_DONE | ACMSTREAMHEADER_STATUSF_INQUEUE) as u32;
    // SAFETY: `(*native_header).cbSrcLengthUsed` is the packed
    // `cbSrcLengthUsed` field of the caller-owned `ACMSTREAMHEADER` at
    // `native_header`. The record stays live for the write and is a host
    // address, not a guest address. `addr_of_mut` plus `write_unaligned` stores
    // zero without a misaligned reference.
    unsafe { ptr::addr_of_mut!((*native_header).cbSrcLengthUsed).write_unaligned(0) };
    // SAFETY: `(*native_header).cbDstLengthUsed` is the packed
    // `cbDstLengthUsed` field of the caller-owned `ACMSTREAMHEADER` at
    // `native_header`. The record stays live for the write and is a host
    // address, not a guest address. `addr_of_mut` plus `write_unaligned` stores
    // zero without a misaligned reference.
    unsafe { ptr::addr_of_mut!((*native_header).cbDstLengthUsed).write_unaligned(0) };
    // SAFETY: `(*native_header).cbSrcLength` is the packed `cbSrcLength` field
    // of the caller-owned `ACMSTREAMHEADER` at `native_header`. The record stays
    // live for the write and is a host address, not a guest address.
    // `addr_of_mut` plus `write_unaligned` stores `source_bytes` without a
    // misaligned reference.
    unsafe { ptr::addr_of_mut!((*native_header).cbSrcLength).write_unaligned(source_bytes) };
    // SAFETY: `(*native_header).cbDstLength` is the packed `cbDstLength` field
    // of the caller-owned `ACMSTREAMHEADER` at `native_header`. The record stays
    // live for the write and is a host address, not a guest address.
    // `addr_of_mut` plus `write_unaligned` stores `destination_bytes` without a
    // misaligned reference.
    unsafe { ptr::addr_of_mut!((*native_header).cbDstLength).write_unaligned(destination_bytes) };
    // SAFETY: `(*native_header).fdwStatus` is the packed `fdwStatus` field of
    // the caller-owned `ACMSTREAMHEADER` at `native_header`. The record stays
    // live for the read and is a host address, not a guest address. `addr_of`
    // plus `read_unaligned` copies the `u32` and does not retain the pointer.
    let status = unsafe { ptr::addr_of!((*native_header).fdwStatus).read_unaligned() };
    let stored_status = status & !completed;
    // SAFETY: `(*native_header).fdwStatus` is the packed `fdwStatus` field of
    // the caller-owned `ACMSTREAMHEADER` at `native_header`. The record stays
    // live for the write and is a host address, not a guest address.
    // `addr_of_mut` plus `write_unaligned` stores `stored_status` without a
    // misaligned reference.
    unsafe { ptr::addr_of_mut!((*native_header).fdwStatus).write_unaligned(stored_status) };
    // SAFETY: `native_stream` is a live host `HACMSTREAM`. `native_header`
    // points at the prepared `ACMSTREAMHEADER` whose pointers and lengths were
    // fixed when this header was prepared. The host copied fresh bytes into
    // those same owned allocations, which stay live for this call.
    // `acmStreamConvert` returns an `MMRESULT` and retains no pointer. No
    // pointer is a guest address.
    let result = unsafe { acmStreamConvert(native_stream, native_header, flags) };
    header.result(result, reply_destination, destination.len(), false)
}

pub(super) fn reset(
    host: &Win16AcmHost,
    handle: Handle,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(native) = host.stream(handle) else {
        return Ok(ResultValue::Scalar(INVALHANDLE));
    };
    // SAFETY: `native` is a live host `HACMSTREAM`. `acmStreamReset` returns an
    // `MMRESULT` and retains no pointer. The handle is a host value, not a
    // guest address.
    Ok(ResultValue::Scalar(unsafe {
        acmStreamReset(native, flags)
    }))
}

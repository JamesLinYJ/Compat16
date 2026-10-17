//! Native synchronous WinMM services and their resource ownership table.

use std::{collections::BTreeMap, ptr};

use super::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMediaIoHandle,
    Win16HostMediaIoOperation as IoOperation, Win16HostMediaIoResult as IoResult,
    Win16HostMediaOpenResult as OpenResult, Win16HostMediaTimeOperation as TimeOperation,
    Win16HostMediaTimeResult as TimeResult, Win16HostMediaTimeValue,
};
use windows_sys::Win32::Media::Multimedia::{
    HMMIO, MMCKINFO, MMIO_TOUPPER, MMIOINFO, mmioAscend, mmioClose, mmioCreateChunk, mmioDescend,
    mmioFlush, mmioOpenW, mmioRead, mmioRenameW, mmioSeek, mmioWrite,
};
use windows_sys::Win32::Media::{
    MMTIME, TIME_BYTES, TIME_MIDI, TIME_MS, TIME_SAMPLES, TIME_SMPTE, TIMECAPS, timeBeginPeriod,
    timeEndPeriod, timeGetDevCaps, timeGetSystemTime, timeGetTime,
};

const MMIO_DELETE: u32 = 0x0000_0200;
const MMIO_EXIST: u32 = 0x0000_4000;
const MMIO_PARSE: u32 = 0x0000_0100;
const MMIO_GETTEMP: u32 = 0x0002_0000;
// The SDK 3.1 header defines these mode bits; mmioOpen documentation specifies
// their BOOL/MMRESULT pseudo-HMMIO results, which must never enter the handle table.
const MMIO_NO_HANDLE_FLAGS: u32 = MMIO_DELETE | MMIO_EXIST | MMIO_PARSE | MMIO_GETTEMP;
const MMIO_OPEN_PATH_BUFFER_SIZE: usize = 128;

#[path = "win16_media_timer.rs"]
mod timer;

/// Owns native WinMM handles and successful timer-period calls independently
/// of any guest task, so a failed guest cleanup remains available to retry
/// while this owner is alive.
#[derive(Debug)]
pub(super) struct Win16MediaServicesHost {
    text_codec: GuestTextCodec,
    next_identity: u64,
    mmio_handles: BTreeMap<Win16HostMediaIoHandle, HMMIO>,
    period_references: BTreeMap<u16, u32>,
    /// Opaque runtime identities to native ids and callback tokens. Native ids
    /// can be recycled while a previous one-shot still has a queued callback.
    timers: BTreeMap<u32, timer::OwnedTimer>,
}

impl Win16MediaServicesHost {
    pub(super) fn new(text_codec: GuestTextCodec) -> Self {
        Self {
            text_codec,
            next_identity: 0,
            mmio_handles: BTreeMap::new(),
            period_references: BTreeMap::new(),
            timers: BTreeMap::new(),
        }
    }

    pub(super) fn execute_time(
        &mut self,
        operation: TimeOperation,
        callback_sender: &runtime::Win16GuestCallbackSender,
    ) -> Result<TimeResult, RuntimeError> {
        match operation {
            TimeOperation::GetSystemTime => {
                let mut native = MMTIME::default();
                // SAFETY: native is a writable MMTIME and its size matches the binding.
                let result = unsafe {
                    timeGetSystemTime(&mut native, core::mem::size_of::<MMTIME>() as u32)
                };
                let value = if result == 0 {
                    read_time_value(&native)
                } else {
                    Win16HostMediaTimeValue::Milliseconds(0)
                };
                Ok(TimeResult::SystemTime { result, value })
            }
            TimeOperation::GetDevCaps => {
                let mut caps = TIMECAPS::default();
                // SAFETY: caps is a writable TIMECAPS and its size matches the binding.
                let result =
                    unsafe { timeGetDevCaps(&mut caps, core::mem::size_of::<TIMECAPS>() as u32) };
                // SAFETY: windows-sys marks TIMECAPS packed, so read its fields unaligned.
                let (minimum_period, maximum_period) = unsafe {
                    (
                        ptr::read_unaligned(ptr::addr_of!(caps.wPeriodMin)),
                        ptr::read_unaligned(ptr::addr_of!(caps.wPeriodMax)),
                    )
                };
                Ok(TimeResult::DevCaps {
                    result,
                    minimum_period,
                    maximum_period,
                })
            }
            TimeOperation::GetTime => {
                // SAFETY: timeGetTime has no pointer parameters.
                Ok(TimeResult::Time(unsafe { timeGetTime() }))
            }
            TimeOperation::BeginPeriod { period } => {
                if self.period_references.get(&period).copied().unwrap_or(0) == u32::MAX {
                    return Err(RuntimeError::new(
                        Kind::ResourceExhausted,
                        "native timer-period ownership count is exhausted",
                    ));
                }
                // SAFETY: period is a scalar; WinMM retains no caller memory.
                let result = unsafe { timeBeginPeriod(u32::from(period)) };
                if result == 0 {
                    *self.period_references.entry(period).or_default() += 1;
                }
                Ok(TimeResult::Period(result))
            }
            TimeOperation::EndPeriod { period } => {
                // SAFETY: period is a scalar; WinMM retains no caller memory.
                let result = unsafe { timeEndPeriod(u32::from(period)) };
                if result == 0 {
                    decrement_period(&mut self.period_references, period);
                }
                Ok(TimeResult::Period(result))
            }
            TimeOperation::SetEvent {
                delay,
                resolution,
                user,
                periodic,
                callback,
                guest_timer,
            } => Ok(TimeResult::SetEvent {
                timer: timer::set_event(
                    &mut self.timers,
                    callback_sender,
                    delay,
                    resolution,
                    user,
                    periodic,
                    callback,
                    guest_timer,
                )?,
            }),
            TimeOperation::KillEvent { timer } => {
                Ok(TimeResult::Kill(timer::kill_event(&mut self.timers, timer)))
            }
        }
    }

    pub(super) fn execute_io(&mut self, operation: IoOperation) -> Result<IoResult, RuntimeError> {
        match operation {
            IoOperation::Open {
                path,
                path_buffer,
                flags,
            } => {
                let copy_path_back = path_buffer.is_some();
                let mut path_buffer = open_path_buffer(&self.text_codec, &path, path_buffer)?;
                let identity = if flags & MMIO_NO_HANDLE_FLAGS == 0 {
                    Some(self.allocate_identity()?)
                } else {
                    None
                };
                // SDK 3.1 MMIOINFO callbacks and caller buffers are not forwarded;
                // runtime only issues this path with a null native info pointer.
                // The SDK open-mode flags may write a fully qualified or temp path;
                // use a 128-WCHAR owned buffer and distinguish pseudo-HMMIO results.
                // SAFETY: path_buffer has a NUL and 128 writable WCHARs for the call.
                let native_result = unsafe {
                    mmioOpenW(path_buffer.as_mut_ptr(), ptr::null_mut::<MMIOINFO>(), flags)
                };
                let result = if flags & MMIO_GETTEMP != 0 {
                    OpenResult::Status(native_result as usize as u32)
                } else if flags & (MMIO_DELETE | MMIO_EXIST | MMIO_PARSE) != 0 {
                    OpenResult::Boolean(!native_result.is_null())
                } else if native_result.is_null() {
                    OpenResult::File(None)
                } else {
                    let identity = identity.ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "regular mmioOpen unexpectedly lacked a native identity",
                        )
                    })?;
                    self.mmio_handles.insert(identity, native_result);
                    OpenResult::File(Some(identity))
                };
                let path_buffer = if copy_path_back {
                    Some(guest_open_path_buffer(&self.text_codec, &path_buffer)?)
                } else {
                    None
                };
                Ok(IoResult::Open {
                    result,
                    path_buffer,
                })
            }
            IoOperation::Close { handle, flags } => {
                let native = self.native_handle(handle)?;
                // SAFETY: native is an HMMIO owned by this table.
                let result = unsafe { mmioClose(native, u32::from(flags)) };
                if result == 0 {
                    self.mmio_handles.remove(&handle);
                }
                Ok(IoResult::Scalar(result))
            }
            IoOperation::Read { handle, count } => {
                if count < 0 {
                    return Ok(IoResult::Transfer {
                        result: -1,
                        bytes: Vec::new(),
                    });
                }
                let native = self.native_handle(handle)?;
                let length = usize::try_from(count).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::InvalidInput,
                        "negative MMIO read length",
                        error,
                    )
                })?;
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(length).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve native MMIO read buffer",
                        error,
                    )
                })?;
                bytes.resize(length, 0);
                // SAFETY: bytes is writable for `count` bytes; HMMIO is owned here.
                let result = unsafe { mmioRead(native, bytes.as_mut_ptr().cast(), count) };
                if result > count {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "native mmioRead returned more bytes than requested",
                    ));
                }
                if result <= 0 {
                    bytes.clear();
                } else {
                    bytes.truncate(result as usize);
                }
                Ok(IoResult::Transfer { result, bytes })
            }
            IoOperation::Write { handle, data } => {
                let native = self.native_handle(handle)?;
                let count = i32::try_from(data.len()).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::InvalidInput,
                        "MMIO write exceeds signed LONG",
                        error,
                    )
                })?;
                // SAFETY: data is owned and readable for `count` bytes; HMMIO is owned here.
                let result = unsafe { mmioWrite(native, data.as_ptr(), count) };
                Ok(IoResult::Transfer {
                    result,
                    bytes: Vec::new(),
                })
            }
            IoOperation::Seek {
                handle,
                offset,
                origin,
            } => {
                let native = self.native_handle(handle)?;
                // SAFETY: native is an HMMIO owned by this table; both arguments are scalars.
                let result = unsafe { mmioSeek(native, offset, i32::from(origin)) };
                Ok(IoResult::Transfer {
                    result,
                    bytes: Vec::new(),
                })
            }
            IoOperation::Flush { handle, flags } => {
                let native = self.native_handle(handle)?;
                // SAFETY: native is an HMMIO owned by this table.
                Ok(IoResult::Scalar(unsafe {
                    mmioFlush(native, u32::from(flags))
                }))
            }
            IoOperation::StringToFourCc { text, flags } => {
                Ok(IoResult::FourCc(fourcc_from_guest_bytes(&text, flags)))
            }
            IoOperation::Descend {
                handle,
                chunk,
                parent,
                flags,
            } => {
                let native_handle = self.native_handle(handle)?;
                let mut native_chunk_info = native_chunk(chunk);
                let native_parent = parent.map(native_chunk);
                let parent_ptr = native_parent
                    .as_ref()
                    .map_or(ptr::null(), |parent| parent as *const MMCKINFO);
                // SAFETY: the local records live through the synchronous call and are aligned by value.
                let result = unsafe {
                    mmioDescend(
                        native_handle,
                        &mut native_chunk_info,
                        parent_ptr,
                        u32::from(flags),
                    )
                };
                Ok(IoResult::Chunk {
                    result,
                    chunk: host_chunk(&native_chunk_info),
                })
            }
            IoOperation::Ascend {
                handle,
                chunk,
                flags,
            } => {
                let native_handle = self.native_handle(handle)?;
                let mut native = native_chunk(chunk);
                // The SDK declares MMCKINFO as mutable; pass the returned record through.
                // SAFETY: the aligned local record lives through the synchronous call.
                let result = unsafe { mmioAscend(native_handle, &mut native, u32::from(flags)) };
                Ok(IoResult::Chunk {
                    result,
                    chunk: host_chunk(&native),
                })
            }
            IoOperation::CreateChunk {
                handle,
                chunk,
                flags,
            } => {
                let native_handle = self.native_handle(handle)?;
                let mut native = native_chunk(chunk);
                // mmioCreateChunk fills ckid, dwDataOffset, and MMIO_DIRTY in MMCKINFO.
                // SAFETY: the aligned local record lives through the synchronous call.
                let result =
                    unsafe { mmioCreateChunk(native_handle, &mut native, u32::from(flags)) };
                Ok(IoResult::Chunk {
                    result,
                    chunk: host_chunk(&native),
                })
            }
            IoOperation::Rename {
                old_path,
                new_path,
                flags,
            } => {
                let old_path = wide_z(&self.text_codec, &old_path)?;
                let new_path = wide_z(&self.text_codec, &new_path)?;
                // SDK 3.1 MMIOINFO callbacks are unsupported; the supported path passes NULL.
                // SAFETY: both owned strings remain NUL-terminated through the synchronous call.
                let result = unsafe {
                    mmioRenameW(old_path.as_ptr(), new_path.as_ptr(), ptr::null(), flags)
                };
                Ok(IoResult::Scalar(result))
            }
        }
    }

    pub(super) fn retire_all(&mut self) -> Result<(), RuntimeError> {
        let mut first_error = None;
        timer::retire_events(&mut self.timers, &mut first_error);
        let mut after = None;
        loop {
            let next = match after {
                None => self
                    .mmio_handles
                    .first_key_value()
                    .map(|(identity, handle)| (*identity, *handle)),
                Some(identity) => self
                    .mmio_handles
                    .range((
                        std::ops::Bound::Excluded(identity),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(identity, handle)| (*identity, *handle)),
            };
            let Some((identity, handle)) = next else {
                break;
            };
            after = Some(identity);
            // SAFETY: handle is retained in this owner table until close succeeds.
            let result = unsafe { mmioClose(handle, 0) };
            if result == 0 {
                self.mmio_handles.remove(&identity);
            } else {
                keep_first(
                    &mut first_error,
                    RuntimeError::new(
                        Kind::HostFailure,
                        format!("native MMIO close failed during host teardown (0x{result:08X})",),
                    ),
                );
            }
        }

        let mut after_period = None;
        loop {
            let next = match after_period {
                None => self
                    .period_references
                    .first_key_value()
                    .map(|(period, count)| (*period, *count)),
                Some(period) => self
                    .period_references
                    .range((
                        std::ops::Bound::Excluded(period),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(period, count)| (*period, *count)),
            };
            let Some((period, count)) = next else {
                break;
            };
            after_period = Some(period);
            for _ in 0..count {
                // SAFETY: period is a scalar paired with one successful BeginPeriod.
                let result = unsafe { timeEndPeriod(u32::from(period)) };
                if result == 0 {
                    decrement_period(&mut self.period_references, period);
                } else {
                    keep_first(
                        &mut first_error,
                        RuntimeError::new(
                            Kind::HostFailure,
                            format!(
                                "native EndPeriod failed during host teardown (0x{result:08X})",
                            ),
                        ),
                    );
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn allocate_identity(&mut self) -> Result<Win16HostMediaIoHandle, RuntimeError> {
        let candidate = self.next_identity.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native MMIO identity space is exhausted",
            )
        })?;
        let identity = Win16HostMediaIoHandle(candidate);
        if self.mmio_handles.contains_key(&identity) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native MMIO identity allocator reused a live token",
            ));
        }
        self.next_identity = candidate;
        Ok(identity)
    }

    fn native_handle(&self, identity: Win16HostMediaIoHandle) -> Result<HMMIO, RuntimeError> {
        self.mmio_handles.get(&identity).copied().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "runtime referenced an unowned native MMIO identity",
            )
        })
    }
}

impl Drop for Win16MediaServicesHost {
    fn drop(&mut self) {
        if let Err(error) = self.retire_all() {
            // This owner retains only opaque native handles and scalar period
            // counts, so dropping the Rust table does not close those resources.
            eprintln!(
                "runtime: warning: WinMM owner teardown could not release {} MMIO handle(s) and {} timer-period reference(s): {error}; remaining native resources stay active until process exit",
                self.mmio_handles.len(),
                self.period_references
                    .values()
                    .map(|count| u64::from(*count))
                    .sum::<u64>(),
            );
        }
    }
}

fn read_time_value(native: &MMTIME) -> Win16HostMediaTimeValue {
    // MMTIME is packed and contains a C union. Copy only the active arm into
    // owned bytes; no native field reference or pointer crosses this adapter.
    let kind = unsafe { ptr::read_unaligned(ptr::addr_of!(native.wType)) };
    unsafe {
        match kind {
            TIME_MS => Win16HostMediaTimeValue::Milliseconds(ptr::read_unaligned(ptr::addr_of!(
                native.u.ms
            ))),
            TIME_SAMPLES => Win16HostMediaTimeValue::Samples(ptr::read_unaligned(ptr::addr_of!(
                native.u.sample
            ))),
            TIME_BYTES => {
                Win16HostMediaTimeValue::Bytes(ptr::read_unaligned(ptr::addr_of!(native.u.cb)))
            }
            TIME_MIDI => Win16HostMediaTimeValue::Midi(ptr::read_unaligned(ptr::addr_of!(
                native.u.midi.songptrpos
            ))),
            TIME_SMPTE => {
                let mut value = [0_u8; 6];
                ptr::copy_nonoverlapping(
                    ptr::addr_of!(native.u.smpte).cast::<u8>(),
                    value.as_mut_ptr(),
                    value.len(),
                );
                Win16HostMediaTimeValue::Smpte(value)
            }
            time_type => {
                let mut value = [0_u8; 8];
                ptr::copy_nonoverlapping(
                    ptr::addr_of!(native.u).cast::<u8>(),
                    value.as_mut_ptr(),
                    value.len(),
                );
                Win16HostMediaTimeValue::Unknown { time_type, value }
            }
        }
    }
}

fn wide_z(codec: &GuestTextCodec, bytes: &[u8]) -> Result<Vec<u16>, RuntimeError> {
    if bytes.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 MMIO string contains an embedded NUL",
        ));
    }
    codec.to_wide_z(bytes)
}

fn open_path_buffer(
    codec: &GuestTextCodec,
    path: &[u8],
    guest_buffer: Option<Vec<u8>>,
) -> Result<Vec<u16>, RuntimeError> {
    if path.len() >= MMIO_OPEN_PATH_BUFFER_SIZE || path.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "mmioOpen path cannot fit the SDK 3.1 128-byte name buffer",
        ));
    }
    if let Some(buffer) = guest_buffer {
        if buffer.len() != MMIO_OPEN_PATH_BUFFER_SIZE
            || buffer.get(..path.len()) != Some(path)
            || buffer[path.len()] != 0
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "captured mmioOpen path buffer did not preserve its input string",
            ));
        }
    }
    let wide_path = wide_z(codec, path)?;
    if wide_path.len() > MMIO_OPEN_PATH_BUFFER_SIZE {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "mmioOpen UTF-16 path exceeds the SDK 3.1 name buffer",
        ));
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(MMIO_OPEN_PATH_BUFFER_SIZE)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve owned mmioOpen UTF-16 filename buffer",
                error,
            )
        })?;
    buffer.resize(MMIO_OPEN_PATH_BUFFER_SIZE, 0);
    buffer[..wide_path.len()].copy_from_slice(&wide_path);
    Ok(buffer)
}

fn guest_open_path_buffer(
    codec: &GuestTextCodec,
    wide_buffer: &[u16],
) -> Result<Vec<u8>, RuntimeError> {
    let text_length = wide_buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(wide_buffer.len());
    let encoded = codec.from_wide_bounded(
        &wide_buffer[..text_length],
        MMIO_OPEN_PATH_BUFFER_SIZE.saturating_sub(1),
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(MMIO_OPEN_PATH_BUFFER_SIZE)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve returned Win16 mmioOpen path buffer",
                error,
            )
        })?;
    bytes.resize(MMIO_OPEN_PATH_BUFFER_SIZE, 0);
    bytes[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    Ok(bytes)
}

fn native_chunk(info: runtime::Win16HostMmckInfo) -> MMCKINFO {
    MMCKINFO {
        ckid: info.chunk_id,
        cksize: info.chunk_size,
        fccType: info.form_type,
        dwDataOffset: info.data_offset,
        dwFlags: info.flags,
    }
}

fn host_chunk(info: &MMCKINFO) -> runtime::Win16HostMmckInfo {
    // The windows-sys structure is packed; each field is copied unaligned.
    unsafe {
        runtime::Win16HostMmckInfo {
            chunk_id: ptr::read_unaligned(ptr::addr_of!(info.ckid)),
            chunk_size: ptr::read_unaligned(ptr::addr_of!(info.cksize)),
            form_type: ptr::read_unaligned(ptr::addr_of!(info.fccType)),
            data_offset: ptr::read_unaligned(ptr::addr_of!(info.dwDataOffset)),
            flags: ptr::read_unaligned(ptr::addr_of!(info.dwFlags)),
        }
    }
}

fn decrement_period(references: &mut BTreeMap<u16, u32>, period: u16) {
    let Some(count) = references.get_mut(&period) else {
        return;
    };
    *count -= 1;
    if *count == 0 {
        references.remove(&period);
    }
}

fn fourcc_from_guest_bytes(text: &[u8], flags: u16) -> u32 {
    // A FOURCC is four bytes, not guest text. The SDK specifies copy, space
    // padding, truncation and optional uppercase; decoding through a W string
    // would change high bytes and inspect bytes outside that identifier.
    let mut code = [b' '; 4];
    for (slot, byte) in code
        .iter_mut()
        .zip(text.iter().copied().take_while(|byte| *byte != 0))
    {
        *slot = if u32::from(flags) & MMIO_TOUPPER != 0 {
            byte.to_ascii_uppercase()
        } else {
            byte
        };
    }
    u32::from_le_bytes(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fourcc_uses_only_its_four_raw_bytes() {
        assert_eq!(
            fourcc_from_guest_bytes(b"WAVE\xff", 0),
            u32::from_le_bytes(*b"WAVE")
        );
        assert_eq!(
            fourcc_from_guest_bytes(b"ab", MMIO_TOUPPER as u16),
            u32::from_le_bytes(*b"AB  ")
        );
        assert_eq!(
            fourcc_from_guest_bytes(&[0xff, 0, 0xaa], 0),
            u32::from_le_bytes([0xff, b' ', b' ', b' '])
        );
    }
}

fn keep_first(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

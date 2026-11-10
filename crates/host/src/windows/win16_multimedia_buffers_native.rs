//! Native WinMM WAVE structures, buffers, and calls.

use super::super::guest_text::GuestTextCodec;
use super::*;
use std::mem::size_of;
use windows_sys::Win32::Media::Audio::{
    HWAVEIN, HWAVEOUT, WAVE_MAPPER, WAVEFORMATEX, WAVEINCAPSW, WAVEOUTCAPSW, waveInAddBuffer,
    waveInClose, waveInGetDevCapsW, waveInGetErrorTextW, waveInGetID, waveInMessage, waveInOpen,
    waveInPrepareHeader, waveInReset, waveInStart, waveInStop, waveInUnprepareHeader,
    waveOutBreakLoop, waveOutClose, waveOutGetDevCapsW, waveOutGetErrorTextW, waveOutGetID,
    waveOutGetPitch, waveOutGetPlaybackRate, waveOutGetVolume, waveOutMessage, waveOutOpen,
    waveOutPause, waveOutPrepareHeader, waveOutReset, waveOutRestart, waveOutSetPitch,
    waveOutSetPlaybackRate, waveOutSetVolume, waveOutUnprepareHeader, waveOutWrite,
};
use windows_sys::Win32::Media::Multimedia::DRV_QUERYMAPPABLE;
use windows_sys::Win32::Media::{MMSYSERR_NOERROR, MMTIME};

pub(super) fn device_capabilities(
    direction: Win16HostWaveDirection,
    device_id: u16,
    codec: GuestTextCodec,
) -> Result<(u32, Option<Win16HostWaveCapabilities>), RuntimeError> {
    let device_id = if device_id == u16::MAX {
        WAVE_MAPPER as usize
    } else {
        usize::from(device_id)
    };
    match direction {
        Win16HostWaveDirection::Input => {
            let mut native = WAVEINCAPSW::default();
            // SAFETY: `native` is a correctly sized, writable WAVEINCAPSW;
            // all fields copied below are initialized before being read.
            let result = unsafe {
                waveInGetDevCapsW(device_id, &mut native, size_of::<WAVEINCAPSW>() as u32)
            };
            if result != MMSYSERR_NOERROR {
                return Ok((result, None));
            }
            // windows-sys packs this native SDK record to byte alignment.
            // Read fields unaligned and project each field into the distinct
            // Windows 3.1 ABI; the Win16 VERSION is only 16 bits.
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let manufacturer_id = unsafe { ptr::addr_of!(native.wMid).read_unaligned() };
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let product_id = unsafe { ptr::addr_of!(native.wPid).read_unaligned() };
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let driver_version = unsafe { ptr::addr_of!(native.vDriverVersion).read_unaligned() };
            let product_name = guest_wave_product_name(
                codec,
                // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
                unsafe { ptr::addr_of!(native.szPname).read_unaligned() },
            )?;
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let formats = unsafe { ptr::addr_of!(native.dwFormats).read_unaligned() };
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let channels = unsafe { ptr::addr_of!(native.wChannels).read_unaligned() };
            Ok((
                result,
                Some(Win16HostWaveCapabilities::Input {
                    manufacturer_id,
                    product_id,
                    driver_version,
                    product_name,
                    formats,
                    channels,
                }),
            ))
        }
        Win16HostWaveDirection::Output => {
            let mut native = WAVEOUTCAPSW::default();
            // SAFETY: `native` is a correctly sized, writable WAVEOUTCAPSW;
            // all fields copied below are initialized before being read.
            let result = unsafe {
                waveOutGetDevCapsW(device_id, &mut native, size_of::<WAVEOUTCAPSW>() as u32)
            };
            if result != MMSYSERR_NOERROR {
                return Ok((result, None));
            }
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let manufacturer_id = unsafe { ptr::addr_of!(native.wMid).read_unaligned() };
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let product_id = unsafe { ptr::addr_of!(native.wPid).read_unaligned() };
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let driver_version = unsafe { ptr::addr_of!(native.vDriverVersion).read_unaligned() };
            let product_name = guest_wave_product_name(
                codec,
                // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
                unsafe { ptr::addr_of!(native.szPname).read_unaligned() },
            )?;
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let formats = unsafe { ptr::addr_of!(native.dwFormats).read_unaligned() };
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let channels = unsafe { ptr::addr_of!(native.wChannels).read_unaligned() };
            // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
            let support = unsafe { ptr::addr_of!(native.dwSupport).read_unaligned() };
            Ok((
                result,
                Some(Win16HostWaveCapabilities::Output {
                    manufacturer_id,
                    product_id,
                    driver_version,
                    product_name,
                    formats,
                    channels,
                    support,
                }),
            ))
        }
    }
}

fn guest_wave_product_name<const N: usize>(
    codec: GuestTextCodec,
    name: [u16; N],
) -> Result<[u8; N], RuntimeError> {
    let length = name.iter().position(|unit| *unit == 0).unwrap_or(N);
    let encoded = codec.from_wide_bounded(&name[..length], N.saturating_sub(1))?;
    let mut bytes = [0; N];
    bytes[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    Ok(bytes)
}

pub(super) fn error_text(
    direction: Win16HostWaveDirection,
    error: u16,
    capacity: u16,
    codec: GuestTextCodec,
) -> Result<(u32, Option<Vec<u8>>), RuntimeError> {
    let capacity = usize::from(capacity);
    let mut wide = Vec::new();
    wide.try_reserve_exact(capacity).map_err(|source| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve native WinMM error-text buffer",
            source,
        )
    })?;
    wide.resize(capacity, 0);
    let pointer = if wide.is_empty() {
        ptr::null_mut()
    } else {
        wide.as_mut_ptr()
    };
    let text_capacity = capacity as u32;
    let result = match direction {
        Win16HostWaveDirection::Input => {
            // SAFETY: `pointer` is null only when `capacity` is zero. Otherwise
            // it addresses `capacity` writable UTF-16 units in the owned `wide`
            // buffer, and that buffer stays live for this call.
            // waveInGetErrorTextW writes those units and returns an MMRESULT.
            // The pointer is a host address, not a guest address.
            unsafe { waveInGetErrorTextW(u32::from(error), pointer, text_capacity) }
        }
        Win16HostWaveDirection::Output => {
            // SAFETY: `pointer` is null only when `capacity` is zero. Otherwise
            // it addresses `capacity` writable UTF-16 units in the owned `wide`
            // buffer, and that buffer stays live for this call.
            // waveOutGetErrorTextW writes those units and returns an MMRESULT.
            // The pointer is a host address, not a guest address.
            unsafe { waveOutGetErrorTextW(u32::from(error), pointer, text_capacity) }
        }
    };
    if result != MMSYSERR_NOERROR {
        return Ok((result, None));
    }
    let mut bytes = Vec::new();
    if capacity != 0 {
        let text_length = wide
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(wide.len());
        let encoded = codec.from_wide_bounded(&wide[..text_length], capacity - 1)?;
        bytes.try_reserve_exact(capacity).map_err(|source| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve guest WinMM error-text buffer",
                source,
            )
        })?;
        bytes.resize(capacity, 0);
        bytes[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    }
    let bytes = Some(bytes);
    Ok((result, bytes))
}

// SAFETY: `device` must be a live WinMM handle owned by the caller for this
// synchronous call. A direction that does not match the handle variant returns
// `MMSYSERR_INVALHANDLE` and performs no native call. The handle is a host
// value, not a guest address.
pub(super) unsafe fn get_device_id(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
) -> (u32, Option<u32>) {
    let mut device_id = 0_u32;
    let result = match (direction, device) {
        (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
            let id = ptr::addr_of_mut!(device_id);
            // SAFETY: `*handle` is the caller's live HWAVEIN, and `id` points
            // at the local `device_id` DWORD, which stays live. windows-sys
            // marks that output const, but waveInGetID writes one identifier
            // there and retains no pointer. The handle and `id` are host
            // values, not guest addresses.
            unsafe { waveInGetID(*handle, id.cast_const()) }
        }
        (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
            let id = ptr::addr_of_mut!(device_id);
            // SAFETY: `*handle` is the caller's live HWAVEOUT, and `id` points
            // at the local `device_id` DWORD, which stays live. waveOutGetID
            // writes one identifier there and retains no pointer. The handle
            // and `id` are host values, not guest addresses.
            unsafe { waveOutGetID(*handle, id) }
        }
        _ => return (MMSYSERR_INVALHANDLE, None),
    };
    (result, (result == MMSYSERR_NOERROR).then_some(device_id))
}

// SAFETY: `device` must be a live output WinMM handle owned by the caller for
// this synchronous call. Any other direction, handle variant, or parameter
// returns `MMSYSERR_INVALHANDLE` and performs no native call. The handle is a
// host value, not a guest address.
pub(super) unsafe fn get_parameter(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    parameter: Win16HostWaveParameter,
) -> (u32, Option<u32>) {
    let mut value = 0_u32;
    let result = match (direction, device, parameter) {
        (
            Win16HostWaveDirection::Output,
            NativeWaveHandle::Output(handle),
            Win16HostWaveParameter::Pitch,
        ) => {
            let output = ptr::addr_of_mut!(value);
            // SAFETY: `*handle` is the caller's live HWAVEOUT, and `output`
            // points at the local `value` DWORD, which stays live.
            // waveOutGetPitch writes that DWORD and retains no pointer. The
            // handle and `output` are host values, not guest addresses.
            unsafe { waveOutGetPitch(*handle, output) }
        }
        (
            Win16HostWaveDirection::Output,
            NativeWaveHandle::Output(handle),
            Win16HostWaveParameter::PlaybackRate,
        ) => {
            let output = ptr::addr_of_mut!(value);
            // SAFETY: `*handle` is the caller's live HWAVEOUT, and `output`
            // points at the local `value` DWORD, which stays live.
            // waveOutGetPlaybackRate writes that DWORD and retains no pointer.
            // The handle and `output` are host values, not guest addresses.
            unsafe { waveOutGetPlaybackRate(*handle, output) }
        }
        _ => return (MMSYSERR_INVALHANDLE, None),
    };
    (result, (result == MMSYSERR_NOERROR).then_some(value))
}

/// Windows 3.1 SDK MMSYSTEM.H declares the volume parameter as `UINT uDeviceID`
/// (lines 456–457); modern WinMM documents that `waveOutGet/SetVolume` accepts
/// either an open HWAVEOUT or a device identifier in its handle-shaped slot.
/// This dedicated path converts only that scalar identity; it never treats a
/// guest FAR or guest handle as a native pointer.
pub(super) fn get_volume_by_id(device_id: u16) -> (u32, Option<u32>) {
    let mut value = 0_u32;
    let native_id = if device_id == u16::MAX {
        WAVE_MAPPER as usize
    } else {
        usize::from(device_id)
    } as HWAVEOUT;
    // SAFETY: WinMM accepts a device identifier in `hwo`, and `value` is a
    // local writable DWORD. The mapper sentinel is the SDK binding constant.
    let result = unsafe { waveOutGetVolume(native_id, ptr::addr_of_mut!(value)) };
    (result, (result == MMSYSERR_NOERROR).then_some(value))
}

pub(super) fn set_volume_by_id(device_id: u16, value: u32) -> u32 {
    let native_id = if device_id == u16::MAX {
        WAVE_MAPPER as usize
    } else {
        usize::from(device_id)
    } as HWAVEOUT;
    // SAFETY: WinMM accepts a device identifier in `hwo`; this is not an
    // opened-handle lookup or a pointer dereference.
    unsafe { waveOutSetVolume(native_id, value) }
}

// SAFETY: `device` must be a live output WinMM handle owned by the caller for
// this synchronous call. Any other direction, handle variant, or parameter
// returns `MMSYSERR_INVALHANDLE` and performs no native call. `value` is a
// scalar. The handle is a host value, not a guest address.
pub(super) unsafe fn set_parameter(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    parameter: Win16HostWaveParameter,
    value: u32,
) -> u32 {
    match (direction, device, parameter) {
        (
            Win16HostWaveDirection::Output,
            NativeWaveHandle::Output(handle),
            Win16HostWaveParameter::Pitch,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT. waveOutSetPitch
            // takes that handle and `value` by value and retains no pointer.
            // The handle is a host value, not a guest address.
            unsafe { waveOutSetPitch(*handle, value) }
        }
        (
            Win16HostWaveDirection::Output,
            NativeWaveHandle::Output(handle),
            Win16HostWaveParameter::PlaybackRate,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT.
            // waveOutSetPlaybackRate takes that handle and `value` by value
            // and retains no pointer. The handle is a host value, not a guest
            // address.
            unsafe { waveOutSetPlaybackRate(*handle, value) }
        }
        _ => MMSYSERR_INVALHANDLE,
    }
}

pub(super) fn query_mappable(direction: Win16HostWaveDirection, device_id: u16) -> u32 {
    let device_id = if device_id == u16::MAX {
        WAVE_MAPPER as usize
    } else {
        usize::from(device_id)
    };
    // `DRV_QUERYMAPPABLE` is a system-intercepted scalar query: both message
    // parameters are specified as zero. WinMM's documented interface casts a
    // device ID to the corresponding wave handle type for this message.
    match direction {
        Win16HostWaveDirection::Input => {
            let device = device_id as HWAVEIN;
            // SAFETY: `device` is this function's device identifier cast into
            // the handle slot. waveInMessage sends DRV_QUERYMAPPABLE with both
            // parameters zero and does not dereference that slot. The value is
            // not a guest address.
            unsafe { waveInMessage(device, DRV_QUERYMAPPABLE, 0, 0) }
        }
        Win16HostWaveDirection::Output => {
            let device = device_id as HWAVEOUT;
            // SAFETY: `device` is this function's device identifier cast into
            // the handle slot. waveOutMessage sends DRV_QUERYMAPPABLE with both
            // parameters zero and does not dereference that slot. The value is
            // not a guest address.
            unsafe { waveOutMessage(device, DRV_QUERYMAPPABLE, 0, 0) }
        }
    }
}

// SAFETY: `format` must be null or point at a caller-owned WAVEFORMATEX that
// stays live for this synchronous open. `callback` and `instance` are host
// callback scalars supplied by the caller, not guest addresses. The returned
// handle, when non-null, is owned by the caller.
pub(super) unsafe fn open_native(
    direction: Win16HostWaveDirection,
    device_id: u32,
    output_handle_present: bool,
    format: *mut WAVEFORMATEX,
    callback: usize,
    instance: usize,
    flags: u32,
) -> (u32, NativeWaveHandle) {
    match direction {
        Win16HostWaveDirection::Input => {
            let mut handle: HWAVEIN = ptr::null_mut();
            let output = if output_handle_present {
                &mut handle
            } else {
                ptr::null_mut()
            };
            // SAFETY: `format` is null or the caller's WAVEFORMATEX and stays
            // live for this call. `output` is null or the local `handle`.
            // `callback` and `instance` are host callback scalars that the
            // caller keeps valid for the device lifetime. waveInOpen writes
            // `handle` only when `output` is non-null. None of these values is
            // a guest address.
            let result =
                unsafe { waveInOpen(output, device_id, format, callback, instance, flags) };
            (result, NativeWaveHandle::Input(handle))
        }
        Win16HostWaveDirection::Output => {
            let mut handle: HWAVEOUT = ptr::null_mut();
            let output = if output_handle_present {
                &mut handle
            } else {
                ptr::null_mut()
            };
            // SAFETY: `format` is null or the caller's WAVEFORMATEX and stays
            // live for this call. `output` is null or the local `handle`.
            // `callback` and `instance` are host callback scalars that the
            // caller keeps valid for the device lifetime. waveOutOpen writes
            // `handle` only when `output` is non-null. None of these values is
            // a guest address.
            let result =
                unsafe { waveOutOpen(output, device_id, format, callback, instance, flags) };
            (result, NativeWaveHandle::Output(handle))
        }
    }
}

pub(super) fn initial_samples(
    initial: Win16HostWaveInitialBuffer,
    length: u32,
) -> Result<(Option<Vec<u8>>, bool), RuntimeError> {
    let capacity = usize::try_from(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "convert WinMM sample capacity",
            error,
        )
    })?;
    match initial {
        Win16HostWaveInitialBuffer::Null => Ok((None, false)),
        Win16HostWaveInitialBuffer::Playback { bytes } => {
            if bytes.len() != capacity {
                return Err(wave_invariant(
                    "initial WAVE playback bytes do not match header length",
                ));
            }
            Ok((Some(bytes), true))
        }
        Win16HostWaveInitialBuffer::Capture {
            capacity: declared,
            data_present,
        } => {
            if declared != length {
                return Err(wave_invariant(
                    "initial WAVE capture capacity changed at host boundary",
                ));
            }
            if !data_present {
                return Ok((None, false));
            }
            let mut samples = Vec::new();
            samples.try_reserve_exact(capacity).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve stable WinMM capture samples",
                    error,
                )
            })?;
            samples.resize(capacity, 0);
            Ok((Some(samples), true))
        }
    }
}

pub(super) fn completed_input_bytes(
    direction: Win16HostWaveDirection,
    buffer: &WaveBuffer,
    state: Win16HostWaveHeaderState,
) -> Result<Vec<u8>, RuntimeError> {
    if direction == Win16HostWaveDirection::Output {
        return Ok(Vec::new());
    }
    let length = usize::try_from(state.bytes_recorded).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "convert native WAVE input completion length",
            error,
        )
    })?;
    let Some(samples) = buffer.storage.samples.as_ref() else {
        if length == 0 {
            return Ok(Vec::new());
        }
        return Err(wave_invariant(
            "native WAVE input completed into a null sample buffer",
        ));
    };
    if length > samples.len() {
        return Err(wave_invariant(
            "native WAVE input exceeded its stable sample storage",
        ));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve WinMM input completion bytes",
            error,
        )
    })?;
    bytes.extend_from_slice(&samples[..length]);
    Ok(bytes)
}

pub(super) fn zero_header() -> WAVEHDR {
    WAVEHDR {
        lpData: ptr::null_mut(),
        dwBufferLength: 0,
        dwBytesRecorded: 0,
        dwUser: 0,
        dwFlags: 0,
        dwLoops: 0,
        lpNext: ptr::null_mut(),
        reserved: 0,
    }
}

pub(super) fn write_header(
    header: *mut WAVEHDR,
    samples: *mut u8,
    length: u32,
    bytes_recorded: u32,
    loops: u32,
    flags: u32,
) {
    // SAFETY: `header` is the caller's uniquely borrowed live WAVEHDR.
    // `lpData` is packed, so this stores `samples` with write_unaligned and
    // does not create a misaligned reference. `samples` is a host pointer, not
    // a guest address.
    unsafe { ptr::addr_of_mut!((*header).lpData).write_unaligned(samples) };
    // SAFETY: `header` is the caller's uniquely borrowed live WAVEHDR.
    // `dwBufferLength` is packed, so this stores `length` with write_unaligned
    // and does not create a misaligned reference.
    unsafe { ptr::addr_of_mut!((*header).dwBufferLength).write_unaligned(length) };
    // SAFETY: `header` is the caller's uniquely borrowed live WAVEHDR.
    // `dwBytesRecorded` is packed, so this stores `bytes_recorded` with
    // write_unaligned and does not create a misaligned reference.
    unsafe { ptr::addr_of_mut!((*header).dwBytesRecorded).write_unaligned(bytes_recorded) };
    // SAFETY: `header` is the caller's uniquely borrowed live WAVEHDR.
    // `dwFlags` is packed, so this stores `flags` with write_unaligned and
    // does not create a misaligned reference.
    unsafe { ptr::addr_of_mut!((*header).dwFlags).write_unaligned(flags) };
    // SAFETY: `header` is the caller's uniquely borrowed live WAVEHDR.
    // `dwLoops` is packed, so this stores `loops` with write_unaligned and
    // does not create a misaligned reference.
    unsafe { ptr::addr_of_mut!((*header).dwLoops).write_unaligned(loops) };
}

impl NativeWaveBuffer {
    pub(super) fn sample_pointer(&mut self) -> *mut u8 {
        if !self.data_present {
            return ptr::null_mut();
        }
        self.samples
            .as_mut()
            .map_or(ptr::null_mut(), |samples| samples.as_mut_ptr())
    }
}

// SAFETY: `device` must be a live WinMM handle owned by the caller, and
// `header` must be the caller's stable WAVEHDR, for this synchronous call. A
// direction that does not match the handle variant returns
// `MMSYSERR_INVALHANDLE` and performs no native call. Neither value is a guest
// address.
pub(super) unsafe fn prepare_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    header: *mut WAVEHDR,
) -> u32 {
    let header_size = size_of::<WAVEHDR>() as u32;
    match (direction, device) {
        (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN and `header` is
            // the caller's stable WAVEHDR. Both stay live. waveInPrepareHeader
            // prepares that header and returns an MMRESULT. Neither value is a
            // guest address.
            unsafe { waveInPrepareHeader(*handle, header, header_size) }
        }
        (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT and `header` is
            // the caller's stable WAVEHDR. Both stay live. waveOutPrepareHeader
            // prepares that header and returns an MMRESULT. Neither value is a
            // guest address.
            unsafe { waveOutPrepareHeader(*handle, header, header_size) }
        }
        _ => MMSYSERR_INVALHANDLE,
    }
}

// SAFETY: `device` must be a live WinMM handle owned by the caller for this
// synchronous call. A direction that does not match the handle variant returns
// `MMSYSERR_INVALHANDLE` and performs no native call. The handle is a host
// value, not a guest address.
pub(super) unsafe fn position_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    requested_time: u32,
) -> (u32, Option<Win16HostWavePosition>) {
    let mut native = MMTIME::default();
    // SAFETY: `native` is a writable, correctly sized MMTIME owned by this
    // call. `wType` is packed, so this stores the scalar `requested_time`
    // without a misaligned reference. WinMM has not been given this value yet.
    unsafe { ptr::addr_of_mut!(native.wType).write_unaligned(requested_time) };
    let time_size = size_of::<MMTIME>() as u32;
    let result = match (direction, device) {
        (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN, and `native` is
            // the local MMTIME that stays live. waveInGetPosition writes that
            // record and retains no pointer. The handle is a host value, not
            // a guest address.
            unsafe {
                windows_sys::Win32::Media::Audio::waveInGetPosition(*handle, &mut native, time_size)
            }
        }
        (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT, and `native` is
            // the local MMTIME that stays live. waveOutGetPosition writes that
            // record and retains no pointer. The handle is a host value, not
            // a guest address.
            unsafe {
                windows_sys::Win32::Media::Audio::waveOutGetPosition(
                    *handle,
                    &mut native,
                    time_size,
                )
            }
        }
        _ => return (MMSYSERR_INVALHANDLE, None),
    };
    if result != MMSYSERR_NOERROR {
        return (result, None);
    }
    // SAFETY: `native.wType` is a packed field of this local MMTIME. addr_of
    // plus read_unaligned reads that field without a misaligned reference.
    let time_type = unsafe { ptr::addr_of!(native.wType).read_unaligned() };
    let mut value = [0_u8; 8];
    // MMTIME's union is eight bytes on both supported host architectures. Its
    // active discriminant is returned separately; the runtime projects the
    // Win16-sized union only after checking the guest output range.
    // SAFETY: `native.u` is the packed union of this local MMTIME, and `value`
    // is a separate eight-byte array. This copies exactly `value.len()` bytes
    // from the union into that array. The spans do not overlap, and neither
    // address is a guest address.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::addr_of!(native.u).cast::<u8>(),
            value.as_mut_ptr(),
            value.len(),
        );
    }
    (result, Some(Win16HostWavePosition { time_type, value }))
}

// SAFETY: `device` must be a live WinMM handle owned by the caller, and
// `header` must be the caller's prepared WAVEHDR, for this synchronous call.
// A direction that does not match the handle variant returns
// `MMSYSERR_INVALHANDLE` and performs no native call. Neither value is a guest
// address.
pub(super) unsafe fn submit_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    header: *mut WAVEHDR,
) -> u32 {
    let header_size = size_of::<WAVEHDR>() as u32;
    match (direction, device) {
        (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN and `header` is
            // the caller's prepared WAVEHDR. Both stay live. waveInAddBuffer
            // queues that header and returns an MMRESULT. Neither value is a
            // guest address.
            unsafe { waveInAddBuffer(*handle, header, header_size) }
        }
        (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT and `header` is
            // the caller's prepared WAVEHDR. Both stay live. waveOutWrite
            // queues that header and returns an MMRESULT. Neither value is a
            // guest address.
            unsafe { waveOutWrite(*handle, header, header_size) }
        }
        _ => MMSYSERR_INVALHANDLE,
    }
}

// SAFETY: `device` must be a live WinMM handle owned by the caller, and
// `header` must be the caller's prepared WAVEHDR, for this synchronous call.
// A direction that does not match the handle variant returns
// `MMSYSERR_INVALHANDLE` and performs no native call. Neither value is a guest
// address.
pub(super) unsafe fn unprepare_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    header: *mut WAVEHDR,
) -> u32 {
    let header_size = size_of::<WAVEHDR>() as u32;
    match (direction, device) {
        (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN and `header` is
            // the caller's prepared WAVEHDR. Both stay live.
            // waveInUnprepareHeader releases that header and returns an
            // MMRESULT. Neither value is a guest address.
            unsafe { waveInUnprepareHeader(*handle, header, header_size) }
        }
        (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT and `header` is
            // the caller's prepared WAVEHDR. Both stay live.
            // waveOutUnprepareHeader releases that header and returns an
            // MMRESULT. Neither value is a guest address.
            unsafe { waveOutUnprepareHeader(*handle, header, header_size) }
        }
        _ => MMSYSERR_INVALHANDLE,
    }
}

// SAFETY: `device` must be a live WinMM handle owned by the caller for this
// synchronous call, and `direction` must name that handle's kind. A mismatch
// returns `MMSYSERR_INVALHANDLE` and performs no native call. The handle is a
// host value, not a guest address.
pub(super) unsafe fn control_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    command: Win16HostWaveControl,
) -> u32 {
    match (direction, device, command) {
        (
            Win16HostWaveDirection::Input,
            NativeWaveHandle::Input(handle),
            Win16HostWaveControl::Close,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN and stays owned
            // until this call returns. waveInClose closes that device and
            // returns an MMRESULT. The handle is a host value, not a guest
            // address.
            unsafe { waveInClose(*handle) }
        }
        (
            Win16HostWaveDirection::Input,
            NativeWaveHandle::Input(handle),
            Win16HostWaveControl::Start,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN. waveInStart
            // takes that handle by value and returns an MMRESULT. The handle
            // is a host value, not a guest address.
            unsafe { waveInStart(*handle) }
        }
        (
            Win16HostWaveDirection::Input,
            NativeWaveHandle::Input(handle),
            Win16HostWaveControl::Stop,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN. waveInStop takes
            // that handle by value and returns an MMRESULT. The handle is a
            // host value, not a guest address.
            unsafe { waveInStop(*handle) }
        }
        (
            Win16HostWaveDirection::Input,
            NativeWaveHandle::Input(handle),
            Win16HostWaveControl::Reset,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN. waveInReset
            // takes that handle by value and returns an MMRESULT. The handle
            // is a host value, not a guest address.
            unsafe { waveInReset(*handle) }
        }
        (
            Win16HostWaveDirection::Output,
            NativeWaveHandle::Output(handle),
            Win16HostWaveControl::Close,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT and stays owned
            // until this call returns. waveOutClose closes that device and
            // returns an MMRESULT. The handle is a host value, not a guest
            // address.
            unsafe { waveOutClose(*handle) }
        }
        (
            Win16HostWaveDirection::Output,
            NativeWaveHandle::Output(handle),
            Win16HostWaveControl::Pause,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT. waveOutPause
            // takes that handle by value and returns an MMRESULT. The handle
            // is a host value, not a guest address.
            unsafe { waveOutPause(*handle) }
        }
        (
            Win16HostWaveDirection::Output,
            NativeWaveHandle::Output(handle),
            Win16HostWaveControl::Restart,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT. waveOutRestart
            // takes that handle by value and returns an MMRESULT. The handle
            // is a host value, not a guest address.
            unsafe { waveOutRestart(*handle) }
        }
        (
            Win16HostWaveDirection::Output,
            NativeWaveHandle::Output(handle),
            Win16HostWaveControl::Reset,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT. waveOutReset
            // takes that handle by value and returns an MMRESULT. The handle
            // is a host value, not a guest address.
            unsafe { waveOutReset(*handle) }
        }
        (
            Win16HostWaveDirection::Output,
            NativeWaveHandle::Output(handle),
            Win16HostWaveControl::BreakLoop,
        ) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT. waveOutBreakLoop
            // takes that handle by value and returns an MMRESULT. The handle
            // is a host value, not a guest address.
            unsafe { waveOutBreakLoop(*handle) }
        }
        _ => MMSYSERR_INVALHANDLE,
    }
}

// SAFETY: `device` must be a live WinMM handle owned by the caller for this
// synchronous call, and `direction` must name that handle's kind. A mismatch
// returns `MMSYSERR_INVALHANDLE` and performs no native call. The handle is a
// host value, not a guest address.
pub(super) unsafe fn reset_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
) -> u32 {
    match (direction, device) {
        (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN. waveInReset
            // takes that handle by value and returns an MMRESULT. The handle
            // is a host value, not a guest address.
            unsafe { waveInReset(*handle) }
        }
        (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT. waveOutReset
            // takes that handle by value and returns an MMRESULT. The handle
            // is a host value, not a guest address.
            unsafe { waveOutReset(*handle) }
        }
        _ => MMSYSERR_INVALHANDLE,
    }
}

// SAFETY: `device` must be a live WinMM handle owned by the caller until this
// close returns. The handle is a host value, not a guest address.
pub(super) unsafe fn close_native(device: &NativeWaveHandle) -> u32 {
    match device {
        NativeWaveHandle::Input(handle) => {
            // SAFETY: `*handle` is the caller's live HWAVEIN and stays owned
            // until this call returns. waveInClose closes that device and
            // returns an MMRESULT. The handle is a host value, not a guest
            // address.
            unsafe { waveInClose(*handle) }
        }
        NativeWaveHandle::Output(handle) => {
            // SAFETY: `*handle` is the caller's live HWAVEOUT and stays owned
            // until this call returns. waveOutClose closes that device and
            // returns an MMRESULT. The handle is a host value, not a guest
            // address.
            unsafe { waveOutClose(*handle) }
        }
    }
}

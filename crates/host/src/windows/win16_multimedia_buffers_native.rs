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
    // SAFETY: the null pointer is used only for zero capacity; otherwise the
    // owned buffer remains writable for the exact size passed to WinMM.
    let result = unsafe {
        match direction {
            Win16HostWaveDirection::Input => {
                waveInGetErrorTextW(u32::from(error), pointer, capacity as u32)
            }
            Win16HostWaveDirection::Output => {
                waveOutGetErrorTextW(u32::from(error), pointer, capacity as u32)
            }
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

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn get_device_id(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
) -> (u32, Option<u32>) {
    let mut device_id = 0_u32;
    // SAFETY: the caller validates that the native handle variant matches
    // `direction`; the native API writes one DWORD to this local variable.
    let result = unsafe {
        match (direction, device) {
            (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
                // The windows-sys signature is const although WinMM's
                // waveInGetID contract writes the output identifier.
                waveInGetID(*handle, ptr::addr_of_mut!(device_id).cast_const())
            }
            (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
                waveOutGetID(*handle, ptr::addr_of_mut!(device_id))
            }
            _ => return (MMSYSERR_INVALHANDLE, None),
        }
    };
    (result, (result == MMSYSERR_NOERROR).then_some(device_id))
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn get_parameter(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    parameter: Win16HostWaveParameter,
) -> (u32, Option<u32>) {
    let mut value = 0_u32;
    // SAFETY: the caller holds the exact live output handle and a local
    // writable DWORD for the selected WinMM getter.
    let result = unsafe {
        match (direction, device, parameter) {
            (
                Win16HostWaveDirection::Output,
                NativeWaveHandle::Output(handle),
                Win16HostWaveParameter::Pitch,
            ) => waveOutGetPitch(*handle, ptr::addr_of_mut!(value)),
            (
                Win16HostWaveDirection::Output,
                NativeWaveHandle::Output(handle),
                Win16HostWaveParameter::PlaybackRate,
            ) => waveOutGetPlaybackRate(*handle, ptr::addr_of_mut!(value)),
            _ => return (MMSYSERR_INVALHANDLE, None),
        }
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

pub(super) unsafe fn set_parameter(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    parameter: Win16HostWaveParameter,
    value: u32,
) -> u32 {
    // SAFETY: the caller holds the exact live output handle; all parameters
    // are scalar WinMM values and no guest address crosses this boundary.
    unsafe {
        match (direction, device, parameter) {
            (
                Win16HostWaveDirection::Output,
                NativeWaveHandle::Output(handle),
                Win16HostWaveParameter::Pitch,
            ) => waveOutSetPitch(*handle, value),
            (
                Win16HostWaveDirection::Output,
                NativeWaveHandle::Output(handle),
                Win16HostWaveParameter::PlaybackRate,
            ) => waveOutSetPlaybackRate(*handle, value),
            _ => MMSYSERR_INVALHANDLE,
        }
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
    // SAFETY: waveInMessage sends a scalar driver message. Both parameters are zero for this query. waveOutMessage sends a scalar driver message. Both parameters are zero for this query.
    unsafe {
        match direction {
            Win16HostWaveDirection::Input => {
                waveInMessage(device_id as HWAVEIN, DRV_QUERYMAPPABLE, 0, 0)
            }
            Win16HostWaveDirection::Output => {
                waveOutMessage(device_id as HWAVEOUT, DRV_QUERYMAPPABLE, 0, 0)
            }
        }
    }
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn open_native(
    direction: Win16HostWaveDirection,
    device_id: u32,
    output_handle_present: bool,
    format: *mut WAVEFORMATEX,
    callback: usize,
    instance: usize,
    flags: u32,
) -> (u32, NativeWaveHandle) {
    // SAFETY: the caller owns the format storage and callback context for the
    // complete synchronous open call. The output handle is local until return.
    unsafe {
        match direction {
            Win16HostWaveDirection::Input => {
                let mut handle: HWAVEIN = ptr::null_mut();
                let output = if output_handle_present {
                    &mut handle
                } else {
                    ptr::null_mut()
                };
                let result = waveInOpen(output, device_id, format, callback, instance, flags);
                (result, NativeWaveHandle::Input(handle))
            }
            Win16HostWaveDirection::Output => {
                let mut handle: HWAVEOUT = ptr::null_mut();
                let output = if output_handle_present {
                    &mut handle
                } else {
                    ptr::null_mut()
                };
                let result = waveOutOpen(output, device_id, format, callback, instance, flags);
                (result, NativeWaveHandle::Output(handle))
            }
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
    // SAFETY: the caller passes a uniquely borrowed, live WAVEHDR stored in
    // its stable Box. windows-sys packs this SDK structure to byte alignment.
    unsafe {
        ptr::addr_of_mut!((*header).lpData).write_unaligned(samples);
        ptr::addr_of_mut!((*header).dwBufferLength).write_unaligned(length);
        ptr::addr_of_mut!((*header).dwBytesRecorded).write_unaligned(bytes_recorded);
        ptr::addr_of_mut!((*header).dwFlags).write_unaligned(flags);
        ptr::addr_of_mut!((*header).dwLoops).write_unaligned(loops);
    }
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

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn prepare_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    header: *mut WAVEHDR,
) -> u32 {
    // SAFETY: the owner supplies the matching live handle and stable header.
    unsafe {
        match (direction, device) {
            (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
                waveInPrepareHeader(*handle, header, size_of::<WAVEHDR>() as u32)
            }
            (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
                waveOutPrepareHeader(*handle, header, size_of::<WAVEHDR>() as u32)
            }
            _ => MMSYSERR_INVALHANDLE,
        }
    }
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn position_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    requested_time: u32,
) -> (u32, Option<Win16HostWavePosition>) {
    let mut native = MMTIME::default();
    // SAFETY: native is a writable, correctly sized MMTIME; the requested
    // Win16 type is a scalar and WinMM writes only to this owned value.
    unsafe { ptr::addr_of_mut!(native.wType).write_unaligned(requested_time) };
    let result = unsafe {
        match (direction, device) {
            (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
                windows_sys::Win32::Media::Audio::waveInGetPosition(
                    *handle,
                    &mut native,
                    size_of::<MMTIME>() as u32,
                )
            }
            (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
                windows_sys::Win32::Media::Audio::waveOutGetPosition(
                    *handle,
                    &mut native,
                    size_of::<MMTIME>() as u32,
                )
            }
            _ => return (MMSYSERR_INVALHANDLE, None),
        }
    };
    if result != MMSYSERR_NOERROR {
        return (result, None);
    }
    // SAFETY: The field belongs to a packed record. addr_of plus read_unaligned reads it without creating a misaligned reference.
    let time_type = unsafe { ptr::addr_of!(native.wType).read_unaligned() };
    let mut value = [0_u8; 8];
    // MMTIME's union is eight bytes on both supported host architectures. Its
    // active discriminant is returned separately; the runtime projects the
    // Win16-sized union only after checking the guest output range.
    // SAFETY: The source and destination are non-overlapping, and both spans were checked to cover the copied length.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::addr_of!(native.u).cast::<u8>(),
            value.as_mut_ptr(),
            value.len(),
        );
    }
    (result, Some(Win16HostWavePosition { time_type, value }))
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn submit_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    header: *mut WAVEHDR,
) -> u32 {
    // SAFETY: the owner supplies the matching live handle and prepared header.
    unsafe {
        match (direction, device) {
            (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
                waveInAddBuffer(*handle, header, size_of::<WAVEHDR>() as u32)
            }
            (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
                waveOutWrite(*handle, header, size_of::<WAVEHDR>() as u32)
            }
            _ => MMSYSERR_INVALHANDLE,
        }
    }
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn unprepare_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    header: *mut WAVEHDR,
) -> u32 {
    // SAFETY: the owner supplies the matching live handle and prepared header.
    unsafe {
        match (direction, device) {
            (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
                waveInUnprepareHeader(*handle, header, size_of::<WAVEHDR>() as u32)
            }
            (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
                waveOutUnprepareHeader(*handle, header, size_of::<WAVEHDR>() as u32)
            }
            _ => MMSYSERR_INVALHANDLE,
        }
    }
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn control_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
    command: Win16HostWaveControl,
) -> u32 {
    // SAFETY: native handle type and direction are checked together.
    unsafe {
        match (direction, device, command) {
            (
                Win16HostWaveDirection::Input,
                NativeWaveHandle::Input(handle),
                Win16HostWaveControl::Close,
            ) => waveInClose(*handle),
            (
                Win16HostWaveDirection::Input,
                NativeWaveHandle::Input(handle),
                Win16HostWaveControl::Start,
            ) => waveInStart(*handle),
            (
                Win16HostWaveDirection::Input,
                NativeWaveHandle::Input(handle),
                Win16HostWaveControl::Stop,
            ) => waveInStop(*handle),
            (
                Win16HostWaveDirection::Input,
                NativeWaveHandle::Input(handle),
                Win16HostWaveControl::Reset,
            ) => waveInReset(*handle),
            (
                Win16HostWaveDirection::Output,
                NativeWaveHandle::Output(handle),
                Win16HostWaveControl::Close,
            ) => waveOutClose(*handle),
            (
                Win16HostWaveDirection::Output,
                NativeWaveHandle::Output(handle),
                Win16HostWaveControl::Pause,
            ) => waveOutPause(*handle),
            (
                Win16HostWaveDirection::Output,
                NativeWaveHandle::Output(handle),
                Win16HostWaveControl::Restart,
            ) => waveOutRestart(*handle),
            (
                Win16HostWaveDirection::Output,
                NativeWaveHandle::Output(handle),
                Win16HostWaveControl::Reset,
            ) => waveOutReset(*handle),
            (
                Win16HostWaveDirection::Output,
                NativeWaveHandle::Output(handle),
                Win16HostWaveControl::BreakLoop,
            ) => waveOutBreakLoop(*handle),
            _ => MMSYSERR_INVALHANDLE,
        }
    }
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn reset_native(
    direction: Win16HostWaveDirection,
    device: &NativeWaveHandle,
) -> u32 {
    // SAFETY: native handle type and direction are checked together.
    unsafe {
        match (direction, device) {
            (Win16HostWaveDirection::Input, NativeWaveHandle::Input(handle)) => {
                waveInReset(*handle)
            }
            (Win16HostWaveDirection::Output, NativeWaveHandle::Output(handle)) => {
                waveOutReset(*handle)
            }
            _ => MMSYSERR_INVALHANDLE,
        }
    }
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn close_native(device: &NativeWaveHandle) -> u32 {
    // SAFETY: caller retains this handle until native Close returns success.
    unsafe {
        match device {
            NativeWaveHandle::Input(handle) => waveInClose(*handle),
            NativeWaveHandle::Output(handle) => waveOutClose(*handle),
        }
    }
}

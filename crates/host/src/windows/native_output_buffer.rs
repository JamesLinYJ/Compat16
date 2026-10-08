//! Guarded native output storage for calls without a capacity parameter.

use std::ffi::c_void;
use std::io;
use std::mem::{align_of, size_of};
use std::ptr::{self, NonNull};

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc,
    VirtualFree,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use zerocopy::FromBytes;

/// DeviceCapabilities output has no capacity argument. The worker maps the
/// exact expected byte count at the end of committed pages, followed by a
/// reserved no-access page. The guard catches sequential overruns; the worker
/// process contains native faults. `FromBytes` validates typed readback; this
/// host-native output buffer is distinct from Win16 wire codecs.
pub(super) struct NativeOutputBuffer<T: FromBytes + Copy + Default> {
    _reservation: Reservation,
    output: NonNull<T>,
    count: usize,
}

impl<T: FromBytes + Copy + Default> NativeOutputBuffer<T> {
    pub(super) fn new(count: usize) -> Result<Self, RuntimeError> {
        let byte_len = count.checked_mul(size_of::<T>()).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted,
                "native printer output byte length overflow")
        })?;
        // Bound only temporary worker output allocation; this is not a
        // DeviceCapabilities count guarantee or a Win16 selector-size limit.
        let output_budget = super::printer_protocol::MAX_FRAME_BYTES;
        if byte_len > output_budget {
            return Err(RuntimeError::new(Kind::ResourceExhausted, format!(
                "native printer output requires {byte_len} bytes, exceeding the worker output budget of {output_budget} bytes")));
        }
        if byte_len == 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "zero-length native output buffer must not be allocated"));
        }

        let mut system_info = SYSTEM_INFO::default();
        // SAFETY: `system_info` is writable storage for the documented result.
        unsafe { GetSystemInfo(&mut system_info); }
        let page_size = usize::try_from(system_info.dwPageSize).map_err(|error| {
            RuntimeError::with_source(Kind::InternalInvariant,
                "Windows reported an invalid native page size", error)
        })?;
        let alignment = align_of::<T>();
        if page_size == 0 || !page_size.is_power_of_two()
            || page_size % alignment != 0 || byte_len % alignment != 0
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native output size or alignment is incompatible with Windows pages"));
        }

        let rounded = byte_len.checked_add(page_size - 1).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted,
                "native printer page rounding overflow")
        })?;
        let committed_len = (rounded / page_size).checked_mul(page_size).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted,
                "native printer committed size overflow")
        })?;
        let reservation_len = committed_len.checked_add(page_size).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted,
                "native printer guard mapping size overflow")
        })?;

        let reservation = Reservation::new(reservation_len)?;
        // Reserve the final page as PAGE_NOACCESS, then commit only the
        // preceding pages. pOutput ends exactly at that guard page.
        // SAFETY: `base` is the page-aligned start of this reservation;
        // `committed_len` leaves one reserved page after the writable prefix.
        let committed = unsafe {
            VirtualAlloc(reservation.base.as_ptr(), committed_len, MEM_COMMIT, PAGE_READWRITE)
        };
        if committed.is_null() {
            return Err(last_error(Kind::ResourceExhausted,
                "commit guarded native printer output mapping"));
        }
        if committed != reservation.base.as_ptr() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Windows committed native output at an unexpected address"));
        }

        let output_offset = committed_len.checked_sub(byte_len).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "native output does not fit its committed mapping")
        })?;
        if output_offset % alignment != 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "right-aligned native printer buffer lost its type alignment"));
        }
        // SAFETY: `output_offset + byte_len` is at most `committed_len`, and
        // the base pointer refers to the full `reservation_len` allocation.
        // Preserve the VirtualAlloc pointer provenance while moving inside it.
        let output_address = unsafe {
            reservation.base.as_ptr().cast::<u8>().add(output_offset).cast::<T>()
        };
        let output = NonNull::new(output_address).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "native printer output address unexpectedly became null")
        })?;

        // SAFETY: This exact range lies in the committed PAGE_READWRITE area.
        // Initialize every byte before Rust or the native API reads it.
        unsafe { ptr::write_bytes(output.as_ptr().cast::<u8>(), 0, byte_len); }

        Ok(Self { _reservation: reservation, output, count })
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.output.as_ptr().cast()
    }

    pub(super) fn copy_prefix(&self, count: usize) -> Result<Vec<T>, RuntimeError> {
        if count > self.count {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native printer readback exceeds guarded output capacity"));
        }
        let mut output = Vec::new();
        output.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "copy native printer output", error))?;
        output.resize(count, T::default());
        if count != 0 {
            // SAFETY: The native mapping remains committed and readable, both
            // ranges contain `count` values, and FromBytes guarantees every
            // bit pattern in the initialized mapping is a valid `T`.
            unsafe {
                ptr::copy_nonoverlapping(self.output.as_ptr(), output.as_mut_ptr(), count);
            }
        }
        Ok(output)
    }
}

struct Reservation {
    base: NonNull<c_void>,
}

impl Reservation {
    fn new(length: usize) -> Result<Self, RuntimeError> {
        // This private mapping is separate from Rust Vec storage and reserves
        // one final no-access page for the worker's native call.
        // SAFETY: Request a fresh private reservation with no access; only its
        // checked prefix is committed after reservation succeeds.
        let address = unsafe {
            VirtualAlloc(ptr::null(), length, MEM_RESERVE, PAGE_NOACCESS)
        };
        let Some(base) = NonNull::new(address) else {
            return Err(last_error(Kind::ResourceExhausted,
                "reserve guarded native printer output mapping"));
        };
        Ok(Self { base })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // SAFETY: `base` is the original address returned by VirtualAlloc;
        // MEM_RELEASE with size zero releases this complete reservation.
        let _released = unsafe { VirtualFree(self.base.as_ptr(), 0, MEM_RELEASE) };
    }
}

fn last_error(kind: Kind, context: &str) -> RuntimeError {
    // SAFETY: Called immediately after a failed Windows memory API on this thread.
    let error = unsafe { GetLastError() };
    RuntimeError::with_source(kind, context, io::Error::from_raw_os_error(error as i32))
}

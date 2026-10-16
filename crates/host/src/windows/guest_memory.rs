//! Windows process-memory storage for guest RAM.
//!
//! The reservation is ordinary private VirtualAlloc memory, not physical RAM.
//! Rust accesses it only through ReadProcessMemory and WriteProcessMemory with
//! independent caller buffers. Those APIs do not isolate arbitrary native
//! DLLs from this process and do not make concurrent native accesses atomic.

use std::ffi::c_void;
use std::io;
use std::ptr::NonNull;
use std::rc::Rc;

use guest_core::memory::MemoryStorage;
use guest_core::MemoryError;
use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Owns a fixed-size Windows-backed guest-memory region.
///
/// Calling [`Self::storage`] creates another owner of the same reservation.
/// The region is released after the final Rust owner drops.
pub struct WindowsGuestMemory {
    region: Rc<OwnedRegion>,
}

struct OwnedRegion {
    base: NonNull<c_void>,
    length: u32,
}

/// A `MemoryStorage` view that shares the reservation with its host owner.
struct GuestMemoryStorage {
    region: Rc<OwnedRegion>,
}

impl WindowsGuestMemory {
    /// Reserve and commit a fixed-size, zero-initialized guest-memory region.
    pub fn new(size: u32) -> Result<Self, RuntimeError> {
        if size == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "guest memory reservation must have a nonzero size",
            ));
        }
        let allocation_size = usize::try_from(size).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "guest memory size does not fit the host address space",
            )
        })?;

        // SAFETY: This requests a new process-owned private region. The result
        // is kept as an opaque address and is never dereferenced by Rust.
        let allocation = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                allocation_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        let Some(base) = NonNull::new(allocation) else {
            // SAFETY: GetLastError reports the failure from the preceding
            // VirtualAlloc call on this thread.
            let error = unsafe { GetLastError() };
            return Err(RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve guest process memory",
                io::Error::from_raw_os_error(error as i32),
            ));
        };

        Ok(Self {
            region: Rc::new(OwnedRegion {
                base,
                length: size,
            }),
        })
    }

    /// Create a guest-core storage adapter over this same reservation.
    pub fn storage(&self) -> Box<dyn MemoryStorage> {
        Box::new(GuestMemoryStorage {
            region: Rc::clone(&self.region),
        })
    }
}

impl OwnedRegion {
    fn checked_length(&self, address: u32, length: usize) -> Result<usize, MemoryError> {
        let length64 = u64::try_from(length).map_err(|_| MemoryError::AddressOverflow)?;
        let end = u64::from(address)
            .checked_add(length64)
            .ok_or(MemoryError::AddressOverflow)?;
        if end > u64::from(u32::MAX) + 1 {
            return Err(MemoryError::AddressOverflow);
        }
        if end > u64::from(self.length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        usize::try_from(length).map_err(|_| MemoryError::AddressOverflow)
    }

    fn native_address(&self, offset: u32) -> Result<*const c_void, MemoryError> {
        let base = self.base.as_ptr() as usize;
        let offset = usize::try_from(offset).map_err(|_| MemoryError::AddressOverflow)?;
        let address = base.checked_add(offset).ok_or(MemoryError::AddressOverflow)?;
        Ok(address as *const c_void)
    }
}

impl Drop for OwnedRegion {
    fn drop(&mut self) {
        // SAFETY: This is the exact base returned by VirtualAlloc. MEM_RELEASE
        // requires a zero size and releases the complete reservation.
        let _released = unsafe { VirtualFree(self.base.as_ptr(), 0, MEM_RELEASE) };
    }
}

impl MemoryStorage for GuestMemoryStorage {
    fn len(&self) -> u32 {
        self.region.length
    }

    fn read_plain_code(&self, offset: u32, output: &mut [u8]) -> Result<bool, MemoryError> {
        // Rc owners remain on the machine thread. No guest writes or native
        // callbacks run during a pure integer quantum. Copy through the same
        // checked OS boundary; never form a Rust slice over the reservation.
        // Arbitrary native DLL mutation is outside this memory trust boundary,
        // as it already is for ordinary ReadProcessMemory/WriteProcessMemory.
        self.read(offset, output)?;
        Ok(true)
    }
    fn read_plain_data(&self, offset: u32, output: &mut [u8], _writable: bool) -> Result<bool, MemoryError> {
        // The private reservation has no write observers and cannot be
        // mutated by another Rust thread or reentrant callback in a quantum.
        self.read_plain_code(offset,output)
    }

    fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError> {
        let length = self.region.checked_length(offset, output.len())?;
        if length == 0 {
            return Ok(());
        }
        let address = self.region.native_address(offset)?;
        let mut transferred = 0_usize;
        // SAFETY: `address` is within the live VirtualAlloc reservation and
        // `output` is an independent writable buffer of `length` bytes. The
        // OS API performs the copy; Rust never forms a reference to the region.
        let succeeded = unsafe {
            ReadProcessMemory(
                current_process(),
                address,
                output.as_mut_ptr().cast::<c_void>(),
                length,
                &mut transferred,
            )
        };
        let os_error = if succeeded == 0 {
            // SAFETY: ReadProcessMemory just reported failure on this thread.
            Some(unsafe { GetLastError() } as i32)
        } else {
            None
        };
        if succeeded == 0 || transferred != length {
            return Err(MemoryError::StorageAccess {
                address: offset,
                length,
                transferred,
                write: false,
                os_error,
            });
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, input: &[u8]) -> Result<(), MemoryError> {
        let length = self.region.checked_length(offset, input.len())?;
        if length == 0 {
            return Ok(());
        }
        let address = self.region.native_address(offset)?;
        let mut transferred = 0_usize;
        // SAFETY: `address` is within the live VirtualAlloc reservation and
        // `input` is an independent readable buffer of `length` bytes. The OS
        // API performs the copy; Rust never forms a reference to the region.
        let succeeded = unsafe {
            WriteProcessMemory(
                current_process(),
                address,
                input.as_ptr().cast::<c_void>(),
                length,
                &mut transferred,
            )
        };
        let os_error = if succeeded == 0 {
            // SAFETY: WriteProcessMemory just reported failure on this thread.
            Some(unsafe { GetLastError() } as i32)
        } else {
            None
        };
        if succeeded == 0 || transferred != length {
            return Err(MemoryError::StorageAccess {
                address: offset,
                length,
                transferred,
                write: true,
                os_error,
            });
        }
        Ok(())
    }
}

fn current_process() -> HANDLE {
    // SAFETY: GetCurrentProcess returns a pseudo-handle for the calling process.
    unsafe { GetCurrentProcess() }
}

//! Shared section storage and lifetime gate for WinG DIB-section bitmaps.

use std::{
    io,
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex, MutexGuard},
    thread::{self, ThreadId},
};

use super::win16_wing_dib_format::{WinGDibFormat, validate_win_g_dib};
use super::win16_wing_dib_header::{BitmapInfoHeaderWire, BITMAPINFOHEADER_SIZE};

use guest_core::{MemoryError, memory::MemoryMappedDevice};
use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Graphics::Gdi::{
        BITMAPINFO, BITMAPINFOHEADER, CreateDIBSection, DIBSECTION, DIB_RGB_COLORS,
        GdiFlush, GetObjectW, HBITMAP, HDC,
    },
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        Memory::{
            CreateFileMappingW, FILE_MAP_ALL_ACCESS, MapViewOfFile, MEMORY_MAPPED_VIEW_ADDRESS,
            PAGE_READWRITE, UnmapViewOfFile,
        },
        Threading::GetCurrentProcess,
    },
};

const DIB_HEADER_BYTES: usize = BITMAPINFOHEADER_SIZE;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Live,
    Retiring,
    Retired,
}

struct AccessState {
    phase: Phase,
    view_pins: usize,
    native_pins: usize,
}

    /// Owns a file-mapping view shared by GDI and the guest memory device.
/// Pointer values stay private to this Windows adapter.
pub(super) struct Win16DibSectionOwner {
    section: usize,
    view: usize,
    native_bitmap: usize,
    length: u32,
    owner_thread: ThreadId,
    state: Mutex<AccessState>,
    // This storage and its HBITMAP are restricted to the guest-runtime GDI
    // thread. The Rc marker prevents accidental transfer to a worker thread.
    _not_send: PhantomData<Rc<()>>,
}

pub(super) struct CreatedDibSection {
    pub bitmap: HBITMAP,
    pub owner: Arc<Win16DibSectionOwner>,
    pub memory: Rc<dyn MemoryMappedDevice>,
    pub header: [u8; DIB_HEADER_BYTES],
}

impl Win16DibSectionOwner {
    pub(super) fn create(
        dc: HDC,
        info: &[u8],
        image_bytes: u32,
    ) -> Result<Option<CreatedDibSection>, RuntimeError> {
        let Some(format) = validate_win_g_dib(info, image_bytes) else { return Ok(None); };
        let Ok(map_length) = usize::try_from(image_bytes) else { return Ok(None); };
        let mut aligned_info = aligned_bitmap_info(info)?;

        let section = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                image_bytes,
                std::ptr::null(),
            )
        };
        if section.is_null() {
            return Ok(None);
        }

        let view = unsafe {
            MapViewOfFile(
                section,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                map_length,
            )
        };
        if view.Value.is_null() {
            let primary = last_error("map WinG DIB shared section");
            return match close_section(section) {
                Ok(()) => Ok(None),
                Err(cleanup) => Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "mapping WinG DIB storage and closing its section both failed",
                    DibCleanupFailure { primary, cleanup },
                )),
            };
        }

        let mut dib_bits = std::ptr::null_mut();
        let bitmap = unsafe {
            CreateDIBSection(
                dc,
                aligned_info.as_mut_ptr().cast::<BITMAPINFO>(),
                DIB_RGB_COLORS,
                &mut dib_bits,
                section,
                0,
            )
        };
        if bitmap.is_null() {
            let primary = last_error("create WinG DIB section bitmap");
            return match release_view_and_section(view, section) {
                Ok(()) => Ok(None),
                Err(cleanup) => Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "creating WinG DIB bitmap and releasing its storage both failed",
                    DibCleanupFailure { primary, cleanup },
                )),
            };
        }

        let owner = Arc::new(Self {
            section: section as usize,
            view: view.Value as usize,
            native_bitmap: bitmap as usize,
            length: image_bytes,
            owner_thread: thread::current().id(),
            state: Mutex::new(AccessState {
                phase: Phase::Live,
                view_pins: 0,
                native_pins: 0,
            }),
            _not_send: PhantomData,
        });

        if dib_bits.is_null() {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "CreateDIBSection returned a bitmap without pixel storage",
            );
            return Err(combine_cleanup(primary, delete_unpublished_bitmap(bitmap, &owner)));
        }

        let header = match read_dib_section(bitmap, dib_bits, format) {
            Ok(Some(header)) => header,
            Ok(None) => {
                let primary = RuntimeError::new(
                    Kind::HostFailure,
                    "GetObjectW did not return a matching WinG DIBSECTION",
                );
                return Err(combine_cleanup(primary, delete_unpublished_bitmap(bitmap, &owner)));
            }
            Err(primary) => {
                return Err(combine_cleanup(primary, delete_unpublished_bitmap(bitmap, &owner)));
            }
        };

        Ok(Some(CreatedDibSection {
            bitmap,
            owner: Arc::clone(&owner),
            memory: Rc::new(DibMemoryDevice { owner }),
            header,
        }))
    }

    pub(super) fn pin_native(self: &Arc<Self>) -> Result<Win16DibNativeUse, RuntimeError> {
        self.check_owner_thread()?;
        {
            let mut state = self.lock_state()?;
            if state.phase != Phase::Live {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG DIB native use reached a retired bitmap",
                ));
            }
            state.native_pins = state.native_pins.checked_add(1).ok_or_else(|| {
                RuntimeError::new(Kind::ResourceExhausted, "WinG DIB native-use pins exhausted")
            })?;
        }
        if unsafe { GdiFlush() } == 0 {
            let guard = Win16DibNativeUse { owner: Arc::clone(self) };
            drop(guard);
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "GdiFlush failed on the WinG DIB owner thread before native use",
            ));
        }
        Ok(Win16DibNativeUse { owner: Arc::clone(self) })
    }

    pub(super) fn begin_delete(
        self: &Arc<Self>,
    ) -> Result<Option<Win16DibDeleteLease>, RuntimeError> {
        self.check_owner_thread()?;
        {
            let mut state = self.lock_state()?;
            if state.phase != Phase::Live || state.view_pins != 0 || state.native_pins != 0 {
                return Ok(None);
            }
            state.phase = Phase::Retiring;
        }
        // GdiFlush only drains the calling thread's batch. DIB access is
        // intentionally restricted to the creating GDI thread above.
        if unsafe { GdiFlush() } == 0 {
            self.restore_live()?;
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "GdiFlush failed on the WinG DIB owner thread before deletion",
            ));
        }
        Ok(Some(Win16DibDeleteLease { owner: Arc::clone(self), active: true }))
    }

    fn check_owner_thread(&self) -> Result<(), RuntimeError> {
        if thread::current().id() == self.owner_thread {
            Ok(())
        } else {
            Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "WinG DIB access must run on its creating GDI thread",
            ))
        }
    }

    pub(super) fn matches_bitmap(
        &self,
        bitmap: windows_sys::Win32::Graphics::Gdi::HBITMAP,
    ) -> bool {
        self.native_bitmap == bitmap as usize
    }

    pub(super) fn extent(&self) -> u32 { self.length }

    fn lock_state(&self) -> Result<MutexGuard<'_, AccessState>, RuntimeError> {
        self.state.lock().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant,
            "WinG DIB lifetime gate mutex is poisoned",
        ))
    }

    fn restore_live(&self) -> Result<(), RuntimeError> {
        self.lock_state()?.phase = Phase::Live;
        Ok(())
    }

    fn validate_range(&self, offset: u32, length: u32, write: bool) -> Result<(), MemoryError> {
        let end = offset.checked_add(length).ok_or(MemoryError::AddressOverflow)?;
        if end > self.length {
            return Err(MemoryError::OutOfBounds { address: offset, length: length as usize });
        }
        // Runtime::run_machine executes guest CPU accesses and synchronous
        // RuntimeHost GDI calls on one thread. Memory and this device use Rc,
        // so neither the validated access nor the matching DeleteObject can
        // migrate to a worker; guest code cannot reenter between validation
        // and the device copy. The per-copy pin additionally gates retirement
        // and retains this independent view through the OS transfer.
        if thread::current().id() != self.owner_thread {
            return Err(storage_error(offset, length, write, None));
        }
        let state = self.state.lock().map_err(|_| storage_error(offset, length, write, None))?;
        if state.phase != Phase::Live {
            return Err(storage_error(offset, length, write, None));
        }
        Ok(())
    }

    fn begin_view(
        self: &Arc<Self>,
        offset: u32,
        length: usize,
        write: bool,
    ) -> Result<ViewLease, MemoryError> {
        let length32 = u32::try_from(length).map_err(|_| MemoryError::AddressOverflow)?;
        self.validate_range(offset, length32, write)?;
        {
            let mut state = self.state.lock().map_err(|_| storage_error(offset, length32, write, None))?;
            if state.phase != Phase::Live {
                return Err(storage_error(offset, length32, write, None));
            }
            state.view_pins = state.view_pins.checked_add(1)
                .ok_or_else(|| storage_error(offset, length32, write, None))?;
        }
        if unsafe { GdiFlush() } == 0 {
            drop(ViewLease { owner: Arc::clone(self) });
            return Err(storage_error(offset, length32, write, None));
        }
        Ok(ViewLease { owner: Arc::clone(self) })
    }

    fn transfer(
        &self,
        offset: u32,
        local: *mut std::ffi::c_void,
        length: usize,
        write: bool,
    ) -> Result<(), MemoryError> {
        if length == 0 { return Ok(()); }
        let base = self.view.checked_add(offset as usize).ok_or(MemoryError::AddressOverflow)?;
        let mut transferred = 0_usize;
        let process = unsafe { GetCurrentProcess() };
        let succeeded = if write {
            unsafe {
                WriteProcessMemory(
                    process,
                    base as *const std::ffi::c_void,
                    local.cast_const(),
                    length,
                    &mut transferred,
                )
            }
        } else {
            unsafe {
                ReadProcessMemory(
                    process,
                    base as *const std::ffi::c_void,
                    local,
                    length,
                    &mut transferred,
                )
            }
        };
        if succeeded == 0 || transferred != length {
            let os_error = if succeeded == 0 { Some(unsafe { windows_sys::Win32::Foundation::GetLastError() } as i32) }
                else { None };
            return Err(MemoryError::StorageAccess {
                address: offset,
                length,
                transferred,
                write,
                os_error,
            });
        }
        Ok(())
    }

    fn decrement_view_pin(&self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(state.view_pins > 0, "WinG DIB view pin underflow");
        state.view_pins = state.view_pins.saturating_sub(1);
    }

    fn decrement_native_pin(&self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(state.native_pins > 0, "WinG DIB native pin underflow");
        state.native_pins = state.native_pins.saturating_sub(1);
    }

}

impl Drop for Win16DibSectionOwner {
    fn drop(&mut self) {
        let retired = self.state.lock().map(|state| state.phase == Phase::Retired).unwrap_or(false);
        if !retired {
            // A native bitmap may still refer to this section. Leaking the OS
            // view/handle on an unrecoverable teardown error is safer than
            // detaching storage still owned by GDI; process exit reclaims it.
            return;
        }
        let view = MEMORY_MAPPED_VIEW_ADDRESS { Value: self.view as *mut std::ffi::c_void };
        unsafe {
            let _unmapped = UnmapViewOfFile(view);
            let _closed = CloseHandle(self.section as HANDLE);
        }
    }
}

struct DibMemoryDevice {
    owner: Arc<Win16DibSectionOwner>,
}

impl MemoryMappedDevice for DibMemoryDevice {
    fn validate_read(&self, offset: u32, length: u32) -> Result<(), MemoryError> {
        self.owner.validate_range(offset, length, false)
    }

    fn validate_write(&self, offset: u32, length: u32) -> Result<(), MemoryError> {
        self.owner.validate_range(offset, length, true)
    }

    fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError> {
        let _lease = self.owner.begin_view(offset, output.len(), false)?;
        self.owner.transfer(offset, output.as_mut_ptr().cast(), output.len(), false)
    }

    fn write(&self, offset: u32, input: &[u8]) -> Result<(), MemoryError> {
        let _lease = self.owner.begin_view(offset, input.len(), true)?;
        self.owner.transfer(offset, input.as_ptr().cast_mut().cast(), input.len(), true)
    }
}

pub(super) struct Win16DibNativeUse {
    owner: Arc<Win16DibSectionOwner>,
}

impl Drop for Win16DibNativeUse {
    fn drop(&mut self) { self.owner.decrement_native_pin(); }
}

struct ViewLease {
    owner: Arc<Win16DibSectionOwner>,
}

impl Drop for ViewLease {
    fn drop(&mut self) { self.owner.decrement_view_pin(); }
}

pub(super) struct Win16DibDeleteLease {
    owner: Arc<Win16DibSectionOwner>,
    active: bool,
}

impl Win16DibDeleteLease {
    pub(super) fn finish(mut self, deleted: bool) -> Result<(), RuntimeError> {
        let mut state = self.owner.lock_state()?;
        if state.phase != Phase::Retiring {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "WinG DIB deletion phase changed before native receipt",
            ));
        }
        state.phase = if deleted { Phase::Retired } else { Phase::Live };
        self.active = false;
        Ok(())
    }
}

impl Drop for Win16DibDeleteLease {
    fn drop(&mut self) {
        if self.active {
            let _ = self.owner.restore_live();
        }
    }
}

fn aligned_bitmap_info(bytes: &[u8]) -> Result<Vec<u32>, RuntimeError> {
    let Some(padded_length) = bytes.len().checked_add(3) else {
        return Err(RuntimeError::new(Kind::ResourceExhausted, "WinG BITMAPINFO length overflowed"));
    };
    let word_count = padded_length / 4;
    let mut aligned = Vec::new();
    aligned.try_reserve_exact(word_count).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate aligned WinG BITMAPINFO", error,
    ))?;
    aligned.resize(word_count, 0);
    // Vec<u8> has no DWORD alignment guarantee. The native API requires a
    // stable aligned BITMAPINFO for the duration of CreateDIBSection.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            aligned.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    Ok(aligned)
}

fn read_dib_section(
    bitmap: HBITMAP,
    dib_bits: *mut std::ffi::c_void,
    format: WinGDibFormat,
) -> Result<Option<[u8; DIB_HEADER_BYTES]>, RuntimeError> {
    let mut section = std::mem::MaybeUninit::<DIBSECTION>::zeroed();
    let written = unsafe {
        GetObjectW(bitmap.cast(), std::mem::size_of::<DIBSECTION>() as i32,
            section.as_mut_ptr().cast())
    };
    if written != std::mem::size_of::<DIBSECTION>() as i32 { return Ok(None); }
    let section = unsafe { section.assume_init() };
    let header: BITMAPINFOHEADER = section.dsBmih;
    let expected_height = i32::try_from(format.height.unsigned_abs()).ok();
    let actual_extent = u64::try_from(section.dsBm.bmWidthBytes).ok()
        .and_then(|stride| stride.checked_mul(u64::from(format.height.unsigned_abs())));
    if section.dsBm.bmBits != dib_bits
        || section.dsBm.bmWidth != format.width
        || Some(section.dsBm.bmHeight) != expected_height
        || section.dsBm.bmWidthBytes < 0
        || u32::try_from(section.dsBm.bmWidthBytes).ok().is_none_or(|stride|
            stride < format.row_bytes)
        || actual_extent.is_none_or(|extent| extent > u64::from(format.image_extent))
        || header.biWidth != format.width
        || header.biHeight != format.height
        || header.biPlanes != 1
        || header.biBitCount != format.bit_count
        || header.biCompression != format.compression
    {
        return Ok(None);
    }
    let bytes = BitmapInfoHeaderWire::from_native(&header).into_bytes();
    Ok(Some(bytes))
}

fn delete_unpublished_bitmap(
    bitmap: HBITMAP,
    owner: &Arc<Win16DibSectionOwner>,
) -> Result<(), RuntimeError> {
    let lease = owner.begin_delete()?.ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "unpublished WinG bitmap acquired an unexpected active lease",
    ))?;
    let deleted = unsafe { windows_sys::Win32::Graphics::Gdi::DeleteObject(bitmap.cast()) } != 0;
    lease.finish(deleted)?;
    if !deleted {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "DeleteObject returned FALSE for an unpublished WinG DIB bitmap",
        ));
    }
    Ok(())
}

fn release_view_and_section(
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    section: HANDLE,
) -> Result<(), RuntimeError> {
    let unmapped = unsafe { UnmapViewOfFile(view) } != 0;
    let unmap_error = (!unmapped).then(|| last_error("unmap failed WinG DIB view"));
    let closed = unsafe { CloseHandle(section) } != 0;
    let close_error = (!closed).then(|| last_error("close failed WinG DIB section"));
    match (unmap_error, close_error) {
        (None, None) => Ok(()),
        (Some(error), None) | (None, Some(error)) => Err(error),
        (Some(primary), Some(cleanup)) => Err(RuntimeError::with_source(
            Kind::HostFailure,
            "unmap and close both failed while rolling back WinG DIB storage",
            DibCleanupFailure { primary, cleanup },
        )),
    }
}

fn close_section(section: HANDLE) -> Result<(), RuntimeError> {
    if unsafe { CloseHandle(section) } != 0 { Ok(()) }
    else { Err(last_error("close WinG DIB section after mapping failure")) }
}

fn last_error(action: &'static str) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure, action, io::Error::last_os_error())
}

fn combine_cleanup(primary: RuntimeError, cleanup: Result<(), RuntimeError>) -> RuntimeError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => RuntimeError::with_source(
            Kind::HostFailure,
            "WinG DIB operation and resource cleanup both failed",
            DibCleanupFailure { primary, cleanup },
        ),
    }
}

#[derive(Debug)]
struct DibCleanupFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl std::fmt::Display for DibCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; cleanup also failed: {}", self.primary, self.cleanup)
    }
}

impl std::error::Error for DibCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

fn storage_error(offset: u32, length: u32, write: bool, os_error: Option<i32>) -> MemoryError {
    MemoryError::StorageAccess {
        address: offset,
        length: length as usize,
        transferred: 0,
        write,
        os_error,
    }
}

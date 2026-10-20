//! Native GDI objects owned behind opaque host identities.

#[path = "win16_gdi_cleanup.rs"]
mod cleanup;
#[path = "win16_gdi_dc_lease.rs"]
mod dc_lease;
#[path = "win16_gdi_device_caps.rs"]
mod device_caps;
#[path = "win16_gdi_fonts.rs"]
pub(super) mod fonts;
#[path = "win16_gdi_metafile.rs"]
pub(super) mod metafile;
#[path = "win16_gdi_outline_metrics.rs"]
mod outline_metrics;
#[path = "win16_gdi_update_region.rs"]
mod update_region;

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::BTreeMap;
use std::mem::{align_of, size_of};
use std::ptr::{self, NonNull};
use std::sync::{Arc, Mutex, MutexGuard};

use super::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DrawingRect, Win16HostDc, Win16HostDevMode,
    Win16HostWindow,
};
use windows_sys::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDCW, CreateICW, DEVMODEW, DEVMODEW_0, DEVMODEW_0_0, DM_SPECVERSION,
    GetDC, GetDeviceCaps, GetWindowDC, HDC, ResetDCW,
};

/// Complete this thread's batched drawing before another thread uses a shared
/// HDC. GdiFlush drains the batch even when its BOOL reports a failed drawing
/// command; that BOOL is not an inability to perform the synchronization.
pub(super) fn flush_thread_batch() {
    // SAFETY: GdiFlush has no arguments and operates on the calling thread.
    unsafe {
        windows_sys::Win32::Graphics::Gdi::GdiFlush();
    }
}

#[derive(Clone, Copy)]
enum DcOrigin {
    Compatible,
    Information,
    Screen,
    Created,
    Metafile,
    FunctionCallback {
        callback: runtime::Win16HostCallback,
    },
    Window {
        window: Win16HostWindow,
        lease: WindowDcLease,
    },
}

/// A window DC's matching release operation. The USER worker executes that
/// operation; this tag only guards the host identity table against mismatched
/// or duplicate releases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WindowDcLease {
    Client,
    WholeWindow,
    Paint,
    /// A WndProc-supplied HDC that is valid only until the callback returns.
    Callback,
}

#[derive(Clone, Copy)]
struct NativeDc {
    // Store the opaque native handle as an integer so the shared DC table can
    // be referenced by the USER worker without making raw pointers Send.
    handle: usize,
    origin: DcOrigin,
    paint_info: Option<Win16NativePaintInfo>,
    pin_count: usize,
    release_pending: bool,
    retire_on_unpin: bool,
}

impl NativeDc {
    fn handle(self) -> HDC {
        self.handle as HDC
    }
}

#[derive(Clone)]
pub(super) struct Win16Dcs {
    shared: Arc<Mutex<Win16DcState>>,
    text_codec: super::guest_text::GuestTextCodec,
}

/// Pointer-free host-only copy of a native PAINTSTRUCT. It is retained with
/// the matching paint HDC and rebuilt on the owning USER worker for EndPaint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16NativePaintInfo {
    pub erase: i32,
    pub rect: Win16DrawingRect,
    pub restore: i32,
    pub inc_update: i32,
    pub reserved: [u8; 32],
}

struct Win16DcState {
    objects: BTreeMap<Win16HostDc, NativeDc>,
    metafile_outputs: BTreeMap<Win16HostDc, Option<cap_std::fs::File>>,
    next_id: u64,
}

impl Win16Dcs {
    pub(super) fn with_text_codec(text_codec: super::guest_text::GuestTextCodec) -> Self {
        Self {
            text_codec,
            shared: Arc::new(Mutex::new(Win16DcState {
                objects: BTreeMap::new(),
                metafile_outputs: BTreeMap::new(),
                next_id: 1,
            })),
        }
    }
    pub(in crate::windows) fn text_codec(&self) -> super::guest_text::GuestTextCodec {
        self.text_codec
    }

    /// A poisoned guard retains only host-owned DC identities. Host calls
    /// validate tokens before use, and window/callback leases are still
    /// removed only by their matching owner operation.
    fn lock(&self) -> MutexGuard<'_, Win16DcState> {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Transfer a newly created DeleteDC-owned context into the shared table.
    /// The table also releases it if identity allocation fails.
    pub(super) fn adopt_created(&self, native: HDC) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock().record_created(native, DcOrigin::Created)
    }

    pub(super) fn create_compatible(
        &self,
        source: Option<Win16HostDc>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        let source_use = match source {
            Some(source) => match self.lease_dc(source)? {
                Some(source_use) => Some(source_use),
                None => return Ok(None),
            },
            None => None,
        };
        let native_source = source_use
            .as_ref()
            .map_or(ptr::null_mut(), |source_use| source_use.native());
        // SAFETY: A non-NULL source remains pinned until CreateCompatibleDC
        // returns; NULL requests a compatible display DC as documented.
        let native = unsafe { CreateCompatibleDC(native_source) };
        drop(source_use);
        self.lock().record_created(native, DcOrigin::Compatible)
    }

    pub(super) fn create_dc(
        &self,
        driver: Option<&[u8]>,
        device: Option<&[u8]>,
        output: Option<&[u8]>,
        devmode: Option<&Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock()
            .create_dc(self.text_codec, driver, device, output, devmode)
    }

    pub(super) fn create_ic(
        &self,
        driver: Option<&[u8]>,
        device: Option<&[u8]>,
        output: Option<&[u8]>,
        devmode: Option<&Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock()
            .create_ic(self.text_codec, driver, device, output, devmode)
    }

    pub(super) fn acquire_screen(
        &self,
        whole_window: bool,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock().acquire_screen(whole_window)
    }

    pub(super) fn adopt_window_dc(
        &self,
        window: Win16HostWindow,
        whole_window: bool,
        raw_hdc: usize,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock().adopt_window_dc(window, whole_window, raw_hdc)
    }

    pub(super) fn adopt_screen_dc(&self, native: HDC) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock().record_screen_dc(native)
    }

    pub(super) fn adopt_paint_dc(
        &self,
        window: Win16HostWindow,
        raw_hdc: usize,
        paint_info: Win16NativePaintInfo,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock().adopt_paint_dc(window, raw_hdc, paint_info)
    }

    pub(super) fn native_paint_info(
        &self,
        token: Win16HostDc,
        window: Win16HostWindow,
    ) -> Option<Win16NativePaintInfo> {
        self.lock().native_paint_info(token, window)
    }

    pub(super) fn adopt_callback_dc(
        &self,
        window: Win16HostWindow,
        raw_hdc: usize,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock().adopt_callback_dc(window, raw_hdc)
    }

    pub(super) fn adopt_function_dc(
        &self,
        callback: runtime::Win16HostCallback,
        raw_hdc: usize,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock()
            .record_borrowed_dc(DcOrigin::FunctionCallback { callback }, raw_hdc, None)
    }

    pub(super) fn is_function_dc(&self, token: Win16HostDc) -> bool {
        self.lock()
            .objects
            .get(&token)
            .is_some_and(|dc| matches!(dc.origin, DcOrigin::FunctionCallback { .. }))
    }

    pub(super) fn retire_function_dc(
        &self,
        token: Win16HostDc,
        callback: runtime::Win16HostCallback,
    ) -> bool {
        let mut state = self.lock();
        let Some(dc) = state.objects.get_mut(&token) else {
            return false;
        };
        if !matches!(dc.origin, DcOrigin::FunctionCallback { callback: owner } if owner == callback)
        {
            return false;
        }
        if dc.pin_count == 0 {
            state.objects.remove(&token);
        } else {
            dc.retire_on_unpin = true;
        }
        true
    }

    pub(super) fn cleanup(&self, token: Win16HostDc) -> bool {
        self.lock().cleanup(token)
    }
    pub(super) fn cleanup_state(&self, token: Win16HostDc) -> runtime::Win16HostGdiCleanup {
        self.lock().cleanup_state(token)
    }

    pub(super) fn device_caps(
        &self,
        token: Win16HostDc,
        index: i16,
    ) -> Result<Option<i16>, RuntimeError> {
        let Some(dc_use) = self.lease_dc(token)? else {
            return Ok(None);
        };
        // Windows 3.1 `WINDOWS.H` lists the GetDeviceCaps indexes through
        // COLORRES. A later index, including PHYSICALWIDTH, is not queried.
        Ok(Some(device_caps::project_queried(index, |index| {
            // SAFETY: The HDC lease pins its table identity through this call.
            // The closure runs only for an index the Windows 3.1 header defines.
            unsafe { GetDeviceCaps(dc_use.native(), i32::from(index)) }
        })))
    }

    pub(super) fn reset(
        &self,
        token: Win16HostDc,
        devmode: Option<&Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.lock().reset(self.text_codec, token, devmode)
    }
}

impl Win16DcState {
    fn create_dc(
        &mut self,
        codec: GuestTextCodec,
        driver: Option<&[u8]>,
        device: Option<&[u8]>,
        output: Option<&[u8]>,
        devmode: Option<&Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.create_device_dc(
            codec,
            driver,
            device,
            output,
            devmode,
            false,
            |driver, device, output, mode| {
                // SAFETY: The UTF-16 strings and converted native DEVMODE stay
                // alive for this synchronous GDI call; guest pointers never cross.
                unsafe { CreateDCW(driver, device, output, mode) }
            },
        )
    }

    fn create_ic(
        &mut self,
        codec: GuestTextCodec,
        driver: Option<&[u8]>,
        device: Option<&[u8]>,
        output: Option<&[u8]>,
        devmode: Option<&Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.create_device_dc(
            codec,
            driver,
            device,
            output,
            devmode,
            true,
            |driver, device, output, mode| {
                // SAFETY: The UTF-16 strings and converted native DEVMODE stay
                // alive for this synchronous GDI call; guest pointers never cross.
                unsafe { CreateICW(driver, device, output, mode) }
            },
        )
    }

    fn create_device_dc(
        &mut self,
        codec: GuestTextCodec,
        driver: Option<&[u8]>,
        device: Option<&[u8]>,
        output: Option<&[u8]>,
        devmode: Option<&Win16HostDevMode>,
        information_context: bool,
        create: impl FnOnce(*const u16, *const u16, *const u16, *const DEVMODEW) -> HDC,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        if devmode.is_some_and(|mode| !mode.has_mapped_fields()) {
            return Ok(None);
        }
        let driver = wide_string(codec, driver, "driver")?;
        let device = wide_string(codec, device, "device")?;
        let output = wide_string(codec, output, "output")?;
        let native_mode = devmode
            .map(|mode| native_devmode(mode, codec))
            .transpose()?;
        let native_mode_ptr = native_mode
            .as_ref()
            .map_or(ptr::null(), NativeDevMode::as_ptr);
        let driver_ptr = driver.as_ref().map_or(ptr::null(), |value| value.as_ptr());
        let device_ptr = device.as_ref().map_or(ptr::null(), |value| value.as_ptr());
        let output_ptr = output.as_ref().map_or(ptr::null(), |value| value.as_ptr());
        let native = create(driver_ptr, device_ptr, output_ptr, native_mode_ptr);
        self.record_created(
            native,
            if information_context {
                DcOrigin::Information
            } else {
                DcOrigin::Created
            },
        )
    }

    fn record_created(
        &mut self,
        native: HDC,
        origin: DcOrigin,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        if native.is_null() {
            return Ok(None);
        }
        let Some(next_id) = self.next_id.checked_add(1) else {
            // SAFETY: This is a newly created, owned HDC not yet returned to
            // the runtime; CreateDC/CreateIC contexts require DeleteDC.
            (crate::windows::win32_safe::delete_dc(native));
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 host device-context identity exhausted",
            ));
        };
        let token = Win16HostDc(self.next_id);
        self.next_id = next_id;
        self.objects.insert(
            token,
            NativeDc {
                handle: native as usize,
                origin,
                paint_info: None,
                pin_count: 0,
                release_pending: false,
                retire_on_unpin: false,
            },
        );
        Ok(Some(token))
    }

    fn acquire_screen(&mut self, whole_window: bool) -> Result<Option<Win16HostDc>, RuntimeError> {
        // SAFETY: A null HWND requests the display DC. USER32 owns this DC;
        // it must later be returned with ReleaseDC, never DeleteDC.
        let native = unsafe {
            if whole_window {
                GetWindowDC(ptr::null_mut())
            } else {
                GetDC(ptr::null_mut())
            }
        };
        self.record_screen_dc(native)
    }

    fn record_screen_dc(&mut self, native: HDC) -> Result<Option<Win16HostDc>, RuntimeError> {
        if native.is_null() {
            return Ok(None);
        }
        let Some(next_id) = self.next_id.checked_add(1) else {
            // SAFETY: The unpublished screen DC was acquired on this thread.
            (crate::windows::win32_safe::release_dc(ptr::null_mut(), native));
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 host device-context identity exhausted",
            ));
        };
        let token = Win16HostDc(self.next_id);
        self.next_id = next_id;
        self.objects.insert(
            token,
            NativeDc {
                handle: native as usize,
                origin: DcOrigin::Screen,
                paint_info: None,
                pin_count: 0,
                release_pending: false,
                retire_on_unpin: false,
            },
        );
        Ok(Some(token))
    }

    /// Records a USER worker's borrowed window DC in the common HDC identity
    /// table. The worker remains responsible for its matching ReleaseDC call.
    fn adopt_window_dc(
        &mut self,
        window: Win16HostWindow,
        whole_window: bool,
        raw_hdc: usize,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        let lease = if whole_window {
            WindowDcLease::WholeWindow
        } else {
            WindowDcLease::Client
        };
        self.adopt_window_dc_lease(window, lease, raw_hdc, None)
    }

    /// Records a BeginPaint HDC. EndPaint must run on the window's worker and
    /// the identity is forgotten only after that native call succeeds.
    fn adopt_paint_dc(
        &mut self,
        window: Win16HostWindow,
        raw_hdc: usize,
        paint_info: Win16NativePaintInfo,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.adopt_window_dc_lease(window, WindowDcLease::Paint, raw_hdc, Some(paint_info))
    }

    /// Records the borrowed HDC carried by a synchronous native window
    /// callback. It remains in the common table only while the callback frame
    /// is active; USER owns the HDC and no release operation is performed.
    fn adopt_callback_dc(
        &mut self,
        window: Win16HostWindow,
        raw_hdc: usize,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.adopt_window_dc_lease(window, WindowDcLease::Callback, raw_hdc, None)
    }

    fn adopt_window_dc_lease(
        &mut self,
        window: Win16HostWindow,
        lease: WindowDcLease,
        raw_hdc: usize,
        paint_info: Option<Win16NativePaintInfo>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        self.record_borrowed_dc(DcOrigin::Window { window, lease }, raw_hdc, paint_info)
    }

    fn record_borrowed_dc(
        &mut self,
        origin: DcOrigin,
        raw_hdc: usize,
        paint_info: Option<Win16NativePaintInfo>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        if raw_hdc == 0 {
            return Ok(None);
        }
        let Some(next_id) = self.next_id.checked_add(1) else {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 host device-context identity exhausted",
            ));
        };
        let token = Win16HostDc(self.next_id);
        self.next_id = next_id;
        // SAFETY: `raw_hdc` is supplied only by the USER worker that acquired
        // this HDC; `usize` is its host-only transport representation.
        let handle = raw_hdc;
        self.objects.insert(
            token,
            NativeDc {
                handle,
                origin,
                paint_info,
                pin_count: 0,
                release_pending: false,
                retire_on_unpin: false,
            },
        );
        Ok(Some(token))
    }

    fn native_paint_info(
        &self,
        token: Win16HostDc,
        window: Win16HostWindow,
    ) -> Option<Win16NativePaintInfo> {
        self.window_dc_native(token, window, WindowDcLease::Paint)?;
        self.objects.get(&token)?.paint_info
    }

    fn reset(
        &mut self,
        codec: GuestTextCodec,
        token: Win16HostDc,
        devmode: Option<&Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        if devmode.is_some_and(|mode| !mode.has_mapped_fields()) {
            return Ok(None);
        }
        let native_mode = devmode
            .map(|mode| native_devmode(mode, codec))
            .transpose()?;
        let native_mode_ptr = native_mode
            .as_ref()
            .map_or(ptr::null(), NativeDevMode::as_ptr);
        let Some(dc) = self.objects.get(&token) else {
            return Ok(None);
        };
        let old_handle = dc.handle;
        if !matches!(dc.origin, DcOrigin::Created)
            || dc.retire_on_unpin
            || self.native_group_has_pin_or_pending(old_handle)
        {
            return Ok(None);
        }
        // ResetDC mutates this identity rather than borrowing it for an
        // ordinary GDI call. Existing users are excluded by the pin check;
        // keeping the table mutex through this call prevents a new lease or
        // deletion from racing the handle replacement.
        // SAFETY: The DC is an owned created printer/device DC. The converted
        // DEVMODEW and its private bytes remain alive for the synchronous call.
        let replacement = unsafe { ResetDCW(old_handle as HDC, native_mode_ptr) };
        if replacement.is_null() {
            return Ok(None);
        }
        let replacement_handle = replacement as usize;
        if replacement_handle != old_handle {
            // ResetDCW normally returns the original handle. If the native
            // result differs, only the owned token receives that replacement;
            // aliases of the retired raw handle cannot be rebound to it.
            self.objects
                .retain(|id, alias| *id == token || alias.handle != old_handle);
        }
        let Some(dc) = self.objects.get_mut(&token) else {
            return Ok(None);
        };
        dc.handle = replacement_handle;
        Ok(Some(token))
    }
}

impl Drop for Win16DcState {
    fn drop(&mut self) {
        for (_, native) in std::mem::take(&mut self.objects) {
            // SAFETY: This table recorded the matching acquisition operation.
            {
                match native.origin {
                    DcOrigin::Compatible | DcOrigin::Information | DcOrigin::Created => {
                        crate::windows::win32_safe::delete_dc(native.handle());
                    }
                    DcOrigin::Metafile => {
                        metafile::discard(native.handle());
                    }
                    DcOrigin::Screen => {
                        crate::windows::win32_safe::release_dc(ptr::null_mut(), native.handle());
                    }
                    // A borrowed window HDC must be released by its USER worker.
                    DcOrigin::Window { .. } | DcOrigin::FunctionCallback { .. } => {}
                }
            };
        }
    }
}

fn wide_string(
    codec: GuestTextCodec,
    bytes: Option<&[u8]>,
    field: &str,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    if bytes.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("Win16 GDI {field} string contains an embedded NUL"),
        ));
    }
    codec.to_wide_z(bytes).map(Some)
}

pub(super) struct NativeDevMode {
    allocation: NonNull<u8>,
    layout: Layout,
}

impl NativeDevMode {
    pub(super) fn as_ptr(&self) -> *const DEVMODEW {
        self.allocation.as_ptr().cast()
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, RuntimeError> {
        if bytes.len() < size_of::<DEVMODEW>() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "native DEVMODE buffer is incomplete",
            ));
        }
        let layout =
            Layout::from_size_align(bytes.len(), align_of::<DEVMODEW>()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "native DEVMODE allocation layout is invalid",
                    error,
                )
            })?;
        // SAFETY: The nonzero checked layout has the binding's native alignment.
        let allocation = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "allocate native DEVMODE buffer")
        })?;
        // SAFETY: Source and destination are disjoint allocations of equal size.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), allocation.as_ptr(), bytes.len());
        }
        Ok(Self { allocation, layout })
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        // SAFETY: This wrapper owns and initializes the entire allocation.
        unsafe { std::slice::from_raw_parts(self.allocation.as_ptr(), self.layout.size()) }
    }
}

impl Drop for NativeDevMode {
    fn drop(&mut self) {
        // SAFETY: `allocation` was returned by `alloc_zeroed` with this exact
        // layout and remains exclusively owned by this wrapper.
        unsafe { dealloc(self.allocation.as_ptr(), self.layout) };
    }
}

pub(super) fn native_devmode(
    value: &Win16HostDevMode,
    codec: GuestTextCodec,
) -> Result<NativeDevMode, RuntimeError> {
    if let Some(extra) =
        win16_abi::gdi_abi::decode_wow_devmode_extra(value.public_size, &value.driver_extra)
            .map_err(|_| RuntimeError::new(Kind::InvalidInput, "malformed WOW DEVMODE trailer"))?
    {
        return super::win16_devmode::restore(value, extra, codec);
    }
    let name_end = value
        .device_name
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "Win16 DEVMODE device name is not terminated within its fixed field",
            )
        })?;
    let wide_name = codec.to_wide(&value.device_name[..name_end])?;
    if wide_name.len() >= 32 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 DEVMODE device name exceeds the native UTF-16 field",
        ));
    }
    let native_size = size_of::<DEVMODEW>();
    let Some(native_size_u16) = u16::try_from(native_size).ok() else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native DEVMODEW size does not fit its documented WORD field",
        ));
    };
    let Some(extra_size) = u16::try_from(value.driver_extra.len()).ok() else {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 DEVMODE driver-private data exceeds its WORD length",
        ));
    };
    let allocation_size = native_size
        .checked_add(value.driver_extra.len())
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native DEVMODE buffer size overflow",
            )
        })?;
    let layout =
        Layout::from_size_align(allocation_size, align_of::<DEVMODEW>()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "native DEVMODE allocation layout is invalid",
                error,
            )
        })?;
    // Keep the guest private tail opaque. The native printer driver decides
    // whether its current implementation can consume these bytes.
    // Public extensions are not appended because their layouts have not been
    // translated into the native DEVMODEW representation. The character
    // field is decoded with the executable's fixed guest codec; the Windows
    // binding supplies the host structure layout.
    // SAFETY: The checked layout has nonzero size and DEVMODEW alignment.
    let allocation = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "allocate native DEVMODE buffer")
    })?;
    let owned = NativeDevMode { allocation, layout };

    let mut native = DEVMODEW::default();
    native.dmDeviceName[..wide_name.len()].copy_from_slice(&wide_name);
    // dmSpecVersion describes the host Windows DEVMODE ABI, not the guest's
    // Windows 3.1 version field.
    native.dmSpecVersion = DM_SPECVERSION as u16;
    native.dmDriverVersion = value.driver_version;
    native.dmSize = native_size_u16;
    native.dmDriverExtra = extra_size;
    native.dmFields = value.fields;
    native.Anonymous1 = DEVMODEW_0 {
        Anonymous1: DEVMODEW_0_0 {
            dmOrientation: value.settings[0],
            dmPaperSize: value.settings[1],
            dmPaperLength: value.settings[2],
            dmPaperWidth: value.settings[3],
            dmScale: value.settings[4],
            dmCopies: value.settings[5],
            dmDefaultSource: value.settings[6],
            dmPrintQuality: value.settings[7],
        },
    };
    native.dmColor = value.settings[8];
    native.dmDuplex = value.settings[9];
    native.dmYResolution = value.settings[10];
    native.dmTTOption = value.settings[11];

    // SAFETY: The allocation is aligned and large enough for the structure;
    // the typed value and opaque tail are copied into disjoint ranges that
    // remain owned until the synchronous native call returns.
    unsafe {
        // Write fields separately so the zeroed allocation's padding remains
        // initialized when PRINTDLG copies the complete byte representation.
        let target = owned.allocation.as_ptr().cast::<DEVMODEW>();
        ptr::addr_of_mut!((*target).dmDeviceName).write(native.dmDeviceName);
        ptr::addr_of_mut!((*target).dmSpecVersion).write(native.dmSpecVersion);
        ptr::addr_of_mut!((*target).dmDriverVersion).write(native.dmDriverVersion);
        ptr::addr_of_mut!((*target).dmSize).write(native.dmSize);
        ptr::addr_of_mut!((*target).dmDriverExtra).write(native.dmDriverExtra);
        ptr::addr_of_mut!((*target).dmFields).write(native.dmFields);
        ptr::addr_of_mut!((*target).Anonymous1).write(native.Anonymous1);
        ptr::addr_of_mut!((*target).dmColor).write(native.dmColor);
        ptr::addr_of_mut!((*target).dmDuplex).write(native.dmDuplex);
        ptr::addr_of_mut!((*target).dmYResolution).write(native.dmYResolution);
        ptr::addr_of_mut!((*target).dmTTOption).write(native.dmTTOption);
        if !value.driver_extra.is_empty() {
            ptr::copy_nonoverlapping(
                value.driver_extra.as_ptr(),
                owned.allocation.as_ptr().add(native_size),
                value.driver_extra.len(),
            );
        }
    }

    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Graphics::Gdi::DM_ORIENTATION;

    #[test]
    fn devmode_w_uses_native_size_and_decodes_fixed_guest_name() {
        let codec = GuestTextCodec::new(936).expect("Windows should provide code page 936");
        let mut device_name = [0_u8; 32];
        device_name[..2].copy_from_slice(&[0xd6, 0xd0]); // CP936 "中"
        let value = Win16HostDevMode {
            public_size: 68,
            device_name,
            spec_version: 0x030a,
            driver_version: 7,
            fields: DM_ORIENTATION,
            settings: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            public_extension: Vec::new(),
            driver_extra: vec![0xa5, 0x5a],
        };

        let native = native_devmode(&value, codec).expect("valid Win16 DEVMODE should convert");
        // SAFETY: `native` owns an aligned allocation at least as large as the
        // complete native DEVMODEW object plus its declared private tail.
        let wide = unsafe { &*native.as_ptr() };
        assert_eq!(wide.dmSize as usize, size_of::<DEVMODEW>());
        assert!(wide.dmSize as usize > 68);
        assert_eq!(&wide.dmDeviceName[..2], &[0x4e2d, 0]);
        assert_eq!(wide.dmDriverVersion, 7);
        assert_eq!(wide.dmFields, DM_ORIENTATION);
        assert_eq!(wide.dmDriverExtra, 2);
        // SAFETY: The tail follows the native structure and its two-byte
        // length is the value declared in dmDriverExtra above.
        let tail = unsafe {
            std::slice::from_raw_parts(native.as_ptr().cast::<u8>().add(size_of::<DEVMODEW>()), 2)
        };
        assert_eq!(tail, &[0xa5, 0x5a]);
    }
}

//! Native PRINTDLG adaptation and owned host-global block conversion.

use std::cell::RefCell;
use std::ptr;
use std::rc::Rc;
use std::slice;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCommonDialogResult as ResultValue,
    Win16HostDevMode, Win16HostPrintDialog,
};
use windows_sys::Win32::Foundation::{GlobalFree, HGLOBAL};
use windows_sys::Win32::Graphics::Gdi::{
    DeleteDC, DEVMODEW, DEVMODEW_0, DEVMODEW_0_0,
    DM_ORIENTATION, DM_PAPERSIZE, DM_PAPERLENGTH, DM_PAPERWIDTH, DM_SCALE,
    DM_COPIES, DM_DEFAULTSOURCE, DM_PRINTQUALITY, DM_COLOR, DM_DUPLEX,
    DM_YRESOLUTION, DM_TTOPTION,
};
use windows_sys::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT,
};
use windows_sys::Win32::UI::Controls::Dialogs::{CommDlgExtendedError, PrintDlgW, PRINTDLGW};

use super::LAST_EXTENDED_ERROR;
use super::super::{win16_window_identity, win16_window_worker::WorkerState};

// Windows 3.1's PRINT.H defines the guest DEVMODE version as 0x030A. The
// current SDK binding constant describes the host OS and must not cross ABI.
const WIN31_DM_SPECVERSION: u16 = 0x030A;

pub(super) fn print_dialog(
    state: &Rc<RefCell<WorkerState>>,
    request: Win16HostPrintDialog,
) -> Result<ResultValue, RuntimeError> {
    const HOOK_OR_TEMPLATE: u32 = 0x0003_f000;
    if request.flags & HOOK_OR_TEMPLATE != 0 {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "Win16 PRINTDLG hook or template needs guest callback/resource conversion"));
    }
    let owner = match request.owner {
        Some(token) => win16_window_identity::resolve_user_window(state, token).ok_or_else(|| RuntimeError::new(
            Kind::CompatibilityGap, "Win16 PRINTDLG owner HWND is no longer mapped"))?,
        None => ptr::null_mut(),
    };
    let mut globals = OwnedGlobalBlocks::default();
    let dev_mode = request.dev_mode.as_ref().map(|value| {
        allocate_native_devmode(state, value).map(|block| {
            globals.set_dev_mode(block);
            block
        })
    }).transpose()?;
    let dev_names = request.dev_names.as_ref().map(|value| {
        let wide = super::guest_devnames_to_wide(state, value)?;
        allocate_global_bytes(&wide).map(|block| {
            globals.set_dev_names(block);
            block
        })
    }).transpose()?;

    let mut native = PRINTDLGW {
        lStructSize: std::mem::size_of::<PRINTDLGW>() as u32,
        hwndOwner: owner,
        hDevMode: dev_mode.unwrap_or(ptr::null_mut()),
        hDevNames: dev_names.unwrap_or(ptr::null_mut()),
        // PRINTDLG.hDC is output selected by PD_RETURNDC/PD_RETURNIC; the
        // Win16 input field is never interpreted as a native HDC.
        hDC: ptr::null_mut(),
        Flags: request.flags,
        nFromPage: request.from_page,
        nToPage: request.to_page,
        nMinPage: request.min_page,
        nMaxPage: request.max_page,
        nCopies: request.copies,
        hInstance: ptr::null_mut(),
        lCustData: 0,
        lpfnPrintHook: None,
        lpfnSetupHook: None,
        lpPrintTemplateName: ptr::null(),
        lpSetupTemplateName: ptr::null(),
        hPrintTemplate: ptr::null_mut(),
        hSetupTemplate: ptr::null_mut(),
    };
    // SAFETY: The native structure refers only to the resolved HWND and the
    // two movable global-memory blocks owned by `globals` for this call.
    let accepted = unsafe { PrintDlgW(&mut native) } != 0;
    // SAFETY: Read the common-dialog error state immediately on the same
    // worker thread as the preceding dialog call.
    let extended_error = unsafe { CommDlgExtendedError() } as u32;
    LAST_EXTENDED_ERROR.with(|last| last.set(extended_error));
    // PrintDlg may replace or reallocate either input HGLOBAL. One slot per
    // output prevents freeing a recycled handle twice.
    globals.replace_after_dialog(native.hDevMode, native.hDevNames);

    if !accepted {
        if !native.hDC.is_null() {
            // SAFETY: PrintDlgW returned this new DC but the guest did not
            // accept a print-dialog result that could own it.
            unsafe { DeleteDC(native.hDC); }
        }
        return Ok(ResultValue::Print {
            accepted,
            extended_error,
            dev_mode: request.dev_mode,
            dev_names: request.dev_names,
            dc: None,
            flags: request.flags,
            from_page: request.from_page,
            to_page: request.to_page,
            min_page: request.min_page,
            max_page: request.max_page,
            copies: request.copies,
        });
    }

    let output_data = read_native_devmode(state, native.hDevMode, request.dev_mode.as_ref())
        .and_then(|dev_mode| read_global_bytes(native.hDevNames).and_then(|dev_names| {
            let dev_names = dev_names.map(|bytes| super::native_wide_devnames_to_guest(
                state, &bytes,
            )).transpose()?;
            Ok((dev_mode, dev_names))
        }));
    let (dev_mode, dev_names) = match output_data {
        Ok(data) => data,
        Err(error) => {
            if !native.hDC.is_null() {
                // SAFETY: PrintDlgW returned this new DC and it has not been
                // registered or transferred to the caller.
                unsafe { DeleteDC(native.hDC); }
            }
            return Err(error);
        }
    };
    if let Some(bytes) = &dev_names {
        if let Err(error) = validate_dev_names(bytes) {
            if !native.hDC.is_null() {
                // SAFETY: PrintDlgW returned this new DC and it has not been
                // registered or transferred to the caller.
                unsafe { DeleteDC(native.hDC); }
            }
            return Err(error);
        }
    }
    const PD_RETURNDC: u32 = 0x0000_0100;
    const PD_RETURNIC: u32 = 0x0000_0200;
    let returns_dc = native.Flags & (PD_RETURNDC | PD_RETURNIC) != 0;
    let dc = if returns_dc && !native.hDC.is_null() {
        let dcs = { state.borrow().dcs.clone() };
        match dcs.adopt_created(native.hDC) {
            Ok(Some(token)) => Some(token),
            Ok(None) => {
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "PRINTDLG returned an HDC that could not be registered"));
            }
            Err(error) => {
                // adopt_created consumes the HDC even if token allocation
                // fails, so this branch must not call DeleteDC again.
                return Err(error);
            }
        }
    } else {
        if !native.hDC.is_null() {
            // SAFETY: PrintDlgW returned this new DC, and the guest did not
            // request an HDC result to transfer into its handle table.
            unsafe { DeleteDC(native.hDC); }
        }
        None
    };
    Ok(ResultValue::Print {
        accepted,
        extended_error,
        dev_mode,
        dev_names,
        dc,
        flags: native.Flags,
        from_page: native.nFromPage,
        to_page: native.nToPage,
        min_page: native.nMinPage,
        max_page: native.nMaxPage,
        copies: native.nCopies,
    })
}

struct OwnedGlobalBlocks {
    dev_mode: HGLOBAL,
    dev_names: HGLOBAL,
}

impl OwnedGlobalBlocks {
    fn set_dev_mode(&mut self, block: HGLOBAL) {
        self.dev_mode = block;
    }

    fn set_dev_names(&mut self, block: HGLOBAL) {
        self.dev_names = block;
    }

    fn replace_after_dialog(&mut self, dev_mode: HGLOBAL, dev_names: HGLOBAL) {
        self.dev_mode = dev_mode;
        self.dev_names = dev_names;
    }
}

impl Default for OwnedGlobalBlocks {
    fn default() -> Self {
        Self { dev_mode: ptr::null_mut(), dev_names: ptr::null_mut() }
    }
}

impl Drop for OwnedGlobalBlocks {
    fn drop(&mut self) {
        if !self.dev_mode.is_null() {
            // SAFETY: The slot contains the final HGLOBAL returned by
            // PrintDlg or allocated before it; replaced inputs are discarded.
            unsafe { GlobalFree(self.dev_mode); }
        }
        if !self.dev_names.is_null() && self.dev_names != self.dev_mode {
            // SAFETY: The slot contains a distinct final HGLOBAL returned by
            // PrintDlg or allocated before it.
            unsafe { GlobalFree(self.dev_names); }
        }
    }
}

fn allocate_global_bytes(bytes: &[u8]) -> Result<HGLOBAL, RuntimeError> {
    // SAFETY: GlobalAlloc receives only a byte count; no guest pointer crosses
    // this boundary.
    let block = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes.len()) };
    if block.is_null() {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "allocate native PRINTDLG global memory"));
    }
    // SAFETY: `block` is a live HGLOBAL returned by the allocation above.
    let destination = unsafe { GlobalLock(block) };
    if destination.is_null() {
        // SAFETY: This adapter still owns the just-allocated HGLOBAL.
        unsafe { GlobalFree(block); }
        return Err(RuntimeError::new(Kind::HostFailure,
            "lock native PRINTDLG global memory"));
    }
    // SAFETY: GlobalLock returned a writable block at least `bytes.len()`
    // bytes long and the source slice has that exact readable extent.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), destination.cast(), bytes.len()); }
    // SAFETY: The HGLOBAL was locked exactly once above.
    unsafe { GlobalUnlock(block); }
    Ok(block)
}

fn allocate_native_devmode(
    state: &Rc<RefCell<WorkerState>>,
    value: &Win16HostDevMode,
) -> Result<HGLOBAL, RuntimeError> {
    const CONVERTED_FIELDS: u32 = DM_ORIENTATION | DM_PAPERSIZE | DM_PAPERLENGTH
        | DM_PAPERWIDTH | DM_SCALE | DM_COPIES | DM_DEFAULTSOURCE | DM_PRINTQUALITY
        | DM_COLOR | DM_DUPLEX | DM_YRESOLUTION | DM_TTOPTION;
    if !value.public_extension.is_empty() {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "PRINTDLG cannot translate an extended Win16 DEVMODE layout"));
    }
    if value.fields & !CONVERTED_FIELDS != 0 {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "PRINTDLG DEVMODE selects fields without a verified Win16-to-Windows mapping"));
    }
    if !value.driver_extra.is_empty() {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "Win16 DEVMODE driver-private bytes have no verified mapping to native driver data"));
    }
    let device_name = super::text::fixed_guest_text_to_wide(state,
        &value.device_name,
        "Win16 DEVMODE device name cannot fit the native UTF-16 field")?;
    let native_size = std::mem::size_of::<DEVMODEW>();
    let native_size_u16 = u16::try_from(native_size).map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, "native DEVMODEW size does not fit its WORD field"))?;
    let total = native_size;
    if total > 64 * 1024 {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "native PRINTDLG DEVMODE exceeds the 64 KiB bound"));
    }
    // SAFETY: `total` is bounded and computed from checked native/public sizes.
    let block = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, total) };
    if block.is_null() {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "allocate native PRINTDLG DEVMODE"));
    }
    // SAFETY: `block` is a live HGLOBAL returned by GlobalAlloc above.
    let destination = unsafe { GlobalLock(block) };
    if destination.is_null() {
        // SAFETY: This adapter still owns the just-allocated HGLOBAL.
        unsafe { GlobalFree(block); }
        return Err(RuntimeError::new(Kind::HostFailure,
            "lock native PRINTDLG DEVMODE"));
    }
    let mut native = DEVMODEW::default();
    native.dmDeviceName = device_name;
    native.dmSpecVersion = WIN31_DM_SPECVERSION;
    native.dmDriverVersion = value.driver_version;
    native.dmSize = native_size_u16;
    native.dmDriverExtra = 0;
    native.dmFields = value.fields;
    native.Anonymous1 = DEVMODEW_0 {
        Anonymous1: DEVMODEW_0_0 {
            dmOrientation: value.settings[0], dmPaperSize: value.settings[1],
            dmPaperLength: value.settings[2], dmPaperWidth: value.settings[3],
            dmScale: value.settings[4], dmCopies: value.settings[5],
            dmDefaultSource: value.settings[6], dmPrintQuality: value.settings[7],
        },
    };
    native.dmColor = value.settings[8];
    native.dmDuplex = value.settings[9];
    native.dmYResolution = value.settings[10];
    native.dmTTOption = value.settings[11];
    // SAFETY: The locked allocation is exactly the native public structure;
    // Win16 private bytes are rejected instead of becoming a native driver tail.
    unsafe { destination.cast::<DEVMODEW>().write(native); }
    // SAFETY: The HGLOBAL was locked exactly once above.
    unsafe { GlobalUnlock(block); }
    Ok(block)
}

fn read_global_bytes(block: HGLOBAL) -> Result<Option<Vec<u8>>, RuntimeError> {
    if block.is_null() { return Ok(None); }
    // SAFETY: `block` is a non-null HGLOBAL returned by the common dialog or
    // allocated by this adapter.
    let size = unsafe { GlobalSize(block) };
    if size > 128 * 1024 {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "native Unicode PRINTDLG global block exceeds 128 KiB"));
    }
    if size == 0 { return Ok(Some(Vec::new())); }
    // SAFETY: `block` is a live HGLOBAL and GlobalSize returned a bounded span.
    let source = unsafe { GlobalLock(block) };
    if source.is_null() {
        return Err(RuntimeError::new(Kind::HostFailure,
            "lock native PRINTDLG global block"));
    }
    let mut bytes = Vec::new();
    let reserve = bytes.try_reserve_exact(size).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy native PRINTDLG global block", error));
    if let Err(error) = reserve {
        // SAFETY: GlobalLock succeeded above.
        unsafe { GlobalUnlock(block); }
        return Err(error);
    }
    // SAFETY: GlobalLock returned a readable pointer to `size` bytes, and the
    // size is nonzero and bounded by the check above.
    let view = unsafe { slice::from_raw_parts(source.cast::<u8>(), size) };
    bytes.extend_from_slice(view);
    // SAFETY: GlobalLock succeeded above.
    unsafe { GlobalUnlock(block); }
    Ok(Some(bytes))
}

fn read_native_devmode(
    state: &Rc<RefCell<WorkerState>>,
    block: HGLOBAL,
    previous: Option<&Win16HostDevMode>,
) -> Result<Option<Win16HostDevMode>, RuntimeError> {
    const CONVERTED_FIELDS: u32 = DM_ORIENTATION | DM_PAPERSIZE | DM_PAPERLENGTH
        | DM_PAPERWIDTH | DM_SCALE | DM_COPIES | DM_DEFAULTSOURCE | DM_PRINTQUALITY
        | DM_COLOR | DM_DUPLEX | DM_YRESOLUTION | DM_TTOPTION;
    let Some(bytes) = read_global_bytes(block)? else { return Ok(None); };
    if bytes.len() < std::mem::size_of::<DEVMODEW>() {
        return Err(RuntimeError::new(Kind::HostFailure,
            "native PRINTDLG DEVMODE is shorter than DEVMODEW"));
    }
    // SAFETY: The byte slice is at least `size_of::<DEVMODEW>()` bytes and the
    // unaligned read is confined to that checked prefix.
    let native = unsafe { bytes.as_ptr().cast::<DEVMODEW>().read_unaligned() };
    let public_size = usize::from(native.dmSize);
    let extra_size = usize::from(native.dmDriverExtra);
    if public_size != std::mem::size_of::<DEVMODEW>()
        || public_size.checked_add(extra_size).is_none_or(|total| total > bytes.len())
    {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "native PRINTDLG DEVMODE public extension has no verified Win16 mapping"));
    }
    if native.dmFields & !CONVERTED_FIELDS != 0 {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "native PRINTDLG DEVMODE returns fields without a verified Win16 mapping"));
    }
    let mut value = previous.cloned().unwrap_or_else(|| Win16HostDevMode {
        device_name: [0; 32], spec_version: 0, driver_version: 0,
        fields: 0, settings: [0; 12], public_extension: Vec::new(),
        driver_extra: Vec::new(),
    });
    let device_end = native.dmDeviceName.iter().position(|unit| *unit == 0)
        .unwrap_or(native.dmDeviceName.len());
    let encoded_name = state.borrow().text_codec.from_wide_bounded(
        &native.dmDeviceName[..device_end], 31,
    )?;
    value.device_name = [0; 32];
    value.device_name[..encoded_name.bytes.len()].copy_from_slice(&encoded_name.bytes);
    if encoded_name.truncated {
        super::super::win16_window_position::report_diagnostic(state, Kind::CompatibilityGap,
            "native DEVMODEW device name was truncated to the Win16 fixed-width field");
    }
    if encoded_name.used_default_char == Some(true) {
        super::super::win16_window_position::report_diagnostic(state, Kind::CompatibilityGap,
            "native DEVMODEW device name used guest-code-page replacement characters");
    }
    value.spec_version = WIN31_DM_SPECVERSION;
    value.driver_version = native.dmDriverVersion;
    value.fields = native.dmFields;
    // SAFETY: The complete DEVMODEW prefix was copied above. Its dmFields has
    // been restricted to printer members. This view contains only integers
    // accepting every bit pattern; only dmFields-marked members are meaningful.
    let printer = unsafe { native.Anonymous1.Anonymous1 };
    value.settings = [
        printer.dmOrientation,
        printer.dmPaperSize,
        printer.dmPaperLength,
        printer.dmPaperWidth,
        printer.dmScale,
        printer.dmCopies,
        printer.dmDefaultSource,
        printer.dmPrintQuality,
        native.dmColor, native.dmDuplex, native.dmYResolution, native.dmTTOption,
    ];
    if extra_size != 0 {
        super::super::win16_window_position::report_diagnostic(state,
            Kind::CompatibilityGap,
            "native DEVMODEW driver-private data has no Win16 guest-layout mapping");
    }
    // The trailing bytes are native driver-private data, not a Win16 private
    // tail. They stay inside the owned host HGLOBAL and are never guest output.
    value.driver_extra.clear();
    Ok(Some(value))
}

fn validate_dev_names(bytes: &[u8]) -> Result<(), RuntimeError> {
    if bytes.len() < 8 || bytes.len() > 64 * 1024 {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "PRINTDLG DEVNAMES block has an invalid size"));
    }
    for offset in [0, 2, 4] {
        let start = usize::from(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]));
        if start < 8 || start >= bytes.len() || !bytes[start..].contains(&0) {
            return Err(RuntimeError::new(Kind::CompatibilityGap,
                "PRINTDLG DEVNAMES offset is outside its string table"));
        }
    }
    Ok(())
}

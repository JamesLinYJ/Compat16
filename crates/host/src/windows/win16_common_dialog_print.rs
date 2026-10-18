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
use windows_sys::Win32::Graphics::Gdi::DeleteDC;

use windows_sys::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT,
};
use windows_sys::Win32::UI::Controls::Dialogs::{CommDlgExtendedError, PrintDlgW, PRINTDLGW};

use super::LAST_EXTENDED_ERROR;
use super::super::{win16_window_identity, win16_window_worker::WorkerState};

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

    let output_data = read_native_devmode(state, native.hDevMode)
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
    // The same checked WOW restoration feeds GDI, the printer worker and
    // PRINTDLG. Legacy driver-private data has no known modern layout.
    let native = crate::windows::win16_devmode::printer_input(
        value, state.borrow().text_codec,
    )?;
    allocate_global_bytes(native.as_bytes())
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
) -> Result<Option<Win16HostDevMode>, RuntimeError> {
    let Some(bytes) = read_global_bytes(block)? else { return Ok(None); };
    let projected = crate::windows::win16_devmode::project(&bytes, state.borrow().text_codec)?;
    if projected.truncated {
        super::super::win16_window_position::report_diagnostic(state, Kind::CompatibilityGap,
            "native DEVMODEW fixed names were truncated to Win16 byte fields");
    }
    if projected.used_default_char {
        super::super::win16_window_position::report_diagnostic(state, Kind::CompatibilityGap,
            "native DEVMODEW fixed names used guest-code-page replacement characters");
    }
    Ok(Some(projected.value))
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

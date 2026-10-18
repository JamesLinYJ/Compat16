//! Unicode ExtDeviceMode with owned driver data and the WOW Win3.1 envelope.
use super::{guest_text::GuestTextCodec, native_output_buffer::NativeOutputBuffer};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostPrinterMode, Win16HostPrinterModeResult,
};
use std::{mem::size_of, ptr};
use windows_sys::Win32::{
    Foundation::HWND,
    Graphics::{
        Gdi::DEVMODEW,
        Printing::{
            ClosePrinter, DocumentPropertiesW, OpenPrinterW, PRINTER_HANDLE, PRINTER_INFO_9W,
            SetPrinterW,
        },
    },
    UI::WindowsAndMessaging::{HWND_BROADCAST, SendNotifyMessageW, WM_DEVMODECHANGE},
};
use zerocopy::IntoBytes;

#[path = "win16_printer_mode_merge.rs"]
mod merge;
#[path = "win16_printer_mode_preferences.rs"]
mod preferences;

const DM_UPDATE: u16 = 1;
const DM_COPY: u16 = 2;
const DM_MODIFY: u16 = 8;
const IDOK: i32 = 1;

pub(super) struct Outcome {
    pub result: Win16HostPrinterModeResult,
    pub truncated: bool,
    pub used_default_char: bool,
}

impl Outcome {
    fn status(value: i32) -> Self {
        Self {
            result: Win16HostPrinterModeResult {
                value,
                output: None,
            },
            truncated: false,
            used_default_char: false,
        }
    }
}

struct Printer(PRINTER_HANDLE);
impl Drop for Printer {
    fn drop(&mut self) {
        // SAFETY: This call owns the printer opened by OpenPrinterW.
        unsafe {
            ClosePrinter(self.0);
        }
    }
}

pub(super) fn execute(
    request: Win16HostPrinterMode,
    owner: HWND,
    codec: GuestTextCodec,
) -> Result<Outcome, RuntimeError> {
    // hInst and lpProfile have no native meaning in ExtDeviceMode. Port is
    // retained at the boundary; modern printer selection uses the device name.
    let device = request
        .device
        .as_deref()
        .map(|name| codec.to_wide_z(name))
        .transpose()?;
    let name = device.as_ref().map_or(ptr::null(), |name| name.as_ptr());
    let mut handle = PRINTER_HANDLE {
        Value: ptr::null_mut(),
    };
    // SAFETY: The optional UTF-16 device name stays live; no guest pointer is used.
    if unsafe { OpenPrinterW(name, &mut handle, ptr::null()) } == 0 {
        return Ok(Outcome::status(-1));
    }
    let printer = Printer(handle);
    // SAFETY: The live printer and optional device name identify this query.
    let required =
        unsafe { DocumentPropertiesW(owner, printer.0, name, ptr::null_mut(), ptr::null(), 0) };
    if required <= 0 {
        return Ok(Outcome::status(required));
    }
    let guest_size = projected_size(required)?;
    // WOW queries the size, but never invokes the requested operation, when
    // DM_COPY has no output pointer. Other mode bits must not defeat that rule.
    if size_only(request.mode, request.output_capacity) {
        return Ok(Outcome::status(guest_size as i32));
    }
    if request
        .output_capacity
        .is_some_and(|capacity| capacity < guest_size)
    {
        return Ok(Outcome::status(-1));
    }
    let capacity = required as usize;
    // Use aligned guarded storage because the driver supplies no capacity
    // parameter. Rounding adds at most three initialized padding bytes.
    let count = capacity.div_ceil(size_of::<u32>());
    let mut output = NativeOutputBuffer::<u32>::new(count)?;
    // SAFETY: The queried driver size fits the owned aligned mapping.
    let defaults_status = unsafe {
        DocumentPropertiesW(
            owner,
            printer.0,
            name,
            output.as_mut_ptr().cast(),
            ptr::null(),
            u32::from(DM_COPY),
        )
    };
    if defaults_status != IDOK {
        return Ok(Outcome::status(defaults_status));
    }
    let words = output.copy_prefix(count)?;
    let mut current = copy_bytes(&words.as_bytes()[..capacity])?;
    checked_native(&current)?;
    if let Some(preferences) = preferences::read(printer.0)? {
        if compatible(&current, &preferences) {
            current = preferences;
        }
    }
    if request.mode & DM_MODIFY != 0 {
        if let Some(input) = &request.input {
            let input = super::win16_devmode::printer_input(input, codec)?;
            merge::apply(&mut current, input.as_bytes())?;
        }
    }
    let input = super::win16_gdi::NativeDevMode::from_bytes(&current)?;
    // As in WOW, feed the per-user defaults even without DM_MODIFY. DM_UPDATE
    // needs a private output copy to persist, independently of guest DM_COPY.
    let native_mode = native_flags(request.mode);
    // SAFETY: Both buffers are owned, aligned and bounded. The UI worker owns
    // owner and remains available to the existing guest-callback continuation.
    let value = unsafe {
        DocumentPropertiesW(
            owner,
            printer.0,
            name,
            output.as_mut_ptr().cast(),
            input.as_ptr(),
            native_mode,
        )
    };
    if value != IDOK {
        return Ok(Outcome::status(value));
    }
    if request.mode & (DM_COPY | DM_UPDATE) == 0 {
        return Ok(Outcome::status(value));
    }
    let words = output.copy_prefix(count)?;
    let bytes = &words.as_bytes()[..capacity];
    checked_native(bytes)?;
    if request.mode & DM_UPDATE != 0 {
        let info = PRINTER_INFO_9W {
            pDevMode: output.as_mut_ptr().cast(),
        };
        // SAFETY: Level 9 writes this user's defaults; the checked DEVMODE
        // remains owned until the synchronous Windows call returns.
        if unsafe { SetPrinterW(printer.0, 9, (&info as *const PRINTER_INFO_9W).cast(), 0) } == 0 {
            return Ok(Outcome::status(-1));
        }
        // SAFETY: WM_DEVMODECHANGE is a system string message. USER performs
        // its documented marshalling; this name stays live through the call.
        unsafe {
            SendNotifyMessageW(HWND_BROADCAST, WM_DEVMODECHANGE, 0, name as isize);
        }
    }
    if request.mode & DM_COPY == 0 {
        return Ok(Outcome::status(value));
    }
    let projected = super::win16_devmode::project(bytes, codec)?;
    Ok(Outcome {
        result: Win16HostPrinterModeResult {
            value,
            output: Some(projected.value),
        },
        truncated: projected.truncated,
        used_default_char: projected.used_default_char,
    })
}

fn projected_size(native: i32) -> Result<usize, RuntimeError> {
    // Preserve native private length, replacing the native public prefix by
    // the checked Win3.1 prefix plus the shared WOW extension and trailer.
    usize::try_from(native)
        .ok()
        .filter(|size| *size >= size_of::<DEVMODEW>())
        .and_then(|size| {
            size.checked_sub(size_of::<DEVMODEW>())?.checked_add(
                win16_abi::gdi_abi::DEVMODE16_SIZE + super::win16_devmode::WOW_EXTRA_OVERHEAD,
            )
        })
        .filter(|size| *size <= usize::from(u16::MAX))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "printer DEVMODE cannot be represented by the Win16 size query",
            )
        })
}

fn size_only(mode: u16, output: Option<usize>) -> bool {
    mode == 0 || (mode & DM_COPY != 0 && output.is_none())
}

fn native_flags(mode: u16) -> u32 {
    u32::from(mode | DM_MODIFY | if mode & DM_UPDATE != 0 { DM_COPY } else { 0 })
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut result = Vec::new();
    result.try_reserve_exact(bytes.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy owned printer settings",
            error,
        )
    })?;
    result.extend_from_slice(bytes);
    Ok(result)
}

fn checked_native(bytes: &[u8]) -> Result<DEVMODEW, RuntimeError> {
    if bytes.len() < size_of::<DEVMODEW>() {
        return Err(bad_mode());
    }
    // SAFETY: The checked prefix has no pointers and accepts all bit patterns.
    let mode = unsafe { bytes.as_ptr().cast::<DEVMODEW>().read_unaligned() };
    if usize::from(mode.dmSize) != size_of::<DEVMODEW>()
        || usize::from(mode.dmSize)
            .checked_add(usize::from(mode.dmDriverExtra))
            .is_none_or(|size| size > bytes.len())
    {
        return Err(bad_mode());
    }
    Ok(mode)
}

fn compatible(current: &[u8], saved: &[u8]) -> bool {
    match (checked_native(current), checked_native(saved)) {
        (Ok(left), Ok(right)) => {
            left.dmSpecVersion == right.dmSpecVersion
                && left.dmDriverVersion == right.dmDriverVersion
                && left.dmSize == right.dmSize
                && left.dmDriverExtra == right.dmDriverExtra
        }
        _ => false,
    }
}

fn bad_mode() -> RuntimeError {
    RuntimeError::new(
        Kind::CompatibilityGap,
        "printer returned an unsupported or truncated DEVMODEW",
    )
}

#[cfg(test)]
#[path = "win16_printer_mode_tests.rs"]
mod tests;

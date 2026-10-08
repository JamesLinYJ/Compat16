//! Windows adapter for the Win16 WINSPOOL DeviceCapabilities export.
//!
//! The Win16 indices, DEVMODE fields, fixed-name widths, and POINT outputs
//! follow the Windows 3.1 SDK PRINT.H and DeviceCapabilities contract. Native
//! calls use the Windows Unicode API. Guest names use the executable's fixed
//! code page; DEVMODE and fixed-width name records are projected explicitly.

use std::mem::{align_of, offset_of, size_of};
use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DrawingPoint,
    Win16PrinterCapabilities, Win16PrinterCapabilitiesResult,
    Win16PrinterCapabilityData,
};
use windows_sys::Win32::Foundation::POINT;
use windows_sys::Win32::Graphics::Gdi::{
    DM_COLOR, DM_COPIES, DM_DEFAULTSOURCE, DM_DUPLEX,
    DM_ORIENTATION, DM_PAPERLENGTH, DM_PAPERSIZE, DM_PAPERWIDTH,
    DM_PRINTQUALITY, DM_SCALE, DM_TTOPTION, DM_YRESOLUTION,
};
use windows_sys::Win32::Storage::Xps::DeviceCapabilitiesW;
use zerocopy::{FromBytes, Immutable, KnownLayout};

use super::guest_text::GuestTextCodec;
use super::win16_gdi::{native_devmode, NativeDevMode};

const DC_FIELDS: u16 = 1;
const DC_PAPERS: u16 = 2;
const DC_PAPERSIZE: u16 = 3;
const DC_MINEXTENT: u16 = 4;
const DC_MAXEXTENT: u16 = 5;
const DC_BINS: u16 = 6;
const DC_DUPLEX: u16 = 7;
const DC_SIZE: u16 = 8;
const DC_EXTRA: u16 = 9;
const DC_VERSION: u16 = 10;
const DC_DRIVER: u16 = 11;
const DC_BINNAMES: u16 = 12;
const DC_ENUMRESOLUTIONS: u16 = 13;
const DC_FILEDEPENDENCIES: u16 = 14;
const DC_TRUETYPE: u16 = 15;
const DC_PAPERNAMES: u16 = 16;
const DC_ORIENTATION: u16 = 17;
const DC_COPIES: u16 = 18;

const WIN16_DEVMODE_SIZE: u32 = 68;
const WIN16_DM_SPECVERSION: u32 = 0x030a;

// PRINT.H's supported Windows 3.1 DEVMODE bits are listed explicitly. Later
// host-only DEVMODE fields must not leak through DC_FIELDS or a guest input.
const WIN16_DEVMODE_FIELDS: [(u32, u32); 12] = [
    (DM_ORIENTATION, 0x0000_0001),
    (DM_PAPERSIZE, 0x0000_0002),
    (DM_PAPERLENGTH, 0x0000_0004),
    (DM_PAPERWIDTH, 0x0000_0008),
    (DM_SCALE, 0x0000_0010),
    (DM_COPIES, 0x0000_0100),
    (DM_DEFAULTSOURCE, 0x0000_0200),
    (DM_PRINTQUALITY, 0x0000_0400),
    (DM_COLOR, 0x0000_0800),
    (DM_DUPLEX, 0x0000_1000),
    (DM_YRESOLUTION, 0x0000_2000),
    (DM_TTOPTION, 0x0000_4000),
];

// windows-sys exposes POINT without zerocopy's FromBytes guarantee. This
// private readback record is checked against that binding and is never used
// to redefine the Windows declaration or as a guest wire structure.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, KnownLayout, Immutable)]
struct NativePointOutput {
    x: i32,
    y: i32,
}

const _: () = {
    assert!(size_of::<NativePointOutput>() == size_of::<POINT>());
    assert!(align_of::<NativePointOutput>() == align_of::<POINT>());
    assert!(offset_of!(NativePointOutput, x) == offset_of!(POINT, x));
    assert!(offset_of!(NativePointOutput, y) == offset_of!(POINT, y));
};

pub(super) fn capabilities(
    request: Win16PrinterCapabilities,
    code_page: u32,
) -> Result<Win16PrinterCapabilitiesResult, RuntimeError> {
    if request.collect_output
        && !is_array_capability(request.index)
        && !is_scalar_capability(request.index)
    {
        return Err(unknown_output_layout(request.index));
    }
    super::printer_worker::capabilities(request, code_page)
}

/// The isolated native worker is the only caller allowed to pass writable
/// storage to DeviceCapabilitiesW. Its output pointer terminates at a guard
/// page; native overruns terminate that process before they can reach the
/// runtime process. This boundary is not a sandbox for arbitrary driver code.
pub(super) fn capabilities_in_worker(
    request: Win16PrinterCapabilities,
    code_page: u32,
) -> Result<Win16PrinterCapabilitiesResult, RuntimeError> {
    let codec = GuestTextCodec::new(code_page)?;
    let inputs = NativeInputs::from_request(&request, codec)?;
    if !request.collect_output || is_scalar_capability(request.index) {
        let native_value = inputs.query(request.index, ptr::null_mut());
        return Ok(value_result(request.index, native_value));
    }

    if is_array_capability(request.index) {
        return array_capabilities(&request, &inputs, codec);
    }
    Err(unknown_output_layout(request.index))
}

fn is_scalar_capability(index: u16) -> bool {
    matches!(index,
        DC_FIELDS | DC_MINEXTENT | DC_MAXEXTENT | DC_DUPLEX | DC_SIZE | DC_EXTRA
        | DC_VERSION | DC_DRIVER | DC_TRUETYPE | DC_ORIENTATION | DC_COPIES)
}

fn is_array_capability(index: u16) -> bool {
    matches!(index,
        DC_PAPERS | DC_PAPERSIZE | DC_BINS | DC_BINNAMES | DC_ENUMRESOLUTIONS
        | DC_FILEDEPENDENCIES | DC_PAPERNAMES)
}

fn unknown_output_layout(index: u16) -> RuntimeError {
    RuntimeError::new(Kind::CompatibilityGap, format!(
        "Win16 DeviceCapabilities index {index} has no verified output layout"))
}

fn array_capabilities(
    request: &Win16PrinterCapabilities,
    inputs: &NativeInputs,
    codec: GuestTextCodec,
) -> Result<Win16PrinterCapabilitiesResult, RuntimeError> {
    match request.index {
        DC_PAPERS | DC_BINS => {
            let (native_value, values) = query_array::<u16>(inputs, request.index, 1)?;
            Ok(array_result(request.index, native_value,
                values.map(Win16PrinterCapabilityData::Words)))
        }
        DC_PAPERSIZE => {
            let (native_value, values) = query_array::<NativePointOutput>(inputs, request.index, 1)?;
            let points = values.map(points_from_native).transpose()?;
            Ok(array_result(request.index, native_value,
                points.map(Win16PrinterCapabilityData::Points)))
        }
        DC_BINNAMES => {
            let (native_value, bytes) = query_names(inputs, request.index, 24, codec)?;
            Ok(array_result(request.index, native_value, bytes.map(|bytes| {
                Win16PrinterCapabilityData::Names { record_bytes: 24, bytes }
            })))
        }
        DC_ENUMRESOLUTIONS => {
            let (native_value, values) = query_array::<i32>(inputs, request.index, 2)?;
            let pairs = values.map(resolution_pairs).transpose()?;
            Ok(array_result(request.index, native_value,
                pairs.map(Win16PrinterCapabilityData::ResolutionPairs)))
        }
        DC_FILEDEPENDENCIES | DC_PAPERNAMES => {
            let (native_value, bytes) = query_names(inputs, request.index, 64, codec)?;
            Ok(array_result(request.index, native_value, bytes.map(|bytes| {
                Win16PrinterCapabilityData::Names { record_bytes: 64, bytes }
            })))
        }
        index => Err(unknown_output_layout(index)),
    }
}

struct NativeInputs {
    device: Option<Vec<u16>>,
    port: Option<Vec<u16>>,
    devmode: Option<NativeDevMode>,
}

impl NativeInputs {
    fn from_request(
        request: &Win16PrinterCapabilities,
        codec: GuestTextCodec,
    ) -> Result<Self, RuntimeError> {
        let device = wide_input(codec, request.device.as_deref(), "device")?;
        let port = wide_input(codec, request.port.as_deref(), "port")?;
        let devmode = request.devmode.as_ref()
            .map(|value| native_input_devmode(value, codec)).transpose()?;
        Ok(Self { device, port, devmode })
    }

    fn query(&self, index: u16, output: *mut core::ffi::c_void) -> i32 {
        let device = self.device.as_ref().map_or(ptr::null(), |name| name.as_ptr());
        let port = self.port.as_ref().map_or(ptr::null(), |name| name.as_ptr());
        let devmode = self.devmode.as_ref().map_or(ptr::null(), NativeDevMode::as_ptr);
        // SAFETY: Optional UTF-16 strings and converted DEVMODE remain owned by
        // self. A non-NULL output pointer is only supplied by
        // capabilities_in_worker and ends at its inaccessible guard page.
        unsafe { DeviceCapabilitiesW(device, port, index, output.cast(), devmode) }
    }
}

fn native_input_devmode(
    value: &runtime::Win16HostDevMode,
    codec: GuestTextCodec,
) -> Result<NativeDevMode, RuntimeError> {
    if !value.public_extension.is_empty() {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "Win16 DeviceCapabilities cannot translate DEVMODE public-extension bytes"));
    }
    if !value.driver_extra.is_empty() {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "Win16 DeviceCapabilities cannot consume host printer-driver private DEVMODE bytes"));
    }
    let supported = WIN16_DEVMODE_FIELDS.iter().fold(0, |mask, (native, _)| mask | *native);
    if value.fields & !supported != 0 {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "Win16 DeviceCapabilities cannot translate unknown DEVMODE field bits"));
    }
    // Reuse the GDI adapter's native DEVMODEW conversion and owned lifetime;
    // the checks above prevent its opaque private-tail path from being used.
    native_devmode(value, codec)
}

fn wide_input(
    codec: GuestTextCodec,
    bytes: Option<&[u8]>,
    label: &str,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let Some(bytes) = bytes else { return Ok(None); };
    if bytes.contains(&0) {
        return Err(RuntimeError::new(Kind::InvalidInput,
            format!("Win16 printer {label} contains an embedded NUL")));
    }
    codec.to_wide_z(bytes).map(Some)
}

fn query_names(
    inputs: &NativeInputs,
    index: u16,
    record_units: usize,
    codec: GuestTextCodec,
) -> Result<(i32, Option<Vec<u8>>), RuntimeError> {
    let (native_value, units) = query_array::<u16>(inputs, index, record_units)?;
    let Some(units) = units else { return Ok((native_value, None)); };
    encode_name_records(codec, &units, record_units).map(|bytes| (native_value, Some(bytes)))
}

fn encode_name_records(
    codec: GuestTextCodec,
    native: &[u16],
    record_units: usize,
) -> Result<Vec<u8>, RuntimeError> {
    if record_units == 0 || native.len() % record_units != 0 {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native printer name array ended inside a fixed WCHAR record"));
    }
    // Win16 PRINT.H exposes fixed ANSI record widths. DeviceCapabilitiesW
    // returns WCHAR records of the same unit count; convert each name
    // separately and retain the guest record size and NUL padding.
    let record_bytes = record_units;
    let records = native.len() / record_units;
    let output_size = records.checked_mul(record_bytes).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "Win16 printer name output size overflow"))?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_size).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate Win16 printer name records", error))?;
    for record in native.chunks_exact(record_units) {
        let end = record.iter().position(|unit| *unit == 0).unwrap_or(record.len());
        let converted = codec.from_wide_bounded(&record[..end], record_bytes)?;
        output.extend_from_slice(&converted.bytes);
        output.resize(output.len() + record_bytes - converted.bytes.len(), 0);
    }
    Ok(output)
}

fn query_array<T: FromBytes + Copy + Default>(
    inputs: &NativeInputs,
    index: u16,
    native_components_per_record: usize,
) -> Result<(i32, Option<Vec<T>>), RuntimeError> {
    // DeviceCapabilities specifies NULL-output queries as the count pass for
    // fixed arrays, but has no capacity argument and does not promise the
    // count is a snapshot. This function only runs in the disposable worker;
    // the guard mapping contains a changed second-call count.
    let count = inputs.query(index, ptr::null_mut());
    if count < 0 { return Ok((count, None)); }
    let count = usize::try_from(count).map_err(|error| RuntimeError::with_source(
        Kind::HostFailure, "printer capability count does not fit host usize", error))?;
    let native_count = count.checked_mul(native_components_per_record).ok_or_else(||
        RuntimeError::new(Kind::ResourceExhausted, "native printer array count overflow"))?;
    if native_count == 0 { return Ok((0, Some(Vec::new()))); }

    let mut output = super::native_output_buffer::NativeOutputBuffer::<T>::new(native_count)?;

    let copied = inputs.query(index, output.as_mut_ptr().cast());
    if copied < 0 { return Ok((copied, None)); }
    let copied_count = usize::try_from(copied).map_err(|error| RuntimeError::with_source(
        Kind::HostFailure, "printer capability result count does not fit host usize", error))?;
    if copied_count > count {
        return Err(RuntimeError::new(Kind::HostFailure,
            "printer driver returned more records than its count query"));
    }
    let copied_elements = copied_count.checked_mul(native_components_per_record).ok_or_else(||
        RuntimeError::new(Kind::InternalInvariant, "printer output truncation overflow"))?;
    Ok((copied, Some(output.copy_prefix(copied_elements)?)))
}

fn points_from_native(
    points: Vec<NativePointOutput>,
) -> Result<Vec<Win16DrawingPoint>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(points.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "convert native printer POINT array", error))?;
    output.extend(points.into_iter().map(|point| Win16DrawingPoint { x: point.x, y: point.y }));
    Ok(output)
}

fn resolution_pairs(values: Vec<i32>) -> Result<Vec<[i32; 2]>, RuntimeError> {
    if values.len() % 2 != 0 {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native printer resolution array ended inside a LONG pair"));
    }
    let mut pairs = Vec::new();
    pairs.try_reserve_exact(values.len() / 2).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "convert printer resolution pairs", error))?;
    pairs.extend(values.chunks_exact(2).map(|pair| [pair[0], pair[1]]));
    Ok(pairs)
}

fn value_result(index: u16, native_value: i32) -> Win16PrinterCapabilitiesResult {
    Win16PrinterCapabilitiesResult {
        value: project_value(index, native_value),
        output: None,
    }
}

fn array_result(
    index: u16,
    native_value: i32,
    output: Option<Win16PrinterCapabilityData>,
) -> Win16PrinterCapabilitiesResult {
    Win16PrinterCapabilitiesResult {
        value: project_value(index, native_value),
        output,
    }
}

fn project_value(index: u16, native_value: i32) -> u32 {
    if native_value == -1 { return u32::MAX; }
    match index {
        DC_FIELDS => project_devmode_fields(native_value as u32),
        DC_SIZE if native_value > 0 => WIN16_DEVMODE_SIZE,
        DC_VERSION if native_value > 0 => WIN16_DM_SPECVERSION,
        DC_EXTRA => {
            // Preserve the native driver's reported private-byte count. No
            // private bytes are converted or claimed portable; such a tail is
            // rejected if a later Win16 request supplies it as DEVMODE input.
            native_value as u32
        }
        _ => native_value as u32,
    }
}

fn project_devmode_fields(native_fields: u32) -> u32 {
    WIN16_DEVMODE_FIELDS.iter().fold(0, |guest, (native, target)| {
        if native_fields & *native != 0 { guest | *target } else { guest }
    })
}

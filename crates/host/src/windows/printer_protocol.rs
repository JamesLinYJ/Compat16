//! Private, bounded request/response protocol for the printer worker process.

use std::io::{Read, Write};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DrawingPoint, Win16HostDevMode,
    Win16PrinterCapabilities, Win16PrinterCapabilitiesResult, Win16PrinterCapabilityData,
};
use serde::{Deserialize, Serialize};
use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const FRAME_MAGIC: [u8; 4] = *b"W16P";
const PROTOCOL_VERSION: u16 = 3;
const OP_DEVICE_CAPABILITIES: u16 = 1;
/// Per-direction IPC resource budget, independent of the Win16 segment limit.
pub(super) const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const FRAME_HEADER_BYTES: usize = 10;

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct FrameHeader {
    magic: [u8; 4],
    version: U16,
    payload_len: U32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    version: u16,
    operation: u16,
    index: u16,
    code_page: u32,
    request: RequestBody,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestBody {
    device: Option<Vec<u8>>,
    port: Option<Vec<u8>>,
    collect_output: bool,
    devmode: Option<DevModeWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevModeWire {
    public_size: u16,
    device_name: [u8; 32],
    spec_version: u16,
    driver_version: u16,
    fields: u32,
    settings: [i16; 12],
    public_extension: Vec<u8>,
    driver_extra: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    version: u16,
    operation: u16,
    index: u16,
    response: ResponseBody,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ResponseBody {
    Result { value: u32, output: Option<CapabilityDataWire> },
    Error { error: WireError },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CapabilityDataWire {
    Words { values: Vec<u16> },
    Points { values: Vec<PointWire> },
    ResolutionPairs { values: Vec<[i32; 2]> },
    Names { record_bytes: u16, bytes: Vec<u8> },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PointWire {
    x: i32,
    y: i32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    kind: WireErrorKind,
    message: String,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireErrorKind {
    CompatibilityGap,
    GuestFault,
    InvalidInput,
    HostFailure,
    ResourceExhausted,
    ExecutionLimit,
    InternalInvariant,
}

impl From<Kind> for WireErrorKind {
    fn from(value: Kind) -> Self {
        match value {
            Kind::CompatibilityGap => Self::CompatibilityGap,
            Kind::GuestFault => Self::GuestFault,
            Kind::InvalidInput => Self::InvalidInput,
            Kind::HostFailure => Self::HostFailure,
            Kind::ResourceExhausted => Self::ResourceExhausted,
            Kind::ExecutionLimit => Self::ExecutionLimit,
            Kind::InternalInvariant => Self::InternalInvariant,
        }
    }
}

impl From<WireErrorKind> for Kind {
    fn from(value: WireErrorKind) -> Self {
        match value {
            WireErrorKind::CompatibilityGap => Self::CompatibilityGap,
            WireErrorKind::GuestFault => Self::GuestFault,
            WireErrorKind::InvalidInput => Self::InvalidInput,
            WireErrorKind::HostFailure => Self::HostFailure,
            WireErrorKind::ResourceExhausted => Self::ResourceExhausted,
            WireErrorKind::ExecutionLimit => Self::ExecutionLimit,
            WireErrorKind::InternalInvariant => Self::InternalInvariant,
        }
    }
}

pub(super) fn write_request(
    writer: &mut impl Write,
    request: &Win16PrinterCapabilities,
    code_page: u32,
) -> Result<(), RuntimeError> {
    let envelope = RequestEnvelope {
        version: PROTOCOL_VERSION,
        operation: OP_DEVICE_CAPABILITIES,
        index: request.index,
        code_page,
        request: RequestBody {
            device: request.device.clone(),
            port: request.port.clone(),
            collect_output: request.collect_output,
            devmode: request.devmode.as_ref().map(devmode_to_wire),
        },
    };
    let payload = serialize_bounded(&envelope, "serialize printer worker request")?;
    write_frame(writer, &payload)
}

pub(super) fn read_request(
    reader: &mut impl Read,
) -> Result<(Win16PrinterCapabilities, u32), RuntimeError> {
    let payload = read_frame(reader, Kind::InvalidInput, "printer worker request")?;
    let envelope: RequestEnvelope = serde_json::from_slice(&payload).map_err(|error| {
        RuntimeError::with_source(Kind::InvalidInput,
            "decode printer worker request schema", error)
    })?;
    if envelope.version != PROTOCOL_VERSION || envelope.operation != OP_DEVICE_CAPABILITIES {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "printer worker request uses an unsupported version or operation"));
    }
    Ok((Win16PrinterCapabilities {
        device: envelope.request.device,
        port: envelope.request.port,
        index: envelope.index,
        collect_output: envelope.request.collect_output,
        devmode: envelope.request.devmode.map(devmode_from_wire),
    }, envelope.code_page))
}

pub(super) fn write_response(
    writer: &mut impl Write,
    index: u16,
    response: Result<Win16PrinterCapabilitiesResult, RuntimeError>,
) -> Result<(), RuntimeError> {
    let response = match response {
        Ok(result) => ResponseBody::Result {
            value: result.value,
            output: match result.output.map(data_to_wire).transpose() {
                Ok(output) => output,
                Err(error) => {
                    return write_response_error(writer, index, error);
                }
            },
        },
        Err(error) => ResponseBody::Error {
            error: WireError { kind: error.kind().into(), message: error.to_string() },
        },
    };
    let envelope = ResponseEnvelope {
        version: PROTOCOL_VERSION,
        operation: OP_DEVICE_CAPABILITIES,
        index,
        response,
    };
    let payload = match serialize_bounded(&envelope, "serialize printer worker response") {
        Ok(payload) => payload,
        Err(error) if error.kind() == Kind::ResourceExhausted => {
            // Keep an oversized native result typed across the IPC boundary.
            // Only the bounded error record is sent; the original result is
            // discarded before it can exceed the channel resource policy.
            let fallback = ResponseEnvelope {
                version: PROTOCOL_VERSION,
                operation: OP_DEVICE_CAPABILITIES,
                index,
                response: ResponseBody::Error {
                    error: WireError {
                        kind: WireErrorKind::ResourceExhausted,
                        message: "printer worker response exceeds the 8 MiB channel budget".into(),
                    },
                },
            };
            serialize_bounded(&fallback, "serialize printer worker size error")?
        }
        Err(error) => return Err(error),
    };
    write_frame(writer, &payload)
}

pub(super) fn read_response(
    reader: &mut impl Read,
    expected_index: u16,
    collect_output: bool,
) -> Result<Win16PrinterCapabilitiesResult, RuntimeError> {
    let payload = read_frame(reader, Kind::HostFailure, "printer worker response")?;
    let envelope: ResponseEnvelope = serde_json::from_slice(&payload).map_err(|error| {
        RuntimeError::with_source(Kind::HostFailure,
            "decode printer worker response schema", error)
    })?;
    if envelope.version != PROTOCOL_VERSION
        || envelope.operation != OP_DEVICE_CAPABILITIES
        || envelope.index != expected_index
    {
        return Err(RuntimeError::new(Kind::HostFailure,
            "printer worker response version, operation, or index does not match the request"));
    }
    match envelope.response {
        ResponseBody::Error { error } => Err(RuntimeError::new(
            error.kind.into(), format!("printer worker reported: {}", error.message),
        )),
        ResponseBody::Result { value, output } => {
            let result = Win16PrinterCapabilitiesResult {
                value,
                output: output.map(data_from_wire).transpose()?,
            };
            validate_result(expected_index, collect_output, &result)?;
            Ok(result)
        }
    }
}

fn devmode_to_wire(value: &Win16HostDevMode) -> DevModeWire {
    DevModeWire {
        public_size: value.public_size,
        device_name: value.device_name,
        spec_version: value.spec_version,
        driver_version: value.driver_version,
        fields: value.fields,
        settings: value.settings,
        public_extension: value.public_extension.clone(),
        driver_extra: value.driver_extra.clone(),
    }
}

fn devmode_from_wire(value: DevModeWire) -> Win16HostDevMode {
    Win16HostDevMode {
        public_size: value.public_size,
        device_name: value.device_name,
        spec_version: value.spec_version,
        driver_version: value.driver_version,
        fields: value.fields,
        settings: value.settings,
        public_extension: value.public_extension,
        driver_extra: value.driver_extra,
    }
}

fn data_to_wire(value: Win16PrinterCapabilityData) -> Result<CapabilityDataWire, RuntimeError> {
    Ok(match value {
        Win16PrinterCapabilityData::Words(values) => CapabilityDataWire::Words { values },
        Win16PrinterCapabilityData::Points(values) => {
            let mut points = Vec::new();
            points.try_reserve_exact(values.len()).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "allocate printer worker POINT response", error,
            ))?;
            points.extend(values.into_iter().map(|point| PointWire { x: point.x, y: point.y }));
            CapabilityDataWire::Points { values: points }
        }
        Win16PrinterCapabilityData::ResolutionPairs(values) =>
            CapabilityDataWire::ResolutionPairs { values },
        Win16PrinterCapabilityData::Names { record_bytes, bytes } =>
            CapabilityDataWire::Names { record_bytes, bytes },
    })
}

fn data_from_wire(value: CapabilityDataWire) -> Result<Win16PrinterCapabilityData, RuntimeError> {
    Ok(match value {
        CapabilityDataWire::Words { values } => Win16PrinterCapabilityData::Words(values),
        CapabilityDataWire::Points { values } => {
            let mut points = Vec::new();
            points.try_reserve_exact(values.len()).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "allocate printer worker POINT result", error,
            ))?;
            points.extend(values.into_iter().map(|point| Win16DrawingPoint { x: point.x, y: point.y }));
            Win16PrinterCapabilityData::Points(points)
        }
        CapabilityDataWire::ResolutionPairs { values } =>
            Win16PrinterCapabilityData::ResolutionPairs(values),
        CapabilityDataWire::Names { record_bytes, bytes } =>
            Win16PrinterCapabilityData::Names { record_bytes, bytes },
    })
}

fn write_response_error(
    writer: &mut impl Write,
    index: u16,
    error: RuntimeError,
) -> Result<(), RuntimeError> {
    let envelope = ResponseEnvelope {
        version: PROTOCOL_VERSION,
        operation: OP_DEVICE_CAPABILITIES,
        index,
        response: ResponseBody::Error {
            error: WireError { kind: error.kind().into(), message: error.to_string() },
        },
    };
    let payload = serialize_bounded(&envelope, "serialize printer worker response error")?;
    write_frame(writer, &payload)
}

fn validate_result(
    index: u16,
    collect_output: bool,
    result: &Win16PrinterCapabilitiesResult,
) -> Result<(), RuntimeError> {
    if result.value == u32::MAX || !collect_output {
        if result.output.is_some() {
            return Err(worker_shape_error());
        }
        return Ok(());
    }
    let output = match index {
        2 | 6 => Some(OutputShape::Words),
        3 => Some(OutputShape::Points),
        12 => Some(OutputShape::Names { record_bytes: 24 }),
        13 => Some(OutputShape::ResolutionPairs),
        14 | 16 => Some(OutputShape::Names { record_bytes: 64 }),
        1 | 4 | 5 | 7 | 8 | 9 | 10 | 11 | 15 | 17 | 18 => None,
        _ => return Err(RuntimeError::new(Kind::HostFailure,
            "printer worker returned data for an index without a verified output shape")),
    };
    let Some(shape) = output else {
        if result.output.is_some() { return Err(worker_shape_error()); }
        return Ok(());
    };
    let data = result.output.as_ref().ok_or_else(worker_shape_error)?;
    let count = match (shape, data) {
        (OutputShape::Words, Win16PrinterCapabilityData::Words(values)) => values.len(),
        (OutputShape::Points, Win16PrinterCapabilityData::Points(values)) => values.len(),
        (OutputShape::ResolutionPairs, Win16PrinterCapabilityData::ResolutionPairs(values)) => values.len(),
        (OutputShape::Names { record_bytes }, Win16PrinterCapabilityData::Names { record_bytes: actual, bytes })
            if *actual == record_bytes && *actual != 0 && bytes.len() % usize::from(*actual) == 0 =>
        {
            bytes.len() / usize::from(*actual)
        }
        _ => return Err(worker_shape_error()),
    };
    let count = u32::try_from(count).map_err(|error| RuntimeError::with_source(
        Kind::HostFailure, "printer worker output count exceeds DWORD", error))?;
    if count != result.value { return Err(worker_shape_error()); }
    Ok(())
}

#[derive(Clone, Copy)]
enum OutputShape {
    Words,
    Points,
    ResolutionPairs,
    Names { record_bytes: u16 },
}

fn worker_shape_error() -> RuntimeError {
    RuntimeError::new(Kind::HostFailure,
        "printer worker returned an invalid output variant or item count")
}

fn write_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), RuntimeError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "printer worker frame exceeds the 8 MiB channel budget"));
    }
    let payload_len = u32::try_from(payload.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "printer worker frame length exceeds protocol width", error))?;
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: U16::new(PROTOCOL_VERSION),
        payload_len: U32::new(payload_len),
    };
    let header_bytes: [u8; FRAME_HEADER_BYTES] = zerocopy::transmute!(header);
    writer.write_all(&header_bytes).map_err(|error| RuntimeError::with_source(
        Kind::HostFailure, "write printer worker frame header", error))?;
    writer.write_all(payload).map_err(|error| RuntimeError::with_source(
        Kind::HostFailure, "write printer worker frame payload", error))?;
    writer.flush().map_err(|error| RuntimeError::with_source(
        Kind::HostFailure, "flush printer worker frame", error))
}

fn serialize_bounded<T: Serialize>(
    value: &T,
    context: &'static str,
) -> Result<Vec<u8>, RuntimeError> {
    // Enforce the channel budget while JSON is produced, before an oversized
    // serialized copy can be allocated.
    let mut writer = BoundedJsonBuffer::new();
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if let Some(failure) = writer.failure.take() {
            return Err(failure.into_runtime_error(context));
        }
        return Err(RuntimeError::with_source(
            Kind::InternalInvariant, context, error,
        ));
    }
    Ok(writer.bytes)
}

struct BoundedJsonBuffer {
    bytes: Vec<u8>,
    failure: Option<BoundedWriteFailure>,
}

impl BoundedJsonBuffer {
    fn new() -> Self {
        Self { bytes: Vec::new(), failure: None }
    }
}

impl Write for BoundedJsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(bytes.len()) else {
            self.failure = Some(BoundedWriteFailure::Limit);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "printer worker frame length overflow",
            ));
        };
        if next_len > MAX_FRAME_BYTES {
            self.failure = Some(BoundedWriteFailure::Limit);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "printer worker frame exceeds channel budget",
            ));
        }
        if let Err(error) = self.bytes.try_reserve(bytes.len()) {
            self.failure = Some(BoundedWriteFailure::Allocation(error));
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "printer worker frame buffer allocation failed",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

enum BoundedWriteFailure {
    Limit,
    Allocation(std::collections::TryReserveError),
}

impl BoundedWriteFailure {
    fn into_runtime_error(self, context: &'static str) -> RuntimeError {
        match self {
            Self::Limit => RuntimeError::new(
                Kind::ResourceExhausted,
                format!("{context} exceeds the 8 MiB channel resource budget"),
            ),
            Self::Allocation(error) => RuntimeError::with_source(
                Kind::ResourceExhausted, format!("allocate {context} buffer"), error,
            ),
        }
    }
}

fn read_frame(
    reader: &mut impl Read,
    malformed_kind: Kind,
    context: &'static str,
) -> Result<Vec<u8>, RuntimeError> {
    let mut header_bytes = [0_u8; FRAME_HEADER_BYTES];
    reader.read_exact(&mut header_bytes).map_err(|error| RuntimeError::with_source(
        malformed_kind, format!("read {context} frame header"), error))?;
    let header: FrameHeader = zerocopy::transmute!(header_bytes);
    if header.magic != FRAME_MAGIC || header.version.get() != PROTOCOL_VERSION {
        return Err(RuntimeError::new(malformed_kind,
            format!("{context} frame has an invalid magic or version")));
    }
    let length = usize::try_from(header.payload_len.get()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, format!("{context} payload length does not fit host usize"), error))?;
    if length > MAX_FRAME_BYTES {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            format!("{context} frame exceeds the 8 MiB channel budget")));
    }
    let mut payload = Vec::new();
    payload.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, format!("allocate {context} frame"), error))?;
    payload.resize(length, 0);
    reader.read_exact(&mut payload).map_err(|error| RuntimeError::with_source(
        malformed_kind, format!("read {context} frame payload"), error))?;
    ensure_eof(reader, malformed_kind, context)?;
    Ok(payload)
}

fn ensure_eof(
    reader: &mut impl Read,
    malformed_kind: Kind,
    context: &'static str,
) -> Result<(), RuntimeError> {
    let mut extra = [0_u8; 1];
    loop {
        match reader.read(&mut extra) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(RuntimeError::new(malformed_kind,
                format!("{context} contains bytes after its single frame"))),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(RuntimeError::with_source(
                malformed_kind, format!("check {context} frame end"), error)),
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<FrameHeader>() == FRAME_HEADER_BYTES);
    assert!(core::mem::align_of::<FrameHeader>() == 1);
    assert!(core::mem::offset_of!(FrameHeader, magic) == 0);
    assert!(core::mem::offset_of!(FrameHeader, version) == 4);
    assert!(core::mem::offset_of!(FrameHeader, payload_len) == 6);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wow_devmode_worker_frame_retains_original_public_size_and_private_bytes() {
        let value = Win16HostDevMode {
            public_size: 64, device_name: [0; 32], spec_version: 0x030a,
            driver_version: 17, fields: 0x0010, settings: [7; 12],
            public_extension: vec![], driver_extra: vec![0, 0xff, 9],
        };
        let request = Win16PrinterCapabilities {
            device: Some(b"Printer".to_vec()), port: None, index: 1,
            collect_output: false, devmode: Some(value.clone()),
        };
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request, 936).unwrap();
        let (decoded, page) = read_request(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.devmode, Some(value));
        assert_eq!(page, 936);
        // Older workers must fail before interpreting the changed schema.
        bytes[4..6].copy_from_slice(&2_u16.to_le_bytes());
        assert!(read_request(&mut bytes.as_slice()).is_err());
    }
}

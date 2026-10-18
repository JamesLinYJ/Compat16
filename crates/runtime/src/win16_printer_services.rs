//! Guest-side projection for Win16 WINSPOOL capability queries.

use guest_core::memory::Memory;
use win16_abi::{printer_abi::ResolutionPair16, Point16, Win16PrinterRequest};

use super::Win16State;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16PrinterCapabilities, Win16PrinterCapabilityData,
};

const DWORD_FAILURE: u32 = u32::MAX;

impl Win16State {
    pub(super) fn printer(
        &mut self,
        request: Win16PrinterRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Win16PrinterRequest::DeviceCapabilities {
            device, port, index, output, devmode,
        } = request;

        let array = capability_array(index);
        if output != 0 && array.is_none() && !known_scalar(index) {
            report_gap(host,
                "Win16 DeviceCapabilities output layout is not verified for this index",
                "Win16 WINSPOOL DeviceCapabilities");
            return Ok(DWORD_FAILURE);
        }

        let host_request = Win16PrinterCapabilities {
            device,
            port,
            index,
            collect_output: output != 0,
            devmode: devmode.map(Into::into),
        };
        if host_request.devmode.as_ref().is_some_and(|mode| !mode.has_mapped_fields()) {
            report_gap(host,
                "Win16 DeviceCapabilities DEVMODE has an invalid or unsupported public layout",
                "Win16 WINSPOOL DeviceCapabilities");
            return Ok(DWORD_FAILURE);
        }
        let result = match host.win16_printer_capabilities(host_request) {
            Ok(result) => result,
            // This is a read-only host query using copied input. A helper
            // failure or resource limit has not changed guest state or output;
            // DWORD -1 is the documented DeviceCapabilities failure result.
            // Guest-memory and internal-state failures outside this call remain
            // errors, rather than being caught by this recovery boundary.
            Err(error) if matches!(error.kind(),
                Kind::CompatibilityGap | Kind::HostFailure | Kind::ResourceExhausted) => {
                host.report_diagnostic(&Diagnostic::warning(error.kind(),
                    "printer capability query could not produce a result")
                    .with_context("Win16 WINSPOOL DeviceCapabilities")
                    .with_cause(error));
                return Ok(DWORD_FAILURE);
            }
            Err(error) => return Err(error),
        };

        // Preserve a native DWORD -1 exactly, without interpreting an output
        // variant or touching the guest output range.
        if result.value == DWORD_FAILURE {
            return Ok(result.value);
        }

        if output == 0 {
            if result.output.is_some() {
                return Err(wrong_host_shape());
            }
            return Ok(result.value);
        }

        let Some(array) = array else {
            if result.output.is_some() {
                return Err(wrong_host_shape());
            }
            // Scalar capabilities, including the Win16 POINT-valued
            // min/max extents, are returned in the DWORD itself.
            return Ok(result.value);
        };

        let bytes = match encode_array(array, result.value, result.output) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "native printer capability cannot be represented by the Win16 output ABI")
                    .with_context("Win16 WINSPOOL DeviceCapabilities")
                    .with_cause(error));
                return Ok(DWORD_FAILURE);
            }
            Err(error) => return Err(error),
        };

        if !bytes.is_empty() {
            let pointer = self.selectors.pointer_from_far(output)
                .map_err(crate::runtime_error)?;
            self.write_text_bytes(memory, pointer, &bytes)?;
        }
        Ok(result.value)
    }
}

#[derive(Clone, Copy)]
enum CapabilityArray {
    Words,
    Points,
    ResolutionPairs,
    Names(u16),
}

fn capability_array(index: u16) -> Option<CapabilityArray> {
    match index {
        2 | 6 => Some(CapabilityArray::Words),
        3 => Some(CapabilityArray::Points),
        12 => Some(CapabilityArray::Names(24)),
        13 => Some(CapabilityArray::ResolutionPairs),
        14 | 16 => Some(CapabilityArray::Names(64)),
        _ => None,
    }
}

fn known_scalar(index: u16) -> bool {
    matches!(index, 1 | 4 | 5 | 7 | 8 | 9 | 10 | 11 | 15 | 17 | 18)
}

fn encode_array(
    array: CapabilityArray,
    count: u32,
    output: Option<Win16PrinterCapabilityData>,
) -> Result<Vec<u8>, RuntimeError> {
    let output = output.ok_or_else(wrong_host_shape)?;
    match (array, output) {
        (CapabilityArray::Words, Win16PrinterCapabilityData::Words(words)) => {
            require_count(words.len(), count)?;
            let mut bytes = byte_buffer(words.len(), 2)?;
            for word in words {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            Ok(bytes)
        }
        (CapabilityArray::Points, Win16PrinterCapabilityData::Points(points)) => {
            require_count(points.len(), count)?;
            let mut bytes = byte_buffer(points.len(), 4)?;
            for point in points {
                let x = i16::try_from(point.x).map_err(|error| RuntimeError::with_source(
                    Kind::CompatibilityGap,
                    "DeviceCapabilities POINT x-coordinate exceeds Win16 POINT16", error))?;
                let y = i16::try_from(point.y).map_err(|error| RuntimeError::with_source(
                    Kind::CompatibilityGap,
                    "DeviceCapabilities POINT y-coordinate exceeds Win16 POINT16", error))?;
                bytes.extend_from_slice(&Point16 { x, y }.encode());
            }
            Ok(bytes)
        }
        (CapabilityArray::ResolutionPairs,
            Win16PrinterCapabilityData::ResolutionPairs(pairs)) => {
            require_count(pairs.len(), count)?;
            let mut bytes = byte_buffer(pairs.len(), 8)?;
            for [x, y] in pairs {
                bytes.extend_from_slice(&ResolutionPair16 { x, y }.encode());
            }
            Ok(bytes)
        }
        (CapabilityArray::Names(expected_record_bytes),
            Win16PrinterCapabilityData::Names { record_bytes, bytes }) => {
            if record_bytes != expected_record_bytes
                || usize::from(record_bytes) == 0
                || bytes.len() % usize::from(record_bytes) != 0
            {
                return Err(wrong_host_shape());
            }
            require_count(bytes.len() / usize::from(record_bytes), count)?;
            Ok(bytes)
        }
        _ => Err(wrong_host_shape()),
    }
}

fn byte_buffer(items: usize, bytes_per_item: usize) -> Result<Vec<u8>, RuntimeError> {
    let capacity = items.checked_mul(bytes_per_item).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "Win16 printer output size overflows host address space"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "could not allocate Win16 printer output buffer", error))?;
    Ok(bytes)
}

fn require_count(actual: usize, expected: u32) -> Result<(), RuntimeError> {
    let actual = u32::try_from(actual).map_err(|error| RuntimeError::with_source(
        Kind::InternalInvariant,
        "host returned a printer output count wider than the Win16 DWORD count",
        error,
    ))?;
    if actual != expected {
        return Err(wrong_host_shape());
    }
    Ok(())
}

fn wrong_host_shape() -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant,
        "host returned the wrong Win16 DeviceCapabilities output shape or count")
}

fn report_gap(host: &mut impl RuntimeHost, message: &'static str, context: &'static str) {
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, message)
        .with_context(context));
}

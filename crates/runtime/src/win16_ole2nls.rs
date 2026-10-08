//! Runtime bridge for Win16 OLE2NLS calls and checked guest writeback.

use guest_core::memory::Memory;
use win16_abi::{SegmentedPointer, Win16Ole2NlsRequest, Win16Ole2NlsString};

use super::{Win16State, guest_ranges::{GuestOutputRange, commit_guest_writes}};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16NlsHostResult as HostResult, Win16NlsOperation as Operation,
    Win16NlsString as HostString};

impl Win16State {
    pub(super) fn ole2nls_api(
        &mut self,
        request: Win16Ole2NlsRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16Ole2NlsRequest::GetUserDefaultLcid => {
                scalar(host.win16_ole2nls(Operation::GetUserDefaultLcid)?)
            }
            Win16Ole2NlsRequest::GetSystemDefaultLcid => {
                scalar(host.win16_ole2nls(Operation::GetSystemDefaultLcid)?)
            }
            Win16Ole2NlsRequest::GetUserDefaultLangId => {
                lang_id(host.win16_ole2nls(Operation::GetUserDefaultLangId)?)
            }
            Win16Ole2NlsRequest::GetSystemDefaultLangId => {
                lang_id(host.win16_ole2nls(Operation::GetSystemDefaultLangId)?)
            }
            Win16Ole2NlsRequest::GetLocaleInfoA { lcid, info_type, output, capacity } => {
                if capacity != 0 && output.is_none() { return Ok(0); }
                let length = usize::from(capacity);
                let range = capture_output(self, memory, output, length)?;
                let result = host.win16_ole2nls(Operation::GetLocaleInfoA {
                    lcid, info_type, capacity,
                })?;
                commit_buffer_result(self, memory, range, length, result)
            }
            Win16Ole2NlsRequest::LcMapStringA {
                lcid, flags, source, destination, destination_capacity,
            } => {
                if source.is_null || (destination_capacity != 0 && destination.is_none()) {
                    return Ok(0);
                }
                let length = usize::from(destination_capacity);
                let range = capture_output(self, memory, destination, length)?;
                let result = host.win16_ole2nls(Operation::LcMapStringA {
                    lcid, flags, source: host_string(source), destination_capacity,
                })?;
                commit_buffer_result(self, memory, range, length, result)
            }
            Win16Ole2NlsRequest::GetStringTypeA { lcid, info_type, source, output } => {
                let length = string_type_output_bytes(&source)?;
                if source.is_null || (length != 0 && output.is_none()) { return Ok(0); }
                let has_source_units = source.declared_count != 0;
                let range = capture_output(self, memory, output, length)?;
                let result = host.win16_ole2nls(Operation::GetStringTypeA {
                    lcid, info_type, source: host_string(source),
                })?;
                match result {
                    HostResult::StringTypes { result, values } => {
                        let byte_count = values.len().checked_mul(std::mem::size_of::<u16>())
                            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                                "OLE2NLS character-type result length overflowed"))?;
                        if byte_count > length {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "host GetStringTypeA exceeded its checked guest output span"));
                        }
                        if result == 0 {
                            if !values.is_empty() {
                                return Err(RuntimeError::new(Kind::InternalInvariant,
                                    "failed GetStringTypeA returned character-type data"));
                            }
                            return Ok(0);
                        }
                        if result != 1 {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "host GetStringTypeA DTO did not contain a canonical BOOL"));
                        }
                        if values.is_empty() && has_source_units {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "successful GetStringTypeA returned no character-type data"));
                        }
                        if result != 0 && byte_count != 0 {
                            let range = range.ok_or_else(|| RuntimeError::new(
                                Kind::InternalInvariant,
                                "OLE2NLS character-type result has no captured guest output"))?;
                            let bytes = encode_words(&values)?;
                            commit_guest_writes(self, memory, vec![(range, bytes)])?;
                        }
                        Ok(result as u32)
                    }
                    _ => Err(unexpected_result("GetStringTypeA")),
                }
            }
            Win16Ole2NlsRequest::CompareStringA { lcid, flags, left, right } => {
                if left.is_null || right.is_null { return Ok(0); }
                compare_result(host.win16_ole2nls(Operation::CompareStringA {
                    lcid, flags, left: host_string(left), right: host_string(right),
                })?)
            }
        }
    }
}

fn capture_output(
    state: &Win16State,
    memory: &Memory,
    pointer: Option<SegmentedPointer>,
    length: usize,
) -> Result<Option<GuestOutputRange>, RuntimeError> {
    if length == 0 { return Ok(None); }
    let pointer = pointer.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
        "OLE2NLS nonempty output has no checked guest address"))?;
    let descriptor = state.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
    let available = descriptor.limit.checked_sub(u32::from(pointer.offset()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
            "OLE2NLS output begins beyond its selector limit"))?;
    if length > available {
        return Err(RuntimeError::new(Kind::GuestFault,
            "OLE2NLS output exceeds its ordinary FAR selector"));
    }
    GuestOutputRange::capture(state, memory, pointer, length).map(Some)
}

fn commit_buffer_result(
    state: &Win16State,
    memory: &mut Memory,
    range: Option<GuestOutputRange>,
    capacity: usize,
    result: HostResult,
) -> Result<u32, RuntimeError> {
    match result {
        HostResult::Buffer { result, bytes } => {
            if result < 0 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "host OLE2NLS returned a negative character count"));
            }
            if result == 0 {
                if !bytes.is_empty() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "failed OLE2NLS buffer query returned data"));
                }
                return Ok(0);
            }
            if capacity == 0 {
                if !bytes.is_empty() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "zero-capacity OLE2NLS query returned output bytes"));
                }
                return Ok(result as u32);
            }
            let expected = usize::try_from(result).map_err(|_| RuntimeError::new(
                Kind::InternalInvariant, "host OLE2NLS count did not fit the output length"))?;
            if bytes.len() != expected || bytes.len() > capacity {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "host OLE2NLS byte count did not match its result or guest capacity"));
            }
            let range = range.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "OLE2NLS buffer result has no captured guest output"))?;
            commit_guest_writes(state, memory, vec![(range, bytes)])?;
            Ok(result as u32)
        }
        _ => Err(unexpected_result("buffer query")),
    }
}

fn scalar(result: HostResult) -> Result<u32, RuntimeError> {
    match result {
        HostResult::Scalar(value) => Ok(value),
        _ => Err(unexpected_result("scalar query")),
    }
}

fn lang_id(result: HostResult) -> Result<u32, RuntimeError> {
    let value = scalar(result)?;
    if value > u16::MAX.into() {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "host returned a LANGID wider than the Win16 result"));
    }
    Ok(value)
}

fn compare_result(result: HostResult) -> Result<u32, RuntimeError> {
    let value = scalar(result)?;
    if value > 3 {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "host CompareStringA returned a value outside CSTR_LESS_THAN through CSTR_GREATER_THAN"));
    }
    Ok(value)
}

fn host_string(source: Win16Ole2NlsString) -> HostString {
    HostString { bytes: source.bytes, declared_count: source.declared_count, is_null: source.is_null }
}

fn string_type_output_bytes(source: &Win16Ole2NlsString) -> Result<usize, RuntimeError> {
    let words = if source.declared_count >= 0 {
        source.declared_count as usize
    } else if source.is_null {
        0
    } else {
        source.bytes.len().checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "OLE2NLS character-type output length overflowed"))?
    };
    words.checked_mul(std::mem::size_of::<u16>()).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "OLE2NLS character-type output length overflowed"))
}

fn encode_words(values: &[u16]) -> Result<Vec<u8>, RuntimeError> {
    let length = values.len().checked_mul(std::mem::size_of::<u16>()).ok_or_else(||
        RuntimeError::new(Kind::ResourceExhausted, "OLE2NLS word buffer length overflowed"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve OLE2NLS output bytes", error))?;
    for value in values { bytes.extend_from_slice(&value.to_le_bytes()); }
    Ok(bytes)
}

fn unexpected_result(operation: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant,
        format!("host returned an incompatible OLE2NLS result for {operation}"))
}

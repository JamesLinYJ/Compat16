//! Synchronous timer queries and balanced WinMM period references.

use compat_services::win16_multimedia::{
    TIME_BYTES, TIME_MIDI, TIME_MS, TIME_SAMPLES, TIME_SMPTE, TIMERR_STRUCT,
};
use guest_core::memory::Memory;
use win16_abi::{Access, Win16MediaTimeRequest, Win16Mmtime16,
    Win16TimeCaps16, MMTIME16_SIZE, TIMECAPS16_SIZE};

use super::{Win16State, guest_ranges::{GuestOutputRange, commit_guest_writes}};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMediaTimeOperation as Operation, Win16HostMediaTimeResult as ResultValue,
    Win16HostMediaTimeValue};

impl Win16State {
    pub(in crate::win16_runtime) fn media_time_api(
        &mut self,
        request: Win16MediaTimeRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16MediaTimeRequest::GetSystemTime { time, size } => {
                if usize::from(size) < MMTIME16_SIZE { return Ok(u32::from(TIMERR_STRUCT)); }
                let output = match capture_fixed_output(self, memory, time, MMTIME16_SIZE) {
                    Ok(output) => output,
                    Err(error) if is_guest_api_failure(&error) => {
                        return Ok(u32::from(TIMERR_STRUCT));
                    }
                    Err(error) => return Err(error),
                };
                let result = host.win16_media_time(Operation::GetSystemTime)?;
                let ResultValue::SystemTime { result, value } = result else {
                    return Err(invariant("timeGetSystemTime returned the wrong result shape"));
                };
                if result == 0 {
                    let (record, unknown) = encode_time_value(value);
                    if unknown {
                        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                            "native timeGetSystemTime returned an MMTIME arm absent from SDK 3.1"));
                    }
                    match commit_guest_writes(self, memory, vec![(output, record.to_vec())]) {
                        Ok(()) => {}
                        Err(error) if is_guest_api_failure(&error) => {
                            return Ok(u32::from(TIMERR_STRUCT));
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(u32::from(result as u16))
            }
            Win16MediaTimeRequest::GetDevCaps { caps, size } => {
                if usize::from(size) < TIMECAPS16_SIZE { return Ok(u32::from(TIMERR_STRUCT)); }
                let output = match capture_fixed_output(self, memory, caps, TIMECAPS16_SIZE) {
                    Ok(output) => output,
                    Err(error) if is_guest_api_failure(&error) => {
                        return Ok(u32::from(TIMERR_STRUCT));
                    }
                    Err(error) => return Err(error),
                };
                let result = host.win16_media_time(Operation::GetDevCaps)?;
                let ResultValue::DevCaps { result, minimum_period, maximum_period } = result else {
                    return Err(invariant("timeGetDevCaps returned the wrong result shape"));
                };
                if result == 0 {
                    let record = Win16TimeCaps16 {
                        minimum_period: minimum_period as u16,
                        maximum_period: maximum_period as u16,
                    }.encode();
                    match commit_guest_writes(self, memory, vec![(output, record.to_vec())]) {
                        Ok(()) => {}
                        Err(error) if is_guest_api_failure(&error) => {
                            return Ok(u32::from(TIMERR_STRUCT));
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(u32::from(result as u16))
            }
            Win16MediaTimeRequest::BeginPeriod { period } => {
                if !self.media_services.can_begin_period(period) {
                    return Err(RuntimeError::new(Kind::ResourceExhausted,
                        "Win16 timer-period reference count is exhausted"));
                }
                match host.win16_media_time(Operation::BeginPeriod { period })? {
                    ResultValue::Period(result) => {
                        if result == 0 { self.media_services.record_period_begin(period); }
                        Ok(u32::from(result as u16))
                    }
                    _ => Err(invariant("timeBeginPeriod returned the wrong result shape")),
                }
            }
            Win16MediaTimeRequest::EndPeriod { period } => {
                match host.win16_media_time(Operation::EndPeriod { period })? {
                    ResultValue::Period(result) => {
                        if result == 0 { self.media_services.record_period_end(period); }
                        Ok(u32::from(result as u16))
                    }
                    _ => Err(invariant("timeEndPeriod returned the wrong result shape")),
                }
            }
            Win16MediaTimeRequest::GetTime => match host.win16_media_time(Operation::GetTime)? {
                ResultValue::Time(value) => Ok(value),
                _ => Err(invariant("timeGetTime returned the wrong result shape")),
            },
        }
    }
}

fn capture_fixed_output(
    state: &Win16State,
    memory: &Memory,
    far: u32,
    size: usize,
) -> Result<GuestOutputRange, RuntimeError> {
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    // MMTIME and TIMECAPS are ordinary FAR records; their bytes may not spill
    // into an adjacent huge-pointer selector.
    state.selectors.translate(pointer, Access::Write, size, memory)
        .map_err(crate::runtime_error)?;
    GuestOutputRange::capture(state, memory, pointer, size)
}

fn encode_time_value(value: Win16HostMediaTimeValue) -> ([u8; MMTIME16_SIZE], bool) {
    let (kind, value, unknown) = match value {
        Win16HostMediaTimeValue::Milliseconds(value) => (TIME_MS, value.to_le_bytes(), false),
        Win16HostMediaTimeValue::Samples(value) => (TIME_SAMPLES, value.to_le_bytes(), false),
        Win16HostMediaTimeValue::Bytes(value) => (TIME_BYTES, value.to_le_bytes(), false),
        Win16HostMediaTimeValue::Smpte(value) => {
            return (Win16Mmtime16 { kind: TIME_SMPTE, value }.encode(), false);
        }
        Win16HostMediaTimeValue::Midi(value) => (TIME_MIDI, value.to_le_bytes(), false),
        Win16HostMediaTimeValue::Unknown { time_type, value } => {
            let mut low = [0_u8; 4];
            low.copy_from_slice(&value[..4]);
            let mut encoded = [0_u8; MMTIME16_SIZE];
            encoded[..2].copy_from_slice(&(time_type as u16).to_le_bytes());
            encoded[2..6].copy_from_slice(&low);
            encoded[6..8].copy_from_slice(&value[4..6]);
            return (encoded, true);
        }
    };
    let mut union = [0_u8; 6];
    union[..4].copy_from_slice(&value);
    (Win16Mmtime16 { kind, value: union }.encode(), unknown)
}

fn is_guest_api_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

fn invariant(message: &str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

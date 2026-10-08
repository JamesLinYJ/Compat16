//! Checked Win16 multimedia timer calls and callback event registration.

use super::*;
use compat_services::win16_multimedia::{
    TIME_BYTES, TIME_MIDI, TIME_MS, TIME_PERIODIC, TIME_SAMPLES, TIME_SMPTE,
    TIME_TICKS, TIMERR_NOCANDO, TIMERR_STRUCT, MMTIME16_SIZE,
    MMTIME16_TYPE_OFFSET, MMTIME16_UNION_OFFSET, MMTIME16_UNION_SIZE,
    TIMECAPS16_MAX_PERIOD_OFFSET, TIMECAPS16_MIN_PERIOD_OFFSET, TIMECAPS16_SIZE,
};
use guest_core::memory::Memory;
use guest_core::Registers;
use win16_abi::{Win16MultimediaCall, Win16ReturnKind};

pub(super) fn is_timer_export(name: &str) -> bool {
    [
        "timeGetSystemTime",
        "timeGetDevCaps",
        "timeSetEvent",
        "timeKillEvent",
        "timeBeginPeriod",
        "timeEndPeriod",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

impl super::super::Win16State {
    pub(super) fn multimedia_timer_api(
        &mut self,
        call: &Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let name = call.name.unwrap_or("");
        if name.eq_ignore_ascii_case("timeGetSystemTime") {
            // MMTIME16 is a packed eight-byte structure: WORD wType and a
            // six-byte union (the SMPTE arm is wider than DWORD).
            if usize::from(word(call, 1)?) < MMTIME16_SIZE {
                return self.finish_multimedia(
                    registers, return_to, u32::from(TIMERR_STRUCT), return_kind,
                );
            }
            let output = self.prepare_multimedia_output(
                memory, pointer(call, 0)?, MMTIME16_SIZE,
            )?.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "MMTIME16 output was not prepared"))?;
            let reply = host.win16_multimedia(Win16HostMultimediaOperation::TimeSystemTime)?;
            let Win16HostMultimediaResult::TimeSystemTime { result, value } = reply else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "timeGetSystemTime returned the wrong multimedia result"));
            };
            if result == 0 {
                output.commit(memory, &encode_win16_mmtime(value)?)?;
            }
            return self.finish_multimedia(registers, return_to, result, return_kind);
        }
        if name.eq_ignore_ascii_case("timeGetDevCaps") {
            if usize::from(word(call, 1)?) < TIMECAPS16_SIZE {
                return self.finish_multimedia(
                    registers, return_to, u32::from(TIMERR_STRUCT), return_kind,
                );
            }
            let output = self.prepare_multimedia_output(
                memory, pointer(call, 0)?, TIMECAPS16_SIZE,
            )?.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "TIMECAPS16 output was not prepared"))?;
            let reply = host.win16_multimedia(
                Win16HostMultimediaOperation::TimeDeviceCapabilities,
            )?;
            let Win16HostMultimediaResult::TimeCapabilities {
                result, minimum_period, maximum_period,
            } = reply else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "timeGetDevCaps returned the wrong multimedia result"));
            };
            if result == 0 {
                let minimum = u16::try_from(minimum_period).map_err(|_| RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native multimedia minimum period exceeds the Win16 WORD range",
                ))?;
                let maximum = u16::try_from(maximum_period).map_err(|_| RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native multimedia maximum period exceeds the Win16 WORD range",
                ))?;
                let mut bytes = [0_u8; TIMECAPS16_SIZE];
                bytes[TIMECAPS16_MIN_PERIOD_OFFSET..TIMECAPS16_MIN_PERIOD_OFFSET + 2]
                    .copy_from_slice(&minimum.to_le_bytes());
                bytes[TIMECAPS16_MAX_PERIOD_OFFSET..TIMECAPS16_MAX_PERIOD_OFFSET + 2]
                    .copy_from_slice(&maximum.to_le_bytes());
                output.commit(memory, &bytes)?;
            }
            return self.finish_multimedia(registers, return_to, result, return_kind);
        }
        if name.eq_ignore_ascii_case("timeSetEvent") {
            let delay = word(call, 0)?;
            let resolution = word(call, 1)?;
            let far_proc = pointer(call, 2)?;
            if far_proc == 0 {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "timeSetEvent requires a guest FAR callback"));
            }
            let user_data = dword(call, 3)?;
            let flags = word(call, 4)?;
            if flags & !TIME_PERIODIC != 0 {
                return Err(RuntimeError::new(Kind::CompatibilityGap, format!(
                    "timeSetEvent does not support Win16 timer flags 0x{flags:04X}",
                )));
            }
            let Some(sender) = host.win16_guest_callback_sender() else {
                return Err(RuntimeError::new(Kind::CompatibilityGap,
                    "native Win16 callback event channel is unavailable"));
            };
            let callback = self.register_guest_callback(
                memory,
                far_proc,
                super::super::far_callback::Win16FarCallbackConvention::Pascal,
                super::super::far_callback::Win16FarCallbackReturn::Void,
            )?;
            let one_shot = flags & TIME_PERIODIC == 0;
            let Some(guest_timer_id) = self.multimedia.reserve_timer(callback, one_shot) else {
                let _ = self.unregister_guest_callback(callback);
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "Win16 multimedia timer table is full"));
            };
            let operation = Win16HostMultimediaOperation::TimerSet {
                guest_timer_id,
                delay,
                resolution,
                user_data,
                flags,
                callback: Win16HostGuestCallback {
                    callback,
                    guest_handle: guest_timer_id,
                    user_data,
                    sender,
                },
            };
            let reply = match host.win16_multimedia(operation) {
                Ok(reply) => reply,
                Err(error) => {
                    let _ = self.multimedia.remove_timer(guest_timer_id);
                    let _ = self.unregister_guest_callback(callback);
                    return Err(error);
                }
            };
            let Win16HostMultimediaResult::TimerSet {
                result, timer_id, callback: host_callback,
            } = reply else {
                let _ = self.multimedia.remove_timer(guest_timer_id);
                let _ = self.unregister_guest_callback(callback);
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "timeSetEvent returned the wrong multimedia result"));
            };
            if result != 0 {
                let _ = self.multimedia.remove_timer(guest_timer_id);
                let _ = self.unregister_guest_callback(callback);
                return self.finish_multimedia(registers, return_to, result, return_kind);
            }
            let (Some(timer_id), Some(host_callback)) = (timer_id, host_callback) else {
                if let Some(host_callback) = host_callback {
                    let _ = host.win16_multimedia(Win16HostMultimediaOperation::TimerKill {
                        timer_id: timer_id.unwrap_or(0),
                        callback: host_callback,
                        force_unregister: true,
                    });
                }
                let _ = self.multimedia.remove_timer(guest_timer_id);
                let _ = self.unregister_guest_callback(callback);
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "successful timeSetEvent omitted its native identities"));
            };
            if !self.multimedia.bind_timer(guest_timer_id, timer_id, host_callback) {
                let _ = host.win16_multimedia(Win16HostMultimediaOperation::TimerKill {
                    timer_id,
                    callback: host_callback,
                    force_unregister: true,
                });
                let _ = self.multimedia.remove_timer(guest_timer_id);
                let _ = self.unregister_guest_callback(callback);
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "timeSetEvent timer reservation could not be bound"));
            }
            return self.finish_multimedia(
                registers, return_to, u32::from(guest_timer_id), return_kind,
            );
        }
        if name.eq_ignore_ascii_case("timeKillEvent") {
            let guest_timer_id = word(call, 0)?;
            let Some((timer_id, callback, host_callback)) =
                self.multimedia.timer(guest_timer_id) else {
                return self.finish_multimedia(
                    registers, return_to, u32::from(TIMERR_NOCANDO), return_kind,
                );
            };
            let result = scalar(host.win16_multimedia(
                Win16HostMultimediaOperation::TimerKill {
                    timer_id,
                    callback: host_callback,
                    force_unregister: false,
                },
            )?)?;
            if result == 0 {
                let _ = self.multimedia.remove_timer(guest_timer_id);
                let _ = self.unregister_guest_callback(callback);
            }
            return self.finish_multimedia(registers, return_to, result, return_kind);
        }
        if name.eq_ignore_ascii_case("timeBeginPeriod")
            || name.eq_ignore_ascii_case("timeEndPeriod")
        {
            let result = scalar(host.win16_multimedia(Win16HostMultimediaOperation::TimePeriod {
                begin: name.eq_ignore_ascii_case("timeBeginPeriod"),
                period: word(call, 0)?,
            })?)?;
            return self.finish_multimedia(registers, return_to, result, return_kind);
        }
        Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 multimedia timer dispatcher received an unsupported export"))
    }
}

fn encode_win16_mmtime(value: Win16HostMultimediaTimeValue) -> Result<[u8; MMTIME16_SIZE], RuntimeError> {
    let mut bytes = [0_u8; MMTIME16_SIZE];
    let (time_type, payload): (u16, [u8; MMTIME16_UNION_SIZE]) = match value {
        Win16HostMultimediaTimeValue::Milliseconds(value) => (TIME_MS, scalar_time_payload(value)),
        Win16HostMultimediaTimeValue::Samples(value) => (TIME_SAMPLES, scalar_time_payload(value)),
        Win16HostMultimediaTimeValue::Bytes(value) => (TIME_BYTES, scalar_time_payload(value)),
        Win16HostMultimediaTimeValue::Smpte(value) => (TIME_SMPTE, value),
        Win16HostMultimediaTimeValue::Midi(value) => (TIME_MIDI, scalar_time_payload(value)),
        Win16HostMultimediaTimeValue::Ticks(value) => (TIME_TICKS, scalar_time_payload(value)),
        Win16HostMultimediaTimeValue::Unsupported(time_type) => {
            return Err(RuntimeError::new(Kind::CompatibilityGap, format!(
                "native timeGetSystemTime returned unsupported MMTIME format 0x{time_type:08X}",
            )));
        }
    };
    bytes[MMTIME16_TYPE_OFFSET..MMTIME16_UNION_OFFSET]
        .copy_from_slice(&time_type.to_le_bytes());
    bytes[MMTIME16_UNION_OFFSET..MMTIME16_UNION_OFFSET + MMTIME16_UNION_SIZE]
        .copy_from_slice(&payload);
    Ok(bytes)
}

fn scalar_time_payload(value: u32) -> [u8; MMTIME16_UNION_SIZE] {
    let mut payload = [0_u8; MMTIME16_UNION_SIZE];
    payload[..4].copy_from_slice(&value.to_le_bytes());
    payload
}

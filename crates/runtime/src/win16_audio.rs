//! Win16 wave and MIDI handle operations with guest-safe callback modes.

use compat_services::win16_multimedia::{
    Win16MultimediaCallback, MMSYSERR_NOTSUPPORTED, WAVE_FORMAT_PCM, WAVE_FORMAT_QUERY,
    WAVEFORMAT16_SIZE,
    WAVEFORMAT16_TAG_OFFSET, PCMWAVEFORMAT16_BITS_PER_SAMPLE_OFFSET, PCMWAVEFORMAT16_SIZE,
};
use guest_core::Registers;
use guest_core::memory::Memory;
use win16_abi::{Access, Win16MultimediaCall, Win16ReturnKind};

use super::multimedia::{
    dword, pointer, word, Win16HostMultimediaOperation, Win16HostMultimediaResult,
    Win16MultimediaAudioApi as Api, Win16MultimediaAudioCommand as Command,
    Win16MultimediaHandleKind as HandleKind,
};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostWindow};

pub(super) fn is_audio_export(name: &str) -> bool {
    [
        "waveOutOpen", "waveOutClose", "waveOutPause", "waveOutRestart", "waveOutReset",
        "waveOutBreakLoop", "waveOutGetVolume", "waveOutSetVolume", "waveOutGetID",
        "waveInOpen", "waveInClose", "waveInStart", "waveInStop", "waveInReset",
        "waveInGetID", "midiOutOpen", "midiOutClose", "midiOutShortMsg", "midiOutReset",
        "midiOutGetVolume", "midiOutSetVolume", "midiOutGetID", "midiInOpen", "midiInClose",
        "midiInStart", "midiInStop", "midiInReset", "midiInGetID",
    ].iter().any(|candidate| name.eq_ignore_ascii_case(candidate))
}

impl super::Win16State {
    pub(super) fn audio_compat_api(
        &mut self,
        call: &Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let name = call.name.unwrap_or("");
        let (api, kind) = audio_api(name).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 audio dispatch received an unknown export",
        ))?;
        let value = if name.to_ascii_lowercase().ends_with("open") {
            let output_pointer = pointer(call, 0)?;
            let device = word(call, 1)?;
            let (format, unsupported_format_tag) = match api {
                Api::WaveInput | Api::WaveOutput => match self.wave_format_copy(memory, pointer(call, 2)?)? {
                    WaveFormatCopy::Supported(format) => (Some(format), None),
                    WaveFormatCopy::Unsupported(format_tag) => (None, Some(format_tag)),
                },
                Api::MidiInput | Api::MidiOutput => (None, None),
            };
            let (callback_index, instance_index, flags_index) = match api {
                Api::WaveInput | Api::WaveOutput => (3, 4, 5),
                Api::MidiInput | Api::MidiOutput => (2, 3, 4),
            };
            let callback_value = dword(call, callback_index)?;
            let instance = dword(call, instance_index)?;
            let flags = dword(call, flags_index)?;
            let query_only = matches!(api, Api::WaveInput | Api::WaveOutput)
                && flags & WAVE_FORMAT_QUERY != 0;
            if query_only {
                if let Some(format_tag) = unsupported_format_tag {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, format!(
                        "Win16 wave format query rejected unsupported tag 0x{format_tag:04X}; returning MMSYSERR_NOTSUPPORTED",
                    )));
                    return self.finish_multimedia(registers, return_to,
                        MMSYSERR_NOTSUPPORTED, return_kind);
                }
                let reply = host.win16_multimedia(Win16HostMultimediaOperation::AudioOpen {
                    api, device, format, callback_window: None, callback: None, instance, flags,
                })?;
                let Win16HostMultimediaResult::Opened { result, handle, callback } = reply else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "wave format query returned the wrong multimedia result"));
                };
                if handle.is_some() || callback.is_some() {
                    if let Some(handle) = handle {
                        let _ = host.win16_multimedia(Win16HostMultimediaOperation::AudioCall {
                            api, file: handle, command: Command::Close,
                            callback, force_unregister: true,
                        });
                    }
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "wave format query unexpectedly allocated multimedia resources"));
                }
                return self.finish_multimedia(registers, return_to, result, return_kind);
            }
            let output = self.prepare_multimedia_output(memory, output_pointer, 2)?
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "two-byte audio open output was not prepared"))?;
            if let Some(format_tag) = unsupported_format_tag {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, format!(
                    "Win16 wave open rejected unsupported format tag 0x{format_tag:04X}; returning MMSYSERR_NOTSUPPORTED",
                )));
                return self.finish_multimedia(registers, return_to,
                    MMSYSERR_NOTSUPPORTED, return_kind);
            }
            let callback_window = self.audio_callback_window(flags, callback_value, memory.len())?;
            let reply = host.win16_multimedia(Win16HostMultimediaOperation::AudioOpen {
                api, device, format, callback_window, callback: None, instance, flags,
            })?;
            let Win16HostMultimediaResult::Opened { result, handle, callback: _ } = reply else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 audio open returned the wrong multimedia result"));
            };
            if result != 0 {
                result
            } else {
                let host_handle = handle.ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "successful Win16 audio open returned no host handle",
                ))?;
                let Some(guest_handle) = self.multimedia.add_handle(kind, host_handle) else {
                    let _ = host.win16_multimedia(Win16HostMultimediaOperation::AudioCall {
                        api, file: host_handle, command: Command::Close,
                        callback: None, force_unregister: true,
                    });
                    return Err(RuntimeError::new(Kind::ResourceExhausted,
                        "Win16 multimedia guest handle table is full"));
                };
                output.commit(memory, &guest_handle.to_le_bytes())?;
                0
            }
        } else {
            let guest_handle = word(call, 0)?;
            let file = self.multimedia.host_handle(guest_handle, kind).ok_or_else(|| {
                RuntimeError::new(Kind::CompatibilityGap, format!(
                    "Win16 multimedia ordinal {} received an unmapped {:?} handle 0x{guest_handle:04X}",
                    call.ordinal, kind,
                ))
            })?;
            let (guest_callback, host_callback) = self.multimedia.callback_ids(guest_handle, kind);
            let command = audio_command(name, call)?;
            let output = match command {
                Command::GetVolume | Command::GetDeviceId => {
                    let bytes = if matches!(command, Command::GetDeviceId) { 2 } else { 4 };
                    let destination = self.prepare_multimedia_output(memory,
                        pointer(call, 1)?, bytes)?.ok_or_else(|| RuntimeError::new(
                            Kind::InternalInvariant, "audio output destination was not prepared",
                        ))?;
                    Some((destination, bytes))
                }
                _ => None,
            };
            let reply = host.win16_multimedia(Win16HostMultimediaOperation::AudioCall {
                api,
                file,
                command,
                callback: (command == Command::Close).then_some(host_callback).flatten(),
                force_unregister: false,
            })?;
            match (command, reply) {
                (Command::Close, Win16HostMultimediaResult::Scalar(result)) => {
                    if result == 0 {
                        let _ = self.multimedia.remove_handle_record(guest_handle, kind);
                        if let Some(callback) = guest_callback {
                            let _ = self.unregister_guest_callback(callback);
                        }
                    }
                    result
                }
                (Command::GetVolume | Command::GetDeviceId,
                    Win16HostMultimediaResult::Output { result, value }) => {
                    if result == 0 {
                        let (destination, width) = output.ok_or_else(|| RuntimeError::new(
                            Kind::InternalInvariant, "audio output operation lost its destination",
                        ))?;
                        let bytes = value.to_le_bytes();
                        destination.commit(memory, &bytes[..width])?;
                    }
                    result
                }
                (_, Win16HostMultimediaResult::Scalar(result)) => result,
                _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 audio service returned the wrong multimedia result")),
            }
        };
        self.finish_multimedia(registers, return_to, value, return_kind)
    }

    fn audio_callback_window(
        &self,
        flags: u32,
        callback_value: u32,
        memory_len: usize,
    ) -> Result<Option<Win16HostWindow>, RuntimeError> {
        let callback = Win16MultimediaCallback::decode(flags, callback_value);
        match callback {
            Win16MultimediaCallback::None => Ok(None),
            Win16MultimediaCallback::Window { guest_window }
                if callback_value <= u32::from(u16::MAX) => {
                if !self.window_handles.contains_key(&guest_window) {
                    return Err(RuntimeError::new(Kind::CompatibilityGap, format!(
                        "Win16 multimedia callback window 0x{guest_window:04X} has no host mapping",
                    )));
                }
                Err(RuntimeError::new(Kind::CompatibilityGap,
                    "Win16 wave and MIDI callback-window messages have no guest message translation"))
            }
            Win16MultimediaCallback::Window { .. } => Err(RuntimeError::new(
                Kind::GuestFault, "Win16 multimedia callback window exceeds 16-bit handle width",
            )),
            Win16MultimediaCallback::Function { far_proc } => {
                if far_proc == 0 {
                    return Err(RuntimeError::new(Kind::GuestFault,
                        "Win16 CALLBACK_FUNCTION requires a nonnull guest FARPROC"));
                }
                let pointer = self.selectors.pointer_from_far(far_proc)
                    .map_err(crate::runtime_error)?;
                self.selectors.address_within(pointer, Access::Execute, 1,
                    memory_len).map_err(crate::runtime_error)?;
                Err(RuntimeError::new(Kind::CompatibilityGap,
                    "Win16 CALLBACK_FUNCTION has no scheduler route; the FARPROC remains guest-only"))
            }
            Win16MultimediaCallback::Task { .. } => Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Win16 CALLBACK_THREAD task identifiers have no native thread mapping",
            )),
            Win16MultimediaCallback::Event { .. } => Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Win16 CALLBACK_EVENT handles have no native event mapping",
            )),
            Win16MultimediaCallback::Unknown { kind, .. } => Err(RuntimeError::new(
                Kind::GuestFault, format!("unknown Win16 multimedia callback kind 0x{kind:08X}"),
            )),
        }
    }

    fn wave_format_copy(&self, memory: &Memory, raw: u32) -> Result<WaveFormatCopy, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(raw).map_err(crate::runtime_error)?;
        let mut format = self.read_text_bytes(memory, pointer, WAVEFORMAT16_SIZE)?;
        let format_tag = u16::from_le_bytes([
            format[WAVEFORMAT16_TAG_OFFSET],
            format[WAVEFORMAT16_TAG_OFFSET + 1],
        ]);
        if format_tag != WAVE_FORMAT_PCM {
            return Ok(WaveFormatCopy::Unsupported(format_tag));
        }
        let bits_pointer = self.selectors.add_bytes(
            pointer, PCMWAVEFORMAT16_BITS_PER_SAMPLE_OFFSET as u32,
        ).map_err(crate::runtime_error)?;
        let bits_per_sample = self.read_text_bytes(memory, bits_pointer, 2)?;
        format.try_reserve_exact(4).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve native WAVEFORMATEX extension", error,
        ))?;
        format.extend_from_slice(&bits_per_sample);
        format.extend_from_slice(&[0, 0]);
        if format.len() != PCMWAVEFORMAT16_SIZE + 2 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 PCMWAVEFORMAT conversion has an inconsistent length"));
        }
        Ok(WaveFormatCopy::Supported(format))
    }
}

enum WaveFormatCopy {
    Supported(Vec<u8>),
    Unsupported(u16),
}

fn audio_api(name: &str) -> Option<(Api, HandleKind)> {
    let lower = name.to_ascii_lowercase();
    let (api, kind, stem) = if lower.starts_with("waveout") {
        (Api::WaveOutput, HandleKind::WaveOutput, "waveOut")
    } else if lower.starts_with("wavein") {
        (Api::WaveInput, HandleKind::WaveInput, "waveIn")
    } else if lower.starts_with("midiout") {
        (Api::MidiOutput, HandleKind::MidiOutput, "midiOut")
    } else if lower.starts_with("midiin") {
        (Api::MidiInput, HandleKind::MidiInput, "midiIn")
    } else {
        return None;
    };
    ["Open", "Close", "Pause", "Restart", "Reset", "BreakLoop", "GetVolume",
        "SetVolume", "GetID", "ShortMsg", "Start", "Stop"]
        .iter().any(|suffix| name.eq_ignore_ascii_case(&format!("{stem}{suffix}")))
        .then_some((api, kind))
}

fn audio_command(name: &str, call: &Win16MultimediaCall) -> Result<Command, RuntimeError> {
    let command = if name.ends_with("Close") { Command::Close }
    else if name.ends_with("Start") { Command::Start }
    else if name.ends_with("Stop") { Command::Stop }
    else if name.ends_with("Pause") { Command::Pause }
    else if name.ends_with("Restart") { Command::Restart }
    else if name.ends_with("Reset") { Command::Reset }
    else if name.ends_with("BreakLoop") { Command::BreakLoop }
    else if name.ends_with("GetVolume") { Command::GetVolume }
    else if name.ends_with("SetVolume") { Command::SetVolume(dword(call, 1)?) }
    else if name.ends_with("ShortMsg") { Command::ShortMessage(dword(call, 1)?) }
    else if name.ends_with("GetID") { Command::GetDeviceId }
    else { return Err(RuntimeError::new(Kind::InternalInvariant,
        "Win16 audio decoder routed an unsupported command")); };
    Ok(command)
}

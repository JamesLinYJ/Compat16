//! Multimedia version, device-count, MCI-string, and AVI lifecycle services.

use super::*;
use guest_core::memory::Memory;
use guest_core::Registers;
use win16_abi::strings::read_ansi_z;
use win16_abi::{Win16MultimediaCall, Win16ReturnKind, MAX_WIN16_STRING_BYTES};

pub(super) fn is_multimedia_service_export(module: &str, name: &str) -> bool {
    if module.eq_ignore_ascii_case("MMSYSTEM") {
        return [
            "mciSendString",
            "mciGetDeviceID",
            "mciGetErrorString",
            "mmsystemGetVersion",
            "joyGetNumDevs",
            "midiInGetNumDevs",
            "midiOutGetNumDevs",
            "auxGetNumDevs",
            "waveInGetNumDevs",
            "waveOutGetNumDevs",
            "mixerGetNumDevs",
            "midiInGetErrorText",
            "midiOutGetErrorText",
            "waveInGetErrorText",
            "waveOutGetErrorText",
        ]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate));
    }
    (module.eq_ignore_ascii_case("MSACM") && name.eq_ignore_ascii_case("acmGetVersion"))
        || (module.eq_ignore_ascii_case("MSVIDEO")
            && ["VideoForWindowsVersion", "videoGetNumDevs"]
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate)))
        || (module.eq_ignore_ascii_case("AVIFILE")
            && ["AVIFileInit", "AVIFileExit"]
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate)))
}

impl super::super::Win16State {
    pub(super) fn multimedia_services_api(
        &mut self,
        call: &Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let module = call.module;
        let name = call.name.unwrap_or("");
        if module.eq_ignore_ascii_case("MMSYSTEM") {
            if name.eq_ignore_ascii_case("mciSendString") {
                let command = string(call, 0)?.to_vec();
                let output_pointer = pointer(call, 1)?;
                let capacity = usize::from(word(call, 2)?);
                let callback_guest = word(call, 3)?;
                if callback_guest != 0 {
                    return Err(RuntimeError::new(Kind::CompatibilityGap,
                        "Win16 MCI callback-window notifications have no guest message translation"));
                }
                let output = self.prepare_multimedia_output(memory, output_pointer, capacity)?;
                let buffer = zeroed_buffer(capacity)?;
                let reply = host.win16_multimedia(Win16HostMultimediaOperation::MciSendString {
                    command,
                    buffer,
                    callback: None,
                })?;
                let (result, bytes) = buffer_result(reply)?;
                commit_text_result(output, memory, capacity, bytes)?;
                return self.finish_multimedia(registers, return_to, result, return_kind);
            }
            if name.eq_ignore_ascii_case("mciGetDeviceID") {
                let raw = pointer(call, 0)?;
                let device_name = read_ansi_z(
                    &self.selectors,
                    memory,
                    raw,
                    MAX_WIN16_STRING_BYTES,
                ).map_err(crate::runtime_error)?;
                let value = scalar(host.win16_multimedia(
                    Win16HostMultimediaOperation::MciGetDeviceId { device_name },
                )?)?;
                return self.finish_multimedia(registers, return_to, value, return_kind);
            }
            if name.eq_ignore_ascii_case("mciGetErrorString") {
                let error = dword(call, 0)?;
                let output_pointer = pointer(call, 1)?;
                let capacity = usize::from(word(call, 2)?);
                let output = self.prepare_multimedia_output(memory, output_pointer, capacity)?;
                let buffer = zeroed_buffer(capacity)?;
                let reply = host.win16_multimedia(Win16HostMultimediaOperation::MciGetErrorString {
                    error,
                    buffer,
                })?;
                let (result, bytes) = buffer_result(reply)?;
                commit_text_result(output, memory, capacity, bytes)?;
                return self.finish_multimedia(registers, return_to, result, return_kind);
            }
            if name.eq_ignore_ascii_case("mmsystemGetVersion") {
                let value = scalar(host.win16_multimedia(
                    Win16HostMultimediaOperation::Version(Win16MultimediaVersionApi::Mmsystem),
                )?)?;
                return self.finish_multimedia(registers, return_to, value, return_kind);
            }
            if let Some(api) = device_count_api(name) {
                let value = scalar(host.win16_multimedia(
                    Win16HostMultimediaOperation::DeviceCount(api),
                )?)?;
                return self.finish_multimedia(registers, return_to, value, return_kind);
            }
            if let Some(api) = error_text_api(name) {
                let error = word(call, 0)?;
                let output_pointer = pointer(call, 1)?;
                let capacity = usize::from(word(call, 2)?);
                let output = self.prepare_multimedia_output(memory, output_pointer, capacity)?;
                let buffer = zeroed_buffer(capacity)?;
                let reply = host.win16_multimedia(Win16HostMultimediaOperation::ErrorText {
                    api,
                    error,
                    buffer,
                })?;
                let (result, bytes) = buffer_result(reply)?;
                commit_text_result(output, memory, capacity, bytes)?;
                return self.finish_multimedia(registers, return_to, result, return_kind);
            }
        }
        if module.eq_ignore_ascii_case("MSACM") {
            let value = scalar(host.win16_multimedia(Win16HostMultimediaOperation::Version(
                Win16MultimediaVersionApi::AudioCompressionManager,
            ))?)?;
            return self.finish_multimedia(registers, return_to, value, return_kind);
        }
        if module.eq_ignore_ascii_case("MSVIDEO") {
            let operation = if name.eq_ignore_ascii_case("VideoForWindowsVersion") {
                Win16HostMultimediaOperation::Version(Win16MultimediaVersionApi::VideoForWindows)
            } else {
                Win16HostMultimediaOperation::DeviceCount(
                    Win16MultimediaDeviceApi::VideoCapture,
                )
            };
            let value = scalar(host.win16_multimedia(operation)?)?;
            return self.finish_multimedia(registers, return_to, value, return_kind);
        }
        if module.eq_ignore_ascii_case("AVIFILE") {
            let initialize = name.eq_ignore_ascii_case("AVIFileInit");
            let next_init_count = if initialize {
                Some(self.multimedia.avi_file_init_count.checked_add(1).ok_or_else(|| {
                    RuntimeError::new(Kind::ResourceExhausted,
                        "Win16 AVIFile initialization count is exhausted")
                })?)
            } else {
                None
            };
            match host.win16_multimedia(
                Win16HostMultimediaOperation::AviFileLifecycle { initialize },
            )? {
                Win16HostMultimediaResult::Unit => {}
                _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "AVIFile host service returned a value for a void operation")),
            }
            if let Some(count) = next_init_count {
                self.multimedia.avi_file_init_count = count;
            } else {
                self.multimedia.avi_file_init_count =
                    self.multimedia.avi_file_init_count.saturating_sub(1);
            }
            return self.finish_multimedia(registers, return_to, 0, return_kind);
        }
        Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 multimedia services dispatcher received an unassigned export"))
    }
}

fn device_count_api(name: &str) -> Option<Win16MultimediaDeviceApi> {
    [
        ("joyGetNumDevs", Win16MultimediaDeviceApi::Joystick),
        ("midiInGetNumDevs", Win16MultimediaDeviceApi::MidiInput),
        ("midiOutGetNumDevs", Win16MultimediaDeviceApi::MidiOutput),
        ("auxGetNumDevs", Win16MultimediaDeviceApi::AuxiliaryOutput),
        ("waveInGetNumDevs", Win16MultimediaDeviceApi::WaveInput),
        ("waveOutGetNumDevs", Win16MultimediaDeviceApi::WaveOutput),
        ("mixerGetNumDevs", Win16MultimediaDeviceApi::Mixer),
    ]
    .into_iter()
    .find_map(|(candidate, api)| name.eq_ignore_ascii_case(candidate).then_some(api))
}

fn error_text_api(name: &str) -> Option<Win16MultimediaErrorApi> {
    [
        ("midiInGetErrorText", Win16MultimediaErrorApi::MidiInput),
        ("midiOutGetErrorText", Win16MultimediaErrorApi::MidiOutput),
        ("waveInGetErrorText", Win16MultimediaErrorApi::WaveInput),
        ("waveOutGetErrorText", Win16MultimediaErrorApi::WaveOutput),
    ]
    .into_iter()
    .find_map(|(candidate, api)| name.eq_ignore_ascii_case(candidate).then_some(api))
}

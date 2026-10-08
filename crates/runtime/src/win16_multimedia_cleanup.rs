//! Task-exit cleanup for multimedia handles, timers, callbacks, and AVI state.

use super::*;

impl super::super::Win16State {
    pub(in crate::win16_runtime) fn close_multimedia_resources(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut first_error = None;
        for (timer_id, guest_callback, host_callback, _) in self.multimedia.take_all_timers() {
            match (timer_id, host_callback) {
                (Some(timer_id), Some(host_callback)) => {
                    match host.win16_multimedia(Win16HostMultimediaOperation::TimerKill {
                        timer_id,
                        callback: host_callback,
                        force_unregister: true,
                    }) {
                        Ok(Win16HostMultimediaResult::Scalar(_)) => {}
                        Ok(_) if first_error.is_none() => first_error = Some(
                            RuntimeError::new(Kind::InternalInvariant,
                                "multimedia timer cleanup returned the wrong result kind")),
                        Err(error) if first_error.is_none() => first_error = Some(error),
                        _ => {}
                    }
                }
                (None, None) => {}
                _ if first_error.is_none() => first_error = Some(RuntimeError::new(
                    Kind::InternalInvariant,
                    "multimedia timer cleanup found incomplete native identities",
                )),
                _ => {}
            }
            let _ = self.unregister_guest_callback(guest_callback);
        }

        for (kind, host_handle, guest_callback, host_callback) in
            self.multimedia.take_all_handles()
        {
            let operation = match (kind, host_handle) {
                (_, None) => None,
                (Win16MultimediaHandleKind::Mmio, Some(file)) => {
                    Some(Win16HostMultimediaOperation::MmioClose { file, flags: 0 })
                }
                (Win16MultimediaHandleKind::WaveInput, Some(file)) => {
                    Some(Win16HostMultimediaOperation::AudioCall {
                        api: Win16MultimediaAudioApi::WaveInput,
                        file,
                        command: Win16MultimediaAudioCommand::Close,
                        callback: host_callback,
                        force_unregister: true,
                    })
                }
                (Win16MultimediaHandleKind::WaveOutput, Some(file)) => {
                    Some(Win16HostMultimediaOperation::AudioCall {
                        api: Win16MultimediaAudioApi::WaveOutput,
                        file,
                        command: Win16MultimediaAudioCommand::Close,
                        callback: host_callback,
                        force_unregister: true,
                    })
                }
                (Win16MultimediaHandleKind::MidiInput, Some(file)) => {
                    Some(Win16HostMultimediaOperation::AudioCall {
                        api: Win16MultimediaAudioApi::MidiInput,
                        file,
                        command: Win16MultimediaAudioCommand::Close,
                        callback: host_callback,
                        force_unregister: true,
                    })
                }
                (Win16MultimediaHandleKind::MidiOutput, Some(file)) => {
                    Some(Win16HostMultimediaOperation::AudioCall {
                        api: Win16MultimediaAudioApi::MidiOutput,
                        file,
                        command: Win16MultimediaAudioCommand::Close,
                        callback: host_callback,
                        force_unregister: true,
                    })
                }
                (other, Some(_)) => {
                    if first_error.is_none() {
                        first_error = Some(RuntimeError::new(Kind::InternalInvariant, format!(
                            "multimedia cleanup has no close operation for {other:?}",
                        )));
                    }
                    None
                }
            };
            if let Some(operation) = operation {
                match host.win16_multimedia(operation) {
                    Ok(Win16HostMultimediaResult::Scalar(_)) => {}
                    Ok(_) if first_error.is_none() => first_error = Some(
                        RuntimeError::new(Kind::InternalInvariant,
                            "multimedia close returned the wrong result kind")),
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    _ => {}
                }
            }
            if let Some(callback) = guest_callback {
                let _ = self.unregister_guest_callback(callback);
            }
        }
        let avi_init_count = std::mem::take(&mut self.multimedia.avi_file_init_count);
        for _ in 0..avi_init_count {
            match host.win16_multimedia(Win16HostMultimediaOperation::AviFileLifecycle {
                initialize: false,
            }) {
                Ok(Win16HostMultimediaResult::Unit) => {}
                Ok(_) if first_error.is_none() => first_error = Some(
                    RuntimeError::new(Kind::InternalInvariant,
                        "AVIFile task cleanup returned the wrong result kind")),
                Err(error) if first_error.is_none() => first_error = Some(error),
                _ => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

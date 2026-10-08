//! Audio ports used by RuntimeHost; identities remain owned host tokens.

macro_rules! audio_runtime_host_ports {
    () => {
        fn win16_wave(&mut self, _operation: $crate::Win16HostWaveOperation)
            -> Result<$crate::Win16HostWaveResult, $crate::RuntimeError> {
            Err($crate::RuntimeError::new($crate::DiagnosticKind::CompatibilityGap,
                "host Win16 waveform audio services are unavailable"))
        }

        fn win16_wave_poll(&mut self)
            -> Result<Option<$crate::Win16HostWaveEvent>, $crate::RuntimeError> {
            Ok(None)
        }

        fn win16_wave_poll_wait(&mut self, max_wait: std::time::Duration)
            -> Result<Option<$crate::Win16HostWaveEvent>, $crate::RuntimeError> {
            let event = self.win16_wave_poll()?;
            if event.is_some() || max_wait.is_zero() {
                return Ok(event);
            }
            std::thread::sleep(max_wait);
            self.win16_wave_poll()
        }

        fn win16_wave_cleanup(&mut self) -> Result<(), $crate::RuntimeError> {
            Ok(())
        }

        /// Read the actual retained-owner inventory after producer quiescence.
        fn win16_wave_retired_owner_barrier(&mut self) -> Result<(), $crate::RuntimeError> {
            Err($crate::RuntimeError::new($crate::DiagnosticKind::CompatibilityGap,
                "host WAVE retired-owner inventory is unavailable"))
        }

        fn win16_wave_mixer_device_id(&mut self, _device: $crate::Win16HostWaveDevice)
            -> Result<$crate::Win16HostWaveMixerId, $crate::RuntimeError> {
            Err($crate::RuntimeError::new($crate::DiagnosticKind::CompatibilityGap,
                "host Win16 WAVE mixer lookup is unavailable"))
        }

        /// SOUND shares the native WAVE owner and its retained PCM buffers.
        fn win16_sound(&mut self, _operation: $crate::Win16SoundHostOperation)
            -> Result<$crate::Win16SoundHostResult, $crate::RuntimeError> {
            Err($crate::RuntimeError::new($crate::DiagnosticKind::CompatibilityGap,
                "host Win16 SOUND playback services are unavailable"))
        }

        fn poll_win16_sound(&mut self)
            -> Result<Option<$crate::Win16SoundPlaybackEvent>, $crate::RuntimeError> {
            Ok(None)
        }
    };
}

pub(super) use audio_runtime_host_ports;

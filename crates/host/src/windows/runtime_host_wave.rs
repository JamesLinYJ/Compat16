//! RuntimeHost methods for the native WAVE owner.

macro_rules! wave_runtime_host_methods {
    () => {
        fn win16_wave(
            &mut self,
            operation: runtime::Win16HostWaveOperation,
        ) -> Result<runtime::Win16HostWaveResult, runtime::RuntimeError> {
            self.win16_wave.execute(operation)
        }

        fn win16_wave_poll(
            &mut self,
        ) -> Result<Option<runtime::Win16HostWaveEvent>, runtime::RuntimeError> {
            self.win16_wave.poll()
        }

        fn win16_wave_poll_wait(
            &mut self,
            max_wait: std::time::Duration,
        ) -> Result<Option<runtime::Win16HostWaveEvent>, runtime::RuntimeError> {
            self.win16_wave.poll_wait(max_wait)
        }

        fn win16_wave_cleanup(&mut self) -> Result<(), runtime::RuntimeError> {
            self.win16_wave.cleanup_retained_owners()
        }

        fn win16_wave_retired_owner_barrier(&mut self) -> Result<(), runtime::RuntimeError> {
            self.win16_wave.retired_owner_barrier()
        }

        fn win16_wave_mixer_device_id(
            &mut self,
            device: runtime::Win16HostWaveDevice,
        ) -> Result<runtime::Win16HostWaveMixerId, runtime::RuntimeError> {
            Ok(self.win16_wave.mixer_device_id(device))
        }

        fn win16_sound(
            &mut self,
            operation: runtime::Win16SoundHostOperation,
        ) -> Result<runtime::Win16SoundHostResult, runtime::RuntimeError> {
            self.win16_wave.sound(operation)
        }

        fn poll_win16_sound(
            &mut self,
        ) -> Result<Option<runtime::Win16SoundPlaybackEvent>, runtime::RuntimeError> {
            self.win16_wave.poll_sound()
        }
    };
}

pub(super) use wave_runtime_host_methods;

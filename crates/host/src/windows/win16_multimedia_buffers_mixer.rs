//! Resolve a live WAVE token to the WinMM mixer device associated with its
//! owned native wave handle.

use super::*;
use windows_sys::Win32::Media::Audio::{
    MIXER_OBJECTF_HANDLE, MIXER_OBJECTF_WAVEIN, MIXER_OBJECTF_WAVEOUT, mixerGetID,
};
use windows_sys::Win32::Media::MMSYSERR_NODRIVER;

impl Win16WaveHost {
    /// Resolve a live host token through the exact WAVE handle retained in
    /// this owner. A native WAVE handle is never reused as mixerOpen's ID.
    pub(crate) fn mixer_device_id(&mut self, token: Win16HostWaveDevice) -> Win16HostWaveMixerId {
        let Some(device) = self
            .devices
            .iter_mut()
            .find(|device| device.token == token && !device.closing && !device.native_closed)
        else {
            return Win16HostWaveMixerId {
                result: MMSYSERR_INVALHANDLE,
                mixer_id: None,
            };
        };

        let mut mixer_id = 0;
        let (handle, object_flags) = match &device.native {
            NativeWaveHandle::Input(handle) => (
                *handle,
                (MIXER_OBJECTF_HANDLE | MIXER_OBJECTF_WAVEIN) as u32,
            ),
            NativeWaveHandle::Output(handle) => (
                *handle,
                (MIXER_OBJECTF_HANDLE | MIXER_OBJECTF_WAVEOUT) as u32,
            ),
        };
        let result = unsafe { mixerGetID(handle, &mut mixer_id, object_flags) };
        Win16HostWaveMixerId {
            result,
            mixer_id: if matches!(result, MMSYSERR_NOERROR | MMSYSERR_NODRIVER) {
                Some(mixer_id)
            } else {
                None
            },
        }
    }
}

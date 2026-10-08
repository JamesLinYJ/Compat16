// The complete declared WAVE ordinal family. MIDI and MCI declarations stay
// in their separate owners.
macro_rules! export_catalog_with_wave {
    ($($existing:tt)*) => {
        export_catalog_with_media_services! {
            $($existing)*
            MmsystemWaveOutGetNumDevs => MMSYSTEM_WAVE_OUT_GET_NUM_DEVS:
                ("MMSYSTEM", 401u16, Stack, &[], Word);
            MmsystemWaveOutGetDevCaps => MMSYSTEM_WAVE_OUT_GET_DEV_CAPS:
                ("MMSYSTEM", 402u16, Stack, wave::DEVICE_CAPS, Word);
            MmsystemWaveOutGetErrorText => MMSYSTEM_WAVE_OUT_GET_ERROR_TEXT:
                ("MMSYSTEM", 403u16, Stack, wave::ERROR_TEXT, Word);
            MmsystemWaveOutOpen => MMSYSTEM_WAVE_OUT_OPEN:
                ("MMSYSTEM", 404u16, Stack, wave::OPEN, Word);
            MmsystemWaveOutClose => MMSYSTEM_WAVE_OUT_CLOSE:
                ("MMSYSTEM", 405u16, Stack, wave::HANDLE, Word);
            MmsystemWaveOutPrepareHeader => MMSYSTEM_WAVE_OUT_PREPARE_HEADER:
                ("MMSYSTEM", 406u16, Stack, wave::HEADER, Word);
            MmsystemWaveOutUnprepareHeader => MMSYSTEM_WAVE_OUT_UNPREPARE_HEADER:
                ("MMSYSTEM", 407u16, Stack, wave::HEADER, Word);
            MmsystemWaveOutWrite => MMSYSTEM_WAVE_OUT_WRITE:
                ("MMSYSTEM", 408u16, Stack, wave::HEADER, Word);
            MmsystemWaveOutPause => MMSYSTEM_WAVE_OUT_PAUSE:
                ("MMSYSTEM", 409u16, Stack, wave::HANDLE, Word);
            MmsystemWaveOutRestart => MMSYSTEM_WAVE_OUT_RESTART:
                ("MMSYSTEM", 410u16, Stack, wave::HANDLE, Word);
            MmsystemWaveOutReset => MMSYSTEM_WAVE_OUT_RESET:
                ("MMSYSTEM", 411u16, Stack, wave::HANDLE, Word);
            MmsystemWaveOutGetPosition => MMSYSTEM_WAVE_OUT_GET_POSITION:
                ("MMSYSTEM", 412u16, Stack, wave::POSITION, Word);
            MmsystemWaveOutGetPitch => MMSYSTEM_WAVE_OUT_GET_PITCH:
                ("MMSYSTEM", 413u16, Stack, wave::GET_PARAMETER, Word);
            MmsystemWaveOutSetPitch => MMSYSTEM_WAVE_OUT_SET_PITCH:
                ("MMSYSTEM", 414u16, Stack, wave::SET_PARAMETER, Word);
            MmsystemWaveOutGetVolume => MMSYSTEM_WAVE_OUT_GET_VOLUME:
                ("MMSYSTEM", 415u16, Stack, wave::GET_DEVICE_VOLUME, Word);
            MmsystemWaveOutSetVolume => MMSYSTEM_WAVE_OUT_SET_VOLUME:
                ("MMSYSTEM", 416u16, Stack, wave::SET_DEVICE_VOLUME, Word);
            MmsystemWaveOutGetPlaybackRate => MMSYSTEM_WAVE_OUT_GET_PLAYBACK_RATE:
                ("MMSYSTEM", 417u16, Stack, wave::GET_PARAMETER, Word);
            MmsystemWaveOutSetPlaybackRate => MMSYSTEM_WAVE_OUT_SET_PLAYBACK_RATE:
                ("MMSYSTEM", 418u16, Stack, wave::SET_PARAMETER, Word);
            MmsystemWaveOutBreakLoop => MMSYSTEM_WAVE_OUT_BREAK_LOOP:
                ("MMSYSTEM", 419u16, Stack, wave::HANDLE, Word);
            MmsystemWaveOutGetID => MMSYSTEM_WAVE_OUT_GET_ID:
                ("MMSYSTEM", 420u16, Stack, wave::DEVICE_ID, Word);
            MmsystemWaveOutMessage => MMSYSTEM_WAVE_OUT_MESSAGE:
                ("MMSYSTEM", 421u16, Stack, wave::MESSAGE, Dword);
            MmsystemWaveInGetNumDevs => MMSYSTEM_WAVE_IN_GET_NUM_DEVS:
                ("MMSYSTEM", 501u16, Stack, &[], Word);
            MmsystemWaveInGetDevCaps => MMSYSTEM_WAVE_IN_GET_DEV_CAPS:
                ("MMSYSTEM", 502u16, Stack, wave::DEVICE_CAPS, Word);
            MmsystemWaveInGetErrorText => MMSYSTEM_WAVE_IN_GET_ERROR_TEXT:
                ("MMSYSTEM", 503u16, Stack, wave::ERROR_TEXT, Word);
            MmsystemWaveInOpen => MMSYSTEM_WAVE_IN_OPEN:
                ("MMSYSTEM", 504u16, Stack, wave::OPEN, Word);
            MmsystemWaveInClose => MMSYSTEM_WAVE_IN_CLOSE:
                ("MMSYSTEM", 505u16, Stack, wave::HANDLE, Word);
            MmsystemWaveInPrepareHeader => MMSYSTEM_WAVE_IN_PREPARE_HEADER:
                ("MMSYSTEM", 506u16, Stack, wave::HEADER, Word);
            MmsystemWaveInUnprepareHeader => MMSYSTEM_WAVE_IN_UNPREPARE_HEADER:
                ("MMSYSTEM", 507u16, Stack, wave::HEADER, Word);
            MmsystemWaveInAddBuffer => MMSYSTEM_WAVE_IN_ADD_BUFFER:
                ("MMSYSTEM", 508u16, Stack, wave::HEADER, Word);
            MmsystemWaveInStart => MMSYSTEM_WAVE_IN_START:
                ("MMSYSTEM", 509u16, Stack, wave::HANDLE, Word);
            MmsystemWaveInStop => MMSYSTEM_WAVE_IN_STOP:
                ("MMSYSTEM", 510u16, Stack, wave::HANDLE, Word);
            MmsystemWaveInReset => MMSYSTEM_WAVE_IN_RESET:
                ("MMSYSTEM", 511u16, Stack, wave::HANDLE, Word);
            MmsystemWaveInGetPosition => MMSYSTEM_WAVE_IN_GET_POSITION:
                ("MMSYSTEM", 512u16, Stack, wave::POSITION, Word);
            MmsystemWaveInGetID => MMSYSTEM_WAVE_IN_GET_ID:
                ("MMSYSTEM", 513u16, Stack, wave::DEVICE_ID, Word);
            MmsystemWaveInMessage => MMSYSTEM_WAVE_IN_MESSAGE:
                ("MMSYSTEM", 514u16, Stack, wave::MESSAGE, Dword);
        }
    };
}

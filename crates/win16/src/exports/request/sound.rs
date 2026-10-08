//! Typed Win16 SOUND.DRV and MMSYSTEM PlaySound requests.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16SoundPlayApi {
    SndPlaySound,
    PlaySound,
}

/// Raw Win16 argument values after fixed-frame ABI decoding. `sound_name` is
/// still a guest FAR value; runtime code interprets it as a name, resource
/// identifier, or in-memory RIFF only after validating the selected flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16SoundRequest {
    Open,
    Close,
    SetVoiceQueueSize { voice: i16, bytes: i16 },
    SetVoiceNote { voice: i16, value: i16, length: i16, dots: i16 },
    SetVoiceAccent { voice: i16, tempo: i16, volume: i16, mode: i16, pitch: i16 },
    SetVoiceEnvelope { voice: i16, shape: i16, repeat: i16 },
    SetSoundNoise { source: i16, duration: i16 },
    SetVoiceSound { voice: i16, frequency_16_16: u32, duration: i16 },
    Start,
    Stop,
    WaitState { state: i16 },
    SyncAllVoices,
    CountVoiceNotes { voice: i16 },
    GetThresholdEvent,
    GetThresholdStatus,
    SetVoiceThreshold { voice: i16, notes: i16 },
    Play {
        api: Win16SoundPlayApi,
        sound_name: u32,
        module: u16,
        flags: u32,
    },
}

//! Fixed-frame decoder for SOUND.DRV and MMSYSTEM PlaySound exports.

use crate::{Win16Argument, Win16Error};

use super::{Win16ExportId, Win16SoundPlayApi, Win16SoundRequest};

pub(super) fn decode(
    id: Win16ExportId,
    arguments: &[Win16Argument],
) -> Result<Win16SoundRequest, Win16Error> {
    use Win16ExportId as Id;
    let request = match id {
        Id::SoundOpen => Win16SoundRequest::Open,
        Id::SoundClose => Win16SoundRequest::Close,
        Id::SoundSetVoiceQueueSize => Win16SoundRequest::SetVoiceQueueSize {
            voice: signed_word(arguments, 0)?, bytes: signed_word(arguments, 1)?,
        },
        Id::SoundSetVoiceNote => Win16SoundRequest::SetVoiceNote {
            voice: signed_word(arguments, 0)?,
            value: signed_word(arguments, 1)?,
            length: signed_word(arguments, 2)?,
            dots: signed_word(arguments, 3)?,
        },
        Id::SoundSetVoiceAccent => Win16SoundRequest::SetVoiceAccent {
            voice: signed_word(arguments, 0)?,
            tempo: signed_word(arguments, 1)?,
            volume: signed_word(arguments, 2)?,
            mode: signed_word(arguments, 3)?,
            pitch: signed_word(arguments, 4)?,
        },
        Id::SoundSetVoiceEnvelope => Win16SoundRequest::SetVoiceEnvelope {
            voice: signed_word(arguments, 0)?,
            shape: signed_word(arguments, 1)?,
            repeat: signed_word(arguments, 2)?,
        },
        Id::SoundSetSoundNoise => Win16SoundRequest::SetSoundNoise {
            source: signed_word(arguments, 0)?,
            duration: signed_word(arguments, 1)?,
        },
        Id::SoundSetVoiceSound => Win16SoundRequest::SetVoiceSound {
            voice: signed_word(arguments, 0)?,
            frequency_16_16: dword(arguments, 1)?,
            duration: signed_word(arguments, 2)?,
        },
        Id::SoundStart => Win16SoundRequest::Start,
        Id::SoundStop => Win16SoundRequest::Stop,
        Id::SoundWaitState => Win16SoundRequest::WaitState { state: signed_word(arguments, 0)? },
        Id::SoundSyncAllVoices => Win16SoundRequest::SyncAllVoices,
        Id::SoundCountVoiceNotes => Win16SoundRequest::CountVoiceNotes {
            voice: signed_word(arguments, 0)?,
        },
        Id::SoundGetThresholdEvent => Win16SoundRequest::GetThresholdEvent,
        Id::SoundGetThresholdStatus => Win16SoundRequest::GetThresholdStatus,
        Id::SoundSetVoiceThreshold => Win16SoundRequest::SetVoiceThreshold {
            voice: signed_word(arguments, 0)?, notes: signed_word(arguments, 1)?,
        },
        Id::MultimediaSndPlaySound => Win16SoundRequest::Play {
            api: Win16SoundPlayApi::SndPlaySound,
            sound_name: dword(arguments, 0)?,
            module: 0,
            flags: u32::from(word(arguments, 1)?),
        },
        Id::MultimediaPlaySound => Win16SoundRequest::Play {
            api: Win16SoundPlayApi::PlaySound,
            sound_name: dword(arguments, 0)?,
            module: word(arguments, 1)?,
            flags: dword(arguments, 2)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn signed_word(arguments: &[Win16Argument], index: usize) -> Result<i16, Win16Error> {
    word(arguments, index).map(|value| value as i16)
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

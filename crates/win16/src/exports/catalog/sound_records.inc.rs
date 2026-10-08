// SOUND.DRV and the later MMSYSTEM sound exports.
macro_rules! export_catalog_with_sound {
    ($($existing:tt)*) => {
        export_catalog_with_winsock! {
            $($existing)*
            MultimediaSndPlaySound => MMSYSTEM_SND_PLAY_SOUND:
                ("MMSYSTEM", 2u16, Stack, sound::SND_PLAY_SOUND, Word);
            MultimediaPlaySound => MMSYSTEM_PLAY_SOUND:
                ("MMSYSTEM", 3u16, Stack, sound::PLAY_SOUND, Word);
            SoundOpen => SOUND_OPEN: ("SOUND", 1u16, Stack, sound::EMPTY, Word);
            SoundClose => SOUND_CLOSE: ("SOUND", 2u16, Stack, sound::EMPTY, Void);
            SoundSetVoiceQueueSize => SOUND_SET_VOICE_QUEUE_SIZE:
                ("SOUND", 3u16, Stack, sound::TWO_WORDS, Word);
            SoundSetVoiceNote => SOUND_SET_VOICE_NOTE:
                ("SOUND", 4u16, Stack, sound::FOUR_WORDS, Word);
            SoundSetVoiceAccent => SOUND_SET_VOICE_ACCENT:
                ("SOUND", 5u16, Stack, sound::FIVE_WORDS, Word);
            SoundSetVoiceEnvelope => SOUND_SET_VOICE_ENVELOPE:
                ("SOUND", 6u16, Stack, sound::THREE_WORDS, Word);
            SoundSetSoundNoise => SOUND_SET_SOUND_NOISE:
                ("SOUND", 7u16, Stack, sound::TWO_WORDS, Word);
            SoundSetVoiceSound => SOUND_SET_VOICE_SOUND:
                ("SOUND", 8u16, Stack, sound::VOICE_FREQUENCY_DURATION, Word);
            SoundStart => SOUND_START: ("SOUND", 9u16, Stack, sound::EMPTY, Word);
            SoundStop => SOUND_STOP: ("SOUND", 10u16, Stack, sound::EMPTY, Word);
            SoundWaitState => SOUND_WAIT_STATE:
                ("SOUND", 11u16, Stack, sound::ONE_WORD, Word);
            SoundSyncAllVoices => SOUND_SYNC_ALL_VOICES:
                ("SOUND", 12u16, Stack, sound::EMPTY, Word);
            SoundCountVoiceNotes => SOUND_COUNT_VOICE_NOTES:
                ("SOUND", 13u16, Stack, sound::ONE_WORD, Word);
            SoundGetThresholdEvent => SOUND_GET_THRESHOLD_EVENT:
                ("SOUND", 14u16, Stack, sound::EMPTY, FarPointer);
            SoundGetThresholdStatus => SOUND_GET_THRESHOLD_STATUS:
                ("SOUND", 15u16, Stack, sound::EMPTY, Word);
            SoundSetVoiceThreshold => SOUND_SET_VOICE_THRESHOLD:
                ("SOUND", 16u16, Stack, sound::TWO_WORDS, Word);
        }
    };
}

// Windows 3.1 MMSYSTEM MIDI entries plus the project-declared later stream
// ordinals, whose data layout remains an explicit compatibility gap.
macro_rules! export_catalog_with_midi {
    ($($existing:tt)*) => {
        export_catalog_with_wave! {
            $($existing)*
            MidiOutGetNumDevs => MMSYSTEM_MIDI_OUT_GET_NUM_DEVS: ("MMSYSTEM", 201u16, Stack, &[], Word);
            MidiOutGetDevCaps => MMSYSTEM_MIDI_OUT_GET_DEV_CAPS: ("MMSYSTEM", 202u16, Stack, midi::CAPS, Word);
            MidiOutGetErrorText => MMSYSTEM_MIDI_OUT_GET_ERROR_TEXT: ("MMSYSTEM", 203u16, Stack, midi::ERROR_TEXT, Word);
            MidiOutOpen => MMSYSTEM_MIDI_OUT_OPEN: ("MMSYSTEM", 204u16, Stack, midi::OPEN, Word);
            MidiOutClose => MMSYSTEM_MIDI_OUT_CLOSE: ("MMSYSTEM", 205u16, Stack, midi::DEVICE, Word);
            MidiOutPrepareHeader => MMSYSTEM_MIDI_OUT_PREPARE_HEADER: ("MMSYSTEM", 206u16, Stack, midi::HEADER, Word);
            MidiOutUnprepareHeader => MMSYSTEM_MIDI_OUT_UNPREPARE_HEADER: ("MMSYSTEM", 207u16, Stack, midi::HEADER, Word);
            MidiOutShortMsg => MMSYSTEM_MIDI_OUT_SHORT_MESSAGE: ("MMSYSTEM", 208u16, Stack, midi::SHORT_MESSAGE, Word);
            MidiOutLongMsg => MMSYSTEM_MIDI_OUT_LONG_MESSAGE: ("MMSYSTEM", 209u16, Stack, midi::HEADER, Word);
            MidiOutReset => MMSYSTEM_MIDI_OUT_RESET: ("MMSYSTEM", 210u16, Stack, midi::DEVICE, Word);
            MidiOutGetVolume => MMSYSTEM_MIDI_OUT_GET_VOLUME: ("MMSYSTEM", 211u16, Stack, midi::GET_VOLUME, Word);
            MidiOutSetVolume => MMSYSTEM_MIDI_OUT_SET_VOLUME: ("MMSYSTEM", 212u16, Stack, midi::SET_VOLUME, Word);
            MidiOutCachePatches => MMSYSTEM_MIDI_OUT_CACHE_PATCHES: ("MMSYSTEM", 213u16, Stack, midi::CACHE_PATCHES, Word);
            MidiOutCacheDrumPatches => MMSYSTEM_MIDI_OUT_CACHE_DRUM_PATCHES: ("MMSYSTEM", 214u16, Stack, midi::CACHE_DRUM_PATCHES, Word);
            MidiOutGetId => MMSYSTEM_MIDI_OUT_GET_ID: ("MMSYSTEM", 215u16, Stack, midi::GET_ID, Word);
            MidiOutMessage => MMSYSTEM_MIDI_OUT_MESSAGE: ("MMSYSTEM", 216u16, Stack, midi::DRIVER_MESSAGE, Dword);
            MidiStreamProperty => MMSYSTEM_MIDI_STREAM_PROPERTY: ("MMSYSTEM", 250u16, Stack, midi::STREAM_PROPERTY, Word);
            MidiStreamOpen => MMSYSTEM_MIDI_STREAM_OPEN: ("MMSYSTEM", 251u16, Stack, midi::STREAM_OPEN, Word);
            MidiStreamClose => MMSYSTEM_MIDI_STREAM_CLOSE: ("MMSYSTEM", 252u16, Stack, midi::DEVICE, Word);
            MidiStreamPosition => MMSYSTEM_MIDI_STREAM_POSITION: ("MMSYSTEM", 253u16, Stack, midi::STREAM_POSITION, Word);
            MidiStreamOut => MMSYSTEM_MIDI_STREAM_OUT: ("MMSYSTEM", 254u16, Stack, midi::STREAM_OUT, Word);
            MidiStreamPause => MMSYSTEM_MIDI_STREAM_PAUSE: ("MMSYSTEM", 255u16, Stack, midi::DEVICE, Word);
            MidiStreamRestart => MMSYSTEM_MIDI_STREAM_RESTART: ("MMSYSTEM", 256u16, Stack, midi::DEVICE, Word);
            MidiStreamStop => MMSYSTEM_MIDI_STREAM_STOP: ("MMSYSTEM", 257u16, Stack, midi::DEVICE, Word);
            MidiInGetNumDevs => MMSYSTEM_MIDI_IN_GET_NUM_DEVS: ("MMSYSTEM", 301u16, Stack, &[], Word);
            MidiInGetDevCaps => MMSYSTEM_MIDI_IN_GET_DEV_CAPS: ("MMSYSTEM", 302u16, Stack, midi::CAPS, Word);
            MidiInGetErrorText => MMSYSTEM_MIDI_IN_GET_ERROR_TEXT: ("MMSYSTEM", 303u16, Stack, midi::ERROR_TEXT, Word);
            MidiInOpen => MMSYSTEM_MIDI_IN_OPEN: ("MMSYSTEM", 304u16, Stack, midi::OPEN, Word);
            MidiInClose => MMSYSTEM_MIDI_IN_CLOSE: ("MMSYSTEM", 305u16, Stack, midi::DEVICE, Word);
            MidiInPrepareHeader => MMSYSTEM_MIDI_IN_PREPARE_HEADER: ("MMSYSTEM", 306u16, Stack, midi::HEADER, Word);
            MidiInUnprepareHeader => MMSYSTEM_MIDI_IN_UNPREPARE_HEADER: ("MMSYSTEM", 307u16, Stack, midi::HEADER, Word);
            MidiInAddBuffer => MMSYSTEM_MIDI_IN_ADD_BUFFER: ("MMSYSTEM", 308u16, Stack, midi::HEADER, Word);
            MidiInStart => MMSYSTEM_MIDI_IN_START: ("MMSYSTEM", 309u16, Stack, midi::DEVICE, Word);
            MidiInStop => MMSYSTEM_MIDI_IN_STOP: ("MMSYSTEM", 310u16, Stack, midi::DEVICE, Word);
            MidiInReset => MMSYSTEM_MIDI_IN_RESET: ("MMSYSTEM", 311u16, Stack, midi::DEVICE, Word);
            MidiInGetId => MMSYSTEM_MIDI_IN_GET_ID: ("MMSYSTEM", 312u16, Stack, midi::GET_ID, Word);
            MidiInMessage => MMSYSTEM_MIDI_IN_MESSAGE: ("MMSYSTEM", 313u16, Stack, midi::DRIVER_MESSAGE, Dword);
        }
    };
}

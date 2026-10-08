//! Decoded Win16 MIDI requests. FAR values stay numeric until runtime checks.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MidiDirection {
    Input,
    Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MidiStreamArgument {
    Word(u16),
    Dword(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MidiRequest {
    DeviceCount { direction: Win16MidiDirection },
    GetDeviceCaps { direction: Win16MidiDirection, device_id: u16, output_far: u32, size: u16 },
    GetErrorText { direction: Win16MidiDirection, error: u16, output_far: u32, size: u16 },
    Open { direction: Win16MidiDirection, output_far: u32, device_id: u16, callback: u32, instance: u32, flags: u32 },
    Close { direction: Win16MidiDirection, device: u16 },
    PrepareHeader { direction: Win16MidiDirection, device: u16, header_far: u32, size: u16 },
    UnprepareHeader { direction: Win16MidiDirection, device: u16, header_far: u32, size: u16 },
    OutputShortMessage { device: u16, message: u32 },
    OutputLongMessage { device: u16, header_far: u32, size: u16 },
    OutputReset { device: u16 },
    OutputGetVolume { device: u16, output_far: u32 },
    OutputSetVolume { device: u16, volume: u32 },
    OutputCachePatches { device: u16, bank: u16, patches_far: u32, flags: u16 },
    OutputCacheDrumPatches { device: u16, patch: u16, keys_far: u32, flags: u16 },
    GetId { direction: Win16MidiDirection, device: u16, output_far: u32 },
    DriverMessage { direction: Win16MidiDirection, device: u16, message: u16, parameter1: u32, parameter2: u32 },
    InputAddBuffer { device: u16, header_far: u32, size: u16 },
    InputStart { device: u16 },
    InputStop { device: u16 },
    InputReset { device: u16 },
    /// These exported names and stack widths are retained, but Windows 3.1
    /// MMSYSTEM.H has no corresponding stream wire declarations. Arguments are
    /// preserved as scalars and no FAR argument is dereferenced.
    StreamUnsupported { ordinal: u16, arguments: Vec<Win16MidiStreamArgument> },
}

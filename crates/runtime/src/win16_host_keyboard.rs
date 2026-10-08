//! Owned KEYBOARD DLL calls for native Windows keyboard services.

/// Host operation issued after runtime has copied all Win16 inputs and
/// translated the guest OEM code page where needed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostKeyboardCall {
    AnsiToOem { source: Vec<u8> },
    OemToAnsi { source: Vec<u8> },
    IsDbcsLeadByte { code_page: u32, value: u8 },
    OemKeyScan { character: u16 },
    VirtualKeyScan { ansi_character: u8 },
    KeyboardType { selector: i16 },
    MapVirtualKey { code: u16, map_type: u16 },
    GetCodePage,
    ToAscii {
        virtual_key: u16,
        scan_code: u16,
        key_state: Box<[u8; 256]>,
        flags: u16,
    },
    /// Map KEYBOARD.7 onto the host's current keyboard repeat-rate setting.
    SetSpeed { speed: u16 },
    KeyNameText { parameter: i32, output: Vec<u8> },
}

/// Operation-tagged results prevent adapters from returning one API's result
/// shape to a different KEYBOARD export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostKeyboardResult {
    Converted(Vec<u8>),
    IsDbcsLeadByte(bool),
    OemKeyScan(u32),
    VirtualKeyScan(i16),
    KeyboardType(i32),
    MapVirtualKey(u32),
    CodePage(u32),
    ToAscii { count: i32, characters: [u16; 2] },
    SetSpeed(u16),
    KeyNameText { output: Vec<u8>, written: usize },
}

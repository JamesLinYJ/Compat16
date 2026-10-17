//! Decoded USER communications calls. Far pointers remain guest values.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserCommRequest {
    Open {
        device: Vec<u8>,
        in_queue: u16,
        out_queue: u16,
    },
    SetState {
        dcb: Vec<u8>,
    },
    GetState {
        id: u16,
        dcb: u32,
    },
    GetError {
        id: u16,
        status: u32,
    },
    Read {
        id: u16,
        buffer: u32,
        count: i16,
    },
    Write {
        id: u16,
        bytes: Vec<u8>,
    },
    Transmit {
        id: u16,
        byte: u8,
    },
    Close {
        id: u16,
    },
    SetEventMask {
        id: u16,
        mask: u16,
    },
    GetEventMask {
        id: u16,
        clear: u16,
    },
    SetBreak {
        id: u16,
    },
    ClearBreak {
        id: u16,
    },
    Unget {
        id: u16,
        byte: u8,
    },
    BuildDcb {
        definition: Vec<u8>,
        dcb: u32,
    },
    Escape {
        id: u16,
        function: i16,
    },
    Flush {
        id: u16,
        queue: i16,
    },
    EnableNotification {
        id: u16,
        window: u16,
        input_threshold: i16,
        output_threshold: i16,
    },
}

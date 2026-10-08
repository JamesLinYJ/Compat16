//! I/O transactions against emulated devices only.
//!
//! Implementations must use process-owned device state. A port number is a
//! guest device address, never permission to execute host IN/OUT instructions.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortWidth {
    Byte,
    Word,
    Dword,
}

impl PortWidth {
    pub const fn bytes(self) -> u8 {
        match self { Self::Byte => 1, Self::Word => 2, Self::Dword => 4 }
    }

    pub const fn mask(self) -> u32 {
        match self { Self::Byte => 0xff, Self::Word => 0xffff, Self::Dword => u32::MAX }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortError {
    Unsupported { port: u16, width: PortWidth, write: bool },
    InvalidState { port: u16, detail: &'static str },
    InternalInvariant { port: u16, detail: &'static str },
}

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { port, width, write } => {
                let width = match width {
                    PortWidth::Byte => "byte (8-bit)",
                    PortWidth::Word => "word (16-bit)",
                    PortWidth::Dword => "dword (32-bit)",
                };
                let operation = if *write { "write" } else { "read" };
                write!(
                    f,
                    "unsupported {width} {operation} on emulated I/O port 0x{port:04X}"
                )
            }
            Self::InvalidState { port, detail } => write!(
                f,
                "invalid device state for emulated I/O at port 0x{port:04X}: {detail}"
            ),
            Self::InternalInvariant { port, detail } => write!(
                f,
                "internal device invariant failed at I/O port 0x{port:04X}: {detail}"
            ),
        }
    }
}
impl std::error::Error for PortError {}

/// Each successful call is one bus transaction of the specified width.
/// A failed transaction must leave device state unchanged. Word/dword access
/// is not automatically split into transactions at neighboring port numbers.
pub trait PortIo {
    fn read(&mut self, port: u16, width: PortWidth) -> Result<u32, PortError>;
    fn write(&mut self, port: u16, width: PortWidth, value: u32) -> Result<(), PortError>;
}

/// Explicitly unconnected bus for CPU callers that have not supplied devices.
pub struct NoPorts;

impl PortIo for NoPorts {
    fn read(&mut self, port: u16, width: PortWidth) -> Result<u32, PortError> {
        Err(PortError::Unsupported { port, width, write: false })
    }
    fn write(&mut self, port: u16, width: PortWidth, _value: u32) -> Result<(), PortError> {
        Err(PortError::Unsupported { port, width, write: true })
    }
}

//! Owned requests for KERNEL debug output, fatal diagnostics, and breakpoints.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelDiagnosticRequest {
    OutputDebugString { message: Vec<u8> },
    FatalAppExit { action: u16, message: Vec<u8> },
    FatalExit { error_code: i16 },
    DebugBreak,
}

//! Owned generic-thunk operations for the native callback worker.
//!
//! Guest offsets remain offsets until the host resolves its private mapping.
//! A returned linear-address DWORD is an explicit legacy API result, not a
//! Rust pointer or a borrow crossing this boundary.

use crate::Diagnostic;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ThunkConvention { Stdcall, Cdecl }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ThunkArgument {
    /// Preserved DWORD bits, including native values obtained by the guest
    /// through an earlier explicit interoperability API.
    Scalar(u32),
    /// Checked offset in the single guest RAM reservation.
    GuestOffset(u32),
}

#[derive(Debug)]
pub enum Win16ThunkOperation {
    LoadLibrary { name: Vec<u8>, reserved_hfile: u32, flags: u32 },
    FreeLibrary { module: u32 },
    GetProcAddress { module: u32, name: Vec<u8> },
    GetLinearAddress { guest_offset: u32 },
    Call {
        procedure: u32,
        convention: Win16ThunkConvention,
        arguments: Vec<Win16ThunkArgument>,
    },
}

#[derive(Debug)]
pub struct Win16ThunkResult {
    /// Actual DWORD result, or the API's documented zero failure value.
    pub value: u32,
    /// Optional explanation of a recoverable native API failure. Internal
    /// invariants and memory transfer failures remain RuntimeError instead.
    pub diagnostic: Option<Diagnostic>,
}

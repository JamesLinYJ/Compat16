//! Shared owned values at the Win16 call boundary.

use super::Win16ApiRequest;
use crate::exports::Win16ExportId;
use crate::{SegmentedPointer, StackCleanup};

/// Comparison semantics selected by the Win16 string API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16StringComparison {
    /// Compare byte values directly, as KERNEL.87 Reserved5 does.
    Binary,
    /// Compare according to the current thread locale.
    Linguistic,
    /// Compare according to the current thread locale, ignoring case.
    LinguisticIgnoreCase,
}

/// Owned Win16 module input. APIs that accept a FAR string but also interpret
/// selector-zero values as handles preserve the distinction at the ABI edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ModuleReference {
    Current,
    Handle(u16),
    Name(Vec<u8>),
}

/// Owned Win16 procedure input, preserving the name-versus-ordinal encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ProcReference {
    Ordinal(u16),
    Name(Vec<u8>),
}

/// The overloaded `AnsiLower` argument: a zero high word denotes the single
/// character in the low word; otherwise it is a checked guest far string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16AnsiCaseTarget {
    Char(u16),
    String { pointer: u32, bytes: Vec<u8> },
}

/// A cursor or icon resource name. `Id` represents a MAKEINTRESOURCE value
/// encoded with a zero selector; `Name` owns bytes copied from a validated
/// guest far string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ResourceName {
    Id(u16),
    Name(Vec<u8>),
}

/// A registered Win16 window-class name or integer class atom.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ClassName {
    /// `MAKEINTATOM`: a class atom encoded in the low word of a FAR pointer.
    Atom(u16),
    /// A NUL-terminated class name copied from validated guest memory.
    Name(Vec<u8>),
}

/// An atom name accepted by Win16 GlobalAddAtom / GlobalFindAtom. `Integer`
/// represents a MAKEINTATOM value encoded with a zero selector; `String` owns
/// bytes copied from a validated guest ANSI string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16AtomName {
    Integer(u16),
    String(Vec<u8>),
}

/// A writable guest far buffer passed through the Win16 ABI.
///
/// `pointer` is selector-checked and `capacity` is checked against every guest
/// segment before the request is returned. The runtime writes results back to
/// guest memory through its selector table; this type contains no host pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16OutputBuffer {
    pub pointer: SegmentedPointer,
    pub capacity: u16,
}

/// Fully decoded ABI call. Input strings and byte buffers are owned copies;
/// output buffers retain only a checked guest far pointer and capacity. No host
/// pointer or borrowed guest memory escapes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedWin16Call {
    pub export: Win16ExportId,
    pub request: Win16ApiRequest,
    pub stack_cleanup: StackCleanup,
}

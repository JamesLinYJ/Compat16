//! Typed native window fields after guest index and handle translation.

use crate::{Win16HostWindow, Win16WindowTarget};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowDataField { Style, ExStyle, ControlId }

/// Native scalar fields only. Guest extra bytes, HINSTANCE and FAR procedures
/// remain owned by the guest runtime and never become native indices/pointers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowDataCall {
    Get { window: Win16WindowTarget, field: Win16WindowDataField },
    Set {
        window: Win16WindowTarget,
        field: Win16WindowDataField,
        value: u32,
        mask: u32,
    },
    GetParent { window: Win16WindowTarget },
    SetParent { window: Win16WindowTarget, parent: Win16WindowTarget },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowDataResult {
    /// None is native failure; Some(0) preserves a successful zero old value.
    Value(Option<u32>),
    Parent {
        succeeded: bool,
        previous: Option<Win16HostWindow>,
        /// Actual child relationship observed after the operation. Top-level
        /// ownership is not a child edge in the guest destruction graph.
        child_parent: Option<Win16HostWindow>,
    },
}

/// An exact native incarnation observed while a callback suspends USER.
/// A retired token and a failed query are distinct from a live top-level
/// window, whose ownership does not create a child destruction edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostWindowParentObservation {
    Live { child_parent: Option<Win16HostWindow> },
    Retired,
}

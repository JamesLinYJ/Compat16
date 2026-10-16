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
    /// GWW_HWNDPARENT: changes the owner for non-child windows.
    SetParent { window: Win16WindowTarget, parent: Win16WindowTarget },
    /// USER.233: always native SetParent, preserving the window style.
    Reparent { window: Win16WindowTarget, parent: Win16WindowTarget },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowDataResult {
    /// None is native failure; Some(0) preserves a successful zero old value.
    Value(Option<u32>),
    /// Immutable native mutation outcome. The previous candidate was captured
    /// before callbacks; projection must check its exact liveness. No fallible
    /// post-call query may discard this outcome or cause native replay.
    /// Foreign aliases retain their host's weaker ABA guarantees; only owned
    /// cookie-backed tokens prove the full native incarnation.
    ParentMutation {
        attempted: bool,
        succeeded: bool,
        previous: Option<Win16HostWindow>,
    },
    Parent {
        succeeded: bool,
        previous: Option<Win16HostWindow>,
        /// Actual parent relationship, including style-preserving reparenting.
        /// Top-level ownership is not an actual-parent edge.
        child_parent: Option<Win16HostWindow>,
    },
}

/// An exact native incarnation observed while a callback suspends USER.
/// A retired token and a failed query are distinct from a live window with
/// no actual parent. Owner relationships are deliberately excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostWindowParentObservation {
    Live { child_parent: Option<Win16HostWindow> },
    Retired,
}

//! Guest access descriptions shared by the checked bus and CPU instructions.

use guest_core::LinearAddr;

use crate::{
    SegmentAccess,
    registers::SegmentRegister,
    system::PageAccess,
};

/// Access class used for segment checks, page permissions, and backing-store
/// validation. Read-modify-write checks write permission before reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccessKind {
    Fetch,
    /// Validate an effective address without reading the operand (INVLPG).
    AddressOnly,
    DataRead,
    DataWrite,
    DataReadWrite,
    StackRead,
    StackWrite,
    SystemTableRead,
    SystemTableWrite,
}

/// The target CPU's alignment requirement for one architectural access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataAlignment {
    Natural(u8),
    Unaligned,
    /// The target manual does not define the operand alignment modulus.
    /// Only an otherwise active #AC gate can make this unknown observable.
    Unspecified,
}

/// Access provenance controls debug-watchpoint eligibility and event EXT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccessOrigin {
    GuestInstruction,
    ProcessorEvent,
}

/// Debug matches captured by one or more completed guest data transfers.
/// `matching` feeds DR6.B0-B3 if some #DB is generated at this boundary;
/// `enabled` decides whether a data breakpoint itself generates that #DB.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DataBreakpointHits {
    pub(crate) matching: u8,
    pub(crate) enabled: u8,
}

impl DataBreakpointHits {
    pub(crate) const fn union(self, other: Self) -> Self {
        Self {
            matching: self.matching | other.matching,
            enabled: self.enabled | other.enabled,
        }
    }
}

impl AccessKind {
    pub(super) const fn reads(self) -> bool {
        matches!(
            self,
            Self::Fetch
                | Self::DataRead
                | Self::DataReadWrite
                | Self::StackRead
                | Self::SystemTableRead
        )
    }

    pub(super) const fn writes(self) -> bool {
        matches!(
            self,
            Self::DataWrite | Self::DataReadWrite | Self::StackWrite | Self::SystemTableWrite
        )
    }

    pub(super) const fn page_access(self) -> PageAccess {
        if self.writes() {
            PageAccess::Write
        } else if matches!(self, Self::Fetch) {
            PageAccess::Execute
        } else {
            PageAccess::Read
        }
    }

    pub(super) const fn segment_access(self) -> SegmentAccess {
        if matches!(self, Self::Fetch) {
            SegmentAccess::Execute
        } else if self.writes() {
            SegmentAccess::Write
        } else {
            SegmentAccess::Read
        }
    }
}

/// Logical range before hidden segment translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LogicalSpan {
    pub(crate) register: SegmentRegister,
    pub(crate) selector: u16,
    /// Start offset; only an operand's initial effective address receives
    /// address-size truncation. Fetch continuations are already canonical.
    pub(crate) offset: u32,
    pub(crate) len: usize,
    pub(crate) address32: bool,
}

/// One checked guest-memory operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccessRequest {
    Logical {
        span: LogicalSpan,
        kind: AccessKind,
        alignment: DataAlignment,
        origin: AccessOrigin,
    },
    /// CPU-created supervisor access after architectural segment checks.
    SystemLinear {
        address: LinearAddr,
        len: usize,
        kind: AccessKind,
    },
}

impl AccessRequest {
    pub(crate) const fn instruction(
        span: LogicalSpan,
        kind: AccessKind,
        alignment: DataAlignment,
    ) -> Self {
        Self::Logical {
            span,
            kind,
            alignment,
            origin: AccessOrigin::GuestInstruction,
        }
    }

    pub(crate) const fn processor_event(
        span: LogicalSpan,
        kind: AccessKind,
        alignment: DataAlignment,
    ) -> Self {
        Self::Logical {
            span,
            kind,
            alignment,
            origin: AccessOrigin::ProcessorEvent,
        }
    }
}

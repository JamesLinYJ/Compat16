//! Caller-owned DOS pointers are separate from DOS-owned real-mode metadata.
//!
//! The runtime implements this contract at the address-space boundary. DOS
//! handlers keep segment/selector values as guest coordinates and never turn
//! a protected-mode selector into a real-mode physical address.

use guest_core::GuestMemory;

use crate::DosError;

/// Stable identity of one DOS caller address space.
///
/// A runtime must keep an ID stable while DOS retains pointers for that
/// caller, and must not reuse it while those pointers remain in DOS state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DosCallerId(u64);

impl DosCallerId {
    /// Construct an identity supplied by the runtime. Zero is reserved for
    /// the legacy real-mode address space.
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Identity used by the real-mode compatibility adapter.
    pub const REAL_MODE: Self = Self(0);

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// A guest far address belonging to a caller, not a host pointer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DosFarPointer {
    RealMode {
        caller: DosCallerId,
        segment: u16,
        offset: u16,
    },
    Protected {
        caller: DosCallerId,
        selector: u16,
        offset: u16,
    },
}

impl DosFarPointer {
    pub const fn real_mode(caller: DosCallerId, segment: u16, offset: u16) -> Self {
        Self::RealMode {
            caller,
            segment,
            offset,
        }
    }

    pub const fn protected(caller: DosCallerId, selector: u16, offset: u16) -> Self {
        Self::Protected {
            caller,
            selector,
            offset,
        }
    }

    pub const fn caller(self) -> DosCallerId {
        match self {
            Self::RealMode { caller, .. } | Self::Protected { caller, .. } => caller,
        }
    }

    /// Guest ABI words used to return this address through ES:BX or a DOS
    /// structure. Protected selectors remain selector values here; they are
    /// never interpreted as real-mode segments.
    pub const fn words(self) -> (u16, u16) {
        match self {
            Self::RealMode {
                segment, offset, ..
            } => (segment, offset),
            Self::Protected {
                selector, offset, ..
            } => (selector, offset),
        }
    }
}

/// A caller pointer retained beyond the DOS call that supplied it.
///
/// `lease` is an opaque runtime identity for the retained caller coordinate
/// and selector generation, or another address-space resource. DOS stores it
/// but cannot interpret it. Protected adapters assign a distinct nonzero lease
/// per caller/domain/selector-generation/starting-offset tuple. Real-mode
/// adapters use lease zero because release is a no-op there.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DosPersistentFarPointer {
    pointer: DosFarPointer,
    lease: u64,
}

impl DosPersistentFarPointer {
    pub const fn new(pointer: DosFarPointer, lease: u64) -> Self {
        Self { pointer, lease }
    }

    pub const fn pointer(self) -> DosFarPointer {
        self.pointer
    }
    pub const fn lease(self) -> u64 {
        self.lease
    }
}

/// Compatibility policy for old real-mode routines whose byte walks differ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosSpanPolicy {
    /// Continue at the next guest linear byte. This is used by bounded DOS
    /// strings and buffers that historically used `real_address + delta`.
    Linear,
    /// Wrap the 16-bit offset within the same real-mode segment. This is used
    /// only by routines that already split at the 64 KiB offset boundary.
    OffsetWrap,
}

/// Access direction for preflight and pointer projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosPointerAccess {
    Read,
    Write,
    Execute,
}

/// Address-space services for DOS operands supplied by the active caller.
///
/// The inherited `GuestMemory` methods remain the route for canonical DOS
/// state such as PSP/MCB/JFT/SFT, IVT, and DOS-owned NLS tables. Methods below
/// are only for caller-owned far pointers. In protected mode, each range must
/// remain within the single selector named by its pointer, regardless of the
/// requested legacy real-mode span policy. Every operation must reject a
/// pointer whose caller differs from `caller_id()`. Persistent-pointer methods
/// must also validate the opaque lease; `expose_dos_pointer` returns an alias
/// owned by the active caller. An `Execute` exposure succeeds only when it
/// supplies a genuinely callable executable view or ABI-correct call gate; it
/// must not return a data alias as a function pointer. If the runtime cannot
/// provide that contract, it reports
/// `DosCallerAddressSpaceFailureKind::Unsupported`.
pub trait DosCallAddressSpace: GuestMemory {
    /// Stable owner identity for this call and any retained DOS pointers.
    fn caller_id(&self) -> DosCallerId;

    /// Validate the caller's raw segment-or-selector words and construct a
    /// typed address token without changing its guest coordinate.
    fn resolve_caller_pointer(
        &mut self,
        segment_or_selector: u16,
        offset: u16,
    ) -> Result<DosFarPointer, DosError>;

    /// Validate an entire caller range before a host side effect or guest
    /// state change. Protected pointers are always single-selector spans.
    fn validate_caller_range(
        &mut self,
        pointer: DosFarPointer,
        byte_offset: usize,
        length: usize,
        access: DosPointerAccess,
        policy: DosSpanPolicy,
    ) -> Result<(), DosError>;

    fn read_caller_range(
        &mut self,
        pointer: DosFarPointer,
        byte_offset: usize,
        output: &mut [u8],
        policy: DosSpanPolicy,
    ) -> Result<(), DosError>;

    fn write_caller_range(
        &mut self,
        pointer: DosFarPointer,
        byte_offset: usize,
        input: &[u8],
        policy: DosSpanPolicy,
    ) -> Result<(), DosError>;

    /// Read a terminator-bounded byte string. Allocation failure and pointer
    /// faults must remain distinguishable errors; the caller decides whether
    /// a malformed string becomes a DOS status or a fatal guest fault.
    fn read_caller_terminated(
        &mut self,
        pointer: DosFarPointer,
        terminator: u8,
        maximum: usize,
        policy: DosSpanPolicy,
    ) -> Result<Vec<u8>, DosError>;

    /// Pin the selector generation or equivalent mapping while DOS retains a
    /// pointer such as the per-caller DTA. The same caller, address domain,
    /// selector generation, and starting offset must return the same token on
    /// repeated calls; distinct protected starting offsets receive distinct
    /// tokens even within one selector. This operation does not add a separate
    /// reference count. A new selector generation gets a new token. DOS
    /// releases each unique token after the current DTA and every active search
    /// stop referring to it, or at caller teardown.
    fn retain_caller_pointer(
        &mut self,
        pointer: DosFarPointer,
    ) -> Result<DosPersistentFarPointer, DosError>;

    fn release_caller_pointer(&mut self, pointer: DosPersistentFarPointer) -> Result<(), DosError>;

    /// Verify the retained owner and selector generation even for a zero-byte
    /// range; callers use that form when returning a persistent far pointer.
    fn validate_persistent_range(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        length: usize,
        access: DosPointerAccess,
    ) -> Result<(), DosError>;

    fn read_persistent_range(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        output: &mut [u8],
    ) -> Result<(), DosError>;

    fn write_persistent_range(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        input: &[u8],
    ) -> Result<(), DosError>;

    /// Give the caller a stable far-address view of a DOS-owned real-mode
    /// object embedded in an output record (for example an NLS table pointer).
    /// The runtime owns any alias mapping until the caller address space ends.
    fn expose_dos_pointer(
        &mut self,
        segment: u16,
        offset: u16,
        length: usize,
        access: DosPointerAccess,
    ) -> Result<DosFarPointer, DosError>;
}

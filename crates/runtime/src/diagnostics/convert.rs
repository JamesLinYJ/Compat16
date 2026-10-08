//! Map subsystem failures to common diagnostics without losing their types.

use super::{DiagnosticKind as Kind, RuntimeError};
use devices::DeviceError;
use dos_kernel::{DosCallerAddressSpaceFailureKind, DosError};
use formats::FormatError;
use guest_core::{MemoryError, arena::ArenaError, io::PortError};
use win16_abi::Win16Error;
use x86_cpu::{CpuContextRestoreError, CpuError};
use xms::PreparedCallMismatch;

fn memory_kind(error: &MemoryError) -> Kind {
    match error {
        MemoryError::AllocationFailed
        | MemoryError::MappingIdentityExhausted
        | MemoryError::RoutingEpochExhausted => {
            Kind::ResourceExhausted
        }
        MemoryError::InvalidMapping => Kind::InternalInvariant,
        MemoryError::AtomicityUnavailable => Kind::CompatibilityGap,
        MemoryError::StorageAccess { .. } => Kind::HostFailure,
        MemoryError::AddressOverflow
        | MemoryError::OutOfBounds { .. }
        | MemoryError::ReadOnly { .. } => Kind::GuestFault,
    }
}

fn port_kind(error: &PortError) -> Kind {
    match error {
        PortError::Unsupported { .. } => Kind::CompatibilityGap,
        PortError::InvalidState { .. } => Kind::GuestFault,
        PortError::InternalInvariant { .. } => Kind::InternalInvariant,
    }
}

impl From<MemoryError> for RuntimeError {
    fn from(error: MemoryError) -> Self {
        Self::from_source(memory_kind(&error), error)
    }
}

impl From<PortError> for RuntimeError {
    fn from(error: PortError) -> Self {
        Self::from_source(port_kind(&error), error)
    }
}

fn cpu_kind(error: &CpuError) -> Kind {
    match error {
        CpuError::Memory(error) => memory_kind(error),
        CpuError::Io(error) => port_kind(error),
        CpuError::UnsupportedOpcode { .. }
        | CpuError::UnsupportedSystemMode { .. }
        | CpuError::UnsupportedSystemAddressing { .. }
        | CpuError::CompatibilityGap { .. } => Kind::CompatibilityGap,
        CpuError::InvalidCodeSize(_) | CpuError::InvalidMemoryAccessPlan { .. } => {
            Kind::InternalInvariant
        }
        CpuError::CallBoundarySequenceExhausted => Kind::ResourceExhausted,
        CpuError::SegmentFault { .. }
        | CpuError::InvalidOpcode { .. }
        | CpuError::InvalidGroup { .. }
        | CpuError::InstructionTooLong { .. }
        | CpuError::FloatException
        | CpuError::DivideError
        | CpuError::GeneralProtectionFault { .. }
        | CpuError::DeviceNotAvailableFault { .. }
        | CpuError::SegmentNotPresentFault { .. }
        | CpuError::StackSegmentFault { .. }
        | CpuError::InvalidTssFault { .. }
        | CpuError::PageFault { .. }
        | CpuError::AlignmentCheckFault { .. }
        | CpuError::BoundRangeFault { .. }
        | CpuError::DebugFault { .. }
        | CpuError::InstructionBreakpointFault { .. } => Kind::GuestFault,
        CpuError::NestedExceptionDelivery { original, delivery } => {
            cpu_delivery_kind(cpu_kind(original), cpu_kind(delivery))
        }
        CpuError::ProcessorShutdown { original, delivery, double_fault } => {
            let preceding = cpu_delivery_kind(cpu_kind(original), cpu_kind(delivery));
            cpu_delivery_kind(preceding, cpu_kind(double_fault))
        }
        CpuError::TaskSwitchCommitted { fault, .. } => cpu_kind(fault),
    }
}

// A guest fault can be delivered normally. If delivery instead stops on a
// host, resource, or compatibility failure, classify that actual cause. An
// architectural follow-up fault must not hide an earlier non-guest failure.
// Invariant violations remain critical anywhere in the retained cause chain.
fn cpu_delivery_kind(preceding: Kind, delivery: Kind) -> Kind {
    match (preceding, delivery) {
        (Kind::InternalInvariant, _) | (_, Kind::InternalInvariant) => Kind::InternalInvariant,
        (Kind::GuestFault, additional) => additional,
        (primary, Kind::GuestFault) => primary,
        (_, additional) => additional,
    }
}

impl From<CpuError> for RuntimeError {
    fn from(error: CpuError) -> Self {
        Self::from_source(cpu_kind(&error), error)
    }
}

impl From<CpuContextRestoreError> for RuntimeError {
    fn from(error: CpuContextRestoreError) -> Self {
        let kind = if error.boundary_sequence_exhausted() {
            Kind::ResourceExhausted
        } else {
            Kind::InternalInvariant
        };
        Self::from_source(kind, error)
            .with_context("restore a scheduler-owned CPU context")
    }
}

impl From<DeviceError> for RuntimeError {
    fn from(error: DeviceError) -> Self {
        let kind = match &error {
            DeviceError::Memory(error) => memory_kind(error),
            DeviceError::UnsupportedInterrupt { .. } => Kind::CompatibilityGap,
            DeviceError::InvalidRequest { .. } => Kind::GuestFault,
        };
        Self::from_source(kind, error)
    }
}

fn dos_error_kind(error: &DosError) -> Kind {
    match error {
        DosError::Memory(error) => memory_kind(error),
        DosError::HostOperation(_) => Kind::HostFailure,
        DosError::MalformedGuestInput(_) | DosError::InvalidMcbSignature { .. } => {
            Kind::GuestFault
        }
        DosError::HostContractViolation(_)
        | DosError::HostMemoryContractViolation { .. }
        | DosError::RollbackFailure { .. } => Kind::InternalInvariant,
        DosError::HostHandleRollbackFailure { cause, .. } => dos_error_kind(cause),
        DosError::CallerAddressSpace { kind, .. } => match kind {
            DosCallerAddressSpaceFailureKind::InvalidPointer => Kind::GuestFault,
            DosCallerAddressSpaceFailureKind::Unsupported => Kind::CompatibilityGap,
            DosCallerAddressSpaceFailureKind::ResourceExhausted => Kind::ResourceExhausted,
            DosCallerAddressSpaceFailureKind::HostFailure => Kind::HostFailure,
            DosCallerAddressSpaceFailureKind::InternalInvariant => Kind::InternalInvariant,
        },
    }
}

impl From<DosError> for RuntimeError {
    fn from(error: DosError) -> Self {
        match error {
            DosError::HostHandleRollbackFailure {
                operation,
                cause,
                rollback,
            } => {
                let primary = Self::from(*cause).with_context(operation);
                let cleanup = Self::from(*rollback)
                    .with_context("close duplicated inherited DOS file handle");
                primary.with_cleanup("DOS inherited-handle rollback failed", cleanup)
            }
            error => Self::from_source(dos_error_kind(&error), error),
        }
    }
}

impl From<FormatError> for RuntimeError {
    fn from(error: FormatError) -> Self {
        let kind = match &error {
            FormatError::UnsupportedExecutable(_)
            | FormatError::UnsupportedNeLoading
            | FormatError::UnsupportedNeFeature(_)
            | FormatError::NeDataImportFailure { .. }
            | FormatError::UnsupportedNeFixup(_)
            | FormatError::UnresolvedNeImport { .. } => Kind::CompatibilityGap,
            FormatError::GuestMemoryRollback { .. } => Kind::InternalInvariant,
            FormatError::AllocationFailed => Kind::ResourceExhausted,
            FormatError::GuestMemory(error) => memory_kind(error),
            FormatError::Truncated { .. }
            | FormatError::InvalidSignature { .. }
            | FormatError::InvalidCom(_)
            | FormatError::InvalidMzHeader(_)
            | FormatError::InvalidNe(_)
            | FormatError::ArithmeticOverflow
            | FormatError::AddressOutOfRange { .. }
            | FormatError::InvalidNeLoad(_) => Kind::InvalidInput,
        };
        Self::from_source(kind, error)
    }
}

// Arena operations here describe fixed machine configuration, not a guest
// allocation request. Guest DOS/XMS out-of-memory remains a protocol result.
impl From<ArenaError> for RuntimeError {
    fn from(error: ArenaError) -> Self {
        let kind = match error {
            ArenaError::IdentityExhausted | ArenaError::RegionIdExhausted => {
                Kind::ResourceExhausted
            }
            _ => Kind::InternalInvariant,
        };
        Self::from_source(kind, error)
    }
}

impl From<PreparedCallMismatch> for RuntimeError {
    fn from(error: PreparedCallMismatch) -> Self {
        Self::from_source(Kind::InternalInvariant, error)
    }
}

impl From<Win16Error> for RuntimeError {
    fn from(error: Win16Error) -> Self {
        let kind = match &error {
            Win16Error::Memory(memory) => memory_kind(memory),
            Win16Error::UnsupportedRegisterContextExport
            | Win16Error::UnsupportedCallingConvention => Kind::CompatibilityGap,
            // These exports have dedicated decoders. Reaching the ordinary
            // decoder is a runtime routing defect, not bad guest input.
            Win16Error::RegisterContextRequired
            | Win16Error::VariableStackRequiresSpecialDecoder
            | Win16Error::GenericThunkRequiresSpecialDecoder => Kind::InternalInvariant,
            Win16Error::SelectorTableFull
            | Win16Error::HandleTableFull
            | Win16Error::OutOfMemory
            | Win16Error::GenerationExhausted
            | Win16Error::IdentityExhausted => Kind::ResourceExhausted,
            Win16Error::ReallocRollbackFailed { .. } => Kind::InternalInvariant,
            Win16Error::InvalidRange
            | Win16Error::InvalidSelector
            | Win16Error::StaleSelector
            | Win16Error::ForeignSelector
            | Win16Error::SelectorBlockInterior
            | Win16Error::LimitViolation { .. }
            | Win16Error::StackOffsetWrap { .. }
            | Win16Error::AccessDenied { .. }
            | Win16Error::InvalidHandle
            | Win16Error::StaleHandle
            | Win16Error::ForeignHandle
            | Win16Error::InvalidSize
            | Win16Error::Locked
            | Win16Error::LockUnderflow
            | Win16Error::LockCountOverflow
            | Win16Error::UnknownTask
            | Win16Error::TaskAlreadyExists
            | Win16Error::InvalidTaskState => Kind::GuestFault,
        };
        Self::from_source(kind, error)
    }
}

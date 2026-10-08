//! Public CPU error and compatibility-gap types.

use guest_core::{MemoryError, io::PortError};

/// Errors raised by the interpreter rather than silently skipped operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CpuError {
    Memory(MemoryError),
    Io(PortError),
    SegmentFault {
        selector: u16,
        offset: u32,
        access: SegmentAccess,
        reason: SegmentFaultReason,
    },
    UnsupportedOpcode {
        opcode: u8,
        ip: u32,
    },
    InvalidOpcode {
        opcode: u8,
        ip: u32,
    },
    GeneralProtectionFault {
        error_code: u32,
        ip: u32,
    },
    SegmentNotPresentFault {
        error_code: u32,
        ip: u32,
    },
    StackSegmentFault {
        error_code: u32,
        ip: u32,
    },
    InvalidTssFault {
        error_code: u32,
        ip: u32,
    },
    PageFault {
        error_code: u32,
        linear_address: u32,
        ip: u32,
    },
    AlignmentCheckFault {
        error_code: u32,
        ip: u32,
    },
    InvalidMemoryAccessPlan {
        ip: u32,
    },
    UnsupportedSystemMode {
        opcode: u8,
        ip: u32,
    },
    UnsupportedSystemAddressing {
        opcode: u8,
        ip: u32,
    },
    CompatibilityGap {
        opcode: u8,
        ip: u32,
        feature: CpuCompatibilityGap,
    },
    InvalidGroup {
        opcode: u8,
        extension: u8,
        ip: u32,
    },
    InstructionTooLong {
        ip: u32,
    },
    InvalidCodeSize(u32),
    FloatException,
    DivideError,
    DeviceNotAvailableFault {
        ip: u32,
    },
    BoundRangeFault {
        ip: u32,
    },
    DebugFault {
        ip: u32,
    },
    /// Fault-class #DB from an enabled instruction breakpoint.
    InstructionBreakpointFault {
        ip: u32,
    },
    /// A CPU exception arose while another event was being delivered. Keep
    /// both architectural causes instead of replacing the first with the
    /// second delivery failure.
    NestedExceptionDelivery {
        original: Box<CpuError>,
        delivery: Box<CpuError>,
    },
    /// A fault while delivering #DF shuts down the modeled processor.
    ProcessorShutdown {
        original: Box<CpuError>,
        delivery: Box<CpuError>,
        double_fault: Box<CpuError>,
    },
    /// A task switch has committed architectural state, but a fault arose
    /// while loading the incoming task's segment state or interrupt frame.
    TaskSwitchCommitted {
        target_ip: u32,
        fault: Box<CpuError>,
    },
    /// The nonwrapping CPU instruction-boundary sequence cannot advance.
    CallBoundarySequenceExhausted,
}

/// A legal guest operation whose required system behavior is not yet wired
/// into this CPU backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuCompatibilityGap {
    ProtectedModeTransition,
    Virtual8086Mode,
    PagingTransition,
    PagingAddressTranslation,
    NumericExceptionReporting,
    AlignmentCheck,
    PageWriteProtection,
    DebugExceptionDelivery,
    DebugRegisterReservedBits,
    AtomicBusTransaction,
    TestRegisters,
    PrivilegeStackSwitch,
    TaskSwitching,
    ProtectedExceptionDelivery,
}

impl std::fmt::Display for CpuCompatibilityGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ProtectedModeTransition => "protected-mode transition",
            Self::Virtual8086Mode => "virtual-8086 execution semantics",
            Self::PagingTransition => "paging transition",
            Self::PagingAddressTranslation => "paged address translation",
            Self::NumericExceptionReporting => "x87 numeric-exception reporting",
            Self::AlignmentCheck => "alignment-check memory semantics",
            Self::PageWriteProtection => "page write-protection semantics",
            Self::DebugExceptionDelivery => "debug exception delivery",
            Self::DebugRegisterReservedBits => "debug-register reserved-bit semantics",
            Self::AtomicBusTransaction => "atomic guest-bus transaction",
            Self::TestRegisters => "Intel486 test-register semantics",
            Self::PrivilegeStackSwitch => "protected-mode privilege stack switching",
            Self::TaskSwitching => "protected-mode task switching",
            Self::ProtectedExceptionDelivery => "protected-mode exception delivery",
        })
    }
}

/// Architectural access requested through a segmented address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentAccess {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentFaultReason {
    NotPresent,
    Limit,
    AccessDenied,
}

impl std::fmt::Display for CpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(error) => write!(f, "x86 guest-memory access failed: {error}"),
            Self::Io(error) => write!(f, "x86 guest I/O operation failed: {error}"),
            Self::SegmentFault {
                selector,
                offset,
                access,
                reason,
            } => write!(
                f,
                "x86 {} access at selector 0x{selector:04X}, offset 0x{offset:08X} failed: {}",
                match access {
                    SegmentAccess::Read => "read",
                    SegmentAccess::Write => "write",
                    SegmentAccess::Execute => "execute",
                },
                match reason {
                    SegmentFaultReason::NotPresent => "selector is not present",
                    SegmentFaultReason::Limit => "segment limit exceeded",
                    SegmentFaultReason::AccessDenied => "access is not permitted",
                },
            ),
            Self::UnsupportedOpcode { opcode, ip } => write!(
                f,
                "x86 opcode 0x{opcode:02X} at instruction pointer 0x{ip:08X} is not implemented by this CPU backend"
            ),
            Self::InvalidOpcode { opcode, ip } => write!(
                f,
                "invalid x86 opcode 0x{opcode:02X} at instruction pointer 0x{ip:08X}"
            ),
            Self::GeneralProtectionFault { error_code, ip } => write!(
                f,
                "x86 general-protection fault (#GP({error_code})) at instruction pointer 0x{ip:08X}"
            ),
            Self::SegmentNotPresentFault { error_code, ip } => write!(
                f,
                "x86 segment-not-present fault (#NP({error_code})) at instruction pointer 0x{ip:08X}"
            ),
            Self::StackSegmentFault { error_code, ip } => write!(
                f,
                "x86 stack-segment fault (#SS({error_code})) at instruction pointer 0x{ip:08X}"
            ),
            Self::InvalidTssFault { error_code, ip } => write!(
                f,
                "x86 invalid-TSS fault (#TS({error_code})) at instruction pointer 0x{ip:08X}"
            ),
            Self::PageFault {
                error_code,
                linear_address,
                ip,
            } => write!(
                f,
                "x86 page fault (#PF({error_code})) at linear address 0x{linear_address:08X}, instruction pointer 0x{ip:08X}"
            ),
            Self::AlignmentCheckFault { error_code, ip } => write!(
                f,
                "x86 alignment-check fault (#AC({error_code})) at instruction pointer 0x{ip:08X}"
            ),
            Self::InvalidMemoryAccessPlan { ip } => write!(
                f,
                "invalid x86 memory-access plan at instruction pointer 0x{ip:08X}"
            ),
            Self::UnsupportedSystemMode { opcode, ip } => write!(
                f,
                "x86 system opcode 0x{opcode:02X} at instruction pointer 0x{ip:08X} requires architectural mode and privilege state not supplied by the machine"
            ),
            Self::UnsupportedSystemAddressing { opcode, ip } => write!(
                f,
                "x86 system opcode 0x{opcode:02X} at instruction pointer 0x{ip:08X} uses an address form not modeled by this CPU backend"
            ),
            Self::CompatibilityGap {
                opcode,
                ip,
                feature,
            } => write!(
                f,
                "x86 system opcode 0x{opcode:02X} at instruction pointer 0x{ip:08X} requires unimplemented {feature} behavior"
            ),
            Self::InvalidGroup {
                opcode,
                extension,
                ip,
            } => write!(
                f,
                "x86 opcode 0x{opcode:02X} at instruction pointer 0x{ip:08X} has invalid group extension 0x{extension:X}"
            ),
            Self::InstructionTooLong { ip } => write!(
                f,
                "x86 instruction at instruction pointer 0x{ip:08X} exceeds the 15-byte length limit"
            ),
            Self::InvalidCodeSize(bits) => write!(
                f,
                "invalid x86 code size of {bits} bits; this backend supports 16-bit and 32-bit code"
            ),
            Self::FloatException => f.write_str("unmasked x87 floating-point exception"),
            Self::DivideError => f.write_str("x86 integer divide error (#DE)"),
            Self::DeviceNotAvailableFault { ip } => write!(
                f,
                "x86 device-not-available fault (#NM) at instruction pointer 0x{ip:08X}"
            ),
            Self::BoundRangeFault { ip } => write!(
                f,
                "x86 bounds-range fault (#BR) at instruction pointer 0x{ip:08X}"
            ),
            Self::DebugFault { ip } => write!(
                f,
                "x86 debug fault (#DB) at instruction pointer 0x{ip:08X}"
            ),
            Self::InstructionBreakpointFault { ip } => write!(
                f,
                "x86 instruction breakpoint (#DB) at instruction pointer 0x{ip:08X}"
            ),
            Self::NestedExceptionDelivery { original, delivery } => write!(
                f,
                "x86 exception delivery failed after {original}: {delivery}"
            ),
            Self::ProcessorShutdown { original, delivery, double_fault } => write!(
                f,
                "x86 processor shutdown after {original}, {delivery}, and failed #DF delivery: {double_fault}"
            ),
            Self::TaskSwitchCommitted { target_ip, fault } => write!(
                f,
                "x86 task switch committed at instruction pointer 0x{target_ip:08X}, then incoming task validation failed: {fault}"
            ),
            Self::CallBoundarySequenceExhausted => {
                f.write_str("CPU instruction-boundary sequence is exhausted")
            }
        }
    }
}

impl std::error::Error for CpuError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::NestedExceptionDelivery { delivery, .. } => Some(delivery),
            Self::ProcessorShutdown { double_fault, .. } => Some(double_fault),
            Self::TaskSwitchCommitted { fault, .. } => Some(fault),
            _ => None,
        }
    }
}

/// Invalid machine-supplied state rejected at the explicit CPU configuration
/// boundary. These errors are not guest faults and never enter guest memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuArchitecturalStateError {
    InvalidControlRegister,
    InvalidPrivilegeLevel,
    VisibleSelectorMismatch,
    InvalidSegmentCache,
    InvalidCodeSegmentCache,
    InvalidStackSegmentCache,
    InvalidSystemSegmentCache,
}

impl std::fmt::Display for CpuArchitecturalStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidControlRegister => "invalid control-register state",
            Self::InvalidPrivilegeLevel => "invalid current privilege level",
            Self::VisibleSelectorMismatch => {
                "hidden segment selector does not match visible register"
            }
            Self::InvalidSegmentCache => "invalid hidden segment cache",
            Self::InvalidCodeSegmentCache => "invalid hidden CS cache",
            Self::InvalidStackSegmentCache => "invalid hidden SS cache",
            Self::InvalidSystemSegmentCache => "invalid hidden LDTR or task cache",
        })
    }
}

impl std::error::Error for CpuArchitecturalStateError {}

impl From<MemoryError> for CpuError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

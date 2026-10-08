//! Diagnostic classification, reporting and typed cause preservation.
use super::{Diagnostic, DiagnosticKind as Kind, DiagnosticSeverity as Severity, RuntimeError};
use std::error::Error;
use x86_cpu::CpuError;
use devices::DeviceError;
use dos_kernel::{DosError, DosErrorCode, DosHostError};
use formats::FormatError;
use guest_core::{MemoryError, PhysAddr, io::{PortError, PortWidth}};
use xms::PreparedCallMismatch;

#[test]
fn warnings_are_reports_and_do_not_require_an_execution_failure() {
    let warning = Diagnostic::warning(Kind::CompatibilityGap, "optional capability unavailable; guest received its documented failure result");
    assert_eq!(warning.kind(), Kind::CompatibilityGap);
    assert_eq!(warning.severity(), Severity::Warn);
    assert!(warning.to_string().starts_with("[warn/compatibility_gap]"));
    let warning = warning.with_cause(std::io::Error::from_raw_os_error(5));
    assert_eq!(warning.cause().unwrap().downcast_ref::<std::io::Error>().unwrap().raw_os_error(), Some(5));
    let info = Diagnostic::info(Kind::ExecutionLimit, "execution budget configured");
    assert_eq!(info.severity(), Severity::Info);
}

#[test]
fn category_and_impact_are_not_the_same_thing() {
    let failure = RuntimeError::new(Kind::CompatibilityGap, "required instruction unavailable");
    assert_eq!(failure.severity(), Severity::Error);
    let limit = RuntimeError::new(Kind::ExecutionLimit, "execution budget exhausted");
    assert_eq!(limit.severity(), Severity::Warn);
    assert_eq!(RuntimeError::new(Kind::InternalInvariant, "bad adapter state").severity(), Severity::Critical);
}

#[test]
fn cpu_faults_remain_distinct_from_missing_execution_support() {
    for error in [CpuError::DivideError, CpuError::FloatException, CpuError::InvalidOpcode { opcode: 0xff, ip: 0x1234 }] {
        assert_eq!(RuntimeError::from(error).kind(), Kind::GuestFault);
    }
    assert_eq!(RuntimeError::from(CpuError::UnsupportedOpcode { opcode: 0xff, ip: 0x1234 }).kind(), Kind::CompatibilityGap);
    assert_eq!(RuntimeError::from(CpuError::Io(PortError::Unsupported { port: 0x123, width: PortWidth::Byte, write: false })).kind(), Kind::CompatibilityGap);
    assert_eq!(RuntimeError::from(CpuError::InvalidCodeSize(17)).kind(), Kind::InternalInvariant);
    assert_eq!(RuntimeError::from(PortError::InternalInvariant { port: 0x20, detail: "invalid host IRQ" }).severity(), Severity::Critical);
}

#[test]
fn source_and_context_survive_service_and_launcher_boundaries() {
    let error = RuntimeError::from(DeviceError::UnsupportedInterrupt { interrupt: 0x21, function: 0x65 })
        .with_context("INT 21h AX=6506")
        .with_context("after 10 instructions, CS:IP=F000:1084");
    assert_eq!(error.kind(), Kind::CompatibilityGap);
    assert!(matches!(error.source().unwrap().downcast_ref::<DeviceError>(), Some(DeviceError::UnsupportedInterrupt { interrupt: 0x21, function: 0x65 })));
    let text = error.to_string();
    assert_eq!(text.matches("[error/compatibility_gap]").count(), 1);
    assert!(text.contains("after 10 instructions, CS:IP=F000:1084: INT 21h AX=6506:"));
    assert!(!text.contains('{') && !text.contains('}'));
}

#[test]
fn user_facing_nested_failures_do_not_dump_debug_structures() {
    let errors = [
        RuntimeError::from(CpuError::Io(PortError::Unsupported {
            port: 0x123, width: PortWidth::Word, write: false,
        })),
        RuntimeError::from(DosError::Memory(MemoryError::OutOfBounds {
            address: 0x10000, length: 32,
        })),
        RuntimeError::from(FormatError::GuestMemoryRollback {
            failed_address: PhysAddr(0x10000),
            primary_error: MemoryError::ReadOnly { address: 0xf0000, length: 1 },
            rollback_failures: Vec::new(),
        }),
    ];
    for error in errors {
        let message = error.to_string();
        assert!(!message.contains('{') && !message.contains('}'), "{message}");
        assert!(error.source().is_some());
    }
}

#[test]
fn memory_allocation_mapping_and_guest_access_have_separate_categories() {
    assert_eq!(RuntimeError::from(MemoryError::AllocationFailed).kind(), Kind::ResourceExhausted);
    assert_eq!(RuntimeError::from(MemoryError::InvalidMapping).kind(), Kind::InternalInvariant);
    assert_eq!(RuntimeError::from(MemoryError::ReadOnly { address: 0xf2000, length: 1 }).kind(), Kind::GuestFault);
}

#[test]
fn protocol_adapter_contract_failure_is_critical() {
    let dos = RuntimeError::from(DosError::HostContractViolation("incorrect write count"));
    assert_eq!(dos.severity(), Severity::Critical);
    let xms = RuntimeError::from(PreparedCallMismatch::MoveDescriptorRequired);
    assert_eq!(xms.kind(), Kind::InternalInvariant);
    assert!(xms.source().unwrap().is::<PreparedCallMismatch>());
}

#[test]
fn loader_rejects_input_separately_from_unsupported_formats_and_failed_rollback() {
    assert_eq!(RuntimeError::from(FormatError::InvalidMzHeader("truncated")).kind(), Kind::InvalidInput);
    assert_eq!(RuntimeError::from(FormatError::UnsupportedNeLoading).kind(), Kind::CompatibilityGap);
    let rollback = FormatError::GuestMemoryRollback {
        failed_address: PhysAddr(0x10000),
        primary_error: MemoryError::OutOfBounds { address: 0x10000, length: 1 },
        rollback_failures: Vec::new(),
    };
    assert_eq!(RuntimeError::from(rollback).severity(), Severity::Critical);
}

#[test]
fn host_os_error_remains_available_as_a_typed_cause() {
    let error = RuntimeError::with_source(Kind::HostFailure, "read executable", std::io::Error::from_raw_os_error(5));
    assert_eq!(error.source().unwrap().downcast_ref::<std::io::Error>().unwrap().raw_os_error(), Some(5));
    assert_eq!(error.severity(), Severity::Error);
    let dos = DosHostError::with_source(DosErrorCode::AccessDenied, std::io::Error::from_raw_os_error(5));
    assert_eq!(dos.code, DosErrorCode::AccessDenied);
    let runtime = RuntimeError::with_source(Kind::HostFailure, "host initialization", dos);
    let native = runtime.source().unwrap().source().unwrap().downcast_ref::<std::io::Error>().unwrap();
    assert_eq!(native.raw_os_error(), Some(5));
    let runtime = RuntimeError::from(DosError::HostOperation(DosHostError::with_source(
        DosErrorCode::AccessDenied, std::io::Error::from_raw_os_error(5),
    )));
    assert_eq!(runtime.kind(), Kind::HostFailure);
    let native = runtime.source().unwrap().source().unwrap().source().unwrap()
        .downcast_ref::<std::io::Error>().unwrap();
    assert_eq!(native.raw_os_error(), Some(5));
}

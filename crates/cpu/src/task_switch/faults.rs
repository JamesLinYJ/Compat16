//! Translate task-transfer validation outcomes into architectural CPU faults.

use crate::{CpuError, x86_decode::NormalizedInstruction};

use super::memory::selector_error_code;

pub(super) fn remap_descriptor_lookup(
    error: CpuError,
    selector: u16,
    task_return: bool,
    external: bool,
    ip: u32,
) -> CpuError {
    match error {
        CpuError::GeneralProtectionFault { .. } | CpuError::InvalidTssFault { .. } => {
            if task_return {
                invalid_tss(selector, ip, external)
            } else {
                general_protection_code(with_external(selector, external), ip)
            }
        }
        CpuError::SegmentNotPresentFault { .. } => not_present(selector, ip, external),
        other => other,
    }
}

pub(super) fn target_descriptor_fault(
    selector: u16,
    expects_busy_target: bool,
    external: bool,
    ip: u32,
) -> CpuError {
    let code = with_external(selector, external);
    if expects_busy_target {
        invalid_tss_code(code, ip)
    } else {
        general_protection_code(code, ip)
    }
}

pub(super) fn not_present(selector: u16, ip: u32, external: bool) -> CpuError {
    CpuError::SegmentNotPresentFault {
        error_code: with_external(selector, external),
        ip,
    }
}

pub(super) fn invalid_tss(selector: u16, ip: u32, external: bool) -> CpuError {
    CpuError::InvalidTssFault {
        error_code: with_external(selector, external),
        ip,
    }
}

pub(super) fn general_protection_code(error_code: u32, ip: u32) -> CpuError {
    CpuError::GeneralProtectionFault { error_code, ip }
}

fn invalid_tss_code(error_code: u32, ip: u32) -> CpuError {
    CpuError::InvalidTssFault { error_code, ip }
}

pub(super) fn with_external(selector: u16, external: bool) -> u32 {
    selector_error_code(selector) | u32::from(external)
}

pub(super) fn task_error_stack_access(error: CpuError, ip: u32, external: bool) -> CpuError {
    match error {
        CpuError::GeneralProtectionFault { .. } | CpuError::StackSegmentFault { .. } => {
            CpuError::StackSegmentFault {
                error_code: u32::from(external),
                ip,
            }
        }
        other => other,
    }
}

pub(super) fn committed_fault(error: CpuError, target_ip: u32) -> CpuError {
    CpuError::TaskSwitchCommitted {
        target_ip,
        fault: Box::new(error),
    }
}

pub(super) fn unsupported_mode(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::UnsupportedSystemMode {
        opcode: instruction.decoded.opcode,
        ip: instruction.decoded.start_ip,
    }
}
